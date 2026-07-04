using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for the AgentService orchestrator — the main BackgroundService
/// that initializes agent state, manages module lifecycle, coordinates
/// the AgentBrain and ChatHandler, and handles graceful shutdown.
/// </summary>
public class AgentServiceTests : IDisposable
{
    private readonly string _tempDir;

    public AgentServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"winsentinel_agentsvc_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private AgentBrain CreateBrain(AgentConfig config, ThreatLog threatLog)
    {
        var policy = ResponsePolicy.CreateDefault(config.RiskTolerance);
        var correlator = new ThreatCorrelator(new NullLogger<ThreatCorrelator>());
        var remediator = new AutoRemediator(new NullLogger<AutoRemediator>());
        var journalPath = Path.Combine(_tempDir, $"journal_{Guid.NewGuid():N}.jsonl");
        var journal = new AgentJournal(new NullLogger<AgentJournal>(), journalPath);

        return new AgentBrain(
            new NullLogger<AgentBrain>(),
            policy,
            correlator,
            remediator,
            journal,
            threatLog,
            config);
    }

    private IpcServer CreateIpcServer(AgentState state, AgentConfig config, ThreatLog threatLog)
    {
        var policy = ResponsePolicy.CreateDefault(config.RiskTolerance);
        return new IpcServer(
            new NullLogger<IpcServer>(),
            state,
            config,
            threatLog,
            policy,
            new ServiceProviderStub());
    }

    private ChatHandler CreateChatHandler(
        AgentState state, AgentConfig config, AgentBrain brain, ThreatLog threatLog, IpcServer ipcServer)
    {
        return new ChatHandler(
            new NullLogger<ChatHandler>(),
            state,
            config,
            brain,
            threatLog,
            ipcServer);
    }

    private AgentService CreateService(
        AgentConfig? config = null,
        IEnumerable<IAgentModule>? modules = null)
    {
        config ??= new AgentConfig();
        var state = new AgentState();
        var threatLog = new ThreatLog();
        var brain = CreateBrain(config, threatLog);
        var ipcServer = CreateIpcServer(state, config, threatLog);
        var chatHandler = CreateChatHandler(state, config, brain, threatLog, ipcServer);

        return new AgentService(
            new NullLogger<AgentService>(),
            state,
            config,
            threatLog,
            ipcServer,
            brain,
            chatHandler,
            modules ?? Array.Empty<IAgentModule>());
    }

    private (AgentService service, AgentState state, ThreatLog threatLog, AgentConfig config) CreateServiceFull(
        AgentConfig? config = null,
        IEnumerable<IAgentModule>? modules = null)
    {
        config ??= new AgentConfig();
        var state = new AgentState();
        var threatLog = new ThreatLog();
        var brain = CreateBrain(config, threatLog);
        var ipcServer = CreateIpcServer(state, config, threatLog);
        var chatHandler = CreateChatHandler(state, config, brain, threatLog, ipcServer);

        var service = new AgentService(
            new NullLogger<AgentService>(),
            state,
            config,
            threatLog,
            ipcServer,
            brain,
            chatHandler,
            modules ?? Array.Empty<IAgentModule>());

        return (service, state, threatLog, config);
    }

    // ── Test module implementations ─────────────────────────────────

    private class FakeModule : IAgentModule
    {
        public string Name { get; }
        public bool IsActive { get; private set; }
        public bool WasStarted { get; private set; }
        public bool WasStopped { get; private set; }
        public int StartCallCount { get; private set; }
        public int StopCallCount { get; private set; }

        public FakeModule(string name) => Name = name;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            WasStarted = true;
            IsActive = true;
            StartCallCount++;
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            WasStopped = true;
            IsActive = false;
            StopCallCount++;
            return Task.CompletedTask;
        }
    }

    private class FailingModule : IAgentModule
    {
        public string Name { get; }
        public bool IsActive { get; private set; }
        public bool StartAttempted { get; private set; }
        public bool WasStopped { get; private set; }

        public FailingModule(string name) => Name = name;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            StartAttempted = true;
            throw new InvalidOperationException($"Module {Name} failed to start");
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            WasStopped = true;
            IsActive = false;
            return Task.CompletedTask;
        }
    }

    private class SlowModule : IAgentModule
    {
        public string Name { get; }
        public bool IsActive { get; private set; }
        public bool WasStarted { get; private set; }

        public SlowModule(string name) => Name = name;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await Task.Delay(50, cancellationToken);
            WasStarted = true;
            IsActive = true;
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            await Task.Delay(20, cancellationToken);
            IsActive = false;
        }
    }

    private class FailingStopModule : IAgentModule
    {
        public string Name { get; }
        public bool IsActive { get; private set; }

        public FailingStopModule(string name) => Name = name;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            IsActive = true;
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            throw new InvalidOperationException($"Module {Name} failed to stop");
        }
    }

    /// <summary>Minimal IServiceProvider stub for IpcServer constructor.</summary>
    private class ServiceProviderStub : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }

    // ── Helper to run service briefly ───────────────────────────────

    private static async Task RunServiceBriefly(AgentService service, int delayMs = 200)
    {
        using var cts = new CancellationTokenSource();
        var startTask = service.StartAsync(cts.Token);
        await Task.Delay(delayMs);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// Polls <paramref name="condition"/> until it returns true or <paramref name="timeoutMs"/>
    /// elapses, checking every <paramref name="pollMs"/>. Returns the final observed value.
    /// Used to wait for the background <c>ExecuteAsync</c> loop to reach a state (e.g. modules
    /// started) rather than assuming a fixed delay is enough — a fixed delay races on slow CI.
    /// </summary>
    private static async Task<bool> WaitForAsync(Func<bool> condition, int timeoutMs = 5000, int pollMs = 25)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
                return true;
            await Task.Delay(pollMs);
        }
        return condition();
    }

    // ══════════════════════════════════════════════════════════════════
    // STATE INITIALIZATION
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_SetsStartTimeOnState()
    {
        var (service, state, _, _) = CreateServiceFull();
        var before = DateTimeOffset.UtcNow;

        await RunServiceBriefly(service);

        Assert.True(state.StartTime >= before);
        Assert.True(state.StartTime <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Execute_SetsThreatLogOnState()
    {
        var (service, state, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        Assert.NotNull(state.ThreatLog);
        Assert.Same(threatLog, state.ThreatLog);
    }

    [Fact]
    public async Task Execute_ConfiguresThreatLogMaxSize()
    {
        var config = new AgentConfig { MaxThreatLogSize = 500 };
        var (service, state, threatLog, _) = CreateServiceFull(config: config);

        await RunServiceBriefly(service);

        // Verify by adding events over the limit
        for (int i = 0; i < 520; i++)
        {
            threatLog.Add(new ThreatEvent
            {
                Source = "Test",
                Severity = ThreatSeverity.Info,
                Title = $"Event {i}"
            });
        }

        // Should be trimmed to max 500
        Assert.True(threatLog.Count <= 500);
    }

    [Fact]
    public async Task Execute_DefaultMaxThreatLogSize_Is1000()
    {
        var (service, state, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        // Add 1050 events
        for (int i = 0; i < 1050; i++)
        {
            threatLog.Add(new ThreatEvent
            {
                Source = "Test",
                Severity = ThreatSeverity.Info,
                Title = $"Event {i}"
            });
        }

        // +1 for the startup event added by the service
        Assert.True(threatLog.Count <= 1001);
    }

    // ══════════════════════════════════════════════════════════════════
    // STARTUP THREAT EVENT
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_LogsStartupThreatEvent()
    {
        var (service, _, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        var events = threatLog.GetAll();
        Assert.Contains(events, e =>
            e.Source == "Agent" &&
            e.Severity == ThreatSeverity.Info &&
            e.Title == "Agent Started");
    }

    [Fact]
    public async Task Execute_StartupEventContainsVersion()
    {
        var (service, state, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        var startEvent = threatLog.GetAll().First(e => e.Title == "Agent Started");
        Assert.Contains("WinSentinel Agent v", startEvent.Description);
        Assert.Contains(state.Version, startEvent.Description);
    }

    [Fact]
    public async Task Execute_StartupEventHasInfoSeverity()
    {
        var (service, _, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        var startEvent = threatLog.GetAll().First(e => e.Title == "Agent Started");
        Assert.Equal(ThreatSeverity.Info, startEvent.Severity);
    }

    // ══════════════════════════════════════════════════════════════════
    // MODULE STARTUP — ENABLED
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_StartsEnabledModules()
    {
        var module1 = new FakeModule("ProcessMonitor");
        var module2 = new FakeModule("FileMonitor");
        var (service, _, _, _) = CreateServiceFull(modules: new IAgentModule[] { module1, module2 });

        using var cts = new CancellationTokenSource();
        var startTask = service.StartAsync(cts.Token);

        // The background ExecuteAsync loop starts modules asynchronously; a fixed delay
        // races on slow CI runners, so wait until both modules actually report started
        // (bounded) rather than asserting immediately.
        var started = await WaitForAsync(() => module1.WasStarted && module2.WasStarted);

        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        Assert.True(started, "Enabled modules did not start within the timeout");
        Assert.True(module1.WasStarted);
        Assert.True(module2.WasStarted);
    }

    [Fact]
    public async Task Execute_TracksActiveModulesInState()
    {
        var module = new FakeModule("ScheduledAudit");
        var (service, state, _, _) = CreateServiceFull(modules: new IAgentModule[] { module });

        using var cts = new CancellationTokenSource();
        var startTask = service.StartAsync(cts.Token);
        await Task.Delay(150);

        // Module should be marked active
        Assert.True(state.ActiveModules.ContainsKey("ScheduledAudit"));
        Assert.True(state.ActiveModules["ScheduledAudit"]);

        cts.Cancel();
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Execute_MultipleModules_AllStarted()
    {
        var modules = new[]
        {
            new FakeModule("Module1"),
            new FakeModule("Module2"),
            new FakeModule("Module3")
        };
        var (service, state, _, _) = CreateServiceFull(modules: modules);

        await RunServiceBriefly(service);

        foreach (var m in modules)
        {
            Assert.True(m.WasStarted, $"Module {m.Name} was not started");
            Assert.Equal(1, m.StartCallCount);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // MODULE STARTUP — DISABLED
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_SkipsDisabledModules()
    {
        var config = new AgentConfig();
        config.ModuleToggles["DisabledModule"] = false;

        var enabledModule = new FakeModule("EnabledModule");
        var disabledModule = new FakeModule("DisabledModule");
        var (service, _, _, _) = CreateServiceFull(
            config: config,
            modules: new IAgentModule[] { enabledModule, disabledModule });

        await RunServiceBriefly(service);

        Assert.True(enabledModule.WasStarted);
        Assert.False(disabledModule.WasStarted);
    }

    [Fact]
    public async Task Execute_DisabledModule_NeverSetToActiveTrue()
    {
        // Disabled modules are never set to active=true during startup.
        // After shutdown, StopAsync sets them to false, so the key exists but was never true.
        var config = new AgentConfig();
        config.ModuleToggles["Disabled"] = false;

        var disabledModule = new FakeModule("Disabled");
        var (service, state, _, _) = CreateServiceFull(
            config: config,
            modules: new IAgentModule[] { disabledModule });

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(150);

        // During run, disabled module should NOT be in ActiveModules
        Assert.False(state.ActiveModules.ContainsKey("Disabled"));

        cts.Cancel();
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Execute_ModuleNotInToggles_DefaultsToEnabled()
    {
        // A module not listed in ModuleToggles should default to enabled
        var config = new AgentConfig();
        // Don't add "NewModule" to ModuleToggles at all
        var module = new FakeModule("NewModule");
        var (service, _, _, _) = CreateServiceFull(
            config: config,
            modules: new IAgentModule[] { module });

        await RunServiceBriefly(service);

        Assert.True(module.WasStarted);
    }

    [Fact]
    public async Task Execute_MixedEnabledDisabled_OnlyStartsEnabled()
    {
        var config = new AgentConfig();
        config.ModuleToggles["ModuleA"] = true;
        config.ModuleToggles["ModuleB"] = false;
        config.ModuleToggles["ModuleC"] = true;

        var modules = new[]
        {
            new FakeModule("ModuleA"),
            new FakeModule("ModuleB"),
            new FakeModule("ModuleC")
        };
        var (service, state, _, _) = CreateServiceFull(
            config: config,
            modules: modules);

        await RunServiceBriefly(service);

        Assert.True(modules[0].WasStarted);   // A enabled
        Assert.False(modules[1].WasStarted);  // B disabled
        Assert.True(modules[2].WasStarted);   // C enabled
    }

    // ══════════════════════════════════════════════════════════════════
    // MODULE STARTUP — FAILURE HANDLING
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_FailingModule_DoesNotCrashService()
    {
        var failingModule = new FailingModule("BadModule");
        var goodModule = new FakeModule("GoodModule");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { failingModule, goodModule });

        // Should not throw
        await RunServiceBriefly(service);

        Assert.True(failingModule.StartAttempted);
        Assert.True(goodModule.WasStarted);
    }

    [Fact]
    public async Task Execute_FailingModule_MarkedInactiveInState()
    {
        var failingModule = new FailingModule("FailModule");
        var (service, state, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { failingModule });

        await RunServiceBriefly(service);

        // The module key exists but is set to false
        Assert.True(state.ActiveModules.ContainsKey("FailModule"));
        Assert.False(state.ActiveModules["FailModule"]);
    }

    [Fact]
    public async Task Execute_FirstModuleFails_SecondStillStarts()
    {
        var failing = new FailingModule("First");
        var healthy = new FakeModule("Second");
        var (service, state, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { failing, healthy });

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(150);

        // During run: Second started and is active, First failed
        Assert.True(healthy.WasStarted);
        Assert.True(state.ActiveModules["Second"]);
        Assert.False(state.ActiveModules["First"]);

        cts.Cancel();
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Execute_AllModulesFail_ServiceStillRunning()
    {
        var modules = new IAgentModule[]
        {
            new FailingModule("Bad1"),
            new FailingModule("Bad2"),
            new FailingModule("Bad3")
        };
        var (service, state, _, _) = CreateServiceFull(modules: modules);

        // Should not throw — service runs even with zero active modules
        await RunServiceBriefly(service);

        Assert.True(state.ActiveModules.All(kv => !kv.Value));
    }

    // ══════════════════════════════════════════════════════════════════
    // MODULE STARTUP — ASYNC MODULES
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_AsyncModule_AwaitsStart()
    {
        var slowModule = new SlowModule("SlowStart");
        var (service, state, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { slowModule });

        await RunServiceBriefly(service, delayMs: 300);

        Assert.True(slowModule.WasStarted);
    }

    // ══════════════════════════════════════════════════════════════════
    // NO MODULES
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_NoModules_RunsSuccessfully()
    {
        var (service, state, threatLog, _) = CreateServiceFull(modules: Array.Empty<IAgentModule>());

        await RunServiceBriefly(service);

        // Service still logs startup event
        Assert.Contains(threatLog.GetAll(), e => e.Title == "Agent Started");
        Assert.Empty(state.ActiveModules);
    }

    // ══════════════════════════════════════════════════════════════════
    // SHUTDOWN
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Shutdown_StopsAllModules()
    {
        var module1 = new FakeModule("Mod1");
        var module2 = new FakeModule("Mod2");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { module1, module2 });

        await RunServiceBriefly(service);

        Assert.True(module1.WasStopped);
        Assert.True(module2.WasStopped);
    }

    [Fact]
    public async Task Shutdown_MarksModulesInactiveInState()
    {
        var module = new FakeModule("TestMod");
        var (service, state, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { module });

        await RunServiceBriefly(service);

        Assert.False(state.ActiveModules["TestMod"]);
    }

    [Fact]
    public async Task Shutdown_FailingStopModule_DoesNotPreventOthersFromStopping()
    {
        var failStop = new FailingStopModule("FailStop");
        var normalModule = new FakeModule("NormalMod");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { failStop, normalModule });

        // Should not throw even though FailStop.StopAsync throws
        await RunServiceBriefly(service);

        Assert.True(normalModule.WasStopped);
    }

    [Fact]
    public async Task Shutdown_DisabledModule_StillAttemptedStop()
    {
        // The service iterates all modules during shutdown (not just active ones)
        var config = new AgentConfig();
        config.ModuleToggles["Disabled"] = false;

        var disabledModule = new FakeModule("Disabled");
        var (service, _, _, _) = CreateServiceFull(
            config: config,
            modules: new IAgentModule[] { disabledModule });

        await RunServiceBriefly(service);

        // Even disabled modules get StopAsync called during shutdown
        Assert.True(disabledModule.WasStopped);
    }

    // ══════════════════════════════════════════════════════════════════
    // CANCELLATION
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_CancellationToken_StopsGracefully()
    {
        var module = new FakeModule("TestMod");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { module });

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(100);

        // Cancel should trigger shutdown
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        Assert.True(module.WasStopped);
    }

    [Fact]
    public async Task Execute_ImmediateCancellation_StillInitializes()
    {
        var (service, state, threatLog, _) = CreateServiceFull();

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(50);
        cts.Cancel();
        await service.StopAsync(CancellationToken.None);

        // State should still be initialized
        Assert.NotNull(state.ThreatLog);
        Assert.Contains(threatLog.GetAll(), e => e.Title == "Agent Started");
    }

    // ══════════════════════════════════════════════════════════════════
    // ACTIVE MODULE COUNT
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_ActiveModuleCount_MatchesSuccessfulStarts()
    {
        var config = new AgentConfig();
        config.ModuleToggles["Disabled"] = false;

        var modules = new IAgentModule[]
        {
            new FakeModule("Good1"),
            new FakeModule("Good2"),
            new FailingModule("Bad1"),
            new FakeModule("Disabled")
        };
        var (service, state, _, _) = CreateServiceFull(
            config: config,
            modules: modules);

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token);
        await Task.Delay(150);

        // Good1 and Good2 are active; Bad1 failed; Disabled was skipped
        var activeCount = state.ActiveModules.Count(kv => kv.Value);
        Assert.Equal(2, activeCount);

        cts.Cancel();
        await service.StopAsync(CancellationToken.None);
    }

    // ══════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public void Constructor_AcceptsValidDependencies()
    {
        // Should not throw
        var service = CreateService();
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_AcceptsEmptyModuleList()
    {
        var service = CreateService(modules: Array.Empty<IAgentModule>());
        Assert.NotNull(service);
    }

    // ══════════════════════════════════════════════════════════════════
    // CONFIG INTEGRATION
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_CustomMaxThreatLogSize_Applied()
    {
        var config = new AgentConfig { MaxThreatLogSize = 50 };
        var (service, _, threatLog, _) = CreateServiceFull(config: config);

        await RunServiceBriefly(service);

        // Fill beyond 50
        for (int i = 0; i < 70; i++)
        {
            threatLog.Add(new ThreatEvent
            {
                Source = "Overflow",
                Severity = ThreatSeverity.Low,
                Title = $"Event {i}"
            });
        }

        Assert.True(threatLog.Count <= 50);
    }

    [Fact]
    public async Task Execute_MinimumThreatLogSize_Clamped()
    {
        // ThreatLog.SetMaxSize clamps to minimum of 10
        var config = new AgentConfig { MaxThreatLogSize = 3 };
        var (service, _, threatLog, _) = CreateServiceFull(config: config);

        await RunServiceBriefly(service);

        for (int i = 0; i < 20; i++)
        {
            threatLog.Add(new ThreatEvent
            {
                Source = "Test",
                Severity = ThreatSeverity.Info,
                Title = $"Ev{i}"
            });
        }

        // Clamped to 10 minimum, not 3
        Assert.True(threatLog.Count >= 10);
        Assert.True(threatLog.Count <= 11); // +1 for startup event
    }

    // ══════════════════════════════════════════════════════════════════
    // MODULE ORDERING
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_ModulesStartedInRegistrationOrder()
    {
        var startOrder = new List<string>();
        var modules = new[]
        {
            new OrderTrackingModule("Alpha", startOrder),
            new OrderTrackingModule("Beta", startOrder),
            new OrderTrackingModule("Gamma", startOrder)
        };
        var (service, _, _, _) = CreateServiceFull(modules: modules);

        await RunServiceBriefly(service);

        Assert.Equal(new[] { "Alpha", "Beta", "Gamma" }, startOrder);
    }

    private class OrderTrackingModule : IAgentModule
    {
        private readonly List<string> _tracker;
        public string Name { get; }
        public bool IsActive { get; private set; }

        public OrderTrackingModule(string name, List<string> tracker)
        {
            Name = name;
            _tracker = tracker;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _tracker.Add(Name);
            IsActive = true;
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            IsActive = false;
            return Task.CompletedTask;
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // IDEMPOTENCY & MULTIPLE RUNS
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_ModuleStartCalledOnlyOnce()
    {
        var module = new FakeModule("SingleStart");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { module });

        await RunServiceBriefly(service);

        Assert.Equal(1, module.StartCallCount);
    }

    [Fact]
    public async Task Execute_ModuleStopCalledOnlyOnce()
    {
        var module = new FakeModule("SingleStop");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { module });

        await RunServiceBriefly(service);

        Assert.Equal(1, module.StopCallCount);
    }

    // ══════════════════════════════════════════════════════════════════
    // BRAIN INITIALIZATION
    // ══════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Execute_BrainInitializedBeforeModuleStart()
    {
        // The brain subscribes to ThreatLog.ThreatDetected during Initialize.
        // Modules that add threats should have the brain already listening.
        var (service, _, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        // The startup event is added after brain.Initialize(), so it would
        // have been processed by the brain's event handler
        var events = threatLog.GetAll();
        Assert.True(events.Count >= 1);
    }

    // -- EDGE CASES --

    [Fact]
    public async Task Execute_LargeModuleCount_AllStarted()
    {
        var modules = Enumerable.Range(0, 20)
            .Select(i => new FakeModule($"Module{i}"))
            .ToArray();
        var (service, state, _, _) = CreateServiceFull(modules: modules);

        await RunServiceBriefly(service, delayMs: 300);

        Assert.All(modules, m => Assert.True(m.WasStarted));
    }

    [Fact]
    public async Task Execute_ModuleWithSameName_BothStarted()
    {
        var module1 = new FakeModule("Duplicate");
        var module2 = new FakeModule("Duplicate");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { module1, module2 });

        await RunServiceBriefly(service);

        Assert.True(module1.WasStarted);
        Assert.True(module2.WasStarted);
    }

    [Fact]
    public async Task Execute_EmptyModuleName_StillStarts()
    {
        var module = new FakeModule("");
        var (service, _, _, _) = CreateServiceFull(
            modules: new IAgentModule[] { module });

        await RunServiceBriefly(service);

        Assert.True(module.WasStarted);
    }

    [Fact]
    public async Task Execute_StartupEventTimestamp_IsRecent()
    {
        var before = DateTimeOffset.UtcNow;
        var (service, _, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        var startEvent = threatLog.GetAll().First(e => e.Title == "Agent Started");
        Assert.True(startEvent.Timestamp >= before);
        Assert.True(startEvent.Timestamp <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Execute_OnlyOneStartupEvent_Logged()
    {
        var (service, _, threatLog, _) = CreateServiceFull();

        await RunServiceBriefly(service);

        var startEvents = threatLog.GetAll().Where(e => e.Title == "Agent Started").ToList();
        Assert.Single(startEvents);
    }
}