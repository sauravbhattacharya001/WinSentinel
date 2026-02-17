using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Services;

namespace WinSentinel.Agent;

/// <summary>
/// Main orchestrator service for the WinSentinel agent.
/// Manages agent modules, coordinates with IPC server, the Agent Brain, and maintains agent state.
/// </summary>
public class AgentService : BackgroundService
{
    private readonly ILogger<AgentService> _logger;
    private readonly AgentState _state;
    private readonly AgentConfig _config;
    private readonly ThreatLog _threatLog;
    private readonly IpcServer _ipcServer;
    private readonly AgentBrain _brain;
    private readonly ChatHandler _chatHandler;
    private readonly IEnumerable<IAgentModule> _modules;

    public AgentService(
        ILogger<AgentService> logger,
        AgentState state,
        AgentConfig config,
        ThreatLog threatLog,
        IpcServer ipcServer,
        AgentBrain brain,
        ChatHandler chatHandler,
        IEnumerable<IAgentModule> modules)
    {
        _logger = logger;
        _state = state;
        _config = config;
        _threatLog = threatLog;
        _ipcServer = ipcServer;
        _brain = brain;
        _chatHandler = chatHandler;
        _modules = modules;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WinSentinel Agent starting...");

        // Initialize state
        _state.StartTime = DateTimeOffset.UtcNow;
        _state.ThreatLog = _threatLog;
        _threatLog.SetMaxSize(_config.MaxThreatLogSize);

        // Initialize the Agent Brain (decision engine)
        _brain.Initialize();

        // Initialize the Chat Handler (chat as control plane)
        _chatHandler.Initialize();

        // Log startup threat event
        _threatLog.Add(new ThreatEvent
        {
            Source = "Agent",
            Severity = ThreatSeverity.Info,
            Title = "Agent Started",
            Description = $"WinSentinel Agent v{_state.Version} started successfully."
        });

        // Start all enabled modules
        var moduleTasks = new List<Task>();
        foreach (var module in _modules)
        {
            if (!_config.IsModuleEnabled(module.Name))
            {
                _logger.LogInformation("Module {Name} is disabled, skipping", module.Name);
                continue;
            }

            _logger.LogInformation("Starting module: {Name}", module.Name);
            _state.ActiveModules[module.Name] = true;

            try
            {
                await module.StartAsync(stoppingToken);
                _logger.LogInformation("Module {Name} started", module.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start module {Name}", module.Name);
                _state.ActiveModules[module.Name] = false;
            }
        }

        _logger.LogInformation("WinSentinel Agent is running. Modules active: {Count}",
            _state.ActiveModules.Count(kv => kv.Value));

        // Keep running until stopped
        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException) { }

        // Shutdown
        _logger.LogInformation("WinSentinel Agent shutting down...");

        // Shut down the brain and chat handler first
        _chatHandler.Shutdown();
        _brain.Shutdown();

        foreach (var module in _modules)
        {
            try
            {
                await module.StopAsync(CancellationToken.None);
                _state.ActiveModules[module.Name] = false;
                _logger.LogInformation("Module {Name} stopped", module.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping module {Name}", module.Name);
            }
        }

        _logger.LogInformation("WinSentinel Agent stopped.");
    }
}
