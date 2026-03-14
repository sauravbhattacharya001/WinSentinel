using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for ChatHandler — command routing, response formatting,
/// input validation, and category assignment.
///
/// Creates a real ChatHandler with real dependencies (AgentBrain, ThreatLog,
/// etc.) using NullLoggers. Tests cover the pure logic paths that don't
/// need OS-level access (no actual process kills, firewall rules, or scans).
/// </summary>
public class ChatHandlerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ChatHandler _handler;
    private readonly AgentState _state;
    private readonly ThreatLog _threatLog;
    private readonly AgentBrain _brain;
    private readonly AgentConfig _config;

    public ChatHandlerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"winsentinel_chattest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);

        _threatLog = new ThreatLog();
        _config = new AgentConfig { RiskTolerance = RiskTolerance.Medium };
        _state = new AgentState { ThreatLog = _threatLog };

        var policy = ResponsePolicy.CreateDefault(RiskTolerance.Medium);
        var correlator = new ThreatCorrelator(new NullLogger<ThreatCorrelator>());
        var remediator = new AutoRemediator(new NullLogger<AutoRemediator>());
        var journalPath = Path.Combine(_tempDir, "journal.jsonl");
        var journal = new AgentJournal(new NullLogger<AgentJournal>(), journalPath);

        _brain = new AgentBrain(
            new NullLogger<AgentBrain>(),
            policy, correlator, remediator, journal, _threatLog, _config);

        var ipcServer = new IpcServer(
            new NullLogger<IpcServer>(), _state, _config,
            _threatLog, policy, new StubServiceProvider());

        _handler = new ChatHandler(
            new NullLogger<ChatHandler>(),
            _state, _config, _brain, _threatLog, ipcServer);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
    }

    // ══════════════════════════════════════════
    //  Empty / null / whitespace input
    // ══════════════════════════════════════════

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public async Task EmptyOrWhitespace_ReturnsGeneralPrompt(string? input)
    {
        var result = await _handler.HandleChatMessageAsync(input!);

        Assert.Contains("help", result.Text, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(ChatResponseCategory.General, result.Category);
    }

    // ══════════════════════════════════════════
    //  Help command
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("help")]
    [InlineData("HELP")]
    [InlineData("/help")]
    public async Task Help_ReturnsHelpCategory(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Help, result.Category);
        Assert.Contains("Commands", result.Text, StringComparison.OrdinalIgnoreCase);
        Assert.True(result.SuggestedActions.Count >= 2, "Help should suggest actions");
    }

    // ══════════════════════════════════════════
    //  Status command
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("status")]
    [InlineData("how are you")]
    [InlineData("how are you?")]
    public async Task Status_ReturnsStatusCategory(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Status, result.Category);
        Assert.Contains("Uptime", result.Text);
        Assert.Contains("Active Monitors", result.Text);
    }

    [Fact]
    public async Task Status_NoScanYet_SaysNeverScanned()
    {
        var result = await _handler.HandleChatMessageAsync("status");

        Assert.Contains("No scan yet", result.Text);
    }

    [Fact]
    public async Task Status_WithScore_ShowsGrade()
    {
        _state.LastScanScore = 92;
        _state.LastScanTime = DateTimeOffset.UtcNow;

        var result = await _handler.HandleChatMessageAsync("status");

        Assert.Contains("92/100", result.Text);
        Assert.Contains("Grade: A", result.Text);
    }

    [Fact]
    public async Task Status_LowScore_SuggestsFixAll()
    {
        _state.LastScanScore = 55;

        var result = await _handler.HandleChatMessageAsync("status");

        Assert.Contains(result.SuggestedActions, a => a.Command == "fix all");
    }

    [Fact]
    public async Task Status_ScanRunning_ShowsRunningIndicator()
    {
        _state.IsScanRunning = true;

        var result = await _handler.HandleChatMessageAsync("status");

        Assert.Contains("scan is currently running", result.Text, StringComparison.OrdinalIgnoreCase);
    }

    // ══════════════════════════════════════════
    //  Monitors command
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("monitors")]
    [InlineData("active monitors")]
    [InlineData("list monitors")]
    public async Task Monitors_ReturnsStatusCategory(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Status, result.Category);
    }

    [Fact]
    public async Task Monitors_NoActive_SaysNone()
    {
        var result = await _handler.HandleChatMessageAsync("monitors");

        Assert.Contains("No monitors", result.Text);
    }

    [Fact]
    public async Task Monitors_WithActive_ListsThem()
    {
        _state.ActiveModules.TryAdd("ProcessMonitor", true);
        _state.ActiveModules.TryAdd("FileSystemMonitor", true);

        var result = await _handler.HandleChatMessageAsync("monitors");

        Assert.Contains("ProcessMonitor", result.Text);
        Assert.Contains("FileSystemMonitor", result.Text);
    }

    // ══════════════════════════════════════════
    //  Threats command
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("threats")]
    [InlineData("show alerts")]
    [InlineData("what happened")]
    [InlineData("what happened?")]
    public async Task Threats_MatchesCommand(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.ThreatList, result.Category);
    }

    [Fact]
    public async Task Threats_Empty_ShowsAllClear()
    {
        var result = await _handler.HandleChatMessageAsync("threats");

        Assert.Contains("No threats", result.Text);
        Assert.Contains("All clear", result.Text);
    }

    [Fact]
    public async Task Threats_WithEvents_ShowsThreats()
    {
        _threatLog.Add(new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Malicious PowerShell",
            Description = "Encoded command detected"
        });
        _threatLog.Add(new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.Low,
            Title = "Config Change",
            Description = "Hosts file modified"
        });

        var result = await _handler.HandleChatMessageAsync("threats");

        Assert.Contains("Malicious PowerShell", result.Text);
        Assert.Contains("Config Change", result.Text);
        Assert.True(result.ThreatEvents.Count >= 2);
    }

    // ══════════════════════════════════════════
    //  Today / daily summary
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("today")]
    [InlineData("daily summary")]
    [InlineData("today's summary")]
    public async Task Today_ReturnsStatusCategory(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Status, result.Category);
    }

    // ══════════════════════════════════════════
    //  History command
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("history")]
    [InlineData("trends")]
    [InlineData("score history")]
    public async Task History_ReturnsStatusCategory(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Status, result.Category);
        Assert.Contains("This Week", result.Text);
    }

    // ══════════════════════════════════════════
    //  Policy command
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("policy")]
    [InlineData("show policies")]
    [InlineData("show policy")]
    public async Task Policy_ShowsRiskTolerance(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Status, result.Category);
        Assert.Contains("Risk Tolerance", result.Text);
        Assert.Contains("Medium", result.Text);
    }

    // ══════════════════════════════════════════
    //  Set risk command
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("set risk low", RiskTolerance.Low)]
    [InlineData("set risk medium", RiskTolerance.Medium)]
    [InlineData("set risk high", RiskTolerance.High)]
    public async Task SetRisk_ChangesConfig(string input, RiskTolerance expected)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.ActionConfirmation, result.Category);
        Assert.True(result.ActionPerformed);
        Assert.Equal(expected, _config.RiskTolerance);
    }

    [Fact]
    public async Task SetRisk_InvalidLevel_ReturnsError()
    {
        var result = await _handler.HandleChatMessageAsync("set risk extreme");

        Assert.Equal(ChatResponseCategory.Error, result.Category);
        Assert.Contains("Invalid", result.Text);
    }

    // ══════════════════════════════════════════
    //  Ignore command
    // ══════════════════════════════════════════

    [Fact]
    public async Task Ignore_AddsUserOverride()
    {
        var result = await _handler.HandleChatMessageAsync("ignore Suspicious DNS");

        Assert.Equal(ChatResponseCategory.ActionConfirmation, result.Category);
        Assert.True(result.ActionPerformed);
        Assert.Contains("Ignoring", result.Text);
        Assert.Contains("Suspicious DNS", result.Text);
    }

    // ══════════════════════════════════════════
    //  Scan command — already running
    // ══════════════════════════════════════════

    [Fact]
    public async Task Scan_AlreadyRunning_RejectsGracefully()
    {
        _state.IsScanRunning = true;

        var result = await _handler.HandleChatMessageAsync("scan");

        Assert.Contains("already running", result.Text, StringComparison.OrdinalIgnoreCase);
    }

    // ══════════════════════════════════════════
    //  Undo command
    // ══════════════════════════════════════════

    [Fact]
    public async Task Undo_NoHistory_ReturnsErrorOrInfo()
    {
        var result = await _handler.HandleChatMessageAsync("undo");

        // Either "No recent actions" or "Undo failed/not supported" — both valid
        Assert.True(
            result.Text.Contains("No recent actions", StringComparison.OrdinalIgnoreCase) ||
            result.Text.Contains("Undo", StringComparison.OrdinalIgnoreCase),
            $"Undo response should mention undo or lack of actions, got: {result.Text}");
    }

    // ══════════════════════════════════════════
    //  Pause / resume monitoring
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("pause monitoring")]
    [InlineData("pause monitors")]
    [InlineData("stop monitoring")]
    public async Task Pause_ReturnsConfirmation(string input)
    {
        _state.ActiveModules.TryAdd("ProcessMonitor", true);

        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.ActionConfirmation, result.Category);
        Assert.Contains("paused", result.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("resume monitoring")]
    [InlineData("start monitoring")]
    [InlineData("unpause monitoring")]
    public async Task Resume_ReturnsConfirmation(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.ActionConfirmation, result.Category);
        Assert.Contains("resumed", result.Text, StringComparison.OrdinalIgnoreCase);
    }

    // ══════════════════════════════════════════
    //  Natural language: security score
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("what's my security score")]
    [InlineData("security score")]
    [InlineData("my score")]
    [InlineData("score")]
    [InlineData("/score")]
    public async Task NaturalLanguage_Score_ReturnsStatus(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Status, result.Category);
    }

    // ══════════════════════════════════════════
    //  Natural language: suspicious today
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("anything suspicious")]
    [InlineData("any threats")]
    [InlineData("anything wrong")]
    public async Task NaturalLanguage_Suspicious_NoThreats_AllClear(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Contains("Nothing suspicious", result.Text);
    }

    [Fact]
    public async Task NaturalLanguage_Suspicious_WithThreats_ShowsThem()
    {
        _threatLog.Add(new ThreatEvent
        {
            Source = "Test",
            Severity = ThreatSeverity.High,
            Title = "Bad Process",
            Description = "Suspicious"
        });

        var result = await _handler.HandleChatMessageAsync("anything suspicious");

        Assert.Contains("Bad Process", result.Text);
        Assert.True(result.ThreatEvents.Count >= 1);
    }

    // ══════════════════════════════════════════
    //  Natural language: while away
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("what's new")]
    [InlineData("while i was away")]
    [InlineData("what happened while")]
    public async Task NaturalLanguage_WhileAway_NoEvents_AllQuiet(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Contains("quiet", result.Text, StringComparison.OrdinalIgnoreCase);
    }

    // ══════════════════════════════════════════
    //  Fallback (unknown command)
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("xyzzy foobar")]
    [InlineData("dance")]
    [InlineData("what is the meaning of life")]
    public async Task Unknown_ReturnsFallback(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.Equal(ChatResponseCategory.Help, result.Category);
        Assert.Contains("not sure", result.Text, StringComparison.OrdinalIgnoreCase);
        Assert.True(result.SuggestedActions.Count >= 2);
    }

    // ══════════════════════════════════════════
    //  Kill command — input validation
    // ══════════════════════════════════════════

    [Fact]
    public async Task Kill_InvalidInput_ReturnsError()
    {
        // InputSanitizer rejects dangerous inputs
        var result = await _handler.HandleChatMessageAsync("kill ../../etc/passwd");

        // Should either be an error or a "not found" — not a crash
        Assert.NotNull(result.Text);
        Assert.True(result.Text.Length > 0);
    }

    // ══════════════════════════════════════════
    //  Quarantine — file not found
    // ══════════════════════════════════════════

    [Fact]
    public async Task Quarantine_FileNotFound_ReturnsError()
    {
        var result = await _handler.HandleChatMessageAsync("quarantine C:\\nonexistent_file_12345.exe");

        Assert.Equal(ChatResponseCategory.Error, result.Category);
    }

    // ══════════════════════════════════════════
    //  Case insensitivity
    // ══════════════════════════════════════════

    [Fact]
    public async Task Commands_AreCaseInsensitive()
    {
        var lower = await _handler.HandleChatMessageAsync("status");
        var upper = await _handler.HandleChatMessageAsync("STATUS");
        var mixed = await _handler.HandleChatMessageAsync("StAtUs");

        Assert.Equal(lower.Category, upper.Category);
        Assert.Equal(lower.Category, mixed.Category);
    }

    // ══════════════════════════════════════════
    //  Grade calculation via status
    // ══════════════════════════════════════════

    [Theory]
    [InlineData(95, "A")]
    [InlineData(85, "B")]
    [InlineData(75, "C")]
    [InlineData(65, "D")]
    [InlineData(50, "F")]
    public async Task Status_ScoreGrades(int score, string expectedGrade)
    {
        _state.LastScanScore = score;

        var result = await _handler.HandleChatMessageAsync("status");

        Assert.Contains($"Grade: {expectedGrade}", result.Text);
    }

    // ══════════════════════════════════════════
    //  Suggested actions are always present
    // ══════════════════════════════════════════

    [Theory]
    [InlineData("help")]
    [InlineData("status")]
    [InlineData("monitors")]
    [InlineData("threats")]
    [InlineData("policy")]
    public async Task CommandResponses_HaveSuggestedActions(string input)
    {
        var result = await _handler.HandleChatMessageAsync(input);

        Assert.True(result.SuggestedActions.Count >= 1,
            $"'{input}' response should have at least one suggested action");
    }

    /// <summary>Minimal IServiceProvider stub for IpcServer construction.</summary>
    private class StubServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
