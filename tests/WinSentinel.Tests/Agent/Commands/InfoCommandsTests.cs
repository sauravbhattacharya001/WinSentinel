using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Tests.Agent.Commands;

public class InfoCommandsTests : IDisposable
{
    private readonly string _tempDir;

    public InfoCommandsTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"winsentinel_infotest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    private ChatContext CreateContext(int? scanScore = null, Action<AgentJournal>? seedJournal = null)
    {
        var log = new ThreatLog();
        var config = new AgentConfig { RiskTolerance = RiskTolerance.Medium };
        var policy = ResponsePolicy.CreateDefault(RiskTolerance.Medium);
        var correlator = new ThreatCorrelator(new NullLogger<ThreatCorrelator>());
        var remediator = new AutoRemediator(new NullLogger<AutoRemediator>());
        var journalPath = Path.Combine(_tempDir, $"journal_{Guid.NewGuid():N}.jsonl");
        var journal = new AgentJournal(new NullLogger<AgentJournal>(), journalPath);

        seedJournal?.Invoke(journal);

        var brain = new AgentBrain(
            new NullLogger<AgentBrain>(),
            policy,
            correlator,
            remediator,
            journal,
            log,
            config);

        var state = new AgentState { ThreatLog = log, LastScanScore = scanScore };

        return new ChatContext
        {
            State = state,
            Config = config,
            Brain = brain,
            ThreatLog = log,
            IpcServer = null!
        };
    }

    // ── Trigger matching ──

    [Theory]
    [InlineData("today")]
    [InlineData("daily summary")]
    [InlineData("today's summary")]
    public async Task TryExecuteAsync_MatchesTodayTriggers(string input)
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        Assert.Equal(ChatResponseCategory.Status, result!.Category);
    }

    [Theory]
    [InlineData("history")]
    [InlineData("trend")]
    [InlineData("trends")]
    [InlineData("score history")]
    public async Task TryExecuteAsync_MatchesHistoryTriggers(string input)
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        Assert.Equal(ChatResponseCategory.Status, result!.Category);
    }

    [Theory]
    [InlineData("why did you kill that process")]
    [InlineData("why did you block the connection")]
    [InlineData("what did you do")]
    [InlineData("explain your action")]
    public async Task TryExecuteAsync_MatchesExplainTriggers(string input)
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        // Even with no actions, it should still return a response (not null)
        Assert.Equal(ChatResponseCategory.General, result!.Category);
    }

    [Theory]
    [InlineData("while i was away")]
    [InlineData("what happened while I was gone")]
    [InlineData("since i left")]
    [InlineData("what's new")]
    public async Task TryExecuteAsync_MatchesWhileAwayTriggers(string input)
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        Assert.Equal(ChatResponseCategory.Status, result!.Category);
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("help")]
    [InlineData("status")]
    [InlineData("fix all")]
    public async Task TryExecuteAsync_ReturnsNull_ForUnmatchedInput(string input)
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.Null(result);
    }

    // ── Today summary content ──

    [Fact]
    public async Task Today_IncludesSuggestedActions()
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("today", "today", ctx);

        Assert.NotNull(result);
        Assert.Contains(result!.SuggestedActions, a => a.Command == "threats");
        Assert.Contains(result.SuggestedActions, a => a.Command == "history");
    }

    // ── History with score ──

    [Fact]
    public async Task History_ShowsCurrentScore_WhenAvailable()
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext(scanScore: 87);

        var result = await cmd.TryExecuteAsync("history", "history", ctx);

        Assert.NotNull(result);
        Assert.Contains("87/100", result!.Text);
        Assert.Contains("Security History", result.Text);
    }

    [Fact]
    public async Task History_ShowsWeekSummary()
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("history", "history", ctx);

        Assert.NotNull(result);
        Assert.Contains("This Week", result!.Text);
        Assert.Contains("Threats:", result.Text);
        Assert.Contains("Actions:", result.Text);
    }

    // ── Explain action ──

    [Fact]
    public async Task ExplainAction_ShowsNoActionsMessage_WhenEmpty()
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("what did you do", "what did you do", ctx);

        Assert.NotNull(result);
        Assert.Contains("No recent actions", result!.Text);
    }

    [Fact]
    public async Task ExplainAction_ShowsActions_WhenPresent()
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext(seedJournal: journal =>
        {
            journal.Record(new JournalEntry
            {
                EntryType = JournalEntryType.ActionTaken,
                Summary = "Blocked suspicious connection to 198.51.100.1",
                Details = "Outbound connection to known C2 server",
                PolicyDecision = "Auto-block: critical threat"
            });
        });

        var result = await cmd.TryExecuteAsync("what did you do", "what did you do", ctx);

        Assert.NotNull(result);
        Assert.Contains("Recent Agent Actions", result!.Text);
        Assert.Contains("Blocked suspicious connection", result.Text);
        Assert.Contains("Auto-block: critical threat", result.Text);
    }

    // ── While away ──

    [Fact]
    public async Task WhileAway_ShowsQuietMessage_WhenNoEvents()
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("what's new", "what's new", ctx);

        Assert.NotNull(result);
        Assert.Contains("All quiet", result!.Text);
    }

    [Fact]
    public async Task WhileAway_ShowsThreatsAndActions_WhenPresent()
    {
        var cmd = new InfoCommands();
        var ctx = CreateContext(seedJournal: journal =>
        {
            journal.Record(new JournalEntry
            {
                EntryType = JournalEntryType.ThreatDetected,
                Summary = "Suspicious PowerShell execution detected",
                Severity = ThreatSeverity.High
            });
            journal.Record(new JournalEntry
            {
                EntryType = JournalEntryType.ActionTaken,
                Summary = "Terminated suspicious process (PID 4521)"
            });
            journal.Record(new JournalEntry
            {
                EntryType = JournalEntryType.CorrelationDetected,
                Summary = "Correlated: PowerShell + network anomaly"
            });
        });

        var result = await cmd.TryExecuteAsync("since i left", "since i left", ctx);

        Assert.NotNull(result);
        Assert.Contains("Activity in the last 24 hours", result!.Text);
        Assert.Contains("threats detected", result.Text);
        Assert.Contains("Suspicious PowerShell", result.Text);
        Assert.Contains("actions taken", result.Text);
        Assert.Contains("correlations detected", result.Text);
    }
}
