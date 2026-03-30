using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Tests.Agent.Commands;

public class StatusCommandTests
{
    private static ChatContext CreateContext(int? scanScore = null, DateTimeOffset? lastScan = null, bool scanRunning = false)
    {
        var state = new AgentState();
        var config = new AgentConfig { RiskTolerance = RiskTolerance.Medium };
        var threatLog = new ThreatLog();
        state.ThreatLog = threatLog;
        state.LastScanScore = scanScore;
        state.LastScanTime = lastScan;
        state.IsScanRunning = scanRunning;
        state.ActiveModules["ProcessMonitor"] = true;
        return new ChatContext
        {
            State = state,
            Config = config,
            Brain = null!,
            ThreatLog = threatLog,
            IpcServer = null!
        };
    }

    [Theory]
    [InlineData("status")]
    [InlineData("how are you")]
    [InlineData("how are you?")]
    [InlineData("security score")]
    [InlineData("score")]
    [InlineData("/score")]
    [InlineData("what's my score")]
    public async Task TryExecuteAsync_MatchesStatusTriggers(string input)
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext(scanScore: 85);

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        Assert.Equal(ChatResponseCategory.Status, result!.Category);
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("help")]
    [InlineData("threats")]
    public async Task TryExecuteAsync_ReturnsNull_ForNonStatusInput(string input)
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.Null(result);
    }

    [Fact]
    public async Task TryExecuteAsync_ShowsScoreAndGrade_WhenScanExists()
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext(scanScore: 92, lastScan: DateTimeOffset.UtcNow.AddHours(-1));

        var result = await cmd.TryExecuteAsync("status", "status", ctx);

        Assert.NotNull(result);
        Assert.Contains("92/100", result!.Text);
        Assert.Contains("Grade: A", result.Text);
        Assert.Equal(92, result.SecurityScore);
    }

    [Fact]
    public async Task TryExecuteAsync_ShowsNoScan_WhenNeverScanned()
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("status", "status", ctx);

        Assert.NotNull(result);
        Assert.Contains("No scan yet", result!.Text);
        Assert.Contains(result.SuggestedActions, a => a.Command == "scan");
    }

    [Fact]
    public async Task TryExecuteAsync_SuggestsFixAll_WhenScoreLow()
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext(scanScore: 55);

        var result = await cmd.TryExecuteAsync("status", "status", ctx);

        Assert.NotNull(result);
        Assert.Contains(result!.SuggestedActions, a => a.Command == "fix all");
    }

    [Fact]
    public async Task TryExecuteAsync_ShowsScanRunning()
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext(scanRunning: true);

        var result = await cmd.TryExecuteAsync("status", "status", ctx);

        Assert.NotNull(result);
        Assert.Contains("scan is currently running", result!.Text);
    }

    [Fact]
    public async Task TryExecuteAsync_ShowsRiskTolerance()
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("status", "status", ctx);

        Assert.NotNull(result);
        Assert.Contains("Medium", result!.Text);
    }

    [Theory]
    [InlineData(95, "A")]
    [InlineData(85, "B")]
    [InlineData(75, "C")]
    [InlineData(65, "D")]
    [InlineData(50, "F")]
    public async Task TryExecuteAsync_CorrectGradeForScore(int score, string expectedGrade)
    {
        var cmd = new StatusCommand();
        var ctx = CreateContext(scanScore: score);

        var result = await cmd.TryExecuteAsync("status", "status", ctx);

        Assert.NotNull(result);
        Assert.Contains($"Grade: {expectedGrade}", result!.Text);
    }
}
