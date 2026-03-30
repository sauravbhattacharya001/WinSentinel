using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Tests.Agent.Commands;

public class ThreatsCommandTests
{
    private static ChatContext CreateContext(params ThreatEvent[] threats)
    {
        var state = new AgentState();
        var config = new AgentConfig();
        var threatLog = new ThreatLog();
        state.ThreatLog = threatLog;
        foreach (var t in threats)
            threatLog.Add(t);
        return new ChatContext
        {
            State = state,
            Config = config,
            Brain = null!,
            ThreatLog = threatLog,
            IpcServer = null!
        };
    }

    private static ThreatEvent MakeThreat(string title, ThreatSeverity severity, string source = "TestModule")
    {
        return new ThreatEvent
        {
            Title = title,
            Severity = severity,
            Source = source,
            Timestamp = DateTimeOffset.UtcNow,
            Description = $"Test threat: {title}"
        };
    }

    [Theory]
    [InlineData("threats")]
    [InlineData("show alerts")]
    [InlineData("what happened")]
    [InlineData("what happened?")]
    public async Task TryExecuteAsync_MatchesThreatTriggers(string input)
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        Assert.Equal(ChatResponseCategory.ThreatList, result!.Category);
    }

    [Theory]
    [InlineData("anything suspicious")]
    [InlineData("suspicious today")]
    [InlineData("any threats")]
    [InlineData("any alerts")]
    [InlineData("anything wrong")]
    public async Task TryExecuteAsync_MatchesSuspiciousTriggers(string input)
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
    }

    [Theory]
    [InlineData("status")]
    [InlineData("help")]
    [InlineData("scan")]
    public async Task TryExecuteAsync_ReturnsNull_ForNonThreatInput(string input)
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.Null(result);
    }

    [Fact]
    public async Task TryExecuteAsync_ShowsAllClear_WhenNoThreats()
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("threats", "threats", ctx);

        Assert.NotNull(result);
        Assert.Contains("No threats", result!.Text);
        Assert.Contains(result.SuggestedActions, a => a.Command == "scan");
    }

    [Fact]
    public async Task TryExecuteAsync_ListsThreats_WhenPresent()
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext(
            MakeThreat("Suspicious process", ThreatSeverity.High),
            MakeThreat("Open port detected", ThreatSeverity.Medium)
        );

        var result = await cmd.TryExecuteAsync("threats", "threats", ctx);

        Assert.NotNull(result);
        Assert.Contains("Suspicious process", result!.Text);
        Assert.Contains("Open port detected", result.Text);
        Assert.Equal(2, result.ThreatEvents.Count);
    }

    [Fact]
    public async Task TryExecuteAsync_SeverityIcons_AreCorrect()
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext(
            MakeThreat("Critical issue", ThreatSeverity.Critical),
            MakeThreat("High issue", ThreatSeverity.High),
            MakeThreat("Medium issue", ThreatSeverity.Medium)
        );

        var result = await cmd.TryExecuteAsync("threats", "threats", ctx);

        Assert.NotNull(result);
        Assert.Contains("🔴", result!.Text); // Critical
        Assert.Contains("🟠", result.Text);  // High
        Assert.Contains("🟡", result.Text);  // Medium
    }

    [Fact]
    public async Task TryExecuteAsync_SuspiciousToday_ShowsAllClear_WhenNoMediumOrHigher()
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext(
            MakeThreat("Low info", ThreatSeverity.Low)
        );

        var result = await cmd.TryExecuteAsync("anything suspicious", "anything suspicious", ctx);

        Assert.NotNull(result);
        Assert.Contains("Nothing suspicious", result!.Text);
    }

    [Fact]
    public async Task TryExecuteAsync_SuspiciousToday_ShowsMediumAndAbove()
    {
        var cmd = new ThreatsCommand();
        var ctx = CreateContext(
            MakeThreat("Critical firewall bypass", ThreatSeverity.Critical),
            MakeThreat("Low noise", ThreatSeverity.Low)
        );

        var result = await cmd.TryExecuteAsync("anything suspicious", "anything suspicious", ctx);

        Assert.NotNull(result);
        Assert.Contains("Critical firewall bypass", result!.Text);
        Assert.DoesNotContain("Low noise", result.Text);
    }

    [Fact]
    public async Task TryExecuteAsync_Caps_At15Threats()
    {
        var cmd = new ThreatsCommand();
        var threats = Enumerable.Range(0, 25)
            .Select(i => MakeThreat($"Threat {i}", ThreatSeverity.Medium))
            .ToArray();
        var ctx = CreateContext(threats);

        var result = await cmd.TryExecuteAsync("threats", "threats", ctx);

        Assert.NotNull(result);
        // Only 15 events in ThreatEvents list (display cap is 15)
        Assert.True(result!.ThreatEvents.Count <= 15);
        Assert.Contains("more", result.Text);
    }
}
