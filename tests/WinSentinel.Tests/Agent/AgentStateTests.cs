using WinSentinel.Agent;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for AgentState tracking.
/// </summary>
public class AgentStateTests
{
    [Fact]
    public void New_AgentState_Has_Valid_Defaults()
    {
        var state = new AgentState();

        Assert.True(state.Uptime.TotalMilliseconds >= 0);
        Assert.Null(state.LastScanTime);
        Assert.Null(state.LastScanScore);
        Assert.False(state.IsScanRunning);
        Assert.Empty(state.ActiveModules);
        Assert.NotEmpty(state.Version);
    }

    [Fact]
    public void Uptime_Increases_Over_Time()
    {
        var state = new AgentState
        {
            StartTime = DateTimeOffset.UtcNow.AddMinutes(-5)
        };

        Assert.True(state.Uptime.TotalMinutes >= 4.9);
    }

    [Fact]
    public void ToSnapshot_Captures_Current_State()
    {
        var threatLog = new ThreatLog();
        var state = new AgentState
        {
            StartTime = DateTimeOffset.UtcNow.AddHours(-2),
            LastScanTime = DateTimeOffset.UtcNow.AddMinutes(-30),
            LastScanScore = 92,
            IsScanRunning = true,
            ThreatLog = threatLog
        };
        state.ActiveModules["ScheduledAudit"] = true;
        state.ActiveModules["ProcessMonitor"] = true;

        var snapshot = state.ToSnapshot();

        Assert.True(snapshot.UptimeSeconds >= 7100); // ~2 hours
        Assert.Equal(92, snapshot.LastScanScore);
        Assert.True(snapshot.IsScanRunning);
        Assert.Equal(2, snapshot.ActiveModules.Count);
        Assert.Contains("ScheduledAudit", snapshot.ActiveModules);
        Assert.Contains("ProcessMonitor", snapshot.ActiveModules);
    }

    [Fact]
    public void ActiveModules_Only_Includes_True_Entries()
    {
        var state = new AgentState();
        state.ActiveModules["Active"] = true;
        state.ActiveModules["Inactive"] = false;

        var snapshot = state.ToSnapshot();

        Assert.Single(snapshot.ActiveModules);
        Assert.Contains("Active", snapshot.ActiveModules);
    }

    [Fact]
    public void ThreatsDetectedToday_Uses_ThreatLog()
    {
        var threatLog = new ThreatLog();
        threatLog.Add(new ThreatEvent
        {
            Source = "Test",
            Severity = ThreatSeverity.High,
            Title = "Test Threat",
            Description = "Test"
        });

        var state = new AgentState { ThreatLog = threatLog };

        Assert.Equal(1, state.ThreatsDetectedToday);
    }

    [Fact]
    public void ThreatsDetectedToday_Returns_Zero_Without_ThreatLog()
    {
        var state = new AgentState();
        Assert.Equal(0, state.ThreatsDetectedToday);
    }
}
