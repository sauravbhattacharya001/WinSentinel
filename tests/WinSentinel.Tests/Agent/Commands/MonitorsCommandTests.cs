using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Tests.Agent.Commands;

public class MonitorsCommandTests
{
    private static ChatContext CreateContext(params string[] activeModules)
    {
        var state = new AgentState();
        var config = new AgentConfig();
        var threatLog = new ThreatLog();
        state.ThreatLog = threatLog;
        foreach (var m in activeModules)
            state.ActiveModules[m] = true;
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
    [InlineData("monitors")]
    [InlineData("active monitors")]
    [InlineData("list monitors")]
    public async Task TryExecuteAsync_MatchesTriggers(string input)
    {
        var cmd = new MonitorsCommand();
        var ctx = CreateContext("ProcessMonitor");

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        Assert.Equal(ChatResponseCategory.Status, result!.Category);
    }

    [Theory]
    [InlineData("status")]
    [InlineData("help")]
    [InlineData("monitor")]
    public async Task TryExecuteAsync_ReturnsNull_ForNonMonitorInput(string input)
    {
        var cmd = new MonitorsCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.Null(result);
    }

    [Fact]
    public async Task TryExecuteAsync_ListsActiveModules()
    {
        var cmd = new MonitorsCommand();
        var ctx = CreateContext("ProcessMonitor", "FileSystemMonitor");

        var result = await cmd.TryExecuteAsync("monitors", "monitors", ctx);

        Assert.NotNull(result);
        Assert.Contains("ProcessMonitor", result!.Text);
        Assert.Contains("FileSystemMonitor", result.Text);
    }

    [Fact]
    public async Task TryExecuteAsync_ShowsNoMonitors_WhenEmpty()
    {
        var cmd = new MonitorsCommand();
        var ctx = CreateContext();

        var result = await cmd.TryExecuteAsync("monitors", "monitors", ctx);

        Assert.NotNull(result);
        Assert.Contains("No monitors", result!.Text);
    }

    [Fact]
    public async Task TryExecuteAsync_UsesCorrectIcons()
    {
        var cmd = new MonitorsCommand();
        var ctx = CreateContext("ProcessMonitor", "FileSystemMonitor", "EventLogMonitor", "ScheduledAudit", "CustomModule");

        var result = await cmd.TryExecuteAsync("monitors", "monitors", ctx);

        Assert.NotNull(result);
        Assert.Contains("⚙️", result!.Text);  // ProcessMonitor
        Assert.Contains("📂", result.Text);    // FileSystemMonitor
        Assert.Contains("📋", result.Text);    // EventLogMonitor
        Assert.Contains("🔍", result.Text);    // ScheduledAudit
        Assert.Contains("🔹", result.Text);    // CustomModule (default)
    }
}
