using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Tests.Agent.Commands;

public class HelpCommandTests
{
    private static ChatContext CreateMinimalContext()
    {
        var state = new AgentState();
        var config = new AgentConfig();
        var threatLog = new ThreatLog();
        state.ThreatLog = threatLog;
        // ChatContext requires Brain and IpcServer but HelpCommand never touches them
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
    [InlineData("help")]
    [InlineData("/help")]
    public async Task TryExecuteAsync_MatchesHelpTriggers(string input)
    {
        var cmd = new HelpCommand();
        var ctx = CreateMinimalContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.NotNull(result);
        Assert.Equal(ChatResponseCategory.Help, result!.Category);
        Assert.Contains("Chat Commands", result.Text);
    }

    [Theory]
    [InlineData("status")]
    [InlineData("scan")]
    [InlineData("helping")]
    [InlineData("")]
    public async Task TryExecuteAsync_ReturnsNull_ForNonHelpInput(string input)
    {
        var cmd = new HelpCommand();
        var ctx = CreateMinimalContext();

        var result = await cmd.TryExecuteAsync(input, input.ToLowerInvariant(), ctx);

        Assert.Null(result);
    }

    [Fact]
    public async Task TryExecuteAsync_IncludesSuggestedActions()
    {
        var cmd = new HelpCommand();
        var ctx = CreateMinimalContext();

        var result = await cmd.TryExecuteAsync("help", "help", ctx);

        Assert.NotNull(result);
        Assert.True(result!.SuggestedActions.Count >= 3);
        Assert.Contains(result.SuggestedActions, a => a.Command == "status");
        Assert.Contains(result.SuggestedActions, a => a.Command == "scan");
    }
}
