using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Tests.Agent.Commands;

public class FallbackCommandTests
{
    [Fact]
    public async Task TryExecuteAsync_AlwaysReturns_NonNull()
    {
        var cmd = new FallbackCommand();

        var result = await cmd.TryExecuteAsync("random input", "random input", null!);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task TryExecuteAsync_IncludesOriginalInput()
    {
        var cmd = new FallbackCommand();

        var result = await cmd.TryExecuteAsync("do a backflip", "do a backflip", null!);

        Assert.NotNull(result);
        Assert.Contains("do a backflip", result!.Text);
    }

    [Fact]
    public async Task TryExecuteAsync_CategoryIsHelp()
    {
        var cmd = new FallbackCommand();

        var result = await cmd.TryExecuteAsync("xyz", "xyz", null!);

        Assert.Equal(ChatResponseCategory.Help, result!.Category);
    }

    [Fact]
    public async Task TryExecuteAsync_HasSuggestedActions()
    {
        var cmd = new FallbackCommand();

        var result = await cmd.TryExecuteAsync("xyz", "xyz", null!);

        Assert.True(result!.SuggestedActions.Count >= 2);
        Assert.Contains(result.SuggestedActions, a => a.Command == "help");
        Assert.Contains(result.SuggestedActions, a => a.Command == "status");
    }
}
