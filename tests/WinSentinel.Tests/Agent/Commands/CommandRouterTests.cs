using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent.Ipc;
using WinSentinel.Agent.Services.Commands;

namespace WinSentinel.Tests.Agent.Commands;

public class CommandRouterTests
{
    private readonly ILogger _logger = NullLoggerFactory.Instance.CreateLogger("Test");

    private sealed class EchoCommand : IChatCommand
    {
        private readonly string _trigger;
        public EchoCommand(string trigger) => _trigger = trigger;

        public Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
        {
            if (lower == _trigger)
                return Task.FromResult<ChatResponsePayload?>(new ChatResponsePayload { Text = $"Matched: {_trigger}" });
            return Task.FromResult<ChatResponsePayload?>(null);
        }
    }

    private sealed class AlwaysNullCommand : IChatCommand
    {
        public Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context) =>
            Task.FromResult<ChatResponsePayload?>(null);
    }

    [Fact]
    public async Task RouteAsync_ReturnsFirstMatchingCommand()
    {
        var router = new CommandRouter(
            new IChatCommand[] { new EchoCommand("foo"), new EchoCommand("bar") },
            _logger);

        var result = await router.RouteAsync("foo", null!);

        Assert.NotNull(result);
        Assert.Equal("Matched: foo", result!.Text);
    }

    [Fact]
    public async Task RouteAsync_SkipsNonMatchingCommands()
    {
        var router = new CommandRouter(
            new IChatCommand[] { new AlwaysNullCommand(), new EchoCommand("bar") },
            _logger);

        var result = await router.RouteAsync("bar", null!);

        Assert.NotNull(result);
        Assert.Equal("Matched: bar", result!.Text);
    }

    [Fact]
    public async Task RouteAsync_ReturnsNull_WhenNoCommandMatches()
    {
        var router = new CommandRouter(
            new IChatCommand[] { new EchoCommand("foo") },
            _logger);

        var result = await router.RouteAsync("unmatched", null!);

        Assert.Null(result);
    }

    [Fact]
    public async Task RouteAsync_TrimsInput()
    {
        var router = new CommandRouter(
            new IChatCommand[] { new EchoCommand("hello") },
            _logger);

        var result = await router.RouteAsync("  hello  ", null!);

        Assert.NotNull(result);
        Assert.Equal("Matched: hello", result!.Text);
    }

    [Fact]
    public async Task RouteAsync_LowercasesInput()
    {
        var router = new CommandRouter(
            new IChatCommand[] { new EchoCommand("hello") },
            _logger);

        var result = await router.RouteAsync("HELLO", null!);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task RouteAsync_FirstMatchWins_NotLast()
    {
        var first = new EchoCommand("x");
        var second = new EchoCommand("x"); // also matches
        var router = new CommandRouter(new IChatCommand[] { first, second }, _logger);

        var result = await router.RouteAsync("x", null!);

        // Should get first match
        Assert.NotNull(result);
        Assert.Equal("Matched: x", result!.Text);
    }

    [Fact]
    public async Task RouteAsync_EmptyCommandList_ReturnsNull()
    {
        var router = new CommandRouter(Array.Empty<IChatCommand>(), _logger);

        var result = await router.RouteAsync("anything", null!);

        Assert.Null(result);
    }
}
