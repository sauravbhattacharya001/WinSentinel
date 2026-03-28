using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Routes incoming chat messages through a pipeline of <see cref="IChatCommand"/>
/// implementations, returning the first match. Falls back to a default handler.
/// </summary>
public sealed class CommandRouter
{
    private readonly IReadOnlyList<IChatCommand> _commands;
    private readonly ILogger _logger;

    public CommandRouter(IEnumerable<IChatCommand> commands, ILogger logger)
    {
        _commands = commands.ToList();
        _logger = logger;
    }

    /// <summary>
    /// Route <paramref name="input"/> through registered commands.
    /// Returns the first non-null response, or null if no command matched.
    /// </summary>
    public async Task<ChatResponsePayload?> RouteAsync(string input, ChatContext context)
    {
        var trimmed = input.Trim();
        var lower = trimmed.ToLowerInvariant();

        foreach (var cmd in _commands)
        {
            var result = await cmd.TryExecuteAsync(trimmed, lower, context);
            if (result != null)
            {
                _logger.LogDebug("Chat routed to {Command}", cmd.GetType().Name);
                return result;
            }
        }

        return null;
    }
}
