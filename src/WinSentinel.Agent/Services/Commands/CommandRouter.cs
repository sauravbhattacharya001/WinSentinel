using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Routes incoming chat messages to the appropriate <see cref="IChatCommand"/>.
/// Commands are registered in priority order: exact triggers first, then
/// fuzzy/NLP matchers, with a fallback for unrecognized input.
/// </summary>
public sealed class CommandRouter
{
    private readonly Dictionary<string, IChatCommand> _triggerMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<IChatCommand> _commands = [];
    private readonly IChatCommand _fallback;

    public CommandRouter(IEnumerable<IChatCommand> commands, IChatCommand fallback)
    {
        _fallback = fallback;

        foreach (var cmd in commands)
        {
            _commands.Add(cmd);
            foreach (var trigger in cmd.Triggers)
            {
                _triggerMap[trigger] = cmd;
            }
        }
    }

    /// <summary>
    /// Find the best command for the input. Checks exact triggers first,
    /// then falls through to CanHandle, then fallback.
    /// </summary>
    public IChatCommand Route(string input)
    {
        var lower = input.Trim().ToLowerInvariant();

        // 1. Exact trigger match
        if (_triggerMap.TryGetValue(lower, out var exact))
            return exact;

        // 2. Fuzzy / prefix / NLP match
        foreach (var cmd in _commands)
        {
            if (cmd.CanHandle(lower))
                return cmd;
        }

        // 3. Fallback
        return _fallback;
    }
}
