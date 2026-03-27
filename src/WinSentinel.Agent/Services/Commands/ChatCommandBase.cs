using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Convenience base class for commands that only match on exact triggers.
/// </summary>
public abstract class ChatCommandBase : IChatCommand
{
    public abstract string[] Triggers { get; }

    /// <summary>Override for prefix/regex/NLP matching beyond exact triggers.</summary>
    public virtual bool CanHandle(string input) => false;

    public abstract Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context);

    protected static ChatResponsePayload SimpleResponse(string text, ChatResponseCategory category,
        params SuggestedAction[] actions)
    {
        var response = new ChatResponsePayload { Text = text, Category = category };
        foreach (var action in actions)
            response.SuggestedActions.Add(action);
        return response;
    }

    protected static bool MatchesAny(string input, params string[] patterns) =>
        patterns.Any(p => input.Contains(p, StringComparison.OrdinalIgnoreCase));
}
