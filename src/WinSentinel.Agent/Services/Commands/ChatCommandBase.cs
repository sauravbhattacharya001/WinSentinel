using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Base class with shared helpers for chat commands.</summary>
public abstract class ChatCommandBase : IChatCommand
{
    public abstract Task<ChatResponsePayload?> TryExecuteAsync(
        string raw, string lower, ChatContext context);

    protected static ChatResponsePayload SimpleResponse(
        string text, ChatResponseCategory category, params SuggestedAction[] actions)
    {
        var response = new ChatResponsePayload { Text = text, Category = category };
        foreach (var action in actions)
            response.SuggestedActions.Add(action);
        return response;
    }

    protected static bool MatchesAny(string input, params string[] patterns) =>
        patterns.Any(p => input.Contains(p, StringComparison.OrdinalIgnoreCase));
}
