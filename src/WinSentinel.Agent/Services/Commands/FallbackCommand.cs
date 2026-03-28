using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Fallback handler for unrecognized commands.</summary>
public sealed class FallbackCommand : ChatCommandBase
{
    /// <summary>Always matches — must be registered last in the pipeline.</summary>
    public override Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        return Task.FromResult<ChatResponsePayload?>(new ChatResponsePayload
        {
            Text = $"🤔 I'm not sure how to handle \"{raw}\".\n\n" +
                   "Try:\n" +
                   "  • `status` — Check agent status\n" +
                   "  • `scan` — Run a security audit\n" +
                   "  • `threats` — View recent threats\n" +
                   "  • `help` — See all commands\n\n" +
                   "💡 Or ask in natural language: \"What's my security score?\", \"Anything suspicious today?\"",
            Category = ChatResponseCategory.Help,
            SuggestedActions =
            {
                new SuggestedAction { Label = "❓ Help", Command = "help" },
                new SuggestedAction { Label = "📊 Status", Command = "status" },
                new SuggestedAction { Label = "🔍 Scan", Command = "scan" }
            }
        });
    }
}
