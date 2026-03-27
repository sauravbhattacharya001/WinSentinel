using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>
/// Fallback handler for unrecognized input. Always matches (used as the
/// default in <see cref="CommandRouter"/>).
/// </summary>
public sealed class FallbackCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        return Task.FromResult(new ChatResponsePayload
        {
            Text = $"🤔 I'm not sure how to handle \"{input}\".\n\n" +
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
