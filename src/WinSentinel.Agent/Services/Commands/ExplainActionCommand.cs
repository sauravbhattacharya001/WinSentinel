using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class ExplainActionCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override bool CanHandle(string input) =>
        MatchesAny(input, "why did you kill", "why did you block", "why did you quarantine",
            "what did you do", "explain your action", "why that");

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var recentActions = context.Brain.Journal.Query(new JournalQuery
        {
            EntryType = JournalEntryType.ActionTaken,
            Limit = 5
        });

        if (recentActions.Count == 0)
            return Task.FromResult(SimpleResponse("No recent actions found in the journal.", ChatResponseCategory.General));

        var sb = new StringBuilder();
        sb.AppendLine("📝 **Recent Agent Actions:**");
        sb.AppendLine();

        foreach (var entry in recentActions)
        {
            sb.AppendLine($"⏱️ {entry.Timestamp.ToLocalTime():MMM dd HH:mm}");
            sb.AppendLine($"  {entry.Summary}");
            if (entry.Details != null) sb.AppendLine($"  📋 {entry.Details}");
            if (entry.PolicyDecision != null) sb.AppendLine($"  🧠 Decision: {entry.PolicyDecision}");
            sb.AppendLine();
        }

        return Task.FromResult(new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.General,
            SuggestedActions =
            {
                new SuggestedAction { Label = "↩️ Undo Last", Command = "undo" },
                new SuggestedAction { Label = "📊 Today", Command = "today" }
            }
        });
    }
}
