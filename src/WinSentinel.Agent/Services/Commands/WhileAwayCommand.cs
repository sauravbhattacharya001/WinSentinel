using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class WhileAwayCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override bool CanHandle(string input) =>
        MatchesAny(input, "what did you do while", "while i was away",
            "what happened while", "since i left", "what's new");

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var recent = context.Brain.Journal.Query(new JournalQuery
        {
            After = DateTimeOffset.UtcNow.AddHours(-24),
            Limit = 30
        });

        if (recent.Count == 0)
            return Task.FromResult(SimpleResponse("Nothing happened while you were away. All quiet! 😴", ChatResponseCategory.Status));

        var sb = new StringBuilder();
        sb.AppendLine($"📋 **Activity in the last 24 hours** ({recent.Count} events):");
        sb.AppendLine();

        var threats = recent.Where(e => e.EntryType == JournalEntryType.ThreatDetected).ToList();
        var actions = recent.Where(e => e.EntryType == JournalEntryType.ActionTaken).ToList();
        var correlations = recent.Where(e => e.EntryType == JournalEntryType.CorrelationDetected).ToList();

        if (threats.Count > 0)
        {
            sb.AppendLine($"⚠️ **{threats.Count} threats detected:**");
            foreach (var t in threats.Take(5)) sb.AppendLine($"  • {t.Summary}");
            if (threats.Count > 5) sb.AppendLine($"  ... and {threats.Count - 5} more");
            sb.AppendLine();
        }

        if (actions.Count > 0)
        {
            sb.AppendLine($"🔧 **{actions.Count} actions taken:**");
            foreach (var a in actions.Take(5)) sb.AppendLine($"  • {a.Summary}");
            sb.AppendLine();
        }

        if (correlations.Count > 0)
        {
            sb.AppendLine($"🔗 **{correlations.Count} correlations detected:**");
            foreach (var c in correlations.Take(3)) sb.AppendLine($"  • {c.Summary}");
            sb.AppendLine();
        }

        return Task.FromResult(new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        });
    }
}
