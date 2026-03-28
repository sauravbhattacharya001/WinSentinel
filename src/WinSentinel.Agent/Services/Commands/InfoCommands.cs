using System.Text;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: today, history, explain action, while away.</summary>
public sealed class InfoCommands : ChatCommandBase
{
    public override Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower is "today" or "daily summary" or "today's summary")
            return Task.FromResult<ChatResponsePayload?>(HandleTodaySummary(context));

        if (lower is "history" or "trend" or "trends" or "score history")
            return Task.FromResult<ChatResponsePayload?>(HandleHistory(context));

        if (MatchesAny(lower, "why did you kill", "why did you block", "why did you quarantine",
                "what did you do", "explain your action", "why that"))
            return Task.FromResult<ChatResponsePayload?>(HandleExplainAction(context));

        if (MatchesAny(lower, "what did you do while", "while i was away",
                "what happened while", "since i left", "what's new"))
            return Task.FromResult<ChatResponsePayload?>(HandleWhileAway(context));

        return Task.FromResult<ChatResponsePayload?>(null);
    }

    private static ChatResponsePayload HandleTodaySummary(ChatContext context)
    {
        var summary = context.Brain.Journal.GetTodaySummary();
        return new ChatResponsePayload
        {
            Text = summary.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📈 History", Command = "history" }
            }
        };
    }

    private static ChatResponsePayload HandleHistory(ChatContext context)
    {
        var weekSummary = context.Brain.Journal.GetWeekSummary();
        var sb = new StringBuilder();

        sb.AppendLine("📈 **Security History & Trends**");
        sb.AppendLine();

        if (context.State.LastScanScore.HasValue)
            sb.AppendLine($"🛡️ Current Score: {context.State.LastScanScore.Value}/100");

        sb.AppendLine();
        sb.AppendLine("📊 **This Week:**");
        sb.AppendLine($"  Threats: {weekSummary.ThreatsDetected}");
        sb.AppendLine($"  Actions: {weekSummary.ActionsTaken} (✓{weekSummary.SuccessfulRemediations} ✗{weekSummary.FailedRemediations})");
        sb.AppendLine($"  Correlations: {weekSummary.CorrelationsDetected}");
        sb.AppendLine($"  Severity: 🔴{weekSummary.CriticalCount} 🟠{weekSummary.HighCount} 🟡{weekSummary.MediumCount} ⚪{weekSummary.LowCount}");

        if (weekSummary.TopSources.Count > 0)
            sb.AppendLine($"  Top sources: {string.Join(", ", weekSummary.TopSources.Select(kv => $"{kv.Key}({kv.Value})"))}");

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SecurityScore = context.State.LastScanScore,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🔍 Run Scan", Command = "scan" },
                new SuggestedAction { Label = "📊 Today", Command = "today" }
            }
        };
    }

    private static ChatResponsePayload HandleExplainAction(ChatContext context)
    {
        var recentActions = context.Brain.Journal.Query(new JournalQuery
        {
            EntryType = JournalEntryType.ActionTaken,
            Limit = 5
        });

        if (recentActions.Count == 0)
            return SimpleResponse("No recent actions found in the journal.", ChatResponseCategory.General);

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

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.General,
            SuggestedActions =
            {
                new SuggestedAction { Label = "↩️ Undo Last", Command = "undo" },
                new SuggestedAction { Label = "📊 Today", Command = "today" }
            }
        };
    }

    private static ChatResponsePayload HandleWhileAway(ChatContext context)
    {
        var recent = context.Brain.Journal.Query(new JournalQuery
        {
            After = DateTimeOffset.UtcNow.AddHours(-24),
            Limit = 30
        });

        if (recent.Count == 0)
            return SimpleResponse("Nothing happened while you were away. All quiet! 😴", ChatResponseCategory.Status);

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

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }
}
