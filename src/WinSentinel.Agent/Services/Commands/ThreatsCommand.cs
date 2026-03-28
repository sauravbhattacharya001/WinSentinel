using System.Text;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: threats, show alerts, what happened, anything suspicious.</summary>
public sealed class ThreatsCommand : ChatCommandBase
{
    public override Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower is "threats" or "show alerts" or "what happened" or "what happened?")
            return Task.FromResult<ChatResponsePayload?>(HandleThreats(context));

        if (MatchesAny(lower, "anything suspicious", "suspicious today", "any threats",
                "any alerts", "anything wrong"))
            return Task.FromResult<ChatResponsePayload?>(HandleSuspiciousToday(context));

        return Task.FromResult<ChatResponsePayload?>(null);
    }

    private static ChatResponsePayload HandleThreats(ChatContext context)
    {
        var threats = context.ThreatLog.GetRecent(20);
        var sb = new StringBuilder();

        if (threats.Count == 0)
        {
            sb.AppendLine("✅ **No threats detected.** All clear!");
            return new ChatResponsePayload
            {
                Text = sb.ToString(),
                Category = ChatResponseCategory.ThreatList,
                SuggestedActions = { new SuggestedAction { Label = "🔍 Run Scan", Command = "scan" } }
            };
        }

        sb.AppendLine($"⚠️ **Recent Threats** ({threats.Count} events)");
        sb.AppendLine();

        var chatThreats = new List<ChatThreatEvent>();

        foreach (var t in threats.Take(15))
        {
            var icon = t.Severity switch
            {
                ThreatSeverity.Critical => "🔴",
                ThreatSeverity.High => "🟠",
                ThreatSeverity.Medium => "🟡",
                ThreatSeverity.Low => "⚪",
                _ => "ℹ️"
            };

            var time = t.Timestamp.ToLocalTime().ToString("HH:mm:ss");
            sb.AppendLine($"{icon} [{time}] **{t.Title}**");
            sb.AppendLine($"   Source: {t.Source} | {(t.ResponseTaken ?? "No action")}");

            chatThreats.Add(new ChatThreatEvent
            {
                Id = t.Id,
                Timestamp = t.Timestamp,
                Source = t.Source,
                Severity = t.Severity.ToString(),
                Title = t.Title,
                ResponseTaken = t.ResponseTaken
            });
        }

        if (threats.Count > 15)
            sb.AppendLine($"\n... and {threats.Count - 15} more");

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.ThreatList,
            ThreatEvents = chatThreats,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Today's Summary", Command = "today" },
                new SuggestedAction { Label = "↩️ Undo Last", Command = "undo" }
            }
        };
    }

    private static ChatResponsePayload HandleSuspiciousToday(ChatContext context)
    {
        var todayThreats = context.ThreatLog.GetToday()
            .Where(t => t.Severity >= ThreatSeverity.Medium)
            .ToList();

        if (todayThreats.Count == 0)
        {
            return SimpleResponse("✅ Nothing suspicious today. All monitors report normal activity.",
                ChatResponseCategory.Status,
                new SuggestedAction { Label = "🔍 Run Scan", Command = "scan" });
        }

        var sb = new StringBuilder();
        sb.AppendLine($"⚠️ **{todayThreats.Count} suspicious event(s) today:**");
        sb.AppendLine();

        var chatThreats = new List<ChatThreatEvent>();
        foreach (var t in todayThreats.Take(10))
        {
            var icon = t.Severity switch
            {
                ThreatSeverity.Critical => "🔴",
                ThreatSeverity.High => "🟠",
                _ => "🟡"
            };
            sb.AppendLine($"{icon} **{t.Title}** ({t.Source})");
            sb.AppendLine($"   {t.Description}");

            chatThreats.Add(new ChatThreatEvent
            {
                Id = t.Id,
                Timestamp = t.Timestamp,
                Source = t.Source,
                Severity = t.Severity.ToString(),
                Title = t.Title,
                ResponseTaken = t.ResponseTaken
            });
        }

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.ThreatList,
            ThreatEvents = chatThreats,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Summary", Command = "today" },
                new SuggestedAction { Label = "↩️ Undo Last", Command = "undo" }
            }
        };
    }
}
