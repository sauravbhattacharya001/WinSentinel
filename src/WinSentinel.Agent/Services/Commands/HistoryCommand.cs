using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class HistoryCommand : ChatCommandBase
{
    public override string[] Triggers => ["history", "trend", "trends", "score history"];

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var sb = new StringBuilder();
        var weekSummary = context.Brain.Journal.GetWeekSummary();

        sb.AppendLine("📈 **Security History & Trends**");
        sb.AppendLine();

        if (context.State.LastScanScore.HasValue)
        {
            sb.AppendLine($"🛡️ Current Score: {context.State.LastScanScore.Value}/100");
        }

        sb.AppendLine();
        sb.AppendLine($"📊 **This Week:**");
        sb.AppendLine($"  Threats: {weekSummary.ThreatsDetected}");
        sb.AppendLine($"  Actions: {weekSummary.ActionsTaken} (✓{weekSummary.SuccessfulRemediations} ✗{weekSummary.FailedRemediations})");
        sb.AppendLine($"  Correlations: {weekSummary.CorrelationsDetected}");
        sb.AppendLine($"  Severity: 🔴{weekSummary.CriticalCount} 🟠{weekSummary.HighCount} 🟡{weekSummary.MediumCount} ⚪{weekSummary.LowCount}");

        if (weekSummary.TopSources.Count > 0)
        {
            sb.AppendLine($"  Top sources: {string.Join(", ", weekSummary.TopSources.Select(kv => $"{kv.Key}({kv.Value})"))}");
        }

        return Task.FromResult(new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SecurityScore = context.State.LastScanScore,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🔍 Run Scan", Command = "scan" },
                new SuggestedAction { Label = "📊 Today", Command = "today" }
            }
        });
    }
}
