using System.Text;
using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: status, how are you, security score queries.</summary>
public sealed class StatusCommand : ChatCommandBase
{
    public override Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower is not ("status" or "how are you" or "how are you?") &&
            !MatchesAny(lower, "what's my security score", "what is my security score",
                "security score", "my score", "what's my score", "score", "/score"))
            return Task.FromResult<ChatResponsePayload?>(null);

        var snapshot = context.State.ToSnapshot();
        var uptime = TimeSpan.FromSeconds(snapshot.UptimeSeconds);
        var uptimeStr = uptime.TotalDays >= 1
            ? $"{(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m"
            : uptime.TotalHours >= 1
                ? $"{uptime.Hours}h {uptime.Minutes}m"
                : $"{uptime.Minutes}m {uptime.Seconds}s";

        var sb = new StringBuilder();
        sb.AppendLine("🛡️ **WinSentinel Agent Status**");
        sb.AppendLine();
        sb.AppendLine($"⏱️ Uptime: {uptimeStr}");
        sb.AppendLine($"📡 Active Monitors: {snapshot.ActiveModules.Count} ({string.Join(", ", snapshot.ActiveModules)})");
        sb.AppendLine($"⚠️ Threats Today: {snapshot.ThreatsDetectedToday}");

        if (snapshot.LastScanScore.HasValue)
        {
            var score = snapshot.LastScanScore.Value;
            var grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
            sb.AppendLine($"🛡️ Security Score: {score}/100 (Grade: {grade})");
        }
        else
        {
            sb.AppendLine("🛡️ Security Score: No scan yet");
        }

        if (snapshot.LastScanTime.HasValue)
            sb.AppendLine($"🔍 Last Scan: {snapshot.LastScanTime.Value.ToLocalTime():MMM dd, HH:mm}");
        else
            sb.AppendLine("🔍 Last Scan: Never");

        sb.AppendLine($"🔧 Risk Tolerance: {context.Config.RiskTolerance}");
        sb.AppendLine($"📋 Version: {snapshot.Version}");

        if (snapshot.IsScanRunning)
            sb.AppendLine("\n⏳ A scan is currently running...");

        var response = new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SecurityScore = snapshot.LastScanScore
        };

        if (!snapshot.LastScanScore.HasValue)
            response.SuggestedActions.Add(new SuggestedAction { Label = "🔍 Run First Scan", Command = "scan" });
        else if (snapshot.LastScanScore < 70)
            response.SuggestedActions.Add(new SuggestedAction { Label = "🔧 Fix All", Command = "fix all" });

        if (snapshot.ThreatsDetectedToday > 0)
            response.SuggestedActions.Add(new SuggestedAction { Label = "⚠️ View Threats", Command = "threats" });

        response.SuggestedActions.Add(new SuggestedAction { Label = "📈 History", Command = "history" });

        return Task.FromResult<ChatResponsePayload?>(response);
    }
}
