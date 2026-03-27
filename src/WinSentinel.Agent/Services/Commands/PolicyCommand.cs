using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class PolicyCommand : ChatCommandBase
{
    public override string[] Triggers => ["policy", "show policies", "show policy"];

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var policy = context.Brain.Policy;
        var sb = new StringBuilder();
        sb.AppendLine("📋 **Response Policies**");
        sb.AppendLine();
        sb.AppendLine($"🎯 Risk Tolerance: **{policy.RiskTolerance}**");
        sb.AppendLine();

        if (policy.Rules.Count > 0)
        {
            sb.AppendLine($"**Custom Rules ({policy.Rules.Count}):**");
            foreach (var rule in policy.Rules.Take(10))
                sb.AppendLine($"  • {rule.TitlePattern ?? rule.Category?.ToString() ?? "All"} → {rule.Action} (priority {rule.Priority})");
            sb.AppendLine();
        }

        if (policy.UserOverrides.Count > 0)
        {
            sb.AppendLine($"**User Overrides ({policy.UserOverrides.Count}):**");
            foreach (var ov in policy.UserOverrides)
                sb.AppendLine($"  • \"{ov.ThreatTitle}\" → {ov.OverrideAction}");
        }
        else
        {
            sb.AppendLine("No user overrides set.");
        }

        return Task.FromResult(new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🎯 Set Risk Low", Command = "set risk low" },
                new SuggestedAction { Label = "🎯 Set Risk Medium", Command = "set risk medium" },
                new SuggestedAction { Label = "🎯 Set Risk High", Command = "set risk high" }
            }
        });
    }
}
