using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class SetRiskCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override bool CanHandle(string input) => input.StartsWith("set risk ");

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var level = input.Trim()[9..].Trim();

        if (!Enum.TryParse<RiskTolerance>(level, true, out var riskLevel))
        {
            return Task.FromResult(SimpleResponse(
                "❌ Invalid risk level. Use: `set risk low`, `set risk medium`, or `set risk high`",
                ChatResponseCategory.Error));
        }

        context.Config.RiskTolerance = riskLevel;
        context.Config.Save();
        context.Brain.Policy.RiskTolerance = riskLevel;
        context.Brain.Policy.Save();

        var description = riskLevel switch
        {
            RiskTolerance.Low => "Aggressive — scan frequently, alert on everything, auto-fix critical",
            RiskTolerance.Medium => "Balanced — standard intervals, alert on critical+high",
            RiskTolerance.High => "Relaxed — scan less often, only alert on critical",
            _ => ""
        };

        return Task.FromResult(new ChatResponsePayload
        {
            Text = $"🎯 **Risk tolerance set to: {riskLevel}**\n{description}",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📋 Policies", Command = "policy" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        });
    }
}
