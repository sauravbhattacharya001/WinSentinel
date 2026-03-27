using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class TodaySummaryCommand : ChatCommandBase
{
    public override string[] Triggers => ["today", "daily summary", "today's summary"];

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var summary = context.Brain.Journal.GetTodaySummary();
        return Task.FromResult(new ChatResponsePayload
        {
            Text = summary.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📈 History", Command = "history" }
            }
        });
    }
}
