using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class MonitorsCommand : ChatCommandBase
{
    public override string[] Triggers => ["monitors", "active monitors", "list monitors"];

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var snapshot = context.State.ToSnapshot();
        var sb = new StringBuilder();
        sb.AppendLine("📡 **Active Monitoring Modules**");
        sb.AppendLine();

        if (snapshot.ActiveModules.Count == 0)
        {
            sb.AppendLine("No monitors currently active.");
        }
        else
        {
            foreach (var module in snapshot.ActiveModules)
            {
                var icon = module switch
                {
                    "ProcessMonitor" => "⚙️",
                    "FileSystemMonitor" => "📂",
                    "EventLogMonitor" => "📋",
                    "ScheduledAudit" => "🔍",
                    _ => "🔹"
                };
                sb.AppendLine($"  {icon} {module} — Running");
            }
        }

        return Task.FromResult(new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⏸️ Pause", Command = "pause monitoring" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        });
    }
}
