using System.Text;
using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: monitors, active monitors, list monitors.</summary>
public sealed class MonitorsCommand : ChatCommandBase
{
    public override Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower is not ("monitors" or "active monitors" or "list monitors"))
            return Task.FromResult<ChatResponsePayload?>(null);

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

        return Task.FromResult<ChatResponsePayload?>(new ChatResponsePayload
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
