using System.Text;
using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: help, /help</summary>
public sealed class HelpCommand : ChatCommandBase
{
    public override Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower is not ("help" or "/help"))
            return Task.FromResult<ChatResponsePayload?>(null);

        var sb = new StringBuilder();
        sb.AppendLine("🛡️ **WinSentinel Agent — Chat Commands**");
        sb.AppendLine();
        sb.AppendLine("**Status & Info:**");
        sb.AppendLine("  `status` — Agent status, uptime, monitors, score");
        sb.AppendLine("  `monitors` — List active monitoring modules");
        sb.AppendLine("  `threats` — Recent threat events");
        sb.AppendLine("  `today` — Today's activity summary");
        sb.AppendLine("  `history` — Score history and trends");
        sb.AppendLine("  `policy` — Show response policies");
        sb.AppendLine();
        sb.AppendLine("**Scanning & Fixing:**");
        sb.AppendLine("  `scan` — Run full security audit");
        sb.AppendLine("  `scan <module>` — Scan specific module (firewall, network, etc.)");
        sb.AppendLine("  `fix <finding>` — Fix a specific finding");
        sb.AppendLine("  `fix all` — Fix all warnings & critical issues");
        sb.AppendLine();
        sb.AppendLine("**Actions:**");
        sb.AppendLine("  `block <ip>` — Add firewall block rule");
        sb.AppendLine("  `kill <process>` — Terminate a process");
        sb.AppendLine("  `quarantine <file>` — Move file to quarantine");
        sb.AppendLine("  `undo` — Revert last auto-remediation");
        sb.AppendLine("  `ignore <threat>` — Always ignore a threat type");
        sb.AppendLine();
        sb.AppendLine("**Settings:**");
        sb.AppendLine("  `set risk <low|medium|high>` — Change risk tolerance");
        sb.AppendLine("  `pause monitoring` / `resume monitoring`");
        sb.AppendLine("  `export` — Generate a security report");
        sb.AppendLine();
        sb.AppendLine("💡 You can also ask in natural language!");

        return Task.FromResult<ChatResponsePayload?>(new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Help,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Status", Command = "status" },
                new SuggestedAction { Label = "🔍 Scan", Command = "scan" },
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📈 History", Command = "history" }
            }
        });
    }
}
