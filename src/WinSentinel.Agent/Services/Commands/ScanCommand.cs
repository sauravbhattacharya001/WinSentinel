using System.Text;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: scan, /scan, run audit, scan &lt;module&gt;, scan network.</summary>
public sealed class ScanCommand : ChatCommandBase
{
    public override async Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower is "scan" or "/scan" or "run audit" or "run scan" or "full scan")
            return await ExecuteScanAsync(null, context);

        if (lower is "scan network" or "network scan")
            return await ExecuteScanAsync("network", context);

        if (lower.StartsWith("scan ") || lower.StartsWith("/scan "))
        {
            var module = lower.StartsWith("/scan ") ? raw[6..].Trim() : raw[5..].Trim();
            return await ExecuteScanAsync(module, context);
        }

        if (MatchesAny(lower, "is my firewall ok", "firewall status", "check firewall",
                "firewall check", "how is my firewall"))
            return await ExecuteScanAsync("firewall", context);

        return null;
    }

    private static async Task<ChatResponsePayload> ExecuteScanAsync(string? module, ChatContext context)
    {
        if (context.State.IsScanRunning)
        {
            return SimpleResponse("⏳ A scan is already running. Please wait for it to complete.",
                ChatResponseCategory.General,
                new SuggestedAction { Label = "📊 Status", Command = "status" });
        }

        if (!string.IsNullOrEmpty(module))
        {
            var engine = new AuditEngine();
            var result = await engine.RunSingleAuditAsync(module, CancellationToken.None);

            if (result == null)
            {
                return SimpleResponse(
                    $"❌ No audit module found for '{module}'.\n" +
                    "Available: firewall, updates, defender, accounts, network, processes, startup, system, privacy, browser",
                    ChatResponseCategory.Error);
            }

            var score = SecurityScorer.CalculateCategoryScore(result);
            var sb = new StringBuilder();
            sb.AppendLine($"🔍 **{result.ModuleName}** — Score: {score}/100");
            sb.AppendLine();

            foreach (var f in result.Findings.OrderByDescending(f => f.Severity))
            {
                var icon = f.Severity switch
                {
                    Severity.Critical => "🔴",
                    Severity.Warning => "🟡",
                    Severity.Info => "ℹ️",
                    _ => "✅"
                };
                sb.AppendLine($"  {icon} **{f.Title}** — {f.Description}");
                if (f.FixCommand != null)
                    sb.AppendLine($"     🔧 Auto-fix: `fix {f.Title}`");
            }

            var response = new ChatResponsePayload
            {
                Text = sb.ToString(),
                Category = ChatResponseCategory.AuditResult,
                SecurityScore = score
            };

            var fixable = result.Findings.Count(f => f.Severity >= Severity.Warning && f.FixCommand != null);
            if (fixable > 0)
                response.SuggestedActions.Add(new SuggestedAction { Label = $"🔧 Fix {fixable} Issues", Command = "fix all" });

            response.SuggestedActions.Add(new SuggestedAction { Label = "🔍 Full Scan", Command = "scan" });
            return response;
        }

        // Trigger full audit via agent's IPC
        _ = Task.Run(async () =>
        {
            try
            {
                await context.IpcServer.TriggerAuditAsync();
            }
            catch
            {
                // Logged elsewhere
            }
        });

        return new ChatResponsePayload
        {
            Text = "🔍 **Full security audit started!**\n\nThis will take a minute. I'll update you when it's done.\nUse `status` to check progress.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Status", Command = "status" },
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" }
            }
        };
    }
}
