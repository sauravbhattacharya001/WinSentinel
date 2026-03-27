using System.Text;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services.Commands;

public sealed class ScanCommand : ChatCommandBase
{
    public override string[] Triggers =>
        ["scan", "/scan", "run audit", "run scan", "full scan", "scan network", "network scan"];

    public override bool CanHandle(string input) =>
        input.StartsWith("scan ") || input.StartsWith("/scan ") ||
        MatchesAny(input, "is my firewall ok", "firewall status", "check firewall",
            "firewall check", "how is my firewall");

    public override async Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var lower = input.Trim().ToLowerInvariant();

        // Determine module
        string? module = null;
        if (lower == "scan network" || lower == "network scan")
            module = "network";
        else if (MatchesAny(lower, "firewall"))
            module = "firewall";
        else if (lower.StartsWith("scan ") && lower != "scan")
            module = input.Trim()["scan ".Length..].Trim();
        else if (lower.StartsWith("/scan "))
            module = input.Trim()["/scan ".Length..].Trim();

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

        // Full scan — fire and forget
        _ = Task.Run(async () =>
        {
            try { await context.IpcServer.TriggerAuditAsync(); }
            catch (Exception ex) { context.Logger.LogError(ex, "Error running audit from chat"); }
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
