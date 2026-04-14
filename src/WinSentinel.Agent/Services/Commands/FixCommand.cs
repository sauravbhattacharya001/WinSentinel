using System.Text;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: fix &lt;target&gt;, fix all, /fix, /fixall, fix everything.</summary>
public sealed class FixCommand : ChatCommandBase
{
    public override async Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower.StartsWith("fix all") || lower is "/fixall" or "fix everything")
            return await HandleFixAllAsync();

        if (lower.StartsWith("fix ") || lower.StartsWith("/fix "))
        {
            var target = lower.StartsWith("/fix ") ? raw[5..].Trim() : raw[4..].Trim();
            return await HandleFixAsync(target);
        }

        return null;
    }

    private static async Task<ChatResponsePayload> HandleFixAllAsync()
    {
        var engine = new AuditEngine();
        var report = await engine.RunFullAuditAsync(cancellationToken: CancellationToken.None);

        var fixable = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity >= Severity.Warning && !string.IsNullOrEmpty(f.FixCommand))
            .ToList();

        if (fixable.Count == 0)
        {
            return SimpleResponse("✅ No fixable issues found. Your system looks good!",
                ChatResponseCategory.ActionConfirmation,
                new SuggestedAction { Label = "📊 Status", Command = "status" });
        }

        var fixEngine = new FixEngine();
        var sb = new StringBuilder();
        sb.AppendLine($"🔧 **Fixing {fixable.Count} issues...**");
        sb.AppendLine();

        int succeeded = 0, failed = 0, blocked = 0;
        foreach (var finding in fixable)
        {
            // Safety check: block dangerous commands (matches AutoRemediator & IpcServer)
            var dangerReason = Core.Helpers.InputSanitizer.CheckDangerousCommand(finding.FixCommand!);
            if (dangerReason != null)
            {
                sb.AppendLine($"  🚫 {finding.Title}: blocked by safety check ({dangerReason})");
                blocked++;
                continue;
            }

            var result = await fixEngine.ExecuteFixAsync(finding);
            if (result.Success)
            {
                sb.AppendLine($"  ✅ {finding.Title}");
                succeeded++;
            }
            else
            {
                sb.AppendLine($"  ❌ {finding.Title}: {result.Error}");
                failed++;
            }
        }

        sb.AppendLine();
        sb.AppendLine($"**Results:** {succeeded} fixed, {failed} failed" +
            (blocked > 0 ? $", {blocked} blocked by safety check" : ""));

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🔍 Re-Scan", Command = "scan" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private static async Task<ChatResponsePayload> HandleFixAsync(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return SimpleResponse("Usage: `fix <finding>` or `fix all`\nRun `scan` first to see available findings.",
                ChatResponseCategory.General);
        }

        var engine = new AuditEngine();
        var report = await engine.RunFullAuditAsync(cancellationToken: CancellationToken.None);

        var allFindings = report.Results.SelectMany(r => r.Findings).ToList();
        var match = SecurityAdvisor.FindBestMatch(allFindings, target);

        if (match == null)
        {
            return SimpleResponse(
                $"❌ No finding matching \"{target}\" found.\n" +
                "Available findings:\n" +
                string.Join("\n", allFindings
                    .Where(f => f.Severity >= Severity.Warning)
                    .Take(10)
                    .Select(f => $"  • {f.Title}")),
                ChatResponseCategory.Error,
                new SuggestedAction { Label = "🔍 Scan", Command = "scan" });
        }

        if (string.IsNullOrEmpty(match.FixCommand))
        {
            return SimpleResponse(
                $"⚠️ \"{match.Title}\" doesn't have an automated fix.\n" +
                (match.Remediation != null ? $"💡 Manual fix: {match.Remediation}" : ""),
                ChatResponseCategory.General);
        }

        // Safety check: block dangerous commands (matches AutoRemediator & IpcServer)
        var dangerReason = Core.Helpers.InputSanitizer.CheckDangerousCommand(match.FixCommand);
        if (dangerReason != null)
        {
            return SimpleResponse(
                $"🚫 **Blocked: {match.Title}**\nFix command rejected by safety check: {dangerReason}",
                ChatResponseCategory.Error);
        }

        var fixEngine = new FixEngine();
        var result = await fixEngine.ExecuteFixAsync(match);

        if (result.Success)
        {
            return new ChatResponsePayload
            {
                Text = $"✅ **Fixed: {match.Title}**\n{(result.Output != null ? $"Output: {result.Output}" : "")}",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "🔍 Re-Scan", Command = "scan" },
                    new SuggestedAction { Label = "🔧 Fix All", Command = "fix all" }
                }
            };
        }

        return new ChatResponsePayload
        {
            Text = $"❌ **Failed to fix: {match.Title}**\nError: {result.Error}" +
                   (result.RequiredElevation ? "\n💡 Try running WinSentinel as admin." : ""),
            Category = ChatResponseCategory.Error,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }
}
