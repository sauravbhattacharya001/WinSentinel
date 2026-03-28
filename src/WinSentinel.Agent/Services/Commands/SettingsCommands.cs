using System.Text;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: undo, ignore, policy, set risk, pause/resume monitoring, export.</summary>
public sealed class SettingsCommands : ChatCommandBase
{
    public override async Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower is "undo" or "undo last")
            return HandleUndoLast(context);

        if (lower.StartsWith("ignore "))
        {
            var threatType = raw[7..].Trim();
            if (string.IsNullOrWhiteSpace(threatType) || threatType.Length > 256)
                return SimpleResponse("Invalid threat type. Must be 1–256 characters.", ChatResponseCategory.Error);
            if (threatType.Any(c => char.IsControl(c)))
                return SimpleResponse("Threat type contains invalid characters.", ChatResponseCategory.Error);
            return HandleIgnore(threatType, context);
        }

        if (lower is "policy" or "show policies" or "show policy")
            return HandleShowPolicies(context);

        if (lower.StartsWith("set risk "))
            return HandleSetRisk(raw[9..].Trim(), context);

        if (lower is "pause monitoring" or "pause monitors" or "stop monitoring")
            return HandlePauseMonitoring(context);

        if (lower is "resume monitoring" or "start monitoring" or "unpause monitoring")
            return HandleResumeMonitoring(context);

        if (lower is "export" or "report" or "generate report")
            return await HandleExportAsync();

        return null;
    }

    private static ChatResponsePayload HandleUndoLast(ChatContext context)
    {
        var history = context.Brain.Remediator.GetRecent(1);
        if (history.Count == 0)
            return SimpleResponse("❌ No recent actions to undo.", ChatResponseCategory.General);

        var last = history[0];
        if (last.Undone)
            return SimpleResponse($"↩️ Last action was already undone: {last.Description}", ChatResponseCategory.General);

        var undoResult = context.Brain.UndoRemediation(last.Id);

        return undoResult.Success
            ? new ChatResponsePayload
            {
                Text = $"↩️ **Undone:** {undoResult.Description}",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SuggestedActions = { new SuggestedAction { Label = "📊 Status", Command = "status" } }
            }
            : SimpleResponse($"❌ Undo failed: {undoResult.ErrorMessage}", ChatResponseCategory.Error);
    }

    private static ChatResponsePayload HandleIgnore(string threatType, ChatContext context)
    {
        context.Brain.Policy.AddUserOverride(threatType, UserOverrideAction.AlwaysIgnore);

        return new ChatResponsePayload
        {
            Text = $"🔕 **Ignoring:** \"{threatType}\"\nThis threat type will be suppressed in future detections.\nUse `policy` to review all overrides.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📋 Policies", Command = "policy" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private static ChatResponsePayload HandleShowPolicies(ChatContext context)
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

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🎯 Set Risk Low", Command = "set risk low" },
                new SuggestedAction { Label = "🎯 Set Risk Medium", Command = "set risk medium" },
                new SuggestedAction { Label = "🎯 Set Risk High", Command = "set risk high" }
            }
        };
    }

    private static ChatResponsePayload HandleSetRisk(string level, ChatContext context)
    {
        if (!Enum.TryParse<RiskTolerance>(level, true, out var riskLevel))
        {
            return SimpleResponse("❌ Invalid risk level. Use: `set risk low`, `set risk medium`, or `set risk high`",
                ChatResponseCategory.Error);
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

        return new ChatResponsePayload
        {
            Text = $"🎯 **Risk tolerance set to: {riskLevel}**\n{description}",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📋 Policies", Command = "policy" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private static ChatResponsePayload HandlePauseMonitoring(ChatContext context)
    {
        var activeModules = context.State.ActiveModules.Where(kv => kv.Value).Select(kv => kv.Key).ToList();

        foreach (var module in activeModules)
            context.Config.ModuleToggles[module] = false;
        context.Config.Save();

        return new ChatResponsePayload
        {
            Text = $"⏸️ **Monitoring paused.**\n{activeModules.Count} modules flagged to pause.\nNote: Full pause takes effect after agent restart. Modules will stop accepting new events.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "▶️ Resume", Command = "resume monitoring" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private static ChatResponsePayload HandleResumeMonitoring(ChatContext context)
    {
        var toggledOff = context.Config.ModuleToggles.Where(kv => !kv.Value).Select(kv => kv.Key).ToList();

        foreach (var module in toggledOff)
            context.Config.ModuleToggles[module] = true;
        context.Config.Save();

        return new ChatResponsePayload
        {
            Text = $"▶️ **Monitoring resumed.**\n{toggledOff.Count} modules re-enabled.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📡 Monitors", Command = "monitors" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private static async Task<ChatResponsePayload> HandleExportAsync()
    {
        try
        {
            var engine = new AuditEngine();
            var report = await engine.RunFullAuditAsync(cancellationToken: CancellationToken.None);
            var generator = new ReportGenerator();

            var dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");
            Directory.CreateDirectory(dataDir);
            var reportPath = Path.Combine(dataDir, $"WinSentinel-Report-{DateTime.Now:yyyyMMdd-HHmmss}.html");

            var html = generator.GenerateHtmlReport(report);
            await File.WriteAllTextAsync(reportPath, html);

            return new ChatResponsePayload
            {
                Text = $"📄 **Report generated!**\nSaved to: `{reportPath}`\nScore: {report.SecurityScore}/100",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SecurityScore = report.SecurityScore,
                SuggestedActions = { new SuggestedAction { Label = "📊 Status", Command = "status" } }
            };
        }
        catch (Exception ex)
        {
            return SimpleResponse($"❌ Report generation failed: {ex.Message}", ChatResponseCategory.Error);
        }
    }
}
