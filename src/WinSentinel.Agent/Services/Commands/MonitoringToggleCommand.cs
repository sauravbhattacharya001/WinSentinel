using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class MonitoringToggleCommand : ChatCommandBase
{
    public override string[] Triggers =>
        ["pause monitoring", "pause monitors", "stop monitoring",
         "resume monitoring", "start monitoring", "unpause monitoring"];

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var lower = input.Trim().ToLowerInvariant();
        var isPause = lower.Contains("pause") || lower.Contains("stop");

        if (isPause)
        {
            var activeModules = context.State.ActiveModules.Where(kv => kv.Value).Select(kv => kv.Key).ToList();
            foreach (var module in activeModules)
                context.Config.ModuleToggles[module] = false;
            context.Config.Save();

            return Task.FromResult(new ChatResponsePayload
            {
                Text = $"⏸️ **Monitoring paused.**\n{activeModules.Count} modules flagged to pause.\nNote: Full pause takes effect after agent restart. Modules will stop accepting new events.",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "▶️ Resume", Command = "resume monitoring" },
                    new SuggestedAction { Label = "📊 Status", Command = "status" }
                }
            });
        }

        var toggledOff = context.Config.ModuleToggles.Where(kv => !kv.Value).Select(kv => kv.Key).ToList();
        foreach (var module in toggledOff)
            context.Config.ModuleToggles[module] = true;
        context.Config.Save();

        return Task.FromResult(new ChatResponsePayload
        {
            Text = $"▶️ **Monitoring resumed.**\n{toggledOff.Count} modules re-enabled.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📡 Monitors", Command = "monitors" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        });
    }
}
