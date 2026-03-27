using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class IgnoreCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override bool CanHandle(string input) => input.StartsWith("ignore ");

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var threatType = input.Trim()[7..].Trim();

        if (string.IsNullOrWhiteSpace(threatType) || threatType.Length > 256)
            return Task.FromResult(SimpleResponse("Invalid threat type. Must be 1–256 characters.", ChatResponseCategory.Error));

        if (threatType.Any(c => char.IsControl(c)))
            return Task.FromResult(SimpleResponse("Threat type contains invalid characters.", ChatResponseCategory.Error));

        context.Brain.Policy.AddUserOverride(threatType, UserOverrideAction.AlwaysIgnore);

        return Task.FromResult(new ChatResponsePayload
        {
            Text = $"🔕 **Ignoring:** \"{threatType}\"\nThis threat type will be suppressed in future detections.\nUse `policy` to review all overrides.",
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
