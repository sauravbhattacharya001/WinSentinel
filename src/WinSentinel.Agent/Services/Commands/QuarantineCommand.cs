using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class QuarantineCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override bool CanHandle(string input) => input.StartsWith("quarantine ");

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var filePath = Core.Helpers.InputSanitizer.ValidateFilePath(input.Trim()[11..].Trim());
        if (filePath == null)
        {
            return Task.FromResult(SimpleResponse(
                "Invalid or protected file path. Path traversal, system files, and UNC paths are not allowed.",
                ChatResponseCategory.Error));
        }

        if (!System.IO.File.Exists(filePath))
        {
            return Task.FromResult(SimpleResponse($"❌ File not found: {filePath}", ChatResponseCategory.Error));
        }

        var record = context.Brain.Remediator.QuarantineFile(filePath,
            "chat-" + Guid.NewGuid().ToString("N")[..8]);
        context.Brain.Journal.RecordRemediation(record);

        return Task.FromResult(record.Success
            ? new ChatResponsePayload
            {
                Text = $"🗄️ **Quarantined: {Path.GetFileName(filePath)}**\nMoved to quarantine folder.",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = record.Id,
                SuggestedActions = { new SuggestedAction { Label = "↩️ Undo", Command = "undo" } }
            }
            : SimpleResponse($"❌ Failed to quarantine: {record.ErrorMessage}", ChatResponseCategory.Error));
    }
}
