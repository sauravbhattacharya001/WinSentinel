using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class UndoCommand : ChatCommandBase
{
    public override string[] Triggers => ["undo", "undo last"];

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var history = context.Brain.Remediator.GetRecent(1);
        if (history.Count == 0)
            return Task.FromResult(SimpleResponse("❌ No recent actions to undo.", ChatResponseCategory.General));

        var last = history[0];
        if (last.Undone)
            return Task.FromResult(SimpleResponse($"↩️ Last action was already undone: {last.Description}", ChatResponseCategory.General));

        var undoResult = context.Brain.UndoRemediation(last.Id);

        return Task.FromResult(undoResult.Success
            ? new ChatResponsePayload
            {
                Text = $"↩️ **Undone:** {undoResult.Description}",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SuggestedActions = { new SuggestedAction { Label = "📊 Status", Command = "status" } }
            }
            : SimpleResponse($"❌ Undo failed: {undoResult.ErrorMessage}", ChatResponseCategory.Error));
    }
}
