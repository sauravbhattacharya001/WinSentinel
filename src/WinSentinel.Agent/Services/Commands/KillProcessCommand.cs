using System.Diagnostics;
using System.Text;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed class KillProcessCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override bool CanHandle(string input) => input.StartsWith("kill ");

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var processInput = Core.Helpers.InputSanitizer.SanitizeProcessInput(input.Trim()[5..].Trim());
        if (processInput == null)
        {
            return Task.FromResult(SimpleResponse(
                "Invalid process name or PID. Use a process name (e.g., notepad.exe) or PID (> 4).",
                ChatResponseCategory.Error));
        }

        if (int.TryParse(processInput, out var pid))
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                var name = proc.ProcessName;
                var record = context.Brain.Remediator.KillProcess(pid, name,
                    "chat-" + Guid.NewGuid().ToString("N")[..8]);
                context.Brain.Journal.RecordRemediation(record);

                return Task.FromResult(record.Success
                    ? new ChatResponsePayload
                    {
                        Text = $"⚙️ **Killed process: {name} (PID {pid})**",
                        Category = ChatResponseCategory.ActionConfirmation,
                        ActionPerformed = true,
                        ActionId = record.Id
                    }
                    : SimpleResponse($"❌ Failed to kill PID {pid}: {record.ErrorMessage}", ChatResponseCategory.Error));
            }
            catch
            {
                return Task.FromResult(SimpleResponse($"❌ Process with PID {pid} not found.", ChatResponseCategory.Error));
            }
        }

        var processes = Process.GetProcessesByName(processInput.Replace(".exe", ""));
        if (processes.Length == 0)
        {
            return Task.FromResult(SimpleResponse($"❌ No process named '{processInput}' found.", ChatResponseCategory.Error));
        }

        if (processes.Length > 1)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"⚠️ Found {processes.Length} processes named '{processInput}':");
            foreach (var p in processes.Take(10))
                sb.AppendLine($"  PID {p.Id} — {p.ProcessName}");
            sb.AppendLine("\nSpecify a PID: `kill <pid>`");
            foreach (var p in processes) p.Dispose();
            return Task.FromResult(SimpleResponse(sb.ToString(), ChatResponseCategory.General));
        }

        var target = processes[0];
        var killRecord = context.Brain.Remediator.KillProcess(target.Id, target.ProcessName,
            "chat-" + Guid.NewGuid().ToString("N")[..8]);
        context.Brain.Journal.RecordRemediation(killRecord);
        var targetId = target.Id;
        target.Dispose();

        return Task.FromResult(killRecord.Success
            ? new ChatResponsePayload
            {
                Text = $"⚙️ **Killed process: {processInput} (PID {targetId})**",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = killRecord.Id
            }
            : SimpleResponse($"❌ Failed to kill '{processInput}': {killRecord.ErrorMessage}", ChatResponseCategory.Error));
    }
}
