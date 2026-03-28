using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using WinSentinel.Agent.Ipc;

namespace WinSentinel.Agent.Services.Commands;

/// <summary>Handles: block &lt;ip&gt;, kill &lt;process&gt;, quarantine &lt;file&gt;, natural-language block.</summary>
public sealed partial class ActionCommands : ChatCommandBase
{
    public override Task<ChatResponsePayload?> TryExecuteAsync(string raw, string lower, ChatContext context)
    {
        if (lower.StartsWith("block "))
        {
            var ip = Core.Helpers.InputSanitizer.SanitizeIpAddress(raw[6..].Trim());
            if (ip != null)
                return Task.FromResult<ChatResponsePayload?>(HandleBlockIp(ip, context));
            return Task.FromResult<ChatResponsePayload?>(SimpleResponse(
                "Invalid IP address. Use a valid IPv4 or IPv6 address (e.g., `block 192.168.1.100`).",
                ChatResponseCategory.Error));
        }

        if (lower.StartsWith("kill "))
        {
            var proc = Core.Helpers.InputSanitizer.SanitizeProcessInput(raw[5..].Trim());
            if (proc == null)
                return Task.FromResult<ChatResponsePayload?>(SimpleResponse(
                    "Invalid process name or PID. Use a process name (e.g., notepad.exe) or PID (> 4).",
                    ChatResponseCategory.Error));
            return Task.FromResult<ChatResponsePayload?>(HandleKillProcess(proc, context));
        }

        if (lower.StartsWith("quarantine "))
        {
            var file = Core.Helpers.InputSanitizer.ValidateFilePath(raw[11..].Trim());
            if (file == null)
                return Task.FromResult<ChatResponsePayload?>(SimpleResponse(
                    "Invalid or protected file path. Path traversal, system files, and UNC paths are not allowed.",
                    ChatResponseCategory.Error));
            return Task.FromResult<ChatResponsePayload?>(HandleQuarantineFile(file, context));
        }

        if (BlockIpRegex().IsMatch(lower))
        {
            var ip = ExtractAndSanitizeIp(raw);
            if (ip != null)
                return Task.FromResult<ChatResponsePayload?>(HandleBlockIp(ip, context));
        }

        return Task.FromResult<ChatResponsePayload?>(null);
    }

    private static ChatResponsePayload HandleBlockIp(string ip, ChatContext context)
    {
        var record = context.Brain.Remediator.BlockIp(ip, "Blocked via chat command",
            "chat-" + Guid.NewGuid().ToString("N")[..8]);

        if (record.Success)
        {
            context.Brain.Journal.RecordRemediation(record);
            return new ChatResponsePayload
            {
                Text = $"🔥 **Blocked IP: {ip}**\nFirewall rule created to block all inbound traffic from this address.",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = record.Id,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "↩️ Undo", Command = "undo" },
                    new SuggestedAction { Label = "📊 Status", Command = "status" }
                }
            };
        }

        return SimpleResponse($"❌ Failed to block {ip}: {record.ErrorMessage}\n💡 Running as admin may be required.",
            ChatResponseCategory.Error);
    }

    private static ChatResponsePayload HandleKillProcess(string processInput, ChatContext context)
    {
        if (int.TryParse(processInput, out var pid))
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                var name = proc.ProcessName;
                var record = context.Brain.Remediator.KillProcess(pid, name,
                    "chat-" + Guid.NewGuid().ToString("N")[..8]);
                context.Brain.Journal.RecordRemediation(record);

                return record.Success
                    ? new ChatResponsePayload
                    {
                        Text = $"⚙️ **Killed process: {name} (PID {pid})**",
                        Category = ChatResponseCategory.ActionConfirmation,
                        ActionPerformed = true,
                        ActionId = record.Id
                    }
                    : SimpleResponse($"❌ Failed to kill PID {pid}: {record.ErrorMessage}", ChatResponseCategory.Error);
            }
            catch
            {
                return SimpleResponse($"❌ Process with PID {pid} not found.", ChatResponseCategory.Error);
            }
        }

        var processes = Process.GetProcessesByName(processInput.Replace(".exe", ""));
        if (processes.Length == 0)
            return SimpleResponse($"❌ No process named '{processInput}' found.", ChatResponseCategory.Error);

        if (processes.Length > 1)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"⚠️ Found {processes.Length} processes named '{processInput}':");
            foreach (var p in processes.Take(10))
                sb.AppendLine($"  PID {p.Id} — {p.ProcessName}");
            sb.AppendLine("\nSpecify a PID: `kill <pid>`");
            foreach (var p in processes) p.Dispose();
            return SimpleResponse(sb.ToString(), ChatResponseCategory.General);
        }

        var target = processes[0];
        var killRecord = context.Brain.Remediator.KillProcess(target.Id, target.ProcessName,
            "chat-" + Guid.NewGuid().ToString("N")[..8]);
        context.Brain.Journal.RecordRemediation(killRecord);
        target.Dispose();

        return killRecord.Success
            ? new ChatResponsePayload
            {
                Text = $"⚙️ **Killed process: {processInput} (PID {target.Id})**",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = killRecord.Id
            }
            : SimpleResponse($"❌ Failed to kill '{processInput}': {killRecord.ErrorMessage}", ChatResponseCategory.Error);
    }

    private static ChatResponsePayload HandleQuarantineFile(string filePath, ChatContext context)
    {
        if (!System.IO.File.Exists(filePath))
            return SimpleResponse($"❌ File not found: {filePath}", ChatResponseCategory.Error);

        var record = context.Brain.Remediator.QuarantineFile(filePath,
            "chat-" + Guid.NewGuid().ToString("N")[..8]);
        context.Brain.Journal.RecordRemediation(record);

        return record.Success
            ? new ChatResponsePayload
            {
                Text = $"🗄️ **Quarantined: {Path.GetFileName(filePath)}**\nMoved to quarantine folder.",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = record.Id,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "↩️ Undo", Command = "undo" }
                }
            }
            : SimpleResponse($"❌ Failed to quarantine: {record.ErrorMessage}", ChatResponseCategory.Error);
    }

    [GeneratedRegex(@"block.+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")]
    private static partial Regex BlockIpRegex();

    [GeneratedRegex(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")]
    private static partial Regex ExtractIpRegex();

    private static string? ExtractAndSanitizeIp(string text)
    {
        var match = ExtractIpRegex().Match(text);
        if (!match.Success) return null;
        return Core.Helpers.InputSanitizer.SanitizeIpAddress(match.Groups[1].Value);
    }
}
