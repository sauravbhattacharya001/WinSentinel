using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Services.Commands;

public sealed partial class BlockIpCommand : ChatCommandBase
{
    public override string[] Triggers => [];

    public override bool CanHandle(string input) =>
        input.StartsWith("block ") || BlockIpNlpRegex().IsMatch(input);

    public override Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        var trimmed = input.Trim();

        // Extract IP from "block <ip>" or natural language
        string? ip;
        if (trimmed.StartsWith("block ", StringComparison.OrdinalIgnoreCase))
        {
            ip = Core.Helpers.InputSanitizer.SanitizeIpAddress(trimmed[6..].Trim());
        }
        else
        {
            ip = ExtractAndSanitizeIp(trimmed);
        }

        if (ip == null)
        {
            return Task.FromResult(SimpleResponse(
                "Invalid IP address. Use a valid IPv4 or IPv6 address (e.g., `block 192.168.1.100`).",
                ChatResponseCategory.Error));
        }

        var record = context.Brain.Remediator.BlockIp(ip, "Blocked via chat command",
            "chat-" + Guid.NewGuid().ToString("N")[..8]);

        if (record.Success)
        {
            context.Brain.Journal.RecordRemediation(record);
            return Task.FromResult(new ChatResponsePayload
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
            });
        }

        return Task.FromResult(SimpleResponse(
            $"❌ Failed to block {ip}: {record.ErrorMessage}\n💡 Running as admin may be required.",
            ChatResponseCategory.Error));
    }

    [GeneratedRegex(@"block.+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")]
    private static partial Regex BlockIpNlpRegex();

    [GeneratedRegex(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")]
    private static partial Regex ExtractIpRegex();

    private static string? ExtractAndSanitizeIp(string text)
    {
        var match = ExtractIpRegex().Match(text);
        if (!match.Success) return null;
        return Core.Helpers.InputSanitizer.SanitizeIpAddress(match.Groups[1].Value);
    }
}
