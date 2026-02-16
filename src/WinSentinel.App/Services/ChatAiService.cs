using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace WinSentinel.App.Services;

/// <summary>
/// Tiered AI backend: (1) Windows Copilot Runtime / Phi Silica, (2) Ollama, (3) Rule-based.
/// </summary>
public class ChatAiService
{
    private readonly HttpClient _httpClient = new();
    private AiBackend _activeBackend = AiBackend.Unknown;

    private enum AiBackend
    {
        Unknown,
        PhiSilica,
        Ollama,
        RuleBased
    }

    public async Task<string> GetResponseAsync(string userMessage)
    {
        if (_activeBackend == AiBackend.Unknown)
        {
            _activeBackend = await DetectBackendAsync();
        }

        return _activeBackend switch
        {
            AiBackend.Ollama => await GetOllamaResponseAsync(userMessage),
            _ => GetRuleBasedResponse(userMessage)
        };
    }

    private async Task<AiBackend> DetectBackendAsync()
    {
        // Try Ollama first
        try
        {
            var response = await _httpClient.GetAsync("http://localhost:11434/api/tags");
            if (response.IsSuccessStatusCode)
            {
                return AiBackend.Ollama;
            }
        }
        catch { /* Ollama not available */ }

        return AiBackend.RuleBased;
    }

    private async Task<string> GetOllamaResponseAsync(string userMessage)
    {
        try
        {
            var systemPrompt = "You are WinSentinel, a Windows security expert assistant. " +
                "Help users understand and improve their Windows security posture. " +
                "Be concise, practical, and provide actionable advice. " +
                "When suggesting fixes, include PowerShell or CMD commands when possible.";

            var request = new
            {
                model = "llama3",
                prompt = userMessage,
                system = systemPrompt,
                stream = false
            };

            var json = JsonSerializer.Serialize(request);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("http://localhost:11434/api/generate", content);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = await response.Content.ReadAsStringAsync();
                var doc = JsonDocument.Parse(responseJson);
                return doc.RootElement.GetProperty("response").GetString() ?? "No response generated.";
            }

            // Fallback to rule-based
            _activeBackend = AiBackend.RuleBased;
            return GetRuleBasedResponse(userMessage);
        }
        catch
        {
            _activeBackend = AiBackend.RuleBased;
            return GetRuleBasedResponse(userMessage);
        }
    }

    private string GetRuleBasedResponse(string input)
    {
        var lower = input.ToLowerInvariant();

        // Security knowledge base
        if (lower.Contains("password"))
            return "🔑 **Password Security Tips:**\n" +
                   "• Use at least 12 characters with mixed case, numbers, and symbols\n" +
                   "• Enable Windows Hello for biometric authentication\n" +
                   "• Use a password manager for unique passwords\n" +
                   "• Set minimum password length: `net accounts /minpwlen:12`\n" +
                   "• Enable account lockout: `net accounts /lockoutthreshold:5`";

        if (lower.Contains("ransomware"))
            return "🛡️ **Ransomware Protection:**\n" +
                   "• Enable Controlled Folder Access: `Set-MpPreference -EnableControlledFolderAccess Enabled`\n" +
                   "• Keep backups on disconnected/cloud storage\n" +
                   "• Enable cloud-delivered protection in Defender\n" +
                   "• Don't open email attachments from unknown senders\n" +
                   "• Keep all software updated";

        if (lower.Contains("vpn"))
            return "🌐 **VPN Recommendations:**\n" +
                   "• Use a reputable VPN provider with no-log policy\n" +
                   "• Windows has built-in VPN client: Settings > Network > VPN\n" +
                   "• For business: Consider Always-On VPN with certificate auth\n" +
                   "• Enable VPN kill switch to prevent data leaks";

        if (lower.Contains("encrypt"))
            return "🔒 **Encryption:**\n" +
                   "• Enable BitLocker: `manage-bde -on C:`\n" +
                   "• Check BitLocker status: `manage-bde -status`\n" +
                   "• Use EFS for individual files: Right-click > Properties > Advanced > Encrypt\n" +
                   "• Store BitLocker recovery key in a safe location";

        if (lower.Contains("malware") || lower.Contains("virus"))
            return "🦠 **Malware Protection:**\n" +
                   "• Run a quick scan: `Start-MpScan -ScanType QuickScan`\n" +
                   "• Run a full scan: `Start-MpScan -ScanType FullScan`\n" +
                   "• Update definitions: `Update-MpSignature`\n" +
                   "• Check protection status: `Get-MpComputerStatus`\n" +
                   "• Enable PUA protection: `Set-MpPreference -PUAProtection Enabled`";

        if (lower.Contains("backup"))
            return "💾 **Backup Best Practices:**\n" +
                   "• Enable File History: Settings > Update & Security > Backup\n" +
                   "• Create system image: `wbadmin start backup -backupTarget:D: -include:C:`\n" +
                   "• Use 3-2-1 rule: 3 copies, 2 different media, 1 offsite\n" +
                   "• Test your backups regularly!";

        if (lower.Contains("phishing"))
            return "🎣 **Anti-Phishing Tips:**\n" +
                   "• Enable SmartScreen: Settings > Privacy & Security > Windows Security\n" +
                   "• Check URLs carefully before clicking\n" +
                   "• Never enter credentials on unfamiliar sites\n" +
                   "• Enable multi-factor authentication everywhere\n" +
                   "• Report phishing: forward to phishing@microsoft.com";

        if (lower.Contains("help") || lower.Contains("what can you"))
            return "🛡️ **WinSentinel Commands:**\n" +
                   "• \"Run full audit\" — Complete security assessment\n" +
                   "• \"Check firewall\" — Firewall status & rules\n" +
                   "• \"Check updates\" — Windows Update status\n" +
                   "• \"Check defender\" — Antivirus status\n" +
                   "• \"Check accounts\" — User & admin accounts\n" +
                   "• \"Check network\" — Open ports & exposure\n" +
                   "• \"Check processes\" — Running process analysis\n" +
                   "• \"Check startup\" — Startup items & persistence\n" +
                   "• \"Check system\" — OS config & hardening\n" +
                   "• \"Security score\" — Calculate overall score\n\n" +
                   "You can also ask about passwords, ransomware, encryption, VPNs, and more!";

        return "🤔 I'm not sure about that specific topic. Try:\n" +
               "• \"Run full audit\" for a complete security check\n" +
               "• \"Help\" to see all available commands\n" +
               "• Ask about passwords, malware, encryption, backups, or phishing\n\n" +
               "💡 Tip: Connect Ollama (http://localhost:11434) for AI-powered responses!";
    }
}
