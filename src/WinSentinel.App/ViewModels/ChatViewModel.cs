using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using WinSentinel.App.Services;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.ViewModels;

public partial class ChatViewModel : ObservableObject
{
    private readonly AuditEngine _engine = new();
    private readonly ChatAiService _aiService = new();

    [ObservableProperty]
    private string _userInput = "";

    [ObservableProperty]
    private bool _isBusy;

    public ObservableCollection<ChatMessage> Messages { get; } = new();

    public ChatViewModel()
    {
        Messages.Add(new ChatMessage
        {
            IsBot = true,
            Text = "👋 Hi! I'm WinSentinel, your Windows security assistant.\n\n" +
                   "Try these commands:\n" +
                   "• \"Run full audit\" — Run all 8 security modules\n" +
                   "• \"Check firewall\" — Run firewall audit\n" +
                   "• \"Security score\" — Calculate your security score\n" +
                   "• Or ask me anything about Windows security!"
        });
    }

    [RelayCommand]
    private async Task SendMessageAsync()
    {
        var input = UserInput?.Trim();
        if (string.IsNullOrEmpty(input)) return;

        // Add user message
        Messages.Add(new ChatMessage { IsBot = false, Text = input });
        UserInput = "";
        IsBusy = true;

        try
        {
            var response = await ProcessCommandAsync(input);
            Messages.Add(new ChatMessage { IsBot = true, Text = response });
        }
        catch (Exception ex)
        {
            Messages.Add(new ChatMessage { IsBot = true, Text = $"❌ Error: {ex.Message}" });
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task<string> ProcessCommandAsync(string input)
    {
        var lower = input.ToLowerInvariant();

        // Quick action: full audit
        if (lower.Contains("full audit") || lower.Contains("run all") || lower.Contains("scan all"))
        {
            return await RunFullAuditChatAsync();
        }

        // Quick action: security score
        if (lower.Contains("security score") || lower.Contains("my score"))
        {
            return await GetSecurityScoreAsync();
        }

        // Quick action: specific audit
        var auditKeywords = new Dictionary<string, string>
        {
            { "firewall", "Firewall" },
            { "update", "Updates" },
            { "defender", "Defender" },
            { "account", "Accounts" },
            { "network", "Network" },
            { "process", "Processes" },
            { "startup", "Startup" },
            { "system", "System" },
        };

        foreach (var (keyword, category) in auditKeywords)
        {
            if (lower.Contains(keyword))
            {
                return await RunSingleAuditChatAsync(category);
            }
        }

        // AI response
        return await _aiService.GetResponseAsync(input);
    }

    private async Task<string> RunFullAuditChatAsync()
    {
        var report = await _engine.RunFullAuditAsync();
        var score = report.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"🛡️ **Full Security Audit Complete**");
        sb.AppendLine($"📊 Score: {score}/100 (Grade: {grade})");
        sb.AppendLine();
        sb.AppendLine($"🔴 Critical: {report.TotalCritical}");
        sb.AppendLine($"🟡 Warnings: {report.TotalWarnings}");
        sb.AppendLine($"ℹ️ Info: {report.TotalInfo}");
        sb.AppendLine($"✅ Pass: {report.TotalPass}");
        sb.AppendLine();

        foreach (var result in report.Results)
        {
            var catScore = SecurityScorer.CalculateCategoryScore(result);
            var emoji = catScore >= 80 ? "✅" : catScore >= 60 ? "⚠️" : "🔴";
            sb.AppendLine($"{emoji} {result.Category}: {catScore}/100");
        }

        if (report.TotalCritical > 0)
        {
            sb.AppendLine();
            sb.AppendLine("🚨 **Critical Issues:**");
            foreach (var finding in report.Results.SelectMany(r => r.Findings)
                .Where(f => f.Severity == Severity.Critical))
            {
                sb.AppendLine($"  • {finding.Title}: {finding.Description}");
                if (finding.Remediation != null)
                    sb.AppendLine($"    💡 Fix: {finding.Remediation}");
            }
        }

        return sb.ToString();
    }

    private async Task<string> RunSingleAuditChatAsync(string category)
    {
        var result = await _engine.RunSingleAuditAsync(category);
        if (result == null) return $"❌ No audit module found for '{category}'.";

        var sb = new System.Text.StringBuilder();
        var catScore = SecurityScorer.CalculateCategoryScore(result);
        sb.AppendLine($"🔍 **{result.ModuleName} Results**");
        sb.AppendLine($"📊 Category Score: {catScore}/100");
        sb.AppendLine();

        foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
        {
            var icon = finding.Severity switch
            {
                Severity.Critical => "🔴",
                Severity.Warning => "🟡",
                Severity.Info => "ℹ️",
                Severity.Pass => "✅",
                _ => "❓"
            };

            sb.AppendLine($"{icon} **{finding.Title}**");
            sb.AppendLine($"   {finding.Description}");

            if (finding.Remediation != null)
                sb.AppendLine($"   💡 {finding.Remediation}");
            if (finding.FixCommand != null)
                sb.AppendLine($"   🔧 `{finding.FixCommand}`");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private async Task<string> GetSecurityScoreAsync()
    {
        var report = await _engine.RunFullAuditAsync();
        var score = report.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);

        return $"🛡️ Your security score is **{score}/100** (Grade: {grade})\n\n" +
               $"🔴 {report.TotalCritical} critical issues\n" +
               $"🟡 {report.TotalWarnings} warnings\n" +
               $"ℹ️ {report.TotalInfo} informational\n" +
               $"✅ {report.TotalPass} checks passed";
    }
}

public class ChatMessage
{
    public bool IsBot { get; set; }
    public string Text { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.Now;
}
