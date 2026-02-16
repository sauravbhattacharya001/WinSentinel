using System.Net.Http;
using System.Text;
using System.Text.Json;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// AI-powered security advisor that provides intelligent responses about the system's 
/// security posture. Uses a tiered approach: (1) Ollama LLM if available, (2) rule-based engine.
/// Integrates with AuditEngine and FixEngine to provide actionable advice.
/// </summary>
public class SecurityAdvisor
{
    private readonly AuditEngine _auditEngine;
    private readonly FixEngine _fixEngine;
    private readonly AuditHistoryService? _historyService;
    private readonly HttpClient _httpClient;
    private SecurityReport? _lastReport;
    private bool _ollamaAvailable;
    private bool _ollamaChecked;
    private string _ollamaBaseUrl = "http://localhost:11434";
    private string _ollamaModel = "llama3";

    public SecurityAdvisor(AuditEngine auditEngine, FixEngine fixEngine,
        AuditHistoryService? historyService = null, HttpClient? httpClient = null)
    {
        _auditEngine = auditEngine;
        _fixEngine = fixEngine;
        _historyService = historyService;
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
    }

    /// <summary>Last audit report used for context.</summary>
    public SecurityReport? LastReport
    {
        get => _lastReport;
        set => _lastReport = value;
    }

    /// <summary>Whether Ollama LLM is available for natural language responses.</summary>
    public bool IsOllamaAvailable => _ollamaAvailable;

    /// <summary>Configure the Ollama endpoint.</summary>
    public void ConfigureOllama(string baseUrl, string model = "llama3")
    {
        _ollamaBaseUrl = baseUrl.TrimEnd('/');
        _ollamaModel = model;
        _ollamaChecked = false;
    }

    /// <summary>
    /// Process a user question/command and return an intelligent response.
    /// </summary>
    public async Task<AdvisorResponse> AskAsync(string userInput, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userInput))
            return AdvisorResponse.Text("Please ask me something! Type /help for available commands.");

        var input = userInput.Trim();

        // Handle slash commands first
        if (input.StartsWith('/'))
            return await HandleCommandAsync(input, ct);

        // Try to match against known question patterns
        var ruleResponse = await HandleQuestionAsync(input, ct);
        if (ruleResponse != null)
            return ruleResponse;

        // Try Ollama for a natural language response
        var ollamaResponse = await TryOllamaAsync(input, ct);
        if (ollamaResponse != null)
            return ollamaResponse;

        // Fallback
        return GetFallbackResponse(input);
    }

    /// <summary>
    /// Run a scan and update the last report.
    /// </summary>
    public async Task<SecurityReport> RunScanAsync(
        IProgress<(string module, int current, int total)>? progress = null,
        CancellationToken ct = default)
    {
        _lastReport = await _auditEngine.RunFullAuditAsync(progress, ct);
        return _lastReport;
    }

    #region Command Handling

    private async Task<AdvisorResponse> HandleCommandAsync(string input, CancellationToken ct)
    {
        var parts = input.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        var cmd = parts[0].ToLowerInvariant();
        var arg = parts.Length > 1 ? parts[1].Trim() : "";

        return cmd switch
        {
            "/scan" => await HandleScanCommandAsync(arg, ct),
            "/score" => await HandleScoreCommandAsync(ct),
            "/fix" => await HandleFixCommandAsync(arg, ct),
            "/fixall" => await HandleFixAllCommandAsync(ct),
            "/history" => HandleHistoryCommand(),
            "/help" => HandleHelpCommand(),
            _ => AdvisorResponse.Text($"Unknown command: {cmd}\nType /help for available commands.")
        };
    }

    private async Task<AdvisorResponse> HandleScanCommandAsync(string arg, CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(arg))
        {
            // Single module scan
            var result = await _auditEngine.RunSingleAuditAsync(arg, ct);
            if (result == null)
                return AdvisorResponse.Text($"❌ No audit module found for '{arg}'.\nAvailable modules: Firewall, Updates, Defender, Accounts, Network, Processes, Startup, System, Privacy, Browser");

            // Update lastReport with this single result
            _lastReport ??= new SecurityReport();

            return AdvisorResponse.Text(FormatModuleResult(result));
        }

        // Full scan
        _lastReport = await _auditEngine.RunFullAuditAsync(cancellationToken: ct);
        return AdvisorResponse.Text(FormatFullReport(_lastReport));
    }

    private async Task<AdvisorResponse> HandleScoreCommandAsync(CancellationToken ct)
    {
        if (_lastReport == null)
        {
            _lastReport = await _auditEngine.RunFullAuditAsync(cancellationToken: ct);
        }

        var score = _lastReport.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);
        var sb = new StringBuilder();
        sb.AppendLine($"🛡️ **Security Score: {score}/100 (Grade: {grade})**");
        sb.AppendLine();

        // Per-module breakdown
        foreach (var result in _lastReport.Results)
        {
            var catScore = SecurityScorer.CalculateCategoryScore(result);
            var emoji = catScore >= 90 ? "✅" : catScore >= 70 ? "⚠️" : "🔴";
            sb.AppendLine($"  {emoji} {result.Category}: {catScore}/100");
        }

        sb.AppendLine();
        sb.AppendLine($"🔴 {_lastReport.TotalCritical} critical  •  🟡 {_lastReport.TotalWarnings} warnings");

        // Improvement advice
        var topIssues = GetTopIssues(_lastReport, 2);
        if (topIssues.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("💡 **To improve your score:**");
            foreach (var issue in topIssues)
            {
                var impact = issue.Severity == Severity.Critical ? "up to +20" : "+5";
                sb.AppendLine($"  • Fix \"{issue.Title}\" ({impact} points)");
            }
        }

        return AdvisorResponse.Text(sb.ToString());
    }

    private async Task<AdvisorResponse> HandleFixCommandAsync(string findingSearch, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(findingSearch))
            return AdvisorResponse.Text("Usage: /fix <finding name>\nExample: /fix LLMNR\n\nType /scan first to see available findings.");

        if (_lastReport == null)
            return AdvisorResponse.Text("⚠️ No scan results available. Run /scan first, then try /fix again.");

        var allFindings = _lastReport.Results.SelectMany(r => r.Findings).ToList();
        var match = FindBestMatch(allFindings, findingSearch);

        if (match == null)
            return AdvisorResponse.Text($"❌ No finding matching \"{findingSearch}\" found.\nAvailable findings:\n" +
                string.Join("\n", allFindings
                    .Where(f => f.Severity >= Severity.Warning)
                    .Select(f => $"  • {f.Title}")));

        if (string.IsNullOrEmpty(match.FixCommand))
            return AdvisorResponse.Text($"⚠️ \"{match.Title}\" doesn't have an automated fix.\n" +
                (match.Remediation != null ? $"💡 Manual fix: {match.Remediation}" : "No remediation available."));

        var result = await _fixEngine.ExecuteFixAsync(match, cancellationToken: ct);

        var sb = new StringBuilder();
        if (result.Success)
        {
            sb.AppendLine($"✅ **Fixed: {match.Title}**");
            if (!string.IsNullOrEmpty(result.Output))
                sb.AppendLine($"Output: {result.Output}");
            sb.AppendLine($"⏱️ Took {result.Duration.TotalSeconds:F1}s");

            // Suggest related fixes
            var related = allFindings
                .Where(f => f.Category == match.Category && f != match && f.FixCommand != null && f.Severity >= Severity.Warning)
                .ToList();
            if (related.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine($"🔧 Want me to fix {related.Count} more {match.Category} issue(s) too?");
                foreach (var r in related.Take(3))
                    sb.AppendLine($"  • {r.Title}");
                sb.AppendLine("Type /fixall to fix all warnings and critical issues.");
            }
        }
        else
        {
            sb.AppendLine($"❌ **Failed to fix: {match.Title}**");
            sb.AppendLine($"Error: {result.Error}");
            if (result.RequiredElevation)
                sb.AppendLine("💡 This fix requires administrator privileges. Try running WinSentinel as admin.");
        }

        return AdvisorResponse.Text(sb.ToString());
    }

    private async Task<AdvisorResponse> HandleFixAllCommandAsync(CancellationToken ct)
    {
        if (_lastReport == null)
            return AdvisorResponse.Text("⚠️ No scan results available. Run /scan first.");

        var fixable = _lastReport.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity >= Severity.Warning && !string.IsNullOrEmpty(f.FixCommand))
            .ToList();

        if (fixable.Count == 0)
            return AdvisorResponse.Text("✅ No fixable issues found. Your system looks good!");

        var sb = new StringBuilder();
        sb.AppendLine($"🔧 **Fixing {fixable.Count} issues...**");
        sb.AppendLine();

        int succeeded = 0, failed = 0;
        foreach (var finding in fixable)
        {
            ct.ThrowIfCancellationRequested();
            var result = await _fixEngine.ExecuteFixAsync(finding, cancellationToken: ct);
            if (result.Success)
            {
                sb.AppendLine($"  ✅ {finding.Title}");
                succeeded++;
            }
            else
            {
                sb.AppendLine($"  ❌ {finding.Title}: {result.Error}");
                failed++;
            }
        }

        sb.AppendLine();
        sb.AppendLine($"**Results:** {succeeded} fixed, {failed} failed");
        if (succeeded > 0)
            sb.AppendLine("💡 Run /scan again to see your updated score.");

        return AdvisorResponse.Text(sb.ToString());
    }

    private AdvisorResponse HandleHistoryCommand()
    {
        if (_historyService == null)
            return AdvisorResponse.Text("📊 History service is not available.");

        var runs = _historyService.GetRecentRuns(10);
        if (runs.Count == 0)
            return AdvisorResponse.Text("📊 No scan history found. Run /scan to start tracking.");

        var sb = new StringBuilder();
        sb.AppendLine("📊 **Scan History (last 10 runs)**");
        sb.AppendLine();

        foreach (var run in runs)
        {
            var emoji = run.OverallScore >= 90 ? "🟢" : run.OverallScore >= 70 ? "🟡" : "🔴";
            var date = run.Timestamp.ToLocalTime().ToString("MMM dd, HH:mm");
            var scheduled = run.IsScheduled ? " [auto]" : "";
            sb.AppendLine($"  {emoji} {date} — Score: {run.OverallScore}/{run.Grade} — {run.CriticalCount}C/{run.WarningCount}W{scheduled}");
        }

        var trend = _historyService.GetTrend(30);
        if (trend.PreviousScore.HasValue)
        {
            sb.AppendLine();
            var change = trend.ScoreChange;
            var dir = change > 0 ? "📈 improved" : change < 0 ? "📉 declined" : "➡️ unchanged";
            sb.AppendLine($"**Trend:** Score has {dir} by {Math.Abs(change)} points over last 30 days.");
            sb.AppendLine($"**Average:** {trend.AverageScore:F0}/100 across {trend.TotalScans} scans.");
        }

        return AdvisorResponse.Text(sb.ToString());
    }

    private static AdvisorResponse HandleHelpCommand()
    {
        return AdvisorResponse.Text(
            "🛡️ **WinSentinel Security Advisor — Commands**\n\n" +
            "**Slash Commands:**\n" +
            "  /scan — Run a full security audit\n" +
            "  /scan <module> — Scan a specific module (e.g., /scan network)\n" +
            "  /score — Show your current security score breakdown\n" +
            "  /fix <finding> — Fix a specific issue (e.g., /fix LLMNR)\n" +
            "  /fixall — Fix all warnings and critical issues\n" +
            "  /history — Show scan history and trends\n" +
            "  /help — Show this help message\n\n" +
            "**Natural Language:**\n" +
            "  \"What's wrong?\" — Show current issues\n" +
            "  \"What's my score?\" — Current security score\n" +
            "  \"How do I fix X?\" — Advice on fixing a specific issue\n" +
            "  \"Explain network\" — Explain a module's findings\n" +
            "  \"Run a scan\" — Run a full audit\n" +
            "  \"Fix all warnings\" — Fix everything fixable\n\n" +
            "You can also ask about passwords, encryption, malware, backups, and more!"
        );
    }

    #endregion

    #region Question Handling (Natural Language)

    private async Task<AdvisorResponse?> HandleQuestionAsync(string input, CancellationToken ct)
    {
        var lower = input.ToLowerInvariant();

        // "what's wrong" / "what are my issues" / "show problems"
        if (MatchesAny(lower, "what's wrong", "what is wrong", "show issues", "show problems",
            "my issues", "any issues", "any problems", "what needs fixing", "what should i fix"))
        {
            return await HandleWhatsWrongAsync(ct);
        }

        // "what's my score" / "security score" / "how am I doing"
        if (MatchesAny(lower, "score", "my score", "how am i doing", "how secure", "security rating"))
        {
            return await HandleScoreCommandAsync(ct);
        }

        // "run a scan" / "scan my system" / "audit"
        if (MatchesAny(lower, "run a scan", "run scan", "scan my", "full audit", "run all", "scan all",
            "run audit", "check everything", "scan everything"))
        {
            return await HandleScanCommandAsync("", ct);
        }

        // "fix all" / "fix everything" / "fix all warnings"
        if (MatchesAny(lower, "fix all", "fix everything", "fix all warnings", "fix all issues", "fix them all"))
        {
            return await HandleFixAllCommandAsync(ct);
        }

        // "how do I fix X" / "fix X" / "help me fix"
        if (lower.StartsWith("fix ") || lower.Contains("how do i fix") || lower.Contains("how to fix") ||
            lower.Contains("help me fix") || lower.Contains("can you fix"))
        {
            var target = ExtractFixTarget(input);
            if (!string.IsNullOrEmpty(target))
                return await HandleFixCommandAsync(target, ct);
        }

        // Security knowledge questions (check before explain so "tell me about firewall" hits knowledge base)
        var knowledgeResponse = TrySecurityKnowledge(lower);
        if (knowledgeResponse != null)
            return knowledgeResponse;

        // "explain X" / "tell me about X" / "what is X"
        if (lower.StartsWith("explain ") || lower.Contains("tell me about") || lower.Contains("what is "))
        {
            var topic = ExtractTopic(input);
            return await HandleExplainAsync(topic, ct);
        }

        // "check X" — specific module scan
        if (lower.StartsWith("check "))
        {
            var module = input[6..].Trim();
            return await HandleScanCommandAsync(module, ct);
        }

        return null; // No match — fall through to Ollama or fallback
    }

    private async Task<AdvisorResponse> HandleWhatsWrongAsync(CancellationToken ct)
    {
        if (_lastReport == null)
        {
            _lastReport = await _auditEngine.RunFullAuditAsync(cancellationToken: ct);
        }

        var criticals = _lastReport.Results.SelectMany(r => r.Findings)
            .Where(f => f.Severity == Severity.Critical).ToList();
        var warnings = _lastReport.Results.SelectMany(r => r.Findings)
            .Where(f => f.Severity == Severity.Warning).ToList();

        if (criticals.Count == 0 && warnings.Count == 0)
        {
            return AdvisorResponse.Text(
                $"✅ **Your system looks great!**\n" +
                $"Score: {_lastReport.SecurityScore}/100 ({SecurityScorer.GetGrade(_lastReport.SecurityScore)})\n" +
                $"No critical issues or warnings found.");
        }

        var sb = new StringBuilder();
        sb.AppendLine($"🔍 **Found {criticals.Count + warnings.Count} issues:**");
        sb.AppendLine();

        if (criticals.Count > 0)
        {
            sb.AppendLine($"🔴 **Critical ({criticals.Count}):**");
            foreach (var f in criticals)
            {
                sb.AppendLine($"  • **{f.Title}** — {f.Description}");
                if (f.FixCommand != null) sb.AppendLine($"    🔧 Auto-fix available (use `/fix {f.Title}`)");
                else if (f.Remediation != null) sb.AppendLine($"    💡 {f.Remediation}");
            }
            sb.AppendLine();
        }

        if (warnings.Count > 0)
        {
            sb.AppendLine($"🟡 **Warnings ({warnings.Count}):**");
            foreach (var f in warnings.Take(10))
            {
                sb.AppendLine($"  • **{f.Title}** — {f.Description}");
                if (f.FixCommand != null) sb.AppendLine($"    🔧 Auto-fix available");
            }
            if (warnings.Count > 10)
                sb.AppendLine($"  ... and {warnings.Count - 10} more");
            sb.AppendLine();
        }

        var fixableCount = criticals.Concat(warnings).Count(f => f.FixCommand != null);
        if (fixableCount > 0)
        {
            sb.AppendLine($"💡 {fixableCount} issues have automated fixes. Use `/fixall` to fix them all.");
        }

        // Highlight the most important issue
        var topIssue = criticals.FirstOrDefault() ?? warnings.FirstOrDefault();
        if (topIssue != null)
        {
            sb.AppendLine();
            sb.AppendLine($"⭐ **Most important:** {topIssue.Title}");
            sb.AppendLine($"   {topIssue.Description}");
            if (topIssue.Remediation != null)
                sb.AppendLine($"   💡 {topIssue.Remediation}");
        }

        return AdvisorResponse.Text(sb.ToString());
    }

    private async Task<AdvisorResponse> HandleExplainAsync(string topic, CancellationToken ct)
    {
        // Try to match a module
        var result = await _auditEngine.RunSingleAuditAsync(topic, ct);
        if (result != null)
        {
            return AdvisorResponse.Text(FormatModuleResult(result));
        }

        // Try to match a finding
        if (_lastReport != null)
        {
            var allFindings = _lastReport.Results.SelectMany(r => r.Findings).ToList();
            var match = FindBestMatch(allFindings, topic);
            if (match != null)
            {
                return AdvisorResponse.Text(FormatFindingExplanation(match));
            }
        }

        return AdvisorResponse.Text($"I don't have specific information about \"{topic}\".\n" +
            "Try:\n  • A module name: firewall, network, defender, accounts, system, privacy, startup, processes, updates\n" +
            "  • A finding title from the last scan\n  • Run /scan first to get results to explain.");
    }

    #endregion

    #region Ollama Integration

    private async Task<AdvisorResponse?> TryOllamaAsync(string input, CancellationToken ct)
    {
        if (!_ollamaChecked)
        {
            _ollamaChecked = true;
            _ollamaAvailable = await CheckOllamaAsync(ct);
        }

        if (!_ollamaAvailable) return null;

        try
        {
            var systemPrompt = BuildOllamaSystemPrompt();
            var request = new
            {
                model = _ollamaModel,
                prompt = input,
                system = systemPrompt,
                stream = false
            };

            var json = JsonSerializer.Serialize(request);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"{_ollamaBaseUrl}/api/generate", content, ct);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = await response.Content.ReadAsStringAsync(ct);
                var doc = JsonDocument.Parse(responseJson);
                var text = doc.RootElement.GetProperty("response").GetString();
                if (!string.IsNullOrEmpty(text))
                    return AdvisorResponse.Text("🤖 " + text);
            }
        }
        catch
        {
            _ollamaAvailable = false;
        }

        return null;
    }

    private async Task<bool> CheckOllamaAsync(CancellationToken ct)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, cts.Token);
            var response = await _httpClient.GetAsync($"{_ollamaBaseUrl}/api/tags", linked.Token);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private string BuildOllamaSystemPrompt()
    {
        var sb = new StringBuilder();
        sb.AppendLine("You are WinSentinel, an expert Windows security advisor built into a desktop security app.");
        sb.AppendLine("Be concise, practical, and friendly. Give actionable advice with PowerShell commands when possible.");
        sb.AppendLine("Focus on Windows security: firewall, Defender, accounts, network, updates, privacy.");
        sb.AppendLine();

        if (_lastReport != null)
        {
            sb.AppendLine("CURRENT SYSTEM STATE:");
            sb.AppendLine($"  Security Score: {_lastReport.SecurityScore}/100 (Grade: {SecurityScorer.GetGrade(_lastReport.SecurityScore)})");
            sb.AppendLine($"  Critical Issues: {_lastReport.TotalCritical}");
            sb.AppendLine($"  Warnings: {_lastReport.TotalWarnings}");
            sb.AppendLine();

            var issues = _lastReport.Results.SelectMany(r => r.Findings)
                .Where(f => f.Severity >= Severity.Warning)
                .Take(10)
                .ToList();

            if (issues.Count > 0)
            {
                sb.AppendLine("CURRENT ISSUES:");
                foreach (var issue in issues)
                {
                    sb.AppendLine($"  [{issue.Severity}] {issue.Title}: {issue.Description}");
                    if (issue.Remediation != null)
                        sb.AppendLine($"    Fix: {issue.Remediation}");
                }
            }
        }
        else
        {
            sb.AppendLine("No scan has been run yet. You can suggest the user run /scan.");
        }

        return sb.ToString();
    }

    #endregion

    #region Security Knowledge Base

    private static AdvisorResponse? TrySecurityKnowledge(string lower)
    {
        if (ContainsAny(lower, "password"))
            return AdvisorResponse.Text(
                "🔑 **Password Security Tips:**\n" +
                "• Use at least 12 characters with mixed case, numbers, and symbols\n" +
                "• Enable Windows Hello for biometric authentication\n" +
                "• Use a password manager for unique passwords\n" +
                "• Set minimum password length: `net accounts /minpwlen:12`\n" +
                "• Enable account lockout: `net accounts /lockoutthreshold:5`\n" +
                "• Set maximum password age: `net accounts /maxpwage:90`");

        if (ContainsAny(lower, "ransomware"))
            return AdvisorResponse.Text(
                "🛡️ **Ransomware Protection:**\n" +
                "• Enable Controlled Folder Access:\n  `Set-MpPreference -EnableControlledFolderAccess Enabled`\n" +
                "• Keep backups on disconnected/cloud storage\n" +
                "• Enable cloud-delivered protection in Defender\n" +
                "• Don't open email attachments from unknown senders\n" +
                "• Keep all software and Windows updated");

        if (ContainsAny(lower, "vpn"))
            return AdvisorResponse.Text(
                "🌐 **VPN Recommendations:**\n" +
                "• Use a reputable VPN provider with no-log policy\n" +
                "• Windows built-in VPN: Settings > Network > VPN\n" +
                "• For business: Consider Always-On VPN with certificate auth\n" +
                "• Enable VPN kill switch to prevent data leaks");

        if (ContainsAny(lower, "encrypt", "bitlocker"))
            return AdvisorResponse.Text(
                "🔒 **Encryption:**\n" +
                "• Enable BitLocker: `manage-bde -on C:`\n" +
                "• Check BitLocker status: `manage-bde -status`\n" +
                "• Use EFS for individual files: Right-click > Properties > Advanced > Encrypt\n" +
                "• Store BitLocker recovery key in a safe location\n" +
                "• Ensure TPM is enabled for hardware-backed encryption");

        if (ContainsAny(lower, "malware", "virus", "antivirus"))
            return AdvisorResponse.Text(
                "🦠 **Malware Protection:**\n" +
                "• Quick scan: `Start-MpScan -ScanType QuickScan`\n" +
                "• Full scan: `Start-MpScan -ScanType FullScan`\n" +
                "• Update definitions: `Update-MpSignature`\n" +
                "• Check protection: `Get-MpComputerStatus`\n" +
                "• Enable PUA protection: `Set-MpPreference -PUAProtection Enabled`");

        if (ContainsAny(lower, "backup"))
            return AdvisorResponse.Text(
                "💾 **Backup Best Practices:**\n" +
                "• Enable File History: Settings > Update & Security > Backup\n" +
                "• Create system image: `wbadmin start backup -backupTarget:D: -include:C:`\n" +
                "• Use 3-2-1 rule: 3 copies, 2 different media, 1 offsite\n" +
                "• Test your backups regularly!");

        if (ContainsAny(lower, "phishing"))
            return AdvisorResponse.Text(
                "🎣 **Anti-Phishing Tips:**\n" +
                "• Enable SmartScreen in Windows Security settings\n" +
                "• Check URLs carefully before clicking\n" +
                "• Never enter credentials on unfamiliar sites\n" +
                "• Enable multi-factor authentication everywhere\n" +
                "• Report phishing: forward to phishing@microsoft.com");

        if (ContainsAny(lower, "firewall"))
            return AdvisorResponse.Text(
                "🔥 **Firewall Tips:**\n" +
                "• Check status: `Get-NetFirewallProfile | Select Name, Enabled`\n" +
                "• Enable all profiles: `Set-NetFirewallProfile -All -Enabled True`\n" +
                "• Block inbound by default: `Set-NetFirewallProfile -DefaultInboundAction Block`\n" +
                "• Review rules: `Get-NetFirewallRule | Where Enabled -eq True`\n" +
                "• Or run `/scan firewall` for a detailed check");

        if (ContainsAny(lower, "privacy", "telemetry", "tracking"))
            return AdvisorResponse.Text(
                "🔒 **Privacy & Telemetry:**\n" +
                "• Reduce telemetry: Settings > Privacy > Diagnostics & feedback\n" +
                "• Disable advertising ID: Settings > Privacy > General\n" +
                "• Review app permissions: Settings > Privacy\n" +
                "• Disable location tracking if not needed\n" +
                "• Or run `/scan privacy` for a detailed check");

        if (ContainsAny(lower, "remote desktop", "rdp"))
            return AdvisorResponse.Text(
                "🖥️ **Remote Desktop Security:**\n" +
                "• Disable if not needed: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1`\n" +
                "• Use Network Level Authentication (NLA)\n" +
                "• Change default RDP port from 3389\n" +
                "• Enable RDP only for specific users\n" +
                "• Use VPN for remote access instead of exposing RDP");

        return null;
    }

    #endregion

    #region Formatting Helpers

    public static string FormatFullReport(SecurityReport report)
    {
        var score = report.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);
        var sb = new StringBuilder();

        sb.AppendLine($"🛡️ **Full Security Audit Complete**");
        sb.AppendLine($"📊 Score: {score}/100 (Grade: {grade})");
        sb.AppendLine();
        sb.AppendLine($"🔴 Critical: {report.TotalCritical}  •  🟡 Warnings: {report.TotalWarnings}  •  ℹ️ Info: {report.TotalInfo}  •  ✅ Pass: {report.TotalPass}");
        sb.AppendLine();

        foreach (var result in report.Results)
        {
            var catScore = SecurityScorer.CalculateCategoryScore(result);
            var emoji = catScore >= 90 ? "✅" : catScore >= 70 ? "⚠️" : "🔴";
            sb.AppendLine($"  {emoji} {result.Category}: {catScore}/100 ({result.CriticalCount}C/{result.WarningCount}W)");
        }

        if (report.TotalCritical > 0 || report.TotalWarnings > 0)
        {
            sb.AppendLine();
            var fixable = report.Results.SelectMany(r => r.Findings)
                .Count(f => f.Severity >= Severity.Warning && f.FixCommand != null);
            sb.AppendLine($"💡 {fixable} issues have automated fixes. Type /fixall to fix them.");
        }

        return sb.ToString();
    }

    public static string FormatModuleResult(AuditResult result)
    {
        var score = SecurityScorer.CalculateCategoryScore(result);
        var sb = new StringBuilder();
        sb.AppendLine($"🔍 **{result.ModuleName}** — Score: {score}/100");
        sb.AppendLine();

        foreach (var f in result.Findings.OrderByDescending(f => f.Severity))
        {
            var icon = f.Severity switch
            {
                Severity.Critical => "🔴",
                Severity.Warning => "🟡",
                Severity.Info => "ℹ️",
                Severity.Pass => "✅",
                _ => "❓"
            };
            sb.AppendLine($"  {icon} **{f.Title}**");
            sb.AppendLine($"     {f.Description}");
            if (f.Remediation != null)
                sb.AppendLine($"     💡 {f.Remediation}");
            if (f.FixCommand != null)
                sb.AppendLine($"     🔧 `/fix {f.Title}`");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    public static string FormatFindingExplanation(Finding finding)
    {
        var sb = new StringBuilder();
        var icon = finding.Severity switch
        {
            Severity.Critical => "🔴 Critical",
            Severity.Warning => "🟡 Warning",
            Severity.Info => "ℹ️ Info",
            _ => "✅ Pass"
        };

        sb.AppendLine($"**{finding.Title}** ({icon})");
        sb.AppendLine();
        sb.AppendLine($"📝 {finding.Description}");
        sb.AppendLine();

        if (finding.Severity == Severity.Critical)
            sb.AppendLine("⚠️ This is a **critical** issue that significantly impacts your security score (-20 points).");
        else if (finding.Severity == Severity.Warning)
            sb.AppendLine("⚠️ This is a **warning** that moderately impacts your security score (-5 points).");

        if (finding.Remediation != null)
        {
            sb.AppendLine();
            sb.AppendLine($"💡 **How to fix:** {finding.Remediation}");
        }

        if (finding.FixCommand != null)
        {
            sb.AppendLine();
            sb.AppendLine($"🔧 **Automated fix available!**");
            sb.AppendLine($"Command: `{finding.FixCommand}`");
            sb.AppendLine($"Type `/fix {finding.Title}` to apply automatically.");
        }

        return sb.ToString();
    }

    #endregion

    #region Utility Methods

    private static List<Finding> GetTopIssues(SecurityReport report, int count)
    {
        return report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity >= Severity.Warning)
            .OrderByDescending(f => f.Severity)
            .ThenByDescending(f => f.FixCommand != null ? 1 : 0)
            .Take(count)
            .ToList();
    }

    public static Finding? FindBestMatch(List<Finding> findings, string search)
    {
        var lower = search.ToLowerInvariant();

        // Exact title match
        var exact = findings.FirstOrDefault(f =>
            f.Title.Equals(search, StringComparison.OrdinalIgnoreCase));
        if (exact != null) return exact;

        // Title contains search
        var contains = findings.FirstOrDefault(f =>
            f.Title.Contains(search, StringComparison.OrdinalIgnoreCase));
        if (contains != null) return contains;

        // Search contains title word
        var titleWord = findings.FirstOrDefault(f =>
            f.Title.Split(' ', '-', '_')
                .Any(word => word.Length > 2 && lower.Contains(word.ToLowerInvariant())));
        if (titleWord != null) return titleWord;

        // Description contains search
        var desc = findings
            .Where(f => f.Severity >= Severity.Warning)
            .FirstOrDefault(f =>
                f.Description.Contains(search, StringComparison.OrdinalIgnoreCase));
        if (desc != null) return desc;

        // Category match
        var cat = findings
            .Where(f => f.Severity >= Severity.Warning)
            .FirstOrDefault(f =>
                f.Category.Contains(search, StringComparison.OrdinalIgnoreCase));
        return cat;
    }

    private static string ExtractFixTarget(string input)
    {
        var lower = input.ToLowerInvariant();

        // "fix LLMNR", "fix smb signing"
        if (lower.StartsWith("fix "))
            return input[4..].Trim();

        // "how do I fix LLMNR"
        var patterns = new[] { "how do i fix ", "how to fix ", "help me fix ", "can you fix " };
        foreach (var p in patterns)
        {
            var idx = lower.IndexOf(p, StringComparison.Ordinal);
            if (idx >= 0)
                return input[(idx + p.Length)..].Trim().TrimEnd('?', '!', '.');
        }

        return "";
    }

    private static string ExtractTopic(string input)
    {
        var lower = input.ToLowerInvariant();

        if (lower.StartsWith("explain "))
            return input[8..].Trim();

        var patterns = new[] { "tell me about ", "what is ", "what are " };
        foreach (var p in patterns)
        {
            var idx = lower.IndexOf(p, StringComparison.Ordinal);
            if (idx >= 0)
                return input[(idx + p.Length)..].Trim().TrimEnd('?', '!', '.');
        }

        return input;
    }

    private static bool MatchesAny(string input, params string[] patterns)
    {
        return patterns.Any(p => input.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsAny(string input, params string[] words)
    {
        return words.Any(w => input.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    private static AdvisorResponse GetFallbackResponse(string input)
    {
        return AdvisorResponse.Text(
            "🤔 I'm not sure how to help with that specific topic.\n\n" +
            "Try:\n" +
            "  • /scan — Run a full security audit\n" +
            "  • /score — Check your security score\n" +
            "  • /help — See all available commands\n" +
            "  • Ask about passwords, encryption, malware, firewall, etc.\n\n" +
            "💡 Tip: Install Ollama (http://localhost:11434) for AI-powered natural responses!");
    }

    #endregion
}

/// <summary>
/// Response from the SecurityAdvisor.
/// </summary>
public class AdvisorResponse
{
    public required string Message { get; set; }
    public List<Finding>? RelatedFindings { get; set; }
    public bool SuggestsScan { get; set; }
    public bool SuggestsFix { get; set; }

    public static AdvisorResponse Text(string message) => new() { Message = message };

    public static AdvisorResponse WithFindings(string message, List<Finding> findings) =>
        new() { Message = message, RelatedFindings = findings };
}
