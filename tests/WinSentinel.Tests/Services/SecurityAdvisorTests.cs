using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityAdvisorTests
{
    /// <summary>
    /// Stub audit module for testing.
    /// </summary>
    private class StubAuditModule : IAuditModule
    {
        public string Name { get; set; } = "Test Module";
        public string Category { get; set; } = "Test";
        public string Description { get; set; } = "Test module";
        public List<Finding> Findings { get; set; } = new();

        public Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new AuditResult
            {
                ModuleName = Name,
                Category = Category,
                Findings = Findings,
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow,
                Success = true
            });
        }
    }

    private static SecurityAdvisor CreateAdvisor(List<Finding>? findings = null)
    {
        var stubModule = new StubAuditModule
        {
            Name = "Network Security",
            Category = "Network",
            Findings = findings ?? new List<Finding>
            {
                Finding.Critical("LLMNR Enabled", "LLMNR is enabled, allowing name resolution poisoning.", "Network",
                    "Disable LLMNR via Group Policy or registry.",
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0"),
                Finding.Warning("SMB Signing Disabled", "SMB signing is not required, enabling relay attacks.", "Network",
                    "Enable SMB signing.",
                    "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"),
                Finding.Warning("Open Port 3389", "RDP port 3389 is open.", "Network",
                    "Disable RDP if not needed."),
                Finding.Pass("IPv6 Configuration", "IPv6 is properly configured.", "Network"),
                Finding.Info("Network Profile", "Connected to Domain network.", "Network"),
            }
        };

        var engine = new AuditEngine(new[] { stubModule });
        var fixEngine = new FixEngine();
        return new SecurityAdvisor(engine, fixEngine);
    }

    private static SecurityAdvisor CreateAdvisorWithReport(List<Finding>? findings = null)
    {
        var advisor = CreateAdvisor(findings);
        // Pre-populate with a report
        var report = new SecurityReport
        {
            SecurityScore = 70,
            Results = new List<AuditResult>
            {
                new AuditResult
                {
                    ModuleName = "Network Security",
                    Category = "Network",
                    Findings = findings ?? new List<Finding>
                    {
                        Finding.Critical("LLMNR Enabled", "LLMNR is enabled, allowing name resolution poisoning.", "Network",
                            "Disable LLMNR via Group Policy or registry.",
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0"),
                        Finding.Warning("SMB Signing Disabled", "SMB signing is not required, enabling relay attacks.", "Network",
                            "Enable SMB signing.",
                            "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"),
                        Finding.Warning("Open Port 3389", "RDP port 3389 is open.", "Network",
                            "Disable RDP if not needed."),
                        Finding.Pass("IPv6 Configuration", "IPv6 is properly configured.", "Network"),
                    },
                    StartTime = DateTimeOffset.UtcNow,
                    EndTime = DateTimeOffset.UtcNow,
                    Success = true
                }
            }
        };
        advisor.LastReport = report;
        return advisor;
    }

    #region Help Command

    [Fact]
    public async Task HelpCommand_ReturnsCommandList()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/help");

        Assert.Contains("/scan", response.Message);
        Assert.Contains("/score", response.Message);
        Assert.Contains("/fix", response.Message);
        Assert.Contains("/fixall", response.Message);
        Assert.Contains("/history", response.Message);
        Assert.Contains("/help", response.Message);
    }

    #endregion

    #region Scan Command

    [Fact]
    public async Task ScanCommand_RunsFullAudit()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/scan");

        Assert.Contains("Full Security Audit Complete", response.Message);
        Assert.Contains("Score:", response.Message);
        Assert.Contains("Network", response.Message);
    }

    [Fact]
    public async Task ScanCommand_WithModule_RunsSingleAudit()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/scan network");

        Assert.Contains("Network Security", response.Message);
        Assert.Contains("LLMNR", response.Message);
    }

    [Fact]
    public async Task ScanCommand_UnknownModule_ReturnsError()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/scan nonexistent");

        Assert.Contains("No audit module found", response.Message);
    }

    #endregion

    #region Score Command

    [Fact]
    public async Task ScoreCommand_ReturnsScoreBreakdown()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/score");

        Assert.Contains("Security Score:", response.Message);
        Assert.Contains("/100", response.Message);
        Assert.Contains("Grade:", response.Message);
    }

    [Fact]
    public async Task ScoreCommand_IncludesImprovementAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/score");

        Assert.Contains("To improve your score", response.Message);
    }

    #endregion

    #region Fix Command

    [Fact]
    public async Task FixCommand_NoArgs_ReturnsUsage()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/fix");

        Assert.Contains("Usage:", response.Message);
    }

    [Fact]
    public async Task FixCommand_NoReport_AsksForScan()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/fix LLMNR");

        Assert.Contains("No scan results available", response.Message);
    }

    [Fact]
    public async Task FixCommand_NoFixAvailable_ShowsRemediation()
    {
        var advisor = CreateAdvisorWithReport();
        var response = await advisor.AskAsync("/fix Open Port 3389");

        Assert.Contains("doesn't have an automated fix", response.Message);
    }

    [Fact]
    public async Task FixCommand_UnknownFinding_ShowsAvailable()
    {
        var advisor = CreateAdvisorWithReport();
        var response = await advisor.AskAsync("/fix nonexistent");

        Assert.Contains("No finding matching", response.Message);
    }

    #endregion

    #region FixAll Command

    [Fact]
    public async Task FixAllCommand_NoReport_AsksForScan()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/fixall");

        Assert.Contains("No scan results available", response.Message);
    }

    [Fact]
    public async Task FixAllCommand_NoFixableIssues_ReportsClean()
    {
        var advisor = CreateAdvisorWithReport(new List<Finding>
        {
            Finding.Pass("Everything OK", "All checks passed.", "Test"),
        });
        var response = await advisor.AskAsync("/fixall");

        Assert.Contains("No fixable issues", response.Message);
    }

    #endregion

    #region History Command

    [Fact]
    public async Task HistoryCommand_NoHistory_ReportsEmpty()
    {
        var advisor = CreateAdvisor(); // no history service
        var response = await advisor.AskAsync("/history");

        Assert.Contains("History service is not available", response.Message);
    }

    #endregion

    #region Unknown Command

    [Fact]
    public async Task UnknownCommand_ReturnsError()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("/foobar");

        Assert.Contains("Unknown command", response.Message);
        Assert.Contains("/help", response.Message);
    }

    #endregion

    #region Natural Language - What's Wrong

    [Fact]
    public async Task WhatsWrong_WithIssues_ShowsIssues()
    {
        var advisor = CreateAdvisorWithReport();
        var response = await advisor.AskAsync("what's wrong?");

        Assert.Contains("Critical", response.Message);
        Assert.Contains("LLMNR", response.Message);
        Assert.Contains("Warnings", response.Message);
    }

    [Fact]
    public async Task WhatsWrong_NoIssues_ReportsClean()
    {
        var advisor = CreateAdvisorWithReport(new List<Finding>
        {
            Finding.Pass("All Good", "Everything checks out.", "Test"),
        });
        var response = await advisor.AskAsync("what's wrong?");

        Assert.Contains("looks great", response.Message);
    }

    [Fact]
    public async Task WhatsWrong_VariantPhrases_AllWork()
    {
        var advisor = CreateAdvisorWithReport();

        var phrases = new[] { "show issues", "any problems", "what needs fixing" };
        foreach (var phrase in phrases)
        {
            var response = await advisor.AskAsync(phrase);
            Assert.Contains("LLMNR", response.Message, StringComparison.OrdinalIgnoreCase);
        }
    }

    #endregion

    #region Natural Language - Score

    [Fact]
    public async Task NaturalScore_ReturnsScore()
    {
        var advisor = CreateAdvisor();

        var response = await advisor.AskAsync("what's my score?");
        Assert.Contains("Security Score:", response.Message);
    }

    [Fact]
    public async Task NaturalScore_HowSecure_Works()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("how secure am I?");
        Assert.Contains("Security Score:", response.Message);
    }

    #endregion

    #region Natural Language - Run Scan

    [Fact]
    public async Task NaturalScan_RunsScan()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("run a scan");
        Assert.Contains("Full Security Audit Complete", response.Message);
    }

    [Fact]
    public async Task NaturalScan_ScanEverything_Works()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("scan everything");
        Assert.Contains("Full Security Audit Complete", response.Message);
    }

    #endregion

    #region Natural Language - Fix

    [Fact]
    public async Task NaturalFix_WithoutReport_AsksForScan()
    {
        var advisor = CreateAdvisor();
        // Without a pre-populated report, "how do I fix LLMNR?" should ask for scan
        var response = await advisor.AskAsync("how do I fix LLMNR?");

        Assert.Contains("No scan results available", response.Message);
    }

    #endregion

    #region Natural Language - Explain

    [Fact]
    public async Task Explain_Module_RunsAudit()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("explain network");

        Assert.Contains("Network Security", response.Message);
        Assert.Contains("LLMNR", response.Message);
    }

    [Fact]
    public async Task Explain_Finding_ShowsDetails()
    {
        var advisor = CreateAdvisorWithReport();
        var response = await advisor.AskAsync("explain LLMNR Enabled");

        Assert.Contains("LLMNR Enabled", response.Message);
        Assert.Contains("Critical", response.Message);
    }

    #endregion

    #region Natural Language - Check

    [Fact]
    public async Task Check_Module_RunsSingleScan()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("check network");

        Assert.Contains("Network Security", response.Message);
    }

    #endregion

    #region Security Knowledge Base

    [Fact]
    public async Task SecurityKnowledge_Password_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("how do I set a strong password?");

        Assert.Contains("Password", response.Message);
        Assert.Contains("12 characters", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_Ransomware_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("protect from ransomware");

        Assert.Contains("Ransomware", response.Message);
        Assert.Contains("Controlled Folder Access", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_VPN_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("should I use a VPN?");

        Assert.Contains("VPN", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_Encryption_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("how to encrypt my drive?");

        Assert.Contains("Encryption", response.Message);
        Assert.Contains("BitLocker", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_Malware_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("how to scan for malware?");

        Assert.Contains("Malware", response.Message);
        Assert.Contains("Start-MpScan", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_Phishing_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("phishing protection tips");

        Assert.Contains("Phishing", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_Firewall_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("firewall best practices");

        Assert.Contains("Firewall", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_Privacy_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("how to reduce telemetry and tracking");

        Assert.Contains("Privacy", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_RDP_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("is remote desktop secure?");

        Assert.Contains("Remote Desktop", response.Message);
    }

    [Fact]
    public async Task SecurityKnowledge_Backup_ReturnsAdvice()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("backup best practices");

        Assert.Contains("Backup", response.Message);
        Assert.Contains("3-2-1", response.Message);
    }

    #endregion

    #region Fallback

    [Fact]
    public async Task Fallback_UnknownTopic_ReturnsSuggestions()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("xyzzy quantum 12345");

        Assert.Contains("/scan", response.Message);
        Assert.Contains("/help", response.Message);
    }

    [Fact]
    public async Task EmptyInput_ReturnsHelpPrompt()
    {
        var advisor = CreateAdvisor();
        var response = await advisor.AskAsync("");

        Assert.Contains("/help", response.Message);
    }

    #endregion

    #region FindBestMatch

    [Fact]
    public void FindBestMatch_ExactTitle_Matches()
    {
        var findings = new List<Finding>
        {
            Finding.Critical("LLMNR Enabled", "test", "Network"),
            Finding.Warning("SMB Signing", "test", "Network"),
        };

        var match = SecurityAdvisor.FindBestMatch(findings, "LLMNR Enabled");
        Assert.NotNull(match);
        Assert.Equal("LLMNR Enabled", match.Title);
    }

    [Fact]
    public void FindBestMatch_PartialTitle_Matches()
    {
        var findings = new List<Finding>
        {
            Finding.Critical("LLMNR Enabled", "test", "Network"),
            Finding.Warning("SMB Signing Disabled", "test", "Network"),
        };

        var match = SecurityAdvisor.FindBestMatch(findings, "SMB");
        Assert.NotNull(match);
        Assert.Equal("SMB Signing Disabled", match.Title);
    }

    [Fact]
    public void FindBestMatch_NoMatch_ReturnsNull()
    {
        var findings = new List<Finding>
        {
            Finding.Pass("All Good", "test", "Network"),
        };

        var match = SecurityAdvisor.FindBestMatch(findings, "nonexistent");
        Assert.Null(match);
    }

    [Fact]
    public void FindBestMatch_CategoryMatch_Works()
    {
        var findings = new List<Finding>
        {
            Finding.Warning("Some Issue", "description about firewalls", "Firewall"),
        };

        var match = SecurityAdvisor.FindBestMatch(findings, "firewall");
        Assert.NotNull(match);
        Assert.Equal("Some Issue", match.Title);
    }

    #endregion

    #region Formatting

    [Fact]
    public void FormatFullReport_IncludesAllSections()
    {
        var report = new SecurityReport
        {
            SecurityScore = 75,
            Results = new List<AuditResult>
            {
                new AuditResult
                {
                    ModuleName = "Network Security",
                    Category = "Network",
                    Findings = new List<Finding>
                    {
                        Finding.Critical("Test Critical", "desc", "Network"),
                        Finding.Warning("Test Warning", "desc", "Network"),
                        Finding.Pass("Test Pass", "desc", "Network"),
                    },
                    StartTime = DateTimeOffset.UtcNow,
                    EndTime = DateTimeOffset.UtcNow
                }
            }
        };

        var text = SecurityAdvisor.FormatFullReport(report);

        Assert.Contains("Full Security Audit Complete", text);
        Assert.Contains("75/100", text);
        Assert.Contains("Network", text);
        Assert.Contains("Critical:", text);
        Assert.Contains("Warnings:", text);
    }

    [Fact]
    public void FormatModuleResult_IncludesFindings()
    {
        var result = new AuditResult
        {
            ModuleName = "Firewall Audit",
            Category = "Firewall",
            Findings = new List<Finding>
            {
                Finding.Critical("Firewall Off", "Public profile disabled.", "Firewall",
                    "Enable firewall", "Set-NetFirewallProfile -All -Enabled True"),
                Finding.Pass("Domain Profile", "Domain profile is enabled.", "Firewall"),
            },
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow
        };

        var text = SecurityAdvisor.FormatModuleResult(result);

        Assert.Contains("Firewall Audit", text);
        Assert.Contains("Firewall Off", text);
        Assert.Contains("/fix Firewall Off", text);
        Assert.Contains("Domain Profile", text);
    }

    [Fact]
    public void FormatFindingExplanation_ShowsAllDetails()
    {
        var finding = Finding.Critical("LLMNR Enabled", "LLMNR is enabled.", "Network",
            "Disable LLMNR via Group Policy.", "Set-ItemProperty ...");

        var text = SecurityAdvisor.FormatFindingExplanation(finding);

        Assert.Contains("LLMNR Enabled", text);
        Assert.Contains("Critical", text);
        Assert.Contains("LLMNR is enabled", text);
        Assert.Contains("-20 points", text);
        Assert.Contains("How to fix", text);
        Assert.Contains("Automated fix available", text);
    }

    #endregion

    #region Ollama Integration

    [Fact]
    public void OllamaAvailable_DefaultFalse()
    {
        var advisor = CreateAdvisor();
        Assert.False(advisor.IsOllamaAvailable);
    }

    #endregion

    #region AdvisorResponse

    [Fact]
    public void AdvisorResponse_Text_CreatesCorrectly()
    {
        var response = AdvisorResponse.Text("test message");
        Assert.Equal("test message", response.Message);
        Assert.Null(response.RelatedFindings);
    }

    [Fact]
    public void AdvisorResponse_WithFindings_CreatesCorrectly()
    {
        var findings = new List<Finding>
        {
            Finding.Warning("Test", "desc", "cat"),
        };

        var response = AdvisorResponse.WithFindings("found issues", findings);
        Assert.Equal("found issues", response.Message);
        Assert.NotNull(response.RelatedFindings);
        Assert.Single(response.RelatedFindings);
    }

    #endregion
}
