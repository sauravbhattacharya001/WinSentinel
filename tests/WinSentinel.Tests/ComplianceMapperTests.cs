using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests;

public class ComplianceMapperTests
{
    private readonly ComplianceMapper _mapper = new();

    // ── Helpers ──────────────────────────────────────────────────────

    private static SecurityReport EmptyReport() => new()
    {
        SecurityScore = 100,
        Results = new List<AuditResult>()
    };

    private static SecurityReport ReportWith(params Finding[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = findings.FirstOrDefault()?.Category ?? "General",
            Findings = findings.ToList()
        };
        return new SecurityReport
        {
            SecurityScore = 50,
            Results = new List<AuditResult> { result }
        };
    }

    private static SecurityReport MultiCategoryReport()
    {
        return new SecurityReport
        {
            SecurityScore = 65,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "AccountAudit", Category = "Accounts",
                    Findings = new List<Finding>
                    {
                        Finding.Critical("Weak password policy", "Password complexity not enforced", "Accounts"),
                        Finding.Warning("Guest account enabled", "Guest account is active", "Accounts"),
                        Finding.Pass("Admin account renamed", "Default admin renamed", "Accounts")
                    }
                },
                new()
                {
                    ModuleName = "FirewallAudit", Category = "Firewall",
                    Findings = new List<Finding>
                    {
                        Finding.Pass("Firewall enabled", "Windows Firewall is on for all profiles", "Firewall"),
                        Finding.Warning("Open port 3389", "RDP port is open to all", "Firewall")
                    }
                },
                new()
                {
                    ModuleName = "DefenderAudit", Category = "Defender",
                    Findings = new List<Finding>
                    {
                        Finding.Critical("Real-time protection disabled", "Defender real-time scanning is off", "Defender"),
                        Finding.Warning("Definitions outdated", "Virus definitions are 15 days old", "Defender")
                    }
                },
                new()
                {
                    ModuleName = "UpdateAudit", Category = "Updates",
                    Findings = new List<Finding>
                    {
                        Finding.Warning("Pending updates", "12 updates pending install", "Updates")
                    }
                },
                new()
                {
                    ModuleName = "EncryptionAudit", Category = "Encryption",
                    Findings = new List<Finding>
                    {
                        Finding.Critical("BitLocker not enabled", "System drive not encrypted", "Encryption")
                    }
                },
                new()
                {
                    ModuleName = "EventLogAudit", Category = "Event Logs",
                    Findings = new List<Finding>
                    {
                        Finding.Pass("Audit policy configured", "Security audit logging is enabled", "Event Logs")
                    }
                }
            }
        };
    }

    // ── Framework Discovery ──────────────────────────────────────────

    [Fact]
    public void FrameworkIds_ContainsFourFrameworks()
    {
        Assert.Equal(4, _mapper.FrameworkIds.Count);
        Assert.Contains("cis", _mapper.FrameworkIds);
        Assert.Contains("nist", _mapper.FrameworkIds);
        Assert.Contains("pci-dss", _mapper.FrameworkIds);
        Assert.Contains("hipaa", _mapper.FrameworkIds);
    }

    [Theory]
    [InlineData("cis", "CIS Microsoft Windows Benchmarks")]
    [InlineData("nist", "NIST SP 800-53 Rev. 5")]
    [InlineData("pci-dss", "PCI DSS v4.0")]
    [InlineData("hipaa", "HIPAA Security Rule")]
    public void GetFramework_ReturnsCorrectName(string id, string expectedName)
    {
        var fw = _mapper.GetFramework(id);
        Assert.NotNull(fw);
        Assert.Equal(expectedName, fw!.Name);
    }

    [Fact]
    public void GetFramework_UnknownId_ReturnsNull()
    {
        Assert.Null(_mapper.GetFramework("soc2"));
    }

    [Fact]
    public void GetFramework_CaseInsensitive()
    {
        Assert.NotNull(_mapper.GetFramework("CIS"));
        Assert.NotNull(_mapper.GetFramework("NIST"));
    }

    [Theory]
    [InlineData("cis")]
    [InlineData("nist")]
    [InlineData("pci-dss")]
    [InlineData("hipaa")]
    public void EachFramework_HasControls(string id)
    {
        var fw = _mapper.GetFramework(id);
        Assert.NotNull(fw);
        Assert.NotEmpty(fw!.Controls);
    }

    [Theory]
    [InlineData("cis")]
    [InlineData("nist")]
    [InlineData("pci-dss")]
    [InlineData("hipaa")]
    public void EachControl_HasIdAndTitle(string id)
    {
        var fw = _mapper.GetFramework(id)!;
        foreach (var ctrl in fw.Controls)
        {
            Assert.False(string.IsNullOrWhiteSpace(ctrl.Id), "Control ID should not be empty");
            Assert.False(string.IsNullOrWhiteSpace(ctrl.Title), "Control Title should not be empty");
        }
    }

    // ── Empty Report ─────────────────────────────────────────────────

    [Fact]
    public void Evaluate_EmptyReport_AllNotAssessed()
    {
        var report = _mapper.Evaluate(EmptyReport(), "cis");
        Assert.Equal("cis", report.FrameworkId);
        Assert.All(report.Controls, c => Assert.Equal(ControlStatus.NotAssessed, c.Status));
        Assert.Equal(ComplianceVerdict.NotAssessed, report.Summary.OverallVerdict);
    }

    // ── Single Finding ───────────────────────────────────────────────

    [Fact]
    public void Evaluate_PassFinding_ControlPasses()
    {
        var report = ReportWith(
            Finding.Pass("Password policy enforced", "Strong password complexity enabled", "Accounts"));

        var result = _mapper.Evaluate(report, "cis");
        var passwordCtrl = result.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.Equal(ControlStatus.Pass, passwordCtrl.Status);
    }

    [Fact]
    public void Evaluate_CriticalFinding_ControlFails()
    {
        var report = ReportWith(
            Finding.Critical("Weak password policy", "No complexity requirements", "Accounts"));

        var result = _mapper.Evaluate(report, "cis");
        var passwordCtrl = result.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.Equal(ControlStatus.Fail, passwordCtrl.Status);
    }

    [Fact]
    public void Evaluate_WarningFinding_ControlPartial()
    {
        var report = ReportWith(
            Finding.Warning("Weak password length", "Minimum password length is only 6", "Accounts"));

        var result = _mapper.Evaluate(report, "cis");
        var passwordCtrl = result.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.Equal(ControlStatus.Partial, passwordCtrl.Status);
    }

    // ── Unknown Framework ────────────────────────────────────────────

    [Fact]
    public void Evaluate_UnknownFramework_Throws()
    {
        Assert.Throws<ArgumentException>(() => _mapper.Evaluate(EmptyReport(), "soc2"));
    }

    // ── Multi-Category Report ────────────────────────────────────────

    [Fact]
    public void Evaluate_MultiCategory_CIS_MixedResults()
    {
        var report = MultiCategoryReport();
        var result = _mapper.Evaluate(report, "cis");

        // Password policy: has critical "Weak password" -> Fail
        var password = result.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.Equal(ControlStatus.Fail, password.Status);

        // Firewall public profile: has pass "Firewall enabled" + warning "Open port" -> Partial
        var fwPublic = result.Controls.First(c => c.ControlId == "CIS-5.3");
        Assert.True(fwPublic.Status == ControlStatus.Partial || fwPublic.Status == ControlStatus.Pass,
            $"Expected Partial or Pass but got {fwPublic.Status}");

        // Defender: critical "Real-time protection disabled" -> Fail
        var defender = result.Controls.First(c => c.ControlId == "CIS-9.1");
        Assert.Equal(ControlStatus.Fail, defender.Status);

        // BitLocker: critical "not enabled" -> Fail
        var bitlocker = result.Controls.First(c => c.ControlId == "CIS-18.1");
        Assert.Equal(ControlStatus.Fail, bitlocker.Status);
    }

    [Fact]
    public void Evaluate_MultiCategory_NIST_MapsCorrectly()
    {
        var report = MultiCategoryReport();
        var result = _mapper.Evaluate(report, "nist");

        // AC-2 Account Management: matches "account" keyword (guest account warning + admin pass)
        // but NOT the password critical (no "account"/"user" keyword in that finding)
        var ac2 = result.Controls.First(c => c.ControlId == "AC-2");
        Assert.Equal(ControlStatus.Partial, ac2.Status);

        // SI-3 Malicious Code Protection should be Fail (defender critical)
        var si3 = result.Controls.First(c => c.ControlId == "SI-3");
        Assert.Equal(ControlStatus.Fail, si3.Status);

        // SC-28 Protection of Info at Rest
        var sc28 = result.Controls.First(c => c.ControlId == "SC-28");
        // Might be Fail (only critical encryption finding) or Partial (if other findings match via keywords)
        Assert.NotEqual(ControlStatus.Pass, sc28.Status);
        Assert.NotEqual(ControlStatus.NotAssessed, sc28.Status);
    }

    // ── Summary Calculations ─────────────────────────────────────────

    [Fact]
    public void Summary_AllPassing_Compliant()
    {
        var report = new SecurityReport
        {
            SecurityScore = 100,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "AccountAudit", Category = "Accounts",
                    Findings = new List<Finding>
                    {
                        Finding.Pass("Strong password policy", "Complexity enforced", "Accounts"),
                        Finding.Pass("Account lockout configured", "Lockout after 5 attempts", "Accounts")
                    }
                },
                new()
                {
                    ModuleName = "FirewallAudit", Category = "Firewall",
                    Findings = new List<Finding>
                    {
                        Finding.Pass("Firewall enabled", "All profiles active", "Firewall")
                    }
                }
            }
        };

        var result = _mapper.Evaluate(report, "cis");
        Assert.True(result.Summary.PassCount > 0);
        Assert.Equal(0, result.Summary.FailCount);
    }

    [Fact]
    public void Summary_HasFailures_NonCompliant()
    {
        var report = MultiCategoryReport();
        var result = _mapper.Evaluate(report, "cis");
        Assert.Equal(ComplianceVerdict.NonCompliant, result.Summary.OverallVerdict);
        Assert.True(result.Summary.FailCount > 0);
    }

    [Fact]
    public void Summary_CompliancePercentage_Calculated()
    {
        var report = MultiCategoryReport();
        var result = _mapper.Evaluate(report, "cis");
        // Should be a valid percentage
        Assert.InRange(result.Summary.CompliancePercentage, 0, 100);
    }

    // ── Remediation ──────────────────────────────────────────────────

    [Fact]
    public void FailedControl_IncludesRemediation()
    {
        var finding = Finding.Critical("No encryption", "Drive not encrypted", "Encryption");
        finding.Remediation = "Enable BitLocker on system drive";
        var report = ReportWith(finding);

        var result = _mapper.Evaluate(report, "cis");
        var bitlocker = result.Controls.First(c => c.ControlId == "CIS-18.1");
        Assert.Equal(ControlStatus.Fail, bitlocker.Status);
        Assert.Contains("Enable BitLocker", bitlocker.Remediation.First());
    }

    [Fact]
    public void PassingControl_NoRemediation()
    {
        var report = ReportWith(
            Finding.Pass("BitLocker enabled", "System drive encrypted", "Encryption"));

        var result = _mapper.Evaluate(report, "cis");
        var bitlocker = result.Controls.First(c => c.ControlId == "CIS-18.1");
        Assert.Equal(ControlStatus.Pass, bitlocker.Status);
        Assert.Empty(bitlocker.Remediation);
    }

    // ── EvaluateAll ──────────────────────────────────────────────────

    [Fact]
    public void EvaluateAll_ReturnsFourReports()
    {
        var reports = _mapper.EvaluateAll(MultiCategoryReport());
        Assert.Equal(4, reports.Count);
        Assert.Contains(reports, r => r.FrameworkId == "cis");
        Assert.Contains(reports, r => r.FrameworkId == "nist");
        Assert.Contains(reports, r => r.FrameworkId == "pci-dss");
        Assert.Contains(reports, r => r.FrameworkId == "hipaa");
    }

    // ── CrossFrameworkAnalysis ────────────────────────────────────────

    [Fact]
    public void CrossFramework_IncludesAllFrameworks()
    {
        var summary = _mapper.CrossFrameworkAnalysis(MultiCategoryReport());
        Assert.Equal(65, summary.SecurityScore);
        Assert.Equal(4, summary.FrameworkResults.Count);
    }

    [Fact]
    public void CrossFramework_CriticalGaps_Listed()
    {
        var summary = _mapper.CrossFrameworkAnalysis(MultiCategoryReport());
        // At least one framework should report critical gaps
        Assert.True(summary.FrameworkResults.Any(f => f.CriticalGaps.Count > 0));
    }

    [Fact]
    public void CrossFramework_EmptyReport_AllNotAssessed()
    {
        var summary = _mapper.CrossFrameworkAnalysis(EmptyReport());
        Assert.All(summary.FrameworkResults,
            f => Assert.Equal(ComplianceVerdict.NotAssessed, f.Verdict));
    }

    // ── Control Matching ─────────────────────────────────────────────

    [Fact]
    public void PasswordFinding_MatchesMultipleFrameworks()
    {
        var report = ReportWith(
            Finding.Critical("Weak password", "No complexity", "Accounts"));

        var cis = _mapper.Evaluate(report, "cis");
        var nist = _mapper.Evaluate(report, "nist");
        var pci = _mapper.Evaluate(report, "pci-dss");

        // CIS-1.1 (Password Policy)
        Assert.Equal(ControlStatus.Fail,
            cis.Controls.First(c => c.ControlId == "CIS-1.1").Status);

        // NIST IA-5 (Authenticator Management)
        Assert.Equal(ControlStatus.Fail,
            nist.Controls.First(c => c.ControlId == "IA-5").Status);

        // PCI-8.1 (User Authentication)
        Assert.Equal(ControlStatus.Fail,
            pci.Controls.First(c => c.ControlId == "PCI-8.1").Status);
    }

    [Fact]
    public void FirewallFinding_MatchesNetworkControls()
    {
        var report = ReportWith(
            Finding.Pass("Firewall enabled", "All firewall profiles active", "Firewall"));

        var cis = _mapper.Evaluate(report, "cis");
        var nist = _mapper.Evaluate(report, "nist");

        // CIS firewall controls should pass
        Assert.Equal(ControlStatus.Pass,
            cis.Controls.First(c => c.ControlId == "CIS-5.1").Status);

        // NIST SC-7 Boundary Protection
        Assert.Equal(ControlStatus.Pass,
            nist.Controls.First(c => c.ControlId == "SC-7").Status);
    }

    [Fact]
    public void UnrelatedCategory_DoesNotMatchControl()
    {
        // WiFi finding should not match Accounts controls
        var report = ReportWith(
            Finding.Critical("Weak WiFi security", "WPA2 not enforced", "WiFi"));

        var cis = _mapper.Evaluate(report, "cis");
        // Password control shouldn't be affected by WiFi findings
        var passwordCtrl = cis.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.Equal(ControlStatus.NotAssessed, passwordCtrl.Status);
    }

    // ── Edge Cases ───────────────────────────────────────────────────

    [Fact]
    public void InfoSeverity_TreatedAsPass()
    {
        var report = ReportWith(
            Finding.Info("Password policy noted", "Password policy is configured", "Accounts"));

        var result = _mapper.Evaluate(report, "cis");
        var passwordCtrl = result.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.Equal(ControlStatus.Pass, passwordCtrl.Status);
    }

    [Fact]
    public void MixedSeverities_CriticalWins()
    {
        var report = new SecurityReport
        {
            SecurityScore = 50,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "AccountAudit", Category = "Accounts",
                    Findings = new List<Finding>
                    {
                        Finding.Pass("Some check passed", "Password length OK", "Accounts"),
                        Finding.Critical("Critical password issue", "No complexity", "Accounts")
                    }
                }
            }
        };

        var result = _mapper.Evaluate(report, "cis");
        var passwordCtrl = result.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.Equal(ControlStatus.Fail, passwordCtrl.Status);
    }

    [Fact]
    public void RelatedFindings_AttachedToControl()
    {
        var report = ReportWith(
            Finding.Critical("Weak password", "No complexity", "Accounts"),
            Finding.Warning("Short password", "Min length is 4", "Accounts"));

        var result = _mapper.Evaluate(report, "cis");
        var passwordCtrl = result.Controls.First(c => c.ControlId == "CIS-1.1");
        Assert.True(passwordCtrl.RelatedFindings.Count >= 2);
    }

    [Fact]
    public void Report_HasCorrectMetadata()
    {
        var result = _mapper.Evaluate(MultiCategoryReport(), "nist");
        Assert.Equal("nist", result.FrameworkId);
        Assert.Equal("NIST SP 800-53 Rev. 5", result.FrameworkName);
        Assert.Equal("Rev. 5", result.FrameworkVersion);
        Assert.True(result.GeneratedAt <= DateTimeOffset.UtcNow);
    }
}
