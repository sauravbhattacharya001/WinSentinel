using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class RootCauseAnalyzerTests
{
    private readonly RootCauseAnalyzer _analyzer = new();

    private static SecurityReport MakeReport(params Finding[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            Findings = findings.ToList()
        };
        return new SecurityReport { Results = new List<AuditResult> { result } };
    }

    private static SecurityReport MakeMultiModuleReport(params (string module, Finding[] findings)[] modules)
    {
        var report = new SecurityReport();
        foreach (var (module, findings) in modules)
        {
            report.Results.Add(new AuditResult
            {
                ModuleName = module,
                Category = module,
                Findings = findings.ToList()
            });
        }
        return report;
    }

    // ── Basic clustering ──

    [Fact]
    public void EmptyReport_ReturnsEmptyClusters()
    {
        var report = new SecurityReport();
        var result = _analyzer.Analyze(report);

        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.RootCausesIdentified);
        Assert.Empty(result.RootCauses);
        Assert.Equal(100.0, result.CoveragePercent);
    }

    [Fact]
    public void PassFindings_AreExcluded()
    {
        var report = MakeReport(
            Finding.Pass("Update OK", "All updates installed", "System"),
            Finding.Pass("Firewall OK", "Firewall enabled", "Network")
        );

        var result = _analyzer.Analyze(report);
        Assert.Equal(0, result.TotalFindings);
    }

    [Fact]
    public void SingleFinding_NoCluster()
    {
        var report = MakeReport(
            Finding.Warning("Firewall rule open", "Port 445 open", "Network")
        );

        var result = _analyzer.Analyze(report);
        Assert.Equal(0, result.RootCausesIdentified);
        Assert.Equal(1, result.UngroupedFindings);
    }

    [Fact]
    public void TwoRelatedFindings_FormCluster()
    {
        var report = MakeReport(
            Finding.Warning("Firewall inbound rule too broad", "All ports open", "Network"),
            Finding.Critical("Firewall outbound rule missing", "No outbound filtering", "Network")
        );

        var result = _analyzer.Analyze(report);
        Assert.True(result.RootCausesIdentified >= 1);
        Assert.True(result.FindingsCovered >= 2);
    }

    [Fact]
    public void UpdateRelatedFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Critical("Windows Update disabled", "Auto-update is off", "System"),
            Finding.Warning("Outdated .NET Framework", "Version is outdated", "System"),
            Finding.Warning("Missing security patch KB123", "KB123 not installed", "System")
        );

        var result = _analyzer.Analyze(report);
        var updateCause = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-UPDATE");
        Assert.NotNull(updateCause);
        Assert.True(updateCause.ImpactCount >= 2);
    }

    [Fact]
    public void DefenderFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Critical("Real-time protection disabled", "Defender real-time protection off", "Antivirus"),
            Finding.Warning("Virus definitions outdated", "Defender virus definition old", "Antivirus")
        );

        var result = _analyzer.Analyze(report);
        var defenderCause = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-DEFENDER");
        Assert.NotNull(defenderCause);
        Assert.Equal(2, defenderCause.ImpactCount);
    }

    // ── Severity and scoring ──

    [Fact]
    public void WorstSeverity_IsCorrect()
    {
        var report = MakeReport(
            Finding.Warning("Firewall rule issue", "Inbound rule", "Network"),
            Finding.Critical("Firewall disabled", "Firewall is off", "Network"),
            Finding.Info("Firewall info", "Extra info about firewall", "Network")
        );

        var result = _analyzer.Analyze(report);
        var fwCause = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-FIREWALL");
        Assert.NotNull(fwCause);
        Assert.Equal(Severity.Critical, fwCause.WorstSeverity);
    }

    [Fact]
    public void ImpactScore_CalculatesCorrectly()
    {
        var report = MakeReport(
            Finding.Critical("Update missing", "Missing critical update", "System"),
            Finding.Warning("Outdated software", "Software is outdated", "System")
        );

        var result = _analyzer.Analyze(report);
        var cause = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-UPDATE");
        Assert.NotNull(cause);
        Assert.Equal(25, cause.ImpactScore); // 20 + 5
    }

    [Fact]
    public void RootCauses_SortedByImpactScoreDescending()
    {
        var report = MakeReport(
            // Low-impact firewall cluster
            Finding.Warning("Firewall rule 1", "Open port", "Network"),
            Finding.Warning("Firewall rule 2", "Open inbound rule", "Network"),
            // High-impact update cluster
            Finding.Critical("Update disabled", "Windows Update off", "System"),
            Finding.Critical("Outdated OS", "OS is outdated", "System"),
            Finding.Warning("Missing patch KB999", "KB not installed", "System")
        );

        var result = _analyzer.Analyze(report);
        Assert.True(result.RootCauses.Count >= 2);
        Assert.True(result.RootCauses[0].ImpactScore >= result.RootCauses[1].ImpactScore);
    }

    // ── Coverage ──

    [Fact]
    public void CoveragePercent_IsAccurate()
    {
        var report = MakeReport(
            Finding.Warning("Firewall rule open", "Port open", "Network"),
            Finding.Warning("Firewall outbound", "Outbound rule", "Network"),
            Finding.Warning("Random finding", "Unrelated issue", "Misc"),
            Finding.Info("Another finding", "Something else", "Other")
        );

        var result = _analyzer.Analyze(report);
        Assert.Equal(4, result.TotalFindings);
        Assert.Equal(result.FindingsCovered + result.UngroupedFindings, result.TotalFindings);
    }

    // ── Top actions ──

    [Fact]
    public void TopActions_ContainsAtMost5()
    {
        var findings = new List<Finding>();
        // Create findings that match many patterns
        foreach (var keyword in new[] { "update", "firewall", "defender", "encryption", "password", "remote desktop", "telemetry" })
        {
            findings.Add(Finding.Warning($"{keyword} issue 1", $"Problem with {keyword}", "Test"));
            findings.Add(Finding.Warning($"{keyword} issue 2", $"Another {keyword} problem", "Test"));
        }

        var report = MakeReport(findings.ToArray());
        var result = _analyzer.Analyze(report);
        Assert.True(result.TopActions.Count <= 5);
    }

    [Fact]
    public void TopActions_IncludeFindingCount()
    {
        var report = MakeReport(
            Finding.Warning("Firewall inbound rule", "Open", "Network"),
            Finding.Warning("Firewall outbound rule", "Missing", "Network")
        );

        var result = _analyzer.Analyze(report);
        if (result.TopActions.Count > 0)
        {
            Assert.Contains("findings", result.TopActions[0]);
        }
    }

    // ── Custom patterns ──

    [Fact]
    public void CustomPattern_CanBeAdded()
    {
        var analyzer = new RootCauseAnalyzer();
        var customPattern = new RootCauseAnalyzer.CausePattern(
            "RC-CUSTOM", "Custom Root Cause",
            "Test custom pattern",
            "Custom",
            new[] { "foobar" },
            "Fix foobar",
            "Fix-Foobar"
        );

        analyzer.AddPattern(customPattern);
        Assert.Contains(analyzer.Patterns, p => p.CauseId == "RC-CUSTOM");
    }

    [Fact]
    public void CustomPattern_MatchesFindings()
    {
        var analyzer = new RootCauseAnalyzer();
        analyzer.AddPattern(new RootCauseAnalyzer.CausePattern(
            "RC-CUSTOM", "Custom Issue",
            "Custom pattern test",
            "Custom",
            new[] { "foobar" },
            "Fix it",
            null
        ));

        var report = MakeReport(
            Finding.Warning("Foobar detected", "Found foobar", "Test"),
            Finding.Warning("Another foobar", "More foobar issues", "Test")
        );

        var result = analyzer.Analyze(report);
        var custom = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-CUSTOM");
        Assert.NotNull(custom);
        Assert.Equal(2, custom.ImpactCount);
    }

    [Fact]
    public void AddPattern_NullThrows()
    {
        Assert.Throws<ArgumentNullException>(() => _analyzer.AddPattern(null!));
    }

    // ── Multi-module analysis ──

    [Fact]
    public void CrossModuleFindings_ClusterTogether()
    {
        var report = MakeMultiModuleReport(
            ("Firewall", new[] { Finding.Warning("Firewall rule permissive", "Too broad", "Network") }),
            ("Network", new[] { Finding.Warning("Open port via firewall", "Exposed port", "Network") })
        );

        var result = _analyzer.Analyze(report);
        Assert.True(result.RootCausesIdentified >= 1);
    }

    [Fact]
    public void MultiModule_UngroupedFindings_AreCorrect()
    {
        var report = MakeMultiModuleReport(
            ("System", new[] { Finding.Warning("Random issue", "Unmatched", "Misc") }),
            ("Other", new[] { Finding.Info("Exotic finding", "Very specific", "Niche") })
        );

        var result = _analyzer.Analyze(report);
        Assert.Equal(2, result.UngroupedFindings);
        Assert.Equal(2, result.Ungrouped.Count);
    }

    // ── Description matching ──

    [Fact]
    public void MatchesOnDescription_NotJustTitle()
    {
        var report = MakeReport(
            Finding.Warning("Check 1", "BitLocker is not enabled on drive C:", "Encryption"),
            Finding.Warning("Check 2", "Drive D: is unencrypted", "Encryption")
        );

        var result = _analyzer.Analyze(report);
        var encCause = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-ENCRYPTION");
        Assert.NotNull(encCause);
    }

    // ── Edge cases ──

    [Fact]
    public void Analyze_NullReport_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _analyzer.Analyze((SecurityReport)null!));
    }

    [Fact]
    public void AnalyzeResults_Works()
    {
        var results = new[]
        {
            new AuditResult
            {
                ModuleName = "Test",
                Category = "Test",
                Findings = new List<Finding>
                {
                    Finding.Warning("WiFi open network saved", "Open WiFi saved", "Network"),
                    Finding.Warning("WiFi WEP detected", "WEP wireless network", "Network")
                }
            }
        };

        var result = _analyzer.Analyze(results);
        Assert.True(result.RootCausesIdentified >= 1);
    }

    [Fact]
    public void BuiltInPatterns_AreRegistered()
    {
        Assert.True(_analyzer.Patterns.Count >= 14);
    }

    // ── Fix command ──

    [Fact]
    public void FixCommand_IsPopulatedForKnownCauses()
    {
        var report = MakeReport(
            Finding.Critical("Windows Update disabled", "Auto-update off", "System"),
            Finding.Warning("Outdated software", "Software is outdated", "System")
        );

        var result = _analyzer.Analyze(report);
        var updateCause = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-UPDATE");
        Assert.NotNull(updateCause);
        Assert.NotNull(updateCause.FixCommand);
    }

    [Fact]
    public void FixCommand_CanBeNull()
    {
        var report = MakeReport(
            Finding.Warning("Browser extension risky", "Chrome extension suspicious", "Browser"),
            Finding.Warning("Browser password issue", "Browser stored passwords", "Browser")
        );

        var result = _analyzer.Analyze(report);
        var browserCause = result.RootCauses.FirstOrDefault(rc => rc.Id == "RC-BROWSER");
        Assert.NotNull(browserCause);
        Assert.Null(browserCause.FixCommand);
    }

    // ── Specific root cause patterns ──

    [Fact]
    public void PrivacyFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Warning("Telemetry level high", "Windows telemetry is full", "Privacy"),
            Finding.Warning("Advertising ID enabled", "Tracking advertising ID", "Privacy")
        );

        var result = _analyzer.Analyze(report);
        Assert.Contains(result.RootCauses, rc => rc.Id == "RC-PRIVACY");
    }

    [Fact]
    public void NetworkProtocolFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Warning("SMBv1 enabled", "Legacy SMB protocol", "Network"),
            Finding.Warning("NetBIOS over TCP", "NetBIOS is active", "Network")
        );

        var result = _analyzer.Analyze(report);
        Assert.Contains(result.RootCauses, rc => rc.Id == "RC-NETWORK");
    }

    [Fact]
    public void BackupFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Warning("No backup configured", "System backup not found", "Backup"),
            Finding.Warning("System restore disabled", "No restore points exist", "Backup")
        );

        var result = _analyzer.Analyze(report);
        Assert.Contains(result.RootCauses, rc => rc.Id == "RC-BACKUP");
    }

    [Fact]
    public void CertificateFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Warning("Expired certificate found", "Certificate expired", "Certificates"),
            Finding.Warning("Self-signed cert in store", "Self-signed certificate", "Certificates")
        );

        var result = _analyzer.Analyze(report);
        Assert.Contains(result.RootCauses, rc => rc.Id == "RC-CERT");
    }

    [Fact]
    public void AuditLogFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Warning("Audit policy not configured", "No audit policy set", "Logging"),
            Finding.Warning("Security log size too small", "Security log under limit", "Logging")
        );

        var result = _analyzer.Analyze(report);
        Assert.Contains(result.RootCauses, rc => rc.Id == "RC-AUDIT-LOG");
    }

    [Fact]
    public void AccountFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Warning("Weak password policy", "No password complexity", "Account"),
            Finding.Warning("Guest account enabled", "Guest account is active", "Account"),
            Finding.Warning("UAC disabled", "User Account Control off", "Account")
        );

        var result = _analyzer.Analyze(report);
        Assert.Contains(result.RootCauses, rc => rc.Id == "RC-ACCOUNT");
    }

    [Fact]
    public void RemoteAccessFindings_ClusterTogether()
    {
        var report = MakeReport(
            Finding.Warning("RDP enabled", "Remote Desktop is on", "Remote"),
            Finding.Warning("WinRM exposed", "WinRM remote management active", "Remote")
        );

        var result = _analyzer.Analyze(report);
        Assert.Contains(result.RootCauses, rc => rc.Id == "RC-REMOTE");
    }

    // ── Finding not double-counted ──

    [Fact]
    public void Finding_NotAssignedToMultipleCauses()
    {
        // A finding about "update firewall" could match both RC-UPDATE and RC-FIREWALL
        // but should only be assigned to one
        var report = MakeReport(
            Finding.Warning("Update firewall rules", "Update the firewall configuration", "Network"),
            Finding.Warning("Another update issue", "Missing update KB", "System"),
            Finding.Warning("Firewall disabled", "Windows Firewall off", "Network")
        );

        var result = _analyzer.Analyze(report);
        var totalAssigned = result.RootCauses.Sum(rc => rc.ImpactCount);
        Assert.Equal(result.FindingsCovered, totalAssigned);
        Assert.Equal(result.TotalFindings, result.FindingsCovered + result.UngroupedFindings);
    }
}
