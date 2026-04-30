using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class DefenseEvasionDetectorTests
{
    private static AuditHistoryService MakeHistory() => new();

    private static SecurityReport MakeReport(params (string module, Finding[] findings)[] modules)
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

    private static Finding MakeFinding(string title, string desc = "",
        Severity severity = Severity.Warning) => new()
    {
        Title = title,
        Description = desc,
        Category = "Security",
        Severity = severity,
        Timestamp = DateTimeOffset.UtcNow.AddHours(-1)
    };

    // ── Basic Tests ──────────────────────────────────────────────

    [Fact]
    public void Detect_EmptyReport_ReturnsCleanReport()
    {
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(new SecurityReport(), historyDays: 30);

        Assert.Equal(0, report.EvasionsDetected);
        Assert.Equal(0, report.ThreatScore);
        Assert.Equal("Minimal", report.ThreatLevel);
        Assert.Empty(report.Evasions);
        Assert.Empty(report.Campaigns);
        Assert.NotNull(report.Recommendations);
    }

    [Fact]
    public void Detect_NoEvasionFindings_ReturnsZeroDetections()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("High CPU usage by chrome.exe") }),
            ("NetworkAudit", new[] { MakeFinding("DNS query to google.com") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(0, report.EvasionsDetected);
        Assert.Equal(0, report.ThreatScore);
    }

    // ── Technique Detection Tests ────────────────────────────────

    [Fact]
    public void Detect_DisableDefender_DetectsImpairDefenses()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] { MakeFinding("Tamper protection disabled", "Disable Defender real-time monitoring") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1562.001", report.Evasions[0].MitreTechnique);
        Assert.Equal("Antivirus/EDR", report.Evasions[0].TargetDefense);
    }

    [Fact]
    public void Detect_ClearEventLogs_DetectsIndicatorRemoval()
    {
        var secReport = MakeReport(
            ("EventLogAudit", new[] { MakeFinding("Event log cleared", "wevtutil cl Security was executed") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1070.001", report.Evasions[0].MitreTechnique);
        Assert.Equal("Event Logs", report.Evasions[0].TargetDefense);
    }

    [Fact]
    public void Detect_Masquerading_DetectsNameMismatch()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("Name mismatch: svchost.exe running from temp folder") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1036", report.Evasions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ObfuscatedCommand_DetectsObfuscation()
    {
        var secReport = MakeReport(
            ("PowerShellAudit", new[] { MakeFinding("Obfuscated PowerShell command", "Encoded command with base64 encoded payload") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1027", report.Evasions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ProxyExecution_DetectsLolbin()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("Suspicious rundll32 execution", "rundll32.exe loading unknown DLL from AppData") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1218", report.Evasions[0].MitreTechnique);
        Assert.Equal("rundll32.exe", report.Evasions[0].ProcessName);
    }

    [Fact]
    public void Detect_HiddenFiles_DetectsHiddenArtifacts()
    {
        var secReport = MakeReport(
            ("FileAudit", new[] { MakeFinding("Hidden attribute set on executable in System32", "attrib +h applied to suspicious binary") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1564.001", report.Evasions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_SandboxEvasion_DetectsEnvironmentCheck()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("VM detect routines found", "Process performing anti-analysis environment check") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1497", report.Evasions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_PassTheHash_DetectsCredentialEvasion()
    {
        var secReport = MakeReport(
            ("AccountAudit", new[] { MakeFinding("Pass the hash activity detected", "Lateral authentication using stolen token NTLM") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
        Assert.Equal("T1550", report.Evasions[0].MitreTechnique);
    }

    // ── Automation Detection ─────────────────────────────────────

    [Fact]
    public void Detect_AutomatedEvasion_IncreasesConfidence()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] { MakeFinding("PowerShell script disable defender", "Automated script to disable antivirus via Set-MpPreference") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Evasions[0].IsAutomated);
        Assert.True(report.Evasions[0].Confidence > 0.9);
        Assert.Contains("Automated/scripted evasion detected", report.Evasions[0].Indicators);
    }

    [Fact]
    public void Detect_AttackFramework_FlagsIndicator()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("Cobalt Strike beacon using rundll32", "rundll32 proxy execution via cobalt strike framework") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Contains("Known attack framework referenced", report.Evasions[0].Indicators);
        Assert.Equal(EvasionSeverity.Critical, report.Evasions[0].Severity);
    }

    // ── Severity Classification ──────────────────────────────────

    [Fact]
    public void Detect_SecurityToolDisable_ClassifiesHighSeverity()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] { MakeFinding("Disable firewall rule", "Disable firewall via netsh") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(EvasionSeverity.High, report.Evasions[0].Severity);
    }

    [Fact]
    public void Detect_Obfuscation_ClassifiesMediumSeverity()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("Obfuscated script detected in temp folder") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(EvasionSeverity.Medium, report.Evasions[0].Severity);
    }

    [Fact]
    public void Detect_HiddenFiles_ClassifiesLowSeverity()
    {
        var secReport = MakeReport(
            ("FileAudit", new[] { MakeFinding("Concealed file in user profile") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(EvasionSeverity.Low, report.Evasions[0].Severity);
    }

    // ── Campaign Detection ───────────────────────────────────────

    [Fact]
    public void Detect_MultipleEvasionTechniques_DetectsCampaign()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] { MakeFinding("Tamper protection disabled", "Disable defender") }),
            ("EventLogAudit", new[] { MakeFinding("Security event log cleared", "wevtutil cl Security") }),
            ("ProcessAudit", new[] { MakeFinding("Obfuscated payload executed", "Encoded command base64 encoded script") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Campaigns.Count >= 1);
        Assert.True(report.Campaigns[0].TechniqueCount >= 2);
    }

    [Fact]
    public void Detect_DisableAndClearLogs_ClassifiesFullStealth()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] { MakeFinding("Disable defender via script", "Automated disable antivirus") }),
            ("EventLogAudit", new[] { MakeFinding("All event logs cleared", "wevtutil cl System") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Campaigns.Count >= 1);
        Assert.Equal("Full Stealth Operation", report.Campaigns[0].CampaignType);
    }

    // ── Scoring & Threat Level ───────────────────────────────────

    [Fact]
    public void Detect_SingleLowSeverity_MinimalThreat()
    {
        var secReport = MakeReport(
            ("FileAudit", new[] { MakeFinding("Hidden directory found with concealed files") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.ThreatScore < 20);
        Assert.Equal("Minimal", report.ThreatLevel);
    }

    [Fact]
    public void Detect_ManyHighSeverity_HighThreatScore()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] {
                MakeFinding("Tamper protection disabled", "Disable defender real-time monitoring"),
                MakeFinding("Firewall service stopped", "Disable firewall via powershell script")
            }),
            ("EventLogAudit", new[] {
                MakeFinding("Security log cleared", "wevtutil cl Security"),
                MakeFinding("Application log cleared", "wevtutil cl Application")
            }),
            ("AccountAudit", new[] {
                MakeFinding("Pass the hash detected", "Golden ticket forged for domain admin")
            })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.ThreatScore >= 40);
        Assert.True(report.ThreatLevel is "Moderate" or "High" or "Critical");
    }

    // ── Stats Computation ────────────────────────────────────────

    [Fact]
    public void Detect_MultipleFindings_ComputesStats()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] { MakeFinding("Disable defender via automated script") }),
            ("ProcessAudit", new[] { MakeFinding("Rundll32 proxy execution detected", "rundll32.exe loading payload") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Stats.TotalTechniquesUsed >= 2);
        Assert.True(report.Stats.UniqueDefensesTargeted >= 2);
        Assert.True(report.Stats.AverageConfidence > 0);
    }

    // ── Recommendations ──────────────────────────────────────────

    [Fact]
    public void Detect_NoFindings_RecommendsContinueMonitoring()
    {
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(new SecurityReport(), historyDays: 30);

        Assert.Contains(report.Recommendations, r => r.Contains("Continue monitoring"));
    }

    [Fact]
    public void Detect_ImpairDefenses_RecommendsTamperProtection()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] { MakeFinding("Disable defender real-time scan", "Tamper protection bypassed") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Contains(report.Recommendations, r => r.Contains("tamper protection"));
    }

    [Fact]
    public void Detect_LogClearing_RecommendsImmutableLogs()
    {
        var secReport = MakeReport(
            ("EventLogAudit", new[] { MakeFinding("Event log cleared by adversary", "wevtutil cl Security executed") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Contains(report.Recommendations, r => r.Contains("immutable log"));
    }

    [Fact]
    public void Detect_ProxyExecution_RecommendsAppControl()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("Certutil download detected", "certutil download from external URL") })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Contains(report.Recommendations, r => r.Contains("application control") || r.Contains("AppLocker"));
    }

    // ── Deduplication ────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateFindings_Deduplicates()
    {
        var secReport = MakeReport(
            ("DefenderAudit", new[] {
                MakeFinding("Disable defender via registry", "Tamper protection disabled"),
                MakeFinding("Disable defender via registry", "Tamper protection disabled")
            })
        );
        var detector = new DefenseEvasionDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EvasionsDetected);
    }
}
