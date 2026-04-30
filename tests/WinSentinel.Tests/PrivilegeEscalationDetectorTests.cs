using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class PrivilegeEscalationDetectorTests
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
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(new SecurityReport(), historyDays: 30);

        Assert.Equal(0, report.EscalationsDetected);
        Assert.Equal(0, report.ThreatScore);
        Assert.Equal("Minimal", report.ThreatLevel);
        Assert.Empty(report.Escalations);
        Assert.Empty(report.Chains);
        Assert.NotNull(report.Recommendations);
    }

    [Fact]
    public void Detect_NoEscalationFindings_ReturnsZeroDetections()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("High CPU usage by chrome.exe") }),
            ("NetworkAudit", new[] { MakeFinding("DNS query to google.com") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(0, report.EscalationsDetected);
        Assert.Equal("Minimal", report.ThreatLevel);
    }

    // ── Technique Detection Tests ────────────────────────────────

    [Fact]
    public void Detect_TokenManipulation_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("SeDebugPrivilege enabled for suspicious process", "Token manipulation detected via DuplicateToken") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1134", report.Escalations[0].MitreTechnique);
        Assert.Equal("Access Token Manipulation", report.Escalations[0].Technique);
    }

    [Fact]
    public void Detect_UACBypass_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("fodhelper.exe UAC bypass attempt", "Process used fodhelper to bypass UAC elevation prompt") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1548.002", report.Escalations[0].MitreTechnique);
        Assert.Equal("UAC Bypass", report.Escalations[0].Technique);
    }

    [Fact]
    public void Detect_ProcessInjection_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("CreateRemoteThread call detected", "Possible process injection via reflective load into lsass.exe") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1055", report.Escalations[0].MitreTechnique);
    }

    [Fact]
    public void Detect_DLLHijacking_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("ServiceAudit", new[] { MakeFinding("DLL hijack risk in service path", "Phantom DLL vulnerability - writable directory in search order") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1574.001", report.Escalations[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ServiceCreation_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("ServiceAudit", new[] { MakeFinding("New service created with sc create", "Service running as LocalSystem with unusual binary path") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1543.003", report.Escalations[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ScheduledTaskSYSTEM_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("ScheduledTaskAudit", new[] { MakeFinding("schtasks /create used with SYSTEM account", "New scheduled task running as SYSTEM created by standard user") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1053.005", report.Escalations[0].MitreTechnique);
    }

    [Fact]
    public void Detect_COMHijacking_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("RegistryAudit", new[] { MakeFinding("CLSID registry modification detected", "COM hijack via InprocServer modification for persistence") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1546.015", report.Escalations[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ExploitForPrivEsc_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("UpdateAudit", new[] { MakeFinding("CVE-2023-28252 elevation of privilege", "Missing patch for CLFS driver exploit vulnerability") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1068", report.Escalations[0].MitreTechnique);
    }

    [Fact]
    public void Detect_BootAutostart_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("StartupAudit", new[] { MakeFinding("Suspicious Run key entry", "Unknown binary added to CurrentVersion\\Run registry key") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1547.001", report.Escalations[0].MitreTechnique);
    }

    [Fact]
    public void Detect_LocalAdminAbuse_DetectsCorrectly()
    {
        var secReport = MakeReport(
            ("AccountAudit", new[] { MakeFinding("User added to local admin group", "net localgroup administrators /add used by non-admin process") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.Equal("T1078.003", report.Escalations[0].MitreTechnique);
    }

    // ── Multi-technique & Chain Tests ────────────────────────────

    [Fact]
    public void Detect_MultipleTechniques_DetectsAll()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("fodhelper UAC bypass detected", "User elevated without consent prompt"),
                MakeFinding("CreateRemoteThread injection into svchost", "Process injection detected")
            }),
            ("ServiceAudit", new[] {
                MakeFinding("sc create backdoor-svc", "New service running as LocalSystem")
            })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(3, report.EscalationsDetected);
        Assert.Contains(report.Escalations, e => e.MitreTechnique == "T1548.002");
        Assert.Contains(report.Escalations, e => e.MitreTechnique == "T1055");
        Assert.Contains(report.Escalations, e => e.MitreTechnique == "T1543.003");
    }

    [Fact]
    public void Detect_ChainDetection_WhenMultipleEscalationsWithSameAccount()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("UAC bypass via fodhelper", "user: attacker bypassed UAC"),
                MakeFinding("Token manipulation after UAC bypass", "user: attacker used DuplicateToken for SYSTEM")
            })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Chains.Count > 0);
        Assert.True(report.Chains[0].HopCount >= 2);
    }

    // ── Severity & Scoring Tests ─────────────────────────────────

    [Fact]
    public void Detect_AutomatedAttack_IncreasesConfidenceAndSeverity()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("Metasploit getsystem token manipulation", "Automated script elevated via token impersonation") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
        Assert.True(report.Escalations[0].IsAutomated);
        Assert.Equal(PrivEscSeverity.Critical, report.Escalations[0].Severity);
        Assert.Contains(report.Escalations[0].Indicators, i => i.Contains("attack framework"));
    }

    [Fact]
    public void Detect_HighSeverityTargetingSYSTEM()
    {
        var secReport = MakeReport(
            ("ServiceAudit", new[] { MakeFinding("sc create malicious-svc binpath=c:\\evil.exe", "Service configured to run as LocalSystem") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Escalations[0].Severity >= PrivEscSeverity.High);
    }

    [Fact]
    public void Detect_ThreatScore_IncreasesWithSeverity()
    {
        var lowReport = MakeReport(
            ("StartupAudit", new[] { MakeFinding("Suspicious startup folder entry") })
        );
        var highReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("Metasploit getsystem token manipulation", "Automated script"),
                MakeFinding("CreateRemoteThread injection into lsass", "Process injection to SYSTEM"),
                MakeFinding("sc create evil-svc", "Service as LocalSystem")
            })
        );

        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var low = detector.Detect(lowReport, historyDays: 30);
        var high = detector.Detect(highReport, historyDays: 30);

        Assert.True(high.ThreatScore > low.ThreatScore);
    }

    [Fact]
    public void Detect_ThreatLevel_Classification()
    {
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(new SecurityReport(), historyDays: 30);
        Assert.Equal("Minimal", report.ThreatLevel);
    }

    // ── Stats Tests ──────────────────────────────────────────────

    [Fact]
    public void Detect_Stats_ComputedCorrectly()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("UAC bypass via eventvwr"),
                MakeFinding("DLL hijack in application path", "Phantom DLL loading")
            })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(2, report.Stats.TotalTechniquesUsed);
        Assert.True(report.Stats.AverageConfidence > 0);
    }

    [Fact]
    public void Detect_Recommendations_GeneratedForHighRisk()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("UAC bypass detected"),
                MakeFinding("Process injection via CreateRemoteThread"),
                MakeFinding("DLL search order hijack found", "phantom dll in writable path")
            })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.True(report.Recommendations.Count >= 3);
        Assert.Contains(report.Recommendations, r => r.Contains("UAC"));
        Assert.Contains(report.Recommendations, r => r.Contains("ASR") || r.Contains("injection"));
        Assert.Contains(report.Recommendations, r => r.Contains("DLL") || r.Contains("SafeDll"));
    }

    [Fact]
    public void Detect_NoEscalations_GivesMonitoringRecommendation()
    {
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(new SecurityReport(), historyDays: 30);

        Assert.Single(report.Recommendations);
        Assert.Contains("monitoring", report.Recommendations[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Detect_Deduplication_RemovesDuplicateFindings()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] {
                MakeFinding("UAC bypass via fodhelper"),
                MakeFinding("UAC bypass via fodhelper")  // duplicate
            })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(1, report.EscalationsDetected);
    }

    [Fact]
    public void Detect_DaysAnalyzed_SetCorrectly()
    {
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(new SecurityReport(), historyDays: 60);
        Assert.Equal(60, report.DaysAnalyzed);
    }

    [Fact]
    public void Detect_EventsProcessed_CountsAllFindings()
    {
        var secReport = MakeReport(
            ("A", new[] { MakeFinding("finding1"), MakeFinding("finding2") }),
            ("B", new[] { MakeFinding("finding3") })
        );
        var detector = new PrivilegeEscalationDetector(MakeHistory());
        var report = detector.Detect(secReport, historyDays: 30);

        Assert.Equal(3, report.EventsProcessed);
    }
}
