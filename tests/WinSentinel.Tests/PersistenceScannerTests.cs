using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class PersistenceMechScannerTests
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
    public void Scan_EmptyReport_ReturnsCleanReport()
    {
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(new SecurityReport(), historyDays: 30);

        Assert.Equal(0, report.MechanismsDetected);
        Assert.Equal(0, report.ThreatScore);
        Assert.Equal("Minimal", report.ThreatLevel);
        Assert.Empty(report.Entries);
        Assert.Empty(report.Chains);
        Assert.NotNull(report.Recommendations);
    }

    [Fact]
    public void Scan_NoPersistenceFindings_ReturnsZeroDetections()
    {
        var secReport = MakeReport(
            ("ProcessAudit", new[] { MakeFinding("High CPU usage by chrome.exe") }),
            ("NetworkAudit", new[] { MakeFinding("DNS query to google.com") })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.Equal(0, report.MechanismsDetected);
        Assert.Equal(0, report.ThreatScore);
    }

    // ── Technique Detection Tests ────────────────────────────────

    [Fact]
    public void Scan_DetectsRegistryRunKeys()
    {
        var secReport = MakeReport(
            ("RegistryAudit", new[] { MakeFinding("Suspicious entry in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "malware.exe added to registry run key", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1547.001" && e.Technique.Contains("Registry"));
    }

    [Fact]
    public void Scan_DetectsScheduledTasks()
    {
        var secReport = MakeReport(
            ("TaskAudit", new[] { MakeFinding("Scheduled task created with schtasks /create /tn backdoor", "suspicious scheduled task", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1053.005");
    }

    [Fact]
    public void Scan_DetectsWindowsServices()
    {
        var secReport = MakeReport(
            ("ServiceAudit", new[] { MakeFinding("sc create evilsvc binpath= C:\\mal\\svc.exe", "service creation with LocalSystem", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1543.003");
    }

    [Fact]
    public void Scan_DetectsWMISubscriptions()
    {
        var secReport = MakeReport(
            ("WMIAudit", new[] { MakeFinding("WMI event subscription detected", "CommandLineEventConsumer bound to __EventFilter", Severity.Critical) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1546.003");
    }

    [Fact]
    public void Scan_DetectsStartupFolder()
    {
        var secReport = MakeReport(
            ("FileAudit", new[] { MakeFinding("New file in startup folder", "shell:startup contains unknown .lnk startup shortcut", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.Technique.Contains("Startup Folder"));
    }

    [Fact]
    public void Scan_DetectsDllHijacking()
    {
        var secReport = MakeReport(
            ("DLLAudit", new[] { MakeFinding("Phantom DLL detected in application directory", "dll hijack via search order", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1574.001");
    }

    [Fact]
    public void Scan_DetectsBootLogonScripts()
    {
        var secReport = MakeReport(
            ("ScriptAudit", new[] { MakeFinding("UserInitMprLogon script modified", "logon script pointing to suspicious executable", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1037");
    }

    [Fact]
    public void Scan_DetectsIFEO()
    {
        var secReport = MakeReport(
            ("RegistryAudit", new[] { MakeFinding("Image File Execution Options debugger key set", "IFEO hijacking detected for notepad.exe", Severity.Critical) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1546.012");
    }

    [Fact]
    public void Scan_DetectsAppInitDlls()
    {
        var secReport = MakeReport(
            ("RegistryAudit", new[] { MakeFinding("AppInit_DLLs registry value non-empty", "appinit loaded suspicious dll", Severity.Critical) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1546.010");
    }

    [Fact]
    public void Scan_DetectsBrowserExtensions()
    {
        var secReport = MakeReport(
            ("BrowserAudit", new[] { MakeFinding("Unauthorized chrome extension installed", "browser extension policy forced install", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.MechanismsDetected > 0);
        Assert.Contains(report.Entries, e => e.MitreTechnique == "T1176");
    }

    // ── Scoring & Classification Tests ───────────────────────────

    [Fact]
    public void Scan_MultipleTechniques_HigherThreatScore()
    {
        var secReport = MakeReport(
            ("Audit", new[]
            {
                MakeFinding("Registry run key persistence", "currentversion\\run modified", Severity.Warning),
                MakeFinding("WMI event subscription active", "CommandLineEventConsumer triggered", Severity.Critical),
                MakeFinding("Scheduled task persistence", "schtasks /create malicious task", Severity.Warning),
                MakeFinding("AppInit_DLLs loaded", "appinit dll injection", Severity.Critical)
            })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.ThreatScore >= 40);
        Assert.True(report.Stats.UniqueTechniquesUsed >= 3);
    }

    [Fact]
    public void Scan_CriticalFindings_HighThreatLevel()
    {
        var secReport = MakeReport(
            ("Audit", new[]
            {
                MakeFinding("WMI event subscription detected", "CommandLineEventConsumer active", Severity.Critical),
                MakeFinding("IFEO debugger key set", "image file execution options hijack active", Severity.Critical),
                MakeFinding("AppInit_DLLs injected active", "appinit loaded running malware", Severity.Critical)
            })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.ThreatScore >= 60);
        Assert.True(report.ThreatLevel is "High" or "Critical");
    }

    // ── Activity Detection Tests ─────────────────────────────────

    [Fact]
    public void Scan_ActiveIndicators_MarkedActive()
    {
        var secReport = MakeReport(
            ("Audit", new[] { MakeFinding("Active scheduled task running", "schtasks actively triggered execution", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.Contains(report.Entries, e => e.IsActive);
    }

    [Fact]
    public void Scan_DormantIndicators_MarkedDormant()
    {
        var secReport = MakeReport(
            ("Audit", new[] { MakeFinding("Stale registry run key entry", "disabled orphan currentversion\\run entry", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.Contains(report.Entries, e => e.IsDormant);
    }

    // ── Chain Detection Tests ────────────────────────────────────

    [Fact]
    public void Scan_MultipleTechniques_BuildsChains()
    {
        var secReport = MakeReport(
            ("Audit", new[]
            {
                MakeFinding("Registry run key created", "currentversion\\run entry added", Severity.Warning),
                MakeFinding("Scheduled task created", "schtasks persistence mechanism", Severity.Warning),
                MakeFinding("WMI subscription added", "wmi event subscription CommandLineEventConsumer", Severity.Critical)
            })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.Chains.Count > 0);
        Assert.True(report.Chains[0].Depth >= 2);
    }

    // ── Recommendations Tests ────────────────────────────────────

    [Fact]
    public void Scan_NoFindings_GivesCleanRecommendation()
    {
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(new SecurityReport(), historyDays: 30);

        Assert.Contains(report.Recommendations, r => r.Contains("No persistence mechanisms detected"));
    }

    [Fact]
    public void Scan_CriticalFindings_GivesUrgentRecommendation()
    {
        var secReport = MakeReport(
            ("Audit", new[] { MakeFinding("WMI event subscription active", "CommandLineEventConsumer executed", Severity.Critical) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.Contains(report.Recommendations, r => r.Contains("URGENT"));
    }

    [Fact]
    public void Scan_WMIDetection_RecommendationIncludesWMIAudit()
    {
        var secReport = MakeReport(
            ("Audit", new[] { MakeFinding("WMI event subscription created", "wmi event persistence __eventfilter", Severity.Warning) })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.Contains(report.Recommendations, r => r.Contains("WMI"));
    }

    // ── Stats Tests ──────────────────────────────────────────────

    [Fact]
    public void Scan_MultipleEntries_ComputesStats()
    {
        var secReport = MakeReport(
            ("Audit", new[]
            {
                MakeFinding("Registry run key", "currentversion\\run malware", Severity.Warning),
                MakeFinding("Scheduled task", "schtasks persistence", Severity.Warning)
            })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        Assert.True(report.Stats.UniqueTechniquesUsed >= 2);
        Assert.True(report.Stats.AverageConfidence > 0);
        Assert.True(report.Stats.TechniqueDiversity > 0);
    }

    [Fact]
    public void Scan_SeverityCounts_MatchEntries()
    {
        var secReport = MakeReport(
            ("Audit", new[]
            {
                MakeFinding("WMI subscription active", "CommandLineEventConsumer active", Severity.Critical),
                MakeFinding("Startup folder entry", "shell:startup lnk added", Severity.Warning)
            })
        );
        var scanner = new PersistenceMechScanner(MakeHistory());
        var report = scanner.Scan(secReport, historyDays: 30);

        var total = report.CriticalMechanisms + report.HighMechanisms + report.MediumMechanisms + report.LowMechanisms;
        Assert.Equal(report.MechanismsDetected, total);
    }
}
