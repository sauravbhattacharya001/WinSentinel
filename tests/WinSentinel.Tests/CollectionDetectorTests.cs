using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class CollectionDetectorTests
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
        Category = "Security"
    };

    [Fact]
    public void EmptyReport_ReturnsZeroThreatScore()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Events);
    }

    [Fact]
    public void NoCollectionKeywords_ReturnsNoDetections()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Normal HTTP traffic detected", "Regular web browsing activity")
        }));
        var result = detector.Detect(report);

        Assert.Equal(0, result.CollectionActivitiesDetected);
    }

    [Fact]
    public void ScreenCapture_DetectsT1113()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Screenshot utility detected", "Process taking screen capture via BitBlt")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1113");
    }

    [Fact]
    public void ClipboardData_DetectsT1115()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Clipboard monitor installed", "Process hooking clipboard capture events")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1115");
    }

    [Fact]
    public void Keylogging_DetectsT1056_001()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger detected", "SetWindowsHookEx keyboard hook installed by suspicious process")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1056.001");
    }

    [Fact]
    public void GUIInputCapture_DetectsT1056_002()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Fake credential dialog spawned", "GUI capture of user credentials via phishing dialog")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1056.002");
    }

    [Fact]
    public void WebPortalCapture_DetectsT1056_003()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Browser form capture detected", "Web portal credential form grab via injected script")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1056.003");
    }

    [Fact]
    public void CredentialAPIHooking_DetectsT1056_004()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("LSASS hook detected", "Credential API hooking via SSPI hook on authentication")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1056.004");
    }

    [Fact]
    public void LocalDataStaging_DetectsT1074_001()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("FileSystem", new[]
        {
            MakeFinding("Suspicious data staging folder", "Files being collected in local staging directory")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1074.001");
    }

    [Fact]
    public void RemoteDataStaging_DetectsT1074_002()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Network share staging activity", "SMB staging of collected data to shared drive")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1074.002");
    }

    [Fact]
    public void LocalEmailCollection_DetectsT1114_001()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("PST file access detected", "Local email archive mailbox export from Outlook data")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1114.001");
    }

    [Fact]
    public void RemoteEmailCollection_DetectsT1114_002()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Exchange harvest attempt", "Remote email collection via OWA scrape with forwarding rule")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1114.002");
    }

    [Fact]
    public void AutomatedCollection_DetectsT1119()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Automated collection script", "Scripted harvest of sensitive files via bulk collect")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1119");
    }

    [Fact]
    public void ArchiveViaUtility_DetectsT1560_001()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("7zip archive creation", "Data compressed with 7zip before exfil attempt")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1560.001");
    }

    [Fact]
    public void KnownTool_Lazagne_BoostsConfidence()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("LaZagne clipboard credential extraction", "lazagne tool detected accessing clipboard data")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        var ev = result.Events.First();
        Assert.Contains(ev.RiskFactors, r => r.Contains("Known tool"));
        Assert.True(ev.Confidence > 0.8);
    }

    [Fact]
    public void KnownTool_Mimikatz_BoostsConfidence()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Mimikatz credential hook", "mimikatz clipboard capture module active")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.RiskFactors.Any(r => r.Contains("mimikatz")));
    }

    [Fact]
    public void KnownTool_PowerSploit_Detected()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("PowerSploit screen capture module", "powersploit Get-TimedScreenshot taking display capture")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.RiskFactors.Any(r => r.Contains("powersploit")));
    }

    [Fact]
    public void SensitiveTarget_Email_BoostsConfidence()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Email credential clipboard capture", "Clipboard data containing email password intercepted")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.RiskFactors.Any(r => r.Contains("Sensitive")));
    }

    [Fact]
    public void SensitiveTarget_Financial_BoostsConfidence()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Financial data keylogging", "Keylogger capturing financial and bank credentials")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.RiskFactors.Any(r => r.Contains("Sensitive")));
    }

    [Fact]
    public void HighVolume_BoostsConfidence()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Bulk data collection detected", "Mass clipboard data harvest from all files")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.RiskFactors.Any(r => r.Contains("High volume")));
    }

    [Fact]
    public void AutomationIndicator_BoostsConfidence()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Scheduled screenshot task", "Automated screen capture via task scheduler at interval")
        }));
        var result = detector.Detect(report);

        Assert.True(result.CollectionActivitiesDetected > 0);
        Assert.Contains(result.Events, e => e.RiskFactors.Any(r => r.Contains("Automation")));
    }

    [Fact]
    public void CampaignDetection_MultipleTechniques_SameProcess()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger via process: malware.exe", "keystroke capture from keyboard hook"),
            MakeFinding("Screenshot via process: malware.exe", "screen capture from display capture"),
            MakeFinding("Clipboard via process: malware.exe", "clipboard monitor data intercepted"),
        }));
        var result = detector.Detect(report);

        Assert.True(result.Campaigns.Count > 0);
        Assert.Contains(result.Campaigns, c => c.TechniquesUsed.Count >= 3);
    }

    [Fact]
    public void CampaignDetection_TwoTechniques_NoCampaign()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger via process: tool.exe", "keystroke capture"),
            MakeFinding("Screenshot via process: tool.exe", "screen capture"),
        }));
        var result = detector.Detect(report);

        // 2 techniques from same process is NOT enough for a campaign (requires 3+)
        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void ThreatLevel_Minimal_WhenNoEvents()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport();
        var result = detector.Detect(report);

        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void ThreatLevel_Increases_WithMoreEvents()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger active", "keystroke capture via keyboard hook"),
            MakeFinding("Screen capture running", "screenshot display capture ongoing"),
            MakeFinding("Clipboard hooked", "clipboard monitor clipboard capture active"),
            MakeFinding("Email archive accessed", "PST file local email collection"),
            MakeFinding("7zip archiving data", "archive collected compress data for exfil"),
        }));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore > 20);
        Assert.NotEqual("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void ThreatScore_ZeroForEmptyReport()
    {
        var detector = new CollectionDetector(MakeHistory());
        var result = detector.Detect(MakeReport());
        Assert.Equal(0, result.ThreatScore);
    }

    [Fact]
    public void ThreatScore_CappedAt100()
    {
        var detector = new CollectionDetector(MakeHistory());
        var findings = Enumerable.Range(0, 50).Select(i =>
            MakeFinding($"Keylogger instance {i} via process: malware.exe",
                $"keystroke capture keyboard hook mimikatz credential password #{i}")).ToArray();
        var report = MakeReport(("Endpoint", findings));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore <= 100);
    }

    [Fact]
    public void Recommendations_Generated_ForKeylogging()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger detected", "keystroke capture via keyboard hook")
        }));
        var result = detector.Detect(report);

        Assert.True(result.Recommendations.Count > 0);
        Assert.Contains(result.Recommendations, r => r.MitreTechnique == "T1056.001");
    }

    [Fact]
    public void Recommendations_Generated_ForClipboard()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Clipboard hook installed", "clipboard capture active")
        }));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.MitreTechnique == "T1115");
    }

    [Fact]
    public void Recommendations_Generated_ForEmail()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("PST export detected", "local email pst file access")
        }));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.MitreTechnique == "T1114");
    }

    [Fact]
    public void Recommendations_Generated_ForArchive()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("WinRAR compression", "winrar archive collected data compressed")
        }));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.MitreTechnique == "T1560.001");
    }

    [Fact]
    public void TechniqueAggregation_GroupsByTechniqueId()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("First screenshot", "screen capture display capture"),
            MakeFinding("Second screenshot", "another screen capture taken"),
        }));
        var result = detector.Detect(report);

        var t1113 = result.Techniques.FirstOrDefault(t => t.TechniqueId == "T1113");
        Assert.NotNull(t1113);
        Assert.True(t1113.EventCount >= 2);
    }

    [Fact]
    public void Stats_UniqueProcesses_CountedCorrectly()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(
            ("ModuleA", new[] { MakeFinding("Keylogger", "keystroke capture keyboard hook") }),
            ("ModuleB", new[] { MakeFinding("Screenshot", "screen capture display capture") })
        );
        var result = detector.Detect(report);

        Assert.True(result.Stats.UniqueProcesses >= 2);
    }

    [Fact]
    public void Stats_TotalTechniquesDetected_IsCorrect()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger", "keystroke keyboard hook"),
            MakeFinding("Screenshot", "screen capture"),
            MakeFinding("Clipboard", "clipboard monitor"),
        }));
        var result = detector.Detect(report);

        Assert.True(result.Stats.TotalTechniquesDetected >= 3);
    }

    [Fact]
    public void SeverityCount_CorrectlyClassified()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger", "keystroke keyboard hook mimikatz credential"),
            MakeFinding("Clipboard", "clipboard monitor"),
        }));
        var result = detector.Detect(report);

        var totalSeverity = result.HighSeverityCount + result.MediumSeverityCount + result.LowSeverityCount;
        Assert.Equal(result.CollectionActivitiesDetected, totalSeverity);
    }

    [Fact]
    public void MultipleKeywordsInSameFinding_SingleDetection()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Screenshot and screen grab", "screen capture with display capture and snipping")
        }));
        var result = detector.Detect(report);

        // Should detect T1113 once (not multiple times for same technique)
        var t1113Events = result.Events.Count(e => e.TechniqueId == "T1113");
        Assert.Equal(1, t1113Events);
    }

    [Fact]
    public void DaysAnalyzed_PropagatedCorrectly()
    {
        var detector = new CollectionDetector(MakeHistory());
        var result = detector.Detect(MakeReport(), 30);
        Assert.Equal(30, result.DaysAnalyzed);
    }

    [Fact]
    public void EventsProcessed_MatchesFindingCount()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("A", new[]
        {
            MakeFinding("F1", "normal stuff"),
            MakeFinding("F2", "more normal")
        }));
        var result = detector.Detect(report);

        Assert.Equal(2, result.EventsProcessed);
    }

    [Fact]
    public void ConfidenceScore_BetweenZeroAndOne()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Major keylogger campaign", "keystroke keyboard hook lazagne mimikatz credential password bulk automated")
        }));
        var result = detector.Detect(report);

        foreach (var ev in result.Events)
        {
            Assert.True(ev.Confidence >= 0 && ev.Confidence <= 1.0);
        }
    }

    [Fact]
    public void TargetData_DefaultsBasedOnTechnique()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Keylogger found", "keystroke keyboard hook active")
        }));
        var result = detector.Detect(report);

        var ev = result.Events.FirstOrDefault(e => e.TechniqueId == "T1056.001");
        Assert.NotNull(ev);
        Assert.False(string.IsNullOrEmpty(ev.TargetData));
    }

    [Fact]
    public void ContextIndicators_ContainMatchedKeywords()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Screenshot tool", "display capture and screen grab utility")
        }));
        var result = detector.Detect(report);

        var ev = result.Events.FirstOrDefault(e => e.TechniqueId == "T1113");
        Assert.NotNull(ev);
        Assert.True(ev.ContextIndicators.Count > 0);
    }

    [Fact]
    public void GeneratedAt_IsRecentTimestamp()
    {
        var detector = new CollectionDetector(MakeHistory());
        var result = detector.Detect(MakeReport());

        Assert.True(result.GeneratedAt > DateTimeOffset.UtcNow.AddMinutes(-5));
    }

    [Fact]
    public void CredentialAPIHooking_HighConfidence()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("SSPI credential hook", "credential api sspi hook intercepting auth")
        }));
        var result = detector.Detect(report);

        var ev = result.Events.FirstOrDefault(e => e.TechniqueId == "T1056.004");
        Assert.NotNull(ev);
        Assert.True(ev.Confidence >= 0.85);
    }

    [Fact]
    public void CombinedRiskFactors_IncreasesSeverity()
    {
        var detector = new CollectionDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("Lazagne keylogger on sensitive data",
                "lazagne keystroke keyboard hook credential financial password")
        }));
        var result = detector.Detect(report);

        Assert.Contains(result.Events, e =>
            e.Severity == "High" || e.Severity == "Critical");
    }
}
