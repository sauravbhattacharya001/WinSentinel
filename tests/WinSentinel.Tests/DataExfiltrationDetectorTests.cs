using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class DataExfiltrationDetectorTests
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
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Events);
    }

    [Fact]
    public void NoExfilKeywords_ReturnsNoDetections()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Normal HTTP traffic detected", "Regular web browsing activity")
        }));
        var result = detector.Detect(report);

        Assert.Equal(0, result.ExfiltrationsDetected);
    }

    [Fact]
    public void CloudStorageKeyword_DetectsExfiltration()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Dropbox upload detected", "Large file upload to dropbox cloud storage")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1567.002");
    }

    [Fact]
    public void USBKeyword_DetectsExfiltration()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Endpoint", new[]
        {
            MakeFinding("USB mass storage device connected", "Removable media write access granted")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1052.001");
    }

    [Fact]
    public void DNSTunneling_DetectsAlternativeProtocol()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("DNS tunnel detected", "Suspicious DNS TXT record queries indicating dns exfil")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1048.003");
    }

    [Fact]
    public void GitPush_DetectsCodeRepoExfil()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Process", new[]
        {
            MakeFinding("Unauthorized git push to external repository", "git push to github upload of sensitive data")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1567.001");
    }

    [Fact]
    public void WebhookExfil_Detected()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Discord webhook data transfer", "Data sent via discord webhook endpoint")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1567.004");
    }

    [Fact]
    public void C2Channel_DetectsExfiltration()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("C2 channel data exfiltration", "Beacon upload of staged data over command and control")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1041");
    }

    [Fact]
    public void ScheduledTransfer_Detected()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Tasks", new[]
        {
            MakeFinding("Scheduled transfer task found", "Periodic exfil via scheduled task upload")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1029");
    }

    [Fact]
    public void ChunkedTransfer_Detected()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Chunked data transfer to external host", "Fragmented transfer with size limit evasion")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1030");
    }

    [Fact]
    public void EncryptedNonC2_Detected()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("PGP transfer to external server", "Asymmetric encrypt data sent via pgp transfer")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        Assert.Contains(result.Events, e => e.TechniqueId == "T1048.002");
    }

    [Fact]
    public void MultipleTechniques_AllDetected()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(
            ("Network", new[] { MakeFinding("Dropbox upload", "cloud storage upload detected") }),
            ("Endpoint", new[] { MakeFinding("USB removable media write", "thumb drive connected") }),
            ("Process", new[] { MakeFinding("Git push to github", "code repository push detected") })
        );
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected >= 3);
        var techniques = result.Events.Select(e => e.TechniqueId).Distinct().ToList();
        Assert.Contains("T1567.002", techniques);
        Assert.Contains("T1052.001", techniques);
        Assert.Contains("T1567.001", techniques);
    }

    [Fact]
    public void HighVolumeIndicators_BoostConfidence()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Large bulk archive upload to cloud storage", "Massive compressed zip upload to google drive")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        var ev = result.Events.First(e => e.TechniqueId == "T1567.002");
        Assert.Contains("High data volume indicators", ev.RiskFactors);
    }

    [Fact]
    public void EncryptionIndicators_BoostConfidence()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Encrypted FTP upload", "AES encrypted ftp upload to external server")
        }));
        var result = detector.Detect(report);

        Assert.True(result.ExfiltrationsDetected > 0);
        var ev = result.Events.First();
        Assert.Contains("Encrypted channel", ev.RiskFactors);
    }

    [Fact]
    public void ThreatScoreCalculation_HighSeverity()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(
            ("Network", new[] { MakeFinding("Dropbox upload bulk", "large cloud storage upload detected") }),
            ("Network", new[] { MakeFinding("DNS tunnel exfil", "dns exfil dns tunnel detected") }),
            ("Endpoint", new[] { MakeFinding("USB removable media mass storage device", "thumb drive flash drive") }),
            ("Network", new[] { MakeFinding("C2 channel beacon upload staged data", "command and control exfil") })
        );
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore > 0);
    }

    [Fact]
    public void ThreatLevel_Critical_WhenScoreHigh()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        // Create enough high-severity findings to push score over 80
        var findings = Enumerable.Range(0, 10).Select(i =>
            MakeFinding($"USB mass storage device exfil {i}", "removable media thumb drive flash drive large bulk")
        ).ToArray();
        var report = MakeReport(("Endpoint", findings));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 80);
        Assert.Equal("Critical", result.ThreatLevel);
    }

    [Fact]
    public void Channels_AggregatedCorrectly()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Dropbox upload 1", "cloud storage upload"),
            MakeFinding("Google Drive upload 2", "google drive cloud storage upload")
        }));
        var result = detector.Detect(report);

        Assert.True(result.Channels.Count > 0);
        var cloudChannel = result.Channels.FirstOrDefault(c => c.TechniqueId == "T1567.002");
        Assert.NotNull(cloudChannel);
        Assert.True(cloudChannel.EventCount >= 2);
    }

    [Fact]
    public void Recommendations_GeneratedForDetectedTechniques()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Dropbox upload", "cloud storage upload detected")
        }));
        var result = detector.Detect(report);

        Assert.True(result.Recommendations.Count > 0);
        Assert.Contains(result.Recommendations, r => r.MitreTechnique == "T1567.002");
    }

    [Fact]
    public void Graph_PopulatedWithNodesAndEdges()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Dropbox upload", "cloud storage upload to dest:external.server.com")
        }));
        var result = detector.Detect(report);

        Assert.True(result.Graph.Nodes.Count > 0);
        Assert.True(result.Graph.Edges.Count > 0);
        Assert.Contains(result.Graph.Nodes, n => n.Type == "process");
        Assert.Contains(result.Graph.Nodes, n => n.Type == "channel");
    }

    [Fact]
    public void Stats_ComputedCorrectly()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(
            ("Network", new[] { MakeFinding("DNS tunnel exfil", "dns tunnel dns exfil covert channel") }),
            ("Endpoint", new[] { MakeFinding("USB removable media", "flash drive mass storage device") })
        );
        var result = detector.Detect(report);

        Assert.True(result.Stats.TotalChannelsDetected >= 2);
    }

    [Fact]
    public void UnusualProtocol_FlaggedInStats()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("ICMP tunnel exfiltration", "icmp tunnel covert channel raw socket data transfer")
        }));
        var result = detector.Detect(report);

        Assert.True(result.Stats.UnusualProtocolCount > 0);
    }

    [Fact]
    public void VolumeEstimation_LargeFile()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Large archive upload to cloud storage", "massive zip compressed gigabyte upload to google drive")
        }));
        var result = detector.Detect(report);

        var ev = result.Events.FirstOrDefault(e => e.DataVolume > 0);
        Assert.NotNull(ev);
        Assert.True(ev.DataVolume >= 1_048_576); // At least 1MB
    }

    [Fact]
    public void DestinationExtraction_WorksWithPattern()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("Cloud storage upload", "dropbox upload to dest:evil.server.com exfil data")
        }));
        var result = detector.Detect(report);

        var ev = result.Events.FirstOrDefault(e => e.DestinationAddress != "Unknown");
        Assert.NotNull(ev);
        Assert.Contains("evil.server.com", ev.DestinationAddress);
    }

    [Fact]
    public void MultipleKeywordMatches_BoostConfidence()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("DNS tunnel with ICMP tunnel and raw socket", "dns tunnel icmp tunnel raw socket dns exfil dns txt record")
        }));
        var result = detector.Detect(report);

        var ev = result.Events.First(e => e.TechniqueId == "T1048.003");
        Assert.Contains("Multiple indicators", ev.RiskFactors);
    }

    [Fact]
    public void DefaultRecommendation_WhenNoExfil()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("General", new[]
        {
            MakeFinding("All systems normal", "No issues found")
        }));
        var result = detector.Detect(report);

        Assert.True(result.Recommendations.Count > 0);
        Assert.Contains(result.Recommendations, r => r.Category == "General");
    }

    [Fact]
    public void EventsProcessed_IncludesAllFindings()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(
            ("A", new[] { MakeFinding("Finding 1"), MakeFinding("Finding 2") }),
            ("B", new[] { MakeFinding("Finding 3") })
        );
        var result = detector.Detect(report);

        Assert.Equal(3, result.EventsProcessed);
    }

    [Fact]
    public void SeverityCounts_MatchEvents()
    {
        var detector = new DataExfiltrationDetector(MakeHistory());
        var report = MakeReport(("Network", new[]
        {
            MakeFinding("USB removable media mass storage device", "thumb drive flash drive large bulk"),
            MakeFinding("Dropbox upload", "cloud storage upload")
        }));
        var result = detector.Detect(report);

        var total = result.HighSeverityCount + result.MediumSeverityCount + result.LowSeverityCount;
        Assert.Equal(result.ExfiltrationsDetected, total);
    }
}
