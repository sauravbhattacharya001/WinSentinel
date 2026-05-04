using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class CommandControlDetectorTests
{
    private static AuditHistoryService CreateHistory() => new();

    private static SecurityReport MakeReport(params (string title, string desc)[] findings)
    {
        var report = new SecurityReport();
        var result = new AuditResult { ModuleName = "TestModule", Category = "TestModule" };
        foreach (var (title, desc) in findings)
            result.Findings.Add(new Finding { Title = title, Description = desc });
        report.Results.Add(result);
        return report;
    }

    // ── Basic Behavior ──────────────────────────────────────────────

    [Fact]
    public void Detect_EmptyReport_ReturnsCleanReport()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.C2DetectionsCount);
        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Detections);
        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void Detect_NoC2Findings_ReturnsZeroDetections()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Firewall enabled", "Windows firewall is active"));
        var result = detector.Detect(report);

        Assert.Equal(0, result.C2DetectionsCount);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void Detect_EmptyReport_HasDefaultStats()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());

        Assert.Equal(0, result.Stats.TotalTechniquesUsed);
        Assert.Equal(0, result.Stats.UniqueProtocols);
        Assert.Equal("None", result.Stats.MostCommonTechnique);
        Assert.Equal(0, result.Stats.FrameworksDetected);
    }

    [Fact]
    public void Detect_EmptyReport_GeneratesMaintenanceRecommendation()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());

        Assert.Single(result.Recommendations);
        Assert.Contains("No C2 activity detected", result.Recommendations[0]);
    }

    // ── Technique Detection (12 MITRE techniques) ───────────────────

    [Fact]
    public void Detect_WebProtocols_T1071001()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("HTTP C2 beacon", "Suspicious http beacon detected on port 443"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1071.001", result.Detections[0].MitreTechnique);
        Assert.Equal("Web Protocols", result.Detections[0].Technique);
        Assert.Equal("WebProtocol", result.Detections[0].ChannelType);
    }

    [Fact]
    public void Detect_FileTransferProtocols_T1071002()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("FTP C2 channel", "FTP c2 communication to external server"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1071.002", result.Detections[0].MitreTechnique);
        Assert.Equal("FileTransfer", result.Detections[0].ChannelType);
    }

    [Fact]
    public void Detect_MailProtocols_T1071003()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("SMTP C2", "SMTP c2 channel sending commands via email"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1071.003", result.Detections[0].MitreTechnique);
        Assert.Equal("MailProtocol", result.Detections[0].ChannelType);
    }

    [Fact]
    public void Detect_DNS_T1071004()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("DNS tunnel", "DNS tunnel detected with encoded data in TXT records"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1071.004", result.Detections[0].MitreTechnique);
        Assert.Equal("DNS", result.Detections[0].ChannelType);
    }

    [Fact]
    public void Detect_StandardEncoding_T1132001()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Base64 C2 commands", "Base64 c2 encoded payload in outbound traffic"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1132.001", result.Detections[0].MitreTechnique);
        Assert.Equal("Encoding", result.Detections[0].ChannelType);
    }

    [Fact]
    public void Detect_NonStandardEncoding_T1132002()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Custom encoding", "Custom encoding scheme in C2 traffic"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1132.002", result.Detections[0].MitreTechnique);
    }

    [Fact]
    public void Detect_SymmetricCryptography_T1573001()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("AES C2", "AES c2 encrypted command channel to external IP"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1573.001", result.Detections[0].MitreTechnique);
        Assert.True(result.Detections[0].IsEncrypted);
    }

    [Fact]
    public void Detect_AsymmetricCryptography_T1573002()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("TLS C2 channel", "tls c2 with certificate pinning c2 and ecdh c2 negotiation"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1573.002", result.Detections[0].MitreTechnique);
        Assert.True(result.Detections[0].IsEncrypted);
    }

    [Fact]
    public void Detect_FallbackChannels_T1008()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Fallback C2", "Fallback c2 channel activated after primary blocked"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1008", result.Detections[0].MitreTechnique);
        Assert.Equal(C2Severity.High, result.Detections[0].Severity);
    }

    [Fact]
    public void Detect_MultiStageChannels_T1104()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Multi-stage C2", "Multi-stage c2 payload staging detected"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1104", result.Detections[0].MitreTechnique);
        Assert.Equal(C2Severity.High, result.Detections[0].Severity);
    }

    [Fact]
    public void Detect_IngressToolTransfer_T1105()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Tool transfer", "Certutil download of remote tool transfer payload"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1105", result.Detections[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ProtocolTunneling_T1572()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("SSH tunnel", "SSH tunnel established for reverse tunnel to external C2"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("T1572", result.Detections[0].MitreTechnique);
        Assert.Equal(C2Severity.High, result.Detections[0].Severity);
    }

    // ── Framework & Confidence Boosting ─────────────────────────────

    [Fact]
    public void Detect_KnownFramework_BoostsConfidence()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Cobalt Strike beacon", "HTTP C2 beacon from cobalt strike implant"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.C2DetectionsCount);
        Assert.Equal("cobalt strike", result.Detections[0].KnownFramework);
        Assert.True(result.Detections[0].Confidence > 0.80);
    }

    [Fact]
    public void Detect_KnownFramework_AddedToIndicators()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Sliver implant", "HTTP C2 beacon from sliver framework"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("sliver"));
    }

    [Fact]
    public void Detect_EncryptionIndicator_BoostsConfidence()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Encrypted HTTP C2", "HTTP C2 beacon with TLS encrypted channel"));
        var result = detector.Detect(report);

        Assert.True(result.Detections[0].IsEncrypted);
        Assert.True(result.Detections[0].Confidence > 0.80);
    }

    [Fact]
    public void Detect_AutomationIndicator_BoostsConfidence()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Periodic HTTP C2", "HTTP C2 beacon with periodic callback interval"));
        var result = detector.Detect(report);

        Assert.True(result.Detections[0].Confidence > 0.80);
        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Automated"));
    }

    // ── Severity Classification ─────────────────────────────────────

    [Fact]
    public void Severity_KnownFrameworkEncrypted_Critical()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Cobalt Strike AES", "AES c2 encrypted channel from cobalt strike implant"));
        var result = detector.Detect(report);

        Assert.Equal(C2Severity.Critical, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_DNSTunneling_High()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("DNS exfil", "DNS c2 channel via subdomain encoding"));
        var result = detector.Detect(report);

        Assert.Equal(C2Severity.High, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_WebProtocol_Medium()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Web C2", "Web c2 outbound connection to suspicious domain"));
        var result = detector.Detect(report);

        Assert.Equal(C2Severity.Medium, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_EncodingOnly_Low()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Base64 C2", "Base64 c2 encoded commands in traffic"));
        var result = detector.Detect(report);

        Assert.Equal(C2Severity.Low, result.Detections[0].Severity);
    }

    // ── Campaign Detection ──────────────────────────────────────────

    [Fact]
    public void Detect_MultipleTechniques_BuildsCampaign()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("HTTP C2 beacon", "HTTP C2 beacon to external server"),
            ("DNS tunnel", "DNS tunnel for covert C2 channel"),
            ("SSH tunnel", "SSH tunnel established as protocol tunnel backup"));
        var result = detector.Detect(report);

        Assert.True(result.C2DetectionsCount >= 3);
        Assert.NotEmpty(result.Campaigns);
    }

    [Fact]
    public void Detect_SingleTechnique_NoCampaign()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("HTTP C2 beacon", "HTTP C2 beacon detected"));
        var result = detector.Detect(report);

        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void Campaign_HasVerdict()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("HTTP C2 beacon", "HTTP C2 beacon to C2 server"),
            ("DNS tunnel", "DNS tunnel for covert C2 communication"));
        var result = detector.Detect(report);

        if (result.Campaigns.Count > 0)
        {
            Assert.NotEmpty(result.Campaigns[0].Verdict);
            Assert.True(result.Campaigns[0].CompoundConfidence > 0);
        }
    }

    // ── Threat Scoring ──────────────────────────────────────────────

    [Fact]
    public void ThreatScore_NoDetections_Zero()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());
        Assert.Equal(0, result.ThreatScore);
    }

    [Fact]
    public void ThreatScore_SingleLow_Small()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Base64 C2", "Base64 c2 encoded payload"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore > 0);
        Assert.True(result.ThreatScore <= 10);
    }

    [Fact]
    public void ThreatScore_CriticalEvent_High()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Cobalt Strike AES C2", "AES c2 encrypted beacon from cobalt strike"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 20);
    }

    [Fact]
    public void ThreatScore_CappedAt100()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("Cobalt Strike AES C2", "AES c2 encrypted from cobalt strike"),
            ("Mythic DNS C2", "DNS c2 tunnel via mythic framework"),
            ("Sliver SSH tunnel", "Protocol tunnel with sliver c2"),
            ("Empire fallback C2", "Fallback c2 channel from empire framework"),
            ("Havoc multi-stage", "Multi-stage c2 payload from havoc"),
            ("Brute Ratel HTTP", "HTTP C2 beacon from brute ratel implant"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore <= 100);
    }

    // ── Threat Level Classification ─────────────────────────────────

    [Fact]
    public void ThreatLevel_Zero_Minimal()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void ThreatLevel_LowScore_Low()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Base64 C2", "Base64 c2 encoded payload data"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore > 0);
        Assert.Equal("Low", result.ThreatLevel);
    }

    // ── Stats Computation ───────────────────────────────────────────

    [Fact]
    public void Stats_WithDetections_ComputedCorrectly()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("HTTP C2 beacon", "HTTP C2 beacon detected"),
            ("DNS tunnel", "DNS tunnel for C2 channel"));
        var result = detector.Detect(report);

        Assert.True(result.Stats.TotalTechniquesUsed >= 2);
        Assert.True(result.Stats.AverageConfidence > 0);
    }

    [Fact]
    public void Stats_EncryptedChannelCount()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("AES C2", "AES c2 channel to server"),
            ("Web C2", "Web c2 outbound callback to suspicious domain"));
        var result = detector.Detect(report);

        Assert.True(result.Stats.EncryptedChannels >= 1);
        Assert.True(result.Stats.ClearTextChannels >= 1);
    }

    [Fact]
    public void Stats_FrameworksDetected_Counted()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("Cobalt Strike HTTP", "HTTP C2 beacon from cobalt strike"),
            ("Sliver DNS", "DNS c2 channel via sliver framework"));
        var result = detector.Detect(report);

        Assert.True(result.Stats.FrameworksDetected >= 2);
    }

    // ── Deduplication ───────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateFindings_Deduplicated()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = new SecurityReport();
        var result1 = new AuditResult { ModuleName = "Module1", Category = "Module1" };
        result1.Findings.Add(new Finding { Title = "HTTP C2 beacon", Description = "HTTP C2 beacon detected" });
        var result2 = new AuditResult { ModuleName = "Module2", Category = "Module2" };
        result2.Findings.Add(new Finding { Title = "HTTP C2 beacon", Description = "HTTP C2 beacon detected" });
        report.Results.Add(result1);
        report.Results.Add(result2);

        var detected = detector.Detect(report);
        Assert.Equal(1, detected.C2DetectionsCount);
    }

    // ── Indicator Detection ─────────────────────────────────────────

    [Fact]
    public void Detect_DomainFronting_IndicatorAdded()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Domain fronting C2", "HTTP C2 beacon using domain fronting via CDN"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Domain fronting"));
    }

    [Fact]
    public void Detect_DNSTunneling_IndicatorAdded()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("DNS covert", "DNS tunnel using dnscat tool"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("DNS tunneling"));
    }

    [Fact]
    public void Detect_MultiStage_IndicatorAdded()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Staged payload", "Multi-stage c2 with stager downloading second stage"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Multi-stage"));
    }

    [Fact]
    public void Detect_Fallback_IndicatorAdded()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Backup C2", "Fallback c2 channel with backup channel activated"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Fallback"));
    }

    [Fact]
    public void Detect_Evasion_IndicatorAdded()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("CDN C2", "HTTP C2 beacon with jitter and cdn fronting"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("evasion"));
    }

    [Fact]
    public void Detect_LateralMovement_IndicatorAdded()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Pivot C2", "HTTP C2 beacon with proxy pivot capability"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("lateral movement"));
    }

    [Fact]
    public void Detect_Exfiltration_IndicatorAdded()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("HTTP C2 exfil", "HTTP C2 beacon channel used for data exfil upload"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("exfiltration"));
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Recommendations_DNS_IncludesDNSAdvice()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("DNS C2", "DNS c2 channel for covert communication"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("DNS"));
    }

    [Fact]
    public void Recommendations_Framework_IncludesFrameworkAdvice()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("Cobalt Strike", "HTTP C2 beacon from cobalt strike"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("cobalt strike"));
    }

    [Fact]
    public void Recommendations_Campaign_IncludesIRAdvice()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("HTTP C2 beacon", "HTTP C2 beacon to external server"),
            ("DNS tunnel", "DNS tunnel for covert C2 channel"),
            ("SSH tunnel", "SSH tunnel as protocol tunnel backup"));
        var result = detector.Detect(report);

        if (result.Campaigns.Count > 0)
            Assert.Contains(result.Recommendations, r => r.Contains("incident response"));
    }

    // ── Protocol Extraction ─────────────────────────────────────────

    [Fact]
    public void Detect_ExtractsHttpProtocol()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("HTTP C2", "HTTP C2 beacon over https to external C2 server"));
        var result = detector.Detect(report);

        Assert.NotNull(result.Detections[0].Protocol);
    }

    [Fact]
    public void Detect_ExtractsDnsProtocol()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(("DNS C2", "DNS c2 channel using dns queries"));
        var result = detector.Detect(report);

        Assert.Equal("dns", result.Detections[0].Protocol);
    }

    // ── Severity Counts ─────────────────────────────────────────────

    [Fact]
    public void SeverityCounts_Correct()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("Base64 C2", "Base64 c2 encoded payload"),
            ("HTTP C2", "Web c2 beacon outbound"),
            ("DNS tunnel", "DNS c2 covert channel"));
        var result = detector.Detect(report);

        Assert.Equal(result.HighSeverityC2 + result.MediumSeverityC2 + result.LowSeverityC2, result.C2DetectionsCount);
    }

    // ── Multiple Frameworks ─────────────────────────────────────────

    [Fact]
    public void Detect_MultipleFrameworks_AllDetected()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("Cobalt Strike", "HTTP C2 beacon from cobalt strike"),
            ("Mythic C2", "DNS c2 from mythic framework"));
        var result = detector.Detect(report);

        Assert.Equal(2, result.C2DetectionsCount);
        var frameworks = result.Detections.Select(d => d.KnownFramework).Where(f => f != null).Distinct().ToList();
        Assert.True(frameworks.Count >= 2);
    }

    // ── Days Analyzed ───────────────────────────────────────────────

    [Fact]
    public void Detect_CustomDays_Reflected()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport(), historyDays: 30);
        Assert.Equal(30, result.DaysAnalyzed);
    }

    [Fact]
    public void Detect_EventsProcessed_Counted()
    {
        var detector = new CommandControlDetector(CreateHistory());
        var report = MakeReport(
            ("Finding 1", "Some unrelated finding"),
            ("Finding 2", "Another unrelated finding"));
        var result = detector.Detect(report);

        Assert.Equal(2, result.EventsProcessed);
    }
}
