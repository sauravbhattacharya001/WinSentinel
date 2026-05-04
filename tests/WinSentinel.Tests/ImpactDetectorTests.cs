using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class ImpactDetectorTests
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
        var detector = new ImpactDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.ImpactDetectionsCount);
        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Detections);
        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void Detect_NoImpactFindings_ReturnsZeroDetections()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Firewall enabled", "Windows firewall is active"));
        var result = detector.Detect(report);

        Assert.Equal(0, result.ImpactDetectionsCount);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void Detect_EmptyReport_HasDefaultStats()
    {
        var detector = new ImpactDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());

        Assert.Equal(0, result.Stats.TotalTechniquesUsed);
        Assert.Equal("None", result.Stats.MostCommonTechnique);
        Assert.Equal(0, result.Stats.ToolsDetected);
        Assert.Equal(0, result.Stats.DestructiveEvents);
    }

    [Fact]
    public void Detect_EmptyReport_GeneratesMaintenanceRecommendation()
    {
        var detector = new ImpactDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());

        Assert.Single(result.Recommendations);
        Assert.Contains("No impact activity detected", result.Recommendations[0]);
    }

    // ── Technique Detection (12 MITRE techniques) ───────────────────

    [Fact]
    public void Detect_DataDestruction_T1485()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Data destruction attack", "Mass delete of critical files detected on server"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1485", result.Detections[0].MitreTechnique);
        Assert.Equal("Data Destruction", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_Ransomware_T1486()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransomware detected", "Crypto locker encrypting files on endpoint"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1486", result.Detections[0].MitreTechnique);
        Assert.Equal("Data Encrypted for Impact", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_DiskStructureWipe_T1561002()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("MBR wipe detected", "Master boot record overwritten on disk"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1561.002", result.Detections[0].MitreTechnique);
        Assert.Equal("Disk Structure Wipe", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_ServiceStop_T1489()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Service stop attack", "Critical services terminated via net stop command"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1489", result.Detections[0].MitreTechnique);
        Assert.Equal("Service Stop", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_InhibitRecovery_T1490()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Shadow copy deletion", "Vssadmin delete shadows executed on host"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1490", result.Detections[0].MitreTechnique);
        Assert.Equal("Inhibit System Recovery", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_InternalDefacement_T1491001()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Internal defacement", "Intranet portal defaced with attacker message"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1491.001", result.Detections[0].MitreTechnique);
        Assert.Equal("Internal Defacement", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_ExternalDefacement_T1491002()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("External defacement", "Public website deface detected"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1491.002", result.Detections[0].MitreTechnique);
        Assert.Equal("External Defacement", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_FirmwareCorruption_T1495()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Firmware corruption", "UEFI tamper attempt detected on endpoint"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1495", result.Detections[0].MitreTechnique);
        Assert.Equal("Firmware Corruption", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_ResourceHijacking_T1496()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Cryptomining detected", "Unauthorized mining process xmrig on workstation"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1496", result.Detections[0].MitreTechnique);
        Assert.Equal("Resource Hijacking", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_NetworkDoS_T1498()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("DDoS attack", "Network flood ddos attack targeting web servers"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1498", result.Detections[0].MitreTechnique);
        Assert.Equal("Network Denial of Service", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_EndpointDoS_T1499()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Endpoint DoS", "Resource exhaustion causing application crash"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1499", result.Detections[0].MitreTechnique);
        Assert.Equal("Endpoint Denial of Service", result.Detections[0].Technique);
    }

    [Fact]
    public void Detect_SystemShutdown_T1529()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Forced shutdown", "Unauthorized forced reboot of production server"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("T1529", result.Detections[0].MitreTechnique);
        Assert.Equal("System Shutdown/Reboot", result.Detections[0].Technique);
    }

    // ── Known Tool Detection ────────────────────────────────────────

    [Fact]
    public void Detect_KnownTool_BoostsConfidence()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransomware attack", "WannaCry ransomware encrypt files on network"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
        Assert.Equal("wannacry", result.Detections[0].KnownTool);
        Assert.True(result.Detections[0].Confidence > 0.90);
    }

    [Fact]
    public void Detect_LockBit_Identified()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("LockBit ransomware", "LockBit ransomware encrypt files on endpoint"));
        var result = detector.Detect(report);

        Assert.Equal("lockbit", result.Detections[0].KnownTool);
    }

    [Fact]
    public void Detect_Shamoon_Identified()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Shamoon wiper", "Shamoon data destruction disk wipe attack"));
        var result = detector.Detect(report);

        Assert.NotNull(result.Detections[0].KnownTool);
        Assert.Equal("shamoon", result.Detections[0].KnownTool);
    }

    [Fact]
    public void Detect_XMRig_Identified()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Mining malware", "XMRig cryptomining process detected"));
        var result = detector.Detect(report);

        Assert.Equal("xmrig", result.Detections[0].KnownTool);
    }

    // ── Destructive & Indicator Flags ───────────────────────────────

    [Fact]
    public void Detect_DestructiveIndicator_SetsFlagTrue()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Wiper malware", "Wiper malware destroy and erase all data"));
        var result = detector.Detect(report);

        Assert.True(result.Detections[0].IsDestructive);
    }

    [Fact]
    public void Detect_NonDestructive_DoS_FlagFalse()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("DDoS attack", "Network flood ddos attack on web server"));
        var result = detector.Detect(report);

        Assert.False(result.Detections[0].IsDestructive);
    }

    [Fact]
    public void Detect_RansomIndicator_AddedToIndicators()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransom attack", "Ransomware ransom note found demanding payment via bitcoin wallet"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Ransomware indicators"));
    }

    [Fact]
    public void Detect_RecoveryInhibit_AddedToIndicators()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransomware with recovery disable", "Ransomware encrypt files and vssadmin delete shadow copies"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Recovery inhibition"));
    }

    [Fact]
    public void Detect_LateralSpread_AddedToIndicators()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Worm ransomware", "Ransomware encrypt files and spread across network"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Lateral spread"));
    }

    [Fact]
    public void Detect_DoubleExtortion_AddedToIndicators()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Double extortion", "Ransomware encrypt files with double extortion data exfil"));
        var result = detector.Detect(report);

        Assert.Contains(result.Detections[0].Indicators, i => i.Contains("Double extortion"));
    }

    // ── Severity Classification ─────────────────────────────────────

    [Fact]
    public void Severity_RansomwareWithRecoveryInhibit_Critical()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransomware", "Ransomware encrypt files and vssadmin delete shadow copies"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.Critical, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_FirmwareCorruption_Critical()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Firmware attack", "Firmware corrupt UEFI tamper detected"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.Critical, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_KnownToolDestructive_Critical()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Shamoon wiper", "Shamoon data destruction wipe and destroy files"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.Critical, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_DataDestruction_High()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Data destruction", "Mass delete of production database files"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.High, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_Ransomware_High()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransomware", "Ransomware encrypt files on endpoint"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.High, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_ServiceStop_Medium()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Service disruption", "Service stop attack disabled critical services"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.Medium, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_Defacement_Medium()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Website deface", "External defacement of public website"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.Medium, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_ResourceHijack_Medium()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Cryptojacking", "Cryptomining unauthorized mining on workstation"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.Medium, result.Detections[0].Severity);
    }

    [Fact]
    public void Severity_DoS_Low()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("DDoS", "Network flood ddos attack on external services"));
        var result = detector.Detect(report);

        Assert.Equal(ImpactSeverity.Low, result.Detections[0].Severity);
    }

    // ── Campaigns ───────────────────────────────────────────────────

    [Fact]
    public void Detect_MultipleTechniques_FormsCampaign()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Ransomware", "Ransomware encrypt files on endpoint"),
            ("Recovery inhibit", "Vssadmin delete shadows executed on host"),
            ("Service stop", "Service stop attack disabled antivirus"));
        var result = detector.Detect(report);

        Assert.True(result.Campaigns.Count >= 1);
        Assert.True(result.Campaigns[0].TechniqueCount >= 2);
    }

    [Fact]
    public void Detect_SingleTechnique_NoCampaign()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransomware", "Ransomware encrypt files on endpoint"));
        var result = detector.Detect(report);

        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void Campaign_HasVerdict()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Ransomware", "Ransomware encrypt files"),
            ("Recovery inhibit", "Delete shadow copies via vssadmin delete"));
        var result = detector.Detect(report);

        if (result.Campaigns.Count > 0)
            Assert.False(string.IsNullOrEmpty(result.Campaigns[0].Verdict));
    }

    // ── Deduplication ───────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateFindings_Deduplicated()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Ransomware detected", "Ransomware encrypt files on server"),
            ("Ransomware detected", "Ransomware encrypt files on server"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ImpactDetectionsCount);
    }

    // ── Threat Score & Level ────────────────────────────────────────

    [Fact]
    public void ThreatScore_NoEvents_Zero()
    {
        var detector = new ImpactDetector(CreateHistory());
        var result = detector.Detect(new SecurityReport());

        Assert.Equal(0, result.ThreatScore);
    }

    [Fact]
    public void ThreatScore_CriticalEvent_High()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Firmware attack", "Firmware corrupt UEFI tamper on server"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 20);
    }

    [Fact]
    public void ThreatScore_CappedAt100()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Ransomware 1", "Ransomware encrypt files on server 1"),
            ("Ransomware 2", "Ransomware encrypt files on server 2"),
            ("Wiper 1", "Wiper malware data destruction on host 1"),
            ("Wiper 2", "Data destruction secure erase on host 2"),
            ("MBR wipe", "MBR wipe boot record overwrite"),
            ("Firmware", "Firmware corrupt BIOS modify"),
            ("Recovery", "Vssadmin delete shadows backup deletion"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore <= 100);
    }

    [Fact]
    public void ThreatLevel_Classification_Correct()
    {
        var detector = new ImpactDetector(CreateHistory());

        // Empty should be Minimal
        var result = detector.Detect(new SecurityReport());
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    // ── Stats ───────────────────────────────────────────────────────

    [Fact]
    public void Stats_CountsTechniquesCorrectly()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Ransomware", "Ransomware encrypt files"),
            ("DDoS", "Network flood ddos attack"));
        var result = detector.Detect(report);

        Assert.Equal(2, result.Stats.TotalTechniquesUsed);
    }

    [Fact]
    public void Stats_CountsDestructiveCorrectly()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Data destruction", "Data destruction wipe files"),
            ("DDoS", "Network flood ddos attack"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.Stats.DestructiveEvents);
        Assert.Equal(1, result.Stats.NonDestructiveEvents);
    }

    [Fact]
    public void Stats_ToolsDetected_CountsCorrectly()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("WannaCry attack", "WannaCry ransomware encrypt files"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.Stats.ToolsDetected);
    }

    [Fact]
    public void Stats_MostCommonTechnique_Identified()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Ransomware 1", "Ransomware encrypt files on server 1"),
            ("Ransomware 2", "Crypto locker encrypt files on server 2"),
            ("DDoS", "Network flood ddos attack"));
        var result = detector.Detect(report);

        Assert.Equal("Data Encrypted for Impact", result.Stats.MostCommonTechnique);
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Recommendations_Ransomware_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ransomware", "Ransomware encrypt files on endpoint"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Ransomware"));
    }

    [Fact]
    public void Recommendations_RecoveryInhibit_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Recovery inhibit", "Delete shadow copies via vssadmin delete"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Recovery inhibition"));
    }

    [Fact]
    public void Recommendations_DataDestruction_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Wiper", "Data destruction mass delete files"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Data destruction"));
    }

    [Fact]
    public void Recommendations_Firmware_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Firmware", "Firmware corrupt BIOS modify attack"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Firmware"));
    }

    [Fact]
    public void Recommendations_ResourceHijack_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Mining", "Cryptomining unauthorized mining detected"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Resource hijacking"));
    }

    [Fact]
    public void Recommendations_KnownTools_Listed()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Ryuk ransomware", "Ryuk ransomware encrypt files"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("ryuk"));
    }

    [Fact]
    public void Recommendations_Campaign_Escalation()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(
            ("Ransomware", "Ransomware encrypt files"),
            ("Recovery", "Delete shadow copies vssadmin delete"),
            ("Service stop", "Service stop attack on antivirus"));
        var result = detector.Detect(report);

        if (result.Campaigns.Count > 0)
            Assert.Contains(result.Recommendations, r => r.Contains("campaign"));
    }

    [Fact]
    public void Recommendations_DoS_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("DDoS", "Network denial of service flooding attack"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Denial of service"));
    }

    [Fact]
    public void Recommendations_Defacement_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Defacement", "External defacement website deface"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Defacement"));
    }

    [Fact]
    public void Recommendations_Shutdown_Present()
    {
        var detector = new ImpactDetector(CreateHistory());
        var report = MakeReport(("Shutdown", "Unauthorized forced shutdown of production server"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("shutdown"));
    }
}
