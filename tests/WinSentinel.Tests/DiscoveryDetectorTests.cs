using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class DiscoveryDetectorTests
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
        var detector = new DiscoveryDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.ActivitiesDetected);
        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Activities);
        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void Detect_NoDiscoveryFindings_ReturnsZeroActivities()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Firewall enabled", "Windows firewall is active and configured"));
        var result = detector.Detect(report);

        Assert.Equal(0, result.ActivitiesDetected);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    // ── Technique Detection ─────────────────────────────────────────

    [Fact]
    public void Detect_SystemInfo_DetectsSystemInformationDiscovery()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("System enumeration detected", "Systeminfo command executed to gather system information"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("System Information Discovery", result.Activities[0].Technique);
        Assert.Equal("T1082", result.Activities[0].MitreTechnique);
        Assert.Equal("System", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_AccountDiscovery_DetectsAccountEnumeration()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("User enumeration", "Net user command used for account discovery"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Account Discovery", result.Activities[0].Technique);
        Assert.Equal("T1087", result.Activities[0].MitreTechnique);
        Assert.Equal("Account", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_ProcessDiscovery_DetectsProcessListing()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Process listing detected", "Tasklist used for process discovery on endpoint"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Process Discovery", result.Activities[0].Technique);
        Assert.Equal("T1057", result.Activities[0].MitreTechnique);
        Assert.Equal("Process", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_NetworkConfig_DetectsNetworkConfigDiscovery()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Network config query", "Ipconfig /all executed to discover network configuration"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("System Network Configuration Discovery", result.Activities[0].Technique);
        Assert.Equal("T1016", result.Activities[0].MitreTechnique);
        Assert.Equal("Network", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_RemoteSystemDiscovery_DetectsNetworkScan()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Network scan detected", "Ping sweep across subnet for remote system discovery"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Remote System Discovery", result.Activities[0].Technique);
        Assert.Equal("T1018", result.Activities[0].MitreTechnique);
        Assert.Equal("Network", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_FileDirectoryDiscovery_DetectsFileEnumeration()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Directory traversal", "Get-ChildItem used for file discovery on sensitive paths"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("File and Directory Discovery", result.Activities[0].Technique);
        Assert.Equal("T1083", result.Activities[0].MitreTechnique);
        Assert.Equal("File System", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_NetworkShareDiscovery_DetectsSmbEnumeration()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("SMB share scan", "Net share command used for network share discovery"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Network Share Discovery", result.Activities[0].Technique);
        Assert.Equal("T1135", result.Activities[0].MitreTechnique);
        Assert.Equal("Network", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_PermissionGroupsDiscovery_DetectsGroupEnumeration()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Group membership query", "Net localgroup administrators for permission group discovery"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Permission Groups Discovery", result.Activities[0].Technique);
        Assert.Equal("T1069", result.Activities[0].MitreTechnique);
        Assert.Equal("Account", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_SoftwareDiscovery_DetectsAppInventory()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Software inventory scan", "Wmic product used for software discovery"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Software Discovery", result.Activities[0].Technique);
        Assert.Equal("T1518", result.Activities[0].MitreTechnique);
        Assert.Equal("Software", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_SecuritySoftwareDiscovery_DetectsAvDetection()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("AV detection attempt", "Security software enumeration for antivirus discovery"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Security Software Discovery", result.Activities[0].Technique);
        Assert.Equal("T1518.001", result.Activities[0].MitreTechnique);
        Assert.Equal("Security", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_ServiceDiscovery_DetectsServiceListing()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Service enumeration", "Sc query used for service discovery on host"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("System Service Discovery", result.Activities[0].Technique);
        Assert.Equal("T1007", result.Activities[0].MitreTechnique);
        Assert.Equal("Service", result.Activities[0].DiscoveryCategory);
    }

    [Fact]
    public void Detect_NetworkSniffing_DetectsPacketCapture()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Packet capture detected", "Wireshark running for network sniffing on interface"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("Network Sniffing", result.Activities[0].Technique);
        Assert.Equal("T1040", result.Activities[0].MitreTechnique);
        Assert.Equal("Network", result.Activities[0].DiscoveryCategory);
    }

    // ── Known Tool Detection ────────────────────────────────────────

    [Fact]
    public void Detect_KnownTool_BoostsConfidence()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Network scan", "Nmap used for remote system discovery on subnet"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("nmap", result.Activities[0].SourceTool);
        Assert.True(result.Activities[0].Confidence > 0.85); // Base 0.85 + 0.05 tool boost
        Assert.Contains(result.Activities[0].Indicators, i => i.Contains("nmap"));
    }

    [Fact]
    public void Detect_BloodHound_DetectedAsTool()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("AD enumeration", "Bloodhound used for account discovery and group enumeration"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.Equal("bloodhound", result.Activities[0].SourceTool);
    }

    // ── Automation Detection ────────────────────────────────────────

    [Fact]
    public void Detect_AutomatedScan_SetsIsAutomated()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Automated network scan", "Automated scanner performing remote system discovery across subnet"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
        Assert.True(result.Activities[0].IsAutomated);
        Assert.Contains(result.Activities[0].Indicators, i => i.Contains("Automated"));
    }

    [Fact]
    public void Detect_ManualDiscovery_NotAutomated()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("User ran whoami", "Whoami command used for account discovery"));
        var result = detector.Detect(report);

        Assert.False(result.Activities[0].IsAutomated);
    }

    // ── Severity Classification ─────────────────────────────────────

    [Fact]
    public void Severity_SecuritySoftwareWithTool_IsCritical()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Security probe", "Seatbelt used for security software enumeration and antivirus discovery"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Critical, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_NetworkSniffingWithTool_IsCritical()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Sniffing", "Tcpdump network sniffing with responder on interface"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Critical, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_RemoteSystemDiscovery_IsHigh()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Host discovery", "Remote system discovery via ping sweep"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.High, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_NetworkSniffing_IsHigh()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Packet capture", "Network sniffing detected on interface"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.High, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_SecuritySoftwareDiscovery_IsHigh()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("AV probe", "Security software discovery on endpoint"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.High, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_AccountDiscovery_IsMedium()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("User enum", "Account discovery via net user command"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Medium, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_PermissionGroups_IsMedium()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Group enum", "Permission group discovery via net localgroup"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Medium, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_SystemInfo_IsLow()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("System check", "System information gathered via systeminfo"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Low, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_ProcessDiscovery_IsLow()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Process check", "Process discovery via tasklist"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Low, result.Activities[0].Severity);
    }

    [Fact]
    public void Severity_FileDiscovery_IsLow()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("File search", "File discovery via get-childitem on sensitive dirs"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Low, result.Activities[0].Severity);
    }

    // ── Campaign Detection ──────────────────────────────────────────

    [Fact]
    public void Detect_MultipleActivities_BuildsCampaign()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(
            ("Account enum on host: target:server01", "Net user for account discovery on target:server01"),
            ("Service scan on host: target:server01", "Service discovery via sc query on target:server01"));
        var result = detector.Detect(report);

        Assert.True(result.Campaigns.Count >= 1);
    }

    [Fact]
    public void Detect_MultiCategoryActivities_DetectsMultiCategoryCampaign()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(
            ("User enumeration", "Account discovery via net user"),
            ("Network scan", "Remote system discovery via ping sweep"),
            ("AV check", "Security software discovery"));
        var result = detector.Detect(report);

        // Should detect multi-category campaign (Account, Network, Security)
        Assert.True(result.Campaigns.Count >= 1);
        Assert.True(result.Campaigns.Any(c => c.CategoryCount >= 2));
    }

    // ── Threat Scoring ──────────────────────────────────────────────

    [Fact]
    public void Score_NoActivities_IsMinimal()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void Score_SingleLowActivity_IsLowScore()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("System check", "System information gathered via systeminfo"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore > 0);
        Assert.True(result.ThreatScore < 20);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void Score_HighSeverityActivity_ScoresHigher()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Network scan", "Remote system discovery via ping sweep with nmap"));
        var result = detector.Detect(report);

        // High severity (15) + tool bonus (15) = at least 30
        Assert.True(result.ThreatScore >= 20);
    }

    [Fact]
    public void Score_CriticalWithCampaign_ExceedsElevated()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(
            ("Probe 1", "Security software enumeration using seatbelt for antivirus discovery"),
            ("Probe 2", "Remote system discovery with nmap on subnet"),
            ("Probe 3", "Account discovery via net user with bloodhound"),
            ("Probe 4", "Network sniffing with tcpdump on interface"),
            ("Probe 5", "Process discovery via tasklist"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 60);
        Assert.True(result.ThreatLevel is "Elevated" or "Critical");
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Recommendations_EmptyReport_HasContinueMonitoring()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Single(result.Recommendations);
        Assert.Contains("Continue monitoring", result.Recommendations[0]);
    }

    [Fact]
    public void Recommendations_WithActivity_GeneratesTechniqueSpecific()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Remote scan", "Remote system discovery via network scan"));
        var result = detector.Detect(report);

        Assert.True(result.Recommendations.Count >= 2); // Technique-specific + general
        Assert.Contains(result.Recommendations, r => r.Contains("CRITICAL"));
    }

    // ── Deduplication ───────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateFindings_Deduplicates()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(
            ("System info check", "System information via systeminfo"),
            ("System info check", "System information via systeminfo"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ActivitiesDetected);
    }

    // ── Statistics ───────────────────────────────────────────────────

    [Fact]
    public void Stats_MultipleActivities_ComputesCorrectly()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(
            ("Account enum", "Account discovery via net user"),
            ("Process list", "Process discovery via tasklist"),
            ("Network scan", "Remote system discovery via ping sweep"));
        var result = detector.Detect(report);

        Assert.Equal(3, result.Stats.TotalTechniquesUsed);
        Assert.Equal("Account Discovery", result.Stats.MostCommonTechnique); // First alphabetically by detection order
        Assert.True(result.Stats.AverageConfidence > 0);
        Assert.True(result.Stats.DiscoveryCategoriesUsed >= 2);
    }

    [Fact]
    public void Stats_EmptyReport_ReturnsDefaultStats()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.Stats.TotalTechniquesUsed);
        Assert.Equal("None", result.Stats.MostCommonTechnique);
        Assert.Equal(0, result.Stats.AutomatedActivities);
    }

    // ── Indicator Correlation ───────────────────────────────────────

    [Fact]
    public void Detect_LateralMovementCorrelation_AddsIndicator()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Lateral recon", "Remote system discovery for lateral movement preparation"));
        var result = detector.Detect(report);

        Assert.Contains(result.Activities[0].Indicators, i => i.Contains("lateral movement"));
    }

    [Fact]
    public void Detect_PrivilegeEscalationCorrelation_AddsIndicator()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Priv enum", "Account discovery targeting privilege escalation paths for admin accounts"));
        var result = detector.Detect(report);

        Assert.Contains(result.Activities[0].Indicators, i => i.Contains("privilege escalation"));
    }

    [Fact]
    public void Detect_ExfiltrationCorrelation_AddsIndicator()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Data staging", "File discovery for data collection and exfiltration staging"));
        var result = detector.Detect(report);

        Assert.Contains(result.Activities[0].Indicators, i => i.Contains("exfiltration"));
    }

    // ── Custom History Days ─────────────────────────────────────────

    [Fact]
    public void Detect_CustomDays_SetsCorrectly()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report, 30);

        Assert.Equal(30, result.DaysAnalyzed);
    }

    // ── Network Share Medium Severity ───────────────────────────────

    [Fact]
    public void Severity_NetworkShare_IsMedium()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Share scan", "Network share discovery via net share command"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Medium, result.Activities[0].Severity);
    }

    // ── Campaign-level Severity ─────────────────────────────────────

    [Fact]
    public void Severity_CampaignIndicator_IsCritical()
    {
        var detector = new DiscoveryDetector(CreateHistory());
        var report = MakeReport(("Mass recon", "Mass network scan campaign for remote system discovery"));
        var result = detector.Detect(report);

        Assert.Equal(DiscoverySeverity.Critical, result.Activities[0].Severity);
    }
}
