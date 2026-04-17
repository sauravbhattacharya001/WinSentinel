using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for <see cref="SecurityCoverageService"/> coverage analysis.
/// </summary>
public class SecurityCoverageServiceTests
{
    private readonly SecurityCoverageService _service = new();

    private static SecurityReport CreateReport(params AuditResult[] results)
    {
        var report = new SecurityReport();
        report.Results.AddRange(results);
        return report;
    }

    private static AuditResult CreateAuditResult(string moduleName, string category, int pass = 0, int warning = 0, int critical = 0)
    {
        var result = new AuditResult { ModuleName = moduleName, Category = category };
        for (int i = 0; i < pass; i++)
            result.Findings.Add(new Finding { Title = $"Pass {i}", Description = "OK", Severity = Severity.Pass });
        for (int i = 0; i < warning; i++)
            result.Findings.Add(new Finding { Title = $"Warn {i}", Description = "Issue", Severity = Severity.Warning });
        for (int i = 0; i < critical; i++)
            result.Findings.Add(new Finding { Title = $"Crit {i}", Description = "Bad", Severity = Severity.Critical });
        return result;
    }

    [Fact]
    public void Analyze_EmptyReport_ReportsAllDomainsAsGaps()
    {
        var report = CreateReport();
        var coverage = _service.Analyze(report);

        Assert.True(coverage.TotalDomains > 0);
        Assert.Equal(0, coverage.CoveredDomains);
        Assert.True(coverage.GapDomains > 0);
        Assert.Equal(0, coverage.OverallCoveragePercent);
    }

    [Fact]
    public void Analyze_FirewallModulePresent_CoversFirewallDomain()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall", pass: 5, warning: 1));

        var coverage = _service.Analyze(report);
        var firewall = coverage.Domains.Single(d => d.Domain == "Firewall");

        Assert.False(firewall.HasGap);
        Assert.Equal(6, firewall.TotalChecks);
        Assert.Equal(5, firewall.PassingChecks);
        Assert.Equal(1, firewall.FailingChecks);
        Assert.Contains("FirewallAudit", firewall.CoveredBy);
    }

    [Fact]
    public void Analyze_CoveragePercent_CalculatesCorrectly()
    {
        var report = CreateReport(
            CreateAuditResult("DefenderAudit", "Defender", pass: 8, warning: 2));

        var coverage = _service.Analyze(report);
        var defender = coverage.Domains.Single(d => d.Domain == "Antivirus / Defender");

        // 8 pass out of 10 total = 80%
        Assert.Equal(80.0, defender.CoveragePercent);
        Assert.False(defender.HasGap);
    }

    [Fact]
    public void Analyze_DomainWithNoExpectedModules_ReportsAsGap()
    {
        // Physical Security and Email Security have no expected modules
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall", pass: 3));

        var coverage = _service.Analyze(report);
        var physical = coverage.Domains.Single(d => d.Domain == "Physical Security");

        Assert.True(physical.HasGap);
        Assert.Equal("No audit module exists for this domain", physical.GapReason);
    }

    [Fact]
    public void Analyze_MissingExpectedModule_ReportsGapWithReason()
    {
        // UpdateAudit not present → Windows Updates domain should show gap
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall", pass: 1));

        var coverage = _service.Analyze(report);
        var updates = coverage.Domains.Single(d => d.Domain == "Windows Updates");

        Assert.True(updates.HasGap);
        Assert.Contains("UpdateAudit", updates.GapReason);
    }

    [Fact]
    public void Analyze_FullCoverage_ReportsHighOverallPercent()
    {
        // Provide all modules that have expected audits
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall", pass: 1),
            CreateAuditResult("UpdateAudit", "Updates", pass: 1),
            CreateAuditResult("DefenderAudit", "Defender", pass: 1),
            CreateAuditResult("AccountAudit", "Accounts", pass: 1),
            CreateAuditResult("NetworkAudit", "Network", pass: 1),
            CreateAuditResult("ProcessAudit", "Processes", pass: 1),
            CreateAuditResult("StartupAudit", "Startup", pass: 1),
            CreateAuditResult("SystemAudit", "System", pass: 1),
            CreateAuditResult("PrivacyAudit", "Privacy", pass: 1),
            CreateAuditResult("BrowserAudit", "Browser", pass: 1),
            CreateAuditResult("AppSecurityAudit", "Applications", pass: 1),
            CreateAuditResult("EncryptionAudit", "Encryption", pass: 1),
            CreateAuditResult("EventLogAudit", "EventLog", pass: 1),
            CreateAuditResult("SoftwareInventoryAudit", "Software", pass: 1),
            CreateAuditResult("CertificateAudit", "Certificates", pass: 1),
            CreateAuditResult("PowerShellAudit", "PowerShell", pass: 1),
            CreateAuditResult("DnsAudit", "DNS", pass: 1),
            CreateAuditResult("ScheduledTaskAudit", "Tasks", pass: 1),
            CreateAuditResult("ServiceAudit", "Services", pass: 1),
            CreateAuditResult("RegistryAudit", "Registry", pass: 1),
            CreateAuditResult("BackupAudit", "Backup", pass: 1),
            CreateAuditResult("RemoteAccessAudit", "RemoteAccess", pass: 1),
            CreateAuditResult("BluetoothAudit", "Bluetooth", pass: 1),
            CreateAuditResult("WifiAudit", "WiFi", pass: 1),
            CreateAuditResult("CredentialExposureAudit", "Credentials", pass: 1),
            CreateAuditResult("VirtualizationAudit", "Virtualization", pass: 1),
            CreateAuditResult("SmbShareAudit", "SMB", pass: 1),
            CreateAuditResult("GroupPolicyAudit", "GroupPolicy", pass: 1),
            CreateAuditResult("DriverAudit", "Drivers", pass: 1));

        var coverage = _service.Analyze(report);

        // Only Physical Security and Email Security have no modules at all
        Assert.True(coverage.OverallCoveragePercent > 90);
        Assert.True(coverage.CoveredDomains >= 29);
    }

    [Fact]
    public void Analyze_Recommendations_ListGapsWhenPresent()
    {
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall", pass: 3));

        var coverage = _service.Analyze(report);

        Assert.True(coverage.Recommendations.Count > 0);
        Assert.Contains(coverage.Recommendations, r => r.Contains("no audit coverage"));
    }

    [Fact]
    public void Analyze_Recommendations_ReportsWeakDomains()
    {
        // More failures than passes in a covered domain
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall", pass: 1, warning: 3, critical: 2));

        var coverage = _service.Analyze(report);

        // Should mention weak domains (5 failing vs 1 passing)
        Assert.Contains(coverage.Recommendations, r => r.Contains("more failures than passes"));
    }

    [Fact]
    public void Analyze_CategoryMatchIsCaseInsensitive()
    {
        // Category with different casing should still match
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "FIREWALL", pass: 2));

        var coverage = _service.Analyze(report);
        var firewall = coverage.Domains.Single(d => d.Domain == "Firewall");

        Assert.False(firewall.HasGap);
    }

    [Fact]
    public void Analyze_ModuleMatchIsCaseInsensitive()
    {
        var report = CreateReport(
            CreateAuditResult("firewallaudit", "other", pass: 2));

        var coverage = _service.Analyze(report);
        var firewall = coverage.Domains.Single(d => d.Domain == "Firewall");

        Assert.False(firewall.HasGap);
    }

    [Fact]
    public void Analyze_ZeroChecks_CoveredDomainShowsFullCoverage()
    {
        // Module exists but has no findings
        var report = CreateReport(
            CreateAuditResult("FirewallAudit", "Firewall"));

        var coverage = _service.Analyze(report);
        var firewall = coverage.Domains.Single(d => d.Domain == "Firewall");

        Assert.False(firewall.HasGap);
        Assert.Equal(0, firewall.TotalChecks);
        Assert.Equal(100, firewall.CoveragePercent);
    }

    [Fact]
    public void Analyze_ReportContainsAllDomains()
    {
        var report = CreateReport();
        var coverage = _service.Analyze(report);

        Assert.Equal(coverage.TotalDomains, coverage.Domains.Count);
        Assert.True(coverage.TotalDomains >= 30);
    }
}
