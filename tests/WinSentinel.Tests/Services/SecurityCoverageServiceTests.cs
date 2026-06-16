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

    [Fact]
    public void Analyze_UnrelatedCategorySubstring_DoesNotContaminateDomainCounts()
    {
        // "DNS Security" expects category "DNS". A separate module reporting category
        // "mDNS-Discovery" .Contains("DNS") as a substring and previously leaked its
        // (failing) findings into the DNS domain's totals, inflating TotalChecks/
        // FailingChecks and falsely flagging DNS as a weak domain. Exact category
        // matching must keep the unrelated module out.
        var report = CreateReport(
            CreateAuditResult("DnsAudit", "DNS", pass: 2),
            CreateAuditResult("SomethingElseAudit", "mDNS-Discovery", critical: 9));

        var coverage = _service.Analyze(report);
        var dns = coverage.Domains.Single(d => d.Domain == "DNS Security");

        Assert.False(dns.HasGap);
        Assert.Equal(2, dns.TotalChecks);
        Assert.Equal(2, dns.PassingChecks);
        Assert.Equal(0, dns.FailingChecks);
        Assert.Equal(100, dns.CoveragePercent);
        // The unrelated module must not push DNS into the weak-domain recommendation.
        Assert.DoesNotContain(coverage.Recommendations,
            r => r.Contains("DNS Security") && r.Contains("failing"));
    }

    [Fact]
    public void Analyze_CategoryOnlyMatch_PopulatesCoveredBy()
    {
        // A plugin module whose name is not in ExpectedModules but whose Category IS a
        // known domain category should both cover the domain AND be credited in
        // CoveredBy (previously CoveredBy only ever listed ExpectedModules, so a
        // category-covered domain showed HasGap=false with an empty CoveredBy).
        var report = CreateReport(
            CreateAuditResult("AcmeFirewallPlugin", "Firewall", pass: 5, warning: 1));

        var coverage = _service.Analyze(report);
        var firewall = coverage.Domains.Single(d => d.Domain == "Firewall");

        Assert.False(firewall.HasGap);
        Assert.Equal(6, firewall.TotalChecks);
        Assert.Equal(5, firewall.PassingChecks);
        Assert.Equal(1, firewall.FailingChecks);
        Assert.NotEmpty(firewall.CoveredBy);
        Assert.Contains("AcmeFirewallPlugin", firewall.CoveredBy);
    }

    [Theory]
    [InlineData("Event Logging", "EventLogAudit", "Event Logs")]
    [InlineData("VPN / Remote Access", "RemoteAccessAudit", "Remote Access")]
    [InlineData("Scheduled Tasks", "ScheduledTaskAudit", "ScheduledTasks")]
    public void Analyze_RealAuditCategory_IsDetectedByCategoryAlone(
        string domainName, string moduleName, string realCategory)
    {
        // These domains' ExpectedCategories must equal the category strings the real
        // audits actually emit (e.g. EventLogAudit reports "Event Logs", not
        // "EventLog"). Verify coverage is detected via the category path even when the
        // reporting module name differs from the expected one.
        var report = CreateReport(
            CreateAuditResult("SomePluginNamed_" + moduleName.ToLowerInvariant(), realCategory, pass: 3));

        var coverage = _service.Analyze(report);
        var domain = coverage.Domains.Single(d => d.Domain == domainName);

        Assert.False(domain.HasGap);
        Assert.Equal(3, domain.TotalChecks);
        Assert.Equal(3, domain.PassingChecks);
    }

    [Fact]
    public void Analyze_NearMissCategory_IsNotTreatedAsCoverage()
    {
        // A category that merely contains a domain category as a substring (here
        // "Networking-Extras" vs the "Network" domain) must NOT, on its own, cover
        // the Network domain now that matching is exact.
        var report = CreateReport(
            CreateAuditResult("ThirdPartyNetTool", "Networking-Extras", pass: 4));

        var coverage = _service.Analyze(report);
        var network = coverage.Domains.Single(d => d.Domain == "Network Security");

        Assert.True(network.HasGap);
        Assert.Equal(0, network.TotalChecks);
        Assert.Contains("NetworkAudit", network.GapReason);
    }
}
