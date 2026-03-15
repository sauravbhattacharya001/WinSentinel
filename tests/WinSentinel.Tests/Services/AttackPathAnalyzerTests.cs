using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class AttackPathAnalyzerTests
{
    private static SecurityReport BuildReport(params (string module, string category, Finding finding)[] entries)
    {
        var groups = entries.GroupBy(e => (e.module, e.category));
        var results = groups.Select(g => new AuditResult
        {
            ModuleName = g.Key.module,
            Category = g.Key.category,
            Findings = g.Select(e => e.finding).ToList(),
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow,
        }).ToList();

        return new SecurityReport
        {
            Results = results,
            SecurityScore = 50,
        };
    }

    [Fact]
    public void Analyze_EmptyReport_ReturnsNoPaths()
    {
        var analyzer = new AttackPathAnalyzer();
        var report = new SecurityReport();
        var result = analyzer.Analyze(report);

        Assert.Empty(result.Paths);
        Assert.Empty(result.Chokepoints);
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal("Minimal", result.OverallRisk);
    }

    [Fact]
    public void Analyze_SingleStage_NoPaths()
    {
        // Only firewall findings (Initial Access) — no path without a second stage
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Warning("Open port 3389", "RDP port exposed", "Firewall")),
            ("FirewallAudit", "Firewall", Finding.Critical("No firewall rules", "Default allow all", "Firewall"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.Empty(result.Paths);
        Assert.Contains("Initial Access", result.StageBreakdown.Keys);
    }

    [Fact]
    public void Analyze_TwoStages_CreatesPath()
    {
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Warning("Open port 3389", "RDP port exposed", "Firewall")),
            ("AccountAudit", "Accounts", Finding.Critical("Admin no MFA", "MFA not enabled for admin", "Accounts"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.NotEmpty(result.Paths);
        Assert.True(result.Paths[0].StagesCovered >= 2);
        Assert.True(result.Paths[0].ExploitabilityScore > 0);
    }

    [Fact]
    public void Analyze_FullKillChain_HighScore()
    {
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Critical("Open port 3389", "RDP exposed", "Firewall")),
            ("PowerShellAudit", "PowerShell", Finding.Warning("Unrestricted execution", "No execution policy", "PowerShell")),
            ("StartupAudit", "Startup", Finding.Warning("Unknown startup item", "Suspicious startup", "Startup")),
            ("AccountAudit", "Accounts", Finding.Critical("Admin no password", "Blank admin password", "Accounts")),
            ("NetworkAudit", "DNS", Finding.Warning("DNS over plaintext", "No DoH/DoT", "DNS")),
            ("PrivacyAudit", "Privacy", Finding.Critical("Clipboard monitoring", "Data leak risk", "Privacy"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.NotEmpty(result.Paths);
        var topPath = result.Paths[0];
        Assert.True(topPath.StagesCovered >= 4, $"Expected ≥4 stages, got {topPath.StagesCovered}");
        Assert.True(topPath.ExploitabilityScore >= 50, $"Expected score ≥50, got {topPath.ExploitabilityScore}");
        Assert.True(result.OverallRisk is "Critical" or "High",
            $"Expected Critical or High risk, got {result.OverallRisk}");
    }

    [Fact]
    public void Analyze_ChokePoints_IdentifiesMostCommon()
    {
        // Create findings that appear across multiple stages
        var firewallFinding = Finding.Critical("Open port 3389", "RDP exposed", "Firewall");
        var accountFinding = Finding.Critical("Admin no MFA", "No MFA", "Accounts");

        var report = BuildReport(
            ("FirewallAudit", "Firewall", firewallFinding),
            ("FirewallAudit", "Firewall", Finding.Warning("Open port 22", "SSH exposed", "Firewall")),
            ("AccountAudit", "Accounts", accountFinding),
            ("StartupAudit", "Startup", Finding.Warning("Persistence item", "Unknown startup", "Startup"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.NotEmpty(result.Chokepoints);
        Assert.Equal(1, result.Chokepoints[0].Priority);
        Assert.True(result.Chokepoints[0].TotalRiskReduced > 0);
    }

    [Fact]
    public void Analyze_PassFindings_Ignored()
    {
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Pass("Firewall enabled", "Good", "Firewall")),
            ("AccountAudit", "Accounts", Finding.Pass("MFA enabled", "Good", "Accounts"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.Empty(result.Paths);
        Assert.Equal(0, result.FindingsInPaths);
    }

    [Fact]
    public void Analyze_InfoFindings_Ignored()
    {
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Info("5 rules configured", "Details", "Firewall")),
            ("AccountAudit", "Accounts", Finding.Info("3 users found", "Details", "Accounts"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.Empty(result.Paths);
    }

    [Fact]
    public void Analyze_StageBreakdown_AllStagesPresent()
    {
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Warning("Open port", "Exposed", "Firewall"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.Equal(6, result.StageBreakdown.Count);
        Assert.Contains("Initial Access", result.StageBreakdown.Keys);
        Assert.Contains("Execution", result.StageBreakdown.Keys);
        Assert.Contains("Persistence", result.StageBreakdown.Keys);
        Assert.Contains("Privilege Escalation", result.StageBreakdown.Keys);
        Assert.Contains("Lateral Movement", result.StageBreakdown.Keys);
        Assert.Contains("Exfiltration", result.StageBreakdown.Keys);
    }

    [Fact]
    public void Analyze_WithMitreReport_UsesMapping()
    {
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Warning("Open port 3389", "RDP exposed", "Firewall")),
            ("PowerShellAudit", "PowerShell", Finding.Warning("Unrestricted execution policy", "Exec bypass", "PowerShell")),
            ("AccountAudit", "Accounts", Finding.Critical("Weak passwords", "No complexity", "Accounts")),
            ("PrivacyAudit", "Privacy", Finding.Warning("Clipboard access", "Data leak", "Privacy"))
        );

        // Create a MITRE attack report
        var mapper = new MitreAttackMapper();
        var attackReport = mapper.Analyze(report);

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report, attackReport);

        // With 4 stages covered, should find paths
        Assert.NotEmpty(result.Paths);
    }

    [Fact]
    public void AttackPath_RiskLevel_CorrectClassification()
    {
        var path = new AttackPathAnalyzer.AttackPath
        {
            Name = "Test",
            Description = "Test path",
        };

        path.ExploitabilityScore = 85;
        Assert.Equal("Critical", path.RiskLevel);

        path.ExploitabilityScore = 65;
        Assert.Equal("High", path.RiskLevel);

        path.ExploitabilityScore = 45;
        Assert.Equal("Medium", path.RiskLevel);

        path.ExploitabilityScore = 25;
        Assert.Equal("Low", path.RiskLevel);

        path.ExploitabilityScore = 10;
        Assert.Equal("Minimal", path.RiskLevel);
    }

    [Fact]
    public void AttackPathReport_Summary_DescriptiveWhenPaths()
    {
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Critical("Open RDP", "Port 3389", "Firewall")),
            ("AccountAudit", "Accounts", Finding.Warning("Weak pass", "No complexity", "Accounts"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        Assert.NotEmpty(result.Summary);
        Assert.Contains("attack path", result.Summary);
    }

    [Fact]
    public void AttackPathReport_Summary_DescriptiveWhenNoPaths()
    {
        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(new SecurityReport());

        Assert.Contains("No multi-stage", result.Summary);
    }

    [Fact]
    public void AttackStep_StageName_Correct()
    {
        var step = new AttackPathAnalyzer.AttackStep
        {
            Stage = AttackPathAnalyzer.AttackStage.InitialAccess,
            Finding = Finding.Warning("Test", "Test", "Test"),
            Module = "TestModule",
        };

        Assert.Equal("Initial Access", step.StageName);
    }

    [Fact]
    public void Analyze_DuplicatePaths_Deduplicated()
    {
        // Two identical firewall findings should produce deduplicated paths
        var report = BuildReport(
            ("FirewallAudit", "Firewall", Finding.Warning("Open port 3389", "RDP", "Firewall")),
            ("FirewallAudit", "Firewall", Finding.Warning("Open port 3389", "RDP", "Firewall")),
            ("AccountAudit", "Accounts", Finding.Warning("Weak pass", "No complexity", "Accounts"))
        );

        var analyzer = new AttackPathAnalyzer();
        var result = analyzer.Analyze(report);

        // Should not have duplicate paths with identical step titles
        var pathKeys = result.Paths.Select(p =>
            string.Join("|", p.Steps.Select(s => s.Finding.Title))).ToList();
        Assert.Equal(pathKeys.Distinct().Count(), pathKeys.Count);
    }
}
