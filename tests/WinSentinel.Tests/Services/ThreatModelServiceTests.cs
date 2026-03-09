using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ThreatModelServiceTests
{
    private readonly ThreatModelService _service = new();

    private static SecurityReport MakeReport(params Finding[] findings)
    {
        var result = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            Findings = findings.ToList()
        };
        return new SecurityReport { Results = new List<AuditResult> { result } };
    }

    // ── Basic Analysis ──

    [Fact]
    public void EmptyReport_ReturnsEmptyModel()
    {
        var report = new SecurityReport();
        var model = _service.Analyze(report);

        Assert.Equal(0, model.TotalThreats);
        Assert.Equal(0, model.TotalAttackPaths);
        Assert.Equal(0, model.FindingsAnalyzed);
        Assert.Equal(Severity.Pass, model.OverallRisk);
        Assert.Empty(model.Threats);
        Assert.Empty(model.AttackPaths);
        Assert.Equal(6, model.CategorySummaries.Count);
        Assert.Equal(0.0, model.StrideCoveragePercent);
    }

    [Fact]
    public void PassOnlyFindings_AreExcluded()
    {
        var report = MakeReport(
            Finding.Pass("All good", "Everything is fine", "Security"));
        var model = _service.Analyze(report);

        Assert.Equal(0, model.FindingsAnalyzed);
        Assert.Equal(0, model.TotalThreats);
    }

    // ── STRIDE Classification ──

    [Fact]
    public void PasswordFinding_ClassifiedAsSpoofing()
    {
        var report = MakeReport(
            Finding.Warning("Weak password policy", "Minimum length is too short", "Auth"));
        var model = _service.Analyze(report);

        Assert.True(model.TotalThreats >= 1);
        var spoofing = model.Threats.Where(t =>
            t.Category == ThreatModelService.StrideCategory.Spoofing).ToList();
        Assert.NotEmpty(spoofing);
    }

    [Fact]
    public void SecureBoot_ClassifiedAsTampering()
    {
        var report = MakeReport(
            Finding.Critical("Secure Boot disabled", "System integrity at risk", "Boot"));
        var model = _service.Analyze(report);

        var tampering = model.Threats.Where(t =>
            t.Category == ThreatModelService.StrideCategory.Tampering).ToList();
        Assert.NotEmpty(tampering);
    }

    [Fact]
    public void AuditPolicy_ClassifiedAsRepudiation()
    {
        var report = MakeReport(
            Finding.Warning("Audit policy not configured", "No event logging", "Logging"));
        var model = _service.Analyze(report);

        var repudiation = model.Threats.Where(t =>
            t.Category == ThreatModelService.StrideCategory.Repudiation).ToList();
        Assert.NotEmpty(repudiation);
    }

    [Fact]
    public void NetworkShare_ClassifiedAsInfoDisclosure()
    {
        var report = MakeReport(
            Finding.Warning("Open SMB share", "Network share with no access control", "Network"));
        var model = _service.Analyze(report);

        var infoDisc = model.Threats.Where(t =>
            t.Category == ThreatModelService.StrideCategory.InformationDisclosure).ToList();
        Assert.NotEmpty(infoDisc);
    }

    [Fact]
    public void DefenderDisabled_ClassifiedAsDos()
    {
        var report = MakeReport(
            Finding.Critical("Windows Defender disabled", "Real-time protection off", "Antivirus"));
        var model = _service.Analyze(report);

        var dos = model.Threats.Where(t =>
            t.Category == ThreatModelService.StrideCategory.DenialOfService).ToList();
        Assert.NotEmpty(dos);
    }

    [Fact]
    public void UacDisabled_ClassifiedAsEoP()
    {
        var report = MakeReport(
            Finding.Critical("UAC is disabled", "User Account Control not enforcing prompts", "Privilege"));
        var model = _service.Analyze(report);

        var eop = model.Threats.Where(t =>
            t.Category == ThreatModelService.StrideCategory.ElevationOfPrivilege).ToList();
        Assert.NotEmpty(eop);
    }

    // ── Threat Properties ──

    [Fact]
    public void Threat_HasEvidenceFindings()
    {
        var report = MakeReport(
            Finding.Warning("Password complexity not enforced", "No complexity rules", "Auth"),
            Finding.Warning("Account lockout not configured", "No lockout threshold", "Auth"));
        var model = _service.Analyze(report);

        var spoofThreat = model.Threats.FirstOrDefault(t =>
            t.Category == ThreatModelService.StrideCategory.Spoofing);
        Assert.NotNull(spoofThreat);
        Assert.True(spoofThreat.EvidenceCount >= 2);
    }

    [Fact]
    public void Threat_RiskLevel_ReflectsWorstFinding()
    {
        var report = MakeReport(
            Finding.Info("Password age", "Password doesn't expire", "Auth"),
            Finding.Critical("No password policy", "Password policy is empty", "Auth"));
        var model = _service.Analyze(report);

        var spoofThreat = model.Threats.FirstOrDefault(t =>
            t.Category == ThreatModelService.StrideCategory.Spoofing);
        Assert.NotNull(spoofThreat);
        Assert.Equal(Severity.Critical, spoofThreat.RiskLevel);
    }

    [Fact]
    public void Threat_HasMitigation()
    {
        var report = MakeReport(
            Finding.Warning("Weak password policy", "Too short", "Auth"));
        var model = _service.Analyze(report);

        var threat = model.Threats.First();
        Assert.False(string.IsNullOrEmpty(threat.Mitigation));
    }

    [Fact]
    public void Threats_OrderedByRiskScore_Descending()
    {
        var report = MakeReport(
            Finding.Info("Telemetry enabled", "Privacy issue", "Privacy"),
            Finding.Critical("UAC disabled", "No elevation prompts", "Privilege"),
            Finding.Warning("Audit policy weak", "Insufficient logging", "Logging"));
        var model = _service.Analyze(report);

        if (model.Threats.Count >= 2)
        {
            for (int i = 1; i < model.Threats.Count; i++)
            {
                Assert.True(model.Threats[i - 1].RiskScore >= model.Threats[i].RiskScore);
            }
        }
    }

    // ── Attack Paths ──

    [Fact]
    public void NoMatchingSteps_NoAttackPaths()
    {
        var report = MakeReport(
            Finding.Info("Minor telemetry", "Not significant", "Privacy"));
        var model = _service.Analyze(report);

        Assert.Empty(model.AttackPaths);
    }

    [Fact]
    public void MultipleRelatedThreats_FormAttackPath()
    {
        // Provide findings that match multiple STRIDE categories to trigger attack paths
        var report = MakeReport(
            Finding.Critical("Weak password policy", "No complexity", "Auth"),
            Finding.Critical("UAC disabled", "No elevation prompts", "Privilege"),
            Finding.Critical("Startup items unprotected", "Persistence risk", "Boot"),
            Finding.Warning("Audit policy not set", "No logging", "Logging"),
            Finding.Warning("Windows Defender disabled", "No AV", "Antivirus"),
            Finding.Warning("Open firewall rules", "Inbound rules too permissive", "Network"),
            Finding.Warning("SMB share exposed", "Network share accessible", "Network"));
        var model = _service.Analyze(report);

        // Should find at least one attack path since multiple STRIDE categories hit
        Assert.True(model.TotalAttackPaths >= 1,
            $"Expected at least 1 attack path, got {model.TotalAttackPaths}");
    }

    [Fact]
    public void AttackPath_HasMultipleSteps()
    {
        var report = MakeReport(
            Finding.Critical("Weak password policy", "No complexity", "Auth"),
            Finding.Critical("UAC disabled", "No prompts", "Privilege"),
            Finding.Critical("Startup items unprotected", "Persistence", "Boot"),
            Finding.Warning("Audit policy disabled", "No logging", "Logging"),
            Finding.Warning("Defender disabled", "No AV", "Antivirus"),
            Finding.Warning("Firewall rule too broad", "Inbound open", "Network"),
            Finding.Warning("SMB share exposed", "Network share", "Network"));
        var model = _service.Analyze(report);

        if (model.AttackPaths.Count > 0)
        {
            Assert.True(model.AttackPaths[0].StepCount >= 2);
        }
    }

    // ── Category Summaries ──

    [Fact]
    public void CategorySummaries_CoverAllSixCategories()
    {
        var report = new SecurityReport();
        var model = _service.Analyze(report);

        Assert.Equal(6, model.CategorySummaries.Count);
        var categories = model.CategorySummaries.Select(c => c.Category).ToList();
        Assert.Contains(ThreatModelService.StrideCategory.Spoofing, categories);
        Assert.Contains(ThreatModelService.StrideCategory.Tampering, categories);
        Assert.Contains(ThreatModelService.StrideCategory.Repudiation, categories);
        Assert.Contains(ThreatModelService.StrideCategory.InformationDisclosure, categories);
        Assert.Contains(ThreatModelService.StrideCategory.DenialOfService, categories);
        Assert.Contains(ThreatModelService.StrideCategory.ElevationOfPrivilege, categories);
    }

    [Fact]
    public void CategorySummary_ReflectsThreatCounts()
    {
        var report = MakeReport(
            Finding.Warning("Password policy weak", "Too short", "Auth"),
            Finding.Critical("Account lockout missing", "No lockout", "Auth"));
        var model = _service.Analyze(report);

        var spoofing = model.CategorySummaries
            .First(c => c.Category == ThreatModelService.StrideCategory.Spoofing);
        Assert.True(spoofing.ThreatCount >= 1);
    }

    // ── Priority Actions ──

    [Fact]
    public void PriorityActions_NotEmpty_WhenThreatsExist()
    {
        var report = MakeReport(
            Finding.Critical("UAC disabled", "No prompts", "Privilege"),
            Finding.Warning("Audit policy weak", "No logging", "Logging"));
        var model = _service.Analyze(report);

        Assert.NotEmpty(model.PriorityActions);
    }

    [Fact]
    public void PriorityActions_Empty_WhenNoThreats()
    {
        var report = new SecurityReport();
        var model = _service.Analyze(report);

        Assert.Empty(model.PriorityActions);
    }

    // ── Custom Rules ──

    [Fact]
    public void AddRule_ExtendsClassification()
    {
        _service.AddRule(new ThreatModelService.ClassificationRule(
            Category: ThreatModelService.StrideCategory.Tampering,
            ThreatId: "T-CUSTOM-01",
            ThreatTitle: "Custom Tampering Threat",
            ThreatDescription: "A custom-defined threat",
            FindingPatterns: new[] { "custom pattern xyz" },
            Mitigation: "Fix the custom thing"
        ));

        var report = MakeReport(
            Finding.Warning("Custom pattern xyz found", "Something unusual", "Test"));
        var model = _service.Analyze(report);

        var custom = model.Threats.FirstOrDefault(t => t.Id == "T-CUSTOM-01");
        Assert.NotNull(custom);
        Assert.Equal("Custom Tampering Threat", custom.Title);
    }

    [Fact]
    public void AddRule_ThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => _service.AddRule(null!));
    }

    [Fact]
    public void Rules_ReturnsRegisteredRules()
    {
        var rules = _service.Rules;
        Assert.True(rules.Count >= 12, "Expected at least 12 built-in rules");
    }

    // ── OverallRisk ──

    [Fact]
    public void OverallRisk_IsPass_WhenNoThreats()
    {
        var report = new SecurityReport();
        var model = _service.Analyze(report);
        Assert.Equal(Severity.Pass, model.OverallRisk);
    }

    [Fact]
    public void OverallRisk_IsCritical_WhenCriticalThreatExists()
    {
        var report = MakeReport(
            Finding.Critical("UAC disabled", "Critical gap", "Privilege"));
        var model = _service.Analyze(report);
        Assert.Equal(Severity.Critical, model.OverallRisk);
    }

    // ── StrideCoverage ──

    [Fact]
    public void StrideCoverage_ZeroWhenNoThreats()
    {
        var report = new SecurityReport();
        var model = _service.Analyze(report);
        Assert.Equal(0.0, model.StrideCoveragePercent);
    }

    [Fact]
    public void StrideCoverage_ReflectsAffectedCategories()
    {
        var report = MakeReport(
            Finding.Warning("Password weak", "Bad auth", "Auth"),
            Finding.Warning("Audit not configured", "No logs", "Logging"));
        var model = _service.Analyze(report);

        // At least Spoofing + Repudiation
        Assert.True(model.StrideCoveragePercent >= 33.0);
        Assert.True(model.AffectedCategories.Count >= 2);
    }

    // ── Analyze ThrowsOnNull ──

    [Fact]
    public void Analyze_ThrowsOnNullReport()
    {
        Assert.Throws<ArgumentNullException>(() => _service.Analyze(null!));
    }

    // ── Finding dedup across rules ──

    [Fact]
    public void Finding_OnlyMatchedOnce_AcrossRules()
    {
        // A finding matching multiple rules should only appear in the first match
        var report = MakeReport(
            Finding.Warning("Password policy and authentication issue",
                "Weak credential and authentication setup", "Auth"));
        var model = _service.Analyze(report);

        // Count total evidence findings across all threats
        var totalEvidence = model.Threats.Sum(t => t.EvidenceCount);
        // The finding should only appear once (in one threat)
        Assert.Equal(1, totalEvidence);
    }

    // ── Multi-module report ──

    [Fact]
    public void MultiModuleReport_AnalyzesAllModules()
    {
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new AuditResult
                {
                    ModuleName = "Auth",
                    Category = "Authentication",
                    Findings = new List<Finding>
                    {
                        Finding.Warning("Password policy", "Too weak", "Auth")
                    }
                },
                new AuditResult
                {
                    ModuleName = "Logging",
                    Category = "AuditLogging",
                    Findings = new List<Finding>
                    {
                        Finding.Warning("Audit policy", "Not configured", "Logging")
                    }
                }
            }
        };

        var model = _service.Analyze(report);
        Assert.Equal(2, model.FindingsAnalyzed);
        Assert.True(model.TotalThreats >= 2);
    }
}
