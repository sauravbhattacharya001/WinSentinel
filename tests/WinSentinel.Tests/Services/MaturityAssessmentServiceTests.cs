using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for MaturityAssessmentService — CMMI-inspired 1–5 maturity grading
/// across security domains based on audit findings.
/// </summary>
public class MaturityAssessmentServiceTests
{
    private readonly MaturityAssessmentService _svc = new();

    // ─── Helper Methods ──────────────────────────────────────────

    private static SecurityReport CreateReport(params AuditResult[] results)
    {
        var report = new SecurityReport();
        report.Results.AddRange(results);
        return report;
    }

    private static AuditResult MakeResult(string category, params Finding[] findings)
        => new()
        {
            ModuleName = $"{category}Audit",
            Category = category,
            Findings = findings.ToList(),
        };

    // ─── Empty / Minimal Input ───────────────────────────────────

    [Fact]
    public void Assess_EmptyReport_ReturnsAllSevenDomains()
    {
        var result = _svc.Assess(CreateReport());

        Assert.NotNull(result);
        Assert.Equal(7, result.Domains.Count);
    }

    [Fact]
    public void Assess_EmptyReport_AllDomainsZeroScores()
    {
        var result = _svc.Assess(CreateReport());

        foreach (var d in result.Domains)
        {
            Assert.Equal(0, d.Score);
            Assert.Equal(0, d.MaxScore);
        }
    }

    [Fact]
    public void Assess_EmptyReport_ZeroFindingCounts()
    {
        var result = _svc.Assess(CreateReport());

        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.CriticalFindings);
        Assert.Equal(0, result.WarningFindings);
    }

    [Fact]
    public void Assess_EmptyReport_GradeIsAssigned()
    {
        var result = _svc.Assess(CreateReport());

        Assert.NotNull(result.Grade);
        Assert.NotEmpty(result.Grade);
        Assert.Contains(result.Grade, new[] { "A", "B", "C", "D", "F" });
    }

    [Fact]
    public void Assess_EmptyReport_AssessedAtIsRecent()
    {
        var result = _svc.Assess(CreateReport());

        Assert.True((DateTime.UtcNow - result.AssessedAt).TotalSeconds < 10);
    }

    // ─── Domain Mapping — every category routes correctly ────────

    [Theory]
    [InlineData("Accounts", "Identity & Access")]
    [InlineData("Credentials", "Identity & Access")]
    [InlineData("Remote Access", "Identity & Access")]
    [InlineData("Firewall", "Network Security")]
    [InlineData("Network", "Network Security")]
    [InlineData("DNS", "Network Security")]
    [InlineData("WiFi", "Network Security")]
    [InlineData("SMB", "Network Security")]
    [InlineData("Bluetooth", "Network Security")]
    [InlineData("Defender", "Endpoint Protection")]
    [InlineData("Processes", "Endpoint Protection")]
    [InlineData("Drivers", "Endpoint Protection")]
    [InlineData("Services", "Endpoint Protection")]
    [InlineData("Startup", "Endpoint Protection")]
    [InlineData("Encryption", "Data Protection")]
    [InlineData("Privacy", "Data Protection")]
    [InlineData("Browser", "Data Protection")]
    [InlineData("Certificates", "Data Protection")]
    [InlineData("Updates", "Patch & Config Management")]
    [InlineData("Applications", "Patch & Config Management")]
    [InlineData("Software", "Patch & Config Management")]
    [InlineData("Registry", "Patch & Config Management")]
    [InlineData("GroupPolicy", "Patch & Config Management")]
    [InlineData("System", "System Hardening")]
    [InlineData("Environment", "System Hardening")]
    [InlineData("PowerShell", "System Hardening")]
    [InlineData("Virtualization", "System Hardening")]
    [InlineData("Backup", "Resilience & Recovery")]
    [InlineData("Event Logs", "Resilience & Recovery")]
    [InlineData("ScheduledTasks", "Resilience & Recovery")]
    public void Assess_CategoryMappedToCorrectDomain(string category, string expectedDomain)
    {
        var report = CreateReport(MakeResult(category,
            Finding.Warning("test", "d", category)));

        var result = _svc.Assess(report);
        var domain = result.Domains.First(d => d.Name == expectedDomain);

        Assert.True(domain.MaxScore > 0,
            $"Category '{category}' should map to domain '{expectedDomain}'");
    }

    [Fact]
    public void Assess_UnknownCategory_DefaultsToSystemHardening()
    {
        var report = CreateReport(MakeResult("TotallyUnknown",
            Finding.Warning("w", "d", "TotallyUnknown")));

        var result = _svc.Assess(report);
        var sys = result.Domains.First(d => d.Name == "System Hardening");

        Assert.True(sys.MaxScore > 0);
    }

    // ─── Scoring Weights ─────────────────────────────────────────
    //   Pass = +3,  Info = +1,  Warning = 0,  Critical = -1
    //   MaxScore = total_findings * 3

    [Fact]
    public void Assess_PassGives3Points()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Pass("p", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Equal(3, domain.Score);
        Assert.Equal(3, domain.MaxScore);
    }

    [Fact]
    public void Assess_InfoGives1Point()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Info("i", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Equal(1, domain.Score);
        Assert.Equal(3, domain.MaxScore);
    }

    [Fact]
    public void Assess_WarningGives0Points()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Warning("w", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Equal(0, domain.Score);
        Assert.Equal(3, domain.MaxScore);
    }

    [Fact]
    public void Assess_CriticalGivesNeg1_ClampedToZero()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Critical("c", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        // Raw score = -1, clamped to 0
        Assert.Equal(0, domain.Score);
        Assert.Equal(3, domain.MaxScore);
    }

    [Fact]
    public void Assess_MixedScoring_CorrectSum()
    {
        // 2 pass(6) + 1 info(1) + 1 warning(0) + 1 critical(-1) = 6, max = 15
        var report = CreateReport(MakeResult("Firewall",
            Finding.Pass("p1", "d", "Firewall"),
            Finding.Pass("p2", "d", "Firewall"),
            Finding.Info("i1", "d", "Firewall"),
            Finding.Warning("w1", "d", "Firewall"),
            Finding.Critical("c1", "d", "Firewall")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Equal(6, domain.Score);
        Assert.Equal(15, domain.MaxScore);
    }

    [Fact]
    public void Assess_ScoreNeverNegative()
    {
        // 5 criticals: raw = -5, clamped to 0
        var report = CreateReport(MakeResult("Firewall",
            Finding.Critical("c1", "d", "Firewall"),
            Finding.Critical("c2", "d", "Firewall"),
            Finding.Critical("c3", "d", "Firewall"),
            Finding.Critical("c4", "d", "Firewall"),
            Finding.Critical("c5", "d", "Firewall")));

        foreach (var d in _svc.Assess(report).Domains)
            Assert.True(d.Score >= 0, $"'{d.Name}' must not be negative");
    }

    // ─── Percentage Calculation ──────────────────────────────────

    [Fact]
    public void Assess_Percentage_CalculatedCorrectly()
    {
        // Score 6, Max 9 → 66.7
        var report = CreateReport(MakeResult("Backup",
            Finding.Pass("p1", "d", "Backup"),
            Finding.Pass("p2", "d", "Backup"),
            Finding.Warning("w1", "d", "Backup")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Resilience & Recovery");

        Assert.Equal(66.7, domain.Percentage);
    }

    [Fact]
    public void Assess_Percentage_ZeroWhenEmpty()
    {
        var domain = _svc.Assess(CreateReport()).Domains.First();
        Assert.Equal(0, domain.Percentage);
    }

    // ─── Level Thresholds ────────────────────────────────────────
    //   >=90 → Optimizing,  >=75 → Managed,  >=55 → Defined,
    //   >=35 → Repeatable,  <35 → Initial

    [Fact]
    public void Level_AllPass_Optimizing()
    {
        var report = CreateReport(MakeResult("Firewall",
            Finding.Pass("p1", "d", "Firewall"),
            Finding.Pass("p2", "d", "Firewall"),
            Finding.Pass("p3", "d", "Firewall")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");
        // pct 100%
        Assert.Equal(MaturityLevel.Optimizing, domain.Level);
    }

    [Fact]
    public void Level_Pct93_Optimizing()
    {
        // 9 pass + 1 info → 28/30 = 93.3%
        var findings = Enumerable.Range(1, 9)
            .Select(i => Finding.Pass($"p{i}", "d", "Updates"))
            .Append(Finding.Info("i1", "d", "Updates"))
            .ToArray();

        var report = CreateReport(MakeResult("Updates", findings));
        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Patch & Config Management");

        Assert.Equal(MaturityLevel.Optimizing, domain.Level);
    }

    [Fact]
    public void Level_Pct83_Managed()
    {
        // 3 pass + 1 info → 10/12 = 83.3%
        var report = CreateReport(MakeResult("Privacy",
            Finding.Pass("p1", "d", "Privacy"),
            Finding.Pass("p2", "d", "Privacy"),
            Finding.Pass("p3", "d", "Privacy"),
            Finding.Info("i1", "d", "Privacy")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Data Protection");
        Assert.Equal(MaturityLevel.Managed, domain.Level);
    }

    [Fact]
    public void Level_Pct58_Defined()
    {
        // 2 pass + 1 info + 1 warning → 7/12 = 58.3%
        var report = CreateReport(MakeResult("System",
            Finding.Pass("p1", "d", "System"),
            Finding.Pass("p2", "d", "System"),
            Finding.Info("i1", "d", "System"),
            Finding.Warning("w1", "d", "System")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "System Hardening");
        Assert.Equal(MaturityLevel.Defined, domain.Level);
    }

    [Fact]
    public void Level_Pct50_Repeatable()
    {
        // 2 pass + 2 warning → 6/12 = 50%
        var report = CreateReport(MakeResult("Firewall",
            Finding.Pass("p1", "d", "Firewall"),
            Finding.Pass("p2", "d", "Firewall"),
            Finding.Warning("w1", "d", "Firewall"),
            Finding.Warning("w2", "d", "Firewall")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");
        Assert.Equal(MaturityLevel.Repeatable, domain.Level);
    }

    [Fact]
    public void Level_Pct25_Initial()
    {
        // 1 pass + 3 warning → 3/12 = 25%
        var report = CreateReport(MakeResult("Accounts",
            Finding.Pass("p1", "d", "Accounts"),
            Finding.Warning("w1", "d", "Accounts"),
            Finding.Warning("w2", "d", "Accounts"),
            Finding.Warning("w3", "d", "Accounts")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Identity & Access");
        Assert.Equal(MaturityLevel.Initial, domain.Level);
    }

    [Fact]
    public void Level_AllWarnings_Initial()
    {
        var report = CreateReport(MakeResult("Encryption",
            Finding.Warning("w1", "d", "Encryption"),
            Finding.Warning("w2", "d", "Encryption")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Data Protection");
        Assert.Equal(MaturityLevel.Initial, domain.Level);
    }

    [Fact]
    public void Level_AllCriticals_Initial()
    {
        var report = CreateReport(MakeResult("Accounts",
            Finding.Critical("c1", "d", "Accounts"),
            Finding.Critical("c2", "d", "Accounts")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Identity & Access");
        Assert.Equal(MaturityLevel.Initial, domain.Level);
    }

    [Fact]
    public void Level_AllInfo_Initial()
    {
        // All info: 3*1 / 3*3 = 33.3% → Initial (< 35)
        var report = CreateReport(MakeResult("System",
            Finding.Info("i1", "d", "System"),
            Finding.Info("i2", "d", "System"),
            Finding.Info("i3", "d", "System")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "System Hardening");
        Assert.Equal(MaturityLevel.Initial, domain.Level);
    }

    // ─── Strengths ───────────────────────────────────────────────

    [Fact]
    public void Strengths_ContainPassFindingTitles()
    {
        var report = CreateReport(MakeResult("Firewall",
            Finding.Pass("Firewall enabled", "d", "Firewall"),
            Finding.Pass("Rules tight", "d", "Firewall"),
            Finding.Warning("Loose rule", "d", "Firewall")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Contains("Firewall enabled", domain.Strengths);
        Assert.Contains("Rules tight", domain.Strengths);
        Assert.DoesNotContain("Loose rule", domain.Strengths);
    }

    [Fact]
    public void Strengths_LimitedToThree()
    {
        var findings = Enumerable.Range(1, 6)
            .Select(i => Finding.Pass($"Pass {i}", "d", "DNS"))
            .ToArray();

        var domain = _svc.Assess(CreateReport(MakeResult("DNS", findings)))
            .Domains.First(d => d.Name == "Network Security");

        Assert.True(domain.Strengths.Length <= 3);
    }

    [Fact]
    public void Strengths_Empty_WhenNoPassFindings()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Warning("w1", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");
        Assert.Empty(domain.Strengths);
    }

    // ─── Gaps ────────────────────────────────────────────────────

    [Fact]
    public void Gaps_CriticalAppearFirst()
    {
        var report = CreateReport(MakeResult("Defender",
            Finding.Warning("Old defs", "d", "Defender"),
            Finding.Critical("AV disabled", "d", "Defender"),
            Finding.Pass("Tamper on", "d", "Defender")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Endpoint Protection");

        Assert.NotEmpty(domain.Gaps);
        Assert.Equal("AV disabled", domain.Gaps[0]);
    }

    [Fact]
    public void Gaps_IncludeWarningsAfterCriticals()
    {
        var report = CreateReport(MakeResult("Defender",
            Finding.Critical("AV disabled", "d", "Defender"),
            Finding.Warning("Old defs", "d", "Defender")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Endpoint Protection");

        Assert.Contains("AV disabled", domain.Gaps);
        Assert.Contains("Old defs", domain.Gaps);
    }

    [Fact]
    public void Gaps_LimitedToThree()
    {
        var findings = Enumerable.Range(1, 6)
            .Select(i => Finding.Critical($"Critical {i}", "d", "Encryption"))
            .ToArray();

        var domain = _svc.Assess(CreateReport(MakeResult("Encryption", findings)))
            .Domains.First(d => d.Name == "Data Protection");

        Assert.True(domain.Gaps.Length <= 3);
    }

    [Fact]
    public void Gaps_Empty_WhenAllPass()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Pass("p1", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");
        Assert.Empty(domain.Gaps);
    }

    [Fact]
    public void Gaps_ExcludeInfoFindings()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Info("info1", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");
        Assert.Empty(domain.Gaps);
    }

    // ─── Recommendations ─────────────────────────────────────────

    [Fact]
    public void Recommendations_CriticalFindings_MentionCount()
    {
        var report = CreateReport(MakeResult("Network",
            Finding.Critical("c1", "d", "Network"),
            Finding.Critical("c2", "d", "Network")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Contains(domain.Recommendations,
            r => r.Contains("critical", StringComparison.OrdinalIgnoreCase) && r.Contains("2"));
    }

    [Fact]
    public void Recommendations_Warnings_MentionRemediate()
    {
        var report = CreateReport(MakeResult("Accounts",
            Finding.Warning("w1", "d", "Accounts")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Identity & Access");

        Assert.Contains(domain.Recommendations,
            r => r.Contains("Remediate", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("Accounts", "Identity & Access", "MFA")]
    [InlineData("Firewall", "Network Security", "firewall")]
    [InlineData("Defender", "Endpoint Protection", "protection")]
    [InlineData("Encryption", "Data Protection", "encryption")]
    [InlineData("Updates", "Patch & Config Management", "updates")]
    [InlineData("System", "System Hardening", "PowerShell")]
    [InlineData("Backup", "Resilience & Recovery", "backup")]
    public void Recommendations_LowMaturity_DomainSpecificAdvice(
        string category, string domainName, string expectedKeyword)
    {
        // All warnings → Initial level → triggers domain-specific recommendation
        var report = CreateReport(MakeResult(category,
            Finding.Warning("w1", "d", category),
            Finding.Warning("w2", "d", category)));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == domainName);

        Assert.Contains(domain.Recommendations,
            r => r.Contains(expectedKeyword, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Recommendations_HighMaturity_MaintainControls()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Pass("p1", "d", "DNS"),
            Finding.Pass("p2", "d", "DNS"),
            Finding.Pass("p3", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Contains(domain.Recommendations,
            r => r.Contains("Maintain", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Recommendations_NoCriticals_NoCriticalMessage()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Pass("p1", "d", "DNS")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.DoesNotContain(domain.Recommendations,
            r => r.Contains("critical", StringComparison.OrdinalIgnoreCase));
    }

    // ─── Overall Grade ───────────────────────────────────────────

    [Fact]
    public void Grade_A_WhenAllDomainsOptimizing()
    {
        var report = CreateReport(
            MakeResult("Accounts", Finding.Pass("p", "d", "Accounts")),
            MakeResult("Firewall", Finding.Pass("p", "d", "Firewall")),
            MakeResult("Defender", Finding.Pass("p", "d", "Defender")),
            MakeResult("Encryption", Finding.Pass("p", "d", "Encryption")),
            MakeResult("Updates", Finding.Pass("p", "d", "Updates")),
            MakeResult("System", Finding.Pass("p", "d", "System")),
            MakeResult("Backup", Finding.Pass("p", "d", "Backup")));

        var result = _svc.Assess(report);

        Assert.Equal("A", result.Grade);
        Assert.Equal(MaturityLevel.Optimizing, result.OverallLevel);
    }

    [Fact]
    public void Grade_F_WhenAllDomainsInitial()
    {
        var report = CreateReport(
            MakeResult("Accounts", Finding.Warning("w", "d", "Accounts")),
            MakeResult("Firewall", Finding.Warning("w", "d", "Firewall")),
            MakeResult("Defender", Finding.Warning("w", "d", "Defender")),
            MakeResult("Encryption", Finding.Warning("w", "d", "Encryption")),
            MakeResult("Updates", Finding.Warning("w", "d", "Updates")),
            MakeResult("System", Finding.Warning("w", "d", "System")),
            MakeResult("Backup", Finding.Warning("w", "d", "Backup")));

        var result = _svc.Assess(report);

        Assert.Equal("F", result.Grade);
        Assert.Equal(MaturityLevel.Initial, result.OverallLevel);
    }

    [Fact]
    public void Grade_AlwaysValidLetter()
    {
        var result = _svc.Assess(CreateReport());
        Assert.Contains(result.Grade, new[] { "A", "B", "C", "D", "F" });
    }

    // ─── OverallScore ────────────────────────────────────────────

    [Fact]
    public void OverallScore_BetweenOneAndFive()
    {
        var report = CreateReport(MakeResult("Firewall",
            Finding.Pass("p", "d", "Firewall")));

        var result = _svc.Assess(report);

        Assert.InRange(result.OverallScore, 1.0, 5.0);
    }

    [Fact]
    public void OverallScore_IsAverageOfDomainLevels()
    {
        // One domain Optimizing (5), six domains Initial (1) → avg = (5+1*6)/7 ≈ 1.6
        var report = CreateReport(MakeResult("Firewall",
            Finding.Pass("p", "d", "Firewall")));

        var result = _svc.Assess(report);
        var expected = Math.Round(result.Domains.Average(d => (int)d.Level), 1);

        Assert.Equal(expected, result.OverallScore);
    }

    // ─── Top Priorities ──────────────────────────────────────────

    [Fact]
    public void TopPriorities_IdentifiesWeakestDomains()
    {
        var report = CreateReport(
            MakeResult("Accounts",
                Finding.Warning("w1", "d", "Accounts"),
                Finding.Warning("w2", "d", "Accounts")),
            MakeResult("Firewall",
                Finding.Pass("p1", "d", "Firewall")));

        var result = _svc.Assess(report);

        Assert.Contains(result.TopPriorities,
            p => p.Contains("Identity & Access"));
    }

    [Fact]
    public void TopPriorities_MaxThree()
    {
        var report = CreateReport(
            MakeResult("Accounts", Finding.Warning("w", "d", "Accounts")),
            MakeResult("Firewall", Finding.Warning("w", "d", "Firewall")),
            MakeResult("Defender", Finding.Warning("w", "d", "Defender")),
            MakeResult("Encryption", Finding.Warning("w", "d", "Encryption")),
            MakeResult("Updates", Finding.Warning("w", "d", "Updates")),
            MakeResult("System", Finding.Warning("w", "d", "System")),
            MakeResult("Backup", Finding.Warning("w", "d", "Backup")));

        var result = _svc.Assess(report);

        Assert.True(result.TopPriorities.Length <= 3);
    }

    [Fact]
    public void TopPriorities_Empty_WhenAllDomainsManaged()
    {
        // All Optimizing → no priorities (threshold is <= Repeatable)
        var report = CreateReport(
            MakeResult("Accounts", Finding.Pass("p", "d", "Accounts")),
            MakeResult("Firewall", Finding.Pass("p", "d", "Firewall")),
            MakeResult("Defender", Finding.Pass("p", "d", "Defender")),
            MakeResult("Encryption", Finding.Pass("p", "d", "Encryption")),
            MakeResult("Updates", Finding.Pass("p", "d", "Updates")),
            MakeResult("System", Finding.Pass("p", "d", "System")),
            MakeResult("Backup", Finding.Pass("p", "d", "Backup")));

        Assert.Empty(_svc.Assess(report).TopPriorities);
    }

    [Fact]
    public void TopPriorities_OrderedByLevelAscending()
    {
        // Accounts Initial, Firewall Repeatable (50%), rest untouched (Initial)
        var report = CreateReport(
            MakeResult("Accounts",
                Finding.Warning("w1", "d", "Accounts"),
                Finding.Warning("w2", "d", "Accounts")),
            MakeResult("Firewall",
                Finding.Pass("p1", "d", "Firewall"),
                Finding.Pass("p2", "d", "Firewall"),
                Finding.Warning("w1", "d", "Firewall"),
                Finding.Warning("w2", "d", "Firewall")));

        var result = _svc.Assess(report);

        Assert.NotEmpty(result.TopPriorities);
        // First priority should be an Initial-level domain (Level 1)
        Assert.Contains("Level 1", result.TopPriorities[0]);
    }

    [Fact]
    public void TopPriorities_ContainLevelInfo()
    {
        var report = CreateReport(
            MakeResult("Accounts", Finding.Warning("w", "d", "Accounts")));

        var result = _svc.Assess(report);

        Assert.Contains(result.TopPriorities,
            p => p.Contains("Level") && p.Contains("Initial"));
    }

    // ─── Domain Descriptions ─────────────────────────────────────

    [Fact]
    public void AllDomains_HaveDescriptions()
    {
        foreach (var d in _svc.Assess(CreateReport()).Domains)
        {
            Assert.NotNull(d.Description);
            Assert.NotEmpty(d.Description);
        }
    }

    [Fact]
    public void AllDomains_HaveUniqueNames()
    {
        var names = _svc.Assess(CreateReport()).Domains.Select(d => d.Name).ToList();
        Assert.Equal(names.Count, names.Distinct().Count());
    }

    [Fact]
    public void AllDomains_ExpectedNames()
    {
        var names = _svc.Assess(CreateReport()).Domains.Select(d => d.Name).ToHashSet();

        Assert.Contains("Identity & Access", names);
        Assert.Contains("Network Security", names);
        Assert.Contains("Endpoint Protection", names);
        Assert.Contains("Data Protection", names);
        Assert.Contains("Patch & Config Management", names);
        Assert.Contains("System Hardening", names);
        Assert.Contains("Resilience & Recovery", names);
    }

    // ─── Multi-Category Aggregation ──────────────────────────────

    [Fact]
    public void MultipleCategoriesSameDomain_Aggregated()
    {
        var report = CreateReport(
            MakeResult("Accounts", Finding.Pass("p", "d", "Accounts")),
            MakeResult("Credentials", Finding.Critical("c", "d", "Credentials")),
            MakeResult("Remote Access", Finding.Warning("w", "d", "Remote Access")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Identity & Access");

        Assert.Equal(9, domain.MaxScore); // 3 findings × 3
    }

    [Fact]
    public void MultipleModulesSameCategory_Aggregated()
    {
        var report = CreateReport(
            MakeResult("Firewall", Finding.Pass("r1", "d", "Firewall")),
            MakeResult("Firewall", Finding.Pass("r2", "d", "Firewall")));

        var domain = _svc.Assess(report).Domains.First(d => d.Name == "Network Security");

        Assert.Equal(6, domain.MaxScore);
        Assert.Equal(6, domain.Score);
    }

    // ─── Finding Counts ──────────────────────────────────────────

    [Fact]
    public void TotalFindings_SumsAllModules()
    {
        var report = CreateReport(
            MakeResult("Accounts",
                Finding.Pass("p1", "d", "Accounts"),
                Finding.Warning("w1", "d", "Accounts")),
            MakeResult("Firewall",
                Finding.Critical("c1", "d", "Firewall")));

        Assert.Equal(3, _svc.Assess(report).TotalFindings);
    }

    [Fact]
    public void CriticalFindings_CountedCorrectly()
    {
        var report = CreateReport(
            MakeResult("Network",
                Finding.Critical("c1", "d", "Network"),
                Finding.Critical("c2", "d", "Network"),
                Finding.Pass("p1", "d", "Network")));

        Assert.Equal(2, _svc.Assess(report).CriticalFindings);
    }

    [Fact]
    public void WarningFindings_CountedCorrectly()
    {
        var report = CreateReport(
            MakeResult("DNS",
                Finding.Warning("w1", "d", "DNS"),
                Finding.Warning("w2", "d", "DNS"),
                Finding.Warning("w3", "d", "DNS"),
                Finding.Pass("p1", "d", "DNS")));

        Assert.Equal(3, _svc.Assess(report).WarningFindings);
    }

    // ─── Idempotency ─────────────────────────────────────────────

    [Fact]
    public void Assess_IsIdempotent()
    {
        var report = CreateReport(
            MakeResult("Firewall",
                Finding.Pass("p1", "d", "Firewall"),
                Finding.Warning("w1", "d", "Firewall")),
            MakeResult("Accounts",
                Finding.Critical("c1", "d", "Accounts")));

        var r1 = _svc.Assess(report);
        var r2 = _svc.Assess(report);

        Assert.Equal(r1.Grade, r2.Grade);
        Assert.Equal(r1.OverallScore, r2.OverallScore);
        Assert.Equal(r1.TotalFindings, r2.TotalFindings);
        Assert.Equal(r1.CriticalFindings, r2.CriticalFindings);
        Assert.Equal(r1.Domains.Count, r2.Domains.Count);
    }

    // ─── Edge Cases ──────────────────────────────────────────────

    [Fact]
    public void Assess_SingleFinding_Works()
    {
        var report = CreateReport(MakeResult("DNS",
            Finding.Pass("Solo", "d", "DNS")));

        var result = _svc.Assess(report);

        Assert.Equal(1, result.TotalFindings);
        // 1 domain Optimizing(5) + 6 domains Initial(1) → avg ≈ 1.6 → Repeatable → "D"
        Assert.Equal("D", result.Grade);
    }

    [Fact]
    public void Assess_LargeReport_NoException()
    {
        var findings = Enumerable.Range(1, 100)
            .Select(i => (i % 4) switch
            {
                0 => Finding.Pass($"p{i}", "d", "Firewall"),
                1 => Finding.Info($"i{i}", "d", "Firewall"),
                2 => Finding.Warning($"w{i}", "d", "Firewall"),
                _ => Finding.Critical($"c{i}", "d", "Firewall"),
            })
            .ToArray();

        var report = CreateReport(MakeResult("Firewall", findings));
        var result = _svc.Assess(report);

        Assert.Equal(100, result.TotalFindings);
        Assert.Equal(7, result.Domains.Count);
    }

    [Fact]
    public void Assess_DomainsWithoutFindings_StayInitial()
    {
        // Only one domain gets findings; other 6 should remain Initial
        var report = CreateReport(MakeResult("DNS",
            Finding.Pass("p", "d", "DNS")));

        var result = _svc.Assess(report);
        var emptyDomains = result.Domains.Where(d => d.Name != "Network Security");

        foreach (var d in emptyDomains)
        {
            Assert.Equal(MaturityLevel.Initial, d.Level);
            Assert.Equal(0, d.Score);
            Assert.Equal(0, d.MaxScore);
        }
    }
}