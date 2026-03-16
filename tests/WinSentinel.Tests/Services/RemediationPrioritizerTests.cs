using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class RemediationPrioritizerTests
{
    private static SecurityReport CreateTestReport(params Finding[] findings)
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            SecurityScore = 50,
        };
        report.Results.Add(new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            Findings = findings.ToList(),
        });
        return report;
    }

    private static Finding MakeFinding(Severity sev, string category, string title = "Test",
        string? fixCommand = null, string? remediation = null, int ageDays = 0)
    {
        return new Finding
        {
            Title = title,
            Description = $"Description for {title}",
            Severity = sev,
            Category = category,
            FixCommand = fixCommand,
            Remediation = remediation,
            Timestamp = DateTimeOffset.UtcNow.AddDays(-ageDays),
        };
    }

    [Fact]
    public void Prioritize_EmptyReport_ReturnsEmptyRankings()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport();

        var result = prioritizer.Prioritize(report);

        Assert.Empty(result.Rankings);
        Assert.Equal(0, result.TotalFindings);
    }

    [Fact]
    public void Prioritize_SkipsPassFindings()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Pass, "Firewall", "Pass finding"),
            MakeFinding(Severity.Warning, "Firewall", "Warning finding"));

        var result = prioritizer.Prioritize(report);

        Assert.Single(result.Rankings);
        Assert.Equal("Warning finding", result.Rankings[0].Finding.Title);
    }

    [Fact]
    public void Prioritize_CriticalRanksHigherThanWarning()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Warning, "Firewall", "Warning"),
            MakeFinding(Severity.Critical, "Firewall", "Critical"));

        var result = prioritizer.Prioritize(report);

        Assert.Equal("Critical", result.Rankings[0].Finding.Title);
        Assert.Equal("Warning", result.Rankings[1].Finding.Title);
    }

    [Fact]
    public void Prioritize_AssignsRanks()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Info, "DNS", "Info1"),
            MakeFinding(Severity.Warning, "DNS", "Warn1"),
            MakeFinding(Severity.Critical, "DNS", "Crit1"));

        var result = prioritizer.Prioritize(report);

        Assert.Equal(1, result.Rankings[0].Rank);
        Assert.Equal(2, result.Rankings[1].Rank);
        Assert.Equal(3, result.Rankings[2].Rank);
    }

    [Fact]
    public void Prioritize_TopLimitsResults()
    {
        var prioritizer = new RemediationPrioritizer();
        var findings = Enumerable.Range(0, 10)
            .Select(i => MakeFinding(Severity.Warning, "Firewall", $"Finding {i}"))
            .ToArray();
        var report = CreateTestReport(findings);

        var result = prioritizer.Prioritize(report, top: 3);

        Assert.Equal(3, result.Rankings.Count);
        Assert.Equal(10, result.TotalFindings);
    }

    [Fact]
    public void Prioritize_MinSeverityFilters()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Info, "DNS", "Info"),
            MakeFinding(Severity.Warning, "DNS", "Warning"),
            MakeFinding(Severity.Critical, "DNS", "Critical"));

        var result = prioritizer.Prioritize(report, minSeverity: Severity.Warning);

        Assert.Equal(2, result.TotalFindings);
        Assert.DoesNotContain(result.Rankings, r => r.Finding.Severity == Severity.Info);
    }

    [Fact]
    public void ScoreFinding_AutoFixIsQuickWin()
    {
        var prioritizer = new RemediationPrioritizer();
        var finding = MakeFinding(Severity.Warning, "Firewall", "Fix me",
            fixCommand: "Set-NetFirewallProfile -Enabled True");

        var scored = prioritizer.ScoreFinding(finding);

        Assert.Equal(RemediationPrioritizer.EffortLevel.Trivial, scored.Effort);
        Assert.True(scored.IsQuickWin);
    }

    [Fact]
    public void ScoreFinding_CriticalFirewallIsImmediate()
    {
        var prioritizer = new RemediationPrioritizer();
        var finding = MakeFinding(Severity.Critical, "Firewall", "Firewall disabled");

        var scored = prioritizer.ScoreFinding(finding);

        Assert.Equal(RemediationPrioritizer.PriorityTier.Immediate, scored.Tier);
        Assert.True(scored.PriorityScore >= 80);
    }

    [Fact]
    public void ScoreFinding_InfoLowBlastIsBacklogOrPlanned()
    {
        var prioritizer = new RemediationPrioritizer();
        var finding = MakeFinding(Severity.Info, "EventLog", "Event log not full");

        var scored = prioritizer.ScoreFinding(finding);

        Assert.True(scored.Tier is RemediationPrioritizer.PriorityTier.Backlog
                                or RemediationPrioritizer.PriorityTier.Planned);
    }

    [Fact]
    public void ScoreFinding_BreakdownComponentsPopulated()
    {
        var prioritizer = new RemediationPrioritizer();
        var finding = MakeFinding(Severity.Warning, "Network", "Open port");

        var scored = prioritizer.ScoreFinding(finding);

        Assert.True(scored.Breakdown.SeverityScore > 0);
        Assert.True(scored.Breakdown.ExploitabilityScore > 0);
        Assert.True(scored.Breakdown.BlastRadiusScore > 0);
    }

    [Fact]
    public void Prioritize_TierSummaryPopulated()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Critical, "Firewall", "Crit"),
            MakeFinding(Severity.Info, "EventLog", "Info"));

        var result = prioritizer.Prioritize(report);

        Assert.True(result.TierSummary.Values.Sum() == 2);
    }

    [Fact]
    public void Prioritize_CategoryBreakdownPopulated()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Warning, "Firewall", "F1"),
            MakeFinding(Severity.Warning, "Firewall", "F2"),
            MakeFinding(Severity.Warning, "DNS", "D1"));

        var result = prioritizer.Prioritize(report);

        Assert.Equal(2, result.CategoryBreakdown.Count);
        Assert.Equal(2, result.CategoryBreakdown["Firewall"].Count);
        Assert.Equal(1, result.CategoryBreakdown["DNS"].Count);
    }

    [Fact]
    public void Prioritize_EffortSummaryPopulated()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Warning, "Firewall", "F1", fixCommand: "fix"),
            MakeFinding(Severity.Warning, "Encryption", "E1"));

        var result = prioritizer.Prioritize(report);

        Assert.True(result.EffortSummary.Values.Sum() == 2);
    }

    [Fact]
    public void Prioritize_QuickWinsIdentified()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Warning, "Firewall", "Easy fix", fixCommand: "Fix-It"),
            MakeFinding(Severity.Warning, "Encryption", "Hard fix"));

        var result = prioritizer.Prioritize(report);

        Assert.True(result.QuickWinCount >= 1);
        Assert.Contains(result.QuickWins, qw => qw.Finding.Title == "Easy fix");
    }

    [Fact]
    public void Prioritize_TotalEffortEstimateNotEmpty()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Warning, "Firewall", "F1"));

        var result = prioritizer.Prioritize(report);

        Assert.False(string.IsNullOrEmpty(result.TotalEffortEstimate));
    }

    [Fact]
    public void SeverityFirstWeights_BoostsCritical()
    {
        var balanced = new RemediationPrioritizer(RemediationPrioritizer.PriorityWeights.Balanced);
        var sevFirst = new RemediationPrioritizer(RemediationPrioritizer.PriorityWeights.SeverityFirst);

        var critFinding = MakeFinding(Severity.Critical, "EventLog", "Critical log issue");
        var balancedScore = balanced.ScoreFinding(critFinding).PriorityScore;
        var sevFirstScore = sevFirst.ScoreFinding(critFinding).PriorityScore;

        Assert.True(sevFirstScore >= balancedScore);
    }

    [Fact]
    public void QuickWinWeights_BoostsAutoFix()
    {
        var balanced = new RemediationPrioritizer(RemediationPrioritizer.PriorityWeights.Balanced);
        var quickWin = new RemediationPrioritizer(RemediationPrioritizer.PriorityWeights.QuickWin);

        var finding = MakeFinding(Severity.Info, "Privacy", "Easy fix", fixCommand: "Fix-Privacy");
        var balancedScore = balanced.ScoreFinding(finding).PriorityScore;
        var quickWinScore = quickWin.ScoreFinding(finding).PriorityScore;

        Assert.True(quickWinScore >= balancedScore);
    }

    [Fact]
    public void GenerateTextReport_ProducesOutput()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Critical, "Firewall", "Firewall disabled"),
            MakeFinding(Severity.Warning, "DNS", "DNS issue"));

        var text = prioritizer.GenerateTextReport(report);

        Assert.Contains("Remediation Priority Queue", text);
        Assert.Contains("Firewall disabled", text);
        Assert.Contains("DNS issue", text);
    }

    [Fact]
    public void GenerateJsonReport_ValidJson()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Warning, "Accounts", "Weak password"));

        var json = prioritizer.GenerateJsonReport(report);

        Assert.Contains("Weak password", json);
        Assert.Contains("PriorityScore", json);
        // Should be valid JSON
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotNull(doc);
    }

    [Fact]
    public void GenerateCsvReport_HasHeaderAndRows()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(
            MakeFinding(Severity.Warning, "Browser", "Cookie issue"),
            MakeFinding(Severity.Critical, "Network", "Open port"));

        var csv = prioritizer.GenerateCsvReport(report);

        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length >= 3); // header + 2 rows
        Assert.Contains("Rank,Title,Category", lines[0]);
    }

    [Fact]
    public void ScoreFinding_OlderFindingsScoreHigher()
    {
        var prioritizer = new RemediationPrioritizer();
        var newFinding = MakeFinding(Severity.Warning, "Firewall", "New", ageDays: 0);
        var oldFinding = MakeFinding(Severity.Warning, "Firewall", "Old", ageDays: 100);

        var newScore = prioritizer.ScoreFinding(newFinding).PriorityScore;
        var oldScore = prioritizer.ScoreFinding(oldFinding).PriorityScore;

        Assert.True(oldScore >= newScore);
    }

    [Fact]
    public void ScoreFinding_RemediationGuidanceBoostsScore()
    {
        var prioritizer = new RemediationPrioritizer();
        var noGuide = MakeFinding(Severity.Warning, "DNS", "No guide");
        var withGuide = MakeFinding(Severity.Warning, "DNS", "With guide", remediation: "Do this to fix");

        var noScore = prioritizer.ScoreFinding(noGuide).PriorityScore;
        var guideScore = prioritizer.ScoreFinding(withGuide).PriorityScore;

        Assert.True(guideScore >= noScore);
    }

    [Fact]
    public void ScoreFinding_UnknownCategoryGetsDefaultScores()
    {
        var prioritizer = new RemediationPrioritizer();
        var finding = MakeFinding(Severity.Warning, "UnknownModule", "Unknown");

        var scored = prioritizer.ScoreFinding(finding);

        Assert.True(scored.PriorityScore > 0);
        Assert.Equal(50, scored.Breakdown.ExploitabilityScore);
        Assert.Equal(50, scored.Breakdown.BlastRadiusScore);
    }

    [Fact]
    public void PrioritizeFindings_DirectListInput()
    {
        var prioritizer = new RemediationPrioritizer();
        var findings = new List<Finding>
        {
            MakeFinding(Severity.Critical, "Network", "Crit"),
            MakeFinding(Severity.Info, "Privacy", "Info"),
        };

        var result = prioritizer.PrioritizeFindings(findings);

        Assert.Equal(2, result.TotalFindings);
        Assert.Equal("Crit", result.Rankings[0].Finding.Title);
    }

    [Fact]
    public void ScoreFinding_ScoreClampedTo100()
    {
        var prioritizer = new RemediationPrioritizer();
        // Critical + high exploit category + old + auto-fix should not exceed 100
        var finding = MakeFinding(Severity.Critical, "RemoteAccess", "Max",
            fixCommand: "fix", ageDays: 100);

        var scored = prioritizer.ScoreFinding(finding);

        Assert.True(scored.PriorityScore <= 100);
        Assert.True(scored.PriorityScore >= 0);
    }

    [Fact]
    public void TimeframeLabel_MatchesTier()
    {
        var prioritizer = new RemediationPrioritizer();
        var finding = MakeFinding(Severity.Critical, "Firewall", "Urgent");
        var scored = prioritizer.ScoreFinding(finding);

        Assert.Equal(RemediationPrioritizer.PriorityTier.Immediate, scored.Tier);
        Assert.Equal("Fix now", scored.TimeframeLabel);
    }

    [Fact]
    public void EffortLabel_MatchesEffort()
    {
        var prioritizer = new RemediationPrioritizer();
        var finding = MakeFinding(Severity.Warning, "Firewall", "Easy", fixCommand: "fix");
        var scored = prioritizer.ScoreFinding(finding);

        Assert.Equal(RemediationPrioritizer.EffortLevel.Trivial, scored.Effort);
        Assert.Contains("auto-fix", scored.EffortLabel);
    }

    [Fact]
    public void FormatTextReport_StaticMethod()
    {
        var prioritizer = new RemediationPrioritizer();
        var report = CreateTestReport(MakeFinding(Severity.Warning, "DNS", "Test"));
        var prioReport = prioritizer.Prioritize(report);

        var text = RemediationPrioritizer.FormatTextReport(prioReport);

        Assert.Contains("Remediation Priority Queue", text);
    }
}
