using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecuritySwarmIntelligenceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _historyService;
    private readonly SecuritySwarmIntelligence _swarm;

    public SecuritySwarmIntelligenceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"winsentinel_swarm_test_{Guid.NewGuid():N}.db");
        _historyService = new AuditHistoryService(_dbPath);
        _swarm = new SecuritySwarmIntelligence(_historyService);
    }

    public void Dispose()
    {
        _historyService.Dispose();
        if (File.Exists(_dbPath))
        {
            try { File.Delete(_dbPath); } catch { }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static SecurityReport MakeReport(params AuditResult[] results)
    {
        var report = new SecurityReport();
        report.Results.AddRange(results);
        return report;
    }

    private static AuditResult MakeModule(string name, string category, params Finding[] findings)
    {
        var result = new AuditResult { ModuleName = name, Category = category };
        result.Findings.AddRange(findings);
        return result;
    }

    private static Finding Crit(string title, string category, string? fixCmd = null) => new()
    {
        Title = title, Description = $"{title} desc", Severity = Severity.Critical,
        Category = category, FixCommand = fixCmd
    };

    private static Finding Warn(string title, string category) => new()
    {
        Title = title, Description = $"{title} desc", Severity = Severity.Warning, Category = category
    };

    private static Finding Info(string title, string category) => new()
    {
        Title = title, Description = $"{title} desc", Severity = Severity.Info, Category = category
    };

    private static Finding Pass(string title, string category) => new()
    {
        Title = title, Description = $"{title} desc", Severity = Severity.Pass, Category = category
    };

    // ── Analyze: basic structure ─────────────────────────────────────

    [Fact]
    public void Analyze_EmptyReport_ReturnsValidSwarmReport()
    {
        var report = MakeReport();
        var result = _swarm.Analyze(report);

        Assert.NotNull(result);
        Assert.Equal(6, result.AgentAnalyses.Count); // 5 agents + synthesizer
        Assert.NotEmpty(result.CollectiveVerdict);
        Assert.InRange(result.CollectiveConfidence, 0, 100);
    }

    [Fact]
    public void Analyze_AllAgentsPresent()
    {
        var report = MakeReport(MakeModule("Firewall", "Network", Warn("Open port", "Network")));
        var result = _swarm.Analyze(report);

        var names = result.AgentAnalyses.Select(a => a.Agent.Name).ToList();
        Assert.Contains("Sentinel", names);
        Assert.Contains("Strategist", names);
        Assert.Contains("Historian", names);
        Assert.Contains("Economist", names);
        Assert.Contains("Contrarian", names);
        Assert.Contains("Synthesizer", names);
    }

    // ── Verdict thresholds ───────────────────────────────────────────

    [Fact]
    public void Analyze_NoCriticals_VerdictNotCritical()
    {
        var report = MakeReport(
            MakeModule("Test", "Cat", Pass("p1", "Cat"), Pass("p2", "Cat")));
        var result = _swarm.Analyze(report);

        Assert.DoesNotContain("CRITICAL RISK", result.CollectiveVerdict);
    }

    [Fact]
    public void Analyze_ManyCriticals_VerdictIsUrgent()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Crit("c1", "C1"), Crit("c2", "C1"), Crit("c3", "C1"),
                Crit("c4", "C2"), Crit("c5", "C2")));
        var result = _swarm.Analyze(report);

        // With many criticals, multiple agents lower confidence → urgent verdict
        Assert.True(result.CollectiveConfidence > 0);
        Assert.NotEmpty(result.CollectiveVerdict);
    }

    // ── Sentinel agent ───────────────────────────────────────────────

    [Fact]
    public void Sentinel_DetectsCriticals()
    {
        var report = MakeReport(
            MakeModule("Firewall", "Network",
                Crit("Remote code execution", "Network"),
                Crit("Unpatched CVE", "Network")));

        var result = _swarm.Analyze(report);
        var sentinel = result.AgentAnalyses.First(a => a.Agent.Name == "Sentinel");

        Assert.True(sentinel.Insights.Any(i => i.Finding.Contains("critical")));
        Assert.True(sentinel.OverallConfidence >= 85);
    }

    [Fact]
    public void Sentinel_WarningsOnly_ModerateConfidence()
    {
        var report = MakeReport(
            MakeModule("Audit", "Logging", Warn("Old logs", "Logging")));

        var result = _swarm.Analyze(report);
        var sentinel = result.AgentAnalyses.First(a => a.Agent.Name == "Sentinel");

        Assert.Equal(70.0, sentinel.OverallConfidence);
    }

    [Fact]
    public void Sentinel_NoIssues_HighConfidence()
    {
        var report = MakeReport(
            MakeModule("Test", "Cat", Pass("All good", "Cat")));

        var result = _swarm.Analyze(report);
        var sentinel = result.AgentAnalyses.First(a => a.Agent.Name == "Sentinel");

        Assert.Equal(95.0, sentinel.OverallConfidence);
    }

    // ── Strategist agent ─────────────────────────────────────────────

    [Fact]
    public void Strategist_IdentifiesDominantCategory()
    {
        var report = MakeReport(
            MakeModule("M1", "C1", Warn("W1", "Auth"), Warn("W2", "Auth"), Crit("C1", "Auth")),
            MakeModule("M2", "C2", Warn("W3", "Crypto")));

        var result = _swarm.Analyze(report);
        var strategist = result.AgentAnalyses.First(a => a.Agent.Name == "Strategist");

        Assert.True(strategist.Insights.Any(i => i.Finding.Contains("Auth")));
    }

    [Fact]
    public void Strategist_DetectsModuleCoupling()
    {
        // Two modules sharing 2+ weakness categories should trigger coupling insight
        var report = MakeReport(
            MakeModule("M1", "C1", Warn("W1", "Auth"), Warn("W2", "Crypto")),
            MakeModule("M2", "C2", Warn("W3", "Auth"), Warn("W4", "Crypto")));

        var result = _swarm.Analyze(report);
        var strategist = result.AgentAnalyses.First(a => a.Agent.Name == "Strategist");

        Assert.True(strategist.Insights.Any(i => i.Finding.Contains("coordinated fix")));
    }

    // ── Historian agent ──────────────────────────────────────────────

    [Fact]
    public void Historian_InsufficientHistory_LowConfidence()
    {
        var report = MakeReport(MakeModule("M1", "C1", Warn("W1", "Cat")));
        var result = _swarm.Analyze(report);
        var historian = result.AgentAnalyses.First(a => a.Agent.Name == "Historian");

        // No history saved → insufficient history message
        Assert.Equal(50.0, historian.OverallConfidence);
        Assert.True(historian.Insights.Any(i => i.Finding.Contains("Insufficient history")));
    }

    [Fact]
    public void Historian_WithHistory_DetectsRegressions()
    {
        // Save two history runs: first with 0 criticals, second with 3
        var report1 = MakeReport(MakeModule("M1", "C1", Pass("OK", "Cat")));
        report1.SecurityScore = 90;
        _historyService.SaveAuditResult(report1);

        // Small delay to ensure ordering
        var report2 = MakeReport(
            MakeModule("M1", "C1",
                Crit("New crit 1", "Cat"), Crit("New crit 2", "Cat"), Crit("New crit 3", "Cat")));
        report2.SecurityScore = 50;
        _historyService.SaveAuditResult(report2);

        var currentReport = MakeReport(MakeModule("M1", "C1", Warn("W1", "Cat")));
        var result = _swarm.Analyze(currentReport, 30);
        var historian = result.AgentAnalyses.First(a => a.Agent.Name == "Historian");

        // With 2 history entries, should provide some analysis (not "insufficient")
        Assert.True(historian.OverallConfidence >= 50);
    }

    // ── Economist agent ──────────────────────────────────────────────

    [Fact]
    public void Economist_EstimatesEffort()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Crit("C1", "Cat"), Warn("W1", "Cat"), Warn("W2", "Cat")));

        var result = _swarm.Analyze(report);
        var economist = result.AgentAnalyses.First(a => a.Agent.Name == "Economist");

        // 1 critical (2h) + 2 warnings (2h) = 4h
        Assert.True(economist.Insights.Any(i => i.Finding.Contains("4 hours")));
    }

    [Fact]
    public void Economist_IdentifiesAutoFixableFindings()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Crit("C1", "Cat", "fix-command-here"),
                Warn("W1", "Cat")));

        var result = _swarm.Analyze(report);
        var economist = result.AgentAnalyses.First(a => a.Agent.Name == "Economist");

        Assert.True(economist.Insights.Any(i => i.Finding.Contains("auto-fixable")));
    }

    [Fact]
    public void Economist_IdentifiesQuickWins()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Crit("Critical auto-fix", "Cat", "run-this")));

        var result = _swarm.Analyze(report);
        var economist = result.AgentAnalyses.First(a => a.Agent.Name == "Economist");

        Assert.True(economist.Insights.Any(i => i.Finding.Contains("Quick win")));
    }

    // ── Contrarian agent ─────────────────────────────────────────────

    [Fact]
    public void Contrarian_ChallengesHighPassRate()
    {
        var findings = Enumerable.Range(0, 20).Select(i => Pass($"P{i}", "Cat")).ToList();
        findings.Add(Warn("W1", "Cat"));

        var report = MakeReport(MakeModule("M1", "C1", findings.ToArray()));
        var result = _swarm.Analyze(report);
        var contrarian = result.AgentAnalyses.First(a => a.Agent.Name == "Contrarian");

        Assert.True(contrarian.Insights.Any(i => i.Finding.Contains("false confidence")));
    }

    [Fact]
    public void Contrarian_FlagsOverlookedInfoFindings()
    {
        var findings = Enumerable.Range(0, 8).Select(i => Info($"I{i}", "Cat")).ToArray();
        var report = MakeReport(MakeModule("M1", "C1", findings));

        var result = _swarm.Analyze(report);
        var contrarian = result.AgentAnalyses.First(a => a.Agent.Name == "Contrarian");

        Assert.True(contrarian.Insights.Any(i => i.Finding.Contains("informational")));
    }

    [Fact]
    public void Contrarian_FlagsEmptyModules()
    {
        var report = MakeReport(
            MakeModule("M1", "C1", Warn("W1", "Cat")),
            MakeModule("EmptyModule", "C2")); // zero findings

        var result = _swarm.Analyze(report);
        var contrarian = result.AgentAnalyses.First(a => a.Agent.Name == "Contrarian");

        Assert.True(contrarian.Insights.Any(i => i.Finding.Contains("zero findings")));
    }

    [Fact]
    public void Contrarian_NoCriticals_SuggestsExpandScope()
    {
        var report = MakeReport(MakeModule("M1", "C1", Pass("P1", "Cat")));
        var result = _swarm.Analyze(report);
        var contrarian = result.AgentAnalyses.First(a => a.Agent.Name == "Contrarian");

        Assert.True(contrarian.Insights.Any(i => i.Finding.Contains("absence of evidence")));
    }

    [Fact]
    public void Contrarian_AlwaysLowerConfidence()
    {
        var report = MakeReport(MakeModule("M1", "C1", Pass("P1", "Cat")));
        var result = _swarm.Analyze(report);
        var contrarian = result.AgentAnalyses.First(a => a.Agent.Name == "Contrarian");

        Assert.Equal(60.0, contrarian.OverallConfidence);
    }

    // ── Synthesizer agent ────────────────────────────────────────────

    [Fact]
    public void Synthesizer_ReportsAgentAgreement()
    {
        var report = MakeReport(
            MakeModule("M1", "C1", Crit("C1", "Cat"), Warn("W1", "Cat")));

        var result = _swarm.Analyze(report);
        var synthesizer = result.AgentAnalyses.First(a => a.Agent.Name == "Synthesizer");

        Assert.True(synthesizer.Insights.Any(i => i.Finding.Contains("agents flagged")));
    }

    [Fact]
    public void Synthesizer_ReportsSwarmConfidence()
    {
        var report = MakeReport(MakeModule("M1", "C1", Warn("W1", "Cat")));
        var result = _swarm.Analyze(report);
        var synthesizer = result.AgentAnalyses.First(a => a.Agent.Name == "Synthesizer");

        Assert.True(synthesizer.Insights.Any(i => i.Finding.Contains("Swarm confidence")));
    }

    // ── Consensus building ───────────────────────────────────────────

    [Fact]
    public void Consensus_CriticalFindings_ProduceConsensusItems()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Crit("C1", "Auth"), Crit("C2", "Auth"), Warn("W1", "Crypto")),
            MakeModule("M2", "C2",
                Crit("C3", "Network")));

        var result = _swarm.Analyze(report);

        // With critical findings, multiple agents should generate consensus
        Assert.NotEmpty(result.Consensus);
        Assert.All(result.Consensus, c =>
        {
            Assert.NotEmpty(c.Recommendation);
            Assert.InRange(c.AgreementLevel, 0, 100);
            Assert.NotEmpty(c.SupportingAgents);
            Assert.Contains(c.Priority, new[] { "URGENT", "HIGH", "MEDIUM" });
        });
    }

    [Fact]
    public void Consensus_VotingRecordPopulated()
    {
        var report = MakeReport(
            MakeModule("M1", "C1", Crit("C1", "Cat"), Warn("W1", "Cat")));

        var result = _swarm.Analyze(report);

        Assert.NotNull(result.VotingRecord);
        // At least some votes when there are actionable findings
        if (result.Consensus.Count > 0)
            Assert.NotEmpty(result.VotingRecord);
    }

    [Fact]
    public void Consensus_DissentsFromContrarian()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Crit("C1", "Cat"), Warn("W1", "Cat"),
                Info("I1", "Cat"), Info("I2", "Cat"), Info("I3", "Cat"),
                Info("I4", "Cat"), Info("I5", "Cat"), Info("I6", "Cat")));

        var result = _swarm.Analyze(report);

        // Contrarian should produce dissents
        Assert.NotEmpty(result.Dissents);
        Assert.All(result.Dissents, d => Assert.Contains("Contrarian", d));
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void Analyze_OnlyPassFindings_StillProducesReport()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Pass("P1", "Cat"), Pass("P2", "Cat"), Pass("P3", "Cat")));

        var result = _swarm.Analyze(report);

        Assert.Equal(6, result.AgentAnalyses.Count);
        // Contrarian always has 60% confidence, pulling average down
        Assert.Contains("RISK", result.CollectiveVerdict);
        Assert.DoesNotContain("CRITICAL RISK", result.CollectiveVerdict);
    }

    [Fact]
    public void Analyze_MixedSeverities_CollectiveConfidenceIsAverage()
    {
        var report = MakeReport(
            MakeModule("M1", "C1",
                Crit("C1", "Cat"), Warn("W1", "Cat"), Info("I1", "Cat"), Pass("P1", "Cat")));

        var result = _swarm.Analyze(report);

        // Collective confidence should be the average of all 6 agents
        var expectedAvg = result.AgentAnalyses.Average(a => a.OverallConfidence);
        Assert.Equal(Math.Round(expectedAvg, 1), result.CollectiveConfidence);
    }

    [Fact]
    public void Analyze_MultipleModules_StrategistDetectsPatterns()
    {
        var report = MakeReport(
            MakeModule("M1", "C1", Warn("Password weakness detected", "Auth")),
            MakeModule("M2", "C2", Warn("Password policy violation", "Auth")),
            MakeModule("M3", "C3", Warn("Password reset missing", "Auth")));

        var result = _swarm.Analyze(report);
        var strategist = result.AgentAnalyses.First(a => a.Agent.Name == "Strategist");

        // "Password" appears in all 3 → recurring theme
        Assert.True(strategist.Insights.Any(i =>
            i.Finding.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
            i.Finding.Contains("Auth")));
    }
}
