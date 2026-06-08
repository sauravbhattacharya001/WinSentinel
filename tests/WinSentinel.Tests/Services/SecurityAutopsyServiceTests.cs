using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityAutopsyServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;
    private readonly SecurityAutopsyService _svc;

    public SecurityAutopsyServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"winsentinel_autopsy_test_{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _svc = new SecurityAutopsyService(_history);
    }

    public void Dispose()
    {
        _history.Dispose();
        if (File.Exists(_dbPath)) { try { File.Delete(_dbPath); } catch { } }
    }

    private SecurityReport MakeReport(DateTimeOffset ts, int score, params (string m, string t, string s)[] f)
    {
        var r = new SecurityReport { GeneratedAt = ts, SecurityScore = score };
        foreach (var grp in f.GroupBy(x => x.m))
        {
            var list = grp.Select(x => x.s switch
            {
                "Critical" => Finding.Critical(x.t, x.t + " desc", x.m),
                "Warning" => Finding.Warning(x.t, x.t + " desc", x.m, "Fix"),
                "Info" => Finding.Info(x.t, x.t + " desc", x.m),
                _ => Finding.Pass(x.t, x.t + " desc", x.m)
            }).ToList();
            r.Results.Add(new AuditResult { ModuleName = grp.Key, Category = grp.Key, Findings = list, Success = true, StartTime = ts.AddSeconds(-5), EndTime = ts });
        }
        return r;
    }

    private void Seed(params (DateTimeOffset ts, int score, (string m, string t, string s)[] f)[] runs)
    {
        foreach (var (ts, score, f) in runs) _history.SaveAuditResult(MakeReport(ts, score, f));
    }

    private DateTimeOffset Ago(int d) => DateTimeOffset.UtcNow.AddDays(-d);

    // ── Empty/minimal ───────────────────────────────────────────────

    [Fact]
    public void NoHistory_EmptyReport()
    {
        var result = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 85));
        Assert.Empty(result.Degradations);
        Assert.Empty(result.RootCauses);
        Assert.Empty(result.Timeline);
        Assert.Empty(result.Lessons);
        Assert.NotNull(result.Summary);
    }

    [Fact]
    public void SingleRun_NoDegradations()
    {
        Seed((Ago(5), 80, new[] { ("Net", "Port 445", "Warning") }));
        var result = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 80));
        Assert.Empty(result.Degradations);
    }

    [Fact]
    public void StableScores_NoDegradations()
    {
        Seed((Ago(10), 80, new[] { ("Net", "A", "Warning") }), (Ago(5), 80, new[] { ("Net", "A", "Warning") }));
        Assert.Empty(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 80)).Degradations);
    }

    // ── Degradation Detection ───────────────────────────────────────

    [Fact]
    public void ScoreDropGt5_Detected()
    {
        Seed((Ago(10), 85, Array.Empty<(string, string, string)>()), (Ago(5), 78, Array.Empty<(string, string, string)>()));
        var result = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 78));
        Assert.Contains(result.Degradations, d => d.Type == "Score Drop");
    }

    [Fact]
    public void ScoreDrop5OrLess_NotDetected()
    {
        Seed((Ago(10), 85, Array.Empty<(string, string, string)>()), (Ago(5), 81, Array.Empty<(string, string, string)>()));
        Assert.DoesNotContain(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 81)).Degradations, d => d.Type == "Score Drop");
    }

    [Fact]
    public void LargeDrop_Severity1()
    {
        Seed((Ago(10), 90, Array.Empty<(string, string, string)>()), (Ago(5), 60, Array.Empty<(string, string, string)>()));
        var drop = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 60)).Degradations.First(d => d.Type == "Score Drop");
        Assert.Equal(1, drop.Severity);
    }

    [Fact]
    public void MediumDrop_Severity2()
    {
        Seed((Ago(10), 80, Array.Empty<(string, string, string)>()), (Ago(5), 65, Array.Empty<(string, string, string)>()));
        var drop = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 65)).Degradations.First(d => d.Type == "Score Drop");
        Assert.Equal(2, drop.Severity);
    }

    [Fact]
    public void SmallDrop_Severity3()
    {
        Seed((Ago(10), 80, Array.Empty<(string, string, string)>()), (Ago(5), 73, Array.Empty<(string, string, string)>()));
        var drop = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 73)).Degradations.First(d => d.Type == "Score Drop");
        Assert.Equal(3, drop.Severity);
    }

    [Fact]
    public void CriticalSpike_Detected()
    {
        Seed(
            (Ago(10), 70, new[] { ("Def", "AV off", "Critical") }),
            (Ago(5), 50, new[] { ("Def", "AV off", "Critical"), ("Net", "RDP", "Critical"), ("Net", "SMB", "Critical"), ("FW", "Disabled", "Critical") })
        );
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50)).Degradations, d => d.Type == "Critical Spike" && d.Severity == 1);
    }

    [Fact]
    public void CriticalPlusOne_NoSpike()
    {
        Seed(
            (Ago(10), 70, new[] { ("Def", "AV off", "Critical") }),
            (Ago(5), 65, new[] { ("Def", "AV off", "Critical"), ("Net", "RDP", "Critical") })
        );
        Assert.DoesNotContain(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 65)).Degradations, d => d.Type == "Critical Spike");
    }

    [Fact]
    public void ModuleDropGt10_ModuleFailure()
    {
        var before = Enumerable.Range(1, 10).Select(i => ("Net", $"P{i}", "Pass")).ToArray();
        var after = Enumerable.Range(1, 10).Select(i => ("Net", $"P{i}", i <= 3 ? "Critical" : "Warning")).ToArray();
        Seed((Ago(10), 80, before), (Ago(5), 60, after));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 60)).Degradations, d => d.Type == "Module Failure" && d.Module == "Net");
    }

    [Fact]
    public void ModuleFilter_OnlyFilteredModule()
    {
        var b1 = Enumerable.Range(1, 5).Select(i => ("Net", $"N{i}", "Pass")).ToArray();
        var b2 = Enumerable.Range(1, 5).Select(i => ("Def", $"D{i}", "Pass")).ToArray();
        var a1 = Enumerable.Range(1, 5).Select(i => ("Net", $"N{i}", "Critical")).ToArray();
        var a2 = Enumerable.Range(1, 5).Select(i => ("Def", $"D{i}", "Critical")).ToArray();
        Seed((Ago(10), 80, b1.Concat(b2).ToArray()), (Ago(5), 50, a1.Concat(a2).ToArray()));
        var mf = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50), moduleFilter: "Net").Degradations.Where(d => d.Type == "Module Failure");
        Assert.All(mf, d => Assert.Contains("Net", d.Module));
    }

    [Fact]
    public void DegradationEvent_CorrectScores()
    {
        Seed((Ago(10), 85, Array.Empty<(string, string, string)>()), (Ago(5), 70, Array.Empty<(string, string, string)>()));
        var drop = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Degradations.First(d => d.Type == "Score Drop");
        Assert.Equal(85, drop.ScoreBefore);
        Assert.Equal(70, drop.ScoreAfter);
    }

    [Fact]
    public void Degradations_Chronological()
    {
        Seed(
            (Ago(20), 90, Array.Empty<(string, string, string)>()),
            (Ago(15), 80, Array.Empty<(string, string, string)>()),
            (Ago(10), 70, Array.Empty<(string, string, string)>()),
            (Ago(5), 60, Array.Empty<(string, string, string)>())
        );
        var degs = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 60)).Degradations;
        for (int i = 0; i < degs.Count - 1; i++) Assert.True(degs[i].DetectedAt <= degs[i + 1].DetectedAt);
    }

    // ── Root Cause Inference ────────────────────────────────────────

    [Fact]
    public void RecurringFinding_InfersRecurringIssue()
    {
        var f = ("Net", "RDP exposed", "Critical");
        Seed((Ago(20), 80, new[] { f }), (Ago(15), 70, new[] { f }), (Ago(10), 70, new[] { f }), (Ago(5), 70, new[] { f }));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).RootCauses, r => r.Category == "Recurring Issue");
    }

    [Fact]
    public void ModuleRepeatedRegression_InfersRegression()
    {
        var good = Enumerable.Range(1, 5).Select(i => ("Net", $"P{i}", "Pass")).ToArray();
        var bad = Enumerable.Range(1, 5).Select(i => ("Net", $"P{i}", "Critical")).ToArray();
        Seed((Ago(30), 80, good), (Ago(25), 50, bad), (Ago(20), 80, good), (Ago(15), 50, bad));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50)).RootCauses, r => r.Category == "Module Regression");
    }

    [Fact]
    public void NewCriticalSurge_InfersVulnerability()
    {
        Seed(
            (Ago(10), 80, new[] { ("Net", "Old", "Warning") }),
            (Ago(5), 50, new[] { ("Net", "Old", "Warning"), ("Def", "AV off", "Critical"), ("FW", "Bypassed", "Critical"), ("Upd", "Missing", "Critical") })
        );
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50)).RootCauses, r => r.Category == "New Vulnerability");
    }

    [Fact]
    public void ConfigFindings_InfersConfigDrift()
    {
        Seed(
            (Ago(15), 85, new[] { ("Def", "Defender enabled check", "Pass") }),
            (Ago(10), 70, new[] {
                ("FW", "Firewall config changed", "Warning"),
                ("Upd", "Update policy disabled", "Warning"),
                ("Reg", "Permission setting wrong", "Critical"),
                ("Def", "Defender enabled check", "Pass")
            })
        );
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).RootCauses, r => r.Category == "Configuration Drift");
    }

    [Fact]
    public void RootCauses_OrderedByConfidence()
    {
        var f = ("Net", "RDP exposed", "Critical");
        Seed(
            (Ago(30), 70, new[] { f, ("FW", "Config drift policy", "Warning"), ("Reg", "Permission setting bad", "Warning"), ("Upd", "Update policy disabled", "Warning") }),
            (Ago(25), 70, new[] { f, ("FW", "Config drift policy", "Warning") }),
            (Ago(20), 70, new[] { f }), (Ago(15), 70, new[] { f })
        );
        var causes = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).RootCauses;
        if (causes.Count >= 2)
            for (int i = 0; i < causes.Count - 1; i++) Assert.True(causes[i].Confidence >= causes[i + 1].Confidence);
    }

    [Fact]
    public void RootCauses_MaxTen()
    {
        var findings = Enumerable.Range(1, 20).Select(i => ($"M{i}", $"Finding {i}", "Warning")).ToArray();
        Seed((Ago(30), 60, findings), (Ago(25), 60, findings), (Ago(20), 60, findings), (Ago(15), 60, findings), (Ago(10), 60, findings));
        Assert.True(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 60)).RootCauses.Count <= 10);
    }

    [Fact]
    public void NoDegradations_NoModuleRegressionCause()
    {
        Seed((Ago(10), 90, Array.Empty<(string, string, string)>()), (Ago(5), 95, Array.Empty<(string, string, string)>()));
        Assert.DoesNotContain(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 95)).RootCauses, r => r.Category == "Module Regression");
    }

    [Fact]
    public void RootCause_ConfidenceCapped()
    {
        var f = ("Net", "RDP exposed", "Critical");
        Seed((Ago(35), 70, new[] { f }), (Ago(30), 70, new[] { f }), (Ago(25), 70, new[] { f }), (Ago(20), 70, new[] { f }), (Ago(15), 70, new[] { f }), (Ago(10), 70, new[] { f }), (Ago(5), 70, new[] { f }));
        Assert.All(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).RootCauses, r => Assert.True(r.Confidence <= 0.95));
    }

    // ── Timeline ────────────────────────────────────────────────────

    [Fact]
    public void MultipleRuns_HasTimeline()
    {
        Seed((Ago(10), 85, new[] { ("Net", "A", "Warning") }), (Ago(5), 80, new[] { ("Net", "B", "Warning") }));
        var tl = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 80)).Timeline;
        Assert.NotEmpty(tl);
        Assert.Contains(tl, t => t.Event == "Audit Scan");
    }

    [Fact]
    public void GradeChange_InTimeline()
    {
        Seed((Ago(10), 90, Array.Empty<(string, string, string)>()), (Ago(5), 70, Array.Empty<(string, string, string)>()));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Timeline, t => t.Event == "Grade Change");
    }

    [Fact]
    public void NewFindings_InTimeline()
    {
        Seed((Ago(10), 80, new[] { ("Net", "A", "Warning") }), (Ago(5), 70, new[] { ("Net", "A", "Warning"), ("Def", "AV off", "Critical") }));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Timeline, t => t.Event == "New Critical");
    }

    [Fact]
    public void ResolvedFindings_InTimeline()
    {
        Seed((Ago(10), 70, new[] { ("Net", "A", "Warning"), ("Def", "AV off", "Critical") }), (Ago(5), 80, new[] { ("Net", "A", "Warning") }));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 80)).Timeline, t => t.Event == "Resolved");
    }

    [Fact]
    public void Timeline_Chronological()
    {
        Seed((Ago(20), 80, new[] { ("Net", "A", "Warning") }), (Ago(10), 75, new[] { ("Net", "B", "Warning") }), (Ago(5), 70, new[] { ("Def", "X", "Critical") }));
        var tl = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Timeline;
        for (int i = 0; i < tl.Count - 1; i++) Assert.True(tl[i].Timestamp <= tl[i + 1].Timestamp);
    }

    [Fact]
    public void TimelineModuleFilter_OnlyFiltered()
    {
        Seed((Ago(10), 80, new[] { ("Net", "A", "Warning"), ("Def", "B", "Pass") }), (Ago(5), 70, new[] { ("Net", "C", "Warning"), ("Def", "X", "Critical") }));
        var nonScan = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70), moduleFilter: "Net").Timeline.Where(t => t.Event != "Audit Scan" && t.Event != "Grade Change");
        Assert.All(nonScan, t => Assert.Contains("Net", t.Module));
    }

    // ── Lessons Learned ─────────────────────────────────────────────

    [Fact]
    public void PersistentFindings_Lesson()
    {
        var f = ("Net", "Same finding", "Warning");
        Seed((Ago(20), 70, new[] { f }), (Ago(15), 70, new[] { f }), (Ago(10), 70, new[] { f }), (Ago(5), 70, new[] { f }));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Lessons, l => l.Title.Contains("Persistent"));
    }

    [Fact]
    public void RecurringRegressions_Lesson()
    {
        var good = Enumerable.Range(1, 5).Select(i => ("Net", $"P{i}", "Pass")).ToArray();
        var bad = Enumerable.Range(1, 5).Select(i => ("Net", $"P{i}", "Critical")).ToArray();
        Seed((Ago(30), 80, good), (Ago(25), 50, bad), (Ago(20), 80, good), (Ago(15), 50, bad));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50)).Lessons, l => l.Title.Contains("Recurring") || l.Title.Contains("Regression"));
    }

    [Fact]
    public void CriticalDegradations_Lesson()
    {
        Seed((Ago(10), 90, Array.Empty<(string, string, string)>()), (Ago(5), 60, Array.Empty<(string, string, string)>()));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 60)).Lessons, l => l.Title.Contains("Critical Degradation"));
    }

    [Fact]
    public void HighVolatility_Lesson()
    {
        Seed((Ago(25), 90, Array.Empty<(string, string, string)>()), (Ago(20), 50, Array.Empty<(string, string, string)>()), (Ago(15), 85, Array.Empty<(string, string, string)>()), (Ago(10), 40, Array.Empty<(string, string, string)>()), (Ago(5), 80, Array.Empty<(string, string, string)>()));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 80)).Lessons, l => l.Title.Contains("Volatility"));
    }

    [Fact]
    public void StableImproving_Lesson()
    {
        Seed((Ago(15), 80, Array.Empty<(string, string, string)>()), (Ago(10), 82, Array.Empty<(string, string, string)>()), (Ago(5), 85, Array.Empty<(string, string, string)>()));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 85)).Lessons, l => l.Title.Contains("Stable") || l.Title.Contains("Improving"));
    }

    [Fact]
    public void Lessons_HavePriority()
    {
        var f = ("Net", "Persistent", "Warning");
        Seed((Ago(20), 70, new[] { f }), (Ago(15), 70, new[] { f }), (Ago(10), 70, new[] { f }), (Ago(5), 70, new[] { f }));
        Assert.All(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Lessons, l => Assert.Contains(l.Priority, new[] { "High", "Medium", "Low" }));
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void CriticalSpike_RecommendsAlerting()
    {
        Seed(
            (Ago(10), 70, new[] { ("Def", "AV off", "Critical") }),
            (Ago(5), 40, new[] { ("Def", "AV off", "Critical"), ("Net", "RDP", "Critical"), ("Net", "SMB", "Critical"), ("FW", "Dis", "Critical") })
        );
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 40)).Recommendations, r => r.Tag == "RESPOND" && r.Action.Contains("alert"));
    }

    [Fact]
    public void ConfigDrift_RecommendsBaseline()
    {
        Seed(
            (Ago(15), 85, new[] { ("Def", "AV ok", "Pass") }),
            (Ago(10), 70, new[] { ("FW", "Firewall config default", "Warning"), ("Reg", "Permission setting wrong", "Warning"), ("Upd", "Update policy disabled", "Warning"), ("Svc", "Service enabled default", "Warning") })
        );
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Recommendations, r => r.Tag == "PREVENT" && r.Action.Contains("baseline"));
    }

    [Fact]
    public void NoDegradations_RecommendsTighterThresholds()
    {
        Seed((Ago(10), 90, Array.Empty<(string, string, string)>()), (Ago(5), 92, Array.Empty<(string, string, string)>()));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 92)).Recommendations, r => r.Tag == "DETECT" && r.Action.Contains("threshold"));
    }

    [Fact]
    public void AlwaysRecommendsPeriodicReview()
    {
        Seed((Ago(10), 80, Array.Empty<(string, string, string)>()), (Ago(5), 80, Array.Empty<(string, string, string)>()));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 80)).Recommendations, r => r.Action.Contains("autopsy") || r.Action.Contains("review"));
    }

    [Fact]
    public void RecurringIssues_RecommendsSystemicFix()
    {
        var f = ("Net", "RDP exposed", "Critical");
        Seed((Ago(20), 80, new[] { f }), (Ago(15), 70, new[] { f }), (Ago(10), 70, new[] { f }), (Ago(5), 70, new[] { f }));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Recommendations, r => r.Tag == "PREVENT" && r.Action.Contains("recurring"));
    }

    [Fact]
    public void ManyDegradations_RecommendsFrequency()
    {
        Seed((Ago(35), 90, Array.Empty<(string, string, string)>()), (Ago(30), 82, Array.Empty<(string, string, string)>()), (Ago(25), 73, Array.Empty<(string, string, string)>()), (Ago(20), 64, Array.Empty<(string, string, string)>()), (Ago(15), 55, Array.Empty<(string, string, string)>()), (Ago(10), 46, Array.Empty<(string, string, string)>()), (Ago(5), 38, Array.Empty<(string, string, string)>()));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 38)).Recommendations, r => r.Tag == "RESPOND" && r.Action.Contains("frequency"));
    }

    [Fact]
    public void ModuleRegression_RecommendsRegressionTests()
    {
        var good = Enumerable.Range(1, 5).Select(i => ("Net", $"P{i}", "Pass")).ToArray();
        var bad = Enumerable.Range(1, 5).Select(i => ("Net", $"P{i}", "Critical")).ToArray();
        Seed((Ago(30), 80, good), (Ago(25), 50, bad), (Ago(20), 80, good), (Ago(15), 50, bad));
        Assert.Contains(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50)).Recommendations, r => r.Tag == "DETECT" && r.Action.Contains("regression"));
    }

    // ── Summary ─────────────────────────────────────────────────────

    [Fact]
    public void Summary_HasVerdictAndRationale()
    {
        Seed((Ago(10), 80, Array.Empty<(string, string, string)>()), (Ago(5), 75, Array.Empty<(string, string, string)>()));
        var s = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 75)).Summary;
        Assert.NotNull(s.OverallVerdict);
        Assert.NotEmpty(s.VerdictRationale);
    }

    [Fact]
    public void ManyCriticalEvents_VerdictCritical()
    {
        Seed((Ago(20), 90, Array.Empty<(string, string, string)>()), (Ago(15), 60, Array.Empty<(string, string, string)>()), (Ago(12), 85, Array.Empty<(string, string, string)>()), (Ago(10), 55, Array.Empty<(string, string, string)>()), (Ago(7), 80, Array.Empty<(string, string, string)>()), (Ago(5), 50, Array.Empty<(string, string, string)>()));
        Assert.Equal("Critical", _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50)).Summary.OverallVerdict);
    }

    [Fact]
    public void DecliningScores_VerdictDeclining()
    {
        Seed((Ago(15), 80, Array.Empty<(string, string, string)>()), (Ago(10), 75, Array.Empty<(string, string, string)>()), (Ago(5), 70, Array.Empty<(string, string, string)>()));
        Assert.Equal("Declining", _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Summary.OverallVerdict);
    }

    [Fact]
    public void RecoveringAfterDrop_VerdictRecovering()
    {
        Seed((Ago(15), 85, Array.Empty<(string, string, string)>()), (Ago(10), 60, Array.Empty<(string, string, string)>()), (Ago(5), 70, Array.Empty<(string, string, string)>()));
        Assert.Equal("Recovering", _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 70)).Summary.OverallVerdict);
    }

    [Fact]
    public void StableNoEvents_VerdictStable()
    {
        Seed((Ago(10), 80, Array.Empty<(string, string, string)>()), (Ago(5), 82, Array.Empty<(string, string, string)>()));
        Assert.Equal("Stable", _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 82)).Summary.OverallVerdict);
    }

    [Fact]
    public void Summary_TracksWorstModule()
    {
        var b = Enumerable.Range(1, 5).Select(i => ("Net", $"N{i}", "Pass")).Concat(Enumerable.Range(1, 5).Select(i => ("Def", $"D{i}", "Pass"))).ToArray();
        var a = Enumerable.Range(1, 5).Select(i => ("Net", $"N{i}", "Critical")).Concat(Enumerable.Range(1, 5).Select(i => ("Def", $"D{i}", "Warning"))).ToArray();
        Seed((Ago(10), 80, b), (Ago(5), 50, a));
        Assert.Equal("Net", _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 50)).Summary.WorstModule);
    }

    [Fact]
    public void Summary_TracksLargestDrop()
    {
        Seed((Ago(10), 90, Array.Empty<(string, string, string)>()), (Ago(5), 55, Array.Empty<(string, string, string)>()));
        Assert.Equal(35, _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 55)).Summary.LargestDrop);
    }

    [Fact]
    public void NoDegradations_LargestDropZero()
    {
        Seed((Ago(10), 80, Array.Empty<(string, string, string)>()), (Ago(5), 85, Array.Empty<(string, string, string)>()));
        Assert.Equal(0, _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 85)).Summary.LargestDrop);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void DaysParam_LimitsHistory()
    {
        Seed((Ago(30), 90, Array.Empty<(string, string, string)>()), (Ago(20), 55, Array.Empty<(string, string, string)>()));
        Assert.NotEmpty(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 55), days: 90).Degradations);
        Assert.Empty(_svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 55), days: 10).Degradations);
    }

    [Fact]
    public void GeneratedAt_IsRecent()
    {
        Seed((Ago(5), 80, Array.Empty<(string, string, string)>()));
        var result = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 80));
        Assert.True(result.GeneratedAt > DateTime.UtcNow.AddMinutes(-1));
        Assert.True(result.GeneratedAt <= DateTime.UtcNow);
    }

    [Fact]
    public void ComplexScenario_AllSectionsPopulated()
    {
        Seed(
            (Ago(30), 85, new[] { ("Net", "Port 80", "Warning"), ("Def", "AV on", "Pass") }),
            (Ago(25), 85, new[] { ("Net", "Port 80", "Warning"), ("Def", "AV on", "Pass") }),
            (Ago(20), 70, new[] { ("Net", "Port 80", "Warning"), ("Net", "RDP", "Critical"), ("Def", "AV off", "Critical") }),
            (Ago(15), 65, new[] { ("Net", "Port 80", "Warning"), ("Net", "RDP", "Critical"), ("Def", "AV off", "Critical"), ("FW", "Config default", "Warning") }),
            (Ago(10), 60, new[] { ("Net", "Port 80", "Warning"), ("Net", "RDP", "Critical"), ("Def", "AV off", "Critical"), ("FW", "Config default", "Warning"), ("Upd", "Policy disabled", "Critical") }),
            (Ago(5), 55, new[] { ("Net", "Port 80", "Warning"), ("Net", "RDP", "Critical"), ("Def", "AV off", "Critical"), ("FW", "Config default", "Warning"), ("Upd", "Policy disabled", "Critical"), ("Reg", "Permission setting weak", "Warning") })
        );
        var result = _svc.Analyze(MakeReport(DateTimeOffset.UtcNow, 55));
        Assert.NotEmpty(result.Degradations);
        Assert.NotEmpty(result.RootCauses);
        Assert.NotEmpty(result.Timeline);
        Assert.NotEmpty(result.Lessons);
        Assert.NotEmpty(result.Recommendations);
        Assert.Equal("Declining", result.Summary.OverallVerdict);
    }
}