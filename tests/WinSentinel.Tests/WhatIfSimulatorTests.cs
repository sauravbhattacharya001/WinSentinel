using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for WhatIfSimulator — score projection and finding simulation.
/// </summary>
public class WhatIfSimulatorTests
{
    private readonly WhatIfSimulator _simulator = new();

    private static SecurityReport MakeReport(params (string module, Severity[] findings)[] modules)
    {
        var report = new SecurityReport();
        foreach (var (module, findings) in modules)
        {
            var result = new AuditResult { ModuleName = module, Category = "Test" };
            int i = 0;
            foreach (var sev in findings)
            {
                result.Findings.Add(new Finding
                {
                    Title = $"{module}-finding-{i++}",
                    Description = $"Test finding {sev}",
                    Severity = sev,
                    Category = "Test"
                });
            }
            report.Results.Add(result);
        }
        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    // ── SimulateFixAll ───────────────────────────────────────────────

    [Fact]
    public void SimulateFixAll_EmptyReport_Returns100()
    {
        var report = MakeReport();
        var result = _simulator.SimulateFixAll(report);
        Assert.Equal(100, result.ProjectedScore);
        Assert.Equal(0, result.ScoreDelta);
    }

    [Fact]
    public void SimulateFixAll_OneCritical_Recovers20Points()
    {
        var report = MakeReport(("Firewall", new[] { Severity.Critical }));
        var result = _simulator.SimulateFixAll(report);
        Assert.Equal(80, result.CurrentScore);
        Assert.Equal(100, result.ProjectedScore);
        Assert.Equal(20, result.ScoreDelta);
    }

    [Fact]
    public void SimulateFixAll_MixedFindings_AllRecovered()
    {
        var report = MakeReport(
            ("Firewall", new[] { Severity.Critical, Severity.Warning }),
            ("Network", new[] { Severity.Warning, Severity.Warning })
        );
        var result = _simulator.SimulateFixAll(report);
        Assert.Equal(100, result.ProjectedScore);
        Assert.Equal(1, result.CriticalResolved);
        Assert.Equal(3, result.WarningResolved);
    }

    [Fact]
    public void SimulateFixAll_InfoAndPassIgnored()
    {
        var report = MakeReport(("System", new[] { Severity.Info, Severity.Pass, Severity.Warning }));
        var result = _simulator.SimulateFixAll(report);
        Assert.Equal(1, result.ResolvedFindings.Count); // only the warning
        Assert.Equal(100, result.ProjectedScore);
    }

    // ── SimulateBySeverity ───────────────────────────────────────────

    [Fact]
    public void SimulateBySeverity_Critical_OnlyRemovesCritical()
    {
        var report = MakeReport(("Firewall", new[] { Severity.Critical, Severity.Warning }));
        var result = _simulator.SimulateBySeverity(report, Severity.Critical);
        Assert.Equal(1, result.CriticalResolved);
        Assert.Equal(0, result.WarningResolved);
    }

    [Fact]
    public void SimulateBySeverity_Warning_OnlyRemovesWarnings()
    {
        var report = MakeReport(
            ("Firewall", new[] { Severity.Critical, Severity.Warning, Severity.Warning })
        );
        var result = _simulator.SimulateBySeverity(report, Severity.Warning);
        Assert.Equal(0, result.CriticalResolved);
        Assert.Equal(2, result.WarningResolved);
    }

    [Fact]
    public void SimulateBySeverity_NoMatches_NoChange()
    {
        var report = MakeReport(("Firewall", new[] { Severity.Warning }));
        var result = _simulator.SimulateBySeverity(report, Severity.Critical);
        Assert.Equal(0, result.ScoreDelta);
        Assert.Empty(result.ResolvedFindings);
    }

    // ── SimulateByModule ─────────────────────────────────────────────

    [Fact]
    public void SimulateByModule_MatchesSubstring()
    {
        var report = MakeReport(
            ("FirewallAudit", new[] { Severity.Critical }),
            ("NetworkAudit", new[] { Severity.Warning })
        );
        var result = _simulator.SimulateByModule(report, "Firewall");
        Assert.Equal(1, result.CriticalResolved);
        Assert.Empty(result.ResolvedFindings.Where(f => f.Module == "NetworkAudit"));
    }

    [Fact]
    public void SimulateByModule_NoMatch_NoChange()
    {
        var report = MakeReport(("FirewallAudit", new[] { Severity.Critical }));
        var result = _simulator.SimulateByModule(report, "NonExistent");
        Assert.Equal(0, result.ScoreDelta);
    }

    [Fact]
    public void SimulateByModule_CaseInsensitive()
    {
        var report = MakeReport(("FirewallAudit", new[] { Severity.Warning }));
        var result = _simulator.SimulateByModule(report, "firewall");
        Assert.Equal(1, result.WarningResolved);
    }

    // ── SimulateByPattern ────────────────────────────────────────────

    [Fact]
    public void SimulateByPattern_MatchesTitle()
    {
        var report = MakeReport(("Firewall", new[] { Severity.Critical, Severity.Warning }));
        // Titles are "Firewall-finding-0" and "Firewall-finding-1"
        var result = _simulator.SimulateByPattern(report, "finding-0");
        Assert.Equal(1, result.ResolvedFindings.Count);
    }

    [Fact]
    public void SimulateByPattern_MatchesDescription()
    {
        var report = MakeReport(("Firewall", new[] { Severity.Critical }));
        var result = _simulator.SimulateByPattern(report, "Test finding Critical");
        Assert.Equal(1, result.ResolvedFindings.Count);
    }

    [Fact]
    public void SimulateByPattern_NoMatch_NoChange()
    {
        var report = MakeReport(("Firewall", new[] { Severity.Critical }));
        var result = _simulator.SimulateByPattern(report, "zzzznotfound");
        Assert.Equal(0, result.ScoreDelta);
    }

    // ── SimulateTopN ─────────────────────────────────────────────────

    [Fact]
    public void SimulateTopN_PrioritizesCriticalOverWarning()
    {
        var report = MakeReport(
            ("A", new[] { Severity.Warning, Severity.Warning, Severity.Warning }),
            ("B", new[] { Severity.Critical })
        );
        var result = _simulator.SimulateTopN(report, 1);
        Assert.Equal(1, result.CriticalResolved);
        Assert.Equal(0, result.WarningResolved);
    }

    [Fact]
    public void SimulateTopN_RespectsCount()
    {
        var report = MakeReport(
            ("A", new[] { Severity.Critical, Severity.Critical, Severity.Warning })
        );
        var result = _simulator.SimulateTopN(report, 2);
        Assert.Equal(2, result.ResolvedFindings.Count);
        Assert.Equal(2, result.CriticalResolved);
    }

    [Fact]
    public void SimulateTopN_MoreThanAvailable_FixesAll()
    {
        var report = MakeReport(("A", new[] { Severity.Warning }));
        var result = _simulator.SimulateTopN(report, 10);
        Assert.Equal(1, result.ResolvedFindings.Count);
        Assert.Equal(100, result.ProjectedScore);
    }

    // ── ModuleImpacts ────────────────────────────────────────────────

    [Fact]
    public void ModuleImpacts_ShowsDeltaPerModule()
    {
        var report = MakeReport(
            ("Firewall", new[] { Severity.Critical }),
            ("Network", new[] { Severity.Warning })
        );
        var result = _simulator.SimulateFixAll(report);
        Assert.Equal(2, result.ModuleImpacts.Count);
        Assert.All(result.ModuleImpacts, m => Assert.True(m.Delta > 0));
    }

    [Fact]
    public void ModuleImpacts_OnlyShowsAffectedModules()
    {
        var report = MakeReport(
            ("Firewall", new[] { Severity.Critical }),
            ("Clean", new[] { Severity.Pass })
        );
        var result = _simulator.SimulateFixAll(report);
        // Only Firewall should appear (Clean has no actionable findings)
        Assert.Single(result.ModuleImpacts);
        Assert.Equal("Firewall", result.ModuleImpacts[0].Module);
    }

    // ── Grade ────────────────────────────────────────────────────────

    [Fact]
    public void GradeImproved_DetectsUpgrade()
    {
        // 2 critical = 60 score (D), fixing both = 100 (A)
        var report = MakeReport(("A", new[] { Severity.Critical, Severity.Critical }));
        var result = _simulator.SimulateFixAll(report);
        Assert.True(result.GradeImproved);
        Assert.Equal("D", result.CurrentGrade);
        Assert.Equal("A", result.ProjectedGrade);
    }

    [Fact]
    public void GradeImproved_FalseWhenSameGrade()
    {
        // 1 warning = 95 score (A), fixing = 100 (A)
        var report = MakeReport(("A", new[] { Severity.Warning }));
        var result = _simulator.SimulateFixAll(report);
        Assert.False(result.GradeImproved);
    }

    // ── Edge Cases ───────────────────────────────────────────────────

    [Fact]
    public void MultipleModules_ScoreCalculatedCorrectly()
    {
        var report = MakeReport(
            ("A", new[] { Severity.Critical }),  // 80
            ("B", new[] { Severity.Warning }),   // 95
            ("C", new[] { Severity.Pass })       // 100
        );
        // Current avg = (80+95+100)/3 = 92
        var result = _simulator.SimulateFixAll(report);
        Assert.Equal(92, result.CurrentScore);
        Assert.Equal(100, result.ProjectedScore);
    }

    [Fact]
    public void PointsRecovered_CorrectPerSeverity()
    {
        var report = MakeReport(("A", new[] { Severity.Critical, Severity.Warning }));
        var result = _simulator.SimulateFixAll(report);
        var critical = result.ResolvedFindings.First(f => f.Severity == Severity.Critical);
        var warning = result.ResolvedFindings.First(f => f.Severity == Severity.Warning);
        Assert.Equal(20, critical.PointsRecovered);
        Assert.Equal(5, warning.PointsRecovered);
    }

    [Fact]
    public void ScoreDelta_IsPositiveWhenFixing()
    {
        var report = MakeReport(("A", new[] { Severity.Critical }));
        var result = _simulator.SimulateFixAll(report);
        Assert.True(result.ScoreDelta > 0);
    }

    [Fact]
    public void ScoreDelta_IsZeroWhenNothingToFix()
    {
        var report = MakeReport(("A", new[] { Severity.Pass }));
        var result = _simulator.SimulateFixAll(report);
        Assert.Equal(0, result.ScoreDelta);
    }

    // ── Duplicate Module Names ───────────────────────────────────────
    //   report.Results may contain multiple AuditResults that share the
    //   same ModuleName. Resolution must be tracked per result instance,
    //   not keyed by the (non-unique) module name, or findings get
    //   cross-resolved between same-named results.

    private static SecurityReport MakeReportRaw(params AuditResult[] results)
    {
        var report = new SecurityReport();
        report.Results.AddRange(results);
        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    private static AuditResult MakeResult(string module, params Severity[] sevs)
    {
        var r = new AuditResult { ModuleName = module, Category = "Test" };
        int i = 0;
        foreach (var s in sevs)
            r.Findings.Add(new Finding
            {
                Title = $"{module}-{i++}",
                Description = $"Test finding {s}",
                Severity = s,
                Category = "Test"
            });
        return r;
    }

    [Fact]
    public void DuplicateModuleName_BySeverity_DoesNotCrossResolve()
    {
        // Two results share ModuleName "Firewall".
        //   [0] index0 = Critical (the real target)
        //   [1] index0 = Pass     (must NOT be touched)
        var report = MakeReportRaw(
            MakeResult("Firewall", Severity.Critical),
            MakeResult("Firewall", Severity.Pass));

        var result = _simulator.SimulateBySeverity(report, Severity.Critical);

        // Exactly one Critical resolved; the Pass in the second result is untouched.
        Assert.Equal(1, result.CriticalResolved);
        Assert.Single(result.ResolvedFindings);
        Assert.All(result.ResolvedFindings, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void DuplicateModuleName_ProjectedScore_IsCorrect()
    {
        // [0] Firewall: Critical  -> category 80
        // [1] Firewall: Critical  -> category 80
        // Overall current = (80+80)/2 = 80.
        // Resolve only the FIRST result's critical: categories 100 & 80 -> 90.
        var report = MakeReportRaw(
            MakeResult("Firewall", Severity.Critical),
            MakeResult("Firewall", Severity.Critical));

        // Target a single result instance via SimulateByIndices-equivalent path:
        // SimulateBySeverity resolves BOTH criticals (both match), projected = 100.
        var both = _simulator.SimulateBySeverity(report, Severity.Critical);
        Assert.Equal(2, both.CriticalResolved);
        Assert.Equal(80, both.CurrentScore);
        Assert.Equal(100, both.ProjectedScore);
    }

    [Fact]
    public void DuplicateModuleName_ResolvedCount_NotInflated()
    {
        // [0] Firewall: Critical, Warning
        // [1] Firewall: Pass, Pass
        // FixAll should resolve exactly the 1 Critical + 1 Warning from [0],
        // never the passes from [1].
        var report = MakeReportRaw(
            MakeResult("Firewall", Severity.Critical, Severity.Warning),
            MakeResult("Firewall", Severity.Pass, Severity.Pass));

        var result = _simulator.SimulateFixAll(report);

        Assert.Equal(1, result.CriticalResolved);
        Assert.Equal(1, result.WarningResolved);
        Assert.Equal(2, result.ResolvedFindings.Count);
        // ModuleImpacts only lists results that actually had findings resolved.
        Assert.Equal(2, result.ModuleImpacts.Sum(m => m.FindingsResolved));
    }
}
