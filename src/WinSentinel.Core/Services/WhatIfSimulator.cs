using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Simulates resolving findings and projects the resulting security score.
/// Lets users preview the impact of fixing specific issues before taking action.
/// </summary>
public class WhatIfSimulator
{
    /// <summary>
    /// Result of a what-if simulation showing before/after scores.
    /// </summary>
    public class SimulationResult
    {
        /// <summary>Score before any simulated fixes.</summary>
        public int CurrentScore { get; set; }

        /// <summary>Score after simulated fixes are applied.</summary>
        public int ProjectedScore { get; set; }

        /// <summary>Net score change (positive = improvement).</summary>
        public int ScoreDelta => ProjectedScore - CurrentScore;

        /// <summary>Current letter grade.</summary>
        public string CurrentGrade => SecurityScorer.GetGrade(CurrentScore);

        /// <summary>Projected letter grade after fixes.</summary>
        public string ProjectedGrade => SecurityScorer.GetGrade(ProjectedScore);

        /// <summary>Whether the grade improves.</summary>
        public bool GradeImproved => string.Compare(ProjectedGrade, CurrentGrade, StringComparison.Ordinal) < 0;

        /// <summary>Findings that were simulated as resolved.</summary>
        public List<ResolvedFinding> ResolvedFindings { get; set; } = new();

        /// <summary>Per-module score breakdown showing before/after.</summary>
        public List<ModuleImpact> ModuleImpacts { get; set; } = new();

        /// <summary>Total critical findings removed.</summary>
        public int CriticalResolved => ResolvedFindings.Count(f => f.Severity == Severity.Critical);

        /// <summary>Total warning findings removed.</summary>
        public int WarningResolved => ResolvedFindings.Count(f => f.Severity == Severity.Warning);
    }

    /// <summary>
    /// A finding that was simulated as resolved.
    /// </summary>
    public class ResolvedFinding
    {
        public required string Module { get; set; }
        public required string Title { get; set; }
        public Severity Severity { get; set; }
        public int PointsRecovered { get; set; }
    }

    /// <summary>
    /// Per-module impact of a simulation.
    /// </summary>
    public class ModuleImpact
    {
        public required string Module { get; set; }
        public int ScoreBefore { get; set; }
        public int ScoreAfter { get; set; }
        public int Delta => ScoreAfter - ScoreBefore;
        public int FindingsResolved { get; set; }
    }

    /// <summary>
    /// Simulate fixing all findings of a given severity level.
    /// </summary>
    public SimulationResult SimulateBySeverity(SecurityReport report, Severity severity)
    {
        var indices = new List<(string module, int findingIndex)>();
        foreach (var result in report.Results)
        {
            for (int i = 0; i < result.Findings.Count; i++)
            {
                if (result.Findings[i].Severity == severity)
                    indices.Add((result.ModuleName, i));
            }
        }
        return SimulateByIndices(report, indices);
    }

    /// <summary>
    /// Simulate fixing all findings in a specific module.
    /// </summary>
    public SimulationResult SimulateByModule(SecurityReport report, string moduleName)
    {
        var indices = new List<(string module, int findingIndex)>();
        foreach (var result in report.Results)
        {
            if (!result.ModuleName.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                continue;
            for (int i = 0; i < result.Findings.Count; i++)
            {
                if (result.Findings[i].Severity is Severity.Critical or Severity.Warning)
                    indices.Add((result.ModuleName, i));
            }
        }
        return SimulateByIndices(report, indices);
    }

    /// <summary>
    /// Simulate fixing findings that match a title pattern (substring, case-insensitive).
    /// </summary>
    public SimulationResult SimulateByPattern(SecurityReport report, string pattern)
    {
        var indices = new List<(string module, int findingIndex)>();
        foreach (var result in report.Results)
        {
            for (int i = 0; i < result.Findings.Count; i++)
            {
                var f = result.Findings[i];
                if (f.Severity is not (Severity.Critical or Severity.Warning)) continue;
                if (f.Title.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                    f.Description.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    indices.Add((result.ModuleName, i));
            }
        }
        return SimulateByIndices(report, indices);
    }

    /// <summary>
    /// Simulate fixing all critical and warning findings (best-case scenario).
    /// </summary>
    public SimulationResult SimulateFixAll(SecurityReport report)
    {
        var indices = new List<(string module, int findingIndex)>();
        foreach (var result in report.Results)
        {
            for (int i = 0; i < result.Findings.Count; i++)
            {
                if (result.Findings[i].Severity is Severity.Critical or Severity.Warning)
                    indices.Add((result.ModuleName, i));
            }
        }
        return SimulateByIndices(report, indices);
    }

    /// <summary>
    /// Simulate fixing the top N highest-impact findings.
    /// Returns the optimal set of findings to fix for maximum score improvement.
    /// </summary>
    public SimulationResult SimulateTopN(SecurityReport report, int count)
    {
        // Rank all actionable findings by point value (critical=20, warning=5)
        var ranked = new List<(string module, int index, Finding finding, int points)>();
        foreach (var result in report.Results)
        {
            for (int i = 0; i < result.Findings.Count; i++)
            {
                var f = result.Findings[i];
                int pts = f.Severity switch
                {
                    Severity.Critical => 20,
                    Severity.Warning => 5,
                    _ => 0
                };
                if (pts > 0)
                    ranked.Add((result.ModuleName, i, f, pts));
            }
        }

        var topN = ranked
            .OrderByDescending(r => r.points)
            .ThenBy(r => r.module)
            .Take(count)
            .Select(r => (r.module, r.index))
            .ToList();

        return SimulateByIndices(report, topN);
    }

    /// <summary>
    /// Core simulation: remove specified findings and recalculate scores.
    /// </summary>
    private SimulationResult SimulateByIndices(SecurityReport report,
        List<(string module, int findingIndex)> toResolve)
    {
        var currentScore = SecurityScorer.CalculateScore(report);
        var resolved = new List<ResolvedFinding>();
        var moduleImpacts = new List<ModuleImpact>();

        // Group removals by module
        var byModule = toResolve
            .GroupBy(t => t.module)
            .ToDictionary(g => g.Key, g => g.Select(x => x.findingIndex).ToHashSet());

        foreach (var result in report.Results)
        {
            int scoreBefore = SecurityScorer.CalculateCategoryScore(result);

            if (!byModule.TryGetValue(result.ModuleName, out var indicesToRemove))
            {
                moduleImpacts.Add(new ModuleImpact
                {
                    Module = result.ModuleName,
                    ScoreBefore = scoreBefore,
                    ScoreAfter = scoreBefore,
                    FindingsResolved = 0
                });
                continue;
            }

            // Build a simulated result without the resolved findings
            var simResult = new AuditResult
            {
                ModuleName = result.ModuleName,
                Category = result.Category,
                StartTime = result.StartTime,
                EndTime = result.EndTime,
                Success = result.Success
            };

            for (int i = 0; i < result.Findings.Count; i++)
            {
                if (indicesToRemove.Contains(i))
                {
                    var f = result.Findings[i];
                    int pts = f.Severity switch
                    {
                        Severity.Critical => 20,
                        Severity.Warning => 5,
                        _ => 0
                    };
                    resolved.Add(new ResolvedFinding
                    {
                        Module = result.ModuleName,
                        Title = f.Title,
                        Severity = f.Severity,
                        PointsRecovered = pts
                    });
                }
                else
                {
                    simResult.Findings.Add(result.Findings[i]);
                }
            }

            int scoreAfter = SecurityScorer.CalculateCategoryScore(simResult);
            moduleImpacts.Add(new ModuleImpact
            {
                Module = result.ModuleName,
                ScoreBefore = scoreBefore,
                ScoreAfter = scoreAfter,
                FindingsResolved = indicesToRemove.Count
            });
        }

        // Calculate projected overall score
        var simReport = new SecurityReport();
        foreach (var result in report.Results)
        {
            if (byModule.TryGetValue(result.ModuleName, out var indices))
            {
                var simResult = new AuditResult
                {
                    ModuleName = result.ModuleName,
                    Category = result.Category,
                    StartTime = result.StartTime,
                    EndTime = result.EndTime,
                    Success = result.Success
                };
                for (int i = 0; i < result.Findings.Count; i++)
                {
                    if (!indices.Contains(i))
                        simResult.Findings.Add(result.Findings[i]);
                }
                simReport.Results.Add(simResult);
            }
            else
            {
                simReport.Results.Add(result);
            }
        }

        var projectedScore = SecurityScorer.CalculateScore(simReport);

        return new SimulationResult
        {
            CurrentScore = currentScore,
            ProjectedScore = projectedScore,
            ResolvedFindings = resolved,
            ModuleImpacts = moduleImpacts.Where(m => m.FindingsResolved > 0).OrderByDescending(m => m.Delta).ToList()
        };
    }
}
