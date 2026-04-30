namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Security Posture Momentum Analyzer — autonomous analysis of security improvement
/// velocity, acceleration, and trajectory. Detects stalls, regressions, false plateaus,
/// and improvement bursts. Generates autonomous intervention recommendations.
///
/// Physics analogy: Score = position, Velocity = change rate, Acceleration = velocity change,
/// Jerk = acceleration change. Provides a complete "kinematic" view of security posture.
/// </summary>
public sealed class PostureMomentumAnalyzer
{
    private readonly AuditHistoryService _history;

    // ── Thresholds ──────────────────────────────────────────────────
    private const double VelocityStallThreshold = 0.05;    // points/day
    private const double AccelerationWarning = -0.02;       // deceleration alert
    private const double FalsePlateauVariance = 2.0;        // low variance but rising risk
    private const int MinDataPoints = 5;
    private const int DefaultHistoryDays = 90;

    public PostureMomentumAnalyzer(AuditHistoryService history) => _history = history;

    /// <summary>Run full momentum analysis on current posture history.</summary>
    public MomentumReport Analyze(SecurityReport currentReport, int historyDays = DefaultHistoryDays)
    {
        var runs = _history.GetHistory(historyDays);
        // Add current report as most recent data point
        var dataPoints = BuildDataPoints(runs, currentReport);

        var report = new MomentumReport
        {
            AnalyzedDays = historyDays,
            DataPointCount = dataPoints.Count,
            AnalyzedAt = DateTimeOffset.UtcNow
        };

        if (dataPoints.Count < MinDataPoints)
        {
            report.Phase = MomentumPhase.InsufficientData;
            report.Summary = $"Need at least {MinDataPoints} data points for momentum analysis (have {dataPoints.Count}).";
            return report;
        }

        // Compute kinematics
        report.Kinematics = ComputeKinematics(dataPoints);

        // Classify current phase
        report.Phase = ClassifyPhase(report.Kinematics);

        // Detect patterns
        report.Patterns = DetectPatterns(dataPoints, report.Kinematics);

        // Per-module momentum
        report.ModuleMomentum = ComputeModuleMomentum(runs, currentReport);

        // Generate interventions
        report.Interventions = GenerateInterventions(report);

        // Compute momentum score (0-100)
        report.MomentumScore = ComputeMomentumScore(report);

        // Generate summary
        report.Summary = GenerateSummary(report);

        return report;
    }

    // ── Data Point Construction ──────────────────────────────────────

    private List<PostureDataPoint> BuildDataPoints(List<AuditRunRecord> runs, SecurityReport current)
    {
        var points = runs
            .OrderBy(r => r.Timestamp)
            .Select(r => new PostureDataPoint
            {
                Timestamp = r.Timestamp,
                Score = r.OverallScore,
                CriticalCount = r.CriticalCount,
                WarningCount = r.WarningCount,
                TotalFindings = r.TotalFindings
            })
            .ToList();

        // Add current
        points.Add(new PostureDataPoint
        {
            Timestamp = current.GeneratedAt,
            Score = current.SecurityScore,
            CriticalCount = current.TotalCritical,
            WarningCount = current.TotalWarnings,
            TotalFindings = current.TotalFindings
        });

        return points;
    }

    // ── Kinematics Computation ───────────────────────────────────────

    private KinematicState ComputeKinematics(List<PostureDataPoint> points)
    {
        var state = new KinematicState();

        // Current position (latest score)
        state.Position = points[^1].Score;

        // Velocity: weighted average of recent score changes per day
        var velocities = new List<double>();
        for (int i = 1; i < points.Count; i++)
        {
            var dt = (points[i].Timestamp - points[i - 1].Timestamp).TotalDays;
            if (dt < 0.01) continue; // skip same-day duplicates
            velocities.Add((points[i].Score - points[i - 1].Score) / dt);
        }

        if (velocities.Count > 0)
        {
            // Exponential weighted moving average (recent matters more)
            double alpha = 0.3;
            double ewma = velocities[0];
            for (int i = 1; i < velocities.Count; i++)
                ewma = alpha * velocities[i] + (1 - alpha) * ewma;
            state.Velocity = ewma;

            // Recent velocity (last 3 intervals)
            var recent = velocities.Skip(Math.Max(0, velocities.Count - 3)).ToList();
            state.RecentVelocity = recent.Average();
        }

        // Acceleration: change in velocity over recent windows
        if (velocities.Count >= 4)
        {
            var firstHalf = velocities.Take(velocities.Count / 2).Average();
            var secondHalf = velocities.Skip(velocities.Count / 2).Average();
            var totalDays = (points[^1].Timestamp - points[0].Timestamp).TotalDays;
            state.Acceleration = (secondHalf - firstHalf) / (totalDays / 2.0);
        }

        // Jerk: acceleration trend
        if (velocities.Count >= 6)
        {
            var q1 = velocities.Take(velocities.Count / 3).Average();
            var q2 = velocities.Skip(velocities.Count / 3).Take(velocities.Count / 3).Average();
            var q3 = velocities.Skip(2 * velocities.Count / 3).Average();
            var a1 = q2 - q1;
            var a2 = q3 - q2;
            state.Jerk = a2 - a1;
        }

        // Score variance (stability)
        var scores = points.Select(p => (double)p.Score).ToList();
        var mean = scores.Average();
        state.Variance = scores.Sum(s => (s - mean) * (s - mean)) / scores.Count;

        // Trend line (simple linear regression)
        var n = points.Count;
        var xs = Enumerable.Range(0, n).Select(i => (double)i).ToList();
        var ys = scores;
        var xMean = xs.Average();
        var yMean = ys.Average();
        var num = xs.Zip(ys, (x, y) => (x - xMean) * (y - yMean)).Sum();
        var den = xs.Sum(x => (x - xMean) * (x - xMean));
        state.TrendSlope = den > 0 ? num / den : 0;

        // Risk momentum (critical findings trend)
        var criticals = points.Select(p => (double)p.CriticalCount).ToList();
        var cMean = criticals.Average();
        var cNum = xs.Zip(criticals, (x, c) => (x - xMean) * (c - cMean)).Sum();
        state.RiskMomentum = den > 0 ? cNum / den : 0;

        return state;
    }

    // ── Phase Classification ─────────────────────────────────────────

    private MomentumPhase ClassifyPhase(KinematicState k)
    {
        // Regression: negative velocity + negative acceleration
        if (k.Velocity < -VelocityStallThreshold && k.Acceleration <= 0)
            return MomentumPhase.FreeFall;

        if (k.Velocity < -VelocityStallThreshold)
            return MomentumPhase.Regressing;

        // Stall: near-zero velocity
        if (Math.Abs(k.Velocity) <= VelocityStallThreshold)
        {
            if (k.Acceleration < AccelerationWarning)
                return MomentumPhase.Decelerating;
            if (k.RiskMomentum > 0.1)
                return MomentumPhase.FalsePlateau;
            return MomentumPhase.Stalled;
        }

        // Positive velocity
        if (k.Acceleration > 0.01)
            return MomentumPhase.Accelerating;

        if (k.Velocity > 0.5)
            return MomentumPhase.Surging;

        return MomentumPhase.Cruising;
    }

    // ── Pattern Detection ────────────────────────────────────────────

    private List<MomentumPattern> DetectPatterns(List<PostureDataPoint> points, KinematicState k)
    {
        var patterns = new List<MomentumPattern>();

        // Sawtooth: repeated rise-then-fall pattern
        var sawteeth = 0;
        for (int i = 2; i < points.Count; i++)
        {
            if (points[i].Score < points[i - 1].Score && points[i - 1].Score > points[i - 2].Score)
                sawteeth++;
        }
        if (sawteeth >= 3)
        {
            patterns.Add(new MomentumPattern
            {
                Name = "Sawtooth",
                Description = "Repeated improve-then-regress cycles detected",
                Severity = "High",
                Occurrences = sawteeth,
                Emoji = "🪚"
            });
        }

        // Ceiling Effect: stuck near max with bouncing
        var highScores = points.Count(p => p.Score >= 90);
        if (highScores > points.Count * 0.6 && k.Variance < 5)
        {
            patterns.Add(new MomentumPattern
            {
                Name = "CeilingEffect",
                Description = "Score near maximum with diminishing returns",
                Severity = "Info",
                Occurrences = highScores,
                Emoji = "🔝"
            });
        }

        // Sudden Drop: large score decrease between consecutive runs
        for (int i = 1; i < points.Count; i++)
        {
            var drop = points[i - 1].Score - points[i].Score;
            if (drop >= 15)
            {
                patterns.Add(new MomentumPattern
                {
                    Name = "SuddenDrop",
                    Description = $"Sharp {drop}-point score drop on {points[i].Timestamp:yyyy-MM-dd}",
                    Severity = "Critical",
                    Occurrences = 1,
                    Emoji = "📉"
                });
            }
        }

        // Stagnation: 5+ consecutive points with same score (±1)
        var stagnant = 1;
        var maxStagnant = 1;
        for (int i = 1; i < points.Count; i++)
        {
            if (Math.Abs(points[i].Score - points[i - 1].Score) <= 1)
                stagnant++;
            else
                stagnant = 1;
            maxStagnant = Math.Max(maxStagnant, stagnant);
        }
        if (maxStagnant >= 5)
        {
            patterns.Add(new MomentumPattern
            {
                Name = "Stagnation",
                Description = $"{maxStagnant} consecutive scans with no meaningful change",
                Severity = "Medium",
                Occurrences = maxStagnant,
                Emoji = "🧊"
            });
        }

        // Critical Creep: rising critical findings despite stable score
        if (k.RiskMomentum > 0.05 && Math.Abs(k.TrendSlope) < 0.3)
        {
            patterns.Add(new MomentumPattern
            {
                Name = "CriticalCreep",
                Description = "Critical findings trending up while overall score appears stable",
                Severity = "High",
                Occurrences = (int)Math.Ceiling(k.RiskMomentum * 10),
                Emoji = "🐛"
            });
        }

        // Improvement Burst: 3+ consecutive strong gains
        var burstLen = 0;
        var maxBurst = 0;
        for (int i = 1; i < points.Count; i++)
        {
            if (points[i].Score - points[i - 1].Score >= 3)
                burstLen++;
            else
                burstLen = 0;
            maxBurst = Math.Max(maxBurst, burstLen);
        }
        if (maxBurst >= 3)
        {
            patterns.Add(new MomentumPattern
            {
                Name = "ImprovementBurst",
                Description = $"{maxBurst} consecutive strong improvement intervals",
                Severity = "Good",
                Occurrences = maxBurst,
                Emoji = "🚀"
            });
        }

        return patterns;
    }

    // ── Per-Module Momentum ──────────────────────────────────────────

    private List<ModuleMomentumInfo> ComputeModuleMomentum(List<AuditRunRecord> runs, SecurityReport current)
    {
        var moduleHistory = new Dictionary<string, List<(DateTimeOffset Ts, int Score)>>();

        foreach (var run in runs.OrderBy(r => r.Timestamp))
        {
            foreach (var ms in run.ModuleScores)
            {
                if (!moduleHistory.ContainsKey(ms.ModuleName))
                    moduleHistory[ms.ModuleName] = [];
                moduleHistory[ms.ModuleName].Add((run.Timestamp, ms.Score));
            }
        }

        // Add current scores
        foreach (var result in current.Results)
        {
            if (!moduleHistory.ContainsKey(result.ModuleName))
                moduleHistory[result.ModuleName] = [];
            moduleHistory[result.ModuleName].Add((current.GeneratedAt, result.Score));
        }

        var moduleMomentum = new List<ModuleMomentumInfo>();
        foreach (var (module, history) in moduleHistory)
        {
            if (history.Count < 3) continue;

            var ordered = history.OrderBy(h => h.Ts).ToList();
            var latest = ordered[^1].Score;
            var earliest = ordered[0].Score;
            var totalDays = Math.Max(1, (ordered[^1].Ts - ordered[0].Ts).TotalDays);

            // Compute velocity
            var velocity = (latest - earliest) / totalDays;

            // Recent trend (last 3 points)
            var recentSlice = ordered.Skip(Math.Max(0, ordered.Count - 3)).ToList();
            var recentDays = Math.Max(1, (recentSlice[^1].Ts - recentSlice[0].Ts).TotalDays);
            var recentVelocity = (recentSlice[^1].Score - recentSlice[0].Score) / recentDays;

            var direction = recentVelocity switch
            {
                > 0.1 => "Improving",
                < -0.1 => "Declining",
                _ => "Stable"
            };

            moduleMomentum.Add(new ModuleMomentumInfo
            {
                ModuleName = module,
                CurrentScore = latest,
                Velocity = velocity,
                RecentVelocity = recentVelocity,
                Direction = direction,
                DataPoints = history.Count
            });
        }

        return moduleMomentum.OrderBy(m => m.RecentVelocity).ToList();
    }

    // ── Intervention Generator ───────────────────────────────────────

    private List<MomentumIntervention> GenerateInterventions(MomentumReport report)
    {
        var interventions = new List<MomentumIntervention>();

        // Phase-based interventions
        switch (report.Phase)
        {
            case MomentumPhase.FreeFall:
                interventions.Add(new MomentumIntervention
                {
                    Priority = "Critical",
                    Action = "Emergency Security Review",
                    Rationale = "Security posture is in free-fall — rapid deterioration with accelerating losses.",
                    Steps = ["Identify root cause of regression", "Freeze non-essential changes", "Revert recent configuration changes", "Run full audit immediately"],
                    ExpectedImpact = "Stop further score decline within 24-48 hours"
                });
                break;

            case MomentumPhase.Regressing:
                interventions.Add(new MomentumIntervention
                {
                    Priority = "High",
                    Action = "Regression Containment",
                    Rationale = "Score is declining — intervention needed before it accelerates.",
                    Steps = ["Compare recent changes to baseline", "Identify new findings introduced", "Prioritize critical finding remediation", "Increase scan frequency"],
                    ExpectedImpact = "Halt regression within 1 week"
                });
                break;

            case MomentumPhase.FalsePlateau:
                interventions.Add(new MomentumIntervention
                {
                    Priority = "High",
                    Action = "Hidden Risk Investigation",
                    Rationale = "Score appears stable but critical risks are silently growing underneath.",
                    Steps = ["Review critical findings trend", "Investigate compensating controls masking risk", "Audit score calculation for blind spots", "Run threat-specific deep scans"],
                    ExpectedImpact = "Surface hidden risks before they cascade"
                });
                break;

            case MomentumPhase.Stalled:
                interventions.Add(new MomentumIntervention
                {
                    Priority = "Medium",
                    Action = "Plateau Breaking Strategy",
                    Rationale = "Improvement has stalled — need new approaches to move forward.",
                    Steps = ["Identify highest-impact unfixed findings", "Review remediation backlog", "Consider architectural improvements", "Set incremental score targets"],
                    ExpectedImpact = "Resume improvement trajectory within 2 weeks"
                });
                break;

            case MomentumPhase.Decelerating:
                interventions.Add(new MomentumIntervention
                {
                    Priority = "Medium",
                    Action = "Momentum Preservation",
                    Rationale = "Improvement rate is slowing — at risk of stalling completely.",
                    Steps = ["Identify friction in remediation pipeline", "Automate recurring fixes", "Address low-hanging fruit for quick wins", "Review resource allocation"],
                    ExpectedImpact = "Maintain positive velocity above stall threshold"
                });
                break;
        }

        // Pattern-based interventions
        foreach (var pattern in report.Patterns)
        {
            switch (pattern.Name)
            {
                case "Sawtooth":
                    interventions.Add(new MomentumIntervention
                    {
                        Priority = "High",
                        Action = "Fix Durability Audit",
                        Rationale = "Improvements keep reverting — fixes aren't persistent.",
                        Steps = ["Identify fixes that reverted", "Implement configuration management", "Add regression tests for security settings", "Automate enforcement"],
                        ExpectedImpact = "Eliminate repeated regression cycles"
                    });
                    break;

                case "CriticalCreep":
                    interventions.Add(new MomentumIntervention
                    {
                        Priority = "High",
                        Action = "Critical Finding Blitz",
                        Rationale = "Critical findings are accumulating despite stable overall score.",
                        Steps = ["List all unresolved critical findings", "Assign owners and deadlines", "Escalate blockers", "Track daily until resolved"],
                        ExpectedImpact = "Reduce critical count to baseline within 1 week"
                    });
                    break;

                case "SuddenDrop":
                    interventions.Add(new MomentumIntervention
                    {
                        Priority = "Critical",
                        Action = "Incident Response",
                        Rationale = "A sudden large score drop indicates a significant security event.",
                        Steps = ["Correlate drop with system changes", "Check for unauthorized modifications", "Review recent deployments", "Restore from known-good baseline if needed"],
                        ExpectedImpact = "Recover score within 48 hours"
                    });
                    break;
            }
        }

        // Module-based interventions: flag modules that are dragging momentum down
        var decliningModules = report.ModuleMomentum
            .Where(m => m.RecentVelocity < -0.1)
            .OrderBy(m => m.RecentVelocity)
            .Take(3)
            .ToList();

        if (decliningModules.Count > 0)
        {
            interventions.Add(new MomentumIntervention
            {
                Priority = "Medium",
                Action = "Module-Level Remediation Focus",
                Rationale = $"These modules are dragging overall momentum down: {string.Join(", ", decliningModules.Select(m => m.ModuleName))}",
                Steps = decliningModules.Select(m => $"Investigate {m.ModuleName} (velocity: {m.RecentVelocity:+0.00;-0.00} pts/day)").ToList(),
                ExpectedImpact = "Improve overall velocity by fixing weakest links"
            });
        }

        return interventions;
    }

    // ── Momentum Score (0-100) ───────────────────────────────────────

    private int ComputeMomentumScore(MomentumReport report)
    {
        var k = report.Kinematics;
        double score = 50; // neutral starting point

        // Velocity contribution (±25)
        score += Math.Clamp(k.Velocity * 50, -25, 25);

        // Acceleration contribution (±15)
        score += Math.Clamp(k.Acceleration * 500, -15, 15);

        // Pattern penalties
        foreach (var p in report.Patterns)
        {
            score -= p.Severity switch
            {
                "Critical" => 10,
                "High" => 7,
                "Medium" => 4,
                "Good" => -5, // bonus for good patterns
                _ => 0
            };
        }

        // Phase bonus/penalty
        score += report.Phase switch
        {
            MomentumPhase.Surging => 10,
            MomentumPhase.Accelerating => 5,
            MomentumPhase.Cruising => 3,
            MomentumPhase.Stalled => -3,
            MomentumPhase.FalsePlateau => -8,
            MomentumPhase.Decelerating => -5,
            MomentumPhase.Regressing => -10,
            MomentumPhase.FreeFall => -15,
            _ => 0
        };

        return (int)Math.Clamp(score, 0, 100);
    }

    // ── Summary Generation ───────────────────────────────────────────

    private string GenerateSummary(MomentumReport report)
    {
        var k = report.Kinematics;
        var phase = report.Phase;

        var emoji = phase switch
        {
            MomentumPhase.Surging => "🚀",
            MomentumPhase.Accelerating => "📈",
            MomentumPhase.Cruising => "✈️",
            MomentumPhase.Stalled => "⏸️",
            MomentumPhase.FalsePlateau => "⚠️",
            MomentumPhase.Decelerating => "📉",
            MomentumPhase.Regressing => "🔻",
            MomentumPhase.FreeFall => "💥",
            _ => "❓"
        };

        var velocityDesc = k.Velocity switch
        {
            > 0.5 => "rapidly improving",
            > 0.1 => "steadily improving",
            > VelocityStallThreshold => "slowly improving",
            > -VelocityStallThreshold => "effectively stalled",
            > -0.1 => "slowly declining",
            > -0.5 => "steadily declining",
            _ => "rapidly declining"
        };

        return $"{emoji} Phase: {phase} | Momentum Score: {report.MomentumScore}/100 | " +
               $"Velocity: {k.Velocity:+0.000;-0.000} pts/day ({velocityDesc}) | " +
               $"Position: {k.Position}/100 | Patterns: {report.Patterns.Count} detected | " +
               $"Interventions: {report.Interventions.Count} recommended";
    }
}
