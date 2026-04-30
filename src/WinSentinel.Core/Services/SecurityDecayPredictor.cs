namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Security Decay Predictor — autonomous forecasting of when findings will escalate
/// in severity based on age, exposure profile, and category risk characteristics.
///
/// Uses an exponential decay model where each finding accumulates "decay pressure"
/// over time. Categories with higher exposure (e.g., network-facing, credential-related)
/// decay faster. Predictions enable proactive prioritization: fix what's about to
/// escalate, not just what's currently worst.
///
/// Decay Formula: pressure = age_days * decay_rate * exposure_multiplier
/// Escalation threshold varies by current severity level.
/// </summary>
public sealed class SecurityDecayPredictor
{
    // ── Category Exposure Profiles ──────────────────────────────────
    // Higher multiplier = faster decay (more exposed to exploitation)
    private static readonly Dictionary<string, double> CategoryExposure = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Firewall"] = 1.8,
        ["Network"] = 1.7,
        ["RemoteAccess"] = 1.9,
        ["Accounts"] = 1.6,
        ["Credentials"] = 2.0,
        ["Encryption"] = 1.5,
        ["Defender"] = 1.4,
        ["Updates"] = 1.3,
        ["Services"] = 1.2,
        ["Processes"] = 1.1,
        ["Registry"] = 1.0,
        ["Privacy"] = 0.9,
        ["Browser"] = 1.3,
        ["Startup"] = 1.1,
        ["Drivers"] = 1.2,
        ["Bluetooth"] = 0.8,
        ["Wifi"] = 1.4,
        ["DNS"] = 1.5,
        ["SMB"] = 1.6,
        ["PowerShell"] = 1.3,
        ["GroupPolicy"] = 1.1,
        ["Certificates"] = 1.2,
        ["EventLog"] = 0.7,
        ["Backup"] = 0.8,
        ["Virtualization"] = 1.0,
        ["Config"] = 1.0,
        ["Security"] = 1.3,
    };

    // ── Base Decay Rates (per day) ──────────────────────────────────
    // How fast findings accumulate escalation pressure by current severity
    private const double InfoDecayRate = 0.005;      // Very slow — info findings rarely escalate
    private const double WarningDecayRate = 0.02;    // Moderate — warnings can become critical
    private const double CriticalDecayRate = 0.0;    // Already at max severity

    // ── Escalation Thresholds ───────────────────────────────────────
    // Accumulated pressure needed to trigger escalation
    private const double InfoToWarningThreshold = 1.0;
    private const double WarningToCriticalThreshold = 1.0;

    // ── Confidence Parameters ───────────────────────────────────────
    private const int BaseConfidence = 70;
    private const int MaxConfidence = 95;
    private const int MinConfidence = 30;

    /// <summary>Run full decay prediction analysis on current findings.</summary>
    public DecayPredictionReport Predict(SecurityReport report)
    {
        var predictions = new List<FindingDecayPrediction>();
        var now = DateTimeOffset.UtcNow;

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                if (finding.Severity == Severity.Pass)
                    continue;

                var prediction = PredictFinding(finding, now);
                predictions.Add(prediction);
            }
        }

        // Sort by urgency (most urgent first), then by days to escalation
        predictions.Sort((a, b) =>
        {
            var urgencyCompare = ((int)b.Urgency).CompareTo((int)a.Urgency);
            if (urgencyCompare != 0) return urgencyCompare;
            return a.DaysToEscalation.CompareTo(b.DaysToEscalation);
        });

        var result2 = new DecayPredictionReport
        {
            TotalFindings = predictions.Count,
            Predictions = predictions,
            EscalatingWithin7Days = predictions.Count(p => p.DaysToEscalation <= 7 && p.DaysToEscalation > 0),
            EscalatingWithin30Days = predictions.Count(p => p.DaysToEscalation <= 30 && p.DaysToEscalation > 0),
            OverdueCount = predictions.Count(p => p.Trajectory == DecayTrajectory.Overdue),
        };

        // Category summaries
        result2.CategorySummaries = BuildCategorySummaries(predictions);

        // Health score
        result2.HealthScore = ComputeHealthScore(predictions);

        // Recommendations
        result2.Recommendations = GenerateRecommendations(result2);

        // Summary
        result2.Summary = GenerateSummary(result2);

        return result2;
    }

    /// <summary>Predict decay for a single finding.</summary>
    internal FindingDecayPrediction PredictFinding(Finding finding, DateTimeOffset now)
    {
        var ageDays = Math.Max(0, (now - finding.Timestamp).TotalDays);
        var exposureMultiplier = GetExposureMultiplier(finding.Category);
        var decayRate = GetDecayRate(finding.Severity);
        var threshold = GetEscalationThreshold(finding.Severity);

        // Current accumulated pressure
        var currentPressure = ageDays * decayRate * exposureMultiplier;

        // Days remaining until escalation
        double daysToEscalation;
        DecayTrajectory trajectory;
        Severity predictedNext;

        if (finding.Severity == Severity.Critical)
        {
            // Already at max severity — no further escalation
            daysToEscalation = double.MaxValue;
            trajectory = DecayTrajectory.Stable;
            predictedNext = Severity.Critical;
        }
        else if (currentPressure >= threshold)
        {
            // Already overdue
            daysToEscalation = 0;
            trajectory = DecayTrajectory.Overdue;
            predictedNext = finding.Severity == Severity.Info ? Severity.Warning : Severity.Critical;
        }
        else
        {
            var remainingPressure = threshold - currentPressure;
            var dailyPressure = decayRate * exposureMultiplier;
            daysToEscalation = dailyPressure > 0 ? remainingPressure / dailyPressure : double.MaxValue;
            trajectory = ClassifyTrajectory(daysToEscalation);
            predictedNext = finding.Severity == Severity.Info ? Severity.Warning : Severity.Critical;
        }

        var urgency = ClassifyUrgency(daysToEscalation, finding.Severity);
        var confidence = ComputeConfidence(ageDays, exposureMultiplier);
        var interventionWindow = DescribeInterventionWindow(daysToEscalation, trajectory);
        var decayVelocity = decayRate * exposureMultiplier;

        return new FindingDecayPrediction
        {
            FindingTitle = finding.Title,
            CurrentSeverity = finding.Severity,
            PredictedNextSeverity = predictedNext,
            Category = finding.Category,
            AgeDays = Math.Round(ageDays, 1),
            DaysToEscalation = daysToEscalation == double.MaxValue ? -1 : Math.Round(daysToEscalation, 1),
            Trajectory = trajectory,
            Urgency = urgency,
            DecayVelocity = Math.Round(decayVelocity, 4),
            ExposureMultiplier = exposureMultiplier,
            Confidence = confidence,
            InterventionWindow = interventionWindow
        };
    }

    private static double GetExposureMultiplier(string category)
    {
        if (string.IsNullOrEmpty(category)) return 1.0;
        return CategoryExposure.TryGetValue(category, out var multiplier) ? multiplier : 1.0;
    }

    private static double GetDecayRate(Severity severity) => severity switch
    {
        Severity.Info => InfoDecayRate,
        Severity.Warning => WarningDecayRate,
        Severity.Critical => CriticalDecayRate,
        _ => 0.0
    };

    private static double GetEscalationThreshold(Severity severity) => severity switch
    {
        Severity.Info => InfoToWarningThreshold,
        Severity.Warning => WarningToCriticalThreshold,
        _ => double.MaxValue
    };

    private static DecayTrajectory ClassifyTrajectory(double daysToEscalation) => daysToEscalation switch
    {
        <= 0 => DecayTrajectory.Overdue,
        <= 7 => DecayTrajectory.RapidDecay,
        <= 30 => DecayTrajectory.ActiveDecay,
        <= 90 => DecayTrajectory.SlowDecay,
        _ => DecayTrajectory.Stable
    };

    private static DecayUrgency ClassifyUrgency(double daysToEscalation, Severity currentSeverity)
    {
        if (daysToEscalation <= 0) return DecayUrgency.Critical;

        // Warnings escalating to Critical are more urgent than Info escalating to Warning
        var severityBoost = currentSeverity == Severity.Warning ? 1.5 : 1.0;
        var adjustedDays = daysToEscalation / severityBoost;

        return adjustedDays switch
        {
            <= 7 => DecayUrgency.Critical,
            <= 14 => DecayUrgency.High,
            <= 30 => DecayUrgency.Medium,
            _ => DecayUrgency.Low
        };
    }

    private static int ComputeConfidence(double ageDays, double exposureMultiplier)
    {
        // More data (older findings) = higher confidence in prediction
        var ageBonus = Math.Min(15, ageDays * 0.5);
        // Well-known categories = higher confidence
        var categoryBonus = exposureMultiplier > 1.0 ? 10 : 0;
        var confidence = (int)(BaseConfidence + ageBonus + categoryBonus);
        return Math.Clamp(confidence, MinConfidence, MaxConfidence);
    }

    private static string DescribeInterventionWindow(double daysToEscalation, DecayTrajectory trajectory) => trajectory switch
    {
        DecayTrajectory.Overdue => "OVERDUE — immediate action required",
        DecayTrajectory.RapidDecay => $"Critical window: {daysToEscalation:F0} days remaining",
        DecayTrajectory.ActiveDecay => $"Address within {daysToEscalation:F0} days to prevent escalation",
        DecayTrajectory.SlowDecay => $"Low urgency — ~{daysToEscalation:F0} days until escalation",
        DecayTrajectory.Stable => "No escalation predicted — monitor periodically",
        _ => "Unknown"
    };

    private static List<CategoryDecaySummary> BuildCategorySummaries(List<FindingDecayPrediction> predictions)
    {
        return predictions
            .GroupBy(p => p.Category)
            .Select(g =>
            {
                var items = g.ToList();
                var escalatingItems = items.Where(p => p.DaysToEscalation >= 0).ToList();
                var avgDays = escalatingItems.Count > 0
                    ? escalatingItems.Average(p => p.DaysToEscalation)
                    : -1;

                var critCount = items.Count(p => p.Urgency == DecayUrgency.Critical);
                var highCount = items.Count(p => p.Urgency == DecayUrgency.High);

                // Health: penalize for critical/high urgency findings
                var health = 100 - (critCount * 20) - (highCount * 10);
                health = Math.Clamp(health, 0, 100);

                return new CategoryDecaySummary
                {
                    Category = string.IsNullOrEmpty(g.Key) ? "Uncategorized" : g.Key,
                    FindingCount = items.Count,
                    AvgDaysToEscalation = avgDays >= 0 ? Math.Round(avgDays, 1) : -1,
                    CriticalUrgencyCount = critCount,
                    HighUrgencyCount = highCount,
                    HealthScore = health
                };
            })
            .OrderBy(c => c.HealthScore)
            .ToList();
    }

    private static int ComputeHealthScore(List<FindingDecayPrediction> predictions)
    {
        if (predictions.Count == 0) return 100;

        var criticalPenalty = predictions.Count(p => p.Urgency == DecayUrgency.Critical) * 15;
        var highPenalty = predictions.Count(p => p.Urgency == DecayUrgency.High) * 8;
        var mediumPenalty = predictions.Count(p => p.Urgency == DecayUrgency.Medium) * 3;
        var overduePenalty = predictions.Count(p => p.Trajectory == DecayTrajectory.Overdue) * 20;

        var score = 100 - criticalPenalty - highPenalty - mediumPenalty - overduePenalty;
        return Math.Clamp(score, 0, 100);
    }

    private static List<string> GenerateRecommendations(DecayPredictionReport report)
    {
        var recs = new List<string>();

        if (report.OverdueCount > 0)
            recs.Add($"🚨 {report.OverdueCount} finding(s) are OVERDUE for escalation — address immediately to prevent severity increase.");

        if (report.EscalatingWithin7Days > 0)
            recs.Add($"⚡ {report.EscalatingWithin7Days} finding(s) will escalate within 7 days — prioritize these in your next remediation sprint.");

        if (report.EscalatingWithin30Days > 3)
            recs.Add($"📈 {report.EscalatingWithin30Days} findings approaching escalation within 30 days — consider a focused remediation campaign.");

        var worstCategories = report.CategorySummaries
            .Where(c => c.HealthScore < 50)
            .Take(3)
            .ToList();

        if (worstCategories.Count > 0)
        {
            var cats = string.Join(", ", worstCategories.Select(c => c.Category));
            recs.Add($"🎯 Focus on high-decay categories: {cats} — these have the most escalation pressure.");
        }

        var highExposure = report.Predictions
            .Where(p => p.ExposureMultiplier >= 1.7 && p.Urgency >= DecayUrgency.Medium)
            .Take(3)
            .ToList();

        if (highExposure.Count > 0)
            recs.Add($"🌐 {highExposure.Count} high-exposure finding(s) (network/remote/credential) are decaying fast — external attack surface risk.");

        if (report.HealthScore >= 80)
            recs.Add("✅ Decay pressure is well-managed — maintain current remediation cadence.");
        else if (report.HealthScore < 40)
            recs.Add("🔴 High decay pressure across the board — consider an emergency remediation push.");

        if (recs.Count == 0)
            recs.Add("✅ No significant decay pressure detected — security posture is stable.");

        return recs;
    }

    private static string GenerateSummary(DecayPredictionReport report)
    {
        if (report.TotalFindings == 0)
            return "No active findings to analyze for decay.";

        var urgentCount = report.Predictions.Count(p => p.Urgency >= DecayUrgency.High);
        return $"Analyzed {report.TotalFindings} findings: {report.OverdueCount} overdue, " +
               $"{report.EscalatingWithin7Days} escalating within 7d, " +
               $"{urgentCount} requiring urgent attention. Health: {report.HealthScore}/100.";
    }
}
