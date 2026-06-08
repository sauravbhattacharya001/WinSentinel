namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Post-incident forensic analysis — reconstructs security degradations,
/// identifies root causes, builds a forensic timeline, and distills lessons learned.
/// </summary>
public sealed class SecurityAutopsyService
{
    private readonly AuditHistoryService _history;

    public SecurityAutopsyService(AuditHistoryService history) => _history = history;

    public AutopsyReport Analyze(SecurityReport report, int days = 90, string? moduleFilter = null)
    {
        var runs = _history.GetHistoryWithFindings(days);
        var moduleTrends = _history.GetModuleHistory(maxRuns: 10);
        var ordered = runs.OrderBy(r => r.Timestamp).ToList();

        var degradations = DetectDegradations(ordered, moduleFilter);
        var rootCauses = InferRootCauses(ordered, degradations);
        var timeline = BuildTimeline(ordered, moduleFilter);
        var lessons = DistillLessons(ordered, degradations, rootCauses);
        var recommendations = BuildRecommendations(degradations, rootCauses);
        var summary = BuildSummary(ordered, degradations, moduleTrends);

        return new AutopsyReport(degradations, rootCauses, timeline, lessons,
            recommendations, summary, DateTime.UtcNow);
    }

    // ── Degradation Detection ────────────────────────────────────────

    private static List<DegradationEvent> DetectDegradations(
        List<AuditRunRecord> runs, string? moduleFilter)
    {
        var events = new List<DegradationEvent>();
        for (int i = 1; i < runs.Count; i++)
        {
            var prev = runs[i - 1];
            var curr = runs[i];

            // Overall score drop > 5
            if (prev.OverallScore - curr.OverallScore > 5)
            {
                var drop = prev.OverallScore - curr.OverallScore;
                var severity = drop > 20 ? 1 : drop > 10 ? 2 : 3;
                events.Add(new DegradationEvent(curr.Timestamp, "Score Drop", "Overall",
                    prev.OverallScore, curr.OverallScore, severity,
                    $"Overall score dropped {drop} points ({prev.OverallScore} → {curr.OverallScore})"));
            }

            // Critical spike
            if (curr.CriticalCount > prev.CriticalCount + 1)
            {
                var spike = curr.CriticalCount - prev.CriticalCount;
                events.Add(new DegradationEvent(curr.Timestamp, "Critical Spike", "Overall",
                    prev.CriticalCount, curr.CriticalCount, 1,
                    $"Critical findings spiked by {spike} ({prev.CriticalCount} → {curr.CriticalCount})"));
            }

            // Module-level drops > 10
            var prevModules = prev.ModuleScores.ToDictionary(m => m.ModuleName, m => m.Score);
            foreach (var mod in curr.ModuleScores)
            {
                if (moduleFilter != null &&
                    !mod.ModuleName.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (prevModules.TryGetValue(mod.ModuleName, out var prevScore) &&
                    prevScore - mod.Score > 10)
                {
                    var drop = prevScore - mod.Score;
                    var severity = drop > 30 ? 1 : drop > 15 ? 2 : 3;
                    events.Add(new DegradationEvent(curr.Timestamp, "Module Failure",
                        mod.ModuleName, prevScore, mod.Score, severity,
                        $"{mod.ModuleName} dropped {drop} points ({prevScore} → {mod.Score})"));
                }
            }
        }

        return events.OrderBy(e => e.DetectedAt).ToList();
    }

    // ── Root Cause Inference ─────────────────────────────────────────

    private static List<RootCauseHypothesis> InferRootCauses(
        List<AuditRunRecord> runs, List<DegradationEvent> degradations)
    {
        var hypotheses = new List<RootCauseHypothesis>();
        if (runs.Count < 2 || degradations.Count == 0) return hypotheses;

        // Find recurring findings (appeared, resolved, reappeared)
        var findingTimelines = new Dictionary<string, List<(DateTimeOffset ts, bool present)>>();
        foreach (var run in runs)
        {
            var titles = run.Findings.Select(f => f.Title).ToHashSet();
            foreach (var f in run.Findings)
            {
                if (!findingTimelines.ContainsKey(f.Title))
                    findingTimelines[f.Title] = [];
                findingTimelines[f.Title].Add((run.Timestamp, true));
            }
        }

        // Recurring issues
        foreach (var (title, timeline) in findingTimelines)
        {
            if (timeline.Count < 3) continue;
            hypotheses.Add(new RootCauseHypothesis("Recurring Issue",
                $"Finding \"{Truncate(title, 60)}\" has appeared in {timeline.Count} scans",
                Math.Min(0.9, 0.5 + timeline.Count * 0.1),
                [$"Seen in {timeline.Count} scans over the analysis period",
                 $"First: {timeline[0].ts:yyyy-MM-dd}, Latest: {timeline[^1].ts:yyyy-MM-dd}"],
                $"Investigate why \"{Truncate(title, 40)}\" keeps reappearing — likely a systemic root cause"));
        }

        // Module regression patterns
        var moduleDrops = degradations
            .Where(d => d.Type == "Module Failure")
            .GroupBy(d => d.Module)
            .Where(g => g.Count() >= 2);
        foreach (var group in moduleDrops)
        {
            hypotheses.Add(new RootCauseHypothesis("Module Regression",
                $"{group.Key} experienced {group.Count()} degradation events",
                Math.Min(0.95, 0.6 + group.Count() * 0.1),
                group.Select(d => $"{d.DetectedAt:yyyy-MM-dd}: {d.Description}").ToList(),
                $"Deep review of {group.Key} recommended — repeated regressions indicate structural weakness"));
        }

        // New vulnerability surges
        for (int i = 1; i < runs.Count; i++)
        {
            var prevTitles = runs[i - 1].Findings.Select(f => f.Title).ToHashSet();
            var newCriticals = runs[i].Findings
                .Where(f => f.Severity == "Critical" && !prevTitles.Contains(f.Title))
                .ToList();
            if (newCriticals.Count >= 2)
            {
                hypotheses.Add(new RootCauseHypothesis("New Vulnerability",
                    $"{newCriticals.Count} new critical findings appeared on {runs[i].Timestamp:yyyy-MM-dd}",
                    0.7,
                    newCriticals.Select(f => f.Title).Take(5).ToList(),
                    "Immediate remediation of new critical findings required"));
            }
        }

        // Configuration drift
        var configKeywords = new[] { "config", "setting", "policy", "permission", "enabled", "disabled", "default" };
        var configFindings = runs.SelectMany(r => r.Findings)
            .Where(f => configKeywords.Any(k => f.Title.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                                                  f.Description.Contains(k, StringComparison.OrdinalIgnoreCase)))
            .Select(f => f.Title)
            .Distinct()
            .ToList();
        if (configFindings.Count >= 3)
        {
            hypotheses.Add(new RootCauseHypothesis("Configuration Drift",
                $"{configFindings.Count} configuration-related findings detected across scans",
                0.65,
                configFindings.Take(5).ToList(),
                "Review and lock down security configuration baseline"));
        }

        return hypotheses.OrderByDescending(h => h.Confidence).Take(10).ToList();
    }

    // ── Timeline ─────────────────────────────────────────────────────

    private static List<TimelineEntry> BuildTimeline(
        List<AuditRunRecord> runs, string? moduleFilter)
    {
        var entries = new List<TimelineEntry>();
        if (runs.Count == 0) return entries;

        for (int i = 0; i < runs.Count; i++)
        {
            var run = runs[i];
            // Scan event
            entries.Add(new TimelineEntry(run.Timestamp, "🔍", "Audit Scan",
                "Overall", $"Score: {run.OverallScore} ({run.Grade}) — {run.TotalFindings} findings"));

            if (i == 0) continue;
            var prev = runs[i - 1];

            // Grade changes
            if (prev.Grade != run.Grade)
            {
                var icon = string.Compare(run.Grade, prev.Grade, StringComparison.Ordinal) < 0 ? "📈" : "📉";
                entries.Add(new TimelineEntry(run.Timestamp, icon, "Grade Change",
                    "Overall", $"{prev.Grade} → {run.Grade}"));
            }

            // New findings
            var prevTitles = prev.Findings.Select(f => f.Title).ToHashSet();
            var newFindings = run.Findings.Where(f => !prevTitles.Contains(f.Title)).ToList();
            foreach (var f in newFindings.Take(3))
            {
                if (moduleFilter != null &&
                    !f.ModuleName.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase))
                    continue;
                var icon = f.Severity == "Critical" ? "🔴" : f.Severity == "Warning" ? "🟡" : "🔵";
                entries.Add(new TimelineEntry(run.Timestamp, icon, $"New {f.Severity}",
                    f.ModuleName, Truncate(f.Title, 60)));
            }

            // Resolved findings
            var currTitles = run.Findings.Select(f => f.Title).ToHashSet();
            var resolved = prev.Findings.Where(f => !currTitles.Contains(f.Title)).ToList();
            foreach (var f in resolved.Take(3))
            {
                if (moduleFilter != null &&
                    !f.ModuleName.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase))
                    continue;
                entries.Add(new TimelineEntry(run.Timestamp, "✅", "Resolved",
                    f.ModuleName, Truncate(f.Title, 60)));
            }
        }

        return entries.OrderBy(e => e.Timestamp).ToList();
    }

    // ── Lessons Learned ──────────────────────────────────────────────

    private static List<LessonLearned> DistillLessons(
        List<AuditRunRecord> runs, List<DegradationEvent> degradations,
        List<RootCauseHypothesis> rootCauses)
    {
        var lessons = new List<LessonLearned>();

        // Lesson: persistent findings
        if (runs.Count >= 3)
        {
            var allTitles = runs.SelectMany(r => r.Findings.Select(f => f.Title));
            var persistent = allTitles.GroupBy(t => t)
                .Where(g => g.Count() >= runs.Count * 0.8)
                .Select(g => g.Key)
                .ToList();
            if (persistent.Count > 0)
            {
                lessons.Add(new LessonLearned(
                    "Persistent Findings Not Being Remediated",
                    $"{persistent.Count} finding(s) appeared in 80%+ of scans without resolution",
                    "Create a dedicated remediation sprint for persistent findings",
                    "High"));
            }
        }

        // Lesson: recurring regressions
        var recurringModules = rootCauses
            .Where(r => r.Category == "Module Regression")
            .ToList();
        if (recurringModules.Count > 0)
        {
            lessons.Add(new LessonLearned(
                "Recurring Module Regressions",
                $"{recurringModules.Count} module(s) show repeated degradation — fixes aren't sticking",
                "Investigate root causes at the infrastructure level, not just symptoms",
                "High"));
        }

        // Lesson: critical response time
        var criticalDegradations = degradations.Where(d => d.Severity == 1).ToList();
        if (criticalDegradations.Count > 0)
        {
            lessons.Add(new LessonLearned(
                "Critical Degradations Occurred",
                $"{criticalDegradations.Count} severity-1 event(s) detected in the analysis period",
                "Implement alerting for score drops >20 points or critical finding spikes",
                "High"));
        }

        // Lesson: score volatility
        if (runs.Count >= 5)
        {
            var scores = runs.Select(r => r.OverallScore).ToList();
            var avg = scores.Average();
            var stdDev = Math.Sqrt(scores.Select(s => Math.Pow(s - avg, 2)).Average());
            if (stdDev > 10)
            {
                lessons.Add(new LessonLearned(
                    "High Score Volatility",
                    $"Score standard deviation is {stdDev:F1} — posture is unstable",
                    "Establish a security baseline and monitor for configuration drift",
                    "Medium"));
            }
        }

        // Lesson: improving trend
        if (runs.Count >= 3 && degradations.Count == 0)
        {
            lessons.Add(new LessonLearned(
                "Stable or Improving Posture",
                "No degradation events detected — security practices are working",
                "Continue current practices and consider raising the bar",
                "Low"));
        }

        return lessons;
    }

    // ── Recommendations ──────────────────────────────────────────────

    private static List<ProactiveRecommendation> BuildRecommendations(
        List<DegradationEvent> degradations, List<RootCauseHypothesis> rootCauses)
    {
        var recs = new List<ProactiveRecommendation>();

        if (degradations.Any(d => d.Type == "Critical Spike"))
            recs.Add(new ProactiveRecommendation("RESPOND",
                "Set up automated alerting for critical finding spikes",
                "Critical spikes were detected — faster response reduces exposure window"));

        if (rootCauses.Any(r => r.Category == "Configuration Drift"))
            recs.Add(new ProactiveRecommendation("PREVENT",
                "Implement configuration baseline enforcement",
                "Configuration drift is a recurring root cause of degradations"));

        if (rootCauses.Any(r => r.Category == "Recurring Issue"))
            recs.Add(new ProactiveRecommendation("PREVENT",
                "Address recurring findings at the systemic level",
                "Recurring issues suggest fixes are superficial — deeper investigation needed"));

        if (rootCauses.Any(r => r.Category == "Module Regression"))
            recs.Add(new ProactiveRecommendation("DETECT",
                "Add per-module regression tests to your scan pipeline",
                "Module regressions indicate changes are degrading specific security areas"));

        if (degradations.Count > 5)
            recs.Add(new ProactiveRecommendation("RESPOND",
                "Increase scan frequency during volatile periods",
                "High degradation count suggests gaps between detection and response"));

        if (degradations.Count == 0)
            recs.Add(new ProactiveRecommendation("DETECT",
                "Consider tightening degradation thresholds",
                "No events detected — current thresholds may be too lenient"));

        recs.Add(new ProactiveRecommendation("PREVENT",
            "Schedule regular autopsy reviews (monthly)",
            "Periodic forensic review catches slow-moving degradation patterns"));

        return recs;
    }

    // ── Summary ──────────────────────────────────────────────────────

    private static AutopsySummary BuildSummary(
        List<AuditRunRecord> runs, List<DegradationEvent> degradations,
        List<ModuleTrendInfo> moduleTrends)
    {
        var criticalEvents = degradations.Count(d => d.Severity == 1);
        var worstModule = degradations
            .Where(d => d.Type == "Module Failure")
            .GroupBy(d => d.Module)
            .OrderByDescending(g => g.Sum(d => d.ScoreBefore - d.ScoreAfter))
            .FirstOrDefault()?.Key ?? "None";
        var largestDrop = degradations.Count > 0
            ? degradations.Max(d => d.ScoreBefore - d.ScoreAfter)
            : 0;

        string verdict, rationale;
        if (criticalEvents >= 3)
        {
            verdict = "Critical";
            rationale = $"{criticalEvents} critical degradation events — immediate attention required";
        }
        else if (runs.Count >= 3 && runs[^1].OverallScore < runs[^2].OverallScore &&
                 runs[^2].OverallScore < runs[^3].OverallScore)
        {
            verdict = "Declining";
            rationale = "Score has been declining over the last 3 scans";
        }
        else if (runs.Count >= 2 && runs[^1].OverallScore > runs[^2].OverallScore &&
                 degradations.Count > 0)
        {
            verdict = "Recovering";
            rationale = "Recent score improvement after degradation events";
        }
        else
        {
            verdict = "Stable";
            rationale = degradations.Count == 0
                ? "No degradation events detected in the analysis period"
                : $"{degradations.Count} minor event(s) but overall posture is stable";
        }

        return new AutopsySummary(degradations.Count, criticalEvents, worstModule,
            largestDrop, verdict, rationale);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 1)] + "…";

    // ── Records ──────────────────────────────────────────────────────

    public record AutopsyReport(
        List<DegradationEvent> Degradations,
        List<RootCauseHypothesis> RootCauses,
        List<TimelineEntry> Timeline,
        List<LessonLearned> Lessons,
        List<ProactiveRecommendation> Recommendations,
        AutopsySummary Summary,
        DateTime GeneratedAt);

    public record DegradationEvent(
        DateTimeOffset DetectedAt,
        string Type,
        string Module,
        int ScoreBefore,
        int ScoreAfter,
        int Severity,
        string Description);

    public record RootCauseHypothesis(
        string Category,
        string Description,
        double Confidence,
        List<string> Evidence,
        string SuggestedFix);

    public record TimelineEntry(
        DateTimeOffset Timestamp,
        string Icon,
        string Event,
        string Module,
        string Detail);

    public record LessonLearned(
        string Title,
        string Description,
        string ActionItem,
        string Priority);

    public record ProactiveRecommendation(
        string Tag,
        string Action,
        string Rationale);

    public record AutopsySummary(
        int TotalDegradations,
        int CriticalEvents,
        string WorstModule,
        int LargestDrop,
        string OverallVerdict,
        string VerdictRationale);
}
