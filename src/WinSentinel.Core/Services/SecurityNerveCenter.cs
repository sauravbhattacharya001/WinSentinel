namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Autonomous unified situational awareness — consolidates all security signals
/// into a single nerve-center view with DEFCON threat level, active incidents,
/// module vitals, signal feed, proactive actions, and autonomous alerts.
/// </summary>
public sealed class SecurityNerveCenter
{
    private readonly AuditHistoryService _history;

    public SecurityNerveCenter(AuditHistoryService history) => _history = history;

    // ── Public API ───────────────────────────────────────────────────

    public NerveCenterReport Analyze(SecurityReport report, int days = 30)
    {
        var runs = _history.GetHistoryWithFindings(days);
        var moduleTrends = _history.GetModuleHistory(maxRuns: 5);

        var threatLevel = ComputeThreatLevel(report, runs);
        var incidents = BuildIncidents(report);
        var vitals = BuildVitals(report, moduleTrends);
        var signals = BuildSignals(report, runs);
        var actions = BuildActions(report, vitals, incidents);
        var alerts = BuildAlerts(report, runs, vitals);

        return new NerveCenterReport(
            threatLevel.Level, threatLevel.Label, threatLevel.Rationale,
            incidents, vitals, signals, actions, alerts,
            DateTime.UtcNow);
    }

    // ── Threat Level ─────────────────────────────────────────────────

    private static (int Level, string Label, string Rationale) ComputeThreatLevel(
        SecurityReport report, List<AuditRunRecord> runs)
    {
        var score = report.SecurityScore;
        var criticals = report.TotalCritical;

        // Check for declining trend (last 3+ scans)
        bool declining = false;
        if (runs.Count >= 3)
        {
            var recent = runs.OrderByDescending(r => r.Timestamp).Take(3).ToList();
            declining = recent[0].OverallScore < recent[1].OverallScore &&
                        recent[1].OverallScore < recent[2].OverallScore;
        }

        if (score < 40 || criticals >= 5)
            return (1, "DEFCON 1 — MAXIMUM READINESS",
                $"Score {score}/100 with {criticals} critical findings. Immediate action required.");
        if (score < 60 || criticals >= 3 || declining)
            return (2, "DEFCON 2 — ARMED FORCES READY",
                declining
                    ? $"Score {score}/100 with declining trend across last 3 scans."
                    : $"Score {score}/100 with {criticals} critical findings. Elevated risk.");
        if (score < 75)
            return (3, "DEFCON 3 — INCREASE READINESS",
                $"Score {score}/100. Some issues need attention.");
        if (score < 90)
            return (4, "DEFCON 4 — ABOVE NORMAL READINESS",
                $"Score {score}/100. Minor issues only.");
        return (5, "DEFCON 5 — LOWEST READINESS",
            $"Score {score}/100. System is well secured.");
    }

    // ── Active Incidents ─────────────────────────────────────────────

    private static List<ActiveIncident> BuildIncidents(SecurityReport report)
    {
        var incidents = new List<ActiveIncident>();
        foreach (var result in report.Results)
        {
            var serious = result.Findings
                .Where(f => f.Severity is Severity.Critical or Severity.Warning)
                .ToList();
            if (serious.Count == 0) continue;

            var oldest = serious.Min(f => f.Timestamp);
            var ageDays = (int)(DateTimeOffset.UtcNow - oldest).TotalDays;
            var top = serious.OrderByDescending(f => f.Severity).First();

            incidents.Add(new ActiveIncident(
                result.ModuleName,
                top.Severity.ToString(),
                serious.Count,
                ageDays,
                top.Title));
        }
        return incidents.OrderByDescending(i => i.Severity == "Critical")
                        .ThenByDescending(i => i.Count)
                        .ToList();
    }

    // ── Module Vitals ────────────────────────────────────────────────

    private static List<ModuleVital> BuildVitals(
        SecurityReport report, List<ModuleTrendInfo> trends)
    {
        var trendMap = trends.ToDictionary(t => t.ModuleName, t => t);
        var vitals = new List<ModuleVital>();

        foreach (var result in report.Results)
        {
            var score = (double)result.Score;
            trendMap.TryGetValue(result.ModuleName, out var trend);

            var status = score >= 80 ? "Healthy" : score >= 50 ? "Degraded" : "Critical";
            var trendDir = trend?.TrendIndicator ?? "—";
            var prevScore = trend?.PreviousScore.HasValue == true ? (double?)trend.PreviousScore.Value : null;

            vitals.Add(new ModuleVital(result.ModuleName, status, score, trendDir, prevScore));
        }
        return vitals.OrderBy(v => v.Score).ToList();
    }

    // ── Signal Feed ──────────────────────────────────────────────────

    private static List<SignalEntry> BuildSignals(SecurityReport report, List<AuditRunRecord> runs)
    {
        var signals = new List<SignalEntry>();
        var now = DateTime.UtcNow;

        if (runs.Count >= 2)
        {
            var sorted = runs.OrderByDescending(r => r.Timestamp).ToList();
            var latest = sorted[0];
            var previous = sorted[1];

            var scoreDelta = latest.OverallScore - previous.OverallScore;
            if (Math.Abs(scoreDelta) >= 5)
            {
                var icon = scoreDelta > 0 ? "🟢" : "🔴";
                signals.Add(new SignalEntry(latest.Timestamp.UtcDateTime, icon,
                    $"Score changed {scoreDelta:+#;-#;0} points ({previous.OverallScore}→{latest.OverallScore})"));
            }

            // Detect new critical findings
            var prevCritTitles = previous.Findings
                .Where(f => f.Severity == "Critical")
                .Select(f => f.Title)
                .ToHashSet();
            var newCrits = latest.Findings
                .Where(f => f.Severity == "Critical" && !prevCritTitles.Contains(f.Title))
                .ToList();
            foreach (var c in newCrits.Take(3))
            {
                signals.Add(new SignalEntry(latest.Timestamp.UtcDateTime, "🔴",
                    $"New critical: {c.Title}"));
            }

            // Detect resolved findings
            var currentTitles = latest.Findings.Select(f => f.Title).ToHashSet();
            var resolved = previous.Findings
                .Where(f => f.Severity is "Critical" or "Warning" && !currentTitles.Contains(f.Title))
                .ToList();
            if (resolved.Count > 0)
            {
                signals.Add(new SignalEntry(latest.Timestamp.UtcDateTime, "🟢",
                    $"{resolved.Count} finding(s) resolved since last scan"));
            }
        }

        // Current state signals
        if (report.TotalCritical > 0)
            signals.Add(new SignalEntry(now, "🔴",
                $"{report.TotalCritical} critical finding(s) active"));

        if (report.TotalFindings == 0)
            signals.Add(new SignalEntry(now, "🟢", "Clean scan — zero findings"));

        return signals.OrderByDescending(s => s.Timestamp).Take(10).ToList();
    }

    // ── Proactive Actions ────────────────────────────────────────────

    private static List<ProactiveAction> BuildActions(
        SecurityReport report,
        List<ModuleVital> vitals,
        List<ActiveIncident> incidents)
    {
        var actions = new List<ProactiveAction>();
        int priority = 0;

        // Critical incidents first
        foreach (var incident in incidents.Where(i => i.Severity == "Critical").Take(2))
        {
            actions.Add(new ProactiveAction(++priority, "URGENT",
                $"Resolve {incident.Count} critical finding(s) in {incident.Module}",
                $"Top: {incident.TopFinding}"));
        }

        // Degraded/critical modules
        foreach (var vital in vitals.Where(v => v.Status == "Critical").Take(2))
        {
            actions.Add(new ProactiveAction(++priority, "HIGH",
                $"Investigate {vital.Module} (score: {vital.Score:F0})",
                "Module is in critical state and needs immediate attention."));
        }

        // Declining modules
        foreach (var vital in vitals.Where(v => v.Trend == "↓").Take(2))
        {
            actions.Add(new ProactiveAction(++priority, "MEDIUM",
                $"Address declining trend in {vital.Module}",
                vital.PrevScore.HasValue
                    ? $"Score dropped from {vital.PrevScore.Value:F0} to {vital.Score:F0}."
                    : "Score is trending downward."));
        }

        // General recommendation
        if (report.TotalFindings > 20)
        {
            actions.Add(new ProactiveAction(++priority, "MEDIUM",
                "Consider running --fixall to auto-remediate fixable findings",
                $"{report.TotalFindings} total findings detected."));
        }

        return actions.Take(5).ToList();
    }

    // ── Autonomous Alerts ────────────────────────────────────────────

    private static List<AutonomousAlert> BuildAlerts(
        SecurityReport report,
        List<AuditRunRecord> runs,
        List<ModuleVital> vitals)
    {
        var alerts = new List<AutonomousAlert>();

        // Declining score trend (3+ consecutive drops)
        if (runs.Count >= 3)
        {
            var recent = runs.OrderByDescending(r => r.Timestamp).Take(4).ToList();
            if (recent.Count >= 3 &&
                recent[0].OverallScore < recent[1].OverallScore &&
                recent[1].OverallScore < recent[2].OverallScore)
            {
                var drop = recent[2].OverallScore - recent[0].OverallScore;
                alerts.Add(new AutonomousAlert("TREND",
                    "Sustained Score Decline Detected",
                    $"Score has dropped {drop} points over last {recent.Count} scans ({recent.Last().OverallScore}→{recent.First().OverallScore}).",
                    "Run --mission to plan targeted improvements. Run --correlate to find root causes."));
            }
        }

        // Modules below 50
        var critModules = vitals.Where(v => v.Score < 50).ToList();
        if (critModules.Count > 0)
        {
            alerts.Add(new AutonomousAlert("MODULE",
                $"{critModules.Count} Module(s) in Critical State",
                $"Modules scoring below 50: {string.Join(", ", critModules.Select(m => $"{m.Module} ({m.Score:F0})"))}.",
                "Run --triage to prioritize fixes. Run --debt to estimate remediation effort."));
        }

        // Critical count spike
        if (runs.Count >= 2)
        {
            var sorted = runs.OrderByDescending(r => r.Timestamp).Take(2).ToList();
            if (sorted[0].CriticalCount > sorted[1].CriticalCount + 2)
            {
                var spike = sorted[0].CriticalCount - sorted[1].CriticalCount;
                alerts.Add(new AutonomousAlert("SPIKE",
                    "Critical Finding Spike",
                    $"{spike} new critical findings since last scan.",
                    "Run --rootcause to investigate. Run --patrol for targeted inspection."));
            }
        }

        // High finding density
        if (report.TotalFindings > 50)
        {
            alerts.Add(new AutonomousAlert("DENSITY",
                "High Finding Density",
                $"{report.TotalFindings} total findings detected — noise may obscure real threats.",
                "Run --noise to identify false positives. Run --cluster to group related findings."));
        }

        return alerts;
    }

    // ── Report Model ─────────────────────────────────────────────────

    public record NerveCenterReport(
        int ThreatLevel, string ThreatLabel, string ThreatRationale,
        List<ActiveIncident> Incidents,
        List<ModuleVital> Vitals,
        List<SignalEntry> Signals,
        List<ProactiveAction> Actions,
        List<AutonomousAlert> Alerts,
        DateTime GeneratedAt);

    public record ActiveIncident(string Module, string Severity, int Count, int OldestDays, string TopFinding);
    public record ModuleVital(string Module, string Status, double Score, string Trend, double? PrevScore);
    public record SignalEntry(DateTime Timestamp, string Icon, string Message);
    public record ProactiveAction(int Priority, string Tag, string Action, string Rationale);
    public record AutonomousAlert(string Type, string Title, string Description, string Recommendation);
}
