namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Security Flight Recorder — black-box event recorder that reviews scan history
/// and builds a circular-buffer style log of significant security events with
/// forensic dump capability and proactive insights.
/// </summary>
public class SecurityFlightRecorderService
{
    private readonly AuditHistoryService _history;

    public SecurityFlightRecorderService(AuditHistoryService history) => _history = history;

    public FlightRecorderResult Record(int days, int capacity, string? severityFilter,
        string? moduleFilter, bool criticalOnly)
    {
        var result = new FlightRecorderResult { Capacity = capacity, DaysAnalyzed = days };
        var runs = _history.GetHistory(days);
        if (runs.Count < 2) return result;

        // Runs come newest-first from GetHistory; reverse for chronological processing
        var ordered = runs.OrderBy(r => r.Timestamp).ToList();
        var events = new List<FlightRecorderEvent>();

        for (int i = 1; i < ordered.Count; i++)
        {
            var prev = ordered[i - 1];
            var curr = ordered[i];

            // Score changes
            var scoreDelta = curr.OverallScore - prev.OverallScore;
            if (scoreDelta <= -5)
            {
                events.Add(new FlightRecorderEvent
                {
                    Timestamp = curr.Timestamp,
                    EventType = "ScoreDrop",
                    Severity = scoreDelta <= -15 ? "Critical" : scoreDelta <= -10 ? "Warning" : "Info",
                    Description = $"Score dropped {Math.Abs(scoreDelta)} points ({prev.OverallScore} → {curr.OverallScore})",
                    Data = { ["from"] = prev.OverallScore, ["to"] = curr.OverallScore, ["delta"] = scoreDelta }
                });
            }
            else if (scoreDelta >= 5)
            {
                events.Add(new FlightRecorderEvent
                {
                    Timestamp = curr.Timestamp,
                    EventType = "ScoreGain",
                    Severity = "Info",
                    Description = $"Score improved {scoreDelta} points ({prev.OverallScore} → {curr.OverallScore})",
                    Data = { ["from"] = prev.OverallScore, ["to"] = curr.OverallScore, ["delta"] = scoreDelta }
                });
            }

            // New critical/high findings
            var prevTitles = new HashSet<string>(prev.Findings.Select(f => f.Title));
            foreach (var f in curr.Findings)
            {
                if (!prevTitles.Contains(f.Title))
                {
                    var sev = f.Severity.ToLowerInvariant();
                    if (sev is "critical" or "high")
                    {
                        events.Add(new FlightRecorderEvent
                        {
                            Timestamp = curr.Timestamp,
                            EventType = "NewCritical",
                            Severity = sev == "critical" ? "Critical" : "Warning",
                            Module = f.ModuleName,
                            Description = $"New {sev} finding: {f.Title}",
                            Data = { ["finding"] = f.Title, ["severity"] = sev, ["module"] = f.ModuleName }
                        });
                    }
                }
            }

            // Resolved critical/high findings
            var currTitles = new HashSet<string>(curr.Findings.Select(f => f.Title));
            foreach (var pf in prev.Findings)
            {
                if (!currTitles.Contains(pf.Title) && pf.Severity.ToLowerInvariant() is "critical" or "high")
                {
                    events.Add(new FlightRecorderEvent
                    {
                        Timestamp = curr.Timestamp,
                        EventType = "FindingResolved",
                        Severity = "Info",
                        Module = pf.ModuleName,
                        Description = $"Resolved: {pf.Title}",
                        Data = { ["finding"] = pf.Title, ["module"] = pf.ModuleName }
                    });
                }
            }

            // Module regressions (finding count spikes)
            var prevByModule = prev.Findings.GroupBy(f => f.ModuleName)
                .ToDictionary(g => g.Key, g => g.Count());
            var currByModule = curr.Findings.GroupBy(f => f.ModuleName)
                .ToDictionary(g => g.Key, g => g.Count());

            foreach (var (mod, count) in currByModule)
            {
                var prevCount = prevByModule.GetValueOrDefault(mod, 0);
                if (count >= prevCount + 3)
                {
                    events.Add(new FlightRecorderEvent
                    {
                        Timestamp = curr.Timestamp,
                        EventType = "ModuleRegression",
                        Severity = count >= prevCount + 5 ? "Critical" : "Warning",
                        Module = mod,
                        Description = $"Module '{mod}' findings jumped from {prevCount} to {count}",
                        Data = { ["module"] = mod, ["from"] = prevCount, ["to"] = count }
                    });
                }
            }

            // Critical count spike
            if (curr.CriticalCount > prev.CriticalCount + 2)
            {
                events.Add(new FlightRecorderEvent
                {
                    Timestamp = curr.Timestamp,
                    EventType = "CriticalSpike",
                    Severity = "Critical",
                    Description = $"Critical findings spiked from {prev.CriticalCount} to {curr.CriticalCount}",
                    Data = { ["from"] = prev.CriticalCount, ["to"] = curr.CriticalCount }
                });
            }

            // Milestones
            if (curr.OverallScore >= 90 && prev.OverallScore < 90)
            {
                events.Add(new FlightRecorderEvent
                {
                    Timestamp = curr.Timestamp,
                    EventType = "Milestone",
                    Severity = "Info",
                    Description = $"Crossed 90-point threshold (score: {curr.OverallScore})"
                });
            }
            if (curr.OverallScore < 50 && prev.OverallScore >= 50)
            {
                events.Add(new FlightRecorderEvent
                {
                    Timestamp = curr.Timestamp,
                    EventType = "Milestone",
                    Severity = "Critical",
                    Description = $"Score dropped below 50-point critical threshold (score: {curr.OverallScore})"
                });
            }
        }

        // Apply filters
        if (criticalOnly)
            events = events.Where(e => e.Severity == "Critical").ToList();
        if (!string.IsNullOrEmpty(severityFilter))
            events = events.Where(e => e.Severity.Equals(severityFilter, StringComparison.OrdinalIgnoreCase)).ToList();
        if (!string.IsNullOrEmpty(moduleFilter))
            events = events.Where(e => e.Module.Contains(moduleFilter, StringComparison.OrdinalIgnoreCase)).ToList();

        // Circular buffer — keep most recent up to capacity
        result.TotalEventsRecorded = events.Count;
        events = events.OrderByDescending(e => e.Timestamp).Take(capacity).OrderBy(e => e.Timestamp).ToList();
        result.Events = events;

        if (events.Count > 0)
        {
            result.OldestEvent = events[0].Timestamp;
            result.NewestEvent = events[^1].Timestamp;
        }

        result.EventTypeCounts = events.GroupBy(e => e.EventType).ToDictionary(g => g.Key, g => g.Count());
        result.SeverityCounts = events.GroupBy(e => e.Severity).ToDictionary(g => g.Key, g => g.Count());
        result.OverallVolatility = days > 0 ? Math.Round((double)events.Count / days, 2) : 0;

        // Proactive insights
        var critCount = result.SeverityCounts.GetValueOrDefault("Critical", 0);
        if (critCount > 5)
            result.ProactiveInsights.Add($"High critical event rate ({critCount} critical events) — consider increasing audit frequency");
        if (result.OverallVolatility > 2)
            result.ProactiveInsights.Add($"High volatility ({result.OverallVolatility} events/day) — security posture is unstable");
        if (result.EventTypeCounts.GetValueOrDefault("ScoreDrop", 0) > result.EventTypeCounts.GetValueOrDefault("ScoreGain", 0))
            result.ProactiveInsights.Add("More score drops than gains — negative security trend detected");
        if (result.EventTypeCounts.GetValueOrDefault("FindingResolved", 0) > 0)
            result.ProactiveInsights.Add($"{result.EventTypeCounts["FindingResolved"]} findings resolved — remediation efforts are working");
        if (result.EventTypeCounts.GetValueOrDefault("CriticalSpike", 0) > 0)
            result.ProactiveInsights.Add("Critical finding spikes detected — investigate root cause of sudden escalations");
        if (events.Count == 0)
            result.ProactiveInsights.Add("No significant events recorded — either very stable or insufficient scan history");

        return result;
    }
}

// ── Models ───────────────────────────────────────────────────────────

public class FlightRecorderEvent
{
    public DateTimeOffset Timestamp { get; set; }
    public string EventType { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Module { get; set; } = "";
    public string Description { get; set; } = "";
    public Dictionary<string, object> Data { get; set; } = new();
}

public class FlightRecorderResult
{
    public List<FlightRecorderEvent> Events { get; set; } = [];
    public int TotalEventsRecorded { get; set; }
    public int Capacity { get; set; }
    public int DaysAnalyzed { get; set; }
    public DateTimeOffset? OldestEvent { get; set; }
    public DateTimeOffset? NewestEvent { get; set; }
    public Dictionary<string, int> EventTypeCounts { get; set; } = new();
    public Dictionary<string, int> SeverityCounts { get; set; } = new();
    public List<string> ProactiveInsights { get; set; } = [];
    public double OverallVolatility { get; set; }
}
