using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Represents a correlated group of threat events that form an attack chain.
/// </summary>
public class CorrelatedThreat
{
    /// <summary>Unique correlation ID.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    /// <summary>The individual events that contributed to this correlation.</summary>
    public List<ThreatEvent> ContributingEvents { get; set; } = new();

    /// <summary>The combined severity (elevated from individual events).</summary>
    public ThreatSeverity CombinedSeverity { get; set; }

    /// <summary>Description of the attack chain.</summary>
    public string ChainDescription { get; set; } = "";

    /// <summary>Name of the correlation rule that matched.</summary>
    public string RuleName { get; set; } = "";

    /// <summary>Combined threat score (sum of individual scores + correlation bonus).</summary>
    public int ThreatScore { get; set; }

    /// <summary>When this correlation was first detected.</summary>
    public DateTimeOffset DetectedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Cross-module threat correlation engine.
/// Maintains a sliding window of recent events and looks for attack chain patterns.
/// </summary>
public class ThreatCorrelator
{
    private readonly ILogger<ThreatCorrelator> _logger;
    private readonly ConcurrentQueue<ThreatEvent> _eventWindow = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentCorrelations = new();
    private readonly object _correlationLock = new();

    /// <summary>Sliding window duration (default 5 minutes).</summary>
    public TimeSpan CorrelationWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Minimum cooldown between identical correlations.</summary>
    public TimeSpan CorrelationCooldown { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Event raised when a correlation is detected.</summary>
    public event Action<CorrelatedThreat>? CorrelationDetected;

    public ThreatCorrelator(ILogger<ThreatCorrelator> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Add a new threat event to the correlation window and check for patterns.
    /// Returns any new correlations detected.
    /// </summary>
    public List<CorrelatedThreat> ProcessEvent(ThreatEvent newEvent)
    {
        _eventWindow.Enqueue(newEvent);

        var correlations = new List<CorrelatedThreat>();

        lock (_correlationLock)
        {
            TrimWindow();
            var windowEvents = _eventWindow.ToList();

            // Run all correlation rules
            CheckProcessPlusDll(newEvent, windowEvents, correlations);
            CheckDefenderPlusUnsigned(newEvent, windowEvents, correlations);
            CheckBruteForceChain(newEvent, windowEvents, correlations);
            CheckHostsFileAndProcess(newEvent, windowEvents, correlations);
            CheckRapidMultiModule(newEvent, windowEvents, correlations);
        }

        // Emit correlations
        foreach (var corr in correlations)
        {
            _logger.LogWarning(
                "[CORRELATION] {Rule}: {Desc} (Score: {Score}, Severity: {Severity})",
                corr.RuleName, corr.ChainDescription, corr.ThreatScore, corr.CombinedSeverity);

            CorrelationDetected?.Invoke(corr);
        }

        return correlations;
    }

    /// <summary>
    /// Get all events currently in the correlation window.
    /// </summary>
    public List<ThreatEvent> GetWindowEvents()
    {
        lock (_correlationLock)
        {
            TrimWindow();
            return _eventWindow.ToList();
        }
    }

    /// <summary>
    /// Clear the correlation window and state.
    /// </summary>
    public void Reset()
    {
        lock (_correlationLock)
        {
            while (_eventWindow.TryDequeue(out _)) { }
        }
        _recentCorrelations.Clear();
    }

    // ══════════════════════════════════════════
    //  Correlation Rules
    // ══════════════════════════════════════════

    /// <summary>
    /// Attempts a bidirectional correlation: checks whether the new event matches
    /// either side of a two-sided pattern (A↔B) and finds a matching counterpart
    /// in the window. This eliminates the duplicated forward/reverse logic that
    /// previously existed in every correlation rule.
    /// </summary>
    /// <param name="newEvent">The event that just arrived.</param>
    /// <param name="window">Current sliding window of events.</param>
    /// <param name="matchesSideA">Predicate: does this event look like "side A"?</param>
    /// <param name="matchesSideB">Predicate: does this event look like "side B"?</param>
    /// <param name="areRelated">Optional pairwise check (e.g. same directory). Null = always related.</param>
    /// <returns>
    /// A tuple of (sideA, sideB) events if a correlation is found, or null if no match.
    /// The first element is always the side-A event; second is side-B.
    /// </returns>
    private (ThreatEvent sideA, ThreatEvent sideB)? TryBidirectionalMatch(
        ThreatEvent newEvent,
        List<ThreatEvent> window,
        Func<ThreatEvent, bool> matchesSideA,
        Func<ThreatEvent, bool> matchesSideB,
        Func<ThreatEvent, ThreatEvent, bool>? areRelated = null)
    {
        areRelated ??= (_, _) => true;

        if (matchesSideA(newEvent))
        {
            var counterpart = window.FirstOrDefault(e =>
                e.Id != newEvent.Id && matchesSideB(e) && areRelated(newEvent, e));
            if (counterpart != null)
                return (newEvent, counterpart);
        }
        else if (matchesSideB(newEvent))
        {
            var counterpart = window.FirstOrDefault(e =>
                e.Id != newEvent.Id && matchesSideA(e) && areRelated(e, newEvent));
            if (counterpart != null)
                return (counterpart, newEvent);
        }

        return null;
    }

    /// <summary>
    /// Rule 1: Suspicious process + new DLL in same directory = DLL sideloading attack.
    /// </summary>
    internal void CheckProcessPlusDll(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        var match = TryBidirectionalMatch(
            newEvent, window,
            matchesSideA: e => e.Source == "FileSystemMonitor" &&
                        e.Title.Contains("DLL", StringComparison.OrdinalIgnoreCase),
            matchesSideB: e => e.Source == "ProcessMonitor" && e.Severity >= ThreatSeverity.Medium,
            areRelated: (dllEvent, processEvent) =>
            {
                var dir = ExtractDirectory(dllEvent.Description);
                return !string.IsNullOrEmpty(dir) &&
                       processEvent.Description.Contains(dir, StringComparison.OrdinalIgnoreCase);
            });

        if (match == null) return;

        var (dllEvt, processEvt) = match.Value;
        var dllDir = ExtractDirectory(dllEvt.Description) ?? "";

        if (!IsRecentCorrelation("ProcessPlusDll", dllDir))
        {
            results.Add(new CorrelatedThreat
            {
                ContributingEvents = { processEvt, dllEvt },
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "ProcessPlusDll",
                ChainDescription = $"Suspicious process detected alongside new DLL in same directory. " +
                                   $"Process: {processEvt.Title}. DLL: {dllEvt.Title}. " +
                                   $"This combination strongly suggests DLL sideloading or injection.",
                ThreatScore = CalculateChainScore(processEvt, dllEvt) + 30
            });
        }
    }

    /// <summary>
    /// Rule 2: Defender disabled + new unsigned process from temp = critical chain.
    /// </summary>
    internal void CheckDefenderPlusUnsigned(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        static bool IsDefenderDisable(ThreatEvent e) =>
            e.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
            e.Title.Contains("Disabled", StringComparison.OrdinalIgnoreCase);

        static bool IsSuspiciousProcess(ThreatEvent e) =>
            e.Source == "ProcessMonitor" &&
            e.Severity >= ThreatSeverity.Medium;

        var match = TryBidirectionalMatch(
            newEvent, window,
            matchesSideA: IsDefenderDisable,
            matchesSideB: IsSuspiciousProcess);

        if (match == null) return;

        var (defenderEvent, processEvent) = match.Value;

        if (!IsRecentCorrelation("DefenderPlusUnsigned", newEvent.Id))
        {
            results.Add(new CorrelatedThreat
            {
                ContributingEvents = { defenderEvent, processEvent },
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "DefenderPlusUnsigned",
                ChainDescription = $"Windows Defender was disabled, and a suspicious/unsigned process was detected. " +
                                   $"Process: {processEvent.Title}. " +
                                   $"This is a classic attack pattern: disable defenses, then deploy payload.",
                ThreatScore = CalculateChainScore(defenderEvent, processEvent) + 50
            });
        }
    }

    /// <summary>
    /// Rule 3: Failed logons + new connections from unusual IPs = possible breach.
    /// Event log brute force + network activity correlation.
    /// </summary>
    internal void CheckBruteForceChain(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        if (newEvent.Source != "EventLogMonitor") return;

        static bool IsBruteForce(ThreatEvent e) =>
            e.Source == "EventLogMonitor" &&
            e.Title.Contains("Brute Force", StringComparison.OrdinalIgnoreCase);

        static bool IsEscalation(ThreatEvent e) =>
            e.Source == "EventLogMonitor" &&
            (e.Title.Contains("Privilege", StringComparison.OrdinalIgnoreCase) ||
             e.Title.Contains("Account Created", StringComparison.OrdinalIgnoreCase) ||
             e.Title.Contains("Kill Chain", StringComparison.OrdinalIgnoreCase));

        var match = TryBidirectionalMatch(newEvent, window, IsBruteForce, IsEscalation);

        if (match == null) return;

        var (bruteForce, escalation) = match.Value;

        if (!IsRecentCorrelation("BruteForceChain", newEvent.Id))
        {
            results.Add(new CorrelatedThreat
            {
                ContributingEvents = { bruteForce, escalation },
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "BruteForceChain",
                ChainDescription = $"Brute force attack detected alongside {escalation.Title}. " +
                                   $"An attacker may have gained access and is escalating privileges.",
                ThreatScore = CalculateChainScore(bruteForce, escalation) + 40
            });
        }
    }

    /// <summary>
    /// Rule 4: Hosts file modification + suspicious process = DNS hijacking with malware.
    /// Uses TryBidirectionalMatch to avoid self-correlation (newEvent being picked as
    /// both sides) and generates a stable dedup key from the matched event pair.
    /// </summary>
    internal void CheckHostsFileAndProcess(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        var match = TryBidirectionalMatch(
            newEvent, window,
            matchesSideA: e => e.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase),
            matchesSideB: e => e.Source == "ProcessMonitor" && e.Severity >= ThreatSeverity.Medium);

        if (match == null) return;

        var (hostsEvent, processEvent) = match.Value;

        // Use both event IDs for the dedup key so unrelated pairs don't block each other
        if (!IsRecentCorrelation("HostsFilePlusProcess", $"{hostsEvent.Id}|{processEvent.Id}"))
        {
            results.Add(new CorrelatedThreat
            {
                ContributingEvents = { hostsEvent, processEvent },
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "HostsFilePlusProcess",
                ChainDescription = $"Hosts file modification detected alongside suspicious process activity. " +
                                   $"Process: {processEvent.Title}. " +
                                   $"This combination suggests DNS hijacking as part of a malware attack.",
                ThreatScore = CalculateChainScore(hostsEvent, processEvent) + 25
            });
        }
    }

    /// <summary>
    /// Rule 5: Rapid multi-module activity — events from 3+ different sources in the window = coordinated attack.
    /// </summary>
    internal void CheckRapidMultiModule(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        // Only check for medium+ severity events
        if (newEvent.Severity < ThreatSeverity.Medium) return;

        var significantEvents = window.Where(e => e.Severity >= ThreatSeverity.Medium).ToList();
        var distinctSources = significantEvents.Select(e => e.Source).Distinct().ToList();

        if (distinctSources.Count < 3) return;

        // Only fire if newEvent is the one that pushed the distinct source count to 3+.
        // Check: without newEvent's source, would we still have 3+ distinct sources?
        var sourcesWithoutNew = significantEvents
            .Where(e => e.Id != newEvent.Id)
            .Select(e => e.Source)
            .Distinct()
            .Count();

        if (sourcesWithoutNew >= 3) return; // Already had 3+, newEvent didn't push us over

        if (!IsRecentCorrelation("RapidMultiModule", ""))
        {
            results.Add(new CorrelatedThreat
            {
                ContributingEvents = significantEvents.Take(10).ToList(),
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "RapidMultiModule",
                ChainDescription = $"Coordinated attack suspected: {significantEvents.Count} significant events " +
                                   $"detected across {distinctSources.Count} modules ({string.Join(", ", distinctSources)}) " +
                                   $"within {CorrelationWindow.TotalMinutes} minutes.",
                ThreatScore = significantEvents.Sum(e => SeverityScore(e.Severity)) + 20
            });
        }
    }

    // ══════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════

    private void TrimWindow()
    {
        var cutoff = DateTimeOffset.UtcNow - CorrelationWindow;
        while (_eventWindow.TryPeek(out var oldest) && oldest.Timestamp < cutoff)
        {
            _eventWindow.TryDequeue(out _);
        }

        // Also trim old correlations
        var corrCutoff = DateTimeOffset.UtcNow - CorrelationCooldown;
        foreach (var key in _recentCorrelations.Keys.ToList())
        {
            if (_recentCorrelations.TryGetValue(key, out var ts) && ts < corrCutoff)
                _recentCorrelations.TryRemove(key, out _);
        }
    }

    private bool IsRecentCorrelation(string ruleName, string context)
    {
        var key = $"{ruleName}|{context}";
        if (_recentCorrelations.TryGetValue(key, out var lastTime))
        {
            if ((DateTimeOffset.UtcNow - lastTime) < CorrelationCooldown)
                return true;
        }
        _recentCorrelations[key] = DateTimeOffset.UtcNow;
        return false;
    }

    internal static int CalculateChainScore(params ThreatEvent[] events)
    {
        return events.Sum(e => SeverityScore(e.Severity));
    }

    internal static int SeverityScore(ThreatSeverity severity) => severity switch
    {
        ThreatSeverity.Critical => 40,
        ThreatSeverity.High => 25,
        ThreatSeverity.Medium => 15,
        ThreatSeverity.Low => 5,
        ThreatSeverity.Info => 1,
        _ => 0
    };

    /// <summary>Extract a directory path from a threat description.</summary>
    internal static string? ExtractDirectory(string description)
    {
        // Look for "Path: C:\...\..." pattern
        var pathIdx = description.IndexOf("Path:", StringComparison.OrdinalIgnoreCase);
        if (pathIdx >= 0)
        {
            var pathStart = pathIdx + 5;
            while (pathStart < description.Length && description[pathStart] == ' ')
                pathStart++;

            var pathEnd = description.IndexOfAny(new[] { '\n', '\r', '.', ',' }, pathStart);
            if (pathEnd < 0) pathEnd = description.Length;

            var fullPath = description[pathStart..pathEnd].Trim();
            try
            {
                return Path.GetDirectoryName(fullPath);
            }
            catch
            {
                return null;
            }
        }
        return null;
    }
}
