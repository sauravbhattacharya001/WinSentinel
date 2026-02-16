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
        TrimWindow();

        var correlations = new List<CorrelatedThreat>();

        lock (_correlationLock)
        {
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
        TrimWindow();
        return _eventWindow.ToList();
    }

    /// <summary>
    /// Clear the correlation window and state.
    /// </summary>
    public void Reset()
    {
        while (_eventWindow.TryDequeue(out _)) { }
        _recentCorrelations.Clear();
    }

    // ══════════════════════════════════════════
    //  Correlation Rules
    // ══════════════════════════════════════════

    /// <summary>
    /// Rule 1: Suspicious process + new DLL in same directory = DLL sideloading attack.
    /// </summary>
    internal void CheckProcessPlusDll(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        // If a new DLL was detected by FileSystemMonitor...
        if (newEvent.Source == "FileSystemMonitor" &&
            newEvent.Title.Contains("DLL", StringComparison.OrdinalIgnoreCase))
        {
            // Look for suspicious process events in the same time window
            var processEvents = window.Where(e =>
                e.Source == "ProcessMonitor" &&
                e.Id != newEvent.Id &&
                e.Severity >= ThreatSeverity.Medium).ToList();

            if (processEvents.Count > 0)
            {
                // Check if any process event is in a related directory
                var dllDir = ExtractDirectory(newEvent.Description);
                var relatedProcess = processEvents.FirstOrDefault(pe =>
                    !string.IsNullOrEmpty(dllDir) &&
                    pe.Description.Contains(dllDir, StringComparison.OrdinalIgnoreCase));

                if (relatedProcess != null && !IsRecentCorrelation("ProcessPlusDll", dllDir ?? ""))
                {
                    results.Add(new CorrelatedThreat
                    {
                        ContributingEvents = { relatedProcess, newEvent },
                        CombinedSeverity = ThreatSeverity.Critical,
                        RuleName = "ProcessPlusDll",
                        ChainDescription = $"Suspicious process detected alongside new DLL in same directory. " +
                                           $"Process: {relatedProcess.Title}. DLL: {newEvent.Title}. " +
                                           $"This combination strongly suggests DLL sideloading or injection.",
                        ThreatScore = CalculateChainScore(relatedProcess, newEvent) + 30
                    });
                }
            }
        }

        // Also check reverse: suspicious process detected, look for recent DLLs
        if (newEvent.Source == "ProcessMonitor" && newEvent.Severity >= ThreatSeverity.Medium)
        {
            var dllEvents = window.Where(e =>
                e.Source == "FileSystemMonitor" &&
                e.Title.Contains("DLL", StringComparison.OrdinalIgnoreCase) &&
                e.Id != newEvent.Id).ToList();

            var processDir = ExtractDirectory(newEvent.Description);
            var relatedDll = dllEvents.FirstOrDefault(de =>
                !string.IsNullOrEmpty(processDir) &&
                de.Description.Contains(processDir, StringComparison.OrdinalIgnoreCase));

            if (relatedDll != null && !IsRecentCorrelation("ProcessPlusDll", processDir ?? ""))
            {
                results.Add(new CorrelatedThreat
                {
                    ContributingEvents = { newEvent, relatedDll },
                    CombinedSeverity = ThreatSeverity.Critical,
                    RuleName = "ProcessPlusDll",
                    ChainDescription = $"Suspicious process detected alongside new DLL in same directory. " +
                                       $"Process: {newEvent.Title}. DLL: {relatedDll.Title}. " +
                                       $"This combination strongly suggests DLL sideloading or injection.",
                    ThreatScore = CalculateChainScore(newEvent, relatedDll) + 30
                });
            }
        }
    }

    /// <summary>
    /// Rule 2: Defender disabled + new unsigned process from temp = critical chain.
    /// </summary>
    internal void CheckDefenderPlusUnsigned(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        bool defenderDisabled = window.Any(e =>
            e.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
            e.Title.Contains("Disabled", StringComparison.OrdinalIgnoreCase));

        if (!defenderDisabled) return;

        bool suspiciousProcess = window.Any(e =>
            e.Source == "ProcessMonitor" &&
            e.Severity >= ThreatSeverity.Medium &&
            (e.Title.Contains("Unsigned", StringComparison.OrdinalIgnoreCase) ||
             e.Title.Contains("Suspicious", StringComparison.OrdinalIgnoreCase) ||
             e.Description.Contains("Temp", StringComparison.OrdinalIgnoreCase)));

        if (newEvent.Source == "ProcessMonitor" && suspiciousProcess &&
            !IsRecentCorrelation("DefenderPlusUnsigned", newEvent.Id))
        {
            var defenderEvent = window.First(e =>
                e.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
                e.Title.Contains("Disabled", StringComparison.OrdinalIgnoreCase));

            results.Add(new CorrelatedThreat
            {
                ContributingEvents = { defenderEvent, newEvent },
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "DefenderPlusUnsigned",
                ChainDescription = $"Windows Defender was disabled, and a suspicious/unsigned process was detected. " +
                                   $"This is a classic attack pattern: disable defenses, then deploy payload.",
                ThreatScore = CalculateChainScore(defenderEvent, newEvent) + 50
            });
        }

        // Also trigger if the new event IS the Defender disable and there are already suspicious processes
        if (newEvent.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
            newEvent.Title.Contains("Disabled", StringComparison.OrdinalIgnoreCase) &&
            suspiciousProcess &&
            !IsRecentCorrelation("DefenderPlusUnsigned", "reverse"))
        {
            var processEvent = window.First(e =>
                e.Source == "ProcessMonitor" &&
                e.Severity >= ThreatSeverity.Medium);

            results.Add(new CorrelatedThreat
            {
                ContributingEvents = { newEvent, processEvent },
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "DefenderPlusUnsigned",
                ChainDescription = $"Windows Defender was just disabled while suspicious processes are running. " +
                                   $"Process: {processEvent.Title}. Immediate investigation required.",
                ThreatScore = CalculateChainScore(newEvent, processEvent) + 50
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

        // Look for brute force + privilege escalation or account creation
        if (newEvent.Title.Contains("Brute Force", StringComparison.OrdinalIgnoreCase))
        {
            // Check for recent successful logon or privilege escalation
            var escalation = window.FirstOrDefault(e =>
                e.Source == "EventLogMonitor" &&
                e.Id != newEvent.Id &&
                (e.Title.Contains("Privilege", StringComparison.OrdinalIgnoreCase) ||
                 e.Title.Contains("Account Created", StringComparison.OrdinalIgnoreCase) ||
                 e.Title.Contains("Kill Chain", StringComparison.OrdinalIgnoreCase)));

            if (escalation != null && !IsRecentCorrelation("BruteForceChain", newEvent.Id))
            {
                results.Add(new CorrelatedThreat
                {
                    ContributingEvents = { newEvent, escalation },
                    CombinedSeverity = ThreatSeverity.Critical,
                    RuleName = "BruteForceChain",
                    ChainDescription = $"Brute force attack detected alongside {escalation.Title}. " +
                                       $"An attacker may have gained access and is escalating privileges.",
                    ThreatScore = CalculateChainScore(newEvent, escalation) + 40
                });
            }
        }
    }

    /// <summary>
    /// Rule 4: Hosts file modification + suspicious process = DNS hijacking with malware.
    /// </summary>
    internal void CheckHostsFileAndProcess(ThreatEvent newEvent, List<ThreatEvent> window, List<CorrelatedThreat> results)
    {
        bool hostsModified = window.Any(e =>
            e.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase));

        bool suspiciousProcess = window.Any(e =>
            e.Source == "ProcessMonitor" &&
            e.Severity >= ThreatSeverity.Medium);

        if (!hostsModified || !suspiciousProcess) return;

        if ((newEvent.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase) ||
             (newEvent.Source == "ProcessMonitor" && newEvent.Severity >= ThreatSeverity.Medium)) &&
            !IsRecentCorrelation("HostsFilePlusProcess", ""))
        {
            var hostsEvent = window.First(e =>
                e.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase));
            var processEvent = window.First(e =>
                e.Source == "ProcessMonitor" && e.Severity >= ThreatSeverity.Medium);

            results.Add(new CorrelatedThreat
            {
                ContributingEvents = { hostsEvent, processEvent },
                CombinedSeverity = ThreatSeverity.Critical,
                RuleName = "HostsFilePlusProcess",
                ChainDescription = $"Hosts file modification detected alongside suspicious process activity. " +
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
        var significantEvents = window.Where(e => e.Severity >= ThreatSeverity.Medium).ToList();
        var distinctSources = significantEvents.Select(e => e.Source).Distinct().ToList();

        if (distinctSources.Count >= 3 && !IsRecentCorrelation("RapidMultiModule", ""))
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
