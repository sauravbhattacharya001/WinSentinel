using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Types of journal entries.
/// </summary>
public enum JournalEntryType
{
    ThreatDetected,
    DecisionMade,
    ActionTaken,
    ActionUndone,
    CorrelationDetected,
    UserFeedback,
    AgentStarted,
    AgentStopped,
    ConfigChanged
}

/// <summary>
/// A single journal entry recording agent activity.
/// </summary>
public class JournalEntry
{
    /// <summary>Unique ID.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    /// <summary>When this entry was created.</summary>
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Type of journal entry.</summary>
    public JournalEntryType EntryType { get; set; }

    /// <summary>Source module or component.</summary>
    public string Source { get; set; } = "";

    /// <summary>Human-readable summary.</summary>
    public string Summary { get; set; } = "";

    /// <summary>Detailed description.</summary>
    public string? Details { get; set; }

    /// <summary>Threat severity (if applicable).</summary>
    public ThreatSeverity? Severity { get; set; }

    /// <summary>Related threat event ID.</summary>
    public string? ThreatEventId { get; set; }

    /// <summary>Related remediation record ID.</summary>
    public string? RemediationId { get; set; }

    /// <summary>Policy decision that was made (if applicable).</summary>
    public string? PolicyDecision { get; set; }

    /// <summary>Tags for categorization and search.</summary>
    public List<string> Tags { get; set; } = new();
}

/// <summary>
/// Query parameters for searching the journal.
/// </summary>
public class JournalQuery
{
    /// <summary>Filter by entry type.</summary>
    public JournalEntryType? EntryType { get; set; }

    /// <summary>Filter by source.</summary>
    public string? Source { get; set; }

    /// <summary>Filter by minimum severity.</summary>
    public ThreatSeverity? MinSeverity { get; set; }

    /// <summary>Filter entries after this time.</summary>
    public DateTimeOffset? After { get; set; }

    /// <summary>Filter entries before this time.</summary>
    public DateTimeOffset? Before { get; set; }

    /// <summary>Search text in summary and details.</summary>
    public string? SearchText { get; set; }

    /// <summary>Filter by tag.</summary>
    public string? Tag { get; set; }

    /// <summary>Maximum results to return.</summary>
    public int Limit { get; set; } = 100;
}

/// <summary>
/// Persistent activity journal for the agent.
/// Stores all threat detections, decisions, actions, and user feedback.
/// Uses a JSON-lines file for persistence with in-memory cache for queries.
/// </summary>
public class AgentJournal
{
    private readonly ILogger<AgentJournal> _logger;
    private readonly ConcurrentQueue<JournalEntry> _entries = new();
    private readonly string _journalPath;
    private readonly object _writeLock = new();
    private int _count;

    /// <summary>Maximum entries to keep in memory.</summary>
    public int MaxMemoryEntries { get; set; } = 5000;

    private static readonly string DataDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public AgentJournal(ILogger<AgentJournal> logger) : this(logger, null) { }

    /// <summary>
    /// Create a journal with a custom path (for testing).
    /// Pass null to use the default path.
    /// </summary>
    public AgentJournal(ILogger<AgentJournal> logger, string? journalPath)
    {
        _logger = logger;
        if (journalPath != null)
        {
            _journalPath = journalPath;
            var dir = Path.GetDirectoryName(journalPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        }
        else
        {
            Directory.CreateDirectory(DataDir);
            _journalPath = Path.Combine(DataDir, "agent-journal.jsonl");
        }
        LoadExistingEntries();
    }

    /// <summary>
    /// Record a new journal entry.
    /// </summary>
    public void Record(JournalEntry entry)
    {
        _entries.Enqueue(entry);
        Interlocked.Increment(ref _count);
        TrimMemory();
        PersistEntry(entry);
    }

    /// <summary>
    /// Record a threat detection.
    /// </summary>
    public void RecordThreat(ThreatEvent threat, PolicyDecision? decision = null)
    {
        Record(new JournalEntry
        {
            EntryType = JournalEntryType.ThreatDetected,
            Source = threat.Source,
            Summary = $"[{threat.Severity}] {threat.Title}",
            Details = threat.Description,
            Severity = threat.Severity,
            ThreatEventId = threat.Id,
            PolicyDecision = decision != null
                ? $"{decision.Action} ({decision.MatchedRule})"
                : null,
            Tags = { threat.Source, threat.Severity.ToString() }
        });
    }

    /// <summary>
    /// Record a remediation action.
    /// </summary>
    public void RecordRemediation(RemediationRecord remediation)
    {
        Record(new JournalEntry
        {
            EntryType = JournalEntryType.ActionTaken,
            Source = "AutoRemediator",
            Summary = $"[{remediation.ActionType}] {(remediation.Success ? "✓" : "✗")} {remediation.Target}",
            Details = remediation.Description,
            ThreatEventId = remediation.ThreatEventId,
            RemediationId = remediation.Id,
            Tags = { remediation.ActionType.ToString(), remediation.Success ? "success" : "failed" }
        });
    }

    /// <summary>
    /// Record a correlation detection.
    /// </summary>
    public void RecordCorrelation(CorrelatedThreat correlation)
    {
        Record(new JournalEntry
        {
            EntryType = JournalEntryType.CorrelationDetected,
            Source = "ThreatCorrelator",
            Summary = $"[Correlation] {correlation.RuleName} (Score: {correlation.ThreatScore})",
            Details = correlation.ChainDescription,
            Severity = correlation.CombinedSeverity,
            Tags = { "correlation", correlation.RuleName }
        });
    }

    /// <summary>
    /// Record user feedback on a threat (dismissed, acted on, etc.).
    /// </summary>
    public void RecordUserFeedback(string threatEventId, string feedback, string? action = null)
    {
        Record(new JournalEntry
        {
            EntryType = JournalEntryType.UserFeedback,
            Source = "User",
            Summary = $"User feedback: {feedback}",
            Details = action != null ? $"Action taken: {action}" : null,
            ThreatEventId = threatEventId,
            Tags = { "feedback", feedback }
        });
    }

    // ══════════════════════════════════════════
    //  Queries
    // ══════════════════════════════════════════

    /// <summary>
    /// Query the journal with filters.
    /// </summary>
    public List<JournalEntry> Query(JournalQuery query)
    {
        var results = _entries.AsEnumerable();

        if (query.EntryType.HasValue)
            results = results.Where(e => e.EntryType == query.EntryType.Value);

        if (!string.IsNullOrEmpty(query.Source))
            results = results.Where(e => e.Source.Equals(query.Source, StringComparison.OrdinalIgnoreCase));

        if (query.MinSeverity.HasValue)
            results = results.Where(e => e.Severity.HasValue && e.Severity.Value >= query.MinSeverity.Value);

        if (query.After.HasValue)
            results = results.Where(e => e.Timestamp >= query.After.Value);

        if (query.Before.HasValue)
            results = results.Where(e => e.Timestamp <= query.Before.Value);

        if (!string.IsNullOrEmpty(query.SearchText))
        {
            var text = query.SearchText;
            results = results.Where(e =>
                e.Summary.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                (e.Details?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        if (!string.IsNullOrEmpty(query.Tag))
            results = results.Where(e => e.Tags.Contains(query.Tag, StringComparer.OrdinalIgnoreCase));

        return results
            .OrderByDescending(e => e.Timestamp)
            .Take(query.Limit)
            .ToList();
    }

    /// <summary>Get events from today (UTC).</summary>
    public List<JournalEntry> GetToday() => Query(new JournalQuery
    {
        // Use explicit UTC offset to avoid local timezone skew.
        // DateTimeOffset.Date returns Kind=Unspecified, which would get
        // the local timezone offset in the implicit conversion, shifting
        // the filter forward/backward from midnight UTC.
        After = new DateTimeOffset(DateTimeOffset.UtcNow.Date, TimeSpan.Zero),
        Limit = 500
    });

    /// <summary>Get events from this week.</summary>
    public List<JournalEntry> GetThisWeek() => Query(new JournalQuery
    {
        After = DateTimeOffset.UtcNow.AddDays(-7),
        Limit = 1000
    });

    /// <summary>Get all auto-fix actions from this week.</summary>
    public List<JournalEntry> GetAutoFixesThisWeek() => Query(new JournalQuery
    {
        EntryType = JournalEntryType.ActionTaken,
        After = DateTimeOffset.UtcNow.AddDays(-7),
        Limit = 500
    });

    /// <summary>Get a summary of today's activity.</summary>
    public JournalSummary GetTodaySummary()
    {
        var today = GetToday();
        return BuildSummary(today, "Today");
    }

    /// <summary>Get a summary of this week's activity.</summary>
    public JournalSummary GetWeekSummary()
    {
        var week = GetThisWeek();
        return BuildSummary(week, "This Week");
    }

    /// <summary>Total entries in memory.</summary>
    public int Count => _count;

    // ══════════════════════════════════════════
    //  Internal Helpers
    // ══════════════════════════════════════════

    private JournalSummary BuildSummary(List<JournalEntry> entries, string period)
    {
        return new JournalSummary
        {
            Period = period,
            TotalEvents = entries.Count,
            ThreatsDetected = entries.Count(e => e.EntryType == JournalEntryType.ThreatDetected),
            ActionsTaken = entries.Count(e => e.EntryType == JournalEntryType.ActionTaken),
            CorrelationsDetected = entries.Count(e => e.EntryType == JournalEntryType.CorrelationDetected),
            CriticalCount = entries.Count(e => e.Severity == ThreatSeverity.Critical),
            HighCount = entries.Count(e => e.Severity == ThreatSeverity.High),
            MediumCount = entries.Count(e => e.Severity == ThreatSeverity.Medium),
            LowCount = entries.Count(e => e.Severity == ThreatSeverity.Low || e.Severity == ThreatSeverity.Info),
            TopSources = entries
                .Where(e => !string.IsNullOrEmpty(e.Source))
                .GroupBy(e => e.Source)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .ToDictionary(g => g.Key, g => g.Count()),
            SuccessfulRemediations = entries.Count(e =>
                e.EntryType == JournalEntryType.ActionTaken &&
                e.Tags.Contains("success", StringComparer.OrdinalIgnoreCase)),
            FailedRemediations = entries.Count(e =>
                e.EntryType == JournalEntryType.ActionTaken &&
                e.Tags.Contains("failed", StringComparer.OrdinalIgnoreCase))
        };
    }

    private void LoadExistingEntries()
    {
        try
        {
            if (!File.Exists(_journalPath)) return;

            var lines = File.ReadAllLines(_journalPath);
            var loadCount = 0;

            // Load the most recent entries up to MaxMemoryEntries
            var startIdx = Math.Max(0, lines.Length - MaxMemoryEntries);
            for (var i = startIdx; i < lines.Length; i++)
            {
                try
                {
                    var entry = JsonSerializer.Deserialize<JournalEntry>(lines[i], JsonOpts);
                    if (entry != null)
                    {
                        _entries.Enqueue(entry);
                        Interlocked.Increment(ref _count);
                        loadCount++;
                    }
                }
                catch { /* skip malformed lines */ }
            }

            _logger.LogInformation("Loaded {Count} journal entries from disk", loadCount);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load journal from disk");
        }
    }

    private void PersistEntry(JournalEntry entry)
    {
        lock (_writeLock)
        {
            try
            {
                var json = JsonSerializer.Serialize(entry, JsonOpts);
                File.AppendAllText(_journalPath, json + Environment.NewLine);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to persist journal entry");
            }
        }
    }

    private void TrimMemory()
    {
        while (_count > MaxMemoryEntries && _entries.TryDequeue(out _))
        {
            Interlocked.Decrement(ref _count);
        }
    }
}

/// <summary>
/// Summary of journal activity for a time period.
/// </summary>
public class JournalSummary
{
    public string Period { get; set; } = "";
    public int TotalEvents { get; set; }
    public int ThreatsDetected { get; set; }
    public int ActionsTaken { get; set; }
    public int CorrelationsDetected { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public Dictionary<string, int> TopSources { get; set; } = new();
    public int SuccessfulRemediations { get; set; }
    public int FailedRemediations { get; set; }

    public override string ToString()
    {
        return $"📊 {Period} Summary:\n" +
               $"  Threats: {ThreatsDetected} (🔴{CriticalCount} 🟠{HighCount} 🟡{MediumCount} ⚪{LowCount})\n" +
               $"  Correlations: {CorrelationsDetected}\n" +
               $"  Actions: {ActionsTaken} (✓{SuccessfulRemediations} ✗{FailedRemediations})\n" +
               $"  Top sources: {string.Join(", ", TopSources.Select(kv => $"{kv.Key}({kv.Value})"))}";
    }
}
