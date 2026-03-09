using System.Collections.Concurrent;

namespace WinSentinel.Agent;

/// <summary>
/// Thread-safe rate limiter for threat events. Deduplicates alerts
/// by building a key from source + title + description snippet.
///
/// Replaces duplicated rate-limiting logic across
/// ProcessMonitorModule, NetworkMonitorModule, EventLogMonitorModule,
/// and FileSystemMonitorModule.
/// </summary>
public sealed class ThreatRateLimiter
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentAlerts = new();
    private readonly int _rateLimitSeconds;
    private readonly int _descriptionSnippetLength;

    /// <summary>
    /// Create a rate limiter with the specified cooldown and key-building parameters.
    /// </summary>
    /// <param name="rateLimitSeconds">Minimum seconds between identical alerts.</param>
    /// <param name="descriptionSnippetLength">
    /// How many characters of the description to include in the dedup key (default 80).
    /// </param>
    public ThreatRateLimiter(int rateLimitSeconds, int descriptionSnippetLength = 80)
    {
        if (rateLimitSeconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(rateLimitSeconds), "Must be positive.");
        if (descriptionSnippetLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(descriptionSnippetLength), "Must be positive.");

        _rateLimitSeconds = rateLimitSeconds;
        _descriptionSnippetLength = descriptionSnippetLength;
    }

    /// <summary>
    /// Returns true if this threat was already reported recently (should be suppressed).
    /// If not rate-limited, records the alert timestamp.
    /// </summary>
    public bool ShouldRateLimit(ThreatEvent threat)
    {
        var desc = threat.Description ?? "";
        var snippet = desc.Length > _descriptionSnippetLength
            ? desc[.._descriptionSnippetLength]
            : desc;
        var key = $"{threat.Source}|{threat.Title}|{snippet}";
        return ShouldRateLimitByKey(key);
    }

    /// <summary>
    /// Rate-limit by an arbitrary string key.
    /// Useful for non-ThreatEvent dedup (e.g. file-path alerts).
    /// </summary>
    public bool ShouldRateLimitByKey(string key)
    {
        if (_recentAlerts.TryGetValue(key, out var lastAlert))
        {
            if ((DateTimeOffset.UtcNow - lastAlert).TotalSeconds < _rateLimitSeconds)
                return true;
        }
        _recentAlerts[key] = DateTimeOffset.UtcNow;
        return false;
    }

    /// <summary>
    /// Purge stale entries older than 2× the rate-limit window.
    /// Call periodically from the module's cache cleanup loop.
    /// </summary>
    public void PurgeStale()
    {
        var cutoff = DateTimeOffset.UtcNow.AddSeconds(-_rateLimitSeconds * 2);
        foreach (var key in _recentAlerts.Keys.ToList())
        {
            if (_recentAlerts.TryGetValue(key, out var ts) && ts < cutoff)
                _recentAlerts.TryRemove(key, out _);
        }
    }

    /// <summary>Clear all tracked alerts.</summary>
    public void Clear() => _recentAlerts.Clear();

    /// <summary>Number of currently tracked alert keys.</summary>
    public int Count => _recentAlerts.Count;
}
