using System.Collections.Concurrent;

namespace WinSentinel.Agent;

/// <summary>
/// Thread-safe in-memory threat event log with bounded size.
/// Supports event streaming to IPC subscribers.
/// </summary>
public class ThreatLog
{
    private readonly ConcurrentQueue<ThreatEvent> _events = new();
    private readonly ConcurrentDictionary<string, ThreatEvent> _index = new();
    private int _count;
    private int _maxSize;

    /// <summary>Event fired when a new threat is logged.</summary>
    public event Action<ThreatEvent>? ThreatDetected;

    public ThreatLog(int maxSize = 1000)
    {
        _maxSize = maxSize;
    }

    /// <summary>Update the max size (from config changes).</summary>
    public void SetMaxSize(int maxSize)
    {
        _maxSize = Math.Max(10, maxSize);
        TrimExcess();
    }

    /// <summary>Add a threat event, index it, and notify subscribers.</summary>
    public void Add(ThreatEvent threat)
    {
        _events.Enqueue(threat);
        _index[threat.Id] = threat;
        Interlocked.Increment(ref _count);
        TrimExcess();
        ThreatDetected?.Invoke(threat);
    }

    /// <summary>O(1) lookup of a threat event by its ID.</summary>
    public ThreatEvent? FindById(string id) =>
        _index.TryGetValue(id, out var e) ? e : null;

    /// <summary>Get all events (newest first).</summary>
    public List<ThreatEvent> GetAll() =>
        _events.Reverse().ToList();

    /// <summary>
    /// Get the most recent N events (newest first).
    /// Snapshots the queue to an array and iterates from the end,
    /// avoiding the O(n) full-reverse that the previous implementation performed.
    /// </summary>
    public List<ThreatEvent> GetRecent(int count = 50)
    {
        var snapshot = _events.ToArray();
        var result = new List<ThreatEvent>(Math.Min(count, snapshot.Length));
        for (int i = snapshot.Length - 1; i >= 0 && result.Count < count; i--)
        {
            result.Add(snapshot[i]);
        }
        return result;
    }

    /// <summary>
    /// Get events from today only (newest first).
    /// Iterates the full snapshot since callers may Add() out-of-order events
    /// (e.g. backfilled or historical threats), so an early-break on the first
    /// non-today event would under-report.
    /// </summary>
    public List<ThreatEvent> GetToday()
    {
        var today = DateTimeOffset.UtcNow.Date;
        var snapshot = _events.ToArray();
        var result = new List<ThreatEvent>();
        for (int i = snapshot.Length - 1; i >= 0; i--)
        {
            if (snapshot[i].Timestamp.UtcDateTime.Date == today)
                result.Add(snapshot[i]);
        }
        return result;
    }

    /// <summary>
    /// Count of events from today. Iterates the full snapshot for the same
    /// reason as GetToday().
    /// </summary>
    public int GetTodayCount()
    {
        var today = DateTimeOffset.UtcNow.Date;
        var snapshot = _events.ToArray();
        int count = 0;
        for (int i = snapshot.Length - 1; i >= 0; i--)
        {
            if (snapshot[i].Timestamp.UtcDateTime.Date == today)
                count++;
        }
        return count;
    }

    /// <summary>Total events in log.</summary>
    public int Count => _count;

    private void TrimExcess()
    {
        while (_count > _maxSize && _events.TryDequeue(out var evicted))
        {
            _index.TryRemove(evicted.Id, out _);
            Interlocked.Decrement(ref _count);
        }
    }
}
