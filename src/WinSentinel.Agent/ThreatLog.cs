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

    /// <summary>Get the most recent N events.</summary>
    public List<ThreatEvent> GetRecent(int count = 50) =>
        _events.Reverse().Take(count).ToList();

    /// <summary>Get events from today only.</summary>
    public List<ThreatEvent> GetToday()
    {
        var today = DateTimeOffset.UtcNow.Date;
        return _events.Where(e => e.Timestamp.UtcDateTime.Date == today).Reverse().ToList();
    }

    /// <summary>Count of events from today.</summary>
    public int GetTodayCount()
    {
        var today = DateTimeOffset.UtcNow.Date;
        return _events.Count(e => e.Timestamp.UtcDateTime.Date == today);
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
