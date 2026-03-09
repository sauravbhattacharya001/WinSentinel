using WinSentinel.Agent;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for the shared ThreatRateLimiter.
/// </summary>
public class ThreatRateLimiterTests
{
    private static ThreatEvent MakeThreat(string title = "Test", string desc = "desc", string source = "Module")
    {
        return new ThreatEvent { Source = source, Title = title, Description = desc, Severity = ThreatSeverity.Medium };
    }

    // ── Constructor validation ──

    [Fact]
    public void Constructor_ZeroSeconds_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ThreatRateLimiter(0));
    }

    [Fact]
    public void Constructor_NegativeSnippetLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ThreatRateLimiter(30, -1));
    }

    // ── ShouldRateLimit (ThreatEvent) ──

    [Fact]
    public void FirstEvent_NotRateLimited()
    {
        var rl = new ThreatRateLimiter(300); // long window so it doesn't expire
        Assert.False(rl.ShouldRateLimit(MakeThreat()));
    }

    [Fact]
    public void DuplicateEvent_IsRateLimited()
    {
        var rl = new ThreatRateLimiter(300);
        var threat = MakeThreat();
        rl.ShouldRateLimit(threat); // first — records it
        Assert.True(rl.ShouldRateLimit(threat)); // duplicate — suppressed
    }

    [Fact]
    public void DifferentTitle_NotRateLimited()
    {
        var rl = new ThreatRateLimiter(300);
        rl.ShouldRateLimit(MakeThreat("Alert A"));
        Assert.False(rl.ShouldRateLimit(MakeThreat("Alert B")));
    }

    [Fact]
    public void DifferentSource_NotRateLimited()
    {
        var rl = new ThreatRateLimiter(300);
        rl.ShouldRateLimit(MakeThreat(source: "ModuleA"));
        Assert.False(rl.ShouldRateLimit(MakeThreat(source: "ModuleB")));
    }

    [Fact]
    public void DifferentDescription_NotRateLimited()
    {
        var rl = new ThreatRateLimiter(300);
        rl.ShouldRateLimit(MakeThreat(desc: "Something happened on port 443"));
        Assert.False(rl.ShouldRateLimit(MakeThreat(desc: "Something happened on port 8080")));
    }

    [Fact]
    public void DescriptionTruncation_IgnoresTailDifferences()
    {
        // With snippet length 10, descriptions sharing the first 10 chars
        // should be treated as the same event
        var rl = new ThreatRateLimiter(300, descriptionSnippetLength: 10);
        rl.ShouldRateLimit(MakeThreat(desc: "0123456789AAAA"));
        Assert.True(rl.ShouldRateLimit(MakeThreat(desc: "0123456789BBBB")));
    }

    [Fact]
    public void NullDescription_DoesNotThrow()
    {
        var rl = new ThreatRateLimiter(300);
        var threat = MakeThreat();
        threat.Description = null!;
        Assert.False(rl.ShouldRateLimit(threat));
    }

    // ── ShouldRateLimitByKey ──

    [Fact]
    public void ByKey_FirstCall_NotRateLimited()
    {
        var rl = new ThreatRateLimiter(300);
        Assert.False(rl.ShouldRateLimitByKey("key1"));
    }

    [Fact]
    public void ByKey_DuplicateKey_IsRateLimited()
    {
        var rl = new ThreatRateLimiter(300);
        rl.ShouldRateLimitByKey("key1");
        Assert.True(rl.ShouldRateLimitByKey("key1"));
    }

    [Fact]
    public void ByKey_DifferentKeys_NotRateLimited()
    {
        var rl = new ThreatRateLimiter(300);
        rl.ShouldRateLimitByKey("key1");
        Assert.False(rl.ShouldRateLimitByKey("key2"));
    }

    // ── Clear ──

    [Fact]
    public void Clear_ResetsAllTracking()
    {
        var rl = new ThreatRateLimiter(300);
        rl.ShouldRateLimit(MakeThreat());
        Assert.Equal(1, rl.Count);

        rl.Clear();
        Assert.Equal(0, rl.Count);
        // Same event should pass again
        Assert.False(rl.ShouldRateLimit(MakeThreat()));
    }

    // ── PurgeStale ──

    [Fact]
    public void PurgeStale_RemovesOldEntries()
    {
        // Use a very short rate limit so entries become stale immediately
        var rl = new ThreatRateLimiter(1); // 1 second
        rl.ShouldRateLimit(MakeThreat());
        Assert.Equal(1, rl.Count);

        // Wait for entries to become stale (need > 2× rate limit = 2s)
        System.Threading.Thread.Sleep(2100);
        rl.PurgeStale();
        Assert.Equal(0, rl.Count);
    }

    [Fact]
    public void PurgeStale_KeepsFreshEntries()
    {
        var rl = new ThreatRateLimiter(300); // 5 minute window
        rl.ShouldRateLimit(MakeThreat("A"));
        rl.ShouldRateLimit(MakeThreat("B"));
        rl.PurgeStale();
        Assert.Equal(2, rl.Count); // Still fresh
    }

    // ── Count ──

    [Fact]
    public void Count_TracksDistinctAlerts()
    {
        var rl = new ThreatRateLimiter(300);
        rl.ShouldRateLimit(MakeThreat("A"));
        rl.ShouldRateLimit(MakeThreat("B"));
        rl.ShouldRateLimit(MakeThreat("A")); // duplicate, shouldn't increase count
        Assert.Equal(2, rl.Count);
    }

    // ── Edge cases ──

    [Fact]
    public void EmptyDescription_HandledGracefully()
    {
        var rl = new ThreatRateLimiter(300);
        var threat = MakeThreat(desc: "");
        Assert.False(rl.ShouldRateLimit(threat));
        Assert.True(rl.ShouldRateLimit(threat));
    }

    [Fact]
    public void ShortDescription_ShorterThanSnippetLength()
    {
        var rl = new ThreatRateLimiter(300, descriptionSnippetLength: 1000);
        var threat = MakeThreat(desc: "short");
        Assert.False(rl.ShouldRateLimit(threat));
        Assert.True(rl.ShouldRateLimit(threat));
    }
}
