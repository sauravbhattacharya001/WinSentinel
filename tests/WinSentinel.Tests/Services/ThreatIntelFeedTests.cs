using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ThreatIntelFeedTests
{
    private ThreatIntelFeed CreateFeed()
    {
        var feed = new ThreatIntelFeed();
        return feed;
    }

    private ThreatIndicator CreateIndicator(
        IndicatorType type = IndicatorType.IpAddress,
        string value = "192.168.1.1",
        ThreatClassification classification = ThreatClassification.Malware,
        IndicatorConfidence confidence = IndicatorConfidence.High,
        Severity severity = Severity.Critical)
    {
        return new ThreatIndicator
        {
            Value = value,
            Type = type,
            Classification = classification,
            Confidence = confidence,
            Severity = severity,
            Description = $"Test indicator: {value}",
        };
    }

    // ── AddIndicator ─────────────────────────────────────────────

    [Fact]
    public void AddIndicator_Success()
    {
        var feed = CreateFeed();
        var indicator = CreateIndicator();
        Assert.True(feed.AddIndicator(indicator));
        Assert.Equal(1, feed.Count);
    }

    [Fact]
    public void AddIndicator_Duplicate_ReturnsFalse()
    {
        var feed = CreateFeed();
        var ind1 = CreateIndicator(value: "10.0.0.1");
        var ind2 = CreateIndicator(value: "10.0.0.1");
        Assert.True(feed.AddIndicator(ind1));
        Assert.False(feed.AddIndicator(ind2));
        Assert.Equal(1, feed.Count);
    }

    [Fact]
    public void AddIndicator_CaseInsensitiveDuplicate_Domain()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.Domain, "Evil.COM"));
        Assert.False(feed.AddIndicator(CreateIndicator(IndicatorType.Domain, "evil.com")));
    }

    [Fact]
    public void AddIndicator_NullThrows()
    {
        var feed = CreateFeed();
        Assert.Throws<ArgumentNullException>(() => feed.AddIndicator(null!));
    }

    [Fact]
    public void AddIndicator_EmptyValueThrows()
    {
        var feed = CreateFeed();
        Assert.Throws<ArgumentException>(() =>
            feed.AddIndicator(CreateIndicator(value: "")));
    }

    [Fact]
    public void AddIndicator_WhitespaceValueThrows()
    {
        var feed = CreateFeed();
        Assert.Throws<ArgumentException>(() =>
            feed.AddIndicator(CreateIndicator(value: "   ")));
    }

    [Fact]
    public void AddIndicator_DifferentTypes_SameValue_BothAdded()
    {
        var feed = CreateFeed();
        Assert.True(feed.AddIndicator(CreateIndicator(IndicatorType.IpAddress, "test")));
        Assert.True(feed.AddIndicator(CreateIndicator(IndicatorType.Domain, "test")));
        Assert.Equal(2, feed.Count);
    }

    // ── RemoveIndicator ──────────────────────────────────────────

    [Fact]
    public void RemoveIndicator_Success()
    {
        var feed = CreateFeed();
        var ind = CreateIndicator();
        feed.AddIndicator(ind);
        Assert.True(feed.RemoveIndicator(ind.Id));
        Assert.Equal(0, feed.Count);
    }

    [Fact]
    public void RemoveIndicator_NotFound_ReturnsFalse()
    {
        var feed = CreateFeed();
        Assert.False(feed.RemoveIndicator("nonexistent"));
    }

    [Fact]
    public void RemoveIndicator_ThenLookupFails()
    {
        var feed = CreateFeed();
        var ind = CreateIndicator(IndicatorType.ProcessName, "bad.exe");
        feed.AddIndicator(ind);
        feed.RemoveIndicator(ind.Id);
        Assert.Null(feed.CheckProcess("bad.exe"));
    }

    // ── DeactivateIndicator ──────────────────────────────────────

    [Fact]
    public void DeactivateIndicator_StopsMatching()
    {
        var feed = CreateFeed();
        var ind = CreateIndicator(IndicatorType.IpAddress, "10.0.0.1");
        feed.AddIndicator(ind);
        Assert.NotNull(feed.CheckIp("10.0.0.1"));

        feed.DeactivateIndicator(ind.Id);
        Assert.Null(feed.CheckIp("10.0.0.1"));
    }

    [Fact]
    public void DeactivateIndicator_NotFound_ReturnsFalse()
    {
        var feed = CreateFeed();
        Assert.False(feed.DeactivateIndicator("nope"));
    }

    // ── PurgeExpired ─────────────────────────────────────────────

    [Fact]
    public void PurgeExpired_RemovesExpiredOnly()
    {
        var feed = CreateFeed();
        var active = CreateIndicator(value: "1.1.1.1");
        var expired = CreateIndicator(value: "2.2.2.2");
        expired.ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);

        feed.AddIndicator(active);
        feed.AddIndicator(expired);

        Assert.Equal(1, feed.PurgeExpired());
        Assert.Equal(1, feed.Count);
        Assert.NotNull(feed.CheckIp("1.1.1.1"));
        Assert.Null(feed.CheckIp("2.2.2.2"));
    }

    [Fact]
    public void PurgeExpired_NothingExpired_ReturnsZero()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(value: "3.3.3.3"));
        Assert.Equal(0, feed.PurgeExpired());
    }

    // ── CheckIp / CheckDomain / CheckHash / CheckProcess ─────────

    [Fact]
    public void CheckIp_Match()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.IpAddress, "10.0.0.99"));
        var match = feed.CheckIp("10.0.0.99");
        Assert.NotNull(match);
        Assert.Equal("10.0.0.99", match.CheckedValue);
        Assert.Equal(WinSentinel.Core.Services.MatchType.CaseInsensitive, match.MatchType);
    }

    [Fact]
    public void CheckIp_NoMatch()
    {
        var feed = CreateFeed();
        Assert.Null(feed.CheckIp("192.168.0.1"));
    }

    [Fact]
    public void CheckDomain_CaseInsensitive()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.Domain, "EVIL.COM"));
        Assert.NotNull(feed.CheckDomain("evil.com"));
    }

    [Fact]
    public void CheckHash_CaseInsensitive()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.FileHash, "abc123def"));
        Assert.NotNull(feed.CheckHash("ABC123DEF"));
    }

    [Fact]
    public void CheckProcess_Match()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.ProcessName, "mimikatz.exe"));
        Assert.NotNull(feed.CheckProcess("Mimikatz.EXE"));
    }

    [Fact]
    public void CheckUrl_Match()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.Url, "http://evil.com/payload"));
        Assert.NotNull(feed.CheckUrl("http://evil.com/payload"));
    }

    [Fact]
    public void CheckValue_NullOrEmpty_ReturnsNull()
    {
        var feed = CreateFeed();
        Assert.Null(feed.CheckValue(null!, IndicatorType.IpAddress));
        Assert.Null(feed.CheckValue("", IndicatorType.IpAddress));
        Assert.Null(feed.CheckValue("  ", IndicatorType.IpAddress));
    }

    [Fact]
    public void CheckValue_ExpiredIndicator_NoMatch()
    {
        var feed = CreateFeed();
        var ind = CreateIndicator(IndicatorType.IpAddress, "10.0.0.50");
        ind.ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);
        feed.AddIndicator(ind);
        Assert.Null(feed.CheckIp("10.0.0.50"));
    }

    [Fact]
    public void CheckValue_IncrementsHitCount()
    {
        var feed = CreateFeed();
        var ind = CreateIndicator(IndicatorType.IpAddress, "10.0.0.77");
        feed.AddIndicator(ind);

        feed.CheckIp("10.0.0.77");
        feed.CheckIp("10.0.0.77");
        feed.CheckIp("10.0.0.77");

        Assert.Equal(3, ind.HitCount);
        Assert.NotNull(ind.LastHit);
    }

    // ── CheckAll ─────────────────────────────────────────────────

    [Fact]
    public void CheckAll_MatchesMultipleTypes()
    {
        var feed = CreateFeed();
        // "test" as both IP and domain
        feed.AddIndicator(CreateIndicator(IndicatorType.IpAddress, "test"));
        feed.AddIndicator(CreateIndicator(IndicatorType.Domain, "test"));
        var matches = feed.CheckAll("test");
        Assert.Equal(2, matches.Count);
    }

    [Fact]
    public void CheckAll_NoMatch()
    {
        var feed = CreateFeed();
        var matches = feed.CheckAll("nothing");
        Assert.Empty(matches);
    }

    // ── Search ───────────────────────────────────────────────────

    [Fact]
    public void Search_ByType()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.IpAddress, "1.1.1.1"));
        feed.AddIndicator(CreateIndicator(IndicatorType.Domain, "evil.com"));
        feed.AddIndicator(CreateIndicator(IndicatorType.IpAddress, "2.2.2.2"));

        var ips = feed.Search(type: IndicatorType.IpAddress);
        Assert.Equal(2, ips.Count);
    }

    [Fact]
    public void Search_ByClassification()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(classification: ThreatClassification.Malware, value: "a"));
        feed.AddIndicator(CreateIndicator(classification: ThreatClassification.C2Server, value: "b"));

        var c2 = feed.Search(classification: ThreatClassification.C2Server);
        Assert.Single(c2);
    }

    [Fact]
    public void Search_ByMinConfidence()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(confidence: IndicatorConfidence.Low, value: "lo"));
        feed.AddIndicator(CreateIndicator(confidence: IndicatorConfidence.High, value: "hi"));
        feed.AddIndicator(CreateIndicator(confidence: IndicatorConfidence.Confirmed, value: "cf"));

        var highPlus = feed.Search(minConfidence: IndicatorConfidence.High);
        Assert.Equal(2, highPlus.Count);
    }

    [Fact]
    public void Search_BySource()
    {
        var feed = CreateFeed();
        var ind = CreateIndicator(value: "src-test");
        ind.Source = "custom-feed";
        feed.AddIndicator(ind);
        feed.AddIndicator(CreateIndicator(value: "other"));

        var results = feed.Search(source: "custom-feed");
        Assert.Single(results);
    }

    [Fact]
    public void Search_ByTag()
    {
        var feed = CreateFeed();
        var ind = CreateIndicator(value: "tagged");
        ind.Tags.Add("ransomware");
        feed.AddIndicator(ind);
        feed.AddIndicator(CreateIndicator(value: "untagged"));

        var results = feed.Search(tag: "ransomware");
        Assert.Single(results);
    }

    [Fact]
    public void Search_ActiveOnly_ExcludesInactive()
    {
        var feed = CreateFeed();
        var active = CreateIndicator(value: "active");
        var inactive = CreateIndicator(value: "inactive");
        inactive.Active = false;
        feed.AddIndicator(active);
        feed.AddIndicator(inactive);

        var results = feed.Search(activeOnly: true);
        Assert.Single(results);
    }

    [Fact]
    public void Search_IncludeInactive()
    {
        var feed = CreateFeed();
        var active = CreateIndicator(value: "active2");
        var inactive = CreateIndicator(value: "inactive2");
        inactive.Active = false;
        feed.AddIndicator(active);
        feed.AddIndicator(inactive);

        var results = feed.Search(activeOnly: false);
        Assert.Equal(2, results.Count);
    }

    // ── GetStatistics ────────────────────────────────────────────

    [Fact]
    public void GetStatistics_Empty()
    {
        var feed = CreateFeed();
        var stats = feed.GetStatistics();
        Assert.Equal(0, stats.TotalIndicators);
        Assert.Equal(0, stats.ActiveIndicators);
    }

    [Fact]
    public void GetStatistics_WithIndicators()
    {
        var feed = CreateFeed();
        feed.LoadBuiltInIndicators();
        var stats = feed.GetStatistics();

        Assert.True(stats.TotalIndicators > 0);
        Assert.True(stats.ActiveIndicators > 0);
        Assert.True(stats.ByType.Count > 0);
        Assert.True(stats.ByClassification.Count > 0);
        Assert.True(stats.BySource.ContainsKey("built-in"));
        Assert.NotNull(stats.OldestIndicator);
        Assert.NotNull(stats.NewestIndicator);
    }

    [Fact]
    public void GetStatistics_TracksHits()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(IndicatorType.IpAddress, "10.10.10.10"));
        feed.CheckIp("10.10.10.10");
        feed.CheckIp("10.10.10.10");

        var stats = feed.GetStatistics();
        Assert.Equal(2, stats.TotalHits);
    }

    // ── Export / Import ──────────────────────────────────────────

    [Fact]
    public void ExportJson_ReturnsValidJson()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(value: "1.2.3.4"));
        var json = feed.ExportJson();
        Assert.Contains("1.2.3.4", json);
        Assert.Contains("IpAddress", json);
    }

    [Fact]
    public void ImportJson_Success()
    {
        var feed1 = CreateFeed();
        feed1.AddIndicator(CreateIndicator(value: "5.6.7.8"));
        feed1.AddIndicator(CreateIndicator(IndicatorType.Domain, "test.evil.com"));
        var json = feed1.ExportJson();

        var feed2 = CreateFeed();
        var imported = feed2.ImportJson(json);
        Assert.Equal(2, imported);
        Assert.Equal(2, feed2.Count);
    }

    [Fact]
    public void ImportJson_SkipsDuplicates()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(value: "dup.test"));
        var json = feed.ExportJson();

        var imported = feed.ImportJson(json);
        Assert.Equal(0, imported);
        Assert.Equal(1, feed.Count);
    }

    [Fact]
    public void ImportJson_EmptyThrows()
    {
        var feed = CreateFeed();
        Assert.Throws<ArgumentException>(() => feed.ImportJson(""));
    }

    [Fact]
    public void ExportJson_ToFile()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(value: "file-test"));
        var tempPath = Path.Combine(Path.GetTempPath(), $"threat-intel-test-{Guid.NewGuid()}.json");
        try
        {
            feed.ExportJson(tempPath);
            Assert.True(File.Exists(tempPath));
            var json = File.ReadAllText(tempPath);
            Assert.Contains("file-test", json);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    [Fact]
    public void ImportExport_RoundTrip()
    {
        var feed1 = CreateFeed();
        feed1.LoadBuiltInIndicators();
        var json = feed1.ExportJson();

        var feed2 = CreateFeed();
        feed2.ImportJson(json);

        Assert.Equal(feed1.Count, feed2.Count);
    }

    // ── Built-in Indicators ──────────────────────────────────────

    [Fact]
    public void LoadBuiltInIndicators_PopulatesFeed()
    {
        var feed = CreateFeed();
        feed.LoadBuiltInIndicators();
        Assert.True(feed.Count >= 20, $"Expected >= 20 built-in indicators, got {feed.Count}");
    }

    [Fact]
    public void LoadBuiltInIndicators_KnownProcess_Detected()
    {
        var feed = CreateFeed();
        feed.LoadBuiltInIndicators();
        Assert.NotNull(feed.CheckProcess("mimikatz.exe"));
        Assert.NotNull(feed.CheckProcess("xmrig.exe"));
        Assert.NotNull(feed.CheckProcess("rubeus.exe"));
    }

    [Fact]
    public void LoadBuiltInIndicators_KnownPort_Detected()
    {
        var feed = CreateFeed();
        feed.LoadBuiltInIndicators();
        Assert.NotNull(feed.CheckValue("4444", IndicatorType.Port));
        Assert.NotNull(feed.CheckValue("31337", IndicatorType.Port));
    }

    [Fact]
    public void LoadBuiltInIndicators_HaveMitreIds()
    {
        var feed = CreateFeed();
        feed.LoadBuiltInIndicators();
        var indicators = feed.Indicators;
        var withMitre = indicators.Count(i => i.MitreAttackIds.Count > 0);
        Assert.True(withMitre > 10, $"Expected > 10 indicators with MITRE IDs, got {withMitre}");
    }

    [Fact]
    public void LoadBuiltInIndicators_Idempotent()
    {
        var feed = CreateFeed();
        feed.LoadBuiltInIndicators();
        var count1 = feed.Count;
        feed.LoadBuiltInIndicators(); // second call
        Assert.Equal(count1, feed.Count);
    }

    // ── TextReport ───────────────────────────────────────────────

    [Fact]
    public void GenerateTextReport_ContainsHeader()
    {
        var feed = CreateFeed();
        feed.LoadBuiltInIndicators();
        var report = feed.GenerateTextReport();
        Assert.Contains("Threat Intelligence Feed Report", report);
        Assert.Contains("By Type", report);
        Assert.Contains("By Classification", report);
    }

    [Fact]
    public void GenerateTextReport_EmptyFeed()
    {
        var feed = CreateFeed();
        var report = feed.GenerateTextReport();
        Assert.Contains("Total indicators: 0", report);
    }

    // ── IsExpired / IsEffectivelyActive ──────────────────────────

    [Fact]
    public void IsExpired_NotExpired()
    {
        var ind = CreateIndicator();
        ind.ExpiresAt = DateTimeOffset.UtcNow.AddDays(30);
        Assert.False(ind.IsExpired);
        Assert.True(ind.IsEffectivelyActive);
    }

    [Fact]
    public void IsExpired_Expired()
    {
        var ind = CreateIndicator();
        ind.ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);
        Assert.True(ind.IsExpired);
        Assert.False(ind.IsEffectivelyActive);
    }

    [Fact]
    public void IsExpired_NoExpiry()
    {
        var ind = CreateIndicator();
        ind.ExpiresAt = null;
        Assert.False(ind.IsExpired);
    }

    [Fact]
    public void IsEffectivelyActive_InactiveAndNotExpired()
    {
        var ind = CreateIndicator();
        ind.Active = false;
        Assert.False(ind.IsEffectivelyActive);
    }

    // ── ComputeFileHash ──────────────────────────────────────────

    [Fact]
    public void ComputeFileHash_ReturnsHex()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"hash-test-{Guid.NewGuid()}.txt");
        try
        {
            File.WriteAllText(tempPath, "test content for hashing");
            var hash = ThreatIntelFeed.ComputeFileHash(tempPath);
            Assert.Equal(64, hash.Length); // SHA256 = 64 hex chars
            Assert.Matches("^[0-9A-F]+$", hash);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    // ── Indicators property ──────────────────────────────────────

    [Fact]
    public void Indicators_ReturnsDefensiveCopy()
    {
        var feed = CreateFeed();
        feed.AddIndicator(CreateIndicator(value: "copy-test"));
        var list1 = feed.Indicators;
        var list2 = feed.Indicators;
        Assert.NotSame(list1, list2);
        Assert.Equal(list1.Count, list2.Count);
    }
}
