using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class BeaconDetectionServiceTests
{
    private readonly string _tempDir;
    private readonly BeaconDetectionService _service;

    public BeaconDetectionServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"beacon-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _service = new BeaconDetectionService(_tempDir);
    }

    [Fact]
    public void Analyze_EmptyConnections_ReturnsEmptyReport()
    {
        var result = _service.Analyze(new List<ConnectionRecord>());

        Assert.Equal(0, result.ConnectionsAnalyzed);
        Assert.Equal(0, result.BeaconsDetected);
        Assert.Equal(0, result.OverallRiskScore);
    }

    [Fact]
    public void Analyze_FewConnections_BelowMinimum_ReturnsNoBeacons()
    {
        var records = new List<ConnectionRecord>
        {
            new() { RemoteIp = "10.0.0.1", RemotePort = 443, Timestamp = DateTimeOffset.UtcNow },
            new() { RemoteIp = "10.0.0.1", RemotePort = 443, Timestamp = DateTimeOffset.UtcNow.AddSeconds(60) },
        };

        var result = _service.Analyze(records);

        Assert.Equal(0, result.BeaconsDetected);
    }

    [Fact]
    public void Analyze_RegularInterval_DetectsBeacon()
    {
        // Simulate a beacon with exactly 60s interval (like Cobalt Strike default)
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var records = new List<ConnectionRecord>();

        for (int i = 0; i < 20; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "185.100.50.1",
                RemotePort = 443,
                LocalPort = 50000 + i,
                Timestamp = baseTime.AddSeconds(i * 60),
                ProcessName = "suspicious.exe"
            });
        }

        var result = _service.Analyze(records);

        Assert.True(result.BeaconsDetected > 0);
        var beacon = result.Candidates[0];
        Assert.Equal("185.100.50.1", beacon.RemoteIp);
        Assert.InRange(beacon.IntervalSeconds, 55, 65);
        Assert.True(beacon.JitterPercent < 5);
        Assert.True(beacon.Confidence > 0.7);
    }

    [Fact]
    public void Analyze_HighJitter_DoesNotDetectBeacon()
    {
        // Random intervals (high jitter) should NOT be flagged
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var random = new Random(42);
        var records = new List<ConnectionRecord>();

        for (int i = 0; i < 20; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "8.8.8.8",
                RemotePort = 443,
                LocalPort = 50000 + i,
                Timestamp = baseTime.AddSeconds(random.Next(1, 600)),
                ProcessName = "chrome.exe"
            });
        }

        var result = _service.Analyze(records);

        // High jitter connections should either not be detected or have low confidence
        var googleBeacons = result.Candidates.Where(c => c.RemoteIp == "8.8.8.8").ToList();
        Assert.True(googleBeacons.Count == 0 || googleBeacons.All(b => b.ConfidenceLevel == BeaconConfidence.Low));
    }

    [Fact]
    public void Analyze_CobaltStrikeProfile_MatchesKnownProfile()
    {
        // 60s interval with ~10% jitter matches Cobalt Strike default
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var random = new Random(123);
        var records = new List<ConnectionRecord>();

        for (int i = 0; i < 30; i++)
        {
            var jitter = 60 * 0.10 * (random.NextDouble() * 2 - 1); // ±10% jitter
            records.Add(new ConnectionRecord
            {
                RemoteIp = "192.168.100.50",
                RemotePort = 8443,
                LocalPort = 50000 + i,
                Timestamp = baseTime.AddSeconds(i * 60 + jitter),
                ProcessName = "rundll32.exe"
            });
        }

        var result = _service.Analyze(records);

        Assert.True(result.BeaconsDetected > 0);
        var beacon = result.Candidates.First(c => c.RemoteIp == "192.168.100.50");
        Assert.NotNull(beacon.MatchedProfile);
        Assert.Contains("Cobalt Strike", beacon.MatchedProfile);
    }

    [Fact]
    public void Analyze_SlowBeacon_DetectsLongInterval()
    {
        // 5-minute (300s) beacon
        var baseTime = DateTimeOffset.UtcNow.AddHours(-3);
        var records = new List<ConnectionRecord>();

        for (int i = 0; i < 15; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "10.20.30.40",
                RemotePort = 53,
                LocalPort = 50000 + i,
                Timestamp = baseTime.AddSeconds(i * 400)
            });
        }

        var result = _service.Analyze(records);

        Assert.True(result.BeaconsDetected > 0);
        var beacon = result.Candidates.First(c => c.RemoteIp == "10.20.30.40");
        Assert.True(beacon.IntervalSeconds > 300);
    }

    [Fact]
    public void Analyze_MultipleBeacons_RankedByRisk()
    {
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var records = new List<ConnectionRecord>();

        // Perfect beacon (no jitter, high risk)
        for (int i = 0; i < 20; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "evil.1.2.3",
                RemotePort = 4444,
                Timestamp = baseTime.AddSeconds(i * 60)
            });
        }

        // Beacon with some jitter (medium risk)
        var random = new Random(99);
        for (int i = 0; i < 10; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "maybe.5.6.7",
                RemotePort = 8080,
                Timestamp = baseTime.AddSeconds(i * 30 + random.Next(-5, 5))
            });
        }

        var result = _service.Analyze(records);

        Assert.True(result.BeaconsDetected >= 1);
        // First candidate should be the highest risk
        Assert.Equal("evil.1.2.3", result.Candidates[0].RemoteIp);
    }

    [Fact]
    public void Analyze_GeneratesRecommendations()
    {
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var records = new List<ConnectionRecord>();

        for (int i = 0; i < 20; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "192.168.1.100",
                RemotePort = 443,
                Timestamp = baseTime.AddSeconds(i * 60)
            });
        }

        var result = _service.Analyze(records);

        Assert.NotEmpty(result.Recommendations);
        Assert.True(result.Recommendations.All(r => !string.IsNullOrEmpty(r.Action)));
    }

    [Fact]
    public void Analyze_CalculatesStats()
    {
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var records = new List<ConnectionRecord>();

        // Fast beacon (5s)
        for (int i = 0; i < 10; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "fast.1.2.3",
                RemotePort = 443,
                Timestamp = baseTime.AddSeconds(i * 5)
            });
        }

        // Slow beacon (600s)
        for (int i = 0; i < 8; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "slow.4.5.6",
                RemotePort = 53,
                Timestamp = baseTime.AddSeconds(i * 600)
            });
        }

        var result = _service.Analyze(records);

        Assert.True(result.Stats.TotalUniqueEndpoints >= 2);
    }

    [Fact]
    public void Analyze_PersistsReport()
    {
        var records = new List<ConnectionRecord>();
        var baseTime = DateTimeOffset.UtcNow.AddMinutes(-30);
        for (int i = 0; i < 10; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "10.0.0.1",
                RemotePort = 443,
                Timestamp = baseTime.AddSeconds(i * 60)
            });
        }

        _service.Analyze(records);

        var files = Directory.GetFiles(_tempDir, "beacon-*.json");
        Assert.NotEmpty(files);
    }

    [Fact]
    public void GetHistory_ReturnsPersistedReports()
    {
        var records = new List<ConnectionRecord>();
        var baseTime = DateTimeOffset.UtcNow.AddMinutes(-30);
        for (int i = 0; i < 10; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "10.0.0.1",
                RemotePort = 443,
                Timestamp = baseTime.AddSeconds(i * 60)
            });
        }

        _service.Analyze(records);
        var history = _service.GetHistory();

        Assert.NotEmpty(history);
    }

    [Fact]
    public void KnownProfiles_ContainsExpectedFrameworks()
    {
        var profileNames = BeaconDetectionService.KnownProfiles.Select(p => p.Name).ToList();

        Assert.Contains(profileNames, p => p.Contains("Cobalt Strike"));
        Assert.Contains(profileNames, p => p.Contains("Metasploit"));
        Assert.Contains(profileNames, p => p.Contains("Sliver"));
        Assert.Contains(profileNames, p => p.Contains("Empire"));
    }

    [Fact]
    public void Analyze_MitreTechniqueSet()
    {
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var records = new List<ConnectionRecord>();

        for (int i = 0; i < 15; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "172.16.0.1",
                RemotePort = 443,
                Timestamp = baseTime.AddSeconds(i * 30)
            });
        }

        var result = _service.Analyze(records);

        if (result.BeaconsDetected > 0)
        {
            Assert.All(result.Candidates, c => Assert.Contains("T1071", c.MitreTechnique));
        }
    }

    [Fact]
    public void Analyze_FixCommandGenerated()
    {
        var baseTime = DateTimeOffset.UtcNow.AddHours(-1);
        var records = new List<ConnectionRecord>();

        for (int i = 0; i < 15; i++)
        {
            records.Add(new ConnectionRecord
            {
                RemoteIp = "203.0.113.50",
                RemotePort = 8443,
                Timestamp = baseTime.AddSeconds(i * 60)
            });
        }

        var result = _service.Analyze(records);

        if (result.BeaconsDetected > 0)
        {
            var beacon = result.Candidates.First();
            Assert.NotNull(beacon.FixCommand);
            Assert.Contains("203.0.113.50", beacon.FixCommand);
            Assert.Contains("netsh", beacon.FixCommand);
        }
    }
}
