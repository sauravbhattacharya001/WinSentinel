using WinSentinel.Agent;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for the ThreatLog in-memory event store.
/// </summary>
public class ThreatLogTests
{
    [Fact]
    public void Add_And_GetAll_Works()
    {
        var log = new ThreatLog();
        log.Add(CreateThreat("Threat 1"));
        log.Add(CreateThreat("Threat 2"));

        var all = log.GetAll();
        Assert.Equal(2, all.Count);
        // Newest first
        Assert.Equal("Threat 2", all[0].Title);
        Assert.Equal("Threat 1", all[1].Title);
    }

    [Fact]
    public void GetRecent_Limits_Results()
    {
        var log = new ThreatLog();
        for (int i = 0; i < 10; i++)
        {
            log.Add(CreateThreat($"Threat {i}"));
        }

        var recent = log.GetRecent(3);
        Assert.Equal(3, recent.Count);
        Assert.Equal("Threat 9", recent[0].Title);
    }

    [Fact]
    public void MaxSize_Trims_Old_Events()
    {
        var log = new ThreatLog(maxSize: 5);
        for (int i = 0; i < 10; i++)
        {
            log.Add(CreateThreat($"Threat {i}"));
        }

        Assert.Equal(5, log.Count);
        var all = log.GetAll();
        // Should only have the 5 most recent
        Assert.Equal("Threat 9", all[0].Title);
        Assert.Equal("Threat 5", all[4].Title);
    }

    [Fact]
    public void SetMaxSize_Works()
    {
        var log = new ThreatLog(maxSize: 100);
        for (int i = 0; i < 20; i++)
        {
            log.Add(CreateThreat($"Threat {i}"));
        }

        Assert.Equal(20, log.Count);

        log.SetMaxSize(10);
        // Adding one more triggers trim
        log.Add(CreateThreat("New"));
        Assert.True(log.Count <= 11);
    }

    [Fact]
    public void GetToday_Filters_Correctly()
    {
        var log = new ThreatLog();

        // Add a today threat
        log.Add(CreateThreat("Today"));

        // Add a yesterday threat
        var yesterday = new ThreatEvent
        {
            Source = "Test",
            Severity = ThreatSeverity.Medium,
            Title = "Yesterday",
            Description = "Old",
            Timestamp = DateTimeOffset.UtcNow.AddDays(-1)
        };
        log.Add(yesterday);

        var today = log.GetToday();
        Assert.Single(today);
        Assert.Equal("Today", today[0].Title);
    }

    [Fact]
    public void GetTodayCount_Returns_Correct_Count()
    {
        var log = new ThreatLog();
        log.Add(CreateThreat("T1"));
        log.Add(CreateThreat("T2"));

        Assert.Equal(2, log.GetTodayCount());
    }

    [Fact]
    public void ThreatDetected_Event_Fires()
    {
        var log = new ThreatLog();
        ThreatEvent? received = null;
        log.ThreatDetected += t => received = t;

        var threat = CreateThreat("Fire Event");
        log.Add(threat);

        Assert.NotNull(received);
        Assert.Equal("Fire Event", received.Title);
    }

    [Fact]
    public void Empty_Log_Returns_Empty_Collections()
    {
        var log = new ThreatLog();

        Assert.Empty(log.GetAll());
        Assert.Empty(log.GetRecent());
        Assert.Empty(log.GetToday());
        Assert.Equal(0, log.GetTodayCount());
        Assert.Equal(0, log.Count);
    }

    private static ThreatEvent CreateThreat(string title) => new()
    {
        Source = "Test",
        Severity = ThreatSeverity.Medium,
        Title = title,
        Description = "Test threat"
    };
}
