using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

public class AgentJournalTests : IDisposable
{
    private readonly string _tempDir;

    public AgentJournalTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"winsentinel_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    private AgentJournal CreateJournal()
    {
        var logger = new NullLogger<AgentJournal>();
        var path = Path.Combine(_tempDir, $"journal_{Guid.NewGuid():N}.jsonl");
        return new AgentJournal(logger, path);
    }

    // ── Recording tests ──

    [Fact]
    public void Record_StoresEntry()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry
        {
            EntryType = JournalEntryType.ThreatDetected,
            Source = "TestModule",
            Summary = "Test threat detected"
        });

        Assert.Equal(1, journal.Count);
    }

    [Fact]
    public void RecordThreat_CreatesCorrectEntry()
    {
        var journal = CreateJournal();
        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Encoded PowerShell Command",
            Description = "Suspicious PowerShell detected"
        };

        var decision = new PolicyDecision
        {
            Action = ResponseAction.AutoFix,
            MatchedRule = "Default"
        };

        journal.RecordThreat(threat, decision);

        var entries = journal.GetToday();
        Assert.Single(entries);
        Assert.Equal(JournalEntryType.ThreatDetected, entries[0].EntryType);
        Assert.Equal("ProcessMonitor", entries[0].Source);
        Assert.Contains("Critical", entries[0].Summary);
        Assert.Contains("AutoFix", entries[0].PolicyDecision);
    }

    [Fact]
    public void RecordRemediation_CreatesCorrectEntry()
    {
        var journal = CreateJournal();
        var remediation = new RemediationRecord
        {
            ActionType = RemediationAction.KillProcess,
            Target = "evil.exe (PID 1234)",
            Success = true,
            Description = "Killed process",
            ThreatEventId = "threat-1"
        };

        journal.RecordRemediation(remediation);

        var entries = journal.GetToday();
        Assert.Single(entries);
        Assert.Equal(JournalEntryType.ActionTaken, entries[0].EntryType);
        Assert.Contains("success", entries[0].Tags);
    }

    [Fact]
    public void RecordCorrelation_CreatesCorrectEntry()
    {
        var journal = CreateJournal();
        var correlation = new CorrelatedThreat
        {
            RuleName = "DefenderPlusUnsigned",
            CombinedSeverity = ThreatSeverity.Critical,
            ChainDescription = "Defender disabled + suspicious process",
            ThreatScore = 90
        };

        journal.RecordCorrelation(correlation);

        var entries = journal.GetToday();
        Assert.Single(entries);
        Assert.Equal(JournalEntryType.CorrelationDetected, entries[0].EntryType);
        Assert.Contains("correlation", entries[0].Tags);
    }

    // ── Query tests ──

    [Fact]
    public void Query_ByEntryType_Filters()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry { EntryType = JournalEntryType.ThreatDetected, Summary = "Threat 1" });
        journal.Record(new JournalEntry { EntryType = JournalEntryType.ActionTaken, Summary = "Action 1" });
        journal.Record(new JournalEntry { EntryType = JournalEntryType.ThreatDetected, Summary = "Threat 2" });

        var threats = journal.Query(new JournalQuery { EntryType = JournalEntryType.ThreatDetected });
        Assert.Equal(2, threats.Count);
    }

    [Fact]
    public void Query_BySource_Filters()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry { Source = "ProcessMonitor", Summary = "P1" });
        journal.Record(new JournalEntry { Source = "FileSystemMonitor", Summary = "F1" });
        journal.Record(new JournalEntry { Source = "ProcessMonitor", Summary = "P2" });

        var processEntries = journal.Query(new JournalQuery { Source = "ProcessMonitor" });
        Assert.Equal(2, processEntries.Count);
    }

    [Fact]
    public void Query_ByMinSeverity_Filters()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry { Severity = ThreatSeverity.Low, Summary = "Low" });
        journal.Record(new JournalEntry { Severity = ThreatSeverity.Critical, Summary = "Crit" });
        journal.Record(new JournalEntry { Severity = ThreatSeverity.Medium, Summary = "Med" });

        var highPlus = journal.Query(new JournalQuery { MinSeverity = ThreatSeverity.High });
        Assert.Single(highPlus); // Only Critical
    }

    [Fact]
    public void Query_BySearchText_SearchesSummaryAndDetails()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry { Summary = "PowerShell encoded command", Details = "Some details" });
        journal.Record(new JournalEntry { Summary = "Normal event", Details = "PowerShell mentioned here" });
        journal.Record(new JournalEntry { Summary = "Unrelated", Details = "Nothing here" });

        var results = journal.Query(new JournalQuery { SearchText = "PowerShell" });
        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void Query_ByTag_Filters()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry { Summary = "T1", Tags = { "process", "critical" } });
        journal.Record(new JournalEntry { Summary = "T2", Tags = { "file" } });
        journal.Record(new JournalEntry { Summary = "T3", Tags = { "process" } });

        var processEntries = journal.Query(new JournalQuery { Tag = "process" });
        Assert.Equal(2, processEntries.Count);
    }

    [Fact]
    public void Query_WithLimit_RespectsLimit()
    {
        var journal = CreateJournal();

        for (int i = 0; i < 20; i++)
            journal.Record(new JournalEntry { Summary = $"Entry {i}" });

        var results = journal.Query(new JournalQuery { Limit = 5 });
        Assert.Equal(5, results.Count);
    }

    [Fact]
    public void Query_OrdersByTimestampDescending()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry { Timestamp = DateTimeOffset.UtcNow.AddMinutes(-2), Summary = "Old" });
        journal.Record(new JournalEntry { Timestamp = DateTimeOffset.UtcNow, Summary = "New" });
        journal.Record(new JournalEntry { Timestamp = DateTimeOffset.UtcNow.AddMinutes(-1), Summary = "Mid" });

        var results = journal.Query(new JournalQuery());
        Assert.Equal("New", results[0].Summary);
        Assert.Equal("Mid", results[1].Summary);
        Assert.Equal("Old", results[2].Summary);
    }

    // ── Summary tests ──

    [Fact]
    public void GetTodaySummary_AggregatesCorrectly()
    {
        var journal = CreateJournal();

        journal.Record(new JournalEntry { EntryType = JournalEntryType.ThreatDetected, Severity = ThreatSeverity.Critical });
        journal.Record(new JournalEntry { EntryType = JournalEntryType.ThreatDetected, Severity = ThreatSeverity.High });
        journal.Record(new JournalEntry { EntryType = JournalEntryType.ActionTaken, Tags = { "success" } });
        journal.Record(new JournalEntry { EntryType = JournalEntryType.ActionTaken, Tags = { "failed" } });
        journal.Record(new JournalEntry { EntryType = JournalEntryType.CorrelationDetected });

        var summary = journal.GetTodaySummary();

        Assert.Equal("Today", summary.Period);
        Assert.Equal(5, summary.TotalEvents);
        Assert.Equal(2, summary.ThreatsDetected);
        Assert.Equal(2, summary.ActionsTaken);
        Assert.Equal(1, summary.CorrelationsDetected);
        Assert.Equal(1, summary.CriticalCount);
        Assert.Equal(1, summary.HighCount);
        Assert.Equal(1, summary.SuccessfulRemediations);
        Assert.Equal(1, summary.FailedRemediations);
    }

    [Fact]
    public void JournalSummary_ToString_FormatsCorrectly()
    {
        var summary = new JournalSummary
        {
            Period = "Today",
            ThreatsDetected = 5,
            CriticalCount = 1,
            HighCount = 2,
            MediumCount = 1,
            LowCount = 1,
            CorrelationsDetected = 2,
            ActionsTaken = 3,
            SuccessfulRemediations = 2,
            FailedRemediations = 1,
            TopSources = new Dictionary<string, int>
            {
                ["ProcessMonitor"] = 3,
                ["FileSystemMonitor"] = 2
            }
        };

        var str = summary.ToString();
        Assert.Contains("Today", str);
        Assert.Contains("5", str); // ThreatsDetected
        Assert.Contains("ProcessMonitor", str);
    }
}
