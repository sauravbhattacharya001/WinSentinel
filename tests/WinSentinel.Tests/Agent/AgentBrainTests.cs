using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

public class AgentBrainTests : IDisposable
{
    private readonly string _tempDir;

    public AgentBrainTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"winsentinel_braintest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    private (AgentBrain brain, ThreatLog log, ResponsePolicy policy, AgentJournal journal) CreateBrain(
        RiskTolerance risk = RiskTolerance.Medium)
    {
        var log = new ThreatLog();
        var config = new AgentConfig { RiskTolerance = risk };
        var policy = ResponsePolicy.CreateDefault(risk);
        var correlator = new ThreatCorrelator(new NullLogger<ThreatCorrelator>());
        var remediator = new AutoRemediator(new NullLogger<AutoRemediator>());
        var journalPath = Path.Combine(_tempDir, $"journal_{Guid.NewGuid():N}.jsonl");
        var journal = new AgentJournal(new NullLogger<AgentJournal>(), journalPath);

        var brain = new AgentBrain(
            new NullLogger<AgentBrain>(),
            policy,
            correlator,
            remediator,
            journal,
            log,
            config);

        return (brain, log, policy, journal);
    }

    // ── Decision pipeline tests ──

    [Fact]
    public void ProcessThreat_CriticalMediumRisk_ReturnsAlert()
    {
        var (brain, _, _, _) = CreateBrain(RiskTolerance.Medium);

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Encoded PowerShell Command",
            Description = "PowerShell (PID 1234) launched with encoded command",
            AutoFixable = true
        };

        var decision = brain.ProcessThreat(threat);
        Assert.Equal(ResponseAction.Alert, decision.Action);
    }

    [Fact]
    public void ProcessThreat_CriticalLowRisk_ReturnsAutoFix()
    {
        var (brain, _, _, _) = CreateBrain(RiskTolerance.Low);

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Test Critical Threat",
            Description = "Critical threat from PID 99999",
            AutoFixable = true
        };

        var decision = brain.ProcessThreat(threat);
        Assert.Equal(ResponseAction.AutoFix, decision.Action);
    }

    [Fact]
    public void ProcessThreat_RecordsInJournal()
    {
        var (brain, _, _, journal) = CreateBrain();

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Test Threat"
        };

        brain.ProcessThreat(threat);

        var entries = journal.GetToday();
        Assert.NotEmpty(entries);
        Assert.Contains(entries, e => e.EntryType == JournalEntryType.ThreatDetected);
    }

    [Fact]
    public void ProcessThreat_FiresDecisionMadeEvent()
    {
        var (brain, _, _, _) = CreateBrain();
        ThreatEvent? receivedThreat = null;
        PolicyDecision? receivedDecision = null;

        brain.DecisionMade += (threat, decision) =>
        {
            receivedThreat = threat;
            receivedDecision = decision;
        };

        brain.ProcessThreat(new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.High,
            Title = "Test"
        });

        Assert.NotNull(receivedThreat);
        Assert.NotNull(receivedDecision);
    }

    // ── User feedback tests ──

    [Fact]
    public void HandleUserFeedback_Ignore_CreatesOverride()
    {
        var (brain, log, policy, journal) = CreateBrain();

        // First, add a threat to the log
        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.High,
            Title = "LOLBin Execution Detected"
        };
        log.Add(threat);

        // User says "ignore this"
        brain.HandleUserFeedback(threat.Id, "ignore", createOverride: true);

        // Check override was created
        Assert.Single(policy.UserOverrides);
        Assert.Equal("LOLBin Execution Detected", policy.UserOverrides[0].ThreatTitle);
        Assert.Equal(UserOverrideAction.AlwaysIgnore, policy.UserOverrides[0].OverrideAction);

        // Check journal recorded the feedback
        var feedbackEntries = journal.Query(new JournalQuery { EntryType = JournalEntryType.UserFeedback });
        Assert.NotEmpty(feedbackEntries);
    }

    [Fact]
    public void HandleUserFeedback_AutoFix_CreatesOverride()
    {
        var (brain, log, policy, _) = CreateBrain();

        var threat = new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Script Created"
        };
        log.Add(threat);

        brain.HandleUserFeedback(threat.Id, "autofix", createOverride: true);

        Assert.Single(policy.UserOverrides);
        Assert.Equal(UserOverrideAction.AlwaysAutoFix, policy.UserOverrides[0].OverrideAction);
    }

    // ── Extraction helper tests ──

    [Theory]
    [InlineData("Process 'evil.exe' (PID 1234) launched", 1234)]
    [InlineData("PID 5678 is suspicious", 5678)]
    [InlineData("No PID here", null)]
    public void ExtractPid_ParsesCorrectly(string description, int? expected)
    {
        Assert.Equal(expected, AgentBrain.ExtractPid(description));
    }

    [Theory]
    [InlineData("Process 'evil.exe' detected", "evil.exe")]
    [InlineData("Found \"malware.exe\" running", "malware.exe")]
    [InlineData("No process name here", null)]
    public void ExtractProcessName_ParsesCorrectly(string description, string? expected)
    {
        Assert.Equal(expected, AgentBrain.ExtractProcessName(description));
    }

    [Theory]
    [InlineData("Path: C:\\Users\\test\\evil.exe", @"C:\Users\test\evil.exe")]
    [InlineData("Path: C:\\Temp\\payload.dll more text", @"C:\Temp\payload.dll")]
    [InlineData("No path here", null)]
    public void ExtractFilePath_ParsesCorrectly(string description, string? expected)
    {
        Assert.Equal(expected, AgentBrain.ExtractFilePath(description));
    }

    [Theory]
    [InlineData("Connection from 192.168.1.100", "192.168.1.100")]
    [InlineData("Attack from 10.0.0.1 detected", "10.0.0.1")]
    [InlineData("No IP address", null)]
    public void ExtractIpAddress_ParsesCorrectly(string description, string? expected)
    {
        Assert.Equal(expected, AgentBrain.ExtractIpAddress(description));
    }

    // ── Initialization and shutdown ──

    [Fact]
    public void Initialize_RecordsStartInJournal()
    {
        var (brain, _, _, journal) = CreateBrain();

        brain.Initialize();

        var entries = journal.Query(new JournalQuery { EntryType = JournalEntryType.AgentStarted });
        Assert.NotEmpty(entries);

        brain.Shutdown();
    }

    [Fact]
    public void Shutdown_RecordsStopInJournal()
    {
        var (brain, _, _, journal) = CreateBrain();

        brain.Initialize();
        brain.Shutdown();

        var entries = journal.Query(new JournalQuery { EntryType = JournalEntryType.AgentStopped });
        Assert.NotEmpty(entries);
    }

    // ── User override interaction with brain ──

    [Fact]
    public void ProcessThreat_WithUserOverrideIgnore_LogsOnly()
    {
        var (brain, _, policy, _) = CreateBrain();
        policy.AddUserOverride("Test Threat", UserOverrideAction.AlwaysIgnore);

        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Test Threat",
            AutoFixable = true
        };

        var decision = brain.ProcessThreat(threat);
        Assert.Equal(ResponseAction.Log, decision.Action);
        Assert.True(decision.UserOverrideApplied);
    }
}
