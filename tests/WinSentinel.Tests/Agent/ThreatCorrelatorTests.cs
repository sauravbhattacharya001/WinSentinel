using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

public class ThreatCorrelatorTests
{
    private ThreatCorrelator CreateCorrelator()
    {
        var logger = new NullLogger<ThreatCorrelator>();
        return new ThreatCorrelator(logger)
        {
            CorrelationWindow = TimeSpan.FromMinutes(5),
            CorrelationCooldown = TimeSpan.FromSeconds(1) // Short for testing
        };
    }

    // ── ProcessPlusDll correlation ──

    [Fact]
    public void ProcessPlusDll_MatchingDirectory_DetectsCorrelation()
    {
        var correlator = CreateCorrelator();

        // First: suspicious process from a directory
        var processEvent = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Launch Path",
            Description = "Process 'evil.exe' (PID 1234) launched from suspicious location: C:\\Users\\test\\Downloads\\evil.exe"
        };
        var r1 = correlator.ProcessEvent(processEvent);

        // Then: new DLL in the same directory
        var dllEvent = new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.High,
            Title = "Potential DLL Sideloading",
            Description = "A new DLL 'payload.dll' appeared. Path: C:\\Users\\test\\Downloads\\payload.dll"
        };
        var r2 = correlator.ProcessEvent(dllEvent);

        Assert.NotEmpty(r2);
        Assert.Equal("ProcessPlusDll", r2[0].RuleName);
        Assert.Equal(ThreatSeverity.Critical, r2[0].CombinedSeverity);
        Assert.True(r2[0].ThreatScore > 0);
    }

    [Fact]
    public void ProcessPlusDll_DifferentDirectory_NoCorrelation()
    {
        var correlator = CreateCorrelator();

        var processEvent = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Launch Path",
            Description = "Process from Path: C:\\Users\\test\\Desktop\\evil.exe"
        };
        correlator.ProcessEvent(processEvent);

        var dllEvent = new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.High,
            Title = "Potential DLL Sideloading",
            Description = "A new DLL. Path: C:\\Totally\\Different\\Directory\\payload.dll"
        };
        var r2 = correlator.ProcessEvent(dllEvent);

        // Should not correlate — different directories
        var processPlusDll = r2.Where(c => c.RuleName == "ProcessPlusDll").ToList();
        Assert.Empty(processPlusDll);
    }

    // ── DefenderPlusUnsigned correlation ──

    [Fact]
    public void DefenderDisabled_PlusSuspiciousProcess_DetectsCorrelation()
    {
        var correlator = CreateCorrelator();

        // First: Defender disabled
        var defenderEvent = new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Defender Real-Time Protection Disabled",
            Description = "Windows Defender disabled"
        };
        correlator.ProcessEvent(defenderEvent);

        // Then: suspicious process from temp
        var processEvent = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Unsigned Executable from Temp",
            Description = "Process from Temp directory"
        };
        var r2 = correlator.ProcessEvent(processEvent);

        var defenderCorrelation = r2.Where(c => c.RuleName == "DefenderPlusUnsigned").ToList();
        Assert.NotEmpty(defenderCorrelation);
        Assert.Equal(ThreatSeverity.Critical, defenderCorrelation[0].CombinedSeverity);
    }

    // ── BruteForceChain correlation ──

    [Fact]
    public void BruteForce_WithEscalation_DetectsCorrelation()
    {
        var correlator = CreateCorrelator();

        // First: privilege escalation
        var escalation = new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.High,
            Title = "Special Privileges Assigned",
            Description = "Privilege escalation detected"
        };
        correlator.ProcessEvent(escalation);

        // Then: brute force
        var bruteForce = new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "Brute Force Attack Detected",
            Description = "Multiple failed logons"
        };
        var r2 = correlator.ProcessEvent(bruteForce);

        var chain = r2.Where(c => c.RuleName == "BruteForceChain").ToList();
        Assert.NotEmpty(chain);
    }

    // ── HostsFile correlation ──

    [Fact]
    public void HostsFileModified_PlusSuspiciousProcess_DetectsCorrelation()
    {
        var correlator = CreateCorrelator();

        var hostsEvent = new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.High,
            Title = "Hosts File Modified",
            Description = "Hosts file changed"
        };
        correlator.ProcessEvent(hostsEvent);

        var processEvent = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Process",
            Description = "Unknown process running"
        };
        var r2 = correlator.ProcessEvent(processEvent);

        var hostsCorrelation = r2.Where(c => c.RuleName == "HostsFilePlusProcess").ToList();
        Assert.NotEmpty(hostsCorrelation);
    }

    // ── RapidMultiModule correlation ──

    [Fact]
    public void RapidMultiModule_ThreeSources_DetectsCorrelation()
    {
        var correlator = CreateCorrelator();

        // Events from 3 different sources
        correlator.ProcessEvent(new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Process"
        });

        correlator.ProcessEvent(new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious File"
        });

        var r3 = correlator.ProcessEvent(new ThreatEvent
        {
            Source = "EventLogMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Event"
        });

        var multiModule = r3.Where(c => c.RuleName == "RapidMultiModule").ToList();
        Assert.NotEmpty(multiModule);
    }

    // ── Window management ──

    [Fact]
    public void Reset_ClearsWindow()
    {
        var correlator = CreateCorrelator();

        correlator.ProcessEvent(new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Test"
        });

        Assert.NotEmpty(correlator.GetWindowEvents());

        correlator.Reset();
        Assert.Empty(correlator.GetWindowEvents());
    }

    // ── Utility methods ──

    [Fact]
    public void ExtractDirectory_ParsesPathCorrectly()
    {
        var dir = ThreatCorrelator.ExtractDirectory("Something happened. Path: C:\\Users\\test\\Downloads\\evil.exe");
        Assert.Equal(@"C:\Users\test\Downloads", dir);
    }

    [Fact]
    public void ExtractDirectory_NoPath_ReturnsNull()
    {
        var dir = ThreatCorrelator.ExtractDirectory("No path information here");
        Assert.Null(dir);
    }

    [Theory]
    [InlineData(ThreatSeverity.Critical, 40)]
    [InlineData(ThreatSeverity.High, 25)]
    [InlineData(ThreatSeverity.Medium, 15)]
    [InlineData(ThreatSeverity.Low, 5)]
    [InlineData(ThreatSeverity.Info, 1)]
    public void SeverityScore_ReturnsCorrectValue(ThreatSeverity severity, int expected)
    {
        Assert.Equal(expected, ThreatCorrelator.SeverityScore(severity));
    }

    [Fact]
    public void CalculateChainScore_SumsCorrectly()
    {
        var e1 = new ThreatEvent { Severity = ThreatSeverity.Critical };
        var e2 = new ThreatEvent { Severity = ThreatSeverity.High };

        var score = ThreatCorrelator.CalculateChainScore(e1, e2);
        Assert.Equal(65, score); // 40 + 25
    }
}
