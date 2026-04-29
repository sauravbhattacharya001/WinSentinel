using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class KillChainReconstructorTests
{
    private readonly KillChainReconstructorService _svc = new();

    private static Finding MakeFinding(string title, string category, Severity severity = Severity.Warning)
        => new() { Title = title, Description = title, Category = category, Severity = severity };

    [Fact]
    public void Reconstruct_EmptyFindings_ReturnsNoThreat()
    {
        var report = _svc.Reconstruct([]);
        Assert.Equal("None", report.ThreatLevel);
        Assert.Equal(0, report.ActivePhaseCount);
        Assert.Equal(0, report.CoverageScore);
        Assert.Empty(report.Progressions);
        Assert.Contains("no signs of an ongoing attack", report.Narrative.ToLower());
    }

    [Fact]
    public void Reconstruct_PassFindings_AreIgnored()
    {
        var findings = new List<Finding>
        {
            Finding.Pass("Firewall enabled", "All inbound rules reviewed", "Firewall"),
            Finding.Pass("RDP disabled", "Remote Desktop is off", "RemoteAccess"),
        };
        var report = _svc.Reconstruct(findings);
        Assert.Equal("None", report.ThreatLevel);
        Assert.Equal(0, report.MappedFindingCount);
    }

    [Fact]
    public void Reconstruct_SinglePhase_MapsCorrectly()
    {
        var findings = new List<Finding>
        {
            MakeFinding("RDP enabled on public interface", "RemoteAccess", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        Assert.True(report.ActivePhaseCount >= 1);
        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.IsActive);
        Assert.Equal("Critical", initialAccess.MaxSeverity);
    }

    [Fact]
    public void Reconstruct_MultiplePhases_DetectsProgression()
    {
        var findings = new List<Finding>
        {
            MakeFinding("RDP enabled without MFA", "RemoteAccess", Severity.Critical),
            MakeFinding("PowerShell execution policy unrestricted", "PowerShell", Severity.Warning),
            MakeFinding("New startup run key detected", "Startup", Severity.Warning),
            MakeFinding("Windows Defender real-time off", "Defender", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        Assert.True(report.ActivePhaseCount >= 3);
        Assert.True(report.Progressions.Count > 0);
    }

    [Fact]
    public void Reconstruct_RansomwarePattern_Detected()
    {
        var findings = new List<Finding>
        {
            // Initial Access
            MakeFinding("FTP accessible from internet", "Network", Severity.Warning),
            // Execution
            MakeFinding("PowerShell bypass policy", "PowerShell", Severity.Critical),
            // Defense Evasion
            MakeFinding("Defender disabled by tamper", "Defender", Severity.Critical),
            // Impact
            MakeFinding("Shadow copy backup disabled", "Backup", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        var ransomware = report.Progressions.FirstOrDefault(p => p.Name == "Ransomware Campaign");
        Assert.NotNull(ransomware);
        Assert.True(ransomware.Confidence >= 50);
    }

    [Fact]
    public void Reconstruct_CredentialTheftPattern_Detected()
    {
        var findings = new List<Finding>
        {
            // Initial Access
            MakeFinding("SMB open to network", "Network", Severity.Warning),
            // Privilege Escalation
            MakeFinding("UAC disabled local admin", "Account", Severity.Critical),
            // Credential Access
            MakeFinding("Stored password in plain text", "Credential", Severity.Critical),
            // Exfiltration
            MakeFinding("Large data transfer outbound spike", "Network", Severity.Warning),
        };
        var report = _svc.Reconstruct(findings);
        var credTheft = report.Progressions.FirstOrDefault(p => p.Name == "Credential Theft Operation");
        Assert.NotNull(credTheft);
    }

    [Fact]
    public void Reconstruct_GeneratesPredictions()
    {
        var findings = new List<Finding>
        {
            MakeFinding("RDP enabled public", "RemoteAccess", Severity.Critical),
            MakeFinding("PowerShell unrestricted execution", "PowerShell", Severity.Warning),
        };
        var report = _svc.Reconstruct(findings);
        Assert.True(report.Predictions.Count > 0);
        // After Initial Access + Execution, should predict Persistence or Privilege Escalation
        var predictedPhases = report.Predictions.Select(p => p.Phase).ToList();
        Assert.True(predictedPhases.Any(p => p is "Persistence" or "Privilege Escalation" or "Defense Evasion"));
    }

    [Fact]
    public void Reconstruct_PredictionsHavePreventiveActions()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Open port scan results", "Network", Severity.Info),
        };
        var report = _svc.Reconstruct(findings);
        foreach (var pred in report.Predictions)
        {
            Assert.NotEmpty(pred.PreventiveActions);
        }
    }

    [Fact]
    public void Reconstruct_ResponsePlanOrdered()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Defender tamper disabled", "Defender", Severity.Critical),
            MakeFinding("Weak password policy", "Account", Severity.Warning),
            MakeFinding("Startup autorun entry", "Startup", Severity.Warning),
        };
        var report = _svc.Reconstruct(findings);
        Assert.True(report.ResponsePlan.Count > 0);
        // Priorities should be sequential
        for (int i = 0; i < report.ResponsePlan.Count - 1; i++)
            Assert.True(report.ResponsePlan[i].Priority <= report.ResponsePlan[i + 1].Priority);
    }

    [Fact]
    public void Reconstruct_CriticalThreatLevel()
    {
        // Create findings that trigger a Critical progression at >=75% confidence
        var findings = new List<Finding>
        {
            MakeFinding("SSH enabled", "RemoteAccess", Severity.Warning),
            MakeFinding("PowerShell bypass execution", "PowerShell", Severity.Critical),
            MakeFinding("Startup run key added", "Startup", Severity.Warning),
            MakeFinding("UAC disabled admin privilege", "Account", Severity.Critical),
            MakeFinding("Event log cleared", "EventLog", Severity.Critical),
            MakeFinding("Lsass credential dump detected", "Credential", Severity.Critical),
            MakeFinding("Network discovery scanning", "Network", Severity.Info),
            MakeFinding("SMB admin share lateral movement", "SMB", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        Assert.True(report.ThreatLevel is "High" or "Critical");
    }

    [Fact]
    public void Reconstruct_NarrativeNotEmpty()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Firewall disabled inbound", "Firewall", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        Assert.False(string.IsNullOrWhiteSpace(report.Narrative));
    }

    [Fact]
    public void Reconstruct_UnmappedFindingsTracked()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Something random not in any mapping", "UnknownCategory", Severity.Warning),
        };
        var report = _svc.Reconstruct(findings);
        Assert.Equal(1, report.UnmappedFindingCount);
        Assert.Equal(0, report.MappedFindingCount);
    }

    [Fact]
    public void Reconstruct_AllPhasesPresent()
    {
        var report = _svc.Reconstruct([]);
        Assert.Equal(14, report.Phases.Count);
        Assert.Equal("Reconnaissance", report.Phases[0].Phase);
        Assert.Equal("Impact", report.Phases[13].Phase);
    }

    [Fact]
    public void Reconstruct_PhaseIndexesCorrect()
    {
        var report = _svc.Reconstruct([]);
        for (int i = 0; i < report.Phases.Count; i++)
            Assert.Equal(i, report.Phases[i].PhaseIndex);
    }

    [Fact]
    public void Reconstruct_APTPattern_Detected()
    {
        var findings = new List<Finding>
        {
            // Reconnaissance
            MakeFinding("Open port scan exposed", "Network", Severity.Info),
            // Initial Access
            MakeFinding("VNC remote enabled", "RemoteAccess", Severity.Warning),
            // Persistence
            MakeFinding("Scheduled task persistence added", "ScheduledTask", Severity.Warning),
            // Discovery
            MakeFinding("System info discovery whoami", "System", Severity.Info),
            // Lateral Movement
            MakeFinding("PsExec admin share lateral", "SMB", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        var apt = report.Progressions.FirstOrDefault(p => p.Name == "APT Intrusion");
        Assert.NotNull(apt);
        Assert.True(apt.Confidence >= 60);
    }

    [Fact]
    public void Reconstruct_LowConfidenceProgressions_Excluded()
    {
        // Only one phase active — shouldn't trigger any multi-phase progression
        var findings = new List<Finding>
        {
            MakeFinding("DNS zone transfer allowed", "DNS", Severity.Warning),
        };
        var report = _svc.Reconstruct(findings);
        // Single-phase match gives <40% confidence so should be excluded
        Assert.Empty(report.Progressions);
    }

    [Fact]
    public void Reconstruct_DefenseNeutralization_Detected()
    {
        var findings = new List<Finding>
        {
            // Defense Evasion
            MakeFinding("Windows Defender disabled", "Defender", Severity.Critical),
            // Credential Access
            MakeFinding("Mimikatz credential dump found", "Credential", Severity.Critical),
            // Lateral Movement
            MakeFinding("Pass the hash lateral SMB", "SMB", Severity.Critical),
            // Impact
            MakeFinding("Backup recovery disabled shadow copy", "Backup", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        var defNeut = report.Progressions.FirstOrDefault(p => p.Name == "Defense Neutralization");
        Assert.NotNull(defNeut);
        Assert.True(defNeut.Confidence >= 75);
        Assert.Equal("Critical", defNeut.Severity);
    }

    [Fact]
    public void PhaseDefinitions_Has14Phases()
    {
        Assert.Equal(14, KillChainReconstructorService.PhaseDefinitions.Length);
    }

    [Fact]
    public void Reconstruct_HighThreatWith5ActivePhases()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Port scan open port exposed", "Network", Severity.Info),
            MakeFinding("Expired certificate self-signed", "Certificate", Severity.Warning),
            MakeFinding("RDP enabled without restriction", "RemoteAccess", Severity.Critical),
            MakeFinding("PowerShell bypass script execution", "PowerShell", Severity.Warning),
            MakeFinding("New scheduled task persistence", "ScheduledTask", Severity.Warning),
        };
        var report = _svc.Reconstruct(findings);
        Assert.True(report.ActivePhaseCount >= 4);
        Assert.True(report.ThreatLevel is "Moderate" or "High" or "Critical");
    }

    [Fact]
    public void Reconstruct_ObservedTechniquesPopulated()
    {
        var findings = new List<Finding>
        {
            MakeFinding("SMB admin share access", "SMB", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        var lateralPhase = report.Phases.First(p => p.Phase == "Lateral Movement");
        Assert.True(lateralPhase.IsActive);
        Assert.NotEmpty(lateralPhase.ObservedTechniques);
    }

    [Fact]
    public void Reconstruct_NullFindings_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _svc.Reconstruct(null!));
    }

    [Fact]
    public void Reconstruct_ManyFindings_Performance()
    {
        var findings = new List<Finding>();
        var categories = new[] { "Network", "Firewall", "PowerShell", "Account", "Defender", "Credential", "SMB", "Backup" };
        var keywords = new[] { "scan", "disabled", "unrestricted", "admin", "tamper", "dump", "lateral", "shadow copy" };
        for (int i = 0; i < 500; i++)
        {
            findings.Add(MakeFinding(
                $"Finding {i} with {keywords[i % keywords.Length]}",
                categories[i % categories.Length],
                i % 4 == 0 ? Severity.Critical : Severity.Warning));
        }
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var report = _svc.Reconstruct(findings);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 5000, $"Took {sw.ElapsedMilliseconds}ms");
        Assert.True(report.MappedFindingCount > 0);
    }

    [Fact]
    public void Reconstruct_InsiderThreat_Detected()
    {
        var findings = new List<Finding>
        {
            // Discovery
            MakeFinding("File discovery enumeration scan", "FileSystem", Severity.Info),
            // Collection
            MakeFinding("Data collection telemetry active", "Privacy", Severity.Warning),
            // Exfiltration
            MakeFinding("DNS exfil encoded data transfer", "DNS", Severity.Critical),
        };
        var report = _svc.Reconstruct(findings);
        var insider = report.Progressions.FirstOrDefault(p => p.Name == "Insider Threat");
        Assert.NotNull(insider);
    }

    [Fact]
    public void Reconstruct_GeneratedAt_IsRecent()
    {
        var report = _svc.Reconstruct([]);
        Assert.True((DateTimeOffset.UtcNow - report.GeneratedAt).TotalSeconds < 10);
    }

    [Fact]
    public void Reconstruct_CoverageScore_IsPercentage()
    {
        var report = _svc.Reconstruct([]);
        Assert.InRange(report.CoverageScore, 0, 100);
    }
}
