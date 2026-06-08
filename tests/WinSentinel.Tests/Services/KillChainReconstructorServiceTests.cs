using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for KillChainReconstructorService - maps security findings to MITRE ATT&CK
/// kill chain phases, detects multi-phase attack progressions, predicts next phases,
/// and generates prioritized response plans.
/// </summary>
public class KillChainReconstructorServiceTests
{
    private readonly KillChainReconstructorService _svc = new();

    // ━━━ Helper Methods ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    private static Finding MakeFinding(string category, string title,
        Severity severity = Severity.Warning, string? description = null) =>
        new()
        {
            Title = title,
            Description = description ?? $"{title} details",
            Severity = severity,
            Category = category,
        };

    private static Finding CriticalFinding(string category, string title) =>
        MakeFinding(category, title, Severity.Critical);

    private static Finding WarningFinding(string category, string title) =>
        MakeFinding(category, title, Severity.Warning);

    private static Finding InfoFinding(string category, string title) =>
        MakeFinding(category, title, Severity.Info);

    // ━━━ Empty / Minimal State ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_NoFindings_ReturnsCleanReport()
    {
        var report = _svc.Reconstruct([]);

        Assert.Equal("None", report.ThreatLevel);
        Assert.Equal(0, report.ActivePhaseCount);
        Assert.Equal(0, report.CoverageScore);
        Assert.Equal(0, report.MappedFindingCount);
        Assert.Equal(0, report.UnmappedFindingCount);
        Assert.Empty(report.Progressions);
        Assert.Empty(report.Predictions);
        Assert.Empty(report.ResponsePlan);
        Assert.Contains("No active kill chain phases", report.Narrative);
    }

    [Fact]
    public void Reconstruct_OnlyPassFindings_NoActivePhases()
    {
        var findings = new List<Finding>
        {
            Finding.Pass("Firewall enabled", "Firewall is active", "Firewall"),
            Finding.Pass("BitLocker on", "Drive encrypted", "Encryption"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Equal("None", report.ThreatLevel);
        Assert.Equal(0, report.ActivePhaseCount);
        Assert.Equal(0, report.MappedFindingCount);
    }

    [Fact]
    public void Reconstruct_NullFindings_ThrowsArgNull()
    {
        Assert.Throws<ArgumentNullException>(() => _svc.Reconstruct(null!));
    }

    // ━━━ Phase Mapping: Initial Access (phase 2) ━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_RdpExposed_MapsToInitialAccess()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled with weak auth"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Equal(1, report.ActivePhaseCount);
        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.IsActive);
        Assert.Equal(1, initialAccess.FindingCount);
        Assert.Equal("Critical", initialAccess.MaxSeverity);
    }

    [Fact]
    public void Reconstruct_FirewallInbound_MapsToInitialAccess()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Firewall", "Inbound rule allows all traffic"),
        };

        var report = _svc.Reconstruct(findings);

        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.IsActive);
        Assert.Equal("Warning", initialAccess.MaxSeverity);
    }

    [Fact]
    public void Reconstruct_SmbExposed_MapsToInitialAccess()
    {
        // Use "SMB" without triggering Reconnaissance keywords ("scan", "exposed port", "service exposed")
        var findings = new List<Finding>
        {
            CriticalFinding("Network", "SMB protocol accessible without authentication"),
        };

        var report = _svc.Reconstruct(findings);

        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.IsActive);
    }

    // ━━━ Phase Mapping: Execution (phase 3) ━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_PowerShellUnrestricted_MapsToExecution()
    {
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Execution policy set to Unrestricted"),
        };

        var report = _svc.Reconstruct(findings);

        var execution = report.Phases.First(p => p.Phase == "Execution");
        Assert.True(execution.IsActive);
        Assert.Equal(1, execution.FindingCount);
    }

    // ━━━ Phase Mapping: Persistence (phase 4) ━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_StartupAutorun_MapsToPersistence()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Startup", "Unknown autorun entry in registry"),
        };

        var report = _svc.Reconstruct(findings);

        var persistence = report.Phases.First(p => p.Phase == "Persistence");
        Assert.True(persistence.IsActive);
    }

    [Fact]
    public void Reconstruct_ScheduledTaskPersistence_MapsToPersistence()
    {
        // Use "new task" keyword that maps to Persistence (4) without triggering Execution keywords
        var findings = new List<Finding>
        {
            CriticalFinding("ScheduledTask", "New task created at boot for persistence"),
        };

        var report = _svc.Reconstruct(findings);

        var persistence = report.Phases.First(p => p.Phase == "Persistence");
        Assert.True(persistence.IsActive);
        Assert.Equal("Critical", persistence.MaxSeverity);
    }

    // ━━━ Phase Mapping: Privilege Escalation (phase 5) ━━━━━━━━━

    [Fact]
    public void Reconstruct_UacDisabled_MapsToPrivEsc()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Account", "UAC disabled on system"),
        };

        var report = _svc.Reconstruct(findings);

        var privEsc = report.Phases.First(p => p.Phase == "Privilege Escalation");
        Assert.True(privEsc.IsActive);
    }

    [Fact]
    public void Reconstruct_UnquotedServicePath_MapsToPrivEsc()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Service", "Unquoted path for service executable"),
        };

        var report = _svc.Reconstruct(findings);

        var privEsc = report.Phases.First(p => p.Phase == "Privilege Escalation");
        Assert.True(privEsc.IsActive);
    }

    // ━━━ Phase Mapping: Defense Evasion (phase 6) ━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_DefenderDisabled_MapsToDefenseEvasion()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Defender", "Real-time off and tamper protection disabled"),
        };

        var report = _svc.Reconstruct(findings);

        var evasion = report.Phases.First(p => p.Phase == "Defense Evasion");
        Assert.True(evasion.IsActive);
        Assert.Equal("Critical", evasion.MaxSeverity);
    }

    [Fact]
    public void Reconstruct_EventLogCleared_MapsToDefenseEvasion()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("EventLog", "Security event log recently cleared"),
        };

        var report = _svc.Reconstruct(findings);

        var evasion = report.Phases.First(p => p.Phase == "Defense Evasion");
        Assert.True(evasion.IsActive);
    }

    // ━━━ Phase Mapping: Credential Access (phase 7) ━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_WeakPasswordPolicy_MapsToCredentialAccess()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Account", "Weak password policy allows easy guessing"),
        };

        var report = _svc.Reconstruct(findings);

        var credAccess = report.Phases.First(p => p.Phase == "Credential Access");
        Assert.True(credAccess.IsActive);
    }

    [Fact]
    public void Reconstruct_BrowserSavedPasswords_MapsToCredentialAccess()
    {
        var findings = new List<Finding>
        {
            InfoFinding("Browser", "Multiple saved passwords in credential store"),
        };

        var report = _svc.Reconstruct(findings);

        var credAccess = report.Phases.First(p => p.Phase == "Credential Access");
        Assert.True(credAccess.IsActive);
    }

    // ━━━ Phase Mapping: Reconnaissance (phase 0) ━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_OpenPort_MapsToReconnaissance()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Network", "Multiple open ports exposed to network scan"),
        };

        var report = _svc.Reconstruct(findings);

        var recon = report.Phases.First(p => p.Phase == "Reconnaissance");
        Assert.True(recon.IsActive);
    }

    // ━━━ Phase Mapping: Impact (phase 13) ━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_BackupDisabled_MapsToImpact()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Backup", "System backup disabled and no recovery plan"),
        };

        var report = _svc.Reconstruct(findings);

        var impact = report.Phases.First(p => p.Phase == "Impact");
        Assert.True(impact.IsActive);
    }

    [Fact]
    public void Reconstruct_PendingUpdates_MapsToImpact()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Update", "Critical patch pending updates for 30+ days"),
        };

        var report = _svc.Reconstruct(findings);

        var impact = report.Phases.First(p => p.Phase == "Impact");
        Assert.True(impact.IsActive);
    }

    // ━━━ Phase Mapping: Lateral Movement (phase 9) ━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_AdminShare_MapsToLateralMovement()
    {
        var findings = new List<Finding>
        {
            WarningFinding("SMB", "Admin share accessible remotely"),
        };

        var report = _svc.Reconstruct(findings);

        var lateral = report.Phases.First(p => p.Phase == "Lateral Movement");
        Assert.True(lateral.IsActive);
    }

    // ━━━ Phase Mapping: Command & Control (phase 11) ━━━━━━━━━━━

    [Fact]
    public void Reconstruct_BeaconDetected_MapsToCnC()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Network", "Beacon activity detected on outbound connection"),
        };

        var report = _svc.Reconstruct(findings);

        var cnc = report.Phases.First(p => p.Phase == "Command & Control");
        Assert.True(cnc.IsActive);
    }

    // ━━━ Phase Mapping: Collection (phase 10) ━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_DataCollection_MapsToCollection()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Privacy", "Excessive data collection telemetry enabled"),
        };

        var report = _svc.Reconstruct(findings);

        var collection = report.Phases.First(p => p.Phase == "Collection");
        Assert.True(collection.IsActive);
    }

    // ━━━ Phase Mapping: Exfiltration (phase 12) ━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_DataExfiltration_MapsToExfiltration()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Network", "Data exfiltration attempt detected"),
        };

        var report = _svc.Reconstruct(findings);

        var exfil = report.Phases.First(p => p.Phase == "Exfiltration");
        Assert.True(exfil.IsActive);
    }

    // ━━━ Unmapped Findings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_UnrecognizedCategoryOrTitle_CountsAsUnmapped()
    {
        var findings = new List<Finding>
        {
            WarningFinding("UnknownCategory", "Some random finding title"),
            WarningFinding("Miscellaneous", "Not matching any phase keywords"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Equal(2, report.UnmappedFindingCount);
        Assert.Equal(0, report.MappedFindingCount);
        Assert.Equal(0, report.ActivePhaseCount);
    }

    [Fact]
    public void Reconstruct_MixOfMappedAndUnmapped_CorrectCounts()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled without MFA"),  // Maps to Initial Access
            WarningFinding("Randomizer", "Some unrelated finding"),       // Unmapped
        };

        var report = _svc.Reconstruct(findings);

        Assert.Equal(1, report.MappedFindingCount);
        Assert.Equal(1, report.UnmappedFindingCount);
        Assert.Equal(1, report.ActivePhaseCount);
    }

    // ━━━ Severity Tracking ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_CriticalSeverity_TrackedInPhase()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Defender", "Real-time off disabled"),
            WarningFinding("Defender", "Exclusion path added for temp folder"),
        };

        var report = _svc.Reconstruct(findings);

        var evasion = report.Phases.First(p => p.Phase == "Defense Evasion");
        Assert.Equal("Critical", evasion.MaxSeverity);
        Assert.Equal(2, evasion.FindingCount);
    }

    [Fact]
    public void Reconstruct_OnlyWarnings_MaxSeverityIsWarning()
    {
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Bypass execution policy detected"),
        };

        var report = _svc.Reconstruct(findings);

        var execution = report.Phases.First(p => p.Phase == "Execution");
        Assert.Equal("Warning", execution.MaxSeverity);
    }

    [Fact]
    public void Reconstruct_OnlyInfo_MaxSeverityIsInfo()
    {
        var findings = new List<Finding>
        {
            InfoFinding("Network", "Open port 443 detected for scan"),
        };

        var report = _svc.Reconstruct(findings);

        var recon = report.Phases.First(p => p.Phase == "Reconnaissance");
        Assert.Equal("Info", recon.MaxSeverity);
    }

    // ━━━ Coverage Score ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_OneActivePhase_CoverageScoreIsLow()
    {
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Unrestricted execution policy"),
        };

        var report = _svc.Reconstruct(findings);

        // 1/14 phases = ~7%
        Assert.True(report.CoverageScore > 0);
        Assert.True(report.CoverageScore < 15);
    }

    [Fact]
    public void Reconstruct_ManyActivePhases_HighCoverageScore()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Network", "Open port scan exposure"),            // Recon
            CriticalFinding("RemoteAccess", "RDP enabled"),                  // Initial Access
            WarningFinding("PowerShell", "Bypass execution policy"),         // Execution
            WarningFinding("Startup", "Autorun entry detected"),             // Persistence
            CriticalFinding("Account", "Local admin privilege escalation"),  // Priv Esc
            CriticalFinding("Defender", "Real-time off disabled"),           // Defense Evasion
            WarningFinding("Account", "Weak password policy"),               // Credential Access
        };

        var report = _svc.Reconstruct(findings);

        // 7/14 phases = 50%
        Assert.True(report.CoverageScore >= 45);
        Assert.True(report.CoverageScore <= 55);
    }

    // ━━━ Attack Progression Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_RansomwarePattern_DetectsProgression()
    {
        // Ransomware: Initial Access + Execution + Defense Evasion + Impact
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled without auth"),      // Initial Access (2)
            WarningFinding("PowerShell", "Unrestricted execution policy"),     // Execution (3)
            CriticalFinding("Defender", "Real-time off protection disabled"), // Defense Evasion (6)
            CriticalFinding("Backup", "Backup disabled no recovery point"),   // Impact (13)
        };

        var report = _svc.Reconstruct(findings);

        Assert.Contains(report.Progressions, p => p.Name == "Ransomware Campaign");
        var ransomware = report.Progressions.First(p => p.Name == "Ransomware Campaign");
        Assert.True(ransomware.Confidence >= 75);
    }

    [Fact]
    public void Reconstruct_AptPattern_DetectsProgression()
    {
        // APT: Reconnaissance + Initial Access + Persistence + Discovery + Lateral Movement
        var findings = new List<Finding>
        {
            WarningFinding("Network", "Service exposed for scan enumeration"),  // Recon (0)
            CriticalFinding("RemoteAccess", "RDP enabled"),                     // Initial Access (2)
            WarningFinding("Startup", "New autorun startup entry"),             // Persistence (4)
            WarningFinding("System", "System info discovery command ran"),      // Discovery (8)
            WarningFinding("SMB", "Admin share accessible remotely"),           // Lateral Movement (9)
        };

        var report = _svc.Reconstruct(findings);

        Assert.Contains(report.Progressions, p => p.Name == "APT Intrusion");
        var apt = report.Progressions.First(p => p.Name == "APT Intrusion");
        Assert.True(apt.Confidence >= 75);
        Assert.Equal("Critical", apt.Severity);
    }

    [Fact]
    public void Reconstruct_CredentialTheft_DetectsProgression()
    {
        // Credential Theft: Initial Access + Priv Esc + Cred Access + Exfil
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),               // Initial Access (2)
            CriticalFinding("Account", "UAC disabled elevated"),          // Priv Esc (5)
            WarningFinding("Account", "Weak password policy enabled"),    // Credential Access (7)
            CriticalFinding("Network", "Data exfiltration detected"),     // Exfiltration (12)
        };

        var report = _svc.Reconstruct(findings);

        Assert.Contains(report.Progressions, p => p.Name == "Credential Theft Operation");
    }

    [Fact]
    public void Reconstruct_PartialProgression_LowerConfidence()
    {
        // Only 2 of 4 phases for ransomware - should still detect but lower confidence
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),                // Initial Access (2)
            CriticalFinding("Defender", "Real-time off tamper disabled"), // Defense Evasion (6)
        };

        var report = _svc.Reconstruct(findings);

        // Should detect ransomware but at lower confidence (2/4 = 50%)
        var ransomware = report.Progressions.FirstOrDefault(p => p.Name == "Ransomware Campaign");
        Assert.NotNull(ransomware);
        Assert.True(ransomware.Confidence >= 40);
        Assert.True(ransomware.Confidence < 75);
    }

    [Fact]
    public void Reconstruct_SinglePhase_NoProgressionDetected()
    {
        // Only 1 phase active - need 2+ matching for progression
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Bypass execution policy"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Empty(report.Progressions);
    }

    [Fact]
    public void Reconstruct_Progressions_LimitedToTop5()
    {
        // Activate many phases to trigger multiple progressions
        var findings = new List<Finding>
        {
            WarningFinding("Network", "Open port scan exposure"),
            CriticalFinding("Certificate", "Outdated vulnerable version"),
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Bypass execution policy"),
            WarningFinding("Startup", "New autorun entry"),
            CriticalFinding("Account", "Admin privilege elevated"),
            CriticalFinding("Defender", "Real-time off disabled"),
            WarningFinding("Account", "Weak password"),
            WarningFinding("System", "System info discovery detected"),
            WarningFinding("SMB", "Admin share lateral access"),
            WarningFinding("Privacy", "Data collection enabled"),
            CriticalFinding("Network", "Beacon C2 callback detected"),
            CriticalFinding("Network", "Data exfiltration"),
            CriticalFinding("Backup", "Backup disabled"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.True(report.Progressions.Count <= 5);
        // Should be ordered by confidence descending
        for (int i = 0; i < report.Progressions.Count - 1; i++)
        {
            Assert.True(report.Progressions[i].Confidence >= report.Progressions[i + 1].Confidence);
        }
    }

    [Fact]
    public void Reconstruct_ProgressionSeverity_DowngradedWhenLowConfidence()
    {
        // Partial match (2/4) - severity should be downgraded
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),       // Initial Access (2)
            WarningFinding("PowerShell", "Bypass execution"),     // Execution (3)
        };

        var report = _svc.Reconstruct(findings);

        // These match "Ransomware Campaign" partially (2/4=50% < 75%)
        // Template severity is "Critical" -> downgraded to "High"
        var ransomware = report.Progressions.FirstOrDefault(p => p.Name == "Ransomware Campaign");
        if (ransomware != null)
        {
            Assert.Equal("High", ransomware.Severity);
        }
    }

    // ━━━ Phase Predictions ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_InitialAccessActive_PredictsExecution()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled without auth"),
        };

        var report = _svc.Reconstruct(findings);

        // Transition from Initial Access (2) -> Execution (3) probability = 85%
        Assert.Contains(report.Predictions, p => p.Phase == "Execution");
        var execPred = report.Predictions.First(p => p.Phase == "Execution");
        Assert.True(execPred.Probability >= 80);
    }

    [Fact]
    public void Reconstruct_CredentialAccess_PredictsLateralMovement()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Account", "Weak password policy enables guessing"),
        };

        var report = _svc.Reconstruct(findings);

        // Transition from Credential Access (7) -> Lateral Movement (9) = 80%
        Assert.Contains(report.Predictions, p => p.Phase == "Lateral Movement");
    }

    [Fact]
    public void Reconstruct_AlreadyActivePhase_NotPredicted()
    {
        // If a phase is already active, it shouldn't appear in predictions
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),           // Initial Access (2)
            WarningFinding("PowerShell", "Bypass execution policy"),  // Execution (3)
        };

        var report = _svc.Reconstruct(findings);

        // Execution already active - should not be in predictions
        Assert.DoesNotContain(report.Predictions, p => p.Phase == "Execution");
        Assert.DoesNotContain(report.Predictions, p => p.Phase == "Initial Access");
    }

    [Fact]
    public void Reconstruct_Predictions_HavePreventiveActions()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
        };

        var report = _svc.Reconstruct(findings);

        foreach (var pred in report.Predictions)
        {
            Assert.NotEmpty(pred.PreventiveActions);
        }
    }

    [Fact]
    public void Reconstruct_Predictions_LimitedToTop5()
    {
        // Activate many phases to generate many transitions
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Bypass execution policy"),
            WarningFinding("Startup", "Autorun entry"),
            CriticalFinding("Account", "Admin privilege elevated"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.True(report.Predictions.Count <= 5);
    }

    [Fact]
    public void Reconstruct_Predictions_FilteredBelow30Percent()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
        };

        var report = _svc.Reconstruct(findings);

        foreach (var pred in report.Predictions)
        {
            Assert.True(pred.Probability >= 30);
        }
    }

    [Fact]
    public void Reconstruct_MultipleSourcePhases_CombineProbability()
    {
        // Execution (3) and Persistence (4) both lead to Priv Esc (5)
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Bypass execution policy"),  // Execution (3)
            WarningFinding("Startup", "New autorun entry"),          // Persistence (4)
        };

        var report = _svc.Reconstruct(findings);

        var privEscPred = report.Predictions.FirstOrDefault(p => p.Phase == "Privilege Escalation");
        if (privEscPred != null)
        {
            // Combined probability should be higher than either individual
            // Exec->PrivEsc=65%, Persist->PrivEsc=60%, combined > max(65,60)
            Assert.True(privEscPred.Probability > 65);
        }
    }

    // ━━━ Response Plan ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_CriticalFindings_HighestPriorityInResponsePlan()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Defender", "Real-time off disabled"),      // Critical (Defense Evasion)
            WarningFinding("PowerShell", "Bypass execution policy"),    // Warning (Execution)
        };

        var report = _svc.Reconstruct(findings);

        Assert.NotEmpty(report.ResponsePlan);
        var first = report.ResponsePlan[0];
        Assert.Equal(1, first.Priority);
        Assert.Equal("Immediate", first.Urgency);
        Assert.Contains("Defense Evasion", first.TargetPhase);
    }

    [Fact]
    public void Reconstruct_WarningFindings_LowerPriorityThanCritical()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("Defender", "Real-time off disabled"),
            WarningFinding("PowerShell", "Bypass execution policy"),
        };

        var report = _svc.Reconstruct(findings);

        var criticalAction = report.ResponsePlan.First(a => a.TargetPhase == "Defense Evasion");
        var warningAction = report.ResponsePlan.FirstOrDefault(a => a.TargetPhase == "Execution");
        if (warningAction != null)
        {
            Assert.True(criticalAction.Priority < warningAction.Priority);
            Assert.Equal("High", warningAction.Urgency);
        }
    }

    [Fact]
    public void Reconstruct_ResponsePlan_IncludesPreventiveForPredictions()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
        };

        var report = _svc.Reconstruct(findings);

        // Should have response actions for both active phases AND predicted phases
        Assert.True(report.ResponsePlan.Count >= 2);
        // Last items should address predicted phases
        var preventive = report.ResponsePlan.Where(a => a.Action.Contains("Proactively")).ToList();
        Assert.NotEmpty(preventive);
    }

    [Fact]
    public void Reconstruct_ResponsePlan_LimitedTo10Actions()
    {
        var findings = new List<Finding>
        {
            WarningFinding("Network", "Open port scan exposure"),
            CriticalFinding("Certificate", "Outdated vulnerable version"),
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Bypass execution policy"),
            WarningFinding("Startup", "New autorun entry"),
            CriticalFinding("Account", "Admin privilege elevated"),
            CriticalFinding("Defender", "Real-time off disabled"),
            WarningFinding("Account", "Weak password"),
            WarningFinding("System", "System info discovery detected"),
            WarningFinding("SMB", "Admin share lateral access"),
            WarningFinding("Privacy", "Data collection enabled"),
            CriticalFinding("Network", "Beacon C2 callback detected"),
            CriticalFinding("Network", "Data exfiltration"),
            CriticalFinding("Backup", "Backup disabled"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.True(report.ResponsePlan.Count <= 10);
    }

    // ━━━ Threat Level Classification ━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_NoActivePhases_ThreatLevelNone()
    {
        var report = _svc.Reconstruct([]);
        Assert.Equal("None", report.ThreatLevel);
    }

    [Fact]
    public void Reconstruct_SinglePhaseActive_ThreatLevelLow()
    {
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Unrestricted execution policy"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Equal("Low", report.ThreatLevel);
    }

    [Fact]
    public void Reconstruct_ThreePhasesActive_AtLeastModerate()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Bypass execution policy"),
            WarningFinding("Startup", "New autorun entry"),
        };

        var report = _svc.Reconstruct(findings);

        // 3 phases active + progression detection may push to High or Critical
        Assert.Contains(report.ThreatLevel, new[] { "Moderate", "High", "Critical" });
    }

    [Fact]
    public void Reconstruct_FivePhasesActive_ThreatLevelHighOrCritical()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Bypass execution policy"),
            WarningFinding("Startup", "New autorun entry"),
            CriticalFinding("Account", "Admin privilege elevated"),
            CriticalFinding("Defender", "Real-time off disabled"),
        };

        var report = _svc.Reconstruct(findings);

        // 5+ phases active with critical progressions detected → High or Critical
        Assert.Contains(report.ThreatLevel, new[] { "High", "Critical" });
    }

    [Fact]
    public void Reconstruct_FullRansomware_ThreatLevelCritical()
    {
        // All 4 ransomware phases active at >=75% confidence
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Unrestricted execution policy"),
            CriticalFinding("Defender", "Real-time off protection disabled"),
            CriticalFinding("Backup", "Backup disabled no recovery"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Equal("Critical", report.ThreatLevel);
    }

    // ━━━ Narrative Generation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_Empty_NarrativeIsClean()
    {
        var report = _svc.Reconstruct([]);
        Assert.Contains("No active kill chain phases", report.Narrative);
        Assert.Contains("no signs of an ongoing attack", report.Narrative);
    }

    [Fact]
    public void Reconstruct_ActivePhases_NarrativeDescribesState()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Bypass execution policy"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Contains("2 of 14 kill chain phases", report.Narrative);
        Assert.Contains("Initial Access", report.Narrative);
        Assert.Contains("Execution", report.Narrative);
    }

    [Fact]
    public void Reconstruct_WithProgression_NarrativeMentionsPattern()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
            WarningFinding("PowerShell", "Unrestricted execution policy"),
            CriticalFinding("Defender", "Real-time off disabled"),
            CriticalFinding("Backup", "Backup disabled"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Contains("Ransomware Campaign", report.Narrative);
    }

    [Fact]
    public void Reconstruct_WithPredictions_NarrativeMentionsNextPhase()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Contains("Most likely next phase", report.Narrative);
    }

    [Fact]
    public void Reconstruct_Narrative_IncludesThreatLevel()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Contains("threat level", report.Narrative.ToLower());
    }

    // ━━━ Phase Definitions ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void PhaseDefinitions_Has14Phases()
    {
        Assert.Equal(14, KillChainReconstructorService.PhaseDefinitions.Length);
    }

    [Fact]
    public void PhaseDefinitions_AllHaveTacticIds()
    {
        foreach (var phase in KillChainReconstructorService.PhaseDefinitions)
        {
            Assert.StartsWith("TA", phase.TacticId);
            Assert.False(string.IsNullOrEmpty(phase.Name));
        }
    }

    [Fact]
    public void PhaseDefinitions_IndicesAreSequential()
    {
        for (int i = 0; i < KillChainReconstructorService.PhaseDefinitions.Length; i++)
        {
            Assert.Equal(i, KillChainReconstructorService.PhaseDefinitions[i].Index);
        }
    }

    // ━━━ Report Structure ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_Report_HasAll14PhaseResults()
    {
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Bypass execution policy"),
        };

        var report = _svc.Reconstruct(findings);

        Assert.Equal(14, report.Phases.Count);
    }

    [Fact]
    public void Reconstruct_InactivePhase_HasZeroFindings()
    {
        var findings = new List<Finding>
        {
            WarningFinding("PowerShell", "Bypass execution policy"),
        };

        var report = _svc.Reconstruct(findings);

        var impact = report.Phases.First(p => p.Phase == "Impact");
        Assert.False(impact.IsActive);
        Assert.Equal(0, impact.FindingCount);
        Assert.Equal("None", impact.MaxSeverity);
        Assert.Empty(impact.ObservedTechniques);
        Assert.Empty(impact.FindingTitles);
    }

    [Fact]
    public void Reconstruct_ActivePhase_HasTechniquesAndTitles()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled without MFA"),
            WarningFinding("Network", "SMB accessible on local network"),
        };

        var report = _svc.Reconstruct(findings);

        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.IsActive);
        Assert.NotEmpty(initialAccess.FindingTitles);
        Assert.NotEmpty(initialAccess.ObservedTechniques);
    }

    [Fact]
    public void Reconstruct_FindingTitles_LimitedTo10PerPhase()
    {
        // Create 15 findings all mapping to the same phase
        var findings = Enumerable.Range(1, 15)
            .Select(i => CriticalFinding("RemoteAccess", $"RDP vulnerability #{i} enabled"))
            .ToList();

        var report = _svc.Reconstruct(findings);

        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.FindingTitles.Count <= 10);
    }

    // ━━━ Complex Multi-Phase Scenario ━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_ComplexRealWorldScenario_FullAnalysis()
    {
        // Simulate a comprehensive security audit with findings across many phases
        var findings = new List<Finding>
        {
            // Reconnaissance
            WarningFinding("Network", "Multiple open ports exposed to scan"),
            // Resource Development
            WarningFinding("Software", "Outdated .NET runtime with known vulnerabilities"),
            // Initial Access
            CriticalFinding("RemoteAccess", "RDP enabled on public interface"),
            CriticalFinding("Firewall", "Inbound rule allows all from internet"),
            // Execution
            WarningFinding("PowerShell", "Execution policy bypass via registry"),
            // Persistence
            WarningFinding("Startup", "Unrecognized autorun entry in Run key"),
            WarningFinding("Service", "New service installed from temp directory"),
            // Privilege Escalation
            CriticalFinding("Account", "Multiple local admin accounts with weak passwords"),
            CriticalFinding("Service", "Unquoted path for critical service"),
            // Defense Evasion
            CriticalFinding("Defender", "Windows Defender real-time off"),
            CriticalFinding("EventLog", "Security audit log cleared recently"),
            // Credential Access
            WarningFinding("Account", "No password complexity enforced"),
            WarningFinding("Browser", "Saved password in Chrome credential store"),
            // Impact
            CriticalFinding("Backup", "No backup configured, shadow copy deleted"),
        };

        var report = _svc.Reconstruct(findings);

        // Verify comprehensive analysis
        Assert.True(report.ActivePhaseCount >= 8);
        Assert.True(report.MappedFindingCount >= 12);
        Assert.True(report.CoverageScore >= 50);
        Assert.Equal("Critical", report.ThreatLevel);
        Assert.NotEmpty(report.Progressions);
        Assert.NotEmpty(report.ResponsePlan);
        Assert.True(report.Narrative.Length > 100);

        // Ransomware progression should be detected (2+3+6+13 all active)
        Assert.Contains(report.Progressions, p => p.Name == "Ransomware Campaign");

        // Response plan should prioritize critical findings
        var first = report.ResponsePlan[0];
        Assert.Equal("Immediate", first.Urgency);
    }

    // ━━━ Edge Cases ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Fact]
    public void Reconstruct_DuplicateFindings_CountedSeparately()
    {
        var findings = new List<Finding>
        {
            CriticalFinding("RemoteAccess", "RDP enabled"),
            CriticalFinding("RemoteAccess", "RDP enabled"),
            CriticalFinding("RemoteAccess", "RDP enabled"),
        };

        var report = _svc.Reconstruct(findings);

        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.Equal(3, initialAccess.FindingCount);
    }

    [Fact]
    public void Reconstruct_CategoryMatchButNoKeyword_NotMapped()
    {
        // Category matches "Network" but title has no matching keywords
        var findings = new List<Finding>
        {
            WarningFinding("Network", "Generic network configuration notice"),
        };

        var report = _svc.Reconstruct(findings);

        // Should be unmapped - no matching keywords
        Assert.Equal(1, report.UnmappedFindingCount);
        Assert.Equal(0, report.MappedFindingCount);
    }

    [Fact]
    public void Reconstruct_KeywordInDescriptionOnly_StillMaps()
    {
        // Title doesn't match but description does
        var findings = new List<Finding>
        {
            MakeFinding("RemoteAccess", "Service configuration issue",
                Severity.Warning, "RDP is enabled with default settings"),
        };

        var report = _svc.Reconstruct(findings);

        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.IsActive);
    }

    [Fact]
    public void Reconstruct_CaseInsensitiveMatching()
    {
        var findings = new List<Finding>
        {
            WarningFinding("POWERSHELL", "UNRESTRICTED EXECUTION POLICY"),
        };

        var report = _svc.Reconstruct(findings);

        var execution = report.Phases.First(p => p.Phase == "Execution");
        Assert.True(execution.IsActive);
    }

    [Fact]
    public void Reconstruct_LargeDataset_CompletesQuickly()
    {
        // Generate 500 varied findings
        var categories = new[] { "Network", "RemoteAccess", "PowerShell", "Startup", "Account", "Defender", "Backup" };
        var keywords = new[] { "scan", "rdp", "bypass", "autorun", "admin", "disabled", "backup disabled" };

        var findings = Enumerable.Range(0, 500)
            .Select(i => WarningFinding(categories[i % categories.Length], $"Finding {keywords[i % keywords.Length]} #{i}"))
            .ToList();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var report = _svc.Reconstruct(findings);
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 5000, $"Took {sw.ElapsedMilliseconds}ms");
        Assert.True(report.MappedFindingCount > 0);
    }

    [Fact]
    public void Reconstruct_ObservedTechniques_LimitedTo8PerPhase()
    {
        // Many findings in same phase should still limit techniques
        var findings = Enumerable.Range(1, 20)
            .Select(i => CriticalFinding("RemoteAccess", $"RDP vulnerability {i} enabled"))
            .ToList();

        var report = _svc.Reconstruct(findings);

        var initialAccess = report.Phases.First(p => p.Phase == "Initial Access");
        Assert.True(initialAccess.ObservedTechniques.Count <= 8);
    }
}