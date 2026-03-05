using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.BackupAudit;

namespace WinSentinel.Tests.Audits;

public class BackupAuditTests
{
    private readonly BackupAudit _audit;

    public BackupAuditTests()
    {
        _audit = new BackupAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Backup Security Audit",
        Category = "Backup"
    };

    private static DateTimeOffset Now => new(2026, 3, 4, 12, 0, 0, TimeSpan.Zero);

    private static BackupState MakeSecureState() => new()
    {
        Now = Now,
        VssServiceStatus = "Running",
        VssStartType = "Manual",
        ShadowCopies = new List<ShadowCopy>
        {
            new() { Id = "SC1", Volume = @"\\?\Volume{abc}\", CreatedAt = Now.AddDays(-1) },
            new() { Id = "SC2", Volume = @"\\?\Volume{abc}\", CreatedAt = Now.AddDays(-3) },
        },
        SystemRestoreEnabled = true,
        RestoreDiskPercent = 10,
        RestorePoints = new List<RestorePoint>
        {
            new() { SequenceNumber = 1, Description = "Windows Update", CreatedAt = Now.AddDays(-2), Type = "MODIFY_SETTINGS" },
            new() { SequenceNumber = 2, Description = "Install driver", CreatedAt = Now.AddDays(-5), Type = "APPLICATION_INSTALL" },
        },
        FileHistoryEnabled = true,
        FileHistoryTarget = @"D:\FileHistory",
        FileHistoryLastBackup = Now.AddDays(-1),
        WindowsBackupConfigured = false,
        RecoveryPartitionExists = true,
        BitLockerEnabled = true,
        ControlledFolderAccessEnabled = true,
    };

    private static BackupState MakeInsecureState() => new()
    {
        Now = Now,
        VssServiceStatus = "Stopped",
        VssStartType = "Disabled",
        ShadowCopies = new List<ShadowCopy>(),
        SystemRestoreEnabled = false,
        RestoreDiskPercent = 0,
        RestorePoints = new List<RestorePoint>(),
        FileHistoryEnabled = false,
        FileHistoryTarget = null,
        FileHistoryLastBackup = null,
        WindowsBackupConfigured = false,
        RecoveryPartitionExists = false,
        BitLockerEnabled = false,
        ControlledFolderAccessEnabled = false,
    };

    // ─── Module metadata ──────────────────────────────────────────

    [Fact]
    public void Name_ReturnsBackupSecurityAudit()
    {
        Assert.Equal("Backup Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsBackup()
    {
        Assert.Equal("Backup", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ─── VSS ──────────────────────────────────────────────────────

    [Fact]
    public void Analyze_VssDisabled_CriticalFinding()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Volume Shadow Copy Service Disabled") &&
            f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_VssRunning_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Volume Shadow Copy Service Running") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_VssManualStopped_InfoFinding()
    {
        var state = MakeSecureState();
        state.VssServiceStatus = "Stopped";
        state.VssStartType = "Manual";
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Volume Shadow Copy Service: Stopped") &&
            f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_NoShadowCopies_WarningFinding()
    {
        var state = MakeSecureState();
        state.ShadowCopies = new List<ShadowCopy>();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No Shadow Copies Found") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_StaleShadowCopies_WarningFinding()
    {
        var state = MakeSecureState();
        state.ShadowCopies = new List<ShadowCopy>
        {
            new() { Id = "SC1", Volume = "C:", CreatedAt = Now.AddDays(-15) }
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Shadow Copies Stale") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_RecentShadowCopies_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Shadow Copies Present") &&
            f.Severity == Severity.Pass);
    }

    // ─── System Restore ───────────────────────────────────────────

    [Fact]
    public void Analyze_SystemRestoreDisabled_CriticalFinding()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("System Restore Disabled") &&
            f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_SystemRestoreEnabled_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("System Restore Enabled") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_SystemRestoreEnabledNoPoints_WarningFinding()
    {
        var state = MakeSecureState();
        state.RestorePoints = new List<RestorePoint>();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No Restore Points Found") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_StaleRestorePoints_WarningFinding()
    {
        var state = MakeSecureState();
        state.RestorePoints = new List<RestorePoint>
        {
            new() { SequenceNumber = 1, Description = "Old", CreatedAt = Now.AddDays(-30), Type = "MODIFY_SETTINGS" }
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Restore Points Stale") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_RecentRestorePoints_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Restore Points Current") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_LowRestoreDiskAllocation_WarningFinding()
    {
        var state = MakeSecureState();
        state.RestoreDiskPercent = 2;
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Low System Restore Disk Allocation") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_HighRestoreDiskAllocation_InfoFinding()
    {
        var state = MakeSecureState();
        state.RestoreDiskPercent = 40;
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("High System Restore Disk Allocation") &&
            f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_NormalRestoreDiskAllocation_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("System Restore Disk Allocation OK") &&
            f.Severity == Severity.Pass);
    }

    // ─── File History ─────────────────────────────────────────────

    [Fact]
    public void Analyze_FileHistoryDisabled_WarningFinding()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("File History Not Enabled") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_FileHistoryEnabled_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("File History Enabled") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_FileHistoryEnabledWithTarget_DescriptionIncludesTarget()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title == "File History Enabled" &&
            f.Description.Contains(@"D:\FileHistory"));
    }

    [Fact]
    public void Analyze_FileHistoryStale_WarningFinding()
    {
        var state = MakeSecureState();
        state.FileHistoryLastBackup = Now.AddDays(-10);
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("File History Backup Stale") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_FileHistoryRecent_NoStaleWarning()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("File History Backup Stale"));
    }

    // ─── Windows Backup ───────────────────────────────────────────

    [Fact]
    public void Analyze_WindowsBackupNotConfigured_InfoFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Windows Backup Not Configured") &&
            f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_WindowsBackupConfiguredRecent_PassFinding()
    {
        var state = MakeSecureState();
        state.WindowsBackupConfigured = true;
        state.WindowsBackupLastRun = Now.AddDays(-5);
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Windows Backup Recent") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_WindowsBackupStale_WarningFinding()
    {
        var state = MakeSecureState();
        state.WindowsBackupConfigured = true;
        state.WindowsBackupLastRun = Now.AddDays(-45);
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Windows Backup Stale") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_WindowsBackupConfiguredNoLastRun_PassFinding()
    {
        var state = MakeSecureState();
        state.WindowsBackupConfigured = true;
        state.WindowsBackupLastRun = null;
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title == "Windows Backup Configured" &&
            f.Severity == Severity.Pass);
    }

    // ─── Recovery Partition ───────────────────────────────────────

    [Fact]
    public void Analyze_RecoveryPartitionPresent_PassFinding()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Recovery Partition Present") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_NoRecoveryPartition_WarningFinding()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No Recovery Partition Found") &&
            f.Severity == Severity.Warning);
    }

    // ─── Ransomware Resilience ────────────────────────────────────

    [Fact]
    public void Analyze_SecureState_HighResilienceScore()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Ransomware Resilience Score") &&
            f.Title.Contains("7/7") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_InsecureState_CriticalResilienceScore()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Ransomware Resilience Score") &&
            f.Title.Contains("0/7") &&
            f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_MidResilience_WarningScore()
    {
        var state = MakeSecureState();
        state.BitLockerEnabled = false;
        state.ControlledFolderAccessEnabled = false;
        state.RecoveryPartitionExists = false;
        // Score: 4/7 = 57% → C → Warning
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Ransomware Resilience Score") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_ResilienceScore_IncludesDetailChecklist()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Ransomware Resilience Score"));
        Assert.Contains("✓ VSS service enabled", finding.Description);
        Assert.Contains("✓ System Restore enabled", finding.Description);
        Assert.Contains("✓ Controlled folder access", finding.Description);
        Assert.Contains("✓ BitLocker encryption active", finding.Description);
        Assert.Contains("✓ Recovery partition present", finding.Description);
    }

    [Fact]
    public void Analyze_InsecureResilience_IncludesFailedChecks()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Ransomware Resilience Score"));
        Assert.Contains("✗ VSS service disabled", finding.Description);
        Assert.Contains("✗ No shadow copies", finding.Description);
        Assert.Contains("✗ System Restore disabled", finding.Description);
        Assert.Contains("✗ No backup solution", finding.Description);
    }

    // ─── Scoring edge cases ───────────────────────────────────────

    [Fact]
    public void Analyze_WindowsBackupCountsAsBackupSolution()
    {
        var state = MakeInsecureState();
        state.VssStartType = "Manual";
        state.WindowsBackupConfigured = true;
        // Score: VSS enabled + backup solution = 2/7 → 28% → F → Critical
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Ransomware Resilience Score"));
        Assert.Contains("✓ Backup solution configured", finding.Description);
    }

    [Fact]
    public void Analyze_FileHistoryCountsAsBackupSolution()
    {
        var state = MakeInsecureState();
        state.VssStartType = "Manual";
        state.FileHistoryEnabled = true;
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Ransomware Resilience Score"));
        Assert.Contains("✓ Backup solution configured", finding.Description);
    }

    // ─── Combined analysis ────────────────────────────────────────

    [Fact]
    public void Analyze_SecureState_ProducesMultipleFindings()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        // Should have findings from all categories
        Assert.True(result.Findings.Count >= 8, $"Expected >= 8 findings, got {result.Findings.Count}");
    }

    [Fact]
    public void Analyze_InsecureState_ProducesMultipleFindings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.True(result.Findings.Count >= 6, $"Expected >= 6 findings, got {result.Findings.Count}");
    }

    [Fact]
    public void Analyze_AllFindingsHaveCategory()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.All(result.Findings, f => Assert.Equal("Backup", f.Category));
    }

    [Fact]
    public void Analyze_CriticalFindings_HaveRemediation()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        var criticals = result.Findings.Where(f => f.Severity == Severity.Critical);
        Assert.All(criticals, f => Assert.False(string.IsNullOrWhiteSpace(f.Remediation)));
    }

    [Fact]
    public void Analyze_WarningFindings_HaveRemediation()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        var warnings = result.Findings.Where(f => f.Severity == Severity.Warning);
        Assert.All(warnings, f => Assert.False(string.IsNullOrWhiteSpace(f.Remediation)));
    }

    // ─── VSS with shadow copies edge cases ────────────────────────

    [Fact]
    public void Analyze_ShadowCopyExactlyAtThreshold_PassFinding()
    {
        var state = MakeSecureState();
        state.ShadowCopies = new List<ShadowCopy>
        {
            new() { Id = "SC1", Volume = "C:", CreatedAt = Now.AddDays(-ShadowCopyMaxAgeDays) }
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        // Exactly at threshold (7 days) should pass
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Shadow Copies Present") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_ShadowCopyJustOverThreshold_WarningFinding()
    {
        var state = MakeSecureState();
        state.ShadowCopies = new List<ShadowCopy>
        {
            new() { Id = "SC1", Volume = "C:", CreatedAt = Now.AddDays(-(ShadowCopyMaxAgeDays + 1)) }
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Shadow Copies Stale") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_RestorePointExactlyAtThreshold_PassFinding()
    {
        var state = MakeSecureState();
        state.RestorePoints = new List<RestorePoint>
        {
            new() { SequenceNumber = 1, Description = "Test", CreatedAt = Now.AddDays(-RestorePointMaxAgeDays), Type = "MODIFY_SETTINGS" }
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Restore Points Current") &&
            f.Severity == Severity.Pass);
    }

    // ─── Resilience grade boundaries ──────────────────────────────

    [Fact]
    public void Analyze_Resilience6of7_GradeA()
    {
        var state = MakeSecureState();
        state.ControlledFolderAccessEnabled = false; // 6/7 = 86% → A
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Ransomware Resilience Score") &&
            f.Title.Contains("(A)") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_Resilience5of7_GradeB()
    {
        var state = MakeSecureState();
        state.ControlledFolderAccessEnabled = false;
        state.BitLockerEnabled = false; // 5/7 = 71% → B
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Ransomware Resilience Score") &&
            f.Title.Contains("(B)") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_Resilience3of7_GradeD()
    {
        var state = MakeInsecureState();
        state.VssStartType = "Manual";
        state.SystemRestoreEnabled = true;
        state.FileHistoryEnabled = true;
        // 3/7 = 43% → D → Warning
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Ransomware Resilience Score") &&
            f.Title.Contains("(D)") &&
            f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_Resilience2of7_GradeF()
    {
        var state = MakeInsecureState();
        state.VssStartType = "Manual";
        state.SystemRestoreEnabled = true;
        // 2/7 = 29% → F → Critical
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Ransomware Resilience Score") &&
            f.Title.Contains("(F)") &&
            f.Severity == Severity.Critical);
    }

    // ─── System Restore disabled skips disk/point checks ──────────

    [Fact]
    public void Analyze_SystemRestoreDisabled_SkipsDiskAllocationCheck()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Disk Allocation"));
    }

    [Fact]
    public void Analyze_SystemRestoreDisabled_SkipsRestorePointCheck()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Restore Points Stale") || f.Title.Contains("No Restore Points"));
    }

    // ─── File History without target ──────────────────────────────

    [Fact]
    public void Analyze_FileHistoryEnabledNoTarget_PassWithoutTargetMention()
    {
        var state = MakeSecureState();
        state.FileHistoryTarget = null;
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title == "File History Enabled");
        Assert.DoesNotContain("target:", finding.Description);
    }

    // ─── VssDisabled fix command ──────────────────────────────────

    [Fact]
    public void Analyze_VssDisabled_HasFixCommand()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Volume Shadow Copy Service Disabled"));
        Assert.NotNull(finding.FixCommand);
        Assert.Contains("Set-Service VSS", finding.FixCommand);
    }

    [Fact]
    public void Analyze_SystemRestoreDisabled_HasFixCommand()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("System Restore Disabled"));
        Assert.NotNull(finding.FixCommand);
        Assert.Contains("Enable-ComputerRestore", finding.FixCommand);
    }

    [Fact]
    public void Analyze_NoShadowCopies_HasFixCommand()
    {
        var state = MakeSecureState();
        state.ShadowCopies = new List<ShadowCopy>();
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("No Shadow Copies Found"));
        Assert.NotNull(finding.FixCommand);
        Assert.Contains("vssadmin", finding.FixCommand);
    }

    // ─── Multiple shadow copies use newest ────────────────────────

    [Fact]
    public void Analyze_MultipleShadowCopies_UsesNewestForAge()
    {
        var state = MakeSecureState();
        state.ShadowCopies = new List<ShadowCopy>
        {
            new() { Id = "SC1", Volume = "C:", CreatedAt = Now.AddDays(-20) },
            new() { Id = "SC2", Volume = "C:", CreatedAt = Now.AddDays(-2) }, // newest
            new() { Id = "SC3", Volume = "C:", CreatedAt = Now.AddDays(-15) },
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Shadow Copies Present") &&
            f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_MultipleShadowCopies_CountIsCorrect()
    {
        var state = MakeSecureState();
        state.ShadowCopies = new List<ShadowCopy>
        {
            new() { Id = "SC1", Volume = "C:", CreatedAt = Now.AddDays(-1) },
            new() { Id = "SC2", Volume = "C:", CreatedAt = Now.AddDays(-2) },
            new() { Id = "SC3", Volume = "C:", CreatedAt = Now.AddDays(-3) },
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        var finding = result.Findings.First(f => f.Title.Contains("Shadow Copies Present"));
        Assert.Contains("3 copies", finding.Title);
    }

    // ─── Multiple restore points use newest ───────────────────────

    [Fact]
    public void Analyze_MultipleRestorePoints_UsesNewestForAge()
    {
        var state = MakeSecureState();
        state.RestorePoints = new List<RestorePoint>
        {
            new() { SequenceNumber = 1, Description = "Old", CreatedAt = Now.AddDays(-30), Type = "MODIFY_SETTINGS" },
            new() { SequenceNumber = 2, Description = "New", CreatedAt = Now.AddDays(-1), Type = "APPLICATION_INSTALL" },
        };
        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Restore Points Current") &&
            f.Severity == Severity.Pass);
    }
}
