using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits backup and recovery security posture including:
/// - Volume Shadow Copy (VSS) service status and shadow copies
/// - System Restore configuration and restore points
/// - File History settings
/// - Windows Backup configuration
/// - Ransomware resilience indicators (VSS accessible, backups recent)
/// - Recovery partition presence
/// </summary>
public class BackupAudit : AuditModuleBase
{
    public override string Name => "Backup Security Audit";
    public override string Category => "Backup";
    public override string Description =>
        "Checks Volume Shadow Copy, System Restore, File History, " +
        "backup recency, and ransomware resilience posture.";

    /// <summary>Maximum days since last shadow copy before warning.</summary>
    public const int ShadowCopyMaxAgeDays = 7;

    /// <summary>Maximum days since last restore point before warning.</summary>
    public const int RestorePointMaxAgeDays = 14;

    /// <summary>Minimum recommended System Restore disk allocation (%).</summary>
    public const int MinRestoreDiskPercent = 5;

    /// <summary>Maximum recommended System Restore disk allocation (%).</summary>
    public const int MaxRestoreDiskPercent = 25;

    // ── State DTO ─────────────────────────────────────────────────

    /// <summary>Collected backup-related system state for testable analysis.</summary>
    public class BackupState
    {
        /// <summary>VSS service status (Running, Stopped, etc.).</summary>
        public string VssServiceStatus { get; set; } = "Unknown";

        /// <summary>VSS service start type (Automatic, Manual, Disabled).</summary>
        public string VssStartType { get; set; } = "Unknown";

        /// <summary>List of shadow copies on the system.</summary>
        public List<ShadowCopy> ShadowCopies { get; set; } = new();

        /// <summary>Whether System Restore is enabled on the OS drive.</summary>
        public bool SystemRestoreEnabled { get; set; }

        /// <summary>Disk space allocated for System Restore (percentage).</summary>
        public int RestoreDiskPercent { get; set; }

        /// <summary>List of restore points.</summary>
        public List<RestorePoint> RestorePoints { get; set; } = new();

        /// <summary>Whether File History is enabled.</summary>
        public bool FileHistoryEnabled { get; set; }

        /// <summary>File History target path (e.g., external drive).</summary>
        public string? FileHistoryTarget { get; set; }

        /// <summary>Last File History backup time (UTC).</summary>
        public DateTimeOffset? FileHistoryLastBackup { get; set; }

        /// <summary>Whether Windows Backup (wbadmin) is configured.</summary>
        public bool WindowsBackupConfigured { get; set; }

        /// <summary>Last Windows Backup time (UTC).</summary>
        public DateTimeOffset? WindowsBackupLastRun { get; set; }

        /// <summary>Whether a recovery partition exists.</summary>
        public bool RecoveryPartitionExists { get; set; }

        /// <summary>Whether BitLocker is enabled on the OS drive.</summary>
        public bool BitLockerEnabled { get; set; }

        /// <summary>Drives with VSS enabled.</summary>
        public List<string> VssEnabledDrives { get; set; } = new();

        /// <summary>Whether controlled folder access (ransomware protection) is on.</summary>
        public bool ControlledFolderAccessEnabled { get; set; }

        /// <summary>Current evaluation time (for age calculations).</summary>
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    }

    public class ShadowCopy
    {
        public string Id { get; set; } = "";
        public string Volume { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
    }

    public class RestorePoint
    {
        public int SequenceNumber { get; set; }
        public string Description { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
        public string Type { get; set; } = ""; // APPLICATION_INSTALL, MODIFY_SETTINGS, etc.
    }

    // ── Live audit ────────────────────────────────────────────────

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = await GatherStateAsync(cancellationToken);
        Analyze(state, result);
    }

    // ── State gathering ───────────────────────────────────────────

    internal async Task<BackupState> GatherStateAsync(CancellationToken ct)
    {
        var state = new BackupState { Now = DateTimeOffset.UtcNow };

        // VSS service
        try
        {
            var vssInfo = await ShellHelper.RunPowerShellAsync(
                "Get-Service VSS | ForEach-Object { '{0}|{1}' -f $_.Status, $_.StartType }", ct);
            var parts = vssInfo.Trim().Split('|');
            if (parts.Length >= 2)
            {
                state.VssServiceStatus = parts[0].Trim();
                state.VssStartType = parts[1].Trim();
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // Shadow copies
        try
        {
            var shadows = await ShellHelper.RunPowerShellAsync(
                @"Get-CimInstance Win32_ShadowCopy | ForEach-Object {
                    '{0}|{1}|{2}' -f $_.ID, $_.VolumeName, $_.InstallDate
                }", ct);
            foreach (var line in shadows.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var p = line.Split('|');
                if (p.Length >= 3 && DateTimeOffset.TryParse(p[2].Trim(), out var dt))
                {
                    state.ShadowCopies.Add(new ShadowCopy
                    {
                        Id = p[0].Trim(),
                        Volume = p[1].Trim(),
                        CreatedAt = dt
                    });
                }
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // System Restore
        try
        {
            var srEnabled = await ShellHelper.RunPowerShellAsync(
                @"try {
                    $sr = Get-ComputerRestorePoint -ErrorAction Stop
                    'ENABLED|' + ($sr | Measure-Object).Count
                } catch { 'DISABLED|0' }", ct);
            state.SystemRestoreEnabled = srEnabled.Trim().StartsWith("ENABLED");

            var srConfig = await ShellHelper.RunPowerShellAsync(
                @"try {
                    $max = (vssadmin list shadowstorage 2>$null | Select-String 'Maximum') -replace '.*\((\d+)%\).*','$1'
                    if ($max) { $max } else { '0' }
                } catch { '0' }", ct);
            if (int.TryParse(srConfig.Trim(), out var pct))
                state.RestoreDiskPercent = pct;

            // Restore points
            var rpOutput = await ShellHelper.RunPowerShellAsync(
                @"try {
                    Get-ComputerRestorePoint -ErrorAction Stop |
                    ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.SequenceNumber, $_.Description, $_.CreationTime, $_.RestorePointType }
                } catch { }", ct);
            foreach (var line in rpOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var p = line.Split('|');
                if (p.Length >= 4 && DateTimeOffset.TryParse(p[2].Trim(), out var dt))
                {
                    state.RestorePoints.Add(new RestorePoint
                    {
                        SequenceNumber = int.TryParse(p[0].Trim(), out var sn) ? sn : 0,
                        Description = p[1].Trim(),
                        CreatedAt = dt,
                        Type = p[3].Trim()
                    });
                }
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // File History
        try
        {
            var fh = await ShellHelper.RunPowerShellAsync(
                @"$fhPath = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\FileHistory\Configuration\Config1.xml'
                if (Test-Path $fhPath) {
                    [xml]$cfg = Get-Content $fhPath -ErrorAction SilentlyContinue
                    $enabled = $cfg.SelectSingleNode('//Enabled')
                    if ($enabled -and $enabled.InnerText -eq 'true') { 'ENABLED' } else { 'DISABLED' }
                } else { 'DISABLED' }", ct);
            state.FileHistoryEnabled = fh.Trim() == "ENABLED";
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // Windows Backup
        try
        {
            var wb = await ShellHelper.RunPowerShellAsync(
                @"try {
                    $policy = Get-WBPolicy -ErrorAction Stop
                    if ($policy) {
                        $last = (Get-WBSummary -ErrorAction SilentlyContinue).LastSuccessfulBackupTime
                        'CONFIGURED|' + $last
                    } else { 'NONE|' }
                } catch { 'NONE|' }", ct);
            var wbParts = wb.Trim().Split('|');
            state.WindowsBackupConfigured = wbParts[0] == "CONFIGURED";
            if (wbParts.Length > 1 && DateTimeOffset.TryParse(wbParts[1].Trim(), out var wbDt))
                state.WindowsBackupLastRun = wbDt;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // Recovery partition
        try
        {
            var rec = await ShellHelper.RunPowerShellAsync(
                @"Get-Partition | Where-Object { $_.Type -eq 'Recovery' } | Measure-Object | Select-Object -ExpandProperty Count", ct);
            state.RecoveryPartitionExists = int.TryParse(rec.Trim(), out var cnt) && cnt > 0;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // BitLocker
        try
        {
            var bl = await ShellHelper.RunPowerShellAsync(
                @"try {
                    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
                    if ($vol.ProtectionStatus -eq 'On') { 'ON' } else { 'OFF' }
                } catch { 'OFF' }", ct);
            state.BitLockerEnabled = bl.Trim() == "ON";
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // Controlled folder access
        try
        {
            var cfa = await ShellHelper.RunPowerShellAsync(
                @"try {
                    (Get-MpPreference).EnableControlledFolderAccess
                } catch { '0' }", ct);
            state.ControlledFolderAccessEnabled = cfa.Trim() == "1" || cfa.Trim().Equals("Enabled", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        return state;
    }

    // ── Analysis (pure, testable) ─────────────────────────────────

    /// <summary>Analyzes the gathered backup state and adds findings.</summary>
    public void Analyze(BackupState state, AuditResult result)
    {
        AnalyzeVss(state, result);
        AnalyzeSystemRestore(state, result);
        AnalyzeFileHistory(state, result);
        AnalyzeWindowsBackup(state, result);
        AnalyzeRecovery(state, result);
        AnalyzeRansomwareResilience(state, result);
    }

    internal void AnalyzeVss(BackupState state, AuditResult result)
    {
        // VSS service status
        if (state.VssStartType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                "Volume Shadow Copy Service Disabled",
                "The VSS service is disabled. Shadow copies cannot be created, leaving the system " +
                "vulnerable to data loss and ransomware with no recovery snapshots.",
                Category,
                "Enable the VSS service: Set-Service VSS -StartupType Manual",
                "Set-Service VSS -StartupType Manual; Start-Service VSS"));
        }
        else if (state.VssServiceStatus.Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "Volume Shadow Copy Service Running",
                "The VSS service is running and available for snapshot creation.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                $"Volume Shadow Copy Service: {state.VssServiceStatus}",
                $"The VSS service is {state.VssServiceStatus} (start type: {state.VssStartType}). " +
                "It will start on demand when needed.",
                Category));
        }

        // Shadow copy count and age
        if (state.ShadowCopies.Count == 0)
        {
            result.Findings.Add(Finding.Warning(
                "No Shadow Copies Found",
                "No Volume Shadow Copies exist on any drive. Without shadow copies, " +
                "file recovery from accidental deletion or ransomware is not possible.",
                Category,
                "Create a shadow copy: vssadmin create shadow /for=C:",
                "vssadmin create shadow /for=C:"));
        }
        else
        {
            var newest = state.ShadowCopies.Max(s => s.CreatedAt);
            var ageDays = (int)(state.Now - newest).TotalDays;

            if (ageDays > ShadowCopyMaxAgeDays)
            {
                result.Findings.Add(Finding.Warning(
                    $"Shadow Copies Stale ({ageDays} days old)",
                    $"The newest shadow copy is {ageDays} days old (threshold: {ShadowCopyMaxAgeDays} days). " +
                    "Recent changes may not be recoverable.",
                    Category,
                    "Create a fresh shadow copy or verify scheduled shadow copy tasks.",
                    "vssadmin create shadow /for=C:"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    $"Shadow Copies Present ({state.ShadowCopies.Count} copies, newest {ageDays}d old)",
                    $"Found {state.ShadowCopies.Count} shadow copies. The most recent is {ageDays} day(s) old.",
                    Category));
            }
        }
    }

    internal void AnalyzeSystemRestore(BackupState state, AuditResult result)
    {
        if (!state.SystemRestoreEnabled)
        {
            result.Findings.Add(Finding.Critical(
                "System Restore Disabled",
                "System Restore is disabled on the OS drive. You cannot roll back to a known-good state " +
                "after malware infection, bad driver install, or system misconfiguration.",
                Category,
                "Enable System Restore: Enable-ComputerRestore -Drive $env:SystemDrive",
                "Enable-ComputerRestore -Drive $env:SystemDrive"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "System Restore Enabled",
                "System Restore is enabled on the OS drive.",
                Category));
        }

        // Restore point recency
        if (state.SystemRestoreEnabled && state.RestorePoints.Count == 0)
        {
            result.Findings.Add(Finding.Warning(
                "No Restore Points Found",
                "System Restore is enabled but no restore points exist. " +
                "Create a restore point to enable system recovery.",
                Category,
                "Create a restore point: Checkpoint-Computer -Description 'Manual' -RestorePointType MODIFY_SETTINGS",
                "Checkpoint-Computer -Description 'WinSentinel Checkpoint' -RestorePointType MODIFY_SETTINGS"));
        }
        else if (state.RestorePoints.Count > 0)
        {
            var newest = state.RestorePoints.Max(r => r.CreatedAt);
            var ageDays = (int)(state.Now - newest).TotalDays;

            if (ageDays > RestorePointMaxAgeDays)
            {
                result.Findings.Add(Finding.Warning(
                    $"Restore Points Stale ({ageDays} days old)",
                    $"The newest restore point is {ageDays} days old (threshold: {RestorePointMaxAgeDays} days). " +
                    "System recovery may revert too many changes.",
                    Category,
                    "Create a fresh restore point.",
                    "Checkpoint-Computer -Description 'WinSentinel Checkpoint' -RestorePointType MODIFY_SETTINGS"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    $"Restore Points Current ({state.RestorePoints.Count} points, newest {ageDays}d old)",
                    $"Found {state.RestorePoints.Count} restore points. The most recent is {ageDays} day(s) old.",
                    Category));
            }
        }

        // Disk allocation
        if (state.SystemRestoreEnabled && state.RestoreDiskPercent > 0)
        {
            if (state.RestoreDiskPercent < MinRestoreDiskPercent)
            {
                result.Findings.Add(Finding.Warning(
                    $"Low System Restore Disk Allocation ({state.RestoreDiskPercent}%)",
                    $"Only {state.RestoreDiskPercent}% disk space is allocated for System Restore " +
                    $"(recommended minimum: {MinRestoreDiskPercent}%). Old restore points may be purged too quickly.",
                    Category,
                    $"Increase allocation: vssadmin resize shadowstorage /for=C: /on=C: /maxsize={MinRestoreDiskPercent}%"));
            }
            else if (state.RestoreDiskPercent > MaxRestoreDiskPercent)
            {
                result.Findings.Add(Finding.Info(
                    $"High System Restore Disk Allocation ({state.RestoreDiskPercent}%)",
                    $"{state.RestoreDiskPercent}% disk space is allocated for System Restore " +
                    $"(recommended max: {MaxRestoreDiskPercent}%). Consider reducing if disk space is limited.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    $"System Restore Disk Allocation OK ({state.RestoreDiskPercent}%)",
                    $"{state.RestoreDiskPercent}% disk space allocated for System Restore (range: {MinRestoreDiskPercent}-{MaxRestoreDiskPercent}%).",
                    Category));
            }
        }
    }

    internal void AnalyzeFileHistory(BackupState state, AuditResult result)
    {
        if (!state.FileHistoryEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "File History Not Enabled",
                "Windows File History is not configured. File History provides automatic, " +
                "versioned backups of user files to an external drive or network location.",
                Category,
                "Enable File History in Settings > Update & Security > Backup.",
                "start ms-settings:backup"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "File History Enabled",
                $"File History is enabled" +
                (state.FileHistoryTarget != null ? $" (target: {state.FileHistoryTarget})" : "") + ".",
                Category));

            // Check last backup recency
            if (state.FileHistoryLastBackup.HasValue)
            {
                var ageDays = (int)(state.Now - state.FileHistoryLastBackup.Value).TotalDays;
                if (ageDays > 7)
                {
                    result.Findings.Add(Finding.Warning(
                        $"File History Backup Stale ({ageDays} days old)",
                        $"Last File History backup was {ageDays} days ago. " +
                        "The backup drive may be disconnected or File History may have errors.",
                        Category,
                        "Check File History status and ensure the backup drive is connected."));
                }
            }
        }
    }

    internal void AnalyzeWindowsBackup(BackupState state, AuditResult result)
    {
        if (!state.WindowsBackupConfigured)
        {
            result.Findings.Add(Finding.Info(
                "Windows Backup Not Configured",
                "Windows Server Backup (wbadmin) is not configured. This is typical for workstations " +
                "that use File History or third-party backup solutions instead.",
                Category,
                "For full system image backups, configure wbadmin or a third-party solution."));
        }
        else
        {
            if (state.WindowsBackupLastRun.HasValue)
            {
                var ageDays = (int)(state.Now - state.WindowsBackupLastRun.Value).TotalDays;
                if (ageDays > 30)
                {
                    result.Findings.Add(Finding.Warning(
                        $"Windows Backup Stale ({ageDays} days since last run)",
                        $"The last Windows Backup ran {ageDays} days ago. " +
                        "Ensure the backup schedule is active and target storage is available.",
                        Category));
                }
                else
                {
                    result.Findings.Add(Finding.Pass(
                        $"Windows Backup Recent ({ageDays}d ago)",
                        $"Windows Backup last ran {ageDays} day(s) ago.",
                        Category));
                }
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Windows Backup Configured",
                    "Windows Backup is configured.",
                    Category));
            }
        }
    }

    internal void AnalyzeRecovery(BackupState state, AuditResult result)
    {
        if (state.RecoveryPartitionExists)
        {
            result.Findings.Add(Finding.Pass(
                "Recovery Partition Present",
                "A recovery partition exists, enabling Windows Recovery Environment (WinRE) for system repair.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning(
                "No Recovery Partition Found",
                "No recovery partition was detected. Without it, you cannot use Windows Recovery Environment " +
                "for startup repair, system image recovery, or command prompt boot.",
                Category,
                "Consider creating a recovery drive: search 'Create a recovery drive' in Start."));
        }
    }

    internal void AnalyzeRansomwareResilience(BackupState state, AuditResult result)
    {
        // Composite ransomware resilience score
        int score = 0;
        int maxScore = 7;
        var details = new List<string>();

        if (state.VssStartType != "Disabled")
        {
            score++;
            details.Add("✓ VSS service enabled");
        }
        else
        {
            details.Add("✗ VSS service disabled");
        }

        if (state.ShadowCopies.Count > 0)
        {
            score++;
            details.Add($"✓ {state.ShadowCopies.Count} shadow copies available");
        }
        else
        {
            details.Add("✗ No shadow copies");
        }

        if (state.SystemRestoreEnabled)
        {
            score++;
            details.Add("✓ System Restore enabled");
        }
        else
        {
            details.Add("✗ System Restore disabled");
        }

        if (state.FileHistoryEnabled || state.WindowsBackupConfigured)
        {
            score++;
            details.Add("✓ Backup solution configured");
        }
        else
        {
            details.Add("✗ No backup solution");
        }

        if (state.ControlledFolderAccessEnabled)
        {
            score++;
            details.Add("✓ Controlled folder access (ransomware protection) enabled");
        }
        else
        {
            details.Add("✗ Controlled folder access disabled");
        }

        if (state.BitLockerEnabled)
        {
            score++;
            details.Add("✓ BitLocker encryption active");
        }
        else
        {
            details.Add("✗ BitLocker not enabled");
        }

        if (state.RecoveryPartitionExists)
        {
            score++;
            details.Add("✓ Recovery partition present");
        }
        else
        {
            details.Add("✗ No recovery partition");
        }

        var pct = (int)Math.Round(100.0 * score / maxScore);
        var grade = pct >= 85 ? "A" : pct >= 70 ? "B" : pct >= 50 ? "C" : pct >= 30 ? "D" : "F";
        var detailText = string.Join("\n", details);

        if (pct >= 70)
        {
            result.Findings.Add(Finding.Pass(
                $"Ransomware Resilience Score: {score}/{maxScore} ({grade})",
                $"Backup and recovery posture is good.\n{detailText}",
                Category));
        }
        else if (pct >= 40)
        {
            result.Findings.Add(Finding.Warning(
                $"Ransomware Resilience Score: {score}/{maxScore} ({grade})",
                $"Backup and recovery posture has gaps that could leave you vulnerable.\n{detailText}",
                Category,
                "Enable VSS, System Restore, and configure regular backups to improve resilience."));
        }
        else
        {
            result.Findings.Add(Finding.Critical(
                $"Ransomware Resilience Score: {score}/{maxScore} ({grade})",
                $"Critically low backup and recovery posture. A ransomware attack would likely " +
                $"result in permanent data loss.\n{detailText}",
                Category,
                "Urgently configure backups: enable VSS, System Restore, and File History or a third-party backup tool."));
        }
    }
}
