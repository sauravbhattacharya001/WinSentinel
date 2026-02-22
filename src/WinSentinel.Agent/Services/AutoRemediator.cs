using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Represents a remediation action that was taken and can be undone.
/// </summary>
public class RemediationRecord
{
    /// <summary>Unique ID for this remediation.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    /// <summary>When the remediation was performed.</summary>
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Type of remediation action.</summary>
    public RemediationAction ActionType { get; set; }

    /// <summary>Target of the action (PID, file path, IP address, etc.).</summary>
    public string Target { get; set; } = "";

    /// <summary>Details about what was done.</summary>
    public string Description { get; set; } = "";

    /// <summary>Whether the action succeeded.</summary>
    public bool Success { get; set; }

    /// <summary>Error message if the action failed.</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>Undo information: what command/action to reverse this.</summary>
    public string? UndoCommand { get; set; }

    /// <summary>Undo metadata (e.g., original file path for quarantined files).</summary>
    public Dictionary<string, string> UndoMetadata { get; set; } = new();

    /// <summary>Whether this remediation has been undone.</summary>
    public bool Undone { get; set; }

    /// <summary>The threat event that triggered this remediation.</summary>
    public string ThreatEventId { get; set; } = "";
}

/// <summary>
/// Types of remediation actions.
/// </summary>
public enum RemediationAction
{
    KillProcess,
    QuarantineFile,
    BlockIp,
    DisableUserAccount,
    RestoreHostsFile,
    ReEnableDefender,
    RevertRegistry,
    DeleteFirewallRule,
    Custom
}

/// <summary>
/// Autonomous remediation engine.
/// Executes security response actions and maintains an undo log.
/// </summary>
public class AutoRemediator
{
    private readonly ILogger<AutoRemediator> _logger;
    private readonly ConcurrentBag<RemediationRecord> _history = new();
    private readonly string _quarantineDir;
    private readonly string _hostsBackupDir;

    private static readonly string DataDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public AutoRemediator(ILogger<AutoRemediator> logger)
    {
        _logger = logger;
        _quarantineDir = Path.Combine(DataDir, "Quarantine");
        _hostsBackupDir = Path.Combine(DataDir, "HostsBackup");
        Directory.CreateDirectory(_quarantineDir);
        Directory.CreateDirectory(_hostsBackupDir);
    }

    /// <summary>Get all remediation records.</summary>
    public List<RemediationRecord> GetHistory() => _history.ToList();

    /// <summary>Get recent remediation records.</summary>
    public List<RemediationRecord> GetRecent(int count = 50) =>
        _history.OrderByDescending(r => r.Timestamp).Take(count).ToList();

    // ══════════════════════════════════════════
    //  Remediation Actions
    // ══════════════════════════════════════════

    /// <summary>
    /// Kill a suspicious process by PID.
    /// </summary>
    public RemediationRecord KillProcess(int processId, string processName, string threatEventId)
    {
        var record = new RemediationRecord
        {
            ActionType = RemediationAction.KillProcess,
            Target = $"{processName} (PID {processId})",
            ThreatEventId = threatEventId
        };

        try
        {
            using var proc = Process.GetProcessById(processId);
            var exePath = "";
            try { exePath = proc.MainModule?.FileName ?? ""; } catch { }

            proc.Kill(entireProcessTree: true);
            record.Success = true;
            record.Description = $"Killed process '{processName}' (PID {processId}). Path: {exePath}";
            record.UndoMetadata["ProcessName"] = processName;
            record.UndoMetadata["ExecutablePath"] = exePath;
            // Can't truly "undo" a kill, but we record what we can
            _logger.LogWarning("AUTO-REMEDIATION: Killed process {Name} (PID {Pid})", processName, processId);
        }
        catch (ArgumentException)
        {
            record.Success = false;
            record.ErrorMessage = "Process no longer exists";
            record.Description = $"Process '{processName}' (PID {processId}) no longer running";
        }
        catch (Exception ex)
        {
            record.Success = false;
            record.ErrorMessage = ex.Message;
            record.Description = $"Failed to kill '{processName}' (PID {processId}): {ex.Message}";
            _logger.LogError(ex, "Failed to kill process {Name} (PID {Pid})", processName, processId);
        }

        _history.Add(record);
        return record;
    }

    /// <summary>
    /// Quarantine a suspicious file — move to quarantine folder with metadata.
    /// </summary>
    public RemediationRecord QuarantineFile(string filePath, string threatEventId)
    {
        var record = new RemediationRecord
        {
            ActionType = RemediationAction.QuarantineFile,
            Target = filePath,
            ThreatEventId = threatEventId
        };

        try
        {
            if (!File.Exists(filePath))
            {
                record.Success = false;
                record.ErrorMessage = "File not found";
                record.Description = $"File no longer exists: {filePath}";
                _history.Add(record);
                return record;
            }

            var fileName = Path.GetFileName(filePath);
            var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
            var quarantineName = $"{timestamp}_{fileName}.quarantine";
            var quarantinePath = Path.Combine(_quarantineDir, quarantineName);

            // Write metadata file
            var metadataPath = quarantinePath + ".meta.json";
            var metadata = new
            {
                OriginalPath = filePath,
                QuarantinedAt = DateTimeOffset.UtcNow,
                FileSize = new FileInfo(filePath).Length,
                ThreatEventId = threatEventId
            };
            File.WriteAllText(metadataPath, JsonSerializer.Serialize(metadata, JsonOpts));

            // Move the file
            File.Move(filePath, quarantinePath);

            record.Success = true;
            record.Description = $"Quarantined '{fileName}' from {filePath}";
            record.UndoCommand = $"Move-Item -Path \"{quarantinePath}\" -Destination \"{filePath}\"";
            record.UndoMetadata["OriginalPath"] = filePath;
            record.UndoMetadata["QuarantinePath"] = quarantinePath;
            record.UndoMetadata["MetadataPath"] = metadataPath;

            _logger.LogWarning("AUTO-REMEDIATION: Quarantined {Path} → {Quarantine}", filePath, quarantinePath);
        }
        catch (Exception ex)
        {
            record.Success = false;
            record.ErrorMessage = ex.Message;
            record.Description = $"Failed to quarantine {filePath}: {ex.Message}";
            _logger.LogError(ex, "Failed to quarantine {Path}", filePath);
        }

        _history.Add(record);
        return record;
    }

    /// <summary>
    /// Block an IP address via Windows Firewall.
    /// </summary>
    public RemediationRecord BlockIp(string ipAddress, string reason, string threatEventId)
    {
        var record = new RemediationRecord
        {
            ActionType = RemediationAction.BlockIp,
            Target = ipAddress,
            ThreatEventId = threatEventId
        };

        // Validate IP address to prevent command injection
        var sanitizedIp = Core.Helpers.InputSanitizer.SanitizeIpAddress(ipAddress);
        if (sanitizedIp == null)
        {
            record.Success = false;
            record.ErrorMessage = "Invalid IP address format";
            record.Description = $"Rejected IP address '{ipAddress}' — failed validation";
            _logger.LogWarning("AUTO-REMEDIATION: Rejected invalid IP address: {Ip}", ipAddress);
            _history.Add(record);
            return record;
        }

        var ruleName = $"WinSentinel_Block_{sanitizedIp.Replace('.', '_').Replace(':', '_')}";

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block remoteip={sanitizedIp}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);

            if (proc?.ExitCode == 0)
            {
                record.Success = true;
                record.Description = $"Blocked inbound traffic from {ipAddress}. Reason: {reason}";
                record.UndoCommand = $"netsh advfirewall firewall delete rule name=\"{ruleName}\"";
                record.UndoMetadata["RuleName"] = ruleName;
                _logger.LogWarning("AUTO-REMEDIATION: Blocked IP {Ip}", ipAddress);
            }
            else
            {
                var error = proc?.StandardError.ReadToEnd() ?? "Unknown error";
                record.Success = false;
                record.ErrorMessage = error;
                record.Description = $"Failed to block {ipAddress}: {error}";
            }
        }
        catch (Exception ex)
        {
            record.Success = false;
            record.ErrorMessage = ex.Message;
            record.Description = $"Failed to block {ipAddress}: {ex.Message}";
            _logger.LogError(ex, "Failed to block IP {Ip}", ipAddress);
        }

        _history.Add(record);
        return record;
    }

    /// <summary>
    /// Disable a user account (brute force response).
    /// </summary>
    public RemediationRecord DisableUserAccount(string username, string threatEventId)
    {
        var record = new RemediationRecord
        {
            ActionType = RemediationAction.DisableUserAccount,
            Target = username,
            ThreatEventId = threatEventId
        };

        // Validate username to prevent command injection
        var sanitizedUsername = Core.Helpers.InputSanitizer.SanitizeUsername(username);
        if (sanitizedUsername == null)
        {
            record.Success = false;
            record.ErrorMessage = "Invalid username format";
            record.Description = $"Rejected username — failed validation (possible injection attempt)";
            _logger.LogWarning("AUTO-REMEDIATION: Rejected invalid username for disable");
            _history.Add(record);
            return record;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "net",
                Arguments = $"user \"{sanitizedUsername}\" /active:no",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);

            if (proc?.ExitCode == 0)
            {
                record.Success = true;
                record.Description = $"Disabled user account '{username}'";
                record.UndoCommand = $"net user \"{username}\" /active:yes";
                record.UndoMetadata["Username"] = username;
                _logger.LogWarning("AUTO-REMEDIATION: Disabled user account {User}", username);
            }
            else
            {
                var error = proc?.StandardError.ReadToEnd() ?? "Unknown error";
                record.Success = false;
                record.ErrorMessage = error;
                record.Description = $"Failed to disable account '{username}': {error}";
            }
        }
        catch (Exception ex)
        {
            record.Success = false;
            record.ErrorMessage = ex.Message;
            record.Description = $"Failed to disable account '{username}': {ex.Message}";
            _logger.LogError(ex, "Failed to disable user account {User}", username);
        }

        _history.Add(record);
        return record;
    }

    /// <summary>
    /// Restore hosts file from backup.
    /// </summary>
    public RemediationRecord RestoreHostsFile(string threatEventId)
    {
        var hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
        var record = new RemediationRecord
        {
            ActionType = RemediationAction.RestoreHostsFile,
            Target = hostsPath,
            ThreatEventId = threatEventId
        };

        try
        {
            // Find the most recent backup
            var backups = Directory.GetFiles(_hostsBackupDir, "hosts_*.bak")
                .OrderByDescending(f => f)
                .ToList();

            if (backups.Count == 0)
            {
                // No backup exists — create a clean default hosts file
                var defaultHosts = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
                                   "#\r\n" +
                                   "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n" +
                                   "#\r\n" +
                                   "# localhost name resolution is handled within DNS itself.\r\n" +
                                   "#\t127.0.0.1       localhost\r\n" +
                                   "#\t::1             localhost\r\n";

                // Backup current (potentially hijacked) file first
                if (File.Exists(hostsPath))
                {
                    var backupName = $"hosts_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}_hijacked.bak";
                    File.Copy(hostsPath, Path.Combine(_hostsBackupDir, backupName));
                }

                File.WriteAllText(hostsPath, defaultHosts);
                record.Success = true;
                record.Description = "Restored hosts file to clean default (no backup was available)";
            }
            else
            {
                // Backup current file
                if (File.Exists(hostsPath))
                {
                    var backupName = $"hosts_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}_hijacked.bak";
                    File.Copy(hostsPath, Path.Combine(_hostsBackupDir, backupName));
                }

                // Restore from the most recent backup
                File.Copy(backups[0], hostsPath, overwrite: true);
                record.Success = true;
                record.Description = $"Restored hosts file from backup: {Path.GetFileName(backups[0])}";
            }

            record.UndoMetadata["HostsPath"] = hostsPath;
            _logger.LogWarning("AUTO-REMEDIATION: Restored hosts file");
        }
        catch (Exception ex)
        {
            record.Success = false;
            record.ErrorMessage = ex.Message;
            record.Description = $"Failed to restore hosts file: {ex.Message}";
            _logger.LogError(ex, "Failed to restore hosts file");
        }

        _history.Add(record);
        return record;
    }

    /// <summary>
    /// Re-enable Windows Defender real-time protection.
    /// </summary>
    public RemediationRecord ReEnableDefender(string threatEventId)
    {
        var record = new RemediationRecord
        {
            ActionType = RemediationAction.ReEnableDefender,
            Target = "Windows Defender RTP",
            ThreatEventId = threatEventId
        };

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments = "-NoProfile -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(15000);

            if (proc?.ExitCode == 0)
            {
                record.Success = true;
                record.Description = "Re-enabled Windows Defender real-time protection";
                _logger.LogWarning("AUTO-REMEDIATION: Re-enabled Defender RTP");
            }
            else
            {
                var error = proc?.StandardError.ReadToEnd() ?? "Unknown error";
                record.Success = false;
                record.ErrorMessage = error;
                record.Description = $"Failed to re-enable Defender: {error}";
            }
        }
        catch (Exception ex)
        {
            record.Success = false;
            record.ErrorMessage = ex.Message;
            record.Description = $"Failed to re-enable Defender: {ex.Message}";
            _logger.LogError(ex, "Failed to re-enable Defender");
        }

        _history.Add(record);
        return record;
    }

    /// <summary>
    /// Execute an undo operation for a previous remediation.
    /// </summary>
    public RemediationRecord Undo(string remediationId)
    {
        var original = _history.FirstOrDefault(r => r.Id == remediationId);
        if (original == null)
        {
            return new RemediationRecord
            {
                ActionType = RemediationAction.Custom,
                Success = false,
                ErrorMessage = $"Remediation {remediationId} not found",
                Description = "Cannot undo: original remediation not found"
            };
        }

        if (original.Undone)
        {
            return new RemediationRecord
            {
                ActionType = RemediationAction.Custom,
                Success = false,
                ErrorMessage = "Already undone",
                Description = $"Remediation {remediationId} was already undone"
            };
        }

        var undoRecord = new RemediationRecord
        {
            ActionType = RemediationAction.Custom,
            Target = $"Undo of {original.Id}",
            ThreatEventId = original.ThreatEventId
        };

        try
        {
            switch (original.ActionType)
            {
                case RemediationAction.QuarantineFile:
                    UndoQuarantine(original, undoRecord);
                    break;

                case RemediationAction.BlockIp:
                    UndoBlockIp(original, undoRecord);
                    break;

                case RemediationAction.DisableUserAccount:
                    UndoDisableAccount(original, undoRecord);
                    break;

                default:
                    undoRecord.Success = false;
                    undoRecord.ErrorMessage = $"Undo not supported for {original.ActionType}";
                    undoRecord.Description = $"Cannot undo {original.ActionType} actions";
                    break;
            }
        }
        catch (Exception ex)
        {
            undoRecord.Success = false;
            undoRecord.ErrorMessage = ex.Message;
            undoRecord.Description = $"Undo failed: {ex.Message}";
        }

        if (undoRecord.Success)
            original.Undone = true;

        _history.Add(undoRecord);
        return undoRecord;
    }

    private void UndoQuarantine(RemediationRecord original, RemediationRecord undoRecord)
    {
        var originalPath = original.UndoMetadata.GetValueOrDefault("OriginalPath", "");
        var quarantinePath = original.UndoMetadata.GetValueOrDefault("QuarantinePath", "");

        if (string.IsNullOrEmpty(quarantinePath) || !File.Exists(quarantinePath))
        {
            undoRecord.Success = false;
            undoRecord.ErrorMessage = "Quarantined file not found";
            undoRecord.Description = "Cannot restore — quarantined file is missing";
            return;
        }

        File.Move(quarantinePath, originalPath);

        // Clean up metadata file
        var metaPath = original.UndoMetadata.GetValueOrDefault("MetadataPath", "");
        if (!string.IsNullOrEmpty(metaPath) && File.Exists(metaPath))
            File.Delete(metaPath);

        undoRecord.Success = true;
        undoRecord.Description = $"Restored file from quarantine: {originalPath}";
        _logger.LogInformation("UNDO: Restored quarantined file to {Path}", originalPath);
    }

    private void UndoBlockIp(RemediationRecord original, RemediationRecord undoRecord)
    {
        var ruleName = original.UndoMetadata.GetValueOrDefault("RuleName", "");
        if (string.IsNullOrEmpty(ruleName))
        {
            undoRecord.Success = false;
            undoRecord.ErrorMessage = "Firewall rule name not found";
            return;
        }

        // Validate rule name to prevent command injection via stored metadata
        var sanitizedRuleName = Core.Helpers.InputSanitizer.SanitizeFirewallRuleName(ruleName);
        if (sanitizedRuleName == null)
        {
            undoRecord.Success = false;
            undoRecord.ErrorMessage = "Firewall rule name contains invalid characters";
            undoRecord.Description = "Cannot undo — stored rule name failed validation";
            return;
        }

        var psi = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = $"advfirewall firewall delete rule name=\"{sanitizedRuleName}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit(10000);

        undoRecord.Success = proc?.ExitCode == 0;
        undoRecord.Description = undoRecord.Success
            ? $"Removed firewall block rule '{ruleName}'"
            : $"Failed to remove firewall rule: {proc?.StandardError.ReadToEnd()}";

        if (undoRecord.Success)
            _logger.LogInformation("UNDO: Removed firewall block for {Ip}", original.Target);
    }

    private void UndoDisableAccount(RemediationRecord original, RemediationRecord undoRecord)
    {
        var username = original.UndoMetadata.GetValueOrDefault("Username", "");
        if (string.IsNullOrEmpty(username))
        {
            undoRecord.Success = false;
            undoRecord.ErrorMessage = "Username not found";
            return;
        }

        // Validate stored username to prevent command injection
        var sanitizedUsername = Core.Helpers.InputSanitizer.SanitizeUsername(username);
        if (sanitizedUsername == null)
        {
            undoRecord.Success = false;
            undoRecord.ErrorMessage = "Stored username contains invalid characters";
            undoRecord.Description = "Cannot undo — stored username failed validation";
            return;
        }

        var psi = new ProcessStartInfo
        {
            FileName = "net",
            Arguments = $"user \"{sanitizedUsername}\" /active:yes",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit(10000);

        undoRecord.Success = proc?.ExitCode == 0;
        undoRecord.Description = undoRecord.Success
            ? $"Re-enabled user account '{username}'"
            : $"Failed to re-enable account: {proc?.StandardError.ReadToEnd()}";

        if (undoRecord.Success)
            _logger.LogInformation("UNDO: Re-enabled user account {User}", username);
    }

    /// <summary>
    /// Create a backup of the hosts file (should be called periodically when hosts is clean).
    /// </summary>
    public void BackupHostsFile()
    {
        try
        {
            var hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
            if (!File.Exists(hostsPath)) return;

            var backupName = $"hosts_{DateTimeOffset.UtcNow:yyyyMMdd}.bak";
            var backupPath = Path.Combine(_hostsBackupDir, backupName);

            if (!File.Exists(backupPath))
            {
                File.Copy(hostsPath, backupPath);
                _logger.LogInformation("Backed up hosts file to {Path}", backupPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to backup hosts file");
        }
    }

    /// <summary>
    /// Execute a threat's fix command generically. Returns the remediation record.
    /// </summary>
    public RemediationRecord ExecuteFixCommand(ThreatEvent threat)
    {
        if (string.IsNullOrWhiteSpace(threat.FixCommand))
        {
            return new RemediationRecord
            {
                ActionType = RemediationAction.Custom,
                Target = threat.Title,
                ThreatEventId = threat.Id,
                Success = false,
                ErrorMessage = "No fix command available",
                Description = "Threat has no associated fix command"
            };
        }

        // Check for dangerous command patterns before execution
        var dangerCheck = Core.Helpers.InputSanitizer.CheckDangerousCommand(threat.FixCommand);
        if (dangerCheck != null)
        {
            _logger.LogWarning("AUTO-REMEDIATION: Blocked dangerous fix command for '{Title}': {Reason}",
                threat.Title, dangerCheck);
            return new RemediationRecord
            {
                ActionType = RemediationAction.Custom,
                Target = threat.Title,
                ThreatEventId = threat.Id,
                Success = false,
                ErrorMessage = $"Command blocked: {dangerCheck}",
                Description = $"Fix command rejected by safety check: {dangerCheck}"
            };
        }

        var record = new RemediationRecord
        {
            ActionType = RemediationAction.Custom,
            Target = threat.Title,
            ThreatEventId = threat.Id
        };

        try
        {
            // Determine if this is a PowerShell or cmd command
            var isPowerShell = threat.FixCommand.Contains("Set-MpPreference") ||
                               threat.FixCommand.Contains("Remove-Item") ||
                               threat.FixCommand.Contains("Move-Item") ||
                               threat.FixCommand.Contains("$");

            var psi = new ProcessStartInfo
            {
                FileName = isPowerShell ? "powershell" : "cmd.exe",
                Arguments = isPowerShell
                    ? $"-NoProfile -Command \"{threat.FixCommand}\""
                    : $"/c {threat.FixCommand}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(30000);

            record.Success = proc?.ExitCode == 0;
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            var error = proc?.StandardError.ReadToEnd() ?? "";

            record.Description = record.Success
                ? $"Executed fix: {threat.FixCommand}. Output: {Truncate(output, 200)}"
                : $"Fix failed: {threat.FixCommand}. Error: {Truncate(error, 200)}";

            _logger.LogInformation("Executed fix command for '{Title}': success={Success}",
                threat.Title, record.Success);
        }
        catch (Exception ex)
        {
            record.Success = false;
            record.ErrorMessage = ex.Message;
            record.Description = $"Fix command threw exception: {ex.Message}";
            _logger.LogError(ex, "Fix command failed for '{Title}'", threat.Title);
        }

        _history.Add(record);
        return record;
    }

    private static string Truncate(string s, int maxLen) =>
        s.Length <= maxLen ? s : s[..maxLen] + "...";
}
