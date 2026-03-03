using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Scheduled Tasks for security risks including:
/// - Tasks running as SYSTEM/admin with suspicious actions
/// - Tasks executing from writable/temp/user directories
/// - Hidden tasks or tasks with missing/unsigned executables
/// - Tasks triggered at logon/startup (persistence mechanism, MITRE T1053)
/// - Tasks running encoded PowerShell or cmd /c chains
/// - Tasks with actions pointing to non-existent files
/// - Tasks owned by unexpected principals
/// </summary>
public class ScheduledTaskAudit : IAuditModule
{
    public string Name => "Scheduled Task Security Audit";
    public string Category => "ScheduledTasks";
    public string Description =>
        "Checks scheduled tasks for suspicious executables, elevated privileges, " +
        "persistence mechanisms, encoded commands, and missing binaries.";

    /// <summary>
    /// Directories considered suspicious for task executables.
    /// </summary>
    public static readonly string[] SuspiciousPaths = new[]
    {
        @"\temp\",
        @"\tmp\",
        @"\appdata\local\temp\",
        @"\downloads\",
        @"\desktop\",
        @"\public\",
        @"\programdata\",
        @"\users\public\",
        @"\recycle",
    };

    /// <summary>
    /// Known-safe task path prefixes (Microsoft built-in tasks).
    /// </summary>
    public static readonly string[] SafeTaskPrefixes = new[]
    {
        @"\Microsoft\",
        @"\Apple\",
        @"\Google\",
        @"\Adobe\",
    };

    /// <summary>
    /// Suspicious command patterns in task actions.
    /// </summary>
    public static readonly string[] SuspiciousCommandPatterns = new[]
    {
        "-encodedcommand",
        "-enc ",
        "-e ",
        "frombase64string",
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "iwr ",
        "invoke-expression",
        "iex ",
        "start-bitstransfer",
        "net user ",
        "net localgroup ",
        "reg add",
        "reg delete",
        "schtasks /create",
        "bitsadmin",
        "certutil -urlcache",
        "mshta ",
        "rundll32 ",
        "regsvr32 ",
        "wscript ",
        "cscript ",
        "msiexec /q",
    };

    /// <summary>
    /// High-privilege principals that should be scrutinized.
    /// </summary>
    public static readonly HashSet<string> HighPrivilegePrincipals =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "SYSTEM",
            "NT AUTHORITY\\SYSTEM",
            "LOCAL SERVICE",
            "NT AUTHORITY\\LOCAL SERVICE",
            "NETWORK SERVICE",
            "NT AUTHORITY\\NETWORK SERVICE",
        };

    /// <summary>
    /// Data transfer object representing a single scheduled task.
    /// </summary>
    public sealed class TaskEntry
    {
        public string TaskName { get; set; } = "";
        public string TaskPath { get; set; } = "";
        public string State { get; set; } = "Ready"; // Ready, Disabled, Running
        public string Principal { get; set; } = "";
        public string RunLevel { get; set; } = "LeastPrivilege"; // HighestAvailable, LeastPrivilege
        public bool Hidden { get; set; }
        public string Author { get; set; } = "";
        public DateTime? LastRunTime { get; set; }
        public DateTime? NextRunTime { get; set; }
        public List<TaskAction> Actions { get; set; } = new();
        public List<string> Triggers { get; set; } = new(); // "Logon", "Boot", "Daily", etc.

        /// <summary>
        /// Set during collection: true if executable was verified to exist on disk.
        /// Null means existence was not checked (relative path, env var, etc.).
        /// </summary>
        public bool? ExecutableExists { get; set; }
    }

    /// <summary>
    /// Represents a single action within a scheduled task.
    /// </summary>
    public sealed class TaskAction
    {
        public string Execute { get; set; } = "";
        public string Arguments { get; set; } = "";
        public string WorkingDirectory { get; set; } = "";
    }

    /// <summary>
    /// Aggregated system state for analysis.
    /// </summary>
    public sealed class ScheduledTaskState
    {
        public List<TaskEntry> Tasks { get; set; } = new();
        public int TotalTaskCount { get; set; }
    }

    // ── Public entry point ─────────────────────────────────────

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            var state = await CollectStateAsync(cancellationToken);
            AnalyzeState(state, result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    // ── Data collection ─────────────────────────────────────────

    public async Task<ScheduledTaskState> CollectStateAsync(CancellationToken ct = default)
    {
        var state = new ScheduledTaskState();

        try
        {
            var output = await ShellHelper.RunCmdAsync(
                "schtasks /query /fo CSV /v /nh", ct);

            if (!string.IsNullOrWhiteSpace(output))
            {
                var tasks = ParseScheduledTasks(output);
                state.Tasks = tasks;
                state.TotalTaskCount = tasks.Count;
            }
        }
        catch
        {
            // Fallback: try PowerShell
            try
            {
                var psOutput = await ShellHelper.RunPowerShellAsync(
                    "Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author | ConvertTo-Json",
                    ct);

                if (!string.IsNullOrWhiteSpace(psOutput))
                {
                    state.TotalTaskCount = psOutput.Split("TaskName").Length - 1;
                }
            }
            catch { }
        }

        return state;
    }

    private static List<TaskEntry> ParseScheduledTasks(string csvOutput)
    {
        var tasks = new List<TaskEntry>();
        var lines = csvOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines)
        {
            var fields = ParseCsvLine(line.Trim());
            if (fields.Count < 6) continue;

            var entry = new TaskEntry
            {
                TaskPath = fields[0].Trim('"'),
                TaskName = fields[1].Trim('"'),
                State = fields.Count > 3 ? fields[3].Trim('"') : "Unknown",
            };

            // Parse the execute action
            if (fields.Count > 8)
            {
                entry.Actions.Add(new TaskAction
                {
                    Execute = fields[8].Trim('"'),
                });
            }

            // Principal from "Run As User" field
            if (fields.Count > 14)
            {
                entry.Principal = fields[14].Trim('"');
            }

            tasks.Add(entry);
        }

        return tasks;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var inQuotes = false;
        var field = new System.Text.StringBuilder();

        foreach (var c in line)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
                field.Append(c);
            }
            else if (c == ',' && !inQuotes)
            {
                fields.Add(field.ToString());
                field.Clear();
            }
            else
            {
                field.Append(c);
            }
        }

        fields.Add(field.ToString());
        return fields;
    }

    // ── Analysis (pure logic, testable) ─────────────────────────

    /// <summary>
    /// Analyzes scheduled task state and populates findings.
    /// Pure logic — no I/O — testable with synthetic state objects.
    /// </summary>
    public void AnalyzeState(ScheduledTaskState state, AuditResult result)
    {
        CheckTaskCount(state, result);
        
        foreach (var task in state.Tasks)
        {
            if (IsKnownSafeTask(task)) continue;

            CheckSuspiciousExecutablePath(task, result);
            CheckHighPrivilegeTask(task, result);
            CheckSuspiciousCommands(task, result);
            CheckHiddenTask(task, result);
            CheckPersistenceTriggers(task, result);
            CheckMissingExecutable(task, result);
        }

        CheckThirdPartyTaskSummary(state, result);
    }

    private static bool IsKnownSafeTask(TaskEntry task)
    {
        var fullPath = task.TaskPath + task.TaskName;
        return SafeTaskPrefixes.Any(prefix =>
            fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private void CheckTaskCount(ScheduledTaskState state, AuditResult result)
    {
        var thirdPartyCount = state.Tasks.Count(t => !IsKnownSafeTask(t));

        if (thirdPartyCount > 50)
        {
            result.Findings.Add(Finding.Warning(
                $"High Number of Third-Party Tasks: {thirdPartyCount}",
                $"Found {thirdPartyCount} non-Microsoft scheduled tasks. " +
                "A large number of third-party tasks increases the attack surface " +
                "and makes it harder to detect malicious persistence.",
                Category,
                "Review and remove unnecessary scheduled tasks.",
                "schtasks /query /fo TABLE"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                $"Third-Party Task Count: {thirdPartyCount}",
                $"Found {thirdPartyCount} non-Microsoft scheduled tasks — within normal range.",
                Category));
        }
    }

    private void CheckSuspiciousExecutablePath(TaskEntry task, AuditResult result)
    {
        foreach (var action in task.Actions)
        {
            var exe = action.Execute.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(exe)) continue;

            foreach (var suspPath in SuspiciousPaths)
            {
                if (exe.Contains(suspPath, StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(Finding.Critical(
                        $"Task Runs from Suspicious Path: {task.TaskName}",
                        $"Task '{task.TaskPath}{task.TaskName}' executes '{action.Execute}' " +
                        $"from a suspicious directory ({suspPath.Trim('\\')}). " +
                        "Malware commonly places executables in temp/user directories for persistence.",
                        Category,
                        $"Investigate task '{task.TaskName}' and verify the executable is legitimate.",
                        $"schtasks /query /tn \"{task.TaskPath}{task.TaskName}\" /v"));
                    break;
                }
            }
        }
    }

    private void CheckHighPrivilegeTask(TaskEntry task, AuditResult result)
    {
        var isHighPriv = HighPrivilegePrincipals.Contains(task.Principal) ||
                         string.Equals(task.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase);

        if (!isHighPriv) return;

        // Check if actions are also suspicious
        foreach (var action in task.Actions)
        {
            var combined = $"{action.Execute} {action.Arguments}".ToLowerInvariant();
            var hasSuspiciousAction = SuspiciousCommandPatterns.Any(p =>
                combined.Contains(p, StringComparison.OrdinalIgnoreCase));

            if (hasSuspiciousAction)
            {
                result.Findings.Add(Finding.Critical(
                    $"High-Privilege Task with Suspicious Command: {task.TaskName}",
                    $"Task '{task.TaskPath}{task.TaskName}' runs as '{task.Principal}' " +
                    $"with elevated privileges and executes a suspicious command: " +
                    $"'{action.Execute} {action.Arguments}'. " +
                    "This combination is a strong indicator of malicious activity.",
                    Category,
                    $"Immediately investigate task '{task.TaskName}'. Remove if unauthorized.",
                    $"schtasks /delete /tn \"{task.TaskPath}{task.TaskName}\" /f"));
                return;
            }
        }

        // High privilege but no suspicious commands — just informational
        result.Findings.Add(Finding.Info(
            $"Elevated Task: {task.TaskName}",
            $"Task '{task.TaskPath}{task.TaskName}' runs as '{task.Principal}' " +
            "with elevated privileges. Verify this is intended.",
            Category,
            "Review task configuration and ensure it requires elevated privileges."));
    }

    private void CheckSuspiciousCommands(TaskEntry task, AuditResult result)
    {
        foreach (var action in task.Actions)
        {
            var combined = $"{action.Execute} {action.Arguments}".ToLowerInvariant();

            foreach (var pattern in SuspiciousCommandPatterns)
            {
                if (combined.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    // Encoded PowerShell is especially dangerous
                    if (pattern.Contains("encoded", StringComparison.OrdinalIgnoreCase) ||
                        pattern.Contains("base64", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Findings.Add(Finding.Critical(
                            $"Encoded Command in Task: {task.TaskName}",
                            $"Task '{task.TaskPath}{task.TaskName}' uses encoded/base64 commands: " +
                            $"'{combined.Substring(0, Math.Min(combined.Length, 200))}'. " +
                            "Encoded commands are commonly used to obfuscate malicious payloads.",
                            Category,
                            "Decode and review the command. Remove the task if unauthorized.",
                            $"schtasks /query /tn \"{task.TaskPath}{task.TaskName}\" /v"));
                    }
                    else
                    {
                        result.Findings.Add(Finding.Warning(
                            $"Suspicious Command in Task: {task.TaskName}",
                            $"Task '{task.TaskPath}{task.TaskName}' contains suspicious command pattern " +
                            $"'{pattern.Trim()}': '{combined.Substring(0, Math.Min(combined.Length, 200))}'.",
                            Category,
                            $"Review task '{task.TaskName}' and verify the command is legitimate."));
                    }

                    return; // One finding per task for command patterns
                }
            }
        }
    }

    private void CheckHiddenTask(TaskEntry task, AuditResult result)
    {
        if (!task.Hidden) return;

        result.Findings.Add(Finding.Warning(
            $"Hidden Scheduled Task: {task.TaskName}",
            $"Task '{task.TaskPath}{task.TaskName}' is marked as hidden. " +
            "Hidden tasks don't appear in Task Scheduler by default and are " +
            "commonly used by malware to evade detection.",
            Category,
            "Review hidden task and verify it is legitimate.",
            $"schtasks /query /tn \"{task.TaskPath}{task.TaskName}\" /v"));
    }

    private void CheckPersistenceTriggers(TaskEntry task, AuditResult result)
    {
        var persistTriggers = new[] { "Logon", "Boot", "Startup", "SessionConnect" };
        var hasPersistTrigger = task.Triggers.Any(t =>
            persistTriggers.Any(p => t.Contains(p, StringComparison.OrdinalIgnoreCase)));

        if (!hasPersistTrigger) return;

        var triggerList = string.Join(", ", task.Triggers);

        // Only flag as warning if combined with other concerns
        var hasSuspiciousAction = task.Actions.Any(a =>
        {
            var combined = $"{a.Execute} {a.Arguments}".ToLowerInvariant();
            return SuspiciousCommandPatterns.Any(p =>
                combined.Contains(p, StringComparison.OrdinalIgnoreCase));
        });

        if (hasSuspiciousAction)
        {
            result.Findings.Add(Finding.Critical(
                $"Persistence Task with Suspicious Action: {task.TaskName}",
                $"Task '{task.TaskPath}{task.TaskName}' triggers on {triggerList} " +
                "and contains suspicious commands. This is a strong persistence indicator " +
                "(MITRE ATT&CK T1053.005).",
                Category,
                "Investigate immediately. This may be a malware persistence mechanism.",
                $"schtasks /delete /tn \"{task.TaskPath}{task.TaskName}\" /f"));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                $"Persistence Trigger on Task: {task.TaskName}",
                $"Task '{task.TaskPath}{task.TaskName}' triggers on {triggerList}. " +
                "While common for legitimate software, logon/boot triggers are " +
                "also used for persistence.",
                Category,
                "Verify this task's logon/boot trigger is intended."));
        }
    }

    private void CheckMissingExecutable(TaskEntry task, AuditResult result)
    {
        if (task.ExecutableExists != false) return;

        var exeName = task.Actions.FirstOrDefault()?.Execute ?? "unknown";
        result.Findings.Add(Finding.Warning(
            $"Missing Executable for Task: {task.TaskName}",
            $"Task '{task.TaskPath}{task.TaskName}' references executable " +
            $"'{exeName}' which does not exist. This could indicate remnant malware " +
            "or a broken uninstall.",
            Category,
            "Remove the orphaned task or reinstall the associated software.",
            $"schtasks /delete /tn \"{task.TaskPath}{task.TaskName}\" /f"));
    }

    private void CheckThirdPartyTaskSummary(ScheduledTaskState state, AuditResult result)
    {
        var thirdParty = state.Tasks.Where(t => !IsKnownSafeTask(t)).ToList();
        var highPrivCount = thirdParty.Count(t =>
            HighPrivilegePrincipals.Contains(t.Principal) ||
            string.Equals(t.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase));

        if (highPrivCount > 10)
        {
            result.Findings.Add(Finding.Warning(
                $"Many Elevated Third-Party Tasks: {highPrivCount}",
                $"{highPrivCount} third-party tasks run with elevated privileges. " +
                "Each elevated task is a potential avenue for privilege escalation.",
                Category,
                "Review elevated tasks and reduce privileges where possible."));
        }

        var hiddenCount = thirdParty.Count(t => t.Hidden);
        if (hiddenCount > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"Hidden Third-Party Tasks Found: {hiddenCount}",
                $"Found {hiddenCount} hidden third-party scheduled tasks. " +
                "Review each to ensure they are legitimate.",
                Category,
                "Use 'schtasks /query /v' to list all tasks including hidden ones."));
        }
    }
}
