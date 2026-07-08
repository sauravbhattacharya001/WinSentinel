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
    /// Script-interpreter / LOLBin executables that are legitimate, signed, in-box binaries
    /// (so they never trip <see cref="SuspiciousPaths"/> on their own path) yet routinely act
    /// as launchers for an attacker-supplied payload passed as an <em>argument</em>. Compared
    /// by trailing file name so a fully-qualified path (e.g. C:\Windows\System32\WindowsPowerShell
    /// \v1.0\powershell.exe) still matches.
    /// </summary>
    public static readonly string[] LolbinInterpreters = new[]
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "msbuild.exe",
        "installutil.exe",
    };

    /// <summary>
    /// User- or world-writable directory fragments. A script path that lives under one of these
    /// can be replaced by any (even non-admin) local user, so a task that executes it - especially
    /// as SYSTEM - is a persistence / privilege-escalation foothold. These deliberately include
    /// the roaming/local AppData and ProgramData roots that <see cref="SuspiciousPaths"/> omits,
    /// because a signed interpreter's own path never lands there but its <em>payload</em> often does.
    /// </summary>
    public static readonly string[] UserWritablePathNeedles = new[]
    {
        @"\temp\",
        @"\tmp\",
        @"\appdata\local\temp\",
        @"\appdata\local\",
        @"\appdata\roaming\",
        @"\downloads\",
        @"\desktop\",
        @"\users\public\",
        @"\public\",
        @"\programdata\",
        @"\$recycle.bin\",
        @"\windows\tasks\",
        @"\windows\temp\",
    };

    /// <summary>
    /// File extensions treated as "a script / payload the interpreter will execute" when found
    /// in a task's arguments. Used to locate the payload path an interpreter LOLBin is launching.
    /// </summary>
    public static readonly string[] ScriptPayloadExtensions = new[]
    {
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".hta", ".dll", ".sct", ".xml", ".exe",
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
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
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

    // ── Helpers ─────────────────────────────────────────────────

    /// <summary>
    /// Build a safe schtasks /query command by escaping the task identifier.
    /// Task names are attacker-controlled (any local user can create scheduled
    /// tasks with arbitrary names), so embedding them raw inside a FixCommand
    /// string that later runs through FixEngine → PowerShell -EncodedCommand
    /// is CWE-78 command injection.  Single-quote the path (prevents $() expansion)
    /// and double any embedded single-quotes so they become literal characters.
    /// </summary>
    private static string SafeSchtasksQuery(string taskPath, string taskName)
    {
        var escaped = $"{taskPath}{taskName}".Replace("'", "''");
        return $"schtasks /query /tn '{escaped}' /v";
    }

    /// <summary>
    /// Build a safe schtasks /delete command.  Same escaping rationale as
    /// <see cref="SafeSchtasksQuery"/>.
    /// </summary>
    private static string SafeSchtasksDelete(string taskPath, string taskName)
    {
        var escaped = $"{taskPath}{taskName}".Replace("'", "''");
        return $"schtasks /delete /tn '{escaped}' /f";
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
            CheckLolbinScriptFromUserPath(task, result);
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
                        SafeSchtasksQuery(task.TaskPath, task.TaskName)));
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Flags tasks where a legitimate, signed script interpreter (powershell, cmd, wscript,
    /// mshta, rundll32, regsvr32, ...) is used to launch a script/payload that lives in a
    /// user- or world-writable directory (Temp, Downloads, AppData\Roaming, ProgramData,
    /// Public, ...).
    ///
    /// <para>This closes a real gap left by <see cref="CheckSuspiciousExecutablePath"/> and
    /// <see cref="CheckSuspiciousCommands"/>: the interpreter's own path is <c>System32</c>
    /// (so the suspicious-<em>Execute</em>-path check passes it), and a bare
    /// <c>-File C:\Users\bob\AppData\Roaming\update.ps1</c> matches none of the
    /// <see cref="SuspiciousCommandPatterns"/> (no <c>-enc</c>, no <c>iex</c>, no download
    /// cmdlet) - yet any local user can overwrite that <c>.ps1</c> and have it run, often as
    /// SYSTEM. Living-off-the-land persistence via a signed interpreter pointed at a writable
    /// payload is one of the most common real-world scheduled-task abuse patterns
    /// (MITRE ATT&amp;CK T1053.005 + T1059).</para>
    ///
    /// <para>Severity escalates to Critical when the task also runs with elevated privileges
    /// or fires on a logon/boot persistence trigger (attacker gets code execution at every
    /// startup, potentially as SYSTEM); otherwise it is a Warning. Emits at most one finding
    /// per task. Not auto-fixed - blindly deleting a task can break legitimate software - so
    /// the investigative query is offered as remediation, matching the module's convention for
    /// judgement-call findings.</para>
    /// </summary>
    private void CheckLolbinScriptFromUserPath(TaskEntry task, AuditResult result)
    {
        foreach (var action in task.Actions)
        {
            if (!IsLolbinInterpreter(action.Execute)) continue;

            var payload = FindUserWritablePayloadPath(action.Arguments);
            if (payload is null) continue;

            bool isHighPriv = HighPrivilegePrincipals.Contains(task.Principal) ||
                string.Equals(task.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase);

            var persistTriggers = new[] { "Logon", "Boot", "Startup", "SessionConnect" };
            bool hasPersistTrigger = task.Triggers.Any(t =>
                persistTriggers.Any(p => t.Contains(p, StringComparison.OrdinalIgnoreCase)));

            var interpreter = System.IO.Path.GetFileName(action.Execute.Trim('"'));
            var escalators = new List<string>();
            if (isHighPriv) escalators.Add($"runs elevated (as '{(string.IsNullOrWhiteSpace(task.Principal) ? task.RunLevel : task.Principal)}')");
            if (hasPersistTrigger) escalators.Add($"fires on a {string.Join("/", task.Triggers)} trigger");
            var escalatorNote = escalators.Count > 0
                ? " The task " + string.Join(" and ", escalators) + ", so an attacker who overwrites the payload gains code execution" + (isHighPriv ? " with elevated privileges" : "") + (hasPersistTrigger ? " at every startup" : "") + "."
                : "";

            var description =
                $"Task '{task.TaskPath}{task.TaskName}' uses the signed interpreter '{interpreter}' to run " +
                $"a script/payload from a user-writable location: '{payload}'. The interpreter itself is a " +
                "legitimate in-box binary, but any local user can replace a file in that directory - so this is a " +
                "living-off-the-land persistence / privilege-escalation foothold (MITRE ATT&CK T1053.005)." +
                escalatorNote;

            if (isHighPriv || hasPersistTrigger)
            {
                result.Findings.Add(Finding.Critical(
                    $"Interpreter Runs Writable Script: {task.TaskName}",
                    description,
                    Category,
                    $"Move '{payload}' to a location only administrators can write, restrict the payload's ACL, " +
                    $"or remove the task if it is unauthorized. Inspect it first with: {SafeSchtasksQuery(task.TaskPath, task.TaskName)}",
                    SafeSchtasksQuery(task.TaskPath, task.TaskName)));
            }
            else
            {
                result.Findings.Add(Finding.Warning(
                    $"Interpreter Runs Writable Script: {task.TaskName}",
                    description,
                    Category,
                    $"Move '{payload}' to an admin-only directory or tighten its ACL so non-admins cannot modify it. " +
                    $"Review the task with: {SafeSchtasksQuery(task.TaskPath, task.TaskName)}"));
            }

            return; // one finding per task
        }
    }

    /// <summary>
    /// True when <paramref name="execute"/> is one of the known script-interpreter LOLBins
    /// (<see cref="LolbinInterpreters"/>), compared by trailing file name so a full path such
    /// as <c>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</c> still matches.
    /// Surrounding quotes are stripped. Pure - no I/O.
    /// </summary>
    public static bool IsLolbinInterpreter(string? execute)
    {
        if (string.IsNullOrWhiteSpace(execute)) return false;
        var e = execute.Trim().Trim('"').ToLowerInvariant();
        if (e.Length == 0) return false;
        var fileName = e.Replace('/', '\\');
        int slash = fileName.LastIndexOf('\\');
        if (slash >= 0 && slash < fileName.Length - 1) fileName = fileName.Substring(slash + 1);
        return LolbinInterpreters.Any(n => string.Equals(fileName, n, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Scans an interpreter's <paramref name="arguments"/> for a token that both looks like a
    /// script/payload path (ends in one of <see cref="ScriptPayloadExtensions"/>) and resides
    /// in a user- or world-writable directory (<see cref="UserWritablePathNeedles"/>). Returns
    /// the offending path (as it appeared, de-quoted) or <c>null</c> when nothing matches.
    ///
    /// <para>Handles the common forms: a plain path, a quoted path with spaces, and a
    /// <c>-File:</c> / <c>/C</c> style flag immediately followed by the path. The scan is a
    /// whole-argument-string search so it is robust to how the collector split the arguments.
    /// Pure - no I/O, no existence check (that is deliberately not required: the risk is the
    /// writable location, whether or not the file exists right now).</para>
    /// </summary>
    public static string? FindUserWritablePayloadPath(string? arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments)) return null;
        var lower = arguments.ToLowerInvariant();

        // Quick reject: must mention at least one writable-dir fragment AND one payload extension.
        if (!UserWritablePathNeedles.Any(n => lower.Contains(n, StringComparison.OrdinalIgnoreCase)))
            return null;
        if (!ScriptPayloadExtensions.Any(x => lower.Contains(x, StringComparison.OrdinalIgnoreCase)))
            return null;

        // Tokenise on whitespace while honouring double quotes, so "C:\Program Files\..." stays whole.
        foreach (var token in TokenizeArguments(arguments))
        {
            var t = token.Trim().Trim('"');
            if (t.Length == 0) continue;

            // Strip a leading flag glued to the path, e.g. -File:C:\... or /C:C:\...
            // (only when the token starts with a '-'/'/' flag; a bare drive path like
            // C:\... must not be truncated at its drive colon).
            if (t.StartsWith("-") || t.StartsWith("/"))
            {
                int colon = t.IndexOf(':');
                if (colon > 1)
                {
                    var after = t.Substring(colon + 1);
                    if (after.Contains('\\')) t = after;
                }
            }
            var tl = t.ToLowerInvariant();

            bool looksLikePayload = ScriptPayloadExtensions.Any(x =>
                tl.EndsWith(x, StringComparison.OrdinalIgnoreCase));
            bool inWritableDir = UserWritablePathNeedles.Any(n =>
                tl.Contains(n, StringComparison.OrdinalIgnoreCase));

            if (looksLikePayload && inWritableDir) return t;
        }

        return null;
    }

    /// <summary>
    /// Splits an argument string on whitespace, keeping double-quoted spans (which may contain
    /// spaces) as a single token. Pure helper for <see cref="FindUserWritablePayloadPath"/>.
    /// </summary>
    public static List<string> TokenizeArguments(string arguments)
    {
        var tokens = new List<string>();
        if (string.IsNullOrEmpty(arguments)) return tokens;
        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (var c in arguments)
        {
            if (c == '"') { inQuotes = !inQuotes; sb.Append(c); }
            else if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (sb.Length > 0) { tokens.Add(sb.ToString()); sb.Clear(); }
            }
            else sb.Append(c);
        }
        if (sb.Length > 0) tokens.Add(sb.ToString());
        return tokens;
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
                    SafeSchtasksDelete(task.TaskPath, task.TaskName)));
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
                            SafeSchtasksQuery(task.TaskPath, task.TaskName)));
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
            SafeSchtasksQuery(task.TaskPath, task.TaskName)));
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
                SafeSchtasksDelete(task.TaskPath, task.TaskName)));
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
            SafeSchtasksDelete(task.TaskPath, task.TaskName)));
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
