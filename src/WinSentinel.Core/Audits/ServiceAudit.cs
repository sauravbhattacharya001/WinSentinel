using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows services for security risks including:
/// - Unquoted service paths (privilege escalation via path interception)
/// - Services running as SYSTEM from user-writable or suspicious directories
/// - Non-standard services running with highest privileges
/// - Disabled security-critical services (Windows Defender, Firewall, etc.)
/// - Services with suspicious executable paths (temp, downloads, user dirs)
/// - Services set to auto-start that point to missing binaries
/// - Services using cmd.exe or powershell.exe as wrappers
/// </summary>
public class ServiceAudit : IAuditModule
{
    public string Name => "Windows Service Security Audit";
    public string Category => "Services";
    public string Description =>
        "Checks Windows services for unquoted paths, excessive privileges, " +
        "suspicious binaries, disabled security services, and configuration risks.";

    // ── Constants ────────────────────────────────────────────────

    /// <summary>
    /// Services that should be running for baseline security.
    /// Key = service name (case-insensitive), Value = friendly description.
    /// </summary>
    public static readonly Dictionary<string, string> SecurityCriticalServices =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["WinDefend"] = "Windows Defender Antivirus",
            ["mpssvc"] = "Windows Defender Firewall",
            ["wscsvc"] = "Windows Security Center",
            ["WdNisSvc"] = "Windows Defender Network Inspection",
            ["EventLog"] = "Windows Event Log",
            ["SecurityHealthService"] = "Windows Security Health",
            ["SamSs"] = "Security Accounts Manager",
            ["BFE"] = "Base Filtering Engine",
            ["Sense"] = "Windows Defender Advanced Threat Protection",
            ["WuauServ"] = "Windows Update",
        };

    /// <summary>
    /// Directories considered suspicious for service executables.
    /// </summary>
    public static readonly string[] SuspiciousPaths =
    {
        @"\temp\",
        @"\tmp\",
        @"\appdata\local\temp\",
        @"\downloads\",
        @"\desktop\",
        @"\public\",
        @"\users\public\",
        @"\recycle",
    };

    /// <summary>
    /// High-privilege accounts that warrant scrutiny for non-system services.
    /// </summary>
    public static readonly HashSet<string> SystemAccounts =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "LocalSystem",
            "NT AUTHORITY\\SYSTEM",
            "SYSTEM",
            "NT AUTHORITY\\LocalService",
            "LocalService",
            "NT AUTHORITY\\NetworkService",
            "NetworkService",
        };

    /// <summary>
    /// Known-safe service path prefixes for system-account services.
    /// </summary>
    public static readonly string[] TrustedServicePaths =
    {
        @"C:\Windows\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
        @"C:\ProgramData\Microsoft\",
    };

    /// <summary>
    /// Patterns in the binary path that suggest command wrapping.
    /// </summary>
    public static readonly string[] WrapperPatterns =
    {
        "cmd.exe",
        "cmd /c",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
    };

    // ── DTO ─────────────────────────────────────────────────────

    /// <summary>
    /// Represents a single Windows service for analysis.
    /// </summary>
    public sealed class ServiceEntry
    {
        public string ServiceName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string BinaryPath { get; set; } = "";
        public string StartType { get; set; } = "Manual"; // Auto, Manual, Disabled, Boot, System
        public string Status { get; set; } = "Stopped";   // Running, Stopped, Paused
        public string Account { get; set; } = "";
        public string Description { get; set; } = "";

        /// <summary>
        /// Set during collection: true if the binary exists on disk.
        /// Null means existence was not checked.
        /// </summary>
        public bool? BinaryExists { get; set; }
    }

    /// <summary>
    /// Aggregated service state for testable analysis.
    /// </summary>
    public sealed class ServiceState
    {
        public List<ServiceEntry> Services { get; set; } = new();
        public int TotalServiceCount { get; set; }
    }

    // ── Public entry point ──────────────────────────────────────

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

    public async Task<ServiceState> CollectStateAsync(CancellationToken ct = default)
    {
        var state = new ServiceState();

        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State,StartName,Description | ConvertTo-Json -Depth 2",
                ct);

            if (!string.IsNullOrWhiteSpace(output))
            {
                state.Services = ParseServices(output);
                state.TotalServiceCount = state.Services.Count;
            }
        }
        catch
        {
            // Fallback: sc query
            try
            {
                var scOutput = await ShellHelper.RunCmdAsync("sc query type= service state= all", ct);
                if (!string.IsNullOrWhiteSpace(scOutput))
                {
                    state.TotalServiceCount = scOutput.Split("SERVICE_NAME").Length - 1;
                }
            }
            catch { }
        }

        return state;
    }

    public static List<ServiceEntry> ParseServices(string json)
    {
        var entries = new List<ServiceEntry>();

        try
        {
            // Simple JSON array parsing — extract objects
            json = json.Trim();
            if (json.StartsWith("["))
            {
                // Array of objects
                var objects = SplitJsonObjects(json);
                foreach (var obj in objects)
                {
                    var entry = ParseServiceObject(obj);
                    if (!string.IsNullOrEmpty(entry.ServiceName))
                        entries.Add(entry);
                }
            }
            else if (json.StartsWith("{"))
            {
                // Single object
                var entry = ParseServiceObject(json);
                if (!string.IsNullOrEmpty(entry.ServiceName))
                    entries.Add(entry);
            }
        }
        catch { }

        return entries;
    }

    private static ServiceEntry ParseServiceObject(string json)
    {
        var entry = new ServiceEntry();
        entry.ServiceName = ExtractJsonString(json, "Name") ?? "";
        entry.DisplayName = ExtractJsonString(json, "DisplayName") ?? "";
        entry.BinaryPath = ExtractJsonString(json, "PathName") ?? "";
        entry.StartType = ExtractJsonString(json, "StartMode") ?? "Manual";
        entry.Status = ExtractJsonString(json, "State") ?? "Stopped";
        entry.Account = ExtractJsonString(json, "StartName") ?? "";
        entry.Description = ExtractJsonString(json, "Description") ?? "";
        return entry;
    }

    private static string? ExtractJsonString(string json, string key)
    {
        var pattern = $"\"{key}\"";
        var idx = json.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        idx = json.IndexOf(':', idx + pattern.Length);
        if (idx < 0) return null;

        var rest = json.Substring(idx + 1).TrimStart();
        if (rest.StartsWith("null", StringComparison.OrdinalIgnoreCase))
            return null;

        if (rest.StartsWith("\""))
        {
            var end = rest.IndexOf('"', 1);
            return end > 0 ? rest.Substring(1, end - 1) : null;
        }

        // Non-string value (number, bool)
        var endIdx = rest.IndexOfAny(new[] { ',', '}', ']', '\r', '\n' });
        return endIdx > 0 ? rest.Substring(0, endIdx).Trim() : rest.Trim();
    }

    private static List<string> SplitJsonObjects(string json)
    {
        var objects = new List<string>();
        var depth = 0;
        var start = -1;

        for (int i = 0; i < json.Length; i++)
        {
            if (json[i] == '{')
            {
                if (depth == 0) start = i;
                depth++;
            }
            else if (json[i] == '}')
            {
                depth--;
                if (depth == 0 && start >= 0)
                {
                    objects.Add(json.Substring(start, i - start + 1));
                    start = -1;
                }
            }
        }

        return objects;
    }

    // ── Analysis (pure, testable) ───────────────────────────────

    public void AnalyzeState(ServiceState state, AuditResult result)
    {
        if (state.Services.Count == 0 && state.TotalServiceCount == 0)
        {
            result.Findings.Add(Finding.Info(
                "No service data collected",
                "Unable to enumerate Windows services. Run as administrator for full results.",
                Category,
                "Run WinSentinel with elevated privileges."));
            return;
        }

        result.Findings.Add(Finding.Info(
            "Service inventory",
            $"Enumerated {state.Services.Count} services ({state.TotalServiceCount} total).",
            Category));

        CheckUnquotedPaths(state, result);
        CheckSuspiciousServicePaths(state, result);
        CheckSystemAccountServices(state, result);
        CheckSecurityCriticalServices(state, result);
        CheckMissingBinaries(state, result);
        CheckWrapperCommands(state, result);
        CheckDisabledAutoStartServices(state, result);

        // Summary pass finding if no issues
        if (result.CriticalCount == 0 && result.WarningCount == 0)
        {
            result.Findings.Add(Finding.Pass(
                "Service configuration looks good",
                "No unquoted paths, suspicious binaries, or privilege issues detected.",
                Category));
        }
    }

    // ── Check: Unquoted service paths ───────────────────────────

    public void CheckUnquotedPaths(ServiceState state, AuditResult result)
    {
        foreach (var svc in state.Services)
        {
            if (IsUnquotedPathVulnerable(svc.BinaryPath))
            {
                result.Findings.Add(Finding.Critical(
                    $"Unquoted service path: {svc.ServiceName}",
                    $"Service '{svc.DisplayName}' has an unquoted path with spaces: \"{svc.BinaryPath}\". " +
                    "An attacker could plant a binary in an intermediate directory to escalate privileges.",
                    Category,
                    $"Quote the service path or move the binary to a path without spaces.",
                    $"sc config \"{svc.ServiceName}\" binPath= \"\\\"{svc.BinaryPath}\\\"\""));
            }
        }
    }

    /// <summary>
    /// Determines if a service binary path is vulnerable to unquoted path interception.
    /// A path is vulnerable when it: is not quoted, contains spaces, and has multiple
    /// path segments where interception is possible.
    /// </summary>
    public static bool IsUnquotedPathVulnerable(string binaryPath)
    {
        if (string.IsNullOrWhiteSpace(binaryPath))
            return false;

        var path = binaryPath.Trim();

        // Already quoted — safe
        if (path.StartsWith("\""))
            return false;

        // Extract just the executable path (before any arguments)
        var exePath = ExtractExecutablePath(path);

        // No spaces — no interception possible
        if (!exePath.Contains(' '))
            return false;

        // Must have a drive letter or UNC path with directories
        if (exePath.Length < 4)
            return false;

        // Check that there are spaces between path separators (real vulnerability)
        var segments = exePath.Split('\\');
        for (int i = 1; i < segments.Length - 1; i++)
        {
            if (segments[i].Contains(' '))
                return true;
        }

        return false;
    }

    public static string ExtractExecutablePath(string binaryPath)
    {
        var path = binaryPath.Trim();

        // Handle quoted paths
        if (path.StartsWith("\""))
        {
            var end = path.IndexOf('"', 1);
            return end > 0 ? path.Substring(1, end - 1) : path.Substring(1);
        }

        // Look for known executable extensions to find where path ends
        var extensions = new[] { ".exe", ".sys", ".dll" };
        foreach (var ext in extensions)
        {
            var idx = path.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            if (idx > 0)
                return path.Substring(0, idx + ext.Length);
        }

        // Fallback: return up to first space after a plausible path
        return path;
    }

    // ── Check: Suspicious service paths ─────────────────────────

    public void CheckSuspiciousServicePaths(ServiceState state, AuditResult result)
    {
        foreach (var svc in state.Services)
        {
            if (string.IsNullOrWhiteSpace(svc.BinaryPath))
                continue;

            var pathLower = svc.BinaryPath.ToLowerInvariant();
            foreach (var suspicious in SuspiciousPaths)
            {
                if (pathLower.Contains(suspicious.ToLowerInvariant()))
                {
                    result.Findings.Add(Finding.Critical(
                        $"Service in suspicious location: {svc.ServiceName}",
                        $"Service '{svc.DisplayName}' runs from a suspicious directory: \"{svc.BinaryPath}\". " +
                        "Malware commonly installs services in temp/download/public directories.",
                        Category,
                        "Investigate the service and its binary. Remove if unauthorized."));
                    break;
                }
            }
        }
    }

    // ── Check: SYSTEM account services from non-trusted paths ───

    public void CheckSystemAccountServices(ServiceState state, AuditResult result)
    {
        foreach (var svc in state.Services)
        {
            if (string.IsNullOrWhiteSpace(svc.Account) ||
                string.IsNullOrWhiteSpace(svc.BinaryPath))
                continue;

            if (!SystemAccounts.Contains(svc.Account))
                continue;

            var exePath = ExtractExecutablePath(svc.BinaryPath);
            var isTrusted = false;
            foreach (var trusted in TrustedServicePaths)
            {
                if (exePath.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    isTrusted = true;
                    break;
                }
            }

            if (!isTrusted)
            {
                result.Findings.Add(Finding.Warning(
                    $"SYSTEM service outside trusted path: {svc.ServiceName}",
                    $"Service '{svc.DisplayName}' runs as {svc.Account} from \"{exePath}\", " +
                    "which is outside standard system directories. This could indicate " +
                    "a third-party service or potential privilege escalation vector.",
                    Category,
                    "Verify the service is legitimate. Consider running it under a dedicated service account."));
            }
        }
    }

    // ── Check: Security-critical services ───────────────────────

    public void CheckSecurityCriticalServices(ServiceState state, AuditResult result)
    {
        foreach (var (serviceName, friendlyName) in SecurityCriticalServices)
        {
            var svc = state.Services.Find(s =>
                s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));

            if (svc == null)
            {
                // Service not found — might just not be in the snapshot
                continue;
            }

            if (svc.StartType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Critical(
                    $"Security service disabled: {friendlyName}",
                    $"The {friendlyName} ({serviceName}) service is disabled. " +
                    "This reduces system security posture significantly.",
                    Category,
                    $"Enable the service: Set-Service -Name {serviceName} -StartupType Automatic",
                    $"sc config {serviceName} start= auto && sc start {serviceName}"));
            }
            else if (svc.Status.Equals("Stopped", StringComparison.OrdinalIgnoreCase) &&
                     (svc.StartType.Equals("Auto", StringComparison.OrdinalIgnoreCase) ||
                      svc.StartType.Equals("Automatic", StringComparison.OrdinalIgnoreCase)))
            {
                result.Findings.Add(Finding.Warning(
                    $"Security service not running: {friendlyName}",
                    $"The {friendlyName} ({serviceName}) service is set to auto-start but is currently stopped.",
                    Category,
                    $"Start the service: Start-Service -Name {serviceName}",
                    $"sc start {serviceName}"));
            }
            else if (svc.Status.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Pass(
                    $"Security service running: {friendlyName}",
                    $"The {friendlyName} ({serviceName}) is running as expected.",
                    Category));
            }
        }
    }

    // ── Check: Missing binaries ─────────────────────────────────

    public void CheckMissingBinaries(ServiceState state, AuditResult result)
    {
        foreach (var svc in state.Services)
        {
            if (svc.BinaryExists == false &&
                (svc.StartType.Equals("Auto", StringComparison.OrdinalIgnoreCase) ||
                 svc.StartType.Equals("Automatic", StringComparison.OrdinalIgnoreCase)))
            {
                result.Findings.Add(Finding.Warning(
                    $"Auto-start service with missing binary: {svc.ServiceName}",
                    $"Service '{svc.DisplayName}' is set to auto-start but its binary " +
                    $"could not be found: \"{svc.BinaryPath}\". This could indicate a " +
                    "removed program or potential persistence point for an attacker to hijack.",
                    Category,
                    "Remove the orphaned service or reinstall the program.",
                    $"sc delete \"{svc.ServiceName}\""));
            }
        }
    }

    // ── Check: Command wrapper services ─────────────────────────

    public void CheckWrapperCommands(ServiceState state, AuditResult result)
    {
        foreach (var svc in state.Services)
        {
            if (string.IsNullOrWhiteSpace(svc.BinaryPath))
                continue;

            var pathLower = svc.BinaryPath.ToLowerInvariant();
            foreach (var pattern in WrapperPatterns)
            {
                if (pathLower.Contains(pattern.ToLowerInvariant()))
                {
                    result.Findings.Add(Finding.Warning(
                        $"Service uses command wrapper: {svc.ServiceName}",
                        $"Service '{svc.DisplayName}' uses {pattern} as its executable: " +
                        $"\"{svc.BinaryPath}\". Services wrapping script interpreters can " +
                        "be exploited if the script path is writable.",
                        Category,
                        "Replace with a compiled service binary or ensure the script is in a protected directory."));
                    break;
                }
            }
        }
    }

    // ── Check: Disabled auto-start services ─────────────────────

    public void CheckDisabledAutoStartServices(ServiceState state, AuditResult result)
    {
        var disabledCount = state.Services.Count(s =>
            s.StartType.Equals("Disabled", StringComparison.OrdinalIgnoreCase) &&
            !SecurityCriticalServices.ContainsKey(s.ServiceName));

        if (disabledCount > 20)
        {
            result.Findings.Add(Finding.Info(
                $"Many disabled services ({disabledCount})",
                $"Found {disabledCount} non-security disabled services. " +
                "While disabling unused services is good practice, verify no " +
                "legitimate services were inadvertently disabled.",
                Category));
        }
    }
}
