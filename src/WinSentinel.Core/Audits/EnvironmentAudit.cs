using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits environment variable security for risks including:
/// - PATH hijacking via writable or suspicious directories (MITRE T1574.007)
/// - Secrets leaked in environment variables (API keys, tokens, passwords)
/// - Proxy settings that could redirect traffic to untrusted servers
/// - Dangerous PATHEXT entries enabling script execution
/// - TEMP/TMP directories with overly permissive ACLs
/// - Relative or UNC paths in PATH enabling DLL search order hijacking
/// </summary>
public class EnvironmentAudit : IAuditModule
{
    public string Name => "Environment Variable Security Audit";
    public string Category => "Environment";
    public string Description =>
        "Checks PATH hijacking risks, secrets in environment variables, " +
        "proxy configuration, and dangerous PATHEXT/TEMP settings.";

    /// <summary>
    /// Known-safe PATH directories (case-insensitive).
    /// Entries not on this list in system PATH are flagged for review.
    /// </summary>
    public static readonly HashSet<string> TrustedPathPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\Windows",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
    };

    /// <summary>
    /// Default safe PATHEXT extensions.
    /// </summary>
    public static readonly HashSet<string> DefaultPathExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".COM", ".EXE", ".BAT", ".CMD",
    };

    /// <summary>
    /// Risky PATHEXT extensions that enable script execution.
    /// </summary>
    public static readonly HashSet<string> RiskyPathExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".VBS", ".VBE", ".JS", ".JSE", ".WSF", ".WSH", ".MSC",
        ".PS1", ".PSC1", ".PY", ".PYW", ".SCR", ".HTA",
    };

    /// <summary>
    /// Patterns that indicate a secret value in an environment variable.
    /// Matched against variable names (case-insensitive).
    /// </summary>
    public static readonly string[] SecretNamePatterns =
    {
        "API_KEY", "APIKEY", "API_SECRET", "SECRET_KEY", "SECRET",
        "ACCESS_TOKEN", "AUTH_TOKEN", "TOKEN",
        "PASSWORD", "PASSWD", "PASS",
        "PRIVATE_KEY", "ENCRYPTION_KEY",
        "AWS_SECRET", "AWS_ACCESS_KEY", "AZURE_CLIENT_SECRET",
        "GH_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN",
        "DATABASE_URL", "CONNECTION_STRING", "CONNECTIONSTRING",
        "SMTP_PASSWORD", "MAIL_PASSWORD",
    };

    /// <summary>
    /// Variable names that are safe even if they match patterns above
    /// (e.g., "PATHEXT" contains "EXT" but is not a secret).
    /// </summary>
    public static readonly HashSet<string> SecretNameExclusions = new(StringComparer.OrdinalIgnoreCase)
    {
        "PATHEXT", "COMSPEC", "PROCESSOR_IDENTIFIER", "SESSIONNAME",
        "USERDOMAIN", "COMPUTERNAME", "LOGONSERVER", "APPDATA",
        "LOCALAPPDATA", "PROGRAMDATA", "SYSTEMDRIVE", "SYSTEMROOT",
        "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "TEMP", "TMP",
        "WINDIR", "PUBLIC", "PSModulePath", "NUMBER_OF_PROCESSORS",
        "OS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION", "USERNAME",
    };

    /// <summary>
    /// Proxy-related environment variable names.
    /// </summary>
    public static readonly HashSet<string> ProxyVariables = new(StringComparer.OrdinalIgnoreCase)
    {
        "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY",
        "NO_PROXY", "http_proxy", "https_proxy",
    };

    /// <summary>
    /// Data transfer object for environment state.
    /// All checks operate on this record for testability.
    /// </summary>
    public sealed class EnvironmentState
    {
        /// <summary>System PATH entries (Machine scope).</summary>
        public List<string> SystemPathEntries { get; set; } = new();

        /// <summary>User PATH entries (User scope).</summary>
        public List<string> UserPathEntries { get; set; } = new();

        /// <summary>PATHEXT value split into extensions.</summary>
        public List<string> PathExtEntries { get; set; } = new();

        /// <summary>TEMP directory path.</summary>
        public string TempPath { get; set; } = string.Empty;

        /// <summary>TMP directory path.</summary>
        public string TmpPath { get; set; } = string.Empty;

        /// <summary>All environment variables (name → value) from Machine scope.</summary>
        public Dictionary<string, string> SystemVariables { get; set; } = new();

        /// <summary>All environment variables (name → value) from User scope.</summary>
        public Dictionary<string, string> UserVariables { get; set; } = new();

        /// <summary>
        /// For each PATH directory: whether it exists and whether the
        /// current user can write to it. Key = normalized path.
        /// </summary>
        public Dictionary<string, PathDirectoryInfo> PathDirectoryDetails { get; set; } = new();

        /// <summary>Windows directory (WINDIR / SystemRoot).</summary>
        public string WindowsDirectory { get; set; } = @"C:\Windows";
    }

    /// <summary>
    /// Information about a directory in PATH.
    /// </summary>
    public sealed class PathDirectoryInfo
    {
        public string Path { get; set; } = string.Empty;
        public bool Exists { get; set; }
        public bool IsWritable { get; set; }
        public bool IsRelative { get; set; }
        public bool IsUnc { get; set; }
        public string Scope { get; set; } = "System"; // "System" or "User"
    }

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
            var state = await GatherStateAsync(cancellationToken);
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

    /// <summary>
    /// Gather live environment state from the system.
    /// </summary>
    internal async Task<EnvironmentState> GatherStateAsync(CancellationToken ct)
    {
        var state = new EnvironmentState();

        // System PATH
        var systemPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
        state.SystemPathEntries = systemPath
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim())
            .Where(p => !string.IsNullOrEmpty(p))
            .ToList();

        // User PATH
        var userPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
        state.UserPathEntries = userPath
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim())
            .Where(p => !string.IsNullOrEmpty(p))
            .ToList();

        // PATHEXT
        var pathExt = Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD";
        state.PathExtEntries = pathExt
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(e => e.Trim().ToUpperInvariant())
            .Where(e => !string.IsNullOrEmpty(e))
            .ToList();

        // TEMP / TMP
        state.TempPath = Environment.GetEnvironmentVariable("TEMP") ?? "";
        state.TmpPath = Environment.GetEnvironmentVariable("TMP") ?? "";

        // System variables
        var sysVars = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Machine);
        foreach (System.Collections.DictionaryEntry entry in sysVars)
        {
            if (entry.Key is string key && entry.Value is string value)
                state.SystemVariables[key] = value;
        }

        // User variables
        var userVars = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.User);
        foreach (System.Collections.DictionaryEntry entry in userVars)
        {
            if (entry.Key is string key && entry.Value is string value)
                state.UserVariables[key] = value;
        }

        state.WindowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(state.WindowsDirectory))
            state.WindowsDirectory = @"C:\Windows";

        // Check each PATH directory
        var allPaths = state.SystemPathEntries
            .Select(p => (Path: p, Scope: "System"))
            .Concat(state.UserPathEntries.Select(p => (Path: p, Scope: "User")));

        foreach (var (path, scope) in allPaths)
        {
            if (state.PathDirectoryDetails.ContainsKey(path))
                continue;

            var info = new PathDirectoryInfo
            {
                Path = path,
                Scope = scope,
                IsRelative = !System.IO.Path.IsPathRooted(path),
                IsUnc = path.StartsWith(@"\\"),
            };

            if (!info.IsRelative)
            {
                info.Exists = Directory.Exists(path);
                if (info.Exists)
                {
                    info.IsWritable = await CheckDirectoryWritableAsync(path, ct);
                }
            }

            state.PathDirectoryDetails[path] = info;
        }

        return state;
    }

    /// <summary>
    /// Analyze environment state and produce findings.
    /// Pure logic — no I/O. Call directly in tests with crafted state.
    /// </summary>
    public void AnalyzeState(EnvironmentState state, AuditResult result)
    {
        AnalyzePathHijacking(state, result);
        AnalyzePathExtSecurity(state, result);
        AnalyzeSecretLeakage(state, result);
        AnalyzeProxySettings(state, result);
        AnalyzeTempDirectories(state, result);
    }

    // ──────────────────── PATH Hijacking ────────────────────

    private void AnalyzePathHijacking(EnvironmentState state, AuditResult result)
    {
        var systemDir = System.IO.Path.Combine(state.WindowsDirectory, "System32");
        bool system32Found = false;
        int positionBeforeSystem32 = 0;
        var writableBefore = new List<string>();

        // Check system PATH entries in order
        foreach (var entry in state.SystemPathEntries)
        {
            if (state.PathDirectoryDetails.TryGetValue(entry, out var info))
            {
                // Relative paths in system PATH = critical (trivial hijacking)
                if (info.IsRelative)
                {
                    result.Findings.Add(Finding.Critical(
                        "Relative path in system PATH",
                        $"System PATH contains relative path '{entry}'. " +
                        "An attacker can place a malicious executable in the current working " +
                        "directory to hijack program execution (MITRE T1574.007).",
                        Category,
                        "Remove relative paths from the system PATH variable."));
                    continue;
                }

                // UNC paths in system PATH = warning (network-based hijacking)
                if (info.IsUnc)
                {
                    result.Findings.Add(Finding.Warning(
                        "UNC path in system PATH",
                        $"System PATH contains UNC path '{entry}'. " +
                        "Network-based PATH entries can be hijacked via LLMNR/NBNS " +
                        "poisoning or rogue SMB servers.",
                        Category,
                        "Replace UNC paths with local paths where possible."));
                    continue;
                }

                // Non-existent directory in PATH
                if (!info.Exists)
                {
                    result.Findings.Add(Finding.Warning(
                        "Non-existent directory in system PATH",
                        $"System PATH entry '{entry}' does not exist. " +
                        "An attacker who creates this directory can place malicious executables there.",
                        Category,
                        $"Remove the non-existent path '{entry}' from the system PATH."));
                    continue;
                }

                // Track position relative to System32
                if (entry.Equals(systemDir, StringComparison.OrdinalIgnoreCase) ||
                    entry.Equals(state.WindowsDirectory, StringComparison.OrdinalIgnoreCase))
                {
                    system32Found = true;
                }

                // Writable directory before System32 = critical
                if (!system32Found && info.IsWritable)
                {
                    bool isTrusted = false;
                    foreach (var prefix in TrustedPathPrefixes)
                    {
                        if (entry.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            isTrusted = true;
                            break;
                        }
                    }

                    if (!isTrusted)
                    {
                        positionBeforeSystem32++;
                        writableBefore.Add(entry);
                    }
                }

                // Writable directory in system PATH (any position)
                if (info.IsWritable)
                {
                    bool isTrusted = false;
                    foreach (var prefix in TrustedPathPrefixes)
                    {
                        if (entry.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            isTrusted = true;
                            break;
                        }
                    }

                    if (!isTrusted)
                    {
                        result.Findings.Add(Finding.Warning(
                            "Writable directory in system PATH",
                            $"System PATH contains writable directory '{entry}'. " +
                            "A local user could place malicious executables here to hijack " +
                            "programs that search PATH (MITRE T1574.007).",
                            Category,
                            $"Restrict write permissions on '{entry}' or remove it from system PATH."));
                    }
                }
            }
        }

        // Summary finding for writable dirs before System32
        if (writableBefore.Count > 0)
        {
            result.Findings.Add(Finding.Critical(
                "Writable directories before System32 in PATH",
                $"{writableBefore.Count} user-writable directory(ies) appear before " +
                $"System32 in the system PATH: {string.Join(", ", writableBefore)}. " +
                "Executables in these directories take precedence over system binaries, " +
                "enabling PATH hijacking attacks (MITRE T1574.007).",
                Category,
                "Move System32 to the beginning of PATH or remove writable directories."));
        }

        // Check user PATH entries for issues
        foreach (var entry in state.UserPathEntries)
        {
            if (state.PathDirectoryDetails.TryGetValue(entry, out var info))
            {
                if (info.IsRelative)
                {
                    result.Findings.Add(Finding.Warning(
                        "Relative path in user PATH",
                        $"User PATH contains relative path '{entry}'. " +
                        "Programs run by this user could be hijacked via the current " +
                        "working directory.",
                        Category,
                        "Replace relative paths with absolute paths in user PATH."));
                }

                if (info.IsUnc)
                {
                    result.Findings.Add(Finding.Info(
                        "UNC path in user PATH",
                        $"User PATH contains UNC path '{entry}'. " +
                        "Ensure the network share is trusted and access-controlled.",
                        Category));
                }
            }
        }

        // Pass finding if PATH looks clean
        if (writableBefore.Count == 0 &&
            !state.SystemPathEntries.Any(e =>
                state.PathDirectoryDetails.TryGetValue(e, out var i) && i.IsRelative))
        {
            result.Findings.Add(Finding.Pass(
                "System PATH order is secure",
                "No writable or relative directories appear before system directories in PATH.",
                Category));
        }
    }

    // ──────────────────── PATHEXT ────────────────────

    private void AnalyzePathExtSecurity(EnvironmentState state, AuditResult result)
    {
        var risky = new List<string>();

        foreach (var ext in state.PathExtEntries)
        {
            if (RiskyPathExt.Contains(ext))
            {
                risky.Add(ext);
            }
        }

        if (risky.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "Risky extensions in PATHEXT",
                $"PATHEXT includes script extensions that enable execution of " +
                $"potentially dangerous file types: {string.Join(", ", risky)}. " +
                "An attacker could name a malicious script with one of these extensions " +
                "and place it in a PATH directory to hijack execution.",
                Category,
                "Remove unnecessary script extensions from PATHEXT. " +
                "Keep only .COM, .EXE, .BAT, .CMD unless specifically needed."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "PATHEXT contains only standard extensions",
                $"PATHEXT is limited to: {string.Join(", ", state.PathExtEntries)}.",
                Category));
        }

        // Check for unusual extensions not in either known list
        var unknown = state.PathExtEntries
            .Where(e => !DefaultPathExt.Contains(e) && !RiskyPathExt.Contains(e))
            .ToList();

        if (unknown.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Unknown extensions in PATHEXT",
                $"PATHEXT contains non-standard extensions: {string.Join(", ", unknown)}. " +
                "Review whether these are intentional.",
                Category));
        }
    }

    // ──────────────────── Secret Leakage ────────────────────

    private void AnalyzeSecretLeakage(EnvironmentState state, AuditResult result)
    {
        int secretCount = 0;

        void CheckVariables(Dictionary<string, string> vars, string scope)
        {
            foreach (var (name, value) in vars)
            {
                if (SecretNameExclusions.Contains(name))
                    continue;

                bool isSecret = false;
                string matchedPattern = "";

                foreach (var pattern in SecretNamePatterns)
                {
                    if (name.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        isSecret = true;
                        matchedPattern = pattern;
                        break;
                    }
                }

                if (isSecret && !string.IsNullOrEmpty(value))
                {
                    secretCount++;
                    // Mask the value for the finding
                    var masked = value.Length <= 4
                        ? "****"
                        : value[..2] + new string('*', Math.Min(value.Length - 4, 20)) + value[^2..];

                    result.Findings.Add(Finding.Warning(
                        $"Possible secret in {scope} environment variable",
                        $"{scope} variable '{name}' (matched pattern '{matchedPattern}') " +
                        $"contains a value that may be a secret: {masked}. " +
                        "Environment variables are visible to all processes running " +
                        "under the same user and can be enumerated by local attackers.",
                        Category,
                        $"Move the secret from environment variable '{name}' to a " +
                        "secure credential store (Windows Credential Manager, Azure Key Vault, " +
                        "or an encrypted secrets file)."));
                }
            }
        }

        CheckVariables(state.SystemVariables, "System");
        CheckVariables(state.UserVariables, "User");

        if (secretCount == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No secrets detected in environment variables",
                "No environment variable names match known secret patterns.",
                Category));
        }
    }

    // ──────────────────── Proxy Settings ────────────────────

    private void AnalyzeProxySettings(EnvironmentState state, AuditResult result)
    {
        var allVars = state.SystemVariables
            .Concat(state.UserVariables)
            .GroupBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);

        bool hasProxy = false;

        foreach (var proxyVar in ProxyVariables)
        {
            if (allVars.TryGetValue(proxyVar, out var proxyValue) &&
                !string.IsNullOrWhiteSpace(proxyValue))
            {
                hasProxy = true;

                // Check if proxy uses HTTP (not HTTPS)
                if (proxyValue.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(Finding.Warning(
                        $"Insecure proxy protocol in {proxyVar}",
                        $"Environment variable '{proxyVar}' is set to '{proxyValue}' " +
                        "which uses unencrypted HTTP. Traffic between this machine and " +
                        "the proxy server could be intercepted.",
                        Category,
                        $"Use HTTPS for the proxy URL in '{proxyVar}' if the proxy supports it."));
                }

                // Check for credentials in proxy URL
                if (proxyValue.Contains('@') &&
                    (proxyValue.Contains("://") &&
                     proxyValue.IndexOf('@') > proxyValue.IndexOf("://")))
                {
                    result.Findings.Add(Finding.Critical(
                        $"Credentials embedded in proxy URL ({proxyVar})",
                        $"Environment variable '{proxyVar}' contains a proxy URL with " +
                        "embedded credentials (user:pass@host pattern). These credentials " +
                        "are visible to all processes and appear in process listings.",
                        Category,
                        "Configure proxy authentication via a separate credential mechanism " +
                        "rather than embedding credentials in the URL."));
                }

                // Check for localhost proxy (might be legitimate, just informational)
                if (proxyValue.Contains("127.0.0.1") ||
                    proxyValue.Contains("localhost", StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(Finding.Info(
                        $"Localhost proxy configured ({proxyVar})",
                        $"'{proxyVar}' points to localhost ({proxyValue}). " +
                        "This is typical for local proxy tools (Fiddler, mitmproxy, Burp Suite) " +
                        "but should not be left active in production.",
                        Category));
                }
            }
        }

        if (!hasProxy)
        {
            result.Findings.Add(Finding.Pass(
                "No proxy environment variables configured",
                "No HTTP_PROXY, HTTPS_PROXY, or ALL_PROXY variables are set.",
                Category));
        }
    }

    // ──────────────────── TEMP/TMP Directories ────────────────────

    private void AnalyzeTempDirectories(EnvironmentState state, AuditResult result)
    {
        void CheckTempDir(string varName, string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                result.Findings.Add(Finding.Info(
                    $"{varName} is not set",
                    $"The {varName} environment variable is empty or not set.",
                    Category));
                return;
            }

            // Check if TEMP is a shared location
            var normalizedPath = path.TrimEnd('\\').ToLowerInvariant();
            if (normalizedPath == @"c:\temp" || normalizedPath == @"c:\tmp" ||
                normalizedPath == @"c:\windows\temp")
            {
                result.Findings.Add(Finding.Warning(
                    $"{varName} points to a shared directory",
                    $"{varName} is set to '{path}', a shared location accessible by " +
                    "multiple users. Temp file race conditions (symlink attacks) may " +
                    "allow privilege escalation.",
                    Category,
                    $"Set {varName} to a per-user directory such as " +
                    @"'%USERPROFILE%\AppData\Local\Temp'."));
            }

            // Check if TEMP/TMP differ (inconsistency)
            if (varName == "TMP" && !string.IsNullOrEmpty(state.TempPath))
            {
                if (!state.TempPath.Equals(path, StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(Finding.Info(
                        "TEMP and TMP point to different directories",
                        $"TEMP='{state.TempPath}', TMP='{path}'. Some applications " +
                        "use TEMP and others use TMP, which may cause confusion.",
                        Category));
                }
            }
        }

        CheckTempDir("TEMP", state.TempPath);
        CheckTempDir("TMP", state.TmpPath);

        // If TEMP is per-user, that's good
        if (!string.IsNullOrEmpty(state.TempPath))
        {
            var lower = state.TempPath.ToLowerInvariant();
            if (lower.Contains(@"\appdata\local\temp"))
            {
                result.Findings.Add(Finding.Pass(
                    "TEMP uses per-user directory",
                    $"TEMP is set to '{state.TempPath}', a per-user temporary directory.",
                    Category));
            }
        }
    }

    // ──────────────────── Helpers ────────────────────

    /// <summary>
    /// Check if the current user can write to a directory by attempting
    /// to create and delete a temporary file.
    /// </summary>
    private static async Task<bool> CheckDirectoryWritableAsync(string path, CancellationToken ct)
    {
        try
        {
            var testFile = System.IO.Path.Combine(path, $".winsentinel_write_test_{Guid.NewGuid():N}");
            await File.WriteAllTextAsync(testFile, "", ct);
            File.Delete(testFile);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
