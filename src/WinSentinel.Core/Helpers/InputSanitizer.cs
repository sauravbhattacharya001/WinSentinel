using System.Text.RegularExpressions;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Input sanitization helpers to prevent command injection
/// in shell commands executed by ShellHelper, FixEngine, and AutoRemediator.
/// </summary>
public static partial class InputSanitizer
{
    /// <summary>
    /// Critical system paths that must never be quarantined, deleted, or modified
    /// by automated actions. Checked by <see cref="ValidateFilePath"/>.
    /// </summary>
    private static readonly string[] ProtectedDirectories =
    {
        @"C:\Windows",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
        @"C:\ProgramData\Microsoft",
        @"C:\Users\Default",
    };

    /// <summary>
    /// Critical system files that must never be quarantined regardless of location.
    /// </summary>
    private static readonly string[] ProtectedFileNames =
    {
        "ntoskrnl.exe", "kernel32.dll", "ntdll.dll", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "explorer.exe", "dwm.exe", "taskhost.exe", "taskhostw.exe",
        "bootmgr", "bcd", "hal.dll", "ci.dll",
    };

    /// <summary>
    /// Validates and sanitizes an IP address (IPv4 or IPv6) to prevent command injection.
    /// Returns null if the input is not a valid IP address.
    /// </summary>
    public static string? SanitizeIpAddress(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        var trimmed = input.Trim();

        // Only allow valid IP address characters: digits, dots, colons, hex letters
        if (!IpAddressPattern().IsMatch(trimmed))
            return null;

        // Validate with .NET's built-in parser
        if (!System.Net.IPAddress.TryParse(trimmed, out var parsed))
            return null;

        // Return the canonical representation (prevents embedded injection)
        return parsed.ToString();
    }

    /// <summary>
    /// Validates and sanitizes a Windows username to prevent command injection.
    /// Returns null if the input contains dangerous characters.
    /// Allows: letters, digits, spaces, hyphens, underscores, dots, domain backslash.
    /// </summary>
    public static string? SanitizeUsername(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        var trimmed = input.Trim();

        // Max length guard
        if (trimmed.Length > 256)
            return null;

        // Only allow safe username characters
        if (!UsernamePattern().IsMatch(trimmed))
            return null;

        return trimmed;
    }

    /// <summary>
    /// Validates a Windows drive letter (e.g., "C:", "D:").
    /// Returns null if the input is not a valid drive letter.
    /// </summary>
    public static string? SanitizeDriveLetter(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        var trimmed = input.Trim();

        if (!DriveLetterPattern().IsMatch(trimmed))
            return null;

        return trimmed.ToUpperInvariant();
    }

    /// <summary>
    /// Validates a firewall rule name to prevent injection in netsh commands.
    /// Returns null if the input contains dangerous characters.
    /// </summary>
    public static string? SanitizeFirewallRuleName(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        var trimmed = input.Trim();

        if (trimmed.Length > 256)
            return null;

        // Only allow safe characters for firewall rule names
        if (!FirewallRuleNamePattern().IsMatch(trimmed))
            return null;

        return trimmed;
    }

    /// <summary>
    /// Validates a file path for use in quarantine/remediation operations.
    /// Rejects path traversal sequences, UNC paths, alternate data streams,
    /// null bytes, and paths targeting protected system directories/files.
    /// Returns the canonicalized full path on success, null on failure.
    /// </summary>
    public static string? ValidateFilePath(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        var trimmed = input.Trim();

        // Max path length guard (Windows MAX_PATH)
        if (trimmed.Length > 260)
            return null;

        // Reject null bytes (can truncate paths in native APIs)
        if (trimmed.Contains('\0'))
            return null;

        // Reject alternate data streams (file.txt:hidden)
        // Drive letter colon (C:) is at index 1; any colon after that is suspicious
        if (trimmed.Length > 2 && trimmed.IndexOf(':', 2) >= 0)
            return null;

        // Reject UNC paths (\\server\share) - quarantine should be local only
        if (trimmed.StartsWith(@"\\") || trimmed.StartsWith("//"))
            return null;

        // Reject NT object manager paths (\??\, \Device\, \DosDevices\) which
        // bypass normal path resolution and could target arbitrary volumes
        if (trimmed.StartsWith(@"\??") || trimmed.StartsWith(@"\Device", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith(@"\DosDevices", StringComparison.OrdinalIgnoreCase))
            return null;

        // Reject forward-slash UNC variants (//?/, //./device)
        if (trimmed.StartsWith("//?") || trimmed.StartsWith("//./"))
            return null;

        // Reject path traversal sequences before canonicalization
        if (trimmed.Contains(".."))
            return null;

        // Reject command injection characters in the raw path
        if (PathInjectionPattern().IsMatch(trimmed))
            return null;

        // Canonicalize to prevent path tricks
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(trimmed);
        }
        catch
        {
            return null;
        }

        // Re-check for traversal after canonicalization
        if (fullPath.Contains(".."))
            return null;

        // Resolve symlinks/junctions to the real target path to prevent
        // bypass via junction pointing into a protected directory
        string resolvedPath;
        try
        {
            // ResolveLinkTarget returns null for non-links; fall back to fullPath
            var linkTarget = File.ResolveLinkTarget(fullPath, returnFinalTarget: true);
            resolvedPath = linkTarget?.FullName ?? fullPath;
        }
        catch
        {
            resolvedPath = fullPath;
        }

        // Check BOTH the stated path and the resolved target against protected dirs
        foreach (var protectedDir in ProtectedDirectories)
        {
            if (fullPath.StartsWith(protectedDir, StringComparison.OrdinalIgnoreCase) ||
                resolvedPath.StartsWith(protectedDir, StringComparison.OrdinalIgnoreCase))
                return null;
        }

        // Check against protected system file names (check both paths)
        var fileName = Path.GetFileName(fullPath);
        var resolvedFileName = Path.GetFileName(resolvedPath);
        foreach (var protectedFile in ProtectedFileNames)
        {
            if (fileName.Equals(protectedFile, StringComparison.OrdinalIgnoreCase) ||
                resolvedFileName.Equals(protectedFile, StringComparison.OrdinalIgnoreCase))
                return null;
        }

        return fullPath;
    }

    /// <summary>
    /// Validates and sanitizes a process name or PID string for kill operations.
    /// Returns the sanitized input on success, null if it contains dangerous characters.
    /// Accepts: process names (letters, digits, dots, hyphens, underscores) or numeric PIDs.
    /// </summary>
    public static string? SanitizeProcessInput(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;

        var trimmed = input.Trim();

        // Max length guard
        if (trimmed.Length > 256)
            return null;

        // If it looks like a PID (all digits), validate range
        if (uint.TryParse(trimmed, out var pid))
        {
            // PID 0 (System Idle) and PID 4 (System) must never be killed
            if (pid <= 4)
                return null;
            return trimmed;
        }

        // Process name: only allow safe characters (letters, digits, dots, hyphens, underscores)
        if (!ProcessNamePattern().IsMatch(trimmed))
            return null;

        return trimmed;
    }

    /// <summary>
    /// Sanitizes a string for safe inclusion in log messages.
    /// Strips control characters and CRLF sequences that could cause log injection.
    /// </summary>
    public static string SanitizeForLog(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        // Replace CRLF and control characters with safe representations
        return LogInjectionPattern().Replace(input, m =>
            m.Value switch
            {
                "\r\n" => "[CRLF]",
                "\r" => "[CR]",
                "\n" => "[LF]",
                _ => $"[0x{(int)m.Value[0]:X2}]"
            });
    }

    /// <summary>
    /// Checks if a fix command contains obviously dangerous patterns
    /// that should never be auto-executed (e.g., format, del /s, rm -rf).
    /// Returns a reason string if dangerous, null if OK.
    /// </summary>
    public static string? CheckDangerousCommand(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return "Empty command";

        var lower = command.ToLowerInvariant();

        // Destructive commands
        if (lower.Contains("format ") && lower.Contains("/y"))
            return "Contains destructive format command";
        if (lower.Contains("del /s /q") || lower.Contains("remove-item -recurse -force /"))
            return "Contains recursive delete command";

        // Network exfiltration
        if (lower.Contains("invoke-webrequest") || lower.Contains("curl ") ||
            lower.Contains("wget ") || lower.Contains("iwr "))
            return "Contains network request command";

        // .NET download methods (bypass Invoke-WebRequest blocks)
        if (lower.Contains("system.net.webclient") || lower.Contains("net.webclient") ||
            lower.Contains("downloadstring") || lower.Contains("downloadfile") ||
            lower.Contains("downloaddata") || lower.Contains("system.net.http.httpclient"))
            return "Contains .NET network download method";

        // Arbitrary code execution
        if (lower.Contains("invoke-expression") || lower.Contains("iex ") || lower.Contains("iex("))
            return "Contains Invoke-Expression (arbitrary code execution)";
        if (lower.Contains("add-type") && (lower.Contains("-typedefinition") || lower.Contains("-memberdef")))
            return "Contains Add-Type with inline code (arbitrary C# execution)";
        if (lower.Contains("start-process") && (lower.Contains("-verb runas") || lower.Contains("powershell") || lower.Contains("cmd")))
            return "Contains Start-Process launching shell (potential escalation)";

        // Credential access
        if (lower.Contains("mimikatz") || lower.Contains("get-credential") ||
            lower.Contains("cmdkey") || lower.Contains("sekurlsa"))
            return "Contains credential access command";

        // Reverse shells
        if (lower.Contains("ncat") || lower.Contains("nc.exe") ||
            lower.Contains("reverse") || lower.Contains("-e cmd") ||
            lower.Contains("-e powershell"))
            return "Contains potential reverse shell command";

        // Encoded commands (bypass detection)
        if (lower.Contains("-encodedcommand") || lower.Contains("-enc ") ||
            lower.Contains("-e ") && lower.Contains("powershell"))
            return "Contains encoded command (potential bypass)";

        // Subexpression injection (PowerShell $(...) executes inside double-quoted strings)
        if (command.Contains("$("))
            return "Contains PowerShell subexpression (potential injection)";

        // Backtick escape sequences (PowerShell uses ` as escape character;
        // `$(...) or `n / `0 can bypass blocklists or inject control chars)
        if (command.Contains('`'))
            return "Contains PowerShell backtick escape (potential bypass)";

        // LOLBins (Living Off The Land Binaries) — legitimate Windows tools
        // commonly abused for download, execution, or lateral movement
        if (lower.Contains("certutil") && (lower.Contains("-urlcache") || lower.Contains("-decode") || lower.Contains("-encode")))
            return "Contains certutil download/decode (LOLBin abuse)";
        if (lower.Contains("bitsadmin") && (lower.Contains("/transfer") || lower.Contains("/addfile")))
            return "Contains bitsadmin file transfer (LOLBin abuse)";
        if (lower.Contains("mshta") || lower.Contains("mshta.exe"))
            return "Contains mshta execution (LOLBin — runs HTA/script from URL)";
        if (lower.Contains("regsvr32") && (lower.Contains("/s") || lower.Contains("/i:http")))
            return "Contains regsvr32 script execution (Squiblydoo LOLBin)";
        if (lower.Contains("rundll32") && (lower.Contains("javascript:") || lower.Contains("http")))
            return "Contains rundll32 script/URL execution (LOLBin abuse)";
        if (lower.Contains("wmic") && (lower.Contains("process call create") || lower.Contains("/format:") && lower.Contains("http")))
            return "Contains WMIC remote execution (LOLBin abuse)";
        if (lower.Contains("cscript") || lower.Contains("wscript"))
            return "Contains Windows Script Host execution (potential malicious script)";

        // AMSI bypass attempts
        if (lower.Contains("amsiutils") || lower.Contains("amsiinitfailed") ||
            lower.Contains("amsi.dll") || lower.Contains("amsiscanbuffer"))
            return "Contains AMSI bypass attempt";

        // PowerShell execution policy bypass (beyond -ExecutionPolicy Bypass which we control)
        if (lower.Contains("set-executionpolicy") && (lower.Contains("unrestricted") || lower.Contains("bypass")))
            return "Contains Set-ExecutionPolicy override";

        // Reflection-based .NET method invocation (bypasses Add-Type blocks)
        if (lower.Contains("[system.reflection") || lower.Contains("getmethod") ||
            lower.Contains("invoke(") || lower.Contains("assembly::load"))
            return "Contains .NET reflection invocation (potential bypass)";

        // Registry Run key persistence
        if (lower.Contains("hklm\\software\\microsoft\\windows\\currentversion\\run") ||
            lower.Contains("hkcu\\software\\microsoft\\windows\\currentversion\\run"))
            return "Contains registry Run key modification (persistence mechanism)";

        // Scheduled task creation (persistence)
        if (lower.Contains("schtasks") && lower.Contains("/create"))
            return "Contains scheduled task creation (persistence mechanism)";

        // Service creation (persistence / privilege escalation)
        if (lower.Contains("sc.exe") && lower.Contains("create") ||
            lower.Contains("new-service"))
            return "Contains service creation (persistence/escalation)";

        // Pipe-based command chaining (can bypass individual command checks)
        if (command.Contains('|') && (lower.Contains("powershell") || lower.Contains("cmd")))
            return "Contains piped shell execution (potential bypass)";

        // ── Additional bypass vectors ──

        // PowerShell call operator — `& { code }` or `& "path"` executes arbitrary commands
        // without triggering other blocklists.  Also catches `Invoke-Command` and `.Invoke()`.
        if (lower.Contains("invoke-command") || lower.Contains("enter-pssession") ||
            lower.Contains("invoke-item") || lower.Contains("ii "))
            return "Contains PowerShell remote/invoke execution";

        // Start-Job / background jobs — runs code in a separate process, escaping monitoring
        if (lower.Contains("start-job") || lower.Contains("start-threadjob"))
            return "Contains background job execution (evades process-tree monitoring)";

        // COM object instantiation — `New-Object -ComObject WScript.Shell` then `.Run()`
        // bypasses all command-name blocklists since execution goes through COM
        if (lower.Contains("-comobject") || lower.Contains("wscript.shell") ||
            lower.Contains("shell.application") || lower.Contains("mmc20.application"))
            return "Contains COM object instantiation (potential code execution bypass)";

        // Environment variable expansion — `$env:COMSPEC /c malicious` resolves to
        // cmd.exe, bypassing command-name checks
        if (lower.Contains("$env:") && (lower.Contains("comspec") || lower.Contains("systemroot") ||
            lower.Contains("windir") || lower.Contains("temp") || lower.Contains("appdata")))
            return "Contains environment variable reference (potential path resolution bypass)";

        // PowerShell -File parameter — executes an arbitrary .ps1 script
        if (lower.Contains("-file ") && lower.Contains(".ps1"))
            return "Contains PowerShell script file execution";

        // Null bytes — can truncate strings in native APIs, bypassing validation
        if (command.Contains('\0'))
            return "Contains null byte (potential truncation attack)";

        // PowerShell call operator with block — `& { ... }` executes script blocks
        if (CallOperatorPattern().IsMatch(command))
            return "Contains PowerShell call operator (arbitrary execution)";

        // Base64 smuggling — manual Base64 decode + execute patterns (our own
        // -EncodedCommand usage is safe because we control it; blocked here
        // are user-supplied commands that decode + pipe to IEX/Invoke-Expression)
        if (lower.Contains("frombase64string") || lower.Contains("[convert]::") ||
            (lower.Contains("base64") && lower.Contains("invoke")))
            return "Contains Base64 decode + execute pattern (obfuscation bypass)";

        // WMI/CIM arbitrary method invocation
        if (lower.Contains("invoke-wmimethod") || lower.Contains("invoke-cimmethod") ||
            lower.Contains("get-wmiobject") && lower.Contains("call"))
            return "Contains WMI/CIM method invocation (potential remote execution)";

        // DLL loading — can execute arbitrary native code
        if (lower.Contains("loadlibrary") || lower.Contains("[dllimport") ||
            lower.Contains("add-type") && lower.Contains("dllname"))
            return "Contains DLL loading (arbitrary native code execution)";

        // AMSI bypass — disables Antimalware Scan Interface to evade detection.
        // Catches both direct field access and string-concat obfuscation patterns.
        if (lower.Contains("amsiutils") || lower.Contains("amsiinitfailed") ||
            lower.Contains("amsi" + "utils") ||
            (lower.Contains("[ref].assembly") && lower.Contains("amsi")))
            return "Contains AMSI bypass attempt (security evasion)";

        // Registry Run key persistence — adding entries to auto-start locations
        // allows malware to survive reboots.
        if ((lower.Contains("currentversion\\run") || lower.Contains("currentversion/run")) &&
            (lower.Contains("reg add") || lower.Contains("set-itemproperty") ||
             lower.Contains("new-itemproperty")))
            return "Contains registry Run key modification (persistence mechanism)";

        return null;
    }

    [GeneratedRegex(@"^[0-9a-fA-F.:]+$")]
    private static partial Regex IpAddressPattern();

    [GeneratedRegex(@"^[a-zA-Z0-9\s\-_.\\\@]+$")]
    private static partial Regex UsernamePattern();

    [GeneratedRegex(@"^[A-Za-z]:?$")]
    private static partial Regex DriveLetterPattern();

    [GeneratedRegex(@"^[a-zA-Z0-9\s\-_.]+$")]
    private static partial Regex FirewallRuleNamePattern();

    /// <summary>Rejects shell metacharacters, pipes, redirects, backticks in file paths.</summary>
    [GeneratedRegex(@"[|&;`$<>!{}]")]
    private static partial Regex PathInjectionPattern();

    /// <summary>Matches valid process names: letters, digits, dots, hyphens, underscores.</summary>
    [GeneratedRegex(@"^[a-zA-Z0-9._\-]+$")]
    private static partial Regex ProcessNamePattern();

    /// <summary>Matches control characters and newlines for log injection prevention.</summary>
    [GeneratedRegex(@"\r\n|\r|\n|[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]")]
    private static partial Regex LogInjectionPattern();

    /// <summary>Matches PowerShell call operator patterns: &amp; { ... } or &amp; "path".</summary>
    [GeneratedRegex(@"&\s*(\{|""|'|[a-zA-Z])")]
    private static partial Regex CallOperatorPattern();
}
