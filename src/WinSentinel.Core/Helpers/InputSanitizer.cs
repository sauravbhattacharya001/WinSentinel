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

        // Check against protected system directories
        foreach (var protectedDir in ProtectedDirectories)
        {
            if (fullPath.StartsWith(protectedDir, StringComparison.OrdinalIgnoreCase))
                return null;
        }

        // Check against protected system file names
        var fileName = Path.GetFileName(fullPath);
        foreach (var protectedFile in ProtectedFileNames)
        {
            if (fileName.Equals(protectedFile, StringComparison.OrdinalIgnoreCase))
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
}
