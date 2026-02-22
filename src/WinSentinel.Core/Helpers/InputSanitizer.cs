using System.Text.RegularExpressions;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Input sanitization helpers to prevent command injection
/// in shell commands executed by ShellHelper, FixEngine, and AutoRemediator.
/// </summary>
public static partial class InputSanitizer
{
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
}
