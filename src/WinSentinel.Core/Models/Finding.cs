namespace WinSentinel.Core.Models;

/// <summary>
/// A single security finding from an audit module.
/// </summary>
public class Finding
{
    /// <summary>Short title describing the finding.</summary>
    public required string Title { get; set; }

    /// <summary>Detailed description of what was found.</summary>
    public required string Description { get; set; }

    /// <summary>Severity level of this finding.</summary>
    public Severity Severity { get; set; }

    /// <summary>Suggested remediation steps (human-readable).</summary>
    public string? Remediation { get; set; }

    /// <summary>PowerShell command that can auto-fix this finding, if available.</summary>
    public string? FixCommand { get; set; }

    /// <summary>Category grouping (e.g. "Firewall", "Accounts").</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>When this finding was detected.</summary>
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Create a passing (no-issue) finding.
    /// </summary>
    public static Finding Pass(string title, string description, string category,
        string? remediation = null, string? fixCommand = null) => new()
    {
        Title = title,
        Description = description,
        Severity = Severity.Pass,
        Category = category,
        Remediation = remediation,
        FixCommand = fixCommand
    };

    /// <summary>
    /// Create an informational finding (no action required).
    /// </summary>
    public static Finding Info(string title, string description, string category,
        string? remediation = null, string? fixCommand = null) => new()
    {
        Title = title,
        Description = description,
        Severity = Severity.Info,
        Category = category,
        Remediation = remediation,
        FixCommand = fixCommand
    };

    /// <summary>
    /// Create a warning-level finding.
    /// </summary>
    public static Finding Warning(string title, string description, string category,
        string? remediation = null, string? fixCommand = null) => new()
    {
        Title = title,
        Description = description,
        Severity = Severity.Warning,
        Category = category,
        Remediation = remediation,
        FixCommand = fixCommand
    };

    /// <summary>
    /// Create a critical-severity finding.
    /// </summary>
    public static Finding Critical(string title, string description, string category,
        string? remediation = null, string? fixCommand = null) => new()
    {
        Title = title,
        Description = description,
        Severity = Severity.Critical,
        Category = category,
        Remediation = remediation,
        FixCommand = fixCommand
    };
}
