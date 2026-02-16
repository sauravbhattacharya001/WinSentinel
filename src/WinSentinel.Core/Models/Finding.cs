namespace WinSentinel.Core.Models;

/// <summary>
/// A single security finding from an audit module.
/// </summary>
public class Finding
{
    public required string Title { get; set; }
    public required string Description { get; set; }
    public Severity Severity { get; set; }
    public string? Remediation { get; set; }
    public string? FixCommand { get; set; }
    public string Category { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

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
