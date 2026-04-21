namespace WinSentinel.Core.Models;

/// <summary>
/// Centralised severity-related helpers to eliminate duplicated
/// switch expressions scattered across services.
/// </summary>
public static class SeverityExtensions
{
    /// <summary>
    /// Standard risk weight used for aggregate scoring across the codebase.
    /// Critical=10, Warning=5, Info=1, Pass/other=0.
    /// </summary>
    public static int RiskWeight(this Severity severity) => severity switch
    {
        Severity.Critical => 10,
        Severity.Warning  => 5,
        Severity.Info     => 1,
        _                 => 0
    };

    /// <summary>
    /// Human-readable short label (e.g. for log output, text reports).
    /// </summary>
    public static string ShortLabel(this Severity severity) => severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.Warning  => "WARNING",
        Severity.Info     => "INFO",
        Severity.Pass     => "PASS",
        _                 => "UNKNOWN"
    };
}
