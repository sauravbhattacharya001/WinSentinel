using System.Globalization;
using WinSentinel.Core.Localization;

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
    /// <para>
    /// This is an <b>invariant</b> upper-case token intended for logs, parsers and
    /// stable machine-readable output - it is deliberately NOT localized. Use
    /// <see cref="DisplayName(Severity, CultureInfo?)"/> for user-facing text.
    /// </para>
    /// </summary>
    public static string ShortLabel(this Severity severity) => severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.Warning  => "WARNING",
        Severity.Info     => "INFO",
        Severity.Pass     => "PASS",
        _                 => "UNKNOWN"
    };

    /// <summary>
    /// Resource key backing each severity's localized display name.
    /// </summary>
    private static string ResourceKey(this Severity severity) => severity switch
    {
        Severity.Critical => "Severity_Critical",
        Severity.Warning  => "Severity_Warning",
        Severity.Info     => "Severity_Info",
        Severity.Pass     => "Severity_Pass",
        _                 => "Severity_Info"
    };

    /// <summary>
    /// Localized, title-case display name for the severity (e.g. "Critical",
    /// or "Cr\u00edtico" under <c>es</c>). Routes through the <see cref="L"/>
    /// resource helper so the label honours the active UI culture or an
    /// explicit <paramref name="culture"/> override. Falls back to the English
    /// resource value (and ultimately the key) if a translation is missing.
    /// </summary>
    /// <param name="severity">The severity to render.</param>
    /// <param name="culture">Optional culture override; defaults to the current UI culture.</param>
    public static string DisplayName(this Severity severity, CultureInfo? culture = null)
    {
        var effective = culture ?? L.Culture ?? CultureInfo.CurrentUICulture;
        return L.Get(effective, severity.ResourceKey());
    }
}
