using WinSentinel.Core.Models;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// Plugin contract for mapping <see cref="SecurityReport"/> findings to
/// compliance frameworks (CIS Benchmarks, Essential 8, NIST, etc.).
/// </summary>
/// <remarks>
/// The free core ships <c>WinSentinel.Core.Services.ComplianceMapper</c>
/// for a small built-in mapping. Richer framework support (CIS Level 2,
/// Essential 8 maturity model) is intended for Pro plugins via this
/// interface; the concrete class names <c>ComplianceMapper</c> /
/// <c>PdfExporter</c> / etc. must not appear in this repo outside this
/// folder.
/// </remarks>
public interface IComplianceMapper
{
    /// <summary>
    /// Map a report's findings to a framework's control set.
    /// </summary>
    /// <param name="report">The audit report to map.</param>
    /// <param name="framework">Framework identifier, e.g. <c>"cis-v8"</c>, <c>"essential8"</c>.</param>
    IReadOnlyList<ComplianceFinding> Map(SecurityReport report, string framework);
}

/// <summary>A finding mapped to a specific compliance control.</summary>
public sealed class ComplianceFinding
{
    /// <summary>Control identifier within the framework, e.g. <c>"CIS-2.1.1"</c>.</summary>
    public required string ControlId { get; init; }

    /// <summary>Human-readable control title.</summary>
    public required string ControlTitle { get; init; }

    /// <summary>Whether the system meets this control.</summary>
    public bool Compliant { get; init; }

    /// <summary>Severity of the non-compliance, if any.</summary>
    public Severity Severity { get; init; }

    /// <summary>Finding titles from the source report that drove this mapping.</summary>
    public IReadOnlyList<string> SourceFindings { get; init; } = Array.Empty<string>();

    /// <summary>Optional remediation note.</summary>
    public string? Remediation { get; init; }
}
