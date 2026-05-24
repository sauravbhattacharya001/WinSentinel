using System.Collections.Generic;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Plugins;

/// <summary>
/// A single mapped compliance finding — ties an audit finding to a control
/// within a named framework (CIS, NIST 800-53, ISO 27001, …).
/// </summary>
/// <param name="Framework">Framework identifier, e.g. <c>CIS-Windows-11-v2.0.0</c>.</param>
/// <param name="ControlId">Control id within that framework, e.g. <c>2.3.4.1</c>.</param>
/// <param name="FindingId">WinSentinel finding identifier this maps to.</param>
/// <param name="Status">Mapping status: <c>pass</c>, <c>fail</c>, <c>manual</c>, <c>not-applicable</c>.</param>
/// <param name="Evidence">Free-text evidence summary surfaced to the auditor.</param>
public sealed record ComplianceFinding(
    string Framework,
    string ControlId,
    string FindingId,
    string Status,
    string Evidence);

/// <summary>
/// A plugin that translates a WinSentinel <see cref="SecurityReport"/> into
/// findings against a named compliance framework.
/// </summary>
public interface IComplianceMapper
{
    IReadOnlyList<ComplianceFinding> Map(SecurityReport report, string framework);
}
