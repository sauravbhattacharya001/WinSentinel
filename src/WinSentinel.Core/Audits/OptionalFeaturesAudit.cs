using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces risky <b>Windows optional features</b> in a live
/// <c>--audit</c> run: the SMB 1.0/CIFS protocol, the legacy PowerShell 2.0 engine, and
/// cleartext legacy clients (Telnet, TFTP). Each of these expands the local attack surface or
/// defeats other controls (SMBv1 = wormable RCE, PowerShell 2.0 = logging/AMSI bypass) when
/// left enabled.
///
/// <para>This is the thin I/O layer for <see cref="OptionalFeaturesAnalyzer"/>: it runs
/// <c>Get-WindowsOptionalFeature -Online</c> to collect which features are Enabled and
/// delegates every pass/fail decision to the pure, unit-tested analyzer (collector owns I/O,
/// analyzer owns decisions - the same split as <see cref="WerExposureAudit"/> /
/// <see cref="WerExposureAnalyzer"/>). It reads only local feature state, so it is
/// single-machine and therefore FREE / OSS - nothing multi-machine, nothing
/// license-gated.</para>
/// </summary>
public class OptionalFeaturesAudit : AuditModuleBase
{
    public override string Name => "Optional Features Audit";
    public override string Category => OptionalFeaturesAnalyzer.Category;
    public override string Description =>
        "Checks for risky enabled Windows optional features - SMB 1.0/CIFS, the legacy PowerShell 2.0 engine, and " +
        "cleartext legacy clients (Telnet, TFTP) - that expand the local attack surface or bypass other controls.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = await CollectStateAsync(cancellationToken);
        foreach (var finding in OptionalFeaturesAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Enumerate the online optional-feature state via <c>Get-WindowsOptionalFeature</c>,
    /// collecting the FeatureName of every feature whose State is Enabled. Enumeration is
    /// best-effort: on any failure (non-elevated, DISM error, empty output) the state is marked
    /// <see cref="OptionalFeaturesState.EnumerationSucceeded"/> = false so the analyzer emits an
    /// informational finding rather than false-passing every check.
    /// </summary>
    internal static async Task<OptionalFeaturesState> CollectStateAsync(CancellationToken ct = default)
    {
        try
        {
            // Emit only enabled features, one FeatureName per line, to keep parsing trivial and
            // avoid pulling the (large) full feature catalogue into the report.
            const string command =
                "Get-WindowsOptionalFeature -Online | " +
                "Where-Object { $_.State -eq 'Enabled' } | " +
                "Select-Object -ExpandProperty FeatureName";

            var lines = await ShellHelper.RunPowerShellLinesAsync(command, ct);

            var enabled = lines
                .Select(l => l.Trim())
                .Where(l => l.Length > 0)
                .ToArray();

            // No lines at all almost always means the query failed (non-elevated / DISM error)
            // rather than a machine with zero enabled features, so treat it as an enumeration
            // failure and let the analyzer surface it as Info instead of an all-clear.
            if (enabled.Length == 0)
            {
                return new OptionalFeaturesState { EnumerationSucceeded = false };
            }

            return new OptionalFeaturesState
            {
                EnumerationSucceeded = true,
                EnabledFeatures = enabled,
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new OptionalFeaturesState { EnumerationSucceeded = false };
        }
    }
}
