using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows Automatic Restart Sign-On (ARSO) and
/// sign-in-screen account-detail exposure in a live <c>--audit</c> run: whether ARSO is disabled
/// (DisableAutomaticRestartSignOn) so the machine does not silently re-establish the last user's
/// session after an update reboot, and whether the sign-in screen is blocked from displaying account
/// details (BlockUserFromShowingAccountDetailsOnSignin).
///
/// <para>This is the thin I/O layer for <see cref="AutoSignOnAnalyzer"/>: it owns the reading of the
/// Policies\System and Policies\Microsoft\Windows\System registry values and delegates every pass/fail
/// decision to the pure, unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same
/// split as <see cref="InteractiveLogonAudit"/> / <see cref="InteractiveLogonAnalyzer"/>). It reads
/// only local machine state, so it is single-machine and therefore FREE / OSS - nothing multi-machine,
/// nothing license-gated.</para>
/// </summary>
public class AutoSignOnAudit : AuditModuleBase
{
    public override string Name => "Automatic Sign-On Audit";
    public override string Category => AutoSignOnAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows Automatic Restart Sign-On (ARSO) and sign-in-screen hardening - whether ARSO is " +
        "disabled (DisableAutomaticRestartSignOn) so the machine does not silently re-establish the last user's session " +
        "after an update reboot, and whether the sign-in screen is blocked from displaying account details " +
        "(BlockUserFromShowingAccountDetailsOnSignin) - CIS L1 interactive-logon controls.";

    private const string PoliciesSystemSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string PoliciesWindowsSystemSubKey = @"SOFTWARE\Policies\Microsoft\Windows\System";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in AutoSignOnAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local auto-sign-on policy state into the pure <see cref="AutoSignOnState"/>. Each value is
    /// a best-effort DWORD registry read whose absence maps to the secure default (1, see
    /// <see cref="AutoSignOnState"/>) so a missing key never false-positives the dangerous posture.
    /// </summary>
    internal static AutoSignOnState CollectState()
    {
        // Absent/unreadable => secure default (1). ARSO enabled is only asserted when the value is
        // explicitly present and NOT 1; the analyzer treats anything other than 1 as ARSO-active, so
        // we distinguish "explicitly 0" from "absent" by defaulting absent to the secure 1 here.
        int disableArso = ReadDword(PoliciesSystemSubKey, "DisableAutomaticRestartSignOn", defaultValue: 1);
        int blockDetails = ReadDword(PoliciesWindowsSystemSubKey, "BlockUserFromShowingAccountDetailsOnSignin", defaultValue: 1);

        return new AutoSignOnState
        {
            DisableAutomaticRestartSignOn = disableArso,
            BlockUserFromShowingAccountDetailsOnSignin = blockDetails,
        };
    }

    /// <summary>Best-effort read of a REG_DWORD from HKLM, returning <paramref name="defaultValue"/> when missing/unreadable.</summary>
    private static int ReadDword(string subKey, string valueName, int defaultValue)
    {
        try
        {
            return RegistryHelper.GetValue<int>(RegistryHive.LocalMachine, subKey, valueName, defaultValue);
        }
        catch
        {
            return defaultValue;
        }
    }
}
