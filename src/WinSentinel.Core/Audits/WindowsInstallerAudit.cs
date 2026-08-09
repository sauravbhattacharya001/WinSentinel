using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows Installer (MSI) hardening in a
/// live <c>--audit</c> run: whether the classic <c>AlwaysInstallElevated</c>
/// privilege-escalation policy is enabled in BOTH the machine (HKLM) and per-user
/// (HKCU) hives, whether ad-hoc MSI installs are restricted (<c>DisableMSI</c>), and
/// whether unprivileged users can override normally-restricted install properties
/// (<c>EnableUserControl</c>). <c>AlwaysInstallElevated</c> is the first thing local
/// privilege-escalation tooling (PowerUp, Metasploit) checks for, so this is
/// high-value single-machine hardening.
///
/// <para>This is the thin I/O layer for <see cref="WindowsInstallerAnalyzer"/>: it
/// owns the reading of the HKLM and HKCU
/// <c>Policies\Microsoft\Windows\Installer</c> registry values and delegates every
/// pass/fail decision to the pure, unit-tested analyzer (collector owns I/O,
/// analyzer owns decisions - the same split as
/// <see cref="WindowsScriptHostAudit"/> / <see cref="WindowsScriptHostAnalyzer"/>).
/// It reads only local machine / current-user state, so it is single-machine and
/// therefore FREE / OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class WindowsInstallerAudit : AuditModuleBase
{
    public override string Name => "Windows Installer Audit";
    public override string Category => WindowsInstallerAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows Installer (MSI) hardening - whether AlwaysInstallElevated is enabled " +
        "in both HKLM and HKCU (a classic local privilege-escalation path that lets any user install an MSI " +
        "as SYSTEM), whether ad-hoc MSI installs are restricted (DisableMSI), and whether unprivileged users " +
        "can override restricted install properties (EnableUserControl) - CIS L1 controls that decide how " +
        "easily msiexec becomes a local escalation and malware-delivery surface on this box.";

    private const string InstallerSubKey = @"SOFTWARE\Policies\Microsoft\Windows\Installer";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in WindowsInstallerAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local Windows Installer policy state into the pure <see cref="WindowsInstallerState"/>.
    /// Each value is a best-effort registry read whose absence maps to null; the analyzer then treats
    /// absence as the Windows default (installs allowed, no elevation, no user control), so a missing
    /// key never becomes a false pass or a false alarm. The AlwaysInstallElevated escalation requires
    /// BOTH hives, so the HKLM value comes from
    /// <see cref="WindowsInstallerState.MachineAlwaysInstallElevated"/> and the HKCU value from
    /// <see cref="WindowsInstallerState.UserAlwaysInstallElevated"/>.
    /// </summary>
    internal static WindowsInstallerState CollectState()
    {
        return new WindowsInstallerState
        {
            MachineAlwaysInstallElevated = ReadDword(RegistryHive.LocalMachine, InstallerSubKey, "AlwaysInstallElevated"),
            UserAlwaysInstallElevated = ReadDword(RegistryHive.CurrentUser, InstallerSubKey, "AlwaysInstallElevated"),
            DisableMsi = ReadDword(RegistryHive.LocalMachine, InstallerSubKey, "DisableMSI"),
            EnableUserControl = ReadDword(RegistryHive.LocalMachine, InstallerSubKey, "EnableUserControl"),
        };
    }

    /// <summary>Best-effort read of a REG_DWORD as an int; null when missing/unreadable. Tolerates a
    /// REG_SZ-encoded integer as well, mirroring the established audit collectors.</summary>
    private static int? ReadDword(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(hive, subKey, valueName, null);
            if (raw is null) return null;
            return raw is int i ? i : (int.TryParse(raw.ToString(), out var parsed) ? parsed : (int?)null);
        }
        catch
        {
            return null;
        }
    }
}
