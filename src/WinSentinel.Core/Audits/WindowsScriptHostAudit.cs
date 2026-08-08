using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows Script Host (WSH) hardening in
/// a live <c>--audit</c> run: whether WSH (<c>wscript.exe</c>/<c>cscript.exe</c>) is
/// disabled, whether a per-user override re-enables it on top of a machine-wide
/// disable, whether remote script execution is allowed, and whether an Authenticode
/// TrustPolicy is enforced. WSH is a long-standing living-off-the-land execution
/// surface (phishing droppers ship double-clickable <c>.vbs</c>/<c>.js</c> files),
/// so this is high-value single-machine hardening.
///
/// <para>This is the thin I/O layer for <see cref="WindowsScriptHostAnalyzer"/>: it
/// owns the reading of the HKLM and HKCU <c>Windows Script Host\Settings</c> registry
/// values and delegates every pass/fail decision to the pure, unit-tested analyzer
/// (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="ScreenLockAudit"/> / <see cref="ScreenLockAnalyzer"/>). It reads only
/// local machine / current-user state, so it is single-machine and therefore FREE /
/// OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class WindowsScriptHostAudit : AuditModuleBase
{
    public override string Name => "Windows Script Host Audit";
    public override string Category => WindowsScriptHostAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows Script Host hardening - whether wscript.exe/cscript.exe are disabled, " +
        "whether a per-user override re-enables WSH over a machine-wide disable, whether remote script execution " +
        "is allowed, and whether signed-only (Authenticode) TrustPolicy is enforced - to reduce the .vbs/.js " +
        "living-off-the-land execution surface.";

    private const string WshSettingsSubKey = @"SOFTWARE\Microsoft\Windows Script Host\Settings";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in WindowsScriptHostAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local Windows Script Host state into the pure <see cref="WindowsScriptHostState"/>. Each
    /// value is a best-effort registry read whose absence maps to null so the analyzer treats it as the
    /// Windows default (WSH enabled, local scripts, no signature enforcement) - never a false pass.
    /// The machine-wide values come from HKLM; <see cref="WindowsScriptHostState.UserEnabled"/> is the
    /// per-user HKCU Enabled override that can bypass a machine-wide disable.
    /// </summary>
    internal static WindowsScriptHostState CollectState()
    {
        return new WindowsScriptHostState
        {
            Enabled = ReadDword(RegistryHive.LocalMachine, WshSettingsSubKey, "Enabled"),
            UserEnabled = ReadDword(RegistryHive.CurrentUser, WshSettingsSubKey, "Enabled"),
            Remote = ReadDword(RegistryHive.LocalMachine, WshSettingsSubKey, "Remote"),
            TrustPolicy = ReadDword(RegistryHive.LocalMachine, WshSettingsSubKey, "TrustPolicy"),
        };
    }

    /// <summary>
    /// Best-effort read of a WSH DWORD; null when missing/unreadable. Windows stores these values as
    /// REG_SZ ("0"/"1"/"2") historically but modern policy writes REG_DWORD, so this tolerates both.
    /// </summary>
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
