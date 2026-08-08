using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine interactive-session lock &amp; sign-in
/// hardening in a live <c>--audit</c> run: whether the machine auto-locks on
/// inactivity, whether a password-protected screensaver fallback is configured,
/// whether the logon / locked screen leaks the account name, whether Ctrl+Alt+Del
/// is required, and whether automatic (passwordless) console logon is left enabled.
///
/// <para>This is the thin I/O layer for <see cref="ScreenLockAnalyzer"/>: it owns
/// the reading of the HKLM Policies\System, HKLM Winlogon and HKCU Control Panel\Desktop
/// registry values and delegates every pass/fail decision to the pure, unit-tested
/// analyzer (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="InteractiveLogonAudit"/> / <see cref="InteractiveLogonAnalyzer"/>). It
/// reads only local machine / current-user state, so it is single-machine and
/// therefore FREE / OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class ScreenLockAudit : AuditModuleBase
{
    public override string Name => "Session Lock Audit";
    public override string Category => ScreenLockAnalyzer.Category;
    public override string Description =>
        "Checks single-machine interactive-session lock and sign-in hardening - machine inactivity auto-lock, a " +
        "password-protected screensaver fallback, hiding the last user on the logon/locked screen, requiring " +
        "Ctrl+Alt+Del, and disabling automatic passwordless console logon - CIS L1 session-security controls.";

    private const string PoliciesSystemSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string WinlogonSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string DesktopSubKey = @"Control Panel\Desktop";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in ScreenLockAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local session-lock state into the pure <see cref="ScreenLockState"/>. Each value is a
    /// best-effort registry read whose absence maps to the insecure OS default (via null / false) so
    /// a missing key surfaces as the exposure the analyzer expects, never a false pass.
    /// </summary>
    internal static ScreenLockState CollectState()
    {
        return new ScreenLockState
        {
            InactivityTimeoutSecs = ReadDword(RegistryHive.LocalMachine, PoliciesSystemSubKey, "InactivityTimeoutSecs"),
            ScreenSaverActive = ReadBoolString(RegistryHive.CurrentUser, DesktopSubKey, "ScreenSaveActive"),
            ScreenSaverIsSecure = ReadBoolString(RegistryHive.CurrentUser, DesktopSubKey, "ScreenSaverIsSecure"),
            ScreenSaverTimeoutSecs = ReadIntString(RegistryHive.CurrentUser, DesktopSubKey, "ScreenSaveTimeOut"),
            DontDisplayLastUserName = ReadDword(RegistryHive.LocalMachine, PoliciesSystemSubKey, "DontDisplayLastUserName"),
            DisableCad = ReadDword(RegistryHive.LocalMachine, PoliciesSystemSubKey, "DisableCAD"),
            DontDisplayLockedUserId = ReadDword(RegistryHive.LocalMachine, PoliciesSystemSubKey, "DontDisplayLockedUserId"),
            AutoAdminLogon = ReadIntString(RegistryHive.LocalMachine, WinlogonSubKey, "AutoAdminLogon"),
            DefaultPasswordPresent = ReadString(RegistryHive.LocalMachine, WinlogonSubKey, "DefaultPassword") is { Length: > 0 },
        };
    }

    /// <summary>Best-effort read of a REG_DWORD as an int; null when missing/unreadable.</summary>
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

    /// <summary>
    /// Best-effort read of a REG_SZ that carries an integer (e.g. ScreenSaver timeout, AutoAdminLogon);
    /// null when missing/unparsable. These are stored as strings by Windows, not DWORDs.
    /// </summary>
    private static int? ReadIntString(RegistryHive hive, string subKey, string valueName)
    {
        string? raw = ReadString(hive, subKey, valueName);
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return int.TryParse(raw.Trim(), out var parsed) ? parsed : (int?)null;
    }

    /// <summary>Read a REG_SZ "1"/"0" boolean-style flag; true only when the value is exactly "1".</summary>
    private static bool ReadBoolString(RegistryHive hive, string subKey, string valueName)
    {
        string? raw = ReadString(hive, subKey, valueName);
        return raw?.Trim() == "1";
    }

    /// <summary>Best-effort read of a REG_SZ, returning <c>null</c> when missing/unreadable.</summary>
    private static string? ReadString(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            return RegistryHelper.GetValue<string?>(hive, subKey, valueName, null);
        }
        catch
        {
            return null;
        }
    }
}
