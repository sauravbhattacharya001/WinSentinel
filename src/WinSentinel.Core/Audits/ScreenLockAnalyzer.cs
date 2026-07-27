using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for interactive-session lock &amp; sign-in hardening on a
/// single machine. These are the classic CIS Windows L1 settings that decide
/// whether an unattended, unlocked desktop is left exposed and how much a
/// shoulder-surfer at the lock screen can learn:
///
///   * InactivityTimeoutSecs - HKLM\...\System\InactivityTimeoutSecs. Locks the
///                             machine after N seconds of inactivity. 0/absent =
///                             never auto-lock. CIS L1 wants &gt;0 and &lt;= 900 (15 min).
///   * ScreenSaverActive + ScreenSaverIsSecure + ScreenSaverTimeoutSecs -
///                             the per-user screensaver lock (HKCU\Control Panel\Desktop).
///                             A secure screensaver with a sane timeout is the
///                             classic fallback lock. Not secure / no timeout = exposed.
///   * DontDisplayLastUserName - hides the last signed-in username on the logon
///                             screen so an attacker can't harvest a valid account name.
///   * DisableCAD             - Ctrl+Alt+Del at logon (a secure attention sequence)
///                             defeats credential-harvesting fake logon UIs. Disabling
///                             it (DisableCAD = 1) weakens that protection.
///   * DontDisplayLockedUserId - controls whether user details are shown on the
///                             locked screen; 3 = "do not display user information".
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// registry / policy state only. Nothing multi-machine, nothing license-gated.
/// All rules operate on a synthetic <see cref="ScreenLockState"/> so they can be
/// unit tested directly, mirroring the established
/// <see cref="LsaHardeningAnalyzer"/> analyzer pattern (collector owns I/O, the
/// analyzer owns decisions).
/// </summary>
public static class ScreenLockAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Session Security";

    /// <summary>CIS L1 upper bound for the machine inactivity lock timeout (15 minutes).</summary>
    public const int MaxInactivityTimeoutSecs = 900;

    /// <summary>
    /// Evaluate the collected session-lock state and return one finding per check
    /// (a Pass when the setting is already safe, a Warning when it is not).
    /// Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(ScreenLockState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeInactivityTimeout(state),
            AnalyzeScreenSaver(state),
            AnalyzeLastUserName(state),
            AnalyzeSecureAttentionSequence(state),
            AnalyzeLockedUserInfo(state),
        };
    }

    /// <summary>Machine inactivity limit: must be enabled and no longer than 15 minutes.</summary>
    public static Finding AnalyzeInactivityTimeout(ScreenLockState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int secs = state.InactivityTimeoutSecs ?? 0;
        if (secs > 0 && secs <= MaxInactivityTimeoutSecs)
        {
            return Finding.Pass(
                "Machine auto-locks after inactivity",
                $"InactivityTimeoutSecs is {secs}s, within the recommended limit of {MaxInactivityTimeoutSecs}s " +
                "(15 min). An unattended session locks automatically.",
                Category);
        }

        if (secs == 0)
        {
            return Finding.Warning(
                "Machine never auto-locks on inactivity",
                "InactivityTimeoutSecs is 0 or unset, so the machine does not lock itself " +
                "after a period of inactivity. An unattended, unlocked desktop is fully " +
                "usable by anyone with physical access.",
                Category,
                remediation: "Set the machine inactivity limit to 900 seconds (15 min) or less.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name InactivityTimeoutSecs -Type DWord -Value 900");
        }

        return Finding.Warning(
            "Inactivity lock timeout is too long",
            $"InactivityTimeoutSecs is {secs}s, longer than the recommended maximum of " +
            $"{MaxInactivityTimeoutSecs}s (15 min). The machine stays unlocked far longer than it should when left unattended.",
            Category,
            remediation: "Lower the machine inactivity limit to 900 seconds (15 min) or less.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name InactivityTimeoutSecs -Type DWord -Value 900");
    }

    /// <summary>Screensaver must be active, password-protected, and have a sane timeout.</summary>
    public static Finding AnalyzeScreenSaver(ScreenLockState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int timeout = state.ScreenSaverTimeoutSecs ?? 0;
        bool secure = state.ScreenSaverActive && state.ScreenSaverIsSecure &&
                      timeout > 0 && timeout <= MaxInactivityTimeoutSecs;
        if (secure)
        {
            return Finding.Pass(
                "Password-protected screensaver is configured",
                $"A secure screensaver is active with a {timeout}s timeout, providing a " +
                "per-session fallback lock.",
                Category);
        }

        if (!state.ScreenSaverActive)
        {
            return Finding.Warning(
                "No screensaver lock configured",
                "The screensaver is not active (ScreenSaveActive off), so there is no " +
                "per-session screensaver fallback to lock the desktop when idle.",
                Category,
                remediation: "Enable a password-protected screensaver with a timeout of 900s or less " +
                             "(Control Panel\\Desktop: ScreenSaveActive=1, ScreenSaverIsSecure=1, ScreenSaveTimeOut<=900).");
        }

        if (!state.ScreenSaverIsSecure)
        {
            return Finding.Warning(
                "Screensaver does not require a password",
                "A screensaver is active but ScreenSaverIsSecure is off, so dismissing it " +
                "does not require re-authentication - it provides no lock.",
                Category,
                remediation: "Set ScreenSaverIsSecure = 1 so the screensaver requires a password on resume.");
        }

        return Finding.Warning(
            "Screensaver timeout is unset or too long",
            $"The secure screensaver timeout is {timeout}s, which is unset or longer than the " +
            $"recommended maximum of {MaxInactivityTimeoutSecs}s (15 min).",
            Category,
            remediation: "Set ScreenSaveTimeOut to 900 seconds (15 min) or less.");
    }

    /// <summary>The last signed-in username must not be shown on the logon screen.</summary>
    public static Finding AnalyzeLastUserName(ScreenLockState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.DontDisplayLastUserName == 1)
        {
            return Finding.Pass(
                "Last signed-in username is hidden",
                "DontDisplayLastUserName is enabled, so the logon screen does not reveal a " +
                "valid account name to onlookers.",
                Category);
        }

        return Finding.Warning(
            "Logon screen shows the last signed-in username",
            "DontDisplayLastUserName is off, so the logon screen displays the last account " +
            "that signed in. An attacker at the machine already has half of a valid credential (the username).",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName = 1 (DWORD).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name DontDisplayLastUserName -Type DWord -Value 1");
    }

    /// <summary>Ctrl+Alt+Del at logon (the secure attention sequence) should stay required.</summary>
    public static Finding AnalyzeSecureAttentionSequence(ScreenLockState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // DisableCAD = 1 means Ctrl+Alt+Del is NOT required before logon.
        if (state.DisableCad == 1)
        {
            return Finding.Warning(
                "Ctrl+Alt+Del is not required before logon",
                "DisableCAD is enabled, so users can sign in without pressing Ctrl+Alt+Del. " +
                "The secure attention sequence defeats credential-harvesting fake logon UIs; " +
                "disabling it removes that protection.",
                Category,
                remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD = 0 (DWORD).",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name DisableCAD -Type DWord -Value 0");
        }

        return Finding.Pass(
            "Ctrl+Alt+Del is required before logon",
            "DisableCAD is 0 or absent, so the secure attention sequence is required before " +
            "sign-in, defeating fake logon-prompt credential theft.",
            Category);
    }

    /// <summary>The locked screen should not display user account details.</summary>
    public static Finding AnalyzeLockedUserInfo(ScreenLockState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // DontDisplayLockedUserId = 3 -> "Do not display user information".
        if (state.DontDisplayLockedUserId == 3)
        {
            return Finding.Pass(
                "Locked screen hides user information",
                "DontDisplayLockedUserId is 3, so no user account details are shown on the " +
                "locked screen.",
                Category);
        }

        return Finding.Warning(
            "Locked screen may display user information",
            "DontDisplayLockedUserId is not set to 3 (\"do not display user information\"), " +
            "so the locked screen may reveal the account name or full name of the signed-in user.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLockedUserId = 3 (DWORD).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name DontDisplayLockedUserId -Type DWord -Value 3");
    }
}

/// <summary>
/// Raw, collector-supplied interactive-session lock / sign-in registry state.
/// Populated by the audit module's I/O layer and handed to
/// <see cref="ScreenLockAnalyzer"/> for a pure decision. Null numeric fields mean
/// "value absent / not readable"; the analyzer treats absence as the insecure
/// OS default for each key (auto-lock off, last-user shown, etc.).
/// </summary>
public sealed record ScreenLockState
{
    /// <summary>HKLM\...\Policies\System\InactivityTimeoutSecs (DWORD). Seconds before machine auto-lock; 0/null = never.</summary>
    public int? InactivityTimeoutSecs { get; init; }

    /// <summary>HKCU\Control Panel\Desktop\ScreenSaveActive == "1".</summary>
    public bool ScreenSaverActive { get; init; }

    /// <summary>HKCU\Control Panel\Desktop\ScreenSaverIsSecure == "1" (password required on resume).</summary>
    public bool ScreenSaverIsSecure { get; init; }

    /// <summary>HKCU\Control Panel\Desktop\ScreenSaveTimeOut (parsed seconds). Null = unset.</summary>
    public int? ScreenSaverTimeoutSecs { get; init; }

    /// <summary>HKLM\...\Policies\System\DontDisplayLastUserName (DWORD). 1 = hide last user.</summary>
    public int? DontDisplayLastUserName { get; init; }

    /// <summary>HKLM\...\Policies\System\DisableCAD (DWORD). 1 = Ctrl+Alt+Del NOT required.</summary>
    public int? DisableCad { get; init; }

    /// <summary>HKLM\...\Policies\System\DontDisplayLockedUserId (DWORD). 3 = hide user info on locked screen.</summary>
    public int? DontDisplayLockedUserId { get; init; }
}
