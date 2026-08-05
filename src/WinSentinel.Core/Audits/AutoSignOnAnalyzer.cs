using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing single-machine Windows Automatic Restart Sign-On (ARSO) and
/// sign-in-screen account-detail exposure. These are local machine policy controls, so this module is
/// single-machine and therefore FREE / OSS: nothing multi-machine, nothing license-gated.
///
/// <para>Every rule operates on a synthetic <see cref="AutoSignOnState"/> so it can be unit tested
/// directly, mirroring the established <see cref="InteractiveLogonAnalyzer"/> /
/// <see cref="TimeSyncSecurityAnalyzer"/> split (collector owns I/O, analyzer owns decisions).</para>
///
///   * Automatic Restart Sign-On (DisableAutomaticRestartSignOn) - after a Windows-Update-triggered
///     reboot, ARSO silently signs the last interactive user back in (locking the screen) and
///     relaunches their apps so a "Winlogon Automatic Restart Sign-On" (also called Winlogon Cached
///     credentials / auto-logon after update). On a physically exposed or shared machine this stores a
///     protected credential blob and auto-establishes a session without a person present; CIS L1
///     recommends disabling it. Value 1 = disabled (secure), 0/unset = enabled.
///   * Sign-in-screen account details (BlockUserFromShowingAccountDetailsOnSignin) - when 0/unset, the
///     sign-in screen can surface the account's email address / display name to anyone at the console,
///     leaking a valid username for phishing/spray. Value 1 = blocked (secure).
/// </summary>
public static class AutoSignOnAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Automatic Sign-On";

    /// <summary>
    /// Evaluate the collected auto-sign-on state and return one finding per check (a Pass when the
    /// setting is already safe, otherwise Info/Warning). Ordering is stable and deterministic for
    /// diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(AutoSignOnState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeAutomaticRestartSignOn(state),
            AnalyzeSignInAccountDetails(state),
        };
    }

    /// <summary>
    /// DisableAutomaticRestartSignOn controls Automatic Restart Sign-On: 1 = ARSO disabled (secure),
    /// 0 or unset = ARSO enabled (Windows re-establishes the last user's session after an update
    /// reboot, storing a protected auto-logon credential and relaunching apps with no operator
    /// present). CIS L1 recommends disabling ARSO.
    /// </summary>
    public static Finding AnalyzeAutomaticRestartSignOn(AutoSignOnState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        // 1 => ARSO explicitly disabled (secure). Anything else (0, unset) => ARSO active.
        if (state.DisableAutomaticRestartSignOn == 1)
        {
            return Finding.Pass(
                "Automatic Restart Sign-On is disabled",
                "Automatic Restart Sign-On (ARSO) is disabled (DisableAutomaticRestartSignOn = 1). After a Windows Update " +
                "reboot the machine will NOT silently sign the last user back in or relaunch their apps, so no auto-logon " +
                "credential is stored and no session is established without a person present.",
                Category);
        }

        return Finding.Warning(
            "Automatic Restart Sign-On is enabled",
            "Automatic Restart Sign-On (ARSO) is enabled (DisableAutomaticRestartSignOn is 0 or unset). After a " +
            "Windows-Update-triggered reboot, Windows silently signs the last interactive user back in, storing a " +
            "protected auto-logon credential and relaunching that user's applications with no operator present. On a " +
            "physically exposed, shared, or kiosk machine this re-establishes an authenticated session automatically - CIS " +
            "L1 recommends disabling ARSO.",
            Category,
            remediation: "Set DisableAutomaticRestartSignOn to 1 under " +
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System to disable Automatic Restart Sign-On.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' " +
                "-Name DisableAutomaticRestartSignOn -Value 1 -Type DWord");
    }

    /// <summary>
    /// BlockUserFromShowingAccountDetailsOnSignin controls whether the sign-in screen may display the
    /// signed-in account's details (email / display name): 1 = blocked (secure), 0/unset = allowed
    /// (the sign-in screen can leak a valid username to anyone standing at the console).
    /// </summary>
    public static Finding AnalyzeSignInAccountDetails(AutoSignOnState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.BlockUserFromShowingAccountDetailsOnSignin == 1)
        {
            return Finding.Pass(
                "Sign-in screen hides account details",
                "The sign-in screen is blocked from displaying account details " +
                "(BlockUserFromShowingAccountDetailsOnSignin = 1), so a valid account email / display name is not exposed " +
                "to anyone at the console.",
                Category);
        }

        return Finding.Info(
            "Sign-in screen may display account details",
            "The sign-in screen is allowed to display the signed-in account's details such as the email address " +
            "(BlockUserFromShowingAccountDetailsOnSignin is 0 or unset). Anyone standing at the locked console can read a " +
            "valid username, which lowers the bar for targeted phishing or password-spray attacks against that identity.",
            Category,
            remediation: "Set BlockUserFromShowingAccountDetailsOnSignin to 1 under " +
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System to hide account details on the sign-in screen.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' " +
                "-Name BlockUserFromShowingAccountDetailsOnSignin -Value 1 -Type DWord");
    }
}

/// <summary>
/// Raw, collector-supplied Windows auto-sign-on policy state. Populated by the audit module's I/O
/// layer (reading the Policies\System and Policies\Microsoft\Windows\System registry values) and
/// handed to <see cref="AutoSignOnAnalyzer"/> for a pure decision. Defaults are chosen so an
/// unreadable value never false-positives the dangerous posture: both settings default to the secure
/// value (1) so a missing/unreadable key is never spuriously flagged.
/// </summary>
public sealed record AutoSignOnState
{
    /// <summary>
    /// DisableAutomaticRestartSignOn DWORD (1 = ARSO disabled/secure, 0/unset = ARSO enabled).
    /// Secure default: 1 so an unreadable value is not flagged as the dangerous posture.
    /// </summary>
    public int DisableAutomaticRestartSignOn { get; init; } = 1;

    /// <summary>
    /// BlockUserFromShowingAccountDetailsOnSignin DWORD (1 = blocked/secure, 0/unset = allowed).
    /// Secure default: 1 so an unreadable value is not flagged.
    /// </summary>
    public int BlockUserFromShowingAccountDetailsOnSignin { get; init; } = 1;
}
