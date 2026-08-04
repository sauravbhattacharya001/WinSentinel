using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing single-machine Windows interactive-logon policy hardening.
/// These are the classic CIS "Interactive logon" controls, all local machine policy, so this module
/// is single-machine and therefore FREE / OSS: nothing multi-machine, nothing license-gated.
///
/// <para>Every rule operates on a synthetic <see cref="InteractiveLogonState"/> so it can be unit
/// tested directly, mirroring the established <see cref="TimeSyncSecurityAnalyzer"/> /
/// <see cref="ExploitMitigationAnalyzer"/> split (collector owns I/O, analyzer owns decisions).</para>
///
///   * Logon legal-notice banner (LegalNoticeCaption / LegalNoticeText) - a pre-logon banner that
///     asserts the machine is private/monitored. Its presence is a documented legal prerequisite for
///     prosecuting unauthorized access and is a CIS L1 control; a missing banner is surfaced as Info.
///   * Smart-card removal behavior (ScRemoveOption) - what happens when a smart card is pulled from a
///     card-logon session. "No action" (0) leaves an authenticated session unlocked when the operator
///     walks away with their card; "Lock" (1) or "Force logoff" (2) are the safe postures. Only
///     meaningful when smart-card logon is actually in use.
///   * Machine-inactivity lock is covered by the ScreenLock module; this module intentionally does not
///     duplicate it.
/// </summary>
public static class InteractiveLogonAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Interactive Logon";

    /// <summary>ScRemoveOption value meaning "take no action when the smart card is removed" (insecure).</summary>
    public const string ScRemoveNoAction = "0";

    /// <summary>
    /// Evaluate the collected interactive-logon state and return one finding per check (a Pass when
    /// the setting is already safe, otherwise Info/Warning). Ordering is stable and deterministic for
    /// diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(InteractiveLogonState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeLogonBanner(state),
            AnalyzeSmartCardRemoval(state),
        };
    }

    /// <summary>
    /// A pre-logon legal-notice banner (LegalNoticeCaption + LegalNoticeText) warns that the system is
    /// private and monitored. Its presence is a CIS L1 control and a common legal prerequisite for
    /// pursuing unauthorized-access cases; an empty caption or body means no banner is shown.
    /// </summary>
    public static Finding AnalyzeLogonBanner(InteractiveLogonState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var caption = (state.LegalNoticeCaption ?? string.Empty).Trim();
        var text = (state.LegalNoticeText ?? string.Empty).Trim();

        // A banner is only meaningful when BOTH a caption and body are set; either one empty means the
        // pre-logon notice does not actually render.
        if (caption.Length == 0 || text.Length == 0)
        {
            return Finding.Info(
                "No logon legal-notice banner is configured",
                "No pre-logon legal-notice banner is configured (LegalNoticeCaption and/or LegalNoticeText is empty). A " +
                "logon banner that states the system is private and its use may be monitored is a CIS L1 control and is " +
                "often a legal prerequisite for prosecuting unauthorized access - without it, a defendant can claim they " +
                "had no notice that access was restricted.",
                Category,
                remediation: "Set both LegalNoticeCaption (title) and LegalNoticeText (body) under " +
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System to your organization's " +
                    "authorized-use notice.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' " +
                    "-Name LegalNoticeCaption -Value 'Authorized Use Only'; " +
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' " +
                    "-Name LegalNoticeText -Value 'This system is for authorized users only. Activity may be monitored.'");
        }

        return Finding.Pass(
            "Logon legal-notice banner is configured",
            "A pre-logon legal-notice banner is configured (both LegalNoticeCaption and LegalNoticeText are set), so users " +
            "see an authorized-use notice before signing in - satisfying the CIS L1 control and establishing that access is " +
            "restricted.",
            Category);
    }

    /// <summary>
    /// ScRemoveOption controls what happens when a smart card is removed from a smart-card-logon
    /// session: 0 = no action (insecure - the session stays unlocked), 1 = lock, 2 = force logoff.
    /// This is only relevant when smart-card logon is actually in use; on a machine with no smart-card
    /// logon the setting is not a finding.
    /// </summary>
    public static Finding AnalyzeSmartCardRemoval(InteractiveLogonState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (!state.SmartCardLogonInUse)
        {
            return Finding.Pass(
                "Smart-card removal policy is not applicable",
                "No smart-card logon is in use on this machine, so the smart-card removal behavior (ScRemoveOption) does " +
                "not apply. If smart-card logon is later enabled, configure it to lock or log off on card removal.",
                Category);
        }

        var option = (state.ScRemoveOption ?? string.Empty).Trim();

        if (option.Length == 0 || string.Equals(option, ScRemoveNoAction, StringComparison.Ordinal))
        {
            return Finding.Warning(
                "Smart card removal takes no action (session stays unlocked)",
                "Smart-card logon is in use but the smart-card removal policy (ScRemoveOption) is set to 'No Action' (or is " +
                "unset). When the operator pulls their smart card and walks away, the authenticated session is left " +
                "unlocked and available to anyone at the keyboard - defeating the physical-token protection smart-card " +
                "logon is meant to provide.",
                Category,
                remediation: "Set the smart-card removal behavior to Lock (1) or Force Logoff (2) so removing the card " +
                    "immediately secures the session.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' " +
                    "-Name ScRemoveOption -Value '1'");
        }

        var behavior = option switch
        {
            "1" => "lock the workstation",
            "2" => "force logoff",
            _ => $"apply policy value '{option}'",
        };

        return Finding.Pass(
            "Smart card removal locks or logs off the session",
            $"Smart-card logon is in use and the removal policy (ScRemoveOption = {option}) is configured to {behavior} " +
            "when the card is removed, so an authenticated session cannot be left unlocked after the operator takes their " +
            "card and leaves.",
            Category);
    }
}

/// <summary>
/// Raw, collector-supplied Windows interactive-logon policy state. Populated by the audit module's
/// I/O layer (reading the Winlogon and Policies\System registry values) and handed to
/// <see cref="InteractiveLogonAnalyzer"/> for a pure decision. Defaults are chosen so an unreadable
/// value never false-positives the dangerous posture: the banner is assumed configured and smart-card
/// logon is assumed not in use (so the removal check is not a spurious warning on a machine that never
/// uses smart cards).
/// </summary>
public sealed record InteractiveLogonState
{
    /// <summary>The LegalNoticeCaption (banner title). Empty/absent means no banner. Secure default: a non-empty placeholder.</summary>
    public string? LegalNoticeCaption { get; init; } = "configured";

    /// <summary>The LegalNoticeText (banner body). Empty/absent means no banner. Secure default: a non-empty placeholder.</summary>
    public string? LegalNoticeText { get; init; } = "configured";

    /// <summary>Whether smart-card interactive logon is actually in use on this machine (gates the removal check).</summary>
    public bool SmartCardLogonInUse { get; init; }

    /// <summary>The Winlogon ScRemoveOption value (0 = no action, 1 = lock, 2 = force logoff). Secure default: lock.</summary>
    public string? ScRemoveOption { get; init; } = "1";
}
