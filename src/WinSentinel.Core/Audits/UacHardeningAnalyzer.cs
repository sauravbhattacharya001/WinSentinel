using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing User Account Control (UAC) hardening on a single
/// machine. UAC is the local privilege boundary that forces administrative actions to
/// pass through an explicit consent/elevation prompt instead of running silently with the
/// full administrator token. Weakening it lets malware (or a coerced admin) elevate with no
/// prompt, and one specific knob (<c>LocalAccountTokenFilterPolicy</c>) re-enables remote
/// full-token local-admin logons that are the backbone of Pass-the-Hash lateral movement.
///
/// <para>The checks here mirror the CIS Windows L1 "User Account Control" section
/// (2.3.17.x) and read only local policy registry state
/// (<c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System</c>), so this module
/// is single-machine and therefore FREE / OSS: nothing multi-machine, nothing
/// license-gated. All rules operate on a synthetic <see cref="UacHardeningState"/> so they
/// can be unit tested directly, mirroring the established <see cref="SmbSecurityAnalyzer"/>
/// pattern (collector owns I/O, the analyzer owns decisions).</para>
///
///   * EnableLua                    - the master UAC switch. Off = every admin process runs
///                                    with the full token, no elevation prompt ever, the
///                                    single most dangerous UAC misconfiguration.
///   * ConsentPromptBehaviorAdmin   - how the admin-approval-mode consent prompt behaves.
///                                    0 = "Elevate without prompting" (silent elevation, the
///                                    weakest setting); CIS L1 requires 1 (prompt for
///                                    credentials on the secure desktop) or 2 (prompt for
///                                    consent on the secure desktop for non-Windows binaries).
///   * PromptOnSecureDesktop        - whether the elevation prompt is shown on the isolated
///                                    secure desktop, out of reach of a spoofing/overlay
///                                    attack from the interactive session.
///   * FilterAdministratorToken     - whether the built-in Administrator account (RID 500)
///                                    also runs in Admin Approval Mode. CIS L1 requires this
///                                    on so even the built-in admin is subject to UAC.
///   * EnableInstallerDetection     - whether legacy installer executables are detected and
///                                    prompted for elevation instead of silently failing/running.
///   * LocalAccountTokenFilterPolicy - the remote-UAC-filtering override. When set to 1, local
///                                    administrator accounts get a full (unfiltered) token over
///                                    the network, re-enabling remote admin logons that UAC
///                                    would otherwise filter - the classic Pass-the-Hash
///                                    lateral-movement enabler (MITRE ATT&amp;CK T1550.002).
///                                    Secure default is 0 / absent.
/// </summary>
public static class UacHardeningAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "User Account Control";

    /// <summary>
    /// Evaluate the collected UAC state and return one finding per check (a Pass when the
    /// setting is already safe, otherwise Info/Warning/Critical). Ordering is stable and
    /// deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(UacHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeEnableLua(state),
            AnalyzeConsentPromptBehaviorAdmin(state),
            AnalyzePromptOnSecureDesktop(state),
            AnalyzeFilterAdministratorToken(state),
            AnalyzeInstallerDetection(state),
            AnalyzeLocalAccountTokenFilterPolicy(state),
        };
    }

    /// <summary>The master UAC switch (EnableLUA) must be on.</summary>
    public static Finding AnalyzeEnableLua(UacHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.EnableLua)
        {
            return Finding.Pass(
                "UAC is enabled",
                "User Account Control is enabled (EnableLUA = 1), so administrative actions must pass through an " +
                "elevation prompt instead of running silently with the full administrator token.",
                Category);
        }

        return Finding.Critical(
            "UAC is disabled",
            "User Account Control is turned off (EnableLUA = 0). With UAC off, every process launched by an " +
            "administrator runs with the full, unfiltered administrator token and no elevation prompt is ever shown, " +
            "so any malware the admin runs silently gains full control of the machine. This also disables Admin " +
            "Approval Mode and the secure-desktop prompt entirely.",
            Category,
            remediation: "Re-enable UAC (EnableLUA = 1) and reboot. CIS Windows L1 requires UAC to be enabled.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1 -Type DWord");
    }

    /// <summary>
    /// The admin-approval-mode consent behaviour (ConsentPromptBehaviorAdmin) must prompt.
    /// 0 = elevate without prompting (worst); 1 = prompt for credentials on the secure
    /// desktop; 2 = prompt for consent on the secure desktop; 5 = prompt for consent for
    /// non-Windows binaries (the OS default). CIS L1 requires at least a prompt (1 or 2).
    /// </summary>
    public static Finding AnalyzeConsentPromptBehaviorAdmin(UacHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ConsentPromptBehaviorAdmin == 0)
        {
            return Finding.Critical(
                "UAC elevates administrators without prompting",
                "The admin-approval-mode consent policy is set to 'Elevate without prompting' " +
                "(ConsentPromptBehaviorAdmin = 0). Administrative actions are elevated silently with no consent or " +
                "credential prompt, so any code running as an administrator can gain full privileges without user " +
                "interaction. This is the weakest UAC prompt setting.",
                Category,
                remediation: "Require a prompt on the secure desktop for elevation (ConsentPromptBehaviorAdmin = 1 or 2). " +
                    "CIS Windows L1 recommends 'Prompt for consent on the secure desktop' (2).",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord");
        }

        return Finding.Pass(
            "UAC prompts administrators for elevation",
            $"The admin-approval-mode consent policy prompts before elevation (ConsentPromptBehaviorAdmin = " +
            $"{state.ConsentPromptBehaviorAdmin}), so administrative actions require explicit consent or credentials rather than elevating silently.",
            Category);
    }

    /// <summary>The elevation prompt should be shown on the isolated secure desktop.</summary>
    public static Finding AnalyzePromptOnSecureDesktop(UacHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.PromptOnSecureDesktop)
        {
            return Finding.Pass(
                "UAC prompts on the secure desktop",
                "The UAC elevation prompt is displayed on the isolated secure desktop (PromptOnSecureDesktop = 1), " +
                "so it cannot be spoofed or automated by an overlay from the interactive session.",
                Category);
        }

        return Finding.Warning(
            "UAC prompt not shown on the secure desktop",
            "The UAC elevation prompt is not shown on the secure desktop (PromptOnSecureDesktop = 0). When the prompt " +
            "renders on the normal interactive desktop, malware in the user's session can overlay, spoof, or " +
            "programmatically dismiss it, defeating the purpose of the elevation prompt.",
            Category,
            remediation: "Show the elevation prompt on the secure desktop (PromptOnSecureDesktop = 1). CIS Windows L1 requires this.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name PromptOnSecureDesktop -Value 1 -Type DWord");
    }

    /// <summary>
    /// The built-in Administrator (RID 500) should also run in Admin Approval Mode
    /// (FilterAdministratorToken = 1) so even it is subject to UAC.
    /// </summary>
    public static Finding AnalyzeFilterAdministratorToken(UacHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.FilterAdministratorToken)
        {
            return Finding.Pass(
                "Built-in Administrator runs in Admin Approval Mode",
                "The built-in Administrator account is subject to UAC (FilterAdministratorToken = 1), so even RID-500 " +
                "logons receive a filtered token and must elevate through a prompt.",
                Category);
        }

        return Finding.Warning(
            "Built-in Administrator bypasses UAC",
            "The built-in Administrator account (RID 500) is not running in Admin Approval Mode " +
            "(FilterAdministratorToken = 0). That account is exempt from UAC and runs every process with the full, " +
            "unfiltered administrator token and no elevation prompt, so anything running under it silently has full " +
            "control of the machine.",
            Category,
            remediation: "Put the built-in Administrator into Admin Approval Mode (FilterAdministratorToken = 1). CIS Windows L1 requires this.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name FilterAdministratorToken -Value 1 -Type DWord");
    }

    /// <summary>Legacy installer detection should be on so installers are prompted for elevation.</summary>
    public static Finding AnalyzeInstallerDetection(UacHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.EnableInstallerDetection)
        {
            return Finding.Pass(
                "UAC installer detection is enabled",
                "Legacy application-installer detection is enabled (EnableInstallerDetection = 1), so setup executables " +
                "are heuristically detected and prompted for elevation rather than silently failing or running under-privileged.",
                Category);
        }

        return Finding.Info(
            "UAC installer detection is disabled",
            "Legacy installer detection is disabled (EnableInstallerDetection = 0). Setup programs that expect to elevate " +
            "will not be automatically prompted, which can cause silent installer failures and, in some environments, " +
            "encourages users to disable UAC to work around them. CIS Windows L1 recommends leaving detection enabled.",
            Category,
            remediation: "Enable installer detection (EnableInstallerDetection = 1).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableInstallerDetection -Value 1 -Type DWord");
    }

    /// <summary>
    /// LocalAccountTokenFilterPolicy must be 0/absent. Setting it to 1 hands local admin
    /// accounts a full (unfiltered) token over the network, re-enabling remote admin logons
    /// that UAC would otherwise filter - the classic Pass-the-Hash lateral-movement enabler.
    /// </summary>
    public static Finding AnalyzeLocalAccountTokenFilterPolicy(UacHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.LocalAccountTokenFilterPolicyEnabled)
        {
            return Finding.Pass(
                "Remote UAC token filtering is intact",
                "LocalAccountTokenFilterPolicy is not enabled, so local administrator accounts receive a filtered " +
                "token over the network. This keeps remote UAC filtering in place, which limits Pass-the-Hash lateral " +
                "movement using local admin credentials.",
                Category);
        }

        return Finding.Critical(
            "Remote UAC token filtering is disabled",
            "LocalAccountTokenFilterPolicy is set to 1, which disables remote UAC token filtering. Local administrator " +
            "accounts now receive a full, unfiltered token over the network (SMB/WMI/WinRM), re-enabling remote " +
            "administrative logons that UAC would otherwise restrict. This is the backbone of Pass-the-Hash lateral " +
            "movement with a shared local-admin credential (MITRE ATT&CK T1550.002).",
            Category,
            remediation: "Restore remote UAC filtering by removing/zeroing LocalAccountTokenFilterPolicy (set to 0). " +
                "Only enable it for specific, well-understood remote-management scenarios.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name LocalAccountTokenFilterPolicy -Value 0 -Type DWord");
    }
}

/// <summary>
/// Raw, collector-supplied User Account Control (UAC) policy state. Populated by the audit
/// module's I/O layer (reading
/// <c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System</c>) and handed to
/// <see cref="UacHardeningAnalyzer"/> for a pure decision. Defaults are chosen so an
/// unreadable value never false-positives the dangerous posture: the on-by-default UAC
/// booleans default <c>true</c> (secure), <see cref="ConsentPromptBehaviorAdmin"/> defaults
/// to a prompting value, and the Pass-the-Hash override
/// <see cref="LocalAccountTokenFilterPolicyEnabled"/> defaults <c>false</c> (secure).
/// </summary>
public sealed record UacHardeningState
{
    /// <summary>EnableLUA (the master UAC switch). Secure default <c>true</c>.</summary>
    public bool EnableLua { get; init; } = true;

    /// <summary>
    /// ConsentPromptBehaviorAdmin: 0 = elevate without prompting (weakest); 1/2 = prompt on
    /// the secure desktop; 5 = prompt for non-Windows binaries (OS default). Defaults to 2
    /// (a prompting value) so an unreadable value is not flagged as the silent-elevation case.
    /// </summary>
    public int ConsentPromptBehaviorAdmin { get; init; } = 2;

    /// <summary>PromptOnSecureDesktop (elevation prompt on the isolated secure desktop). Secure default <c>true</c>.</summary>
    public bool PromptOnSecureDesktop { get; init; } = true;

    /// <summary>FilterAdministratorToken (built-in Administrator subject to Admin Approval Mode). Secure default <c>true</c>.</summary>
    public bool FilterAdministratorToken { get; init; } = true;

    /// <summary>EnableInstallerDetection (legacy installers prompted for elevation). Secure default <c>true</c>.</summary>
    public bool EnableInstallerDetection { get; init; } = true;

    /// <summary>
    /// Whether LocalAccountTokenFilterPolicy is set to 1 (remote UAC token filtering disabled -
    /// the Pass-the-Hash enabler). Secure default <c>false</c> (0 / absent).
    /// </summary>
    public bool LocalAccountTokenFilterPolicyEnabled { get; init; }
}
