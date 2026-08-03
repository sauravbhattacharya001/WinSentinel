using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing Windows application-control (allowlisting) posture on a
/// single machine. Application allowlisting - only known-good executables, installers, scripts
/// and DLLs are permitted to run - is the single most effective control against untrusted code
/// execution: it is Essential 8 mitigation #1 ("Application control") and a CIS Windows L1
/// requirement. Windows ships three complementary mechanisms:
///
///   * <b>AppLocker</b> - policy-driven allowlisting split into rule collections
///     (Exe, Msi, Script, Dll, Appx). Each collection has an enforcement mode: absent /
///     NotConfigured (unenforced), AuditOnly (0 - logs but still allows), or Enabled
///     (1 - actually blocks). Enforcement is delivered by the Application Identity service
///     (AppIDSvc); if that service is not running, even an "Enabled" AppLocker policy does
///     nothing. State lives under
///     <c>HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\{Exe|Msi|Script|Dll|Appx}</c>.
///   * <b>WDAC / Windows Defender Application Control (Code Integrity policy)</b> - a
///     kernel-enforced allowlist, stronger than AppLocker and harder to tamper with. Its
///     deployed-policy state surfaces under
///     <c>HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy</c>.
///   * <b>Smart App Control</b> - the Win11 consumer allowlist. Its state
///     (<c>VerifiedAndReputablePolicyState</c>) is 0 = Off, 1 = On (enforcing),
///     2 = Evaluation.
///
/// <para>This module reads only local policy/service/CI registry state, so it is
/// single-machine and therefore FREE / OSS - nothing multi-machine, nothing license-gated.
/// All rules operate on a synthetic <see cref="ApplicationControlState"/> so they can be unit
/// tested directly, mirroring the established collector-owns-I/O / analyzer-owns-decisions
/// split used by <see cref="UacHardeningAnalyzer"/> and <see cref="SmbSecurityAnalyzer"/>.
/// Defaults are chosen so an unreadable value never invents a control that is not there: an
/// absent AppLocker collection is reported as "not configured" (a gap), not a false pass.</para>
/// </summary>
public static class ApplicationControlAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Application Control";

    /// <summary>The five AppLocker rule collections, in a stable, diffable order.</summary>
    private static readonly (string Key, string Label, bool Core)[] Collections =
    {
        ("Exe", "executables (.exe/.com)", true),
        ("Msi", "installers (.msi/.msp)", true),
        ("Script", "scripts (.ps1/.bat/.cmd/.vbs/.js)", true),
        ("Dll", "DLLs", false),
        ("Appx", "packaged/Store apps", false),
    };

    /// <summary>
    /// Evaluate collected application-control state and return one finding per check. Ordering
    /// is stable and deterministic for diffable reports: an overall AppLocker posture finding,
    /// the AppIDSvc enforcement-service finding, one finding per AppLocker rule collection, then
    /// WDAC and Smart App Control.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(ApplicationControlState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<Finding>
        {
            AnalyzeAppLockerOverall(state),
            AnalyzeAppIdService(state),
        };

        foreach (var (key, label, core) in Collections)
        {
            findings.Add(AnalyzeCollection(state, key, label, core));
        }

        findings.Add(AnalyzeWdac(state));
        findings.Add(AnalyzeSmartAppControl(state));
        return findings;
    }

    /// <summary>Is any application-control mechanism providing real, enforcing coverage?</summary>
    public static Finding AnalyzeAppLockerOverall(ApplicationControlState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        bool anyConfigured = state.AnyAppLockerConfigured;
        bool anyEnforcing = state.AnyAppLockerEnforcing && state.AppIdServiceRunning;
        bool wdacEnforcing = state.WdacEnforced;
        bool sacEnforcing = state.SmartAppControlState == 1;

        if (anyEnforcing || wdacEnforcing || sacEnforcing)
        {
            return Finding.Pass(
                "Application control is enforcing",
                "At least one application-control mechanism is actively blocking untrusted code " +
                $"(AppLocker enforcing: {(anyEnforcing ? "yes" : "no")}, WDAC/Code Integrity: " +
                $"{(wdacEnforcing ? "yes" : "no")}, Smart App Control: {(sacEnforcing ? "yes" : "no")}). " +
                "Only approved executables/installers/scripts are permitted to run, which is the strongest " +
                "single defense against untrusted-code execution (Essential 8 #1, CIS Windows L1).",
                Category);
        }

        if (anyConfigured)
        {
            return Finding.Warning(
                "Application control is configured but not enforcing",
                "AppLocker rules exist but no collection is actually blocking - every configured collection is in " +
                "AuditOnly mode, or the Application Identity service is not running to enforce them. Audit mode logs " +
                "what would be blocked but still allows everything to run, so it provides visibility without protection.",
                Category,
                remediation: "Move the audited AppLocker collections to enforced mode once the audit logs show the " +
                    "allowlist is complete, and ensure the Application Identity (AppIDSvc) service is running.");
        }

        return Finding.Warning(
            "No application allowlisting is in place",
            "No application-control mechanism is active: AppLocker has no configured rule collections, no WDAC/Code " +
            "Integrity policy is deployed, and Smart App Control is off. Any executable, installer or script the user " +
            "(or malware) launches is permitted to run. Application allowlisting is Essential 8 mitigation #1 and a " +
            "CIS Windows L1 control - it is the most effective defense against untrusted-code execution and living-off-" +
            "the-land binaries.",
            Category,
            remediation: "Deploy an application-control policy. For managed fleets, WDAC (kernel-enforced) is strongest; " +
                "AppLocker (Exe/Msi/Script collections in enforced mode) is a good baseline; Smart App Control suits " +
                "Windows 11 consumer devices.");
    }

    /// <summary>
    /// AppLocker enforcement is delivered by the Application Identity service (AppIDSvc). If it
    /// is not running, an otherwise-enforcing AppLocker policy silently allows everything.
    /// </summary>
    public static Finding AnalyzeAppIdService(ApplicationControlState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        // Only material when AppLocker is configured to enforce something.
        if (!state.AnyAppLockerEnforcing)
        {
            return Finding.Pass(
                "AppLocker enforcement service not required",
                "No AppLocker collection is in enforced mode, so the Application Identity (AppIDSvc) service state does " +
                "not currently gate any enforcement.",
                Category);
        }

        if (state.AppIdServiceRunning)
        {
            return Finding.Pass(
                "Application Identity service is running",
                "The Application Identity (AppIDSvc) service is running, so the enforced AppLocker rule collections are " +
                "actively evaluated and untrusted binaries are blocked.",
                Category);
        }

        return Finding.Critical(
            "AppLocker is enforced but the enforcement service is stopped",
            "One or more AppLocker collections are set to enforce, but the Application Identity (AppIDSvc) service is not " +
            "running. AppLocker rules are only applied while AppIDSvc is running, so with it stopped the allowlist is not " +
            "evaluated at all and every executable, installer and script is permitted - the policy provides a false sense " +
            "of protection. Attackers deliberately stop AppIDSvc to neutralize AppLocker.",
            Category,
            remediation: "Start and set the Application Identity service to automatic so AppLocker enforcement is applied.",
            fixCommand: "Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service -Name AppIDSvc");
    }

    /// <summary>Evaluate one AppLocker rule collection (Exe/Msi/Script/Dll/Appx).</summary>
    public static Finding AnalyzeCollection(ApplicationControlState state, string collectionKey, string label, bool core)
    {
        ArgumentNullException.ThrowIfNull(state);
        var mode = state.GetCollectionMode(collectionKey);

        if (mode == AppLockerEnforcementMode.Enabled)
        {
            return Finding.Pass(
                $"AppLocker enforces {label}",
                $"The AppLocker {collectionKey} rule collection is in enforced mode, so only rules-approved {label} are " +
                "permitted to run and everything else is blocked.",
                Category);
        }

        if (mode == AppLockerEnforcementMode.AuditOnly)
        {
            return Finding.Warning(
                $"AppLocker only audits {label}",
                $"The AppLocker {collectionKey} rule collection is in AuditOnly mode: it logs what would be blocked but " +
                $"still allows all {label} to run. Audit mode is a staging step, not protection.",
                Category,
                remediation: $"Once the audit logs confirm the allowlist for {label} is complete, switch the {collectionKey} " +
                    "collection to enforced mode.");
        }

        // NotConfigured
        var severity = core ? "core" : "supplementary";
        Finding finding = core
            ? Finding.Warning(
                $"AppLocker does not control {label}",
                $"The AppLocker {collectionKey} rule collection is not configured, so {label} are not allowlisted at all. " +
                $"This is a {severity} collection - leaving it unconfigured means untrusted {label} run freely.",
                Category,
                remediation: $"Define and enforce AppLocker {collectionKey} rules to allowlist {label}.")
            : Finding.Info(
                $"AppLocker does not control {label}",
                $"The AppLocker {collectionKey} rule collection is not configured, so {label} are not allowlisted. This is a " +
                $"{severity} collection (the Exe/Msi/Script collections carry most of the protection); configure it for " +
                "defense in depth.",
                Category,
                remediation: $"Optionally define AppLocker {collectionKey} rules for {label} once the core collections are enforced.");
        return finding;
    }

    /// <summary>WDAC / Code Integrity policy - the kernel-enforced, tamper-resistant allowlist.</summary>
    public static Finding AnalyzeWdac(ApplicationControlState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.WdacEnforced)
        {
            return Finding.Pass(
                "WDAC / Code Integrity policy is enforced",
                "A Windows Defender Application Control (Code Integrity) policy is deployed in enforced mode. WDAC is " +
                "kernel-enforced and harder to tamper with than AppLocker, giving the strongest untrusted-code protection.",
                Category);
        }

        if (state.WdacAuditOnly)
        {
            return Finding.Info(
                "WDAC / Code Integrity policy is in audit mode",
                "A WDAC (Code Integrity) policy is deployed but in audit mode - it logs violations without blocking. Move " +
                "it to enforced mode once the audit confirms the allowlist is complete.",
                Category,
                remediation: "Redeploy the WDAC policy without the audit-mode option so it enforces.");
        }

        return Finding.Info(
            "No WDAC / Code Integrity policy is deployed",
            "No Windows Defender Application Control (Code Integrity) policy is active. WDAC is the strongest, kernel-" +
            "enforced application-control option and is recommended for high-value or managed endpoints. Its absence is " +
            "informational when AppLocker or Smart App Control already provides coverage.",
            Category,
            remediation: "Consider deploying a WDAC policy for kernel-enforced application control on managed devices.");
    }

    /// <summary>Smart App Control - the Windows 11 reputation-based consumer allowlist.</summary>
    public static Finding AnalyzeSmartAppControl(ApplicationControlState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        switch (state.SmartAppControlState)
        {
            case 1:
                return Finding.Pass(
                    "Smart App Control is on",
                    "Smart App Control is enabled and enforcing, so Windows 11 blocks untrusted and potentially unwanted " +
                    "applications based on Microsoft's reputation and signing checks.",
                    Category);
            case 2:
                return Finding.Info(
                    "Smart App Control is in evaluation mode",
                    "Smart App Control is in evaluation mode: Windows is assessing whether it can protect this device " +
                    "without getting in the way, and will turn itself on or off automatically. It is not yet enforcing.",
                    Category);
            case 0:
                return Finding.Info(
                    "Smart App Control is off",
                    "Smart App Control is off. On Windows 11 it provides reputation-based blocking of untrusted apps, but " +
                    "once turned off it can only be re-enabled by a clean OS reinstall. Its absence is informational when " +
                    "AppLocker or WDAC already provides application control.",
                    Category,
                    remediation: "On Windows 11 consumer devices without AppLocker/WDAC, consider enabling Smart App Control " +
                        "(requires a reset to turn on once it has been off).");
            default:
                return Finding.Info(
                    "Smart App Control status unknown",
                    "Smart App Control state could not be determined (it is only present on Windows 11). No action is " +
                    "required if AppLocker or WDAC provides application control.",
                    Category);
        }
    }
}

/// <summary>AppLocker per-collection enforcement mode.</summary>
public enum AppLockerEnforcementMode
{
    /// <summary>The collection has no policy - untrusted files of this type run freely.</summary>
    NotConfigured = -1,

    /// <summary>AuditOnly (registry EnforcementMode = 0): logs but still allows.</summary>
    AuditOnly = 0,

    /// <summary>Enabled (registry EnforcementMode = 1): actually blocks.</summary>
    Enabled = 1,
}

/// <summary>
/// Raw, collector-supplied application-control state. Populated by the audit module's I/O layer
/// (reading AppLocker SrpV2 policy, the AppIDSvc service state, the CI/WDAC deployed-policy key,
/// and Smart App Control) and handed to <see cref="ApplicationControlAnalyzer"/> for a pure
/// decision. Defaults are the "nothing configured" posture so an unreadable value never invents
/// a control that is not present.
/// </summary>
public sealed record ApplicationControlState
{
    /// <summary>Per-collection AppLocker enforcement mode, keyed by collection name (Exe/Msi/Script/Dll/Appx).</summary>
    public IReadOnlyDictionary<string, AppLockerEnforcementMode> AppLockerCollections { get; init; }
        = new Dictionary<string, AppLockerEnforcementMode>();

    /// <summary>Whether the Application Identity (AppIDSvc) service is currently running.</summary>
    public bool AppIdServiceRunning { get; init; }

    /// <summary>Whether a WDAC/Code Integrity policy is deployed in enforced mode.</summary>
    public bool WdacEnforced { get; init; }

    /// <summary>Whether a WDAC/Code Integrity policy is deployed in audit-only mode.</summary>
    public bool WdacAuditOnly { get; init; }

    /// <summary>
    /// Smart App Control state: 0 = Off, 1 = On (enforcing), 2 = Evaluation, -1 = unknown/absent.
    /// Defaults to -1 so an absent value is reported as unknown, not a false Off/On.
    /// </summary>
    public int SmartAppControlState { get; init; } = -1;

    /// <summary>Enforcement mode for a named AppLocker collection (NotConfigured when absent).</summary>
    public AppLockerEnforcementMode GetCollectionMode(string collectionKey) =>
        AppLockerCollections.TryGetValue(collectionKey, out var mode) ? mode : AppLockerEnforcementMode.NotConfigured;

    /// <summary>Whether any AppLocker collection has a policy (audit or enforce).</summary>
    public bool AnyAppLockerConfigured =>
        AppLockerCollections.Values.Any(m => m != AppLockerEnforcementMode.NotConfigured);

    /// <summary>Whether any AppLocker collection is in enforced mode.</summary>
    public bool AnyAppLockerEnforcing =>
        AppLockerCollections.Values.Any(m => m == AppLockerEnforcementMode.Enabled);
}
