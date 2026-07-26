using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing Windows Recall posture on a single machine.
///
/// Windows Recall periodically captures full-screen snapshots and builds a
/// searchable, on-disk database ("screenshots of everything you did"). On a
/// machine that handles sensitive data this is a local data-exposure risk: the
/// snapshot store can capture passwords, tokens, private messages and documents,
/// and anyone with access to the profile can browse it. The controls below are
/// all local registry policies that decide whether Recall can run and store
/// snapshots at all:
///
///   * DisableAIDataAnalysis (policy) - 1 turns Recall snapshotting OFF via the
///     Windows AI policy. This is the primary kill switch.
///   * AllowRecallEnablement (policy) - 0 prevents Recall from ever being
///     enabled. Belt-and-suspenders alongside DisableAIDataAnalysis.
///   * Snapshots present - whether a snapshot store already exists on disk
///     (i.e. Recall has been capturing), which is a data-at-rest exposure even
///     if it is later disabled.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// policy/registry state only. Nothing multi-machine, nothing license-gated. All
/// rules operate on a synthetic <see cref="WindowsRecallState"/> so they can be
/// unit tested directly, mirroring the established
/// <see cref="LsaHardeningAnalyzer"/> analyzer pattern (collector owns I/O,
/// analyzer owns decisions).
/// </summary>
public static class WindowsRecallAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Privacy";

    /// <summary>
    /// Evaluate the collected Recall state and return one finding per check.
    /// Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(WindowsRecallState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var findings = new List<Finding>
        {
            AnalyzeDisableAiDataAnalysis(state),
            AnalyzeAllowRecallEnablement(state),
            AnalyzeSnapshotStore(state),
        };
        return findings;
    }

    /// <summary>
    /// Recall snapshotting must be disabled by policy (DisableAIDataAnalysis = 1).
    /// Absent (null) means the policy is not set, so Recall may run where the
    /// hardware/OS supports it - a Warning on a sensitive machine.
    /// </summary>
    public static Finding AnalyzeDisableAiDataAnalysis(WindowsRecallState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.DisableAiDataAnalysis == 1)
        {
            return Finding.Pass(
                "Windows Recall snapshotting is disabled by policy",
                "DisableAIDataAnalysis is set to 1, so Windows Recall does not capture " +
                "or store screen snapshots on this machine.",
                Category);
        }

        return Finding.Warning(
            "Windows Recall snapshotting is not disabled by policy",
            "The DisableAIDataAnalysis policy is not enabled. On supported hardware " +
            "Windows Recall can capture periodic full-screen snapshots into a local, " +
            "searchable database that may include passwords, tokens and private data.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAnalysis = 1 (DWORD) " +
                         "to turn Recall snapshotting off machine-wide.",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI' -Name DisableAIDataAnalysis -Type DWord -Value 1");
    }

    /// <summary>
    /// AllowRecallEnablement = 0 prevents Recall from being enabled at all. A
    /// value of 1 (explicitly allowed) is worth flagging on a hardened machine;
    /// absent is neutral (the DisableAIDataAnalysis check covers the risk).
    /// </summary>
    public static Finding AnalyzeAllowRecallEnablement(WindowsRecallState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.AllowRecallEnablement == 0)
        {
            return Finding.Pass(
                "Windows Recall is blocked from being enabled",
                "AllowRecallEnablement is 0, so Recall cannot be turned on even by a " +
                "local user.",
                Category);
        }

        if (state.AllowRecallEnablement == 1)
        {
            return Finding.Warning(
                "Windows Recall is explicitly allowed to be enabled",
                "AllowRecallEnablement is set to 1, explicitly permitting Recall to be " +
                "turned on. On machines handling sensitive data, blocking enablement " +
                "avoids the snapshot database entirely.",
                Category,
                remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI\\AllowRecallEnablement = 0 (DWORD) " +
                             "to prevent Recall from being enabled.",
                fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI' -Force | Out-Null; " +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI' -Name AllowRecallEnablement -Type DWord -Value 0");
        }

        return Finding.Pass(
            "Windows Recall enablement policy is at default",
            "AllowRecallEnablement is not explicitly set; Recall exposure is governed " +
            "by the DisableAIDataAnalysis policy.",
            Category);
    }

    /// <summary>
    /// A Recall snapshot store already present on disk is a data-at-rest
    /// exposure, even if snapshotting is subsequently disabled.
    /// </summary>
    public static Finding AnalyzeSnapshotStore(WindowsRecallState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.SnapshotStorePresent)
        {
            return Finding.Pass(
                "No Windows Recall snapshot store on disk",
                "No Recall snapshot database was found, so there is no captured " +
                "screen-content data at rest on this machine.",
                Category);
        }

        return Finding.Warning(
            "Windows Recall snapshot store present on disk",
            "A Recall snapshot database exists on disk. It may contain captured " +
            "screen content - including passwords, tokens and private data - that is " +
            "readable by anyone with access to the profile, regardless of whether " +
            "Recall is currently enabled.",
            Category,
            remediation: "Disable Recall (DisableAIDataAnalysis = 1), then delete the snapshot store under " +
                         "%LOCALAPPDATA%\\CoreAIPlatform.* after confirming it is no longer needed.");
    }
}

/// <summary>
/// Raw, collector-supplied Windows Recall policy/registry state. Populated by the
/// audit module's I/O layer and handed to <see cref="WindowsRecallAnalyzer"/> for
/// a pure decision. Null numeric fields mean "policy absent / not readable"; the
/// analyzer treats absence per the semantics documented on each rule.
/// </summary>
public sealed record WindowsRecallState
{
    /// <summary>
    /// HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis
    /// (DWORD). 1 = Recall snapshotting disabled. Null = policy unset.
    /// </summary>
    public int? DisableAiDataAnalysis { get; init; }

    /// <summary>
    /// HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\AllowRecallEnablement
    /// (DWORD). 0 = Recall cannot be enabled; 1 = explicitly allowed; null = default.
    /// </summary>
    public int? AllowRecallEnablement { get; init; }

    /// <summary>Whether a Recall snapshot store already exists on disk.</summary>
    public bool SnapshotStorePresent { get; init; }
}
