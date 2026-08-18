using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for Windows Delivery Optimization (DO) download-source
/// posture on a single machine. Delivery Optimization is the peer-to-peer
/// distribution layer Windows uses to fetch Windows Update, Store app, and (on
/// some SKUs) Defender-definition content. Its <c>DODownloadMode</c> knob decides
/// where that content may come from:
///
///   * <b>0 - HTTP only</b> - no peering at all; content comes only from Microsoft
///     CDN / WSUS. The most conservative source posture.
///   * <b>1 - LAN peering</b> - peers on the same local subnet may supply content.
///     Reasonable inside a trusted LAN.
///   * <b>2 - Group peering</b> - peering across a configured group (e.g. same AD
///     site / GroupID), which can span subnets.
///   * <b>3 - Internet peering</b> - content may be pulled from, and served to,
///     arbitrary peers across the public Internet. This turns the machine into a
///     content peer on the open Internet: it opens inbound peer traffic, advertises
///     the machine to Microsoft's peering service, and accepts update payloads from
///     untrusted third parties (integrity is hash-verified, but it is still an
///     Internet-facing exposure and a bandwidth/data-egress surface most single
///     machines do not want).
///   * <b>99 - Simple / bypass</b> - DO peering disabled, direct download only
///     (functionally similar to HTTP-only for source-exposure purposes).
///   * <b>100 - Bypass</b> - DO bypassed entirely (BITS direct).
///
/// From a single-machine hardening standpoint the finding of interest is
/// <b>Internet peering (mode 3)</b>: it is the only mode that exposes the machine to
/// peers outside the local network. LAN/group peering is flagged as informational
/// (subnet-local trust), and HTTP-only / bypass modes pass.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads only local
/// registry config/policy state. Nothing multi-machine, nothing license-gated. All
/// rules operate on a synthetic <see cref="DeliveryOptimizationState"/> so they can
/// be unit tested directly, mirroring the established <see cref="SmartScreenAnalyzer"/>
/// / <see cref="WindowsScriptHostAnalyzer"/> pattern (collector owns I/O, analyzer
/// owns decisions).
/// </summary>
public static class DeliveryOptimizationAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Delivery Optimization";

    /// <summary>Windows default when neither policy nor config pins a value (mode 1, LAN peering).</summary>
    public const int DefaultDownloadMode = 1;

    /// <summary>
    /// Evaluate the collected Delivery Optimization state and return one finding for
    /// the effective download mode. Policy (HKLM Policies) wins over config
    /// (HKLM CurrentVersion) when both are present; absence of both maps to the
    /// Windows default of LAN peering (mode 1). Ordering is deterministic.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(DeliveryOptimizationState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeDownloadMode(state),
        };
    }

    /// <summary>
    /// The effective DO download mode. Policy value (if present) takes precedence
    /// over the config value; if neither is set, Windows behaves as LAN peering
    /// (mode 1). Internet peering (3) is the exposure concern.
    /// </summary>
    public static Finding AnalyzeDownloadMode(DeliveryOptimizationState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var effective = state.PolicyDownloadMode ?? state.ConfigDownloadMode ?? DefaultDownloadMode;
        var source = state.PolicyDownloadMode.HasValue ? "policy"
            : state.ConfigDownloadMode.HasValue ? "config"
            : "Windows default";

        const string fixCommand =
            "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization' -Force | Out-Null; " +
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization' -Name DODownloadMode -Type DWord -Value 0";
        const string remediation =
            "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\\DODownloadMode = 0 (DWORD, HTTP only) " +
            "or 1 (LAN peering) so the machine no longer exchanges update content with peers on the public Internet.";

        return effective switch
        {
            3 => Finding.Warning(
                "Delivery Optimization uses Internet peering",
                $"The effective Delivery Optimization download mode is 3 (Internet peering), set via {source}. " +
                "The machine may pull update/Store content from - and serve it to - arbitrary peers across the " +
                "public Internet. This opens inbound peer traffic, advertises the machine to Microsoft's peering " +
                "service, and accepts payloads from untrusted third parties. Restricting Delivery Optimization to " +
                "HTTP-only (0) or LAN peering (1) removes that Internet-facing exposure.",
                Category,
                remediation: remediation,
                fixCommand: fixCommand),

            2 => Finding.Info(
                "Delivery Optimization uses group peering",
                $"The effective Delivery Optimization download mode is 2 (group peering), set via {source}. Peering " +
                "spans a configured group (e.g. AD site / GroupID) which can cross subnets, but content is not " +
                "exchanged with arbitrary Internet peers. On a standalone machine HTTP-only (0) or LAN peering (1) " +
                "is a tighter source posture.",
                Category,
                remediation: remediation,
                fixCommand: fixCommand),

            1 => Finding.Info(
                "Delivery Optimization uses LAN peering",
                $"The effective Delivery Optimization download mode is 1 (LAN peering), set via {source}. Update/Store " +
                "content may be exchanged with peers on the same local subnet only - not the public Internet. This is " +
                "the Windows default and is reasonable inside a trusted LAN; set mode 0 (HTTP only) if the machine " +
                "should never peer at all.",
                Category,
                remediation:
                    "Optional: set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\\DODownloadMode = 0 " +
                    "(DWORD, HTTP only) to disable all peering, including LAN peering.",
                fixCommand: fixCommand),

            0 => Finding.Pass(
                "Delivery Optimization is HTTP-only (no peering)",
                $"The effective Delivery Optimization download mode is 0 (HTTP only), set via {source}. Update/Store " +
                "content is fetched only from Microsoft's CDN / WSUS with no peer exchange, so the machine is not a " +
                "Delivery Optimization content peer.",
                Category),

            99 or 100 => Finding.Pass(
                "Delivery Optimization peering is disabled",
                $"The effective Delivery Optimization download mode is {effective} (peering bypassed / direct download), " +
                $"set via {source}. Content is fetched directly with no peer exchange, so the machine is not a Delivery " +
                "Optimization content peer.",
                Category),

            _ => Finding.Info(
                "Delivery Optimization download mode is unrecognized",
                $"The effective Delivery Optimization download mode is {effective} (set via {source}), which is not a " +
                "recognized DODownloadMode value. Set it to 0 (HTTP only) or 1 (LAN peering) for a known, tight source " +
                "posture.",
                Category,
                remediation: remediation,
                fixCommand: fixCommand),
        };
    }
}

/// <summary>
/// Raw, collector-supplied Delivery Optimization state. Populated by the audit
/// module's I/O layer and handed to <see cref="DeliveryOptimizationAnalyzer"/> for a
/// pure decision. Null fields mean "value absent / not readable"; the analyzer
/// treats absence of both values as the Windows default (LAN peering, mode 1) so a
/// missing key is never silently reported as fully hardened.
/// </summary>
public sealed record DeliveryOptimizationState
{
    /// <summary>
    /// Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode (DWORD). The
    /// managed/policy value; when present it overrides the config value.
    /// </summary>
    public int? PolicyDownloadMode { get; init; }

    /// <summary>
    /// Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\DODownloadMode
    /// (DWORD). The unmanaged config value; used only when no policy value is set.
    /// </summary>
    public int? ConfigDownloadMode { get; init; }
}
