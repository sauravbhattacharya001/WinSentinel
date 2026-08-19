using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing risky <b>Windows optional features</b> on a single
/// machine. Windows ships a large catalogue of on-demand features (installable via
/// <c>Enable-WindowsOptionalFeature</c> / "Turn Windows features on or off"), several of
/// which materially expand the local attack surface or defeat other controls when left
/// enabled: the SMB 1.0/CIFS client and server (a wormable, deprecated protocol - EternalBlue
/// territory), the legacy PowerShell 2.0 engine (runs without Script Block Logging / AMSI, a
/// well-known logging bypass), and cleartext legacy network clients such as Telnet and TFTP.
///
/// <para>Every rule operates on a synthetic <see cref="OptionalFeaturesState"/> so it can be
/// unit tested directly, mirroring the established <see cref="WerExposureAnalyzer"/> /
/// <see cref="UacHardeningAnalyzer"/> pattern (collector owns I/O - it runs
/// <c>Get-WindowsOptionalFeature</c> - and the analyzer owns every decision). The checks read
/// only local feature state, so this module is single-machine and therefore FREE / OSS:
/// nothing multi-machine, nothing license-gated.</para>
/// </summary>
public static class OptionalFeaturesAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Optional Features";

    /// <summary>
    /// The risky optional features we evaluate, keyed by the exact DISM feature name reported
    /// by <c>Get-WindowsOptionalFeature</c>. Each entry carries a friendly label, the severity
    /// to raise when the feature is enabled, why it matters, and how to remove it.
    /// </summary>
    public sealed record RiskyFeature(
        string FeatureName,
        string Label,
        Severity SeverityWhenEnabled,
        string WhyItMatters,
        string Remediation);

    /// <summary>
    /// Source-of-truth list of the risky features this analyzer knows about. Names match the
    /// DISM <c>FeatureName</c> values on modern Windows client/server builds.
    /// </summary>
    public static readonly IReadOnlyList<RiskyFeature> KnownRiskyFeatures = new List<RiskyFeature>
    {
        new(
            "SMB1Protocol",
            "SMB 1.0/CIFS File Sharing Support",
            Severity.Critical,
            "SMBv1 is a deprecated, wormable file-sharing protocol (the vector for WannaCry / EternalBlue). " +
            "Microsoft removes it by default; if it is enabled it exposes the machine to well-known remote " +
            "code-execution and man-in-the-middle attacks.",
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"),
        new(
            "MicrosoftWindowsPowerShellV2",
            "Windows PowerShell 2.0 Engine",
            Severity.Warning,
            "The legacy PowerShell 2.0 engine runs without Script Block Logging, Module Logging or AMSI. " +
            "Attackers explicitly downgrade to it (powershell -Version 2) to execute code that modern logging " +
            "and anti-malware scanning would otherwise catch.",
            "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"),
        new(
            "TelnetClient",
            "Telnet Client",
            Severity.Warning,
            "The Telnet client speaks a cleartext protocol with no encryption or integrity. Its presence is a " +
            "legacy-tooling / living-off-the-land indicator and it can be abused to exfiltrate data or interact " +
            "with services over unencrypted channels.",
            "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart"),
        new(
            "TFTP",
            "TFTP Client",
            Severity.Warning,
            "TFTP is an unauthenticated, unencrypted file-transfer client frequently used in ingress-tool-transfer " +
            "attacks to pull payloads onto a host. It has no legitimate use on most endpoints.",
            "Disable-WindowsOptionalFeature -Online -FeatureName TFTP -NoRestart"),
    };

    /// <summary>
    /// Evaluate the collected optional-features state and return one finding per known risky
    /// feature (a Pass when it is disabled/absent, otherwise the feature's configured severity),
    /// plus a trailing Info when the collector could not enumerate features at all. Ordering is
    /// stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(OptionalFeaturesState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<Finding>();

        if (!state.EnumerationSucceeded)
        {
            findings.Add(Finding.Info(
                "Windows optional features could not be enumerated",
                "WinSentinel could not read the list of enabled Windows optional features (Get-WindowsOptionalFeature " +
                "returned no usable output). Risky features such as SMBv1 or the PowerShell 2.0 engine could not be " +
                "checked on this run.",
                Category,
                remediation: "Re-run the audit from an elevated PowerShell session; DISM feature queries require " +
                    "administrator rights."));
            return findings;
        }

        foreach (var feature in KnownRiskyFeatures)
        {
            findings.Add(AnalyzeFeature(feature, state));
        }

        return findings;
    }

    /// <summary>
    /// Evaluate a single risky feature against the collected state: enabled features raise the
    /// feature's configured severity with remediation; disabled/absent features pass.
    /// </summary>
    public static Finding AnalyzeFeature(RiskyFeature feature, OptionalFeaturesState state)
    {
        ArgumentNullException.ThrowIfNull(feature);
        ArgumentNullException.ThrowIfNull(state);

        var enabled = state.EnabledFeatures.Contains(feature.FeatureName, StringComparer.OrdinalIgnoreCase);

        if (!enabled)
        {
            return Finding.Pass(
                $"{feature.Label} is not enabled",
                $"The '{feature.Label}' Windows optional feature ({feature.FeatureName}) is disabled or not present, " +
                "so it does not contribute to the local attack surface.",
                Category);
        }

        return new Finding
        {
            Title = $"{feature.Label} is enabled",
            Description = $"The '{feature.Label}' Windows optional feature ({feature.FeatureName}) is enabled. " +
                feature.WhyItMatters,
            Severity = feature.SeverityWhenEnabled,
            Category = Category,
            Remediation = feature.Remediation,
            FixCommand = feature.Remediation,
        };
    }
}

/// <summary>
/// Raw, collector-supplied Windows optional-features state. Populated by the audit module's
/// I/O layer (running <c>Get-WindowsOptionalFeature -Online</c> and collecting the names of
/// features whose state is Enabled) and handed to <see cref="OptionalFeaturesAnalyzer"/> for a
/// pure decision. Defaults are chosen so a failed enumeration never false-positives: an empty
/// state with <see cref="EnumerationSucceeded"/> = false yields only an informational finding.
/// </summary>
public sealed record OptionalFeaturesState
{
    /// <summary>Whether the collector successfully enumerated optional features at all.</summary>
    public bool EnumerationSucceeded { get; init; }

    /// <summary>DISM FeatureName values whose state is Enabled on this machine.</summary>
    public IReadOnlyCollection<string> EnabledFeatures { get; init; } = Array.Empty<string>();
}
