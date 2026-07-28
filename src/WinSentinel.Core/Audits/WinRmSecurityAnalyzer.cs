using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for hardening the local Windows Remote Management
/// (WinRM / WS-Man) stack on a single machine. WinRM is the transport behind
/// PowerShell Remoting, Enter-PSSession, and much of modern remote admin; a
/// mis-hardened listener is a classic lateral-movement and credential-theft
/// vector. The checks here mirror the CIS Windows L1 "Windows Remote Management"
/// section and split cleanly into the WinRM <b>service</b> (the machine listening
/// for inbound sessions) and the WinRM <b>client</b> (this machine dialling out):
///
///   Service side (inbound):
///   * ServiceAllowUnencrypted - Service\AllowUnencrypted. When on, the listener
///                               accepts unencrypted WS-Man traffic - session
///                               contents (and Basic creds) cross the wire in clear.
///   * ServiceAllowBasic       - Service\AllowBasic. Basic auth ships the password
///                               (base64, not encrypted) on every request.
///   * ServiceAllowDigest      - Service auth Digest. Legacy, weaker than Negotiate/Kerberos.
///   * ServiceCbtHardeningLevel - Service\CbtHardeningLevel. Channel-binding-token
///                               enforcement; "Strict" defeats HTTPS auth relay.
///
///   Client side (outbound):
///   * ClientAllowUnencrypted  - Client\AllowUnencrypted. This machine will send
///                               unencrypted WS-Man if a peer asks.
///   * ClientAllowBasic        - Client\AllowBasic. This machine will send Basic creds.
///   * ClientAllowDigest       - Client Digest auth outbound.
///   * ClientTrustedHosts      - Client\TrustedHosts. A wildcard ("*") disables the
///                               host-identity check, so the client will hand
///                               credentials to ANY responder - a relay/impersonation gift.
///
/// Everything here reads only local WSMan / policy state, so it is single-machine
/// and therefore FREE / OSS: nothing multi-machine, nothing license-gated. All
/// rules operate on a synthetic <see cref="WinRmState"/> so they can be unit
/// tested directly, mirroring the established <see cref="ScreenLockAnalyzer"/>
/// pattern (collector owns I/O, the analyzer owns decisions).
/// </summary>
public static class WinRmSecurityAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Remote Management";

    /// <summary>
    /// Evaluate the collected WinRM state and return one finding per check (a Pass
    /// when the setting is already safe, otherwise a Warning/Critical). When WinRM
    /// is not even running, a single informational finding is returned instead -
    /// there is no inbound attack surface to harden. Ordering is stable and
    /// deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<Finding>();

        if (!state.ServiceRunning)
        {
            findings.Add(Finding.Info(
                "WinRM service is not running",
                "The Windows Remote Management (WS-Management) service is stopped, so there is " +
                "no inbound remote-management listener to harden. Client-side settings are still " +
                "evaluated because this machine can still dial out over WinRM.",
                Category));
        }
        else
        {
            findings.Add(AnalyzeServiceUnencrypted(state));
            findings.Add(AnalyzeServiceBasic(state));
            findings.Add(AnalyzeServiceDigest(state));
            findings.Add(AnalyzeCbtHardening(state));
        }

        findings.Add(AnalyzeClientUnencrypted(state));
        findings.Add(AnalyzeClientBasic(state));
        findings.Add(AnalyzeClientDigest(state));
        findings.Add(AnalyzeTrustedHosts(state));

        return findings;
    }

    /// <summary>Service must not accept unencrypted WS-Man traffic.</summary>
    public static Finding AnalyzeServiceUnencrypted(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ServiceAllowUnencrypted)
        {
            return Finding.Critical(
                "WinRM service accepts unencrypted traffic",
                "Service AllowUnencrypted is enabled, so the WinRM listener accepts WS-Management " +
                "traffic with no transport encryption. Session contents - and any Basic-auth " +
                "credentials - cross the network in clear text where they can be sniffed or relayed.",
                Category,
                remediation: "Disable unencrypted WinRM service traffic.",
                fixCommand: "Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false");
        }

        return Finding.Pass(
            "WinRM service requires encrypted traffic",
            "Service AllowUnencrypted is off, so the WinRM listener rejects unencrypted WS-Management traffic.",
            Category);
    }

    /// <summary>Service should not allow Basic authentication.</summary>
    public static Finding AnalyzeServiceBasic(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ServiceAllowBasic)
        {
            return Finding.Warning(
                "WinRM service allows Basic authentication",
                "Service AllowBasic is enabled. Basic auth transmits the username and password " +
                "base64-encoded (not encrypted) on every request; combined with unencrypted transport " +
                "it hands credentials to anyone on the path.",
                Category,
                remediation: "Disable Basic auth on the WinRM service; use Kerberos/Negotiate instead.",
                fixCommand: "Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Basic -Value $false");
        }

        return Finding.Pass(
            "WinRM service disallows Basic authentication",
            "Service Basic auth is off; the listener relies on stronger Negotiate/Kerberos authentication.",
            Category);
    }

    /// <summary>Service should not allow legacy Digest authentication.</summary>
    public static Finding AnalyzeServiceDigest(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ServiceAllowDigest)
        {
            return Finding.Warning(
                "WinRM service allows Digest authentication",
                "Service Digest auth is enabled. Digest is a legacy challenge-response scheme weaker " +
                "than Negotiate/Kerberos and should be turned off on modern deployments.",
                Category,
                remediation: "Disable Digest auth on the WinRM service.",
                fixCommand: "Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Digest -Value $false");
        }

        return Finding.Pass(
            "WinRM service disallows Digest authentication",
            "Service Digest auth is off.",
            Category);
    }

    /// <summary>Channel-binding-token hardening should be Strict to defeat auth relay over HTTPS.</summary>
    public static Finding AnalyzeCbtHardening(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var level = (state.ServiceCbtHardeningLevel ?? string.Empty).Trim();
        if (string.Equals(level, "Strict", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Pass(
                "WinRM channel-binding-token hardening is Strict",
                "Service CbtHardeningLevel is Strict, so channel binding is enforced and " +
                "authentication cannot be relayed across a terminated TLS channel.",
                Category);
        }

        var shown = level.Length == 0 ? "unset" : level;
        return Finding.Warning(
            "WinRM channel-binding-token hardening is not Strict",
            $"Service CbtHardeningLevel is '{shown}'. Without Strict channel binding, an attacker who " +
            "terminates TLS in the middle can relay the authentication to the real listener.",
            Category,
            remediation: "Set the WinRM service CbtHardeningLevel to Strict.",
            fixCommand: "Set-Item -Path WSMan:\\localhost\\Service\\Auth\\CbtHardeningLevel -Value Strict");
    }

    /// <summary>Client must not send unencrypted WS-Man traffic.</summary>
    public static Finding AnalyzeClientUnencrypted(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ClientAllowUnencrypted)
        {
            return Finding.Critical(
                "WinRM client sends unencrypted traffic",
                "Client AllowUnencrypted is enabled, so this machine will send WS-Management traffic " +
                "with no transport encryption when a peer requests it, exposing session data and credentials.",
                Category,
                remediation: "Disable unencrypted WinRM client traffic.",
                fixCommand: "Set-Item -Path WSMan:\\localhost\\Client\\AllowUnencrypted -Value $false");
        }

        return Finding.Pass(
            "WinRM client requires encrypted traffic",
            "Client AllowUnencrypted is off, so this machine refuses to send unencrypted WS-Management traffic.",
            Category);
    }

    /// <summary>Client should not send Basic-auth credentials.</summary>
    public static Finding AnalyzeClientBasic(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ClientAllowBasic)
        {
            return Finding.Warning(
                "WinRM client allows Basic authentication",
                "Client AllowBasic is enabled, so this machine will send credentials using Basic auth " +
                "(base64, not encrypted) to remote listeners.",
                Category,
                remediation: "Disable Basic auth on the WinRM client.",
                fixCommand: "Set-Item -Path WSMan:\\localhost\\Client\\Auth\\Basic -Value $false");
        }

        return Finding.Pass(
            "WinRM client disallows Basic authentication",
            "Client Basic auth is off.",
            Category);
    }

    /// <summary>Client should not send legacy Digest-auth credentials.</summary>
    public static Finding AnalyzeClientDigest(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ClientAllowDigest)
        {
            return Finding.Warning(
                "WinRM client allows Digest authentication",
                "Client Digest auth is enabled, a legacy scheme weaker than Negotiate/Kerberos.",
                Category,
                remediation: "Disable Digest auth on the WinRM client.",
                fixCommand: "Set-Item -Path WSMan:\\localhost\\Client\\Auth\\Digest -Value $false");
        }

        return Finding.Pass(
            "WinRM client disallows Digest authentication",
            "Client Digest auth is off.",
            Category);
    }

    /// <summary>Client TrustedHosts must not be a blanket wildcard.</summary>
    public static Finding AnalyzeTrustedHosts(WinRmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var trusted = (state.ClientTrustedHosts ?? string.Empty).Trim();

        if (trusted.Length == 0)
        {
            return Finding.Pass(
                "WinRM client TrustedHosts is empty",
                "Client TrustedHosts is not set, so non-Kerberos connections are not blindly trusted.",
                Category);
        }

        // A "*" entry anywhere in the comma/space separated list trusts every host.
        var entries = trusted.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries);
        if (entries.Any(e => e.Trim() == "*"))
        {
            return Finding.Critical(
                "WinRM client trusts all hosts (TrustedHosts = *)",
                "Client TrustedHosts contains a wildcard '*', so this machine will send credentials to " +
                "ANY responder without verifying its identity. An attacker who redirects or spoofs a host " +
                "can harvest or relay those credentials.",
                Category,
                remediation: "Replace the '*' wildcard with an explicit, minimal list of trusted host names.",
                fixCommand: "Set-Item -Path WSMan:\\localhost\\Client\\TrustedHosts -Value '<explicit-host-list>' -Force");
        }

        return Finding.Pass(
            "WinRM client TrustedHosts is an explicit list",
            $"Client TrustedHosts is scoped to specific hosts ('{trusted}') rather than a wildcard.",
            Category);
    }
}

/// <summary>
/// Raw, collector-supplied WinRM (WS-Management) client/service state. Populated
/// by the audit module's I/O layer (reading the WSMan: PowerShell drive and
/// policy registry) and handed to <see cref="WinRmSecurityAnalyzer"/> for a pure
/// decision. Boolean flags default to <c>false</c> (the safer value) so an
/// unreadable setting is not falsely reported as insecure; the collector is
/// responsible for surfacing genuine "enabled" states.
/// </summary>
public sealed record WinRmState
{
    /// <summary>Whether the WinRM (WS-Management) service is running - i.e. there is an inbound listener.</summary>
    public bool ServiceRunning { get; init; }

    /// <summary>WSMan:\localhost\Service\AllowUnencrypted.</summary>
    public bool ServiceAllowUnencrypted { get; init; }

    /// <summary>WSMan:\localhost\Service\Auth\Basic.</summary>
    public bool ServiceAllowBasic { get; init; }

    /// <summary>WSMan:\localhost\Service\Auth\Digest.</summary>
    public bool ServiceAllowDigest { get; init; }

    /// <summary>WSMan:\localhost\Service\Auth\CbtHardeningLevel (None/Relaxed/Strict). Null = unset.</summary>
    public string? ServiceCbtHardeningLevel { get; init; }

    /// <summary>WSMan:\localhost\Client\AllowUnencrypted.</summary>
    public bool ClientAllowUnencrypted { get; init; }

    /// <summary>WSMan:\localhost\Client\Auth\Basic.</summary>
    public bool ClientAllowBasic { get; init; }

    /// <summary>WSMan:\localhost\Client\Auth\Digest.</summary>
    public bool ClientAllowDigest { get; init; }

    /// <summary>WSMan:\localhost\Client\TrustedHosts. "*" = trust everyone; empty = none.</summary>
    public string? ClientTrustedHosts { get; init; }
}
