using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing Remote Desktop (RDP) hardening on a single machine.
/// RDP is one of the most-attacked Windows entry points: an exposed, weakly-configured
/// Remote Desktop listener is a standard ransomware/lateral-movement foothold. The checks
/// here evaluate the local RDP posture that matters most for a single host:
///
///   * RDP enabled           - whether inbound Remote Desktop is turned on at all
///                             (fDenyTSConnections = 0 means connections are allowed).
///                             Surfaced as Info when on, Pass when off.
///   * NLA required          - Network Level Authentication (UserAuthentication = 1) forces
///                             the client to authenticate BEFORE a full session is created,
///                             blocking a large class of pre-auth attacks. Off is a Warning.
///   * Min encryption level  - MinEncryptionLevel: 3 = High (128-bit), 4 = FIPS. 1 (Low) or
///                             2 (Client Compatible) allow weak/downgraded encryption and are
///                             a Warning.
///   * Non-default port      - RDP on the default port 3389 is trivially discoverable by
///                             internet-wide scanners. Not a real security control on its
///                             own, so this is Info only (defense-in-depth note).
///   * Security layer        - SecurityLayer = 2 negotiates TLS; 0 (RDP Security Layer) is
///                             legacy and weak. Anything other than 2 is a Warning.
///
/// <para>The checks read only local Terminal Server policy/registry state
/// (<c>HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server</c> and the RDP-Tcp WinStation),
/// so this module is single-machine and therefore FREE / OSS: nothing multi-machine, nothing
/// license-gated. Every rule operates on a synthetic <see cref="RdpHardeningState"/> so it can
/// be unit tested directly, mirroring the established <see cref="WerExposureAnalyzer"/> split
/// (collector owns I/O, analyzer owns decisions).</para>
/// </summary>
public static class RdpHardeningAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Remote Desktop";

    /// <summary>The well-known default RDP listener port.</summary>
    public const int DefaultRdpPort = 3389;

    /// <summary>
    /// Evaluate the collected RDP hardening state and return one finding per check (a Pass when
    /// the setting is already safe, otherwise Info/Warning). Ordering is stable and
    /// deterministic for diffable reports. When RDP is disabled the remaining checks are still
    /// reported (as informational context) so the posture is fully explicit.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(RdpHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeRdpEnabled(state),
            AnalyzeNla(state),
            AnalyzeEncryptionLevel(state),
            AnalyzeSecurityLayer(state),
            AnalyzePort(state),
        };
    }

    /// <summary>
    /// Whether inbound Remote Desktop is enabled. Disabled (fDenyTSConnections = 1) is the
    /// safest posture and reported as Pass; enabled is Info (it is a legitimate feature, but
    /// its exposure should be explicit and governed by the hardening checks below).
    /// </summary>
    public static Finding AnalyzeRdpEnabled(RdpHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.RdpEnabled)
        {
            return Finding.Pass(
                "Remote Desktop is disabled",
                "Inbound Remote Desktop is turned off (fDenyTSConnections = 1), so this machine does not expose an RDP " +
                "listener - removing one of the most commonly attacked remote-access entry points on Windows.",
                Category);
        }

        return Finding.Info(
            "Remote Desktop is enabled",
            "Inbound Remote Desktop is enabled (fDenyTSConnections = 0). RDP is a legitimate remote-access feature, but " +
            "an exposed listener is a standard ransomware / lateral-movement foothold, so ensure Network Level " +
            "Authentication, strong encryption and network exposure are all locked down (see the checks below).",
            Category,
            remediation: "If Remote Desktop is not needed on this machine, disable it (set fDenyTSConnections = 1). If it " +
                "is needed, keep NLA on, require High/FIPS encryption, and restrict access at the firewall / VPN.");
    }

    /// <summary>
    /// Network Level Authentication (UserAuthentication = 1) forces authentication before a
    /// session is established, blocking pre-auth attacks. Off is a Warning (only meaningful
    /// while RDP is enabled, but flagged either way so the setting is explicit).
    /// </summary>
    public static Finding AnalyzeNla(RdpHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.NlaRequired)
        {
            return Finding.Pass(
                "RDP requires Network Level Authentication",
                "Remote Desktop requires Network Level Authentication (UserAuthentication = 1), so a client must " +
                "authenticate before a full session is created. This blocks a large class of pre-authentication attacks " +
                "against the RDP stack.",
                Category);
        }

        return Finding.Warning(
            "RDP does not require Network Level Authentication",
            "Remote Desktop is not requiring Network Level Authentication (UserAuthentication != 1). Without NLA a client " +
            "can reach the full RDP session stack before authenticating, exposing more attack surface to unauthenticated " +
            "attackers and enabling pre-auth exploitation and easier credential attacks.",
            Category,
            remediation: "Require NLA for Remote Desktop (UserAuthentication = 1).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord");
    }

    /// <summary>
    /// Minimum RDP encryption level. 3 = High (128-bit) or 4 = FIPS are acceptable; 1 (Low)
    /// and 2 (Client Compatible) permit weak/downgraded encryption and are a Warning.
    /// </summary>
    public static Finding AnalyzeEncryptionLevel(RdpHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.MinEncryptionLevel >= 3)
        {
            return Finding.Pass(
                "RDP enforces strong encryption",
                $"Remote Desktop requires a strong minimum encryption level (MinEncryptionLevel = {state.MinEncryptionLevel}, " +
                "High or FIPS), so session traffic cannot be negotiated down to weak ciphers.",
                Category);
        }

        return Finding.Warning(
            "RDP allows weak encryption",
            $"Remote Desktop's minimum encryption level is set to {state.MinEncryptionLevel} " +
            "(Low or Client-Compatible), which permits weak or downgraded encryption of the session. An attacker on the " +
            "network path could more easily intercept or tamper with RDP traffic.",
            Category,
            remediation: "Set the minimum RDP encryption level to High (3) or FIPS (4).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name MinEncryptionLevel -Value 3 -Type DWord");
    }

    /// <summary>
    /// RDP security layer. 2 = negotiate TLS (secure); 0 = legacy RDP Security Layer, 1 =
    /// negotiate. Anything other than 2 is a Warning (TLS not enforced).
    /// </summary>
    public static Finding AnalyzeSecurityLayer(RdpHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.SecurityLayer == 2)
        {
            return Finding.Pass(
                "RDP uses the TLS security layer",
                "Remote Desktop is configured to use the TLS security layer (SecurityLayer = 2), so the RDP handshake is " +
                "protected by TLS rather than the legacy RDP Security Layer.",
                Category);
        }

        return Finding.Warning(
            "RDP does not enforce the TLS security layer",
            $"Remote Desktop's security layer is set to {state.SecurityLayer} rather than 2 (TLS). The legacy RDP Security " +
            "Layer does not provide server authentication and is vulnerable to man-in-the-middle attacks, so the RDP " +
            "handshake is not fully protected.",
            Category,
            remediation: "Set the RDP security layer to TLS (SecurityLayer = 2).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name SecurityLayer -Value 2 -Type DWord");
    }

    /// <summary>
    /// Whether RDP is on the default port 3389. Not a real security control on its own, so
    /// this is Info: on the default port it is trivially discoverable by internet-wide
    /// scanners; on a non-default port it is a minor defense-in-depth win.
    /// </summary>
    public static Finding AnalyzePort(RdpHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.PortNumber != DefaultRdpPort)
        {
            return Finding.Pass(
                "RDP is not on the default port",
                $"Remote Desktop is listening on a non-default port ({state.PortNumber}) rather than 3389. This is a minor " +
                "defense-in-depth measure that reduces trivial discovery by internet-wide port scanners (it is not a " +
                "substitute for NLA, strong encryption and firewall restrictions).",
                Category);
        }

        return Finding.Info(
            "RDP is on the default port 3389",
            "Remote Desktop is listening on the default port 3389. Default-port listeners are trivially discovered by " +
            "internet-wide scanners that constantly probe for exposed RDP. Changing the port is only obscurity, not a " +
            "control - the real protections are NLA, strong encryption and restricting access at the firewall / VPN.",
            Category,
            remediation: "Rely primarily on NLA, strong encryption and firewall/VPN restrictions; optionally move RDP off " +
                "3389 as a minor defense-in-depth measure.");
    }
}

/// <summary>
/// Raw, collector-supplied Remote Desktop (RDP) hardening state. Populated by the audit
/// module's I/O layer (reading
/// <c>HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server</c> and its
/// <c>WinStations\RDP-Tcp</c> subkey) and handed to <see cref="RdpHardeningAnalyzer"/> for a
/// pure decision. Defaults are chosen so an unreadable value never false-positives the
/// dangerous posture: RDP defaults to disabled, NLA defaults to required, encryption defaults
/// to High, the security layer defaults to TLS, and the port defaults to 3389.
/// </summary>
public sealed record RdpHardeningState
{
    /// <summary>Whether inbound RDP is enabled (fDenyTSConnections = 0). Secure default <c>false</c> (RDP off).</summary>
    public bool RdpEnabled { get; init; }

    /// <summary>Whether Network Level Authentication is required (UserAuthentication = 1). Secure default <c>true</c>.</summary>
    public bool NlaRequired { get; init; } = true;

    /// <summary>Minimum RDP encryption level (MinEncryptionLevel). 3 = High, 4 = FIPS. Secure default 3.</summary>
    public int MinEncryptionLevel { get; init; } = 3;

    /// <summary>RDP security layer (SecurityLayer). 2 = TLS. Secure default 2.</summary>
    public int SecurityLayer { get; init; } = 2;

    /// <summary>The RDP listener port (PortNumber). Defaults to the well-known 3389.</summary>
    public int PortNumber { get; init; } = RdpHardeningAnalyzer.DefaultRdpPort;
}
