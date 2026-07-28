using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for hardening the local Windows SMB (Server Message Block)
/// file-sharing stack on a single machine. SMB is the protocol behind Windows file
/// and printer sharing; a mis-hardened stack is the classic vector for
/// man-in-the-middle relay (unsigned SMB), ransomware lateral movement (SMBv1 /
/// EternalBlue), and credential theft (insecure guest fallback). The checks here
/// mirror the CIS Windows L1 "MS Network Server / Client" and "SMBv1" sections and
/// split cleanly into the SMB <b>server</b> (this machine hosting shares) and the
/// SMB <b>client</b> (this machine connecting to shares):
///
///   Server side (hosting shares):
///   * ServerRequireSigning  - LanmanServer RequireSecuritySignature. When on, the
///                             server refuses unsigned sessions - defeats SMB relay.
///   * ServerEnableSigning   - LanmanServer EnableSecuritySignature. Offers signing
///                             even when not strictly required.
///   * Smb1ServerEnabled     - The SMBv1 server protocol. SMBv1 is the WannaCry /
///                             EternalBlue vector and has no modern reason to be on.
///   * ServerEncryptData     - SMB server EncryptData. Encrypts share traffic in transit.
///
///   Client side (connecting to shares):
///   * ClientRequireSigning  - LanmanWorkstation RequireSecuritySignature. Client
///                             refuses to talk to servers that won't sign.
///   * ClientEnableSigning   - LanmanWorkstation EnableSecuritySignature.
///   * Smb1ClientEnabled     - The SMBv1 client protocol / MRxSmb10 driver.
///   * InsecureGuestAuth     - LanmanWorkstation AllowInsecureGuestAuth. When on,
///                             the client silently falls back to unauthenticated
///                             guest access - an easy path to a rogue file server.
///
/// Everything here reads only local SMB/policy registry state, so it is
/// single-machine and therefore FREE / OSS: nothing multi-machine, nothing
/// license-gated. All rules operate on a synthetic <see cref="SmbSecurityState"/>
/// so they can be unit tested directly, mirroring the established
/// <see cref="WinRmSecurityAnalyzer"/> pattern (collector owns I/O, the analyzer
/// owns decisions).
/// </summary>
public static class SmbSecurityAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "SMB / File Sharing";

    /// <summary>
    /// Evaluate the collected SMB state and return one finding per check (a Pass
    /// when the setting is already safe, otherwise a Warning/Critical). Ordering is
    /// stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeServerRequireSigning(state),
            AnalyzeServerEnableSigning(state),
            AnalyzeSmb1Server(state),
            AnalyzeServerEncryption(state),
            AnalyzeClientRequireSigning(state),
            AnalyzeClientEnableSigning(state),
            AnalyzeSmb1Client(state),
            AnalyzeInsecureGuestAuth(state),
        };
    }

    /// <summary>Server should require SMB signing so unsigned sessions are refused.</summary>
    public static Finding AnalyzeServerRequireSigning(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ServerRequireSigning)
        {
            return Finding.Pass(
                "SMB server requires signing",
                "The SMB server requires security signatures (RequireSecuritySignature), so it refuses " +
                "unsigned sessions and cannot be silently relayed by a man-in-the-middle.",
                Category);
        }

        return Finding.Warning(
            "SMB server does not require signing",
            "The SMB server does not require security signatures. Without required signing, an attacker on " +
            "the path can relay or tamper with SMB sessions (SMB relay), a common lateral-movement technique.",
            Category,
            remediation: "Require SMB signing on the server (LanmanServer RequireSecuritySignature = 1).",
            fixCommand: "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force");
    }

    /// <summary>Server should at least offer/enable SMB signing.</summary>
    public static Finding AnalyzeServerEnableSigning(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ServerEnableSigning)
        {
            return Finding.Pass(
                "SMB server offers signing",
                "The SMB server enables security signatures (EnableSecuritySignature), so signing is offered to clients that request it.",
                Category);
        }

        return Finding.Warning(
            "SMB server does not enable signing",
            "The SMB server does not enable security signatures, so clients cannot negotiate signed sessions with it.",
            Category,
            remediation: "Enable SMB signing on the server.",
            fixCommand: "Set-SmbServerConfiguration -EnableSecuritySignature $true -Force");
    }

    /// <summary>The SMBv1 server protocol should be disabled.</summary>
    public static Finding AnalyzeSmb1Server(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.Smb1ServerEnabled)
        {
            return Finding.Critical(
                "SMBv1 server protocol is enabled",
                "The legacy SMBv1 server protocol is enabled. SMBv1 is the vector exploited by WannaCry and " +
                "EternalBlue, has known unpatched design weaknesses, and no modern client needs it. Leaving it on " +
                "exposes this machine to well-known worming ransomware.",
                Category,
                remediation: "Disable the SMBv1 server protocol.",
                fixCommand: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force");
        }

        return Finding.Pass(
            "SMBv1 server protocol is disabled",
            "The legacy SMBv1 server protocol is turned off; only SMBv2/3 sessions are served.",
            Category);
    }

    /// <summary>SMB server encryption in transit is recommended for sensitive shares.</summary>
    public static Finding AnalyzeServerEncryption(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ServerEncryptData)
        {
            return Finding.Pass(
                "SMB server encrypts share traffic",
                "The SMB server encrypts data in transit (EncryptData), so share contents are protected from network sniffing.",
                Category);
        }

        return Finding.Info(
            "SMB server does not encrypt share traffic",
            "The SMB server does not require encryption of data in transit. Signing still protects integrity, but " +
            "share contents cross the network unencrypted. Consider enabling SMB encryption for shares carrying sensitive data.",
            Category,
            remediation: "Enable SMB encryption on the server (globally or per share).",
            fixCommand: "Set-SmbServerConfiguration -EncryptData $true -Force");
    }

    /// <summary>Client should require SMB signing so it refuses unsigned servers.</summary>
    public static Finding AnalyzeClientRequireSigning(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ClientRequireSigning)
        {
            return Finding.Pass(
                "SMB client requires signing",
                "The SMB client requires security signatures (LanmanWorkstation RequireSecuritySignature), so it " +
                "refuses to connect to servers that will not sign, defeating downgrade/relay attacks.",
                Category);
        }

        return Finding.Warning(
            "SMB client does not require signing",
            "The SMB client does not require security signatures. It can be tricked into an unsigned session with a " +
            "rogue or interposed server, enabling SMB relay of its credentials.",
            Category,
            remediation: "Require SMB signing on the client (LanmanWorkstation RequireSecuritySignature = 1).",
            fixCommand: "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force");
    }

    /// <summary>Client should at least offer/enable SMB signing.</summary>
    public static Finding AnalyzeClientEnableSigning(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ClientEnableSigning)
        {
            return Finding.Pass(
                "SMB client offers signing",
                "The SMB client enables security signatures (EnableSecuritySignature), so it will negotiate signed sessions when the server supports them.",
                Category);
        }

        return Finding.Warning(
            "SMB client does not enable signing",
            "The SMB client does not enable security signatures, so it cannot negotiate signed sessions.",
            Category,
            remediation: "Enable SMB signing on the client.",
            fixCommand: "Set-SmbClientConfiguration -EnableSecuritySignature $true -Force");
    }

    /// <summary>The SMBv1 client protocol should be disabled.</summary>
    public static Finding AnalyzeSmb1Client(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.Smb1ClientEnabled)
        {
            return Finding.Critical(
                "SMBv1 client protocol is enabled",
                "The legacy SMBv1 client protocol is enabled. An SMBv1 client can be downgraded and forced to talk to " +
                "a malicious SMBv1 server, and keeping the protocol installed reintroduces the WannaCry/EternalBlue attack surface.",
                Category,
                remediation: "Disable the SMBv1 client protocol / MRxSmb10 driver.",
                fixCommand: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart");
        }

        return Finding.Pass(
            "SMBv1 client protocol is disabled",
            "The legacy SMBv1 client protocol is turned off; this machine will not initiate SMBv1 sessions.",
            Category);
    }

    /// <summary>Insecure guest auth (unauthenticated fallback) should be off on the client.</summary>
    public static Finding AnalyzeInsecureGuestAuth(SmbSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.InsecureGuestAuthEnabled)
        {
            return Finding.Critical(
                "SMB client allows insecure guest logons",
                "The SMB client permits insecure guest logons (AllowInsecureGuestAuth). It will silently connect to file " +
                "shares as an unauthenticated guest, which lets an attacker stand up a rogue file server and serve malicious " +
                "content or harvest connections without any credential prompt.",
                Category,
                remediation: "Disable insecure guest logons on the SMB client.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name AllowInsecureGuestAuth -Value 0");
        }

        return Finding.Pass(
            "SMB client blocks insecure guest logons",
            "The SMB client refuses insecure (unauthenticated) guest logons, so it will not silently connect to a rogue guest-only file server.",
            Category);
    }
}

/// <summary>
/// Raw, collector-supplied SMB (Server Message Block) server/client state.
/// Populated by the audit module's I/O layer (reading Get-SmbServerConfiguration /
/// Get-SmbClientConfiguration and the LanmanServer/LanmanWorkstation policy
/// registry) and handed to <see cref="SmbSecurityAnalyzer"/> for a pure decision.
/// Boolean flags default to <c>false</c>; the collector maps them so the safer
/// posture is the default: signing/encryption flags default off (reported as a
/// gap only when genuinely off), while the legacy SMBv1 and insecure-guest flags
/// default off (reported only when the collector confirms them enabled), so an
/// unreadable setting is never falsely flagged as the dangerous state.
/// </summary>
public sealed record SmbSecurityState
{
    /// <summary>LanmanServer RequireSecuritySignature (server refuses unsigned sessions).</summary>
    public bool ServerRequireSigning { get; init; }

    /// <summary>LanmanServer EnableSecuritySignature (server offers signing).</summary>
    public bool ServerEnableSigning { get; init; }

    /// <summary>Whether the SMBv1 server protocol is enabled.</summary>
    public bool Smb1ServerEnabled { get; init; }

    /// <summary>SMB server EncryptData (encrypt share traffic in transit).</summary>
    public bool ServerEncryptData { get; init; }

    /// <summary>LanmanWorkstation RequireSecuritySignature (client refuses unsigned servers).</summary>
    public bool ClientRequireSigning { get; init; }

    /// <summary>LanmanWorkstation EnableSecuritySignature (client offers signing).</summary>
    public bool ClientEnableSigning { get; init; }

    /// <summary>Whether the SMBv1 client protocol / MRxSmb10 driver is enabled.</summary>
    public bool Smb1ClientEnabled { get; init; }

    /// <summary>LanmanWorkstation AllowInsecureGuestAuth (unauthenticated guest fallback).</summary>
    public bool InsecureGuestAuthEnabled { get; init; }
}
