using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine SMB (Server Message Block) signing,
/// SMBv1, encryption, and insecure-guest hardening in a live <c>--audit</c> run.
///
/// <para>This is the thin I/O layer for <see cref="SmbSecurityAnalyzer"/>: it owns
/// the reading of local SMB/policy registry state and delegates every pass/fail
/// decision to the pure, unit-tested analyzer (collector owns I/O, analyzer owns
/// decisions - the same split as <see cref="EncryptionAudit"/> /
/// <see cref="EncryptionAnalyzer"/>). It reads only local registry state, so it is
/// single-machine and therefore FREE / OSS - nothing multi-machine, nothing
/// license-gated.</para>
///
/// <para>It is intentionally scoped to the SMB <i>protocol hardening</i> knobs
/// (signing / SMBv1 / encryption / guest fallback / null-session access) under the
/// dedicated "<c>SMB / File Sharing</c>" category, complementing the broader
/// <see cref="SmbShareAudit"/> (share permissions, null sessions, hidden shares)
/// which lives under the "<c>SMB</c>" category.</para>
/// </summary>
public class SmbSecurityAudit : AuditModuleBase
{
    public override string Name => "SMB Security Hardening Audit";
    public override string Category => SmbSecurityAnalyzer.Category;
    public override string Description =>
        "Checks SMB server/client signing enforcement, the legacy SMBv1 protocol, " +
        "SMB share encryption, null-session access, and insecure guest-logon fallback against CIS Windows L1.";

    private const string ServerParams =
        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string WorkstationParams =
        @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    private const string Smb1ClientDriver =
        @"SYSTEM\CurrentControlSet\Services\mrxsmb10";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in SmbSecurityAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read local SMB server/client hardening state from the registry into the pure
    /// <see cref="SmbSecurityState"/>. Registry reads are best-effort: an unreadable
    /// value falls back to the safer default (see <see cref="SmbSecurityState"/>) so a
    /// missing key never false-positives the dangerous posture.
    /// </summary>
    internal static SmbSecurityState CollectState()
    {
        // ── Server side (LanmanServer\Parameters) ──
        bool serverRequireSigning = ReadDword(ServerParams, "RequireSecuritySignature") == 1;
        bool serverEnableSigning = ReadDword(ServerParams, "EnableSecuritySignature") == 1;
        // SMB1 server: the LanmanServer "SMB1" value. Present builds set 0 when disabled;
        // when the value is absent we treat it as disabled (modern Windows removes SMBv1).
        bool smb1ServerEnabled = ReadDword(ServerParams, "SMB1", defaultValue: 0) == 1;
        bool serverEncryptData = ReadDword(ServerParams, "EncryptData") == 1;
        // RestrictNullSessAccess: 1 = anonymous/null-session access to named pipes and
        // shares is restricted (safe). Modern Windows defaults this to 1, but treat an
        // unreadable/absent value as "not restricted" so we never miss the gap on an
        // older or tampered host (conservative for a security check).
        bool restrictNullSessAccess = ReadDword(ServerParams, "RestrictNullSessAccess") == 1;

        // ── Client side (LanmanWorkstation\Parameters) ──
        bool clientRequireSigning = ReadDword(WorkstationParams, "RequireSecuritySignature") == 1;
        bool clientEnableSigning = ReadDword(WorkstationParams, "EnableSecuritySignature") == 1;
        // AllowInsecureGuestAuth: 1 = insecure guest logons permitted (dangerous).
        // Absent -> treat as not enabled (safer default; do not false-positive).
        bool insecureGuestAuth = ReadDword(WorkstationParams, "AllowInsecureGuestAuth", defaultValue: 0) == 1;

        // ── SMBv1 client driver (mrxsmb10) Start: 4 = disabled, otherwise loadable ──
        // Absent -> assume disabled (modern Windows uninstalls the SMBv1 feature).
        int smb1ClientStart = ReadDword(Smb1ClientDriver, "Start", defaultValue: 4);
        bool smb1ClientEnabled = smb1ClientStart != 4 && smb1ClientStart != -1;

        return new SmbSecurityState
        {
            ServerRequireSigning = serverRequireSigning,
            ServerEnableSigning = serverEnableSigning,
            Smb1ServerEnabled = smb1ServerEnabled,
            ServerEncryptData = serverEncryptData,
            RestrictNullSessionAccess = restrictNullSessAccess,
            ClientRequireSigning = clientRequireSigning,
            ClientEnableSigning = clientEnableSigning,
            Smb1ClientEnabled = smb1ClientEnabled,
            InsecureGuestAuthEnabled = insecureGuestAuth,
        };
    }

    /// <summary>
    /// Best-effort read of a REG_DWORD from HKLM, returning <paramref name="defaultValue"/>
    /// when the key/value is missing or unreadable.
    /// </summary>
    private static int ReadDword(string subKey, string valueName, int defaultValue = 0)
    {
        try
        {
            return RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine, subKey, valueName, defaultValue);
        }
        catch
        {
            return defaultValue;
        }
    }
}
