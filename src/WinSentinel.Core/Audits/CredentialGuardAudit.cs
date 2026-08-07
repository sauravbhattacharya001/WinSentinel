using Microsoft.Win32;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine LSASS credential-theft defenses in a live
/// <c>--audit</c> run: LSA Protection (RunAsPPL), Windows Defender Credential Guard (LsaCfgFlags),
/// and WDigest cleartext credential caching (UseLogonCredential). Together these decide how hard
/// it is for an attacker who lands code on this host to dump reusable or plaintext credentials
/// from LSASS - the classic Mimikatz attack surface (MITRE ATT&amp;CK T1003.001).
///
/// <para>This is the thin I/O layer for <see cref="CredentialGuardAnalyzer"/>: it owns the reading
/// of the local Lsa / WDigest registry state and delegates every pass/fail decision to the pure,
/// unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="KerberosHardeningAudit"/> / <see cref="KerberosHardeningAnalyzer"/>). It reads only
/// local machine state, so it is single-machine and therefore FREE / OSS - nothing multi-machine,
/// nothing license-gated.</para>
/// </summary>
public class CredentialGuardAudit : AuditModuleBase
{
    public override string Name => "Credential Protection Audit";
    public override string Category => CredentialGuardAnalyzer.Category;
    public override string Description =>
        "Checks single-machine LSASS credential-theft defenses - LSA Protection (RunAsPPL), Credential Guard " +
        "(LsaCfgFlags) and WDigest cleartext caching (UseLogonCredential) - to confirm that credentials in LSASS " +
        "memory are protected against Mimikatz-style dumping.";

    private const string LsaSubKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string RunAsPPLValue = "RunAsPPL";
    private const string LsaCfgFlagsValue = "LsaCfgFlags";

    private const string WDigestSubKey = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
    private const string UseLogonCredentialValue = "UseLogonCredential";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in CredentialGuardAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read the local LSA-protection policy into the pure <see cref="CredentialGuardState"/>. A
    /// missing value (or an unreadable key) is reported as <c>null</c> so the analyzer treats it as
    /// "not configured / OS default" rather than false-positiving a specific value.
    /// </summary>
    internal static CredentialGuardState CollectState()
    {
        return new CredentialGuardState
        {
            RunAsPPL = ReadNullableDword(LsaSubKey, RunAsPPLValue),
            LsaCfgFlags = ReadNullableDword(LsaSubKey, LsaCfgFlagsValue),
            WDigestUseLogonCredential = ReadNullableDword(WDigestSubKey, UseLogonCredentialValue),
        };
    }

    /// <summary>
    /// Best-effort read of a REG_DWORD from HKLM (64-bit view), returning <c>null</c> when the
    /// key/value is missing or unreadable so absence is distinguishable from an explicit 0.
    /// </summary>
    private static int? ReadNullableDword(string subKey, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey);
            var raw = key?.GetValue(valueName);
            if (raw is null)
            {
                return null;
            }

            return raw switch
            {
                int i => i,
                long l => unchecked((int)l),
                _ => Convert.ToInt32(raw),
            };
        }
        catch
        {
            return null;
        }
    }
}
