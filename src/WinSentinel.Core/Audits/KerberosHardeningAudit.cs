using Microsoft.Win32;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Kerberos client encryption-type hardening in a live
/// <c>--audit</c> run: which Kerberos cipher suites this host is willing to negotiate, driven by
/// the <c>SupportedEncryptionTypes</c> bitmask under
/// <c>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters</c>. Offering the legacy DES
/// or weak RC4 suites keeps the host exposed to Kerberos downgrade / Kerberoasting attacks; a
/// hardened host offers only the AES suites.
///
/// <para>This is the thin I/O layer for <see cref="KerberosHardeningAnalyzer"/>: it owns the
/// reading of the local Lsa/Kerberos registry state and delegates every pass/fail decision to the
/// pure, unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="RdpHardeningAudit"/> / <see cref="RdpHardeningAnalyzer"/>). It reads only local
/// machine state, so it is single-machine and therefore FREE / OSS - nothing multi-machine,
/// nothing license-gated.</para>
/// </summary>
public class KerberosHardeningAudit : AuditModuleBase
{
    public override string Name => "Kerberos Hardening Audit";
    public override string Category => KerberosHardeningAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Kerberos client encryption-type hardening - the SupportedEncryptionTypes bitmask that " +
        "controls which cipher suites the host will negotiate - flagging the broken DES suites and the weak RC4 suite " +
        "(which enables fast offline Kerberoasting) and confirming a strong AES suite is offered.";

    private const string KerberosParametersSubKey =
        @"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters";
    private const string SupportedEncryptionTypesValue = "SupportedEncryptionTypes";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in KerberosHardeningAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read the local Kerberos <c>SupportedEncryptionTypes</c> policy into the pure
    /// <see cref="KerberosHardeningState"/>. A missing value (or an unreadable key) is reported as
    /// <c>null</c> so the analyzer treats it as "not configured / OS default" rather than
    /// false-positiving a specific bitmask.
    /// </summary>
    internal static KerberosHardeningState CollectState()
    {
        return new KerberosHardeningState
        {
            SupportedEncryptionTypes = ReadNullableDword(KerberosParametersSubKey, SupportedEncryptionTypesValue),
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
