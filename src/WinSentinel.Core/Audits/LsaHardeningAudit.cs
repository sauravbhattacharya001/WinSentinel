using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine LSA / credential-protection registry
/// hardening in a live <c>--audit</c> run: whether LSASS runs as a Protected
/// Process (RunAsPPL), whether WDigest caches plaintext credentials, whether the
/// weak LM hash is stored, which NTLM dialects are sent/accepted
/// (LmCompatibilityLevel), whether unauthenticated null-session callers can
/// enumerate accounts/shares (RestrictAnonymous* / EveryoneIncludesAnonymous),
/// whether blank-password accounts are confined to console logon
/// (LimitBlankPasswordUse), how many domain logons are cached offline
/// (CachedLogonsCount), and whether autologon stores a cleartext password.
///
/// <para>This is the thin I/O layer for <see cref="LsaHardeningAnalyzer"/>: it owns
/// the reading of the HKLM Lsa, WDigest and Winlogon registry values and delegates
/// every pass/fail decision to the pure, unit-tested analyzer (collector owns I/O,
/// analyzer owns decisions - the same split as
/// <see cref="ScreenLockAudit"/> / <see cref="ScreenLockAnalyzer"/>). It reads only
/// local machine state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class LsaHardeningAudit : AuditModuleBase
{
    public override string Name => "LSA Hardening Audit";
    public override string Category => LsaHardeningAnalyzer.Category;
    public override string Description =>
        "Checks single-machine LSA / credential-protection hardening - LSASS Protected Process (RunAsPPL), " +
        "WDigest plaintext caching, LM hash storage, NTLM dialect restriction, anonymous null-session " +
        "enumeration, blank-password remote logon, cached domain logon count, and cleartext autologon - " +
        "the classic CIS L1 controls that decide how hard it is to lift or replay credentials on this box.";

    private const string LsaSubKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string WDigestSubKey = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
    private const string WinlogonSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string Msv10SubKey = @"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in LsaHardeningAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local LSA hardening state into the pure <see cref="LsaHardeningState"/>. Each value is a
    /// best-effort registry read whose absence maps to null / false; the analyzer then treats absence
    /// as the OS default for each key, so a missing value never becomes a false pass or a false alarm.
    /// </summary>
    internal static LsaHardeningState CollectState()
    {
        return new LsaHardeningState
        {
            RunAsPpl = ReadDword(RegistryHive.LocalMachine, LsaSubKey, "RunAsPPL"),
            WDigestUseLogonCredential = ReadDword(RegistryHive.LocalMachine, WDigestSubKey, "UseLogonCredential"),
            NoLmHash = ReadDword(RegistryHive.LocalMachine, LsaSubKey, "NoLMHash"),
            LmCompatibilityLevel = ReadDword(RegistryHive.LocalMachine, LsaSubKey, "LmCompatibilityLevel"),
            RestrictAnonymous = ReadDword(RegistryHive.LocalMachine, LsaSubKey, "RestrictAnonymous"),
            RestrictAnonymousSam = ReadDword(RegistryHive.LocalMachine, LsaSubKey, "RestrictAnonymousSam"),
            EveryoneIncludesAnonymous = ReadDword(RegistryHive.LocalMachine, LsaSubKey, "EveryoneIncludesAnonymous"),
            LimitBlankPasswordUse = ReadDword(RegistryHive.LocalMachine, LsaSubKey, "LimitBlankPasswordUse"),
            CachedLogonsCount = ReadIntString(RegistryHive.LocalMachine, WinlogonSubKey, "CachedLogonsCount"),
            AutoAdminLogon = ReadBoolString(RegistryHive.LocalMachine, WinlogonSubKey, "AutoAdminLogon"),
            DefaultPassword = ReadString(RegistryHive.LocalMachine, WinlogonSubKey, "DefaultPassword"),
            RestrictSendingNtlmTraffic = ReadDword(RegistryHive.LocalMachine, Msv10SubKey, "RestrictSendingNTLMTraffic"),
        };
    }

    /// <summary>Best-effort read of a REG_DWORD as an int; null when missing/unreadable.</summary>
    private static int? ReadDword(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(hive, subKey, valueName, null);
            if (raw is null) return null;
            return raw is int i ? i : (int.TryParse(raw.ToString(), out var parsed) ? parsed : (int?)null);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Best-effort read of a REG_SZ that carries an integer (e.g. CachedLogonsCount is stored as a
    /// string by Windows, not a DWORD); null when missing/unparsable.
    /// </summary>
    private static int? ReadIntString(RegistryHive hive, string subKey, string valueName)
    {
        string? raw = ReadString(hive, subKey, valueName);
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return int.TryParse(raw.Trim(), out var parsed) ? parsed : (int?)null;
    }

    /// <summary>Read a REG_SZ "1"/"0" boolean-style flag; true only when the value is exactly "1".</summary>
    private static bool ReadBoolString(RegistryHive hive, string subKey, string valueName)
    {
        string? raw = ReadString(hive, subKey, valueName);
        return raw?.Trim() == "1";
    }

    /// <summary>Best-effort read of a REG_SZ, returning <c>null</c> when missing/unreadable.</summary>
    private static string? ReadString(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            return RegistryHelper.GetValue<string?>(hive, subKey, valueName, null);
        }
        catch
        {
            return null;
        }
    }
}
