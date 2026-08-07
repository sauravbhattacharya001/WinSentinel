using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing single-machine LSASS credential-theft defenses - the three
/// registry-backed protections that decide how hard it is for an attacker who lands code on this
/// host to dump plaintext or reusable credentials from the Local Security Authority
/// Subsystem Service (LSASS). This is the classic Mimikatz / <c>sekurlsa::logonpasswords</c>
/// attack surface (MITRE ATT&amp;CK T1003.001 - OS Credential Dumping: LSASS Memory).
///
/// <para>Three independent controls are evaluated, each driven by a REG_DWORD:
/// <list type="bullet">
///   <item><b>LSA Protection (RunAsPPL)</b> under
///     <c>HKLM\SYSTEM\CurrentControlSet\Control\Lsa</c>: runs LSASS as a Protected Process Light so
///     unprivileged/attacker code cannot open a handle to read its memory. <c>1</c> = enabled with
///     a UEFI lock (strongest), <c>2</c> = enabled without the lock, absent/0 = off.</item>
///   <item><b>Credential Guard (LsaCfgFlags)</b> under
///     <c>HKLM\SYSTEM\CurrentControlSet\Control\Lsa</c>: uses virtualization-based security to
///     isolate secrets (NTLM hashes, Kerberos TGTs) in a VTL1 trustlet so they never sit in
///     dumpable LSASS memory. <c>1</c> = enabled with UEFI lock, <c>2</c> = enabled without lock,
///     absent/0 = off.</item>
///   <item><b>WDigest cleartext caching (UseLogonCredential)</b> under
///     <c>HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest</c>: when set to <c>1</c>
///     Windows caches the user's plaintext password in LSASS for the legacy WDigest SSP, which is
///     exactly what makes <c>sekurlsa::wdigest</c> return cleartext passwords. Absent/0 = safe
///     (the modern default).</item>
/// </list></para>
///
/// <para>The check reads only local machine state, so this module is single-machine and therefore
/// FREE / OSS: nothing multi-machine, nothing license-gated. Every rule operates on a synthetic
/// <see cref="CredentialGuardState"/> so it can be unit tested directly, mirroring the established
/// <see cref="KerberosHardeningAnalyzer"/> split (collector owns I/O, analyzer owns decisions).</para>
/// </summary>
public static class CredentialGuardAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Credential Protection";

    /// <summary>RunAsPPL / LsaCfgFlags value meaning "enabled with a UEFI lock" (strongest).</summary>
    public const int EnabledWithUefiLock = 1;

    /// <summary>RunAsPPL / LsaCfgFlags value meaning "enabled without a UEFI lock".</summary>
    public const int EnabledWithoutLock = 2;

    /// <summary>
    /// Evaluate the collected credential-protection state and return one finding per check (a Pass
    /// when the setting is already safe, otherwise Info/Warning). Ordering is stable and
    /// deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(CredentialGuardState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeLsaProtection(state),
            AnalyzeCredentialGuard(state),
            AnalyzeWDigest(state),
        };
    }

    /// <summary>
    /// LSA Protection (RunAsPPL): whether LSASS runs as a Protected Process Light so its memory
    /// cannot be read by unprivileged/attacker code. <c>1</c> (UEFI lock) is the strongest Pass,
    /// <c>2</c> (no lock) is a weaker Pass, absent/0 is a Warning.
    /// </summary>
    public static Finding AnalyzeLsaProtection(CredentialGuardState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int value = state.RunAsPPL ?? 0;

        if (value == EnabledWithUefiLock)
        {
            return Finding.Pass(
                "LSA Protection (RunAsPPL) is enabled with a UEFI lock",
                "RunAsPPL is set to 1, so LSASS runs as a Protected Process Light and the setting is anchored with a UEFI " +
                "lock. Unprivileged or attacker-injected code cannot open a handle to read LSASS memory, defeating the " +
                "standard Mimikatz sekurlsa::logonpasswords credential dump.",
                Category);
        }

        if (value == EnabledWithoutLock)
        {
            return Finding.Info(
                "LSA Protection (RunAsPPL) is enabled but not UEFI-locked",
                "RunAsPPL is set to 2, so LSASS runs as a Protected Process Light, but without the UEFI lock the setting " +
                "can be reverted by a local administrator (or malware) via a simple registry change and reboot.",
                Category,
                remediation: "Once validated, promote RunAsPPL to 1 (UEFI-locked) so the protection cannot be silently " +
                    "disabled by a registry edit.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord");
        }

        return Finding.Warning(
            "LSA Protection (RunAsPPL) is not enabled",
            "RunAsPPL is not configured, so LSASS runs as an ordinary process. Any code running with administrative or " +
            "SYSTEM privileges (or a driver/token-theft primitive) can open LSASS and dump credentials with tools like " +
            "Mimikatz. Enabling LSA Protection runs LSASS as a Protected Process Light and blocks that memory read.",
            Category,
            remediation: "Enable LSA Protection by setting RunAsPPL = 1 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa " +
                "and rebooting, after confirming no unsigned SSP/authentication provider is required.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord");
    }

    /// <summary>
    /// Credential Guard (LsaCfgFlags): whether VBS-isolated credential storage is enabled so
    /// secrets never sit in dumpable LSASS memory. <c>1</c> (UEFI lock) is the strongest Pass,
    /// <c>2</c> (no lock) is a weaker Pass, absent/0 is a Warning.
    /// </summary>
    public static Finding AnalyzeCredentialGuard(CredentialGuardState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int value = state.LsaCfgFlags ?? 0;

        if (value == EnabledWithUefiLock)
        {
            return Finding.Pass(
                "Credential Guard is enabled with a UEFI lock",
                "LsaCfgFlags is set to 1, so Windows Defender Credential Guard is enabled and UEFI-locked. Domain " +
                "credentials, NTLM hashes and Kerberos ticket-granting tickets are isolated in a virtualization-based " +
                "security trustlet, so they are not present in dumpable LSASS memory.",
                Category);
        }

        if (value == EnabledWithoutLock)
        {
            return Finding.Info(
                "Credential Guard is enabled but not UEFI-locked",
                "LsaCfgFlags is set to 2, so Credential Guard is running, but without the UEFI lock the setting can be " +
                "turned off again by a local administrator via a registry change and reboot.",
                Category,
                remediation: "Once validated, promote LsaCfgFlags to 1 (UEFI-locked) so Credential Guard cannot be " +
                    "silently disabled.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LsaCfgFlags -Value 1 -Type DWord");
        }

        return Finding.Warning(
            "Credential Guard is not enabled",
            "LsaCfgFlags is not configured, so Windows Defender Credential Guard is off. Cached domain secrets, NTLM " +
            "hashes and Kerberos TGTs remain in LSASS memory where an attacker with sufficient privileges can steal them " +
            "for pass-the-hash / pass-the-ticket attacks. Credential Guard isolates those secrets with virtualization-" +
            "based security so they cannot be read from LSASS.",
            Category,
            remediation: "Enable Credential Guard (requires VBS-capable hardware with UEFI/Secure Boot) by setting " +
                "LsaCfgFlags = 1 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa, or via the corresponding Device " +
                "Guard group policy, then reboot. Validate driver/SSO compatibility first.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LsaCfgFlags -Value 1 -Type DWord");
    }

    /// <summary>
    /// WDigest cleartext caching (UseLogonCredential): whether Windows is caching plaintext
    /// passwords in LSASS for the legacy WDigest SSP. <c>1</c> is a Warning (cleartext creds are
    /// dumpable); absent/0 is a Pass (the safe modern default).
    /// </summary>
    public static Finding AnalyzeWDigest(CredentialGuardState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int value = state.WDigestUseLogonCredential ?? 0;

        if (value == 0)
        {
            return Finding.Pass(
                "WDigest is not caching cleartext credentials",
                "UseLogonCredential is not enabled, so the legacy WDigest security provider does not cache the user's " +
                "plaintext password in LSASS. This is the safe default on modern Windows and denies attackers the " +
                "sekurlsa::wdigest cleartext-password path.",
                Category);
        }

        return Finding.Warning(
            "WDigest is caching cleartext credentials in LSASS",
            $"UseLogonCredential is set to {value} under " +
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest, which forces Windows to cache the " +
            "user's plaintext password in LSASS for the legacy WDigest SSP. An attacker who can read LSASS (e.g. via " +
            "Mimikatz sekurlsa::wdigest) then recovers passwords in clear text, not just hashes.",
            Category,
            remediation: "Disable WDigest cleartext caching by setting UseLogonCredential = 0 (or removing the value); " +
                "no modern application requires it.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0 -Type DWord");
    }
}

/// <summary>
/// Raw, collector-supplied LSASS credential-protection state. Populated by the audit module's I/O
/// layer (reading RunAsPPL, LsaCfgFlags and the WDigest UseLogonCredential REG_DWORDs) and handed
/// to <see cref="CredentialGuardAnalyzer"/> for a pure decision. A <c>null</c> value means the
/// corresponding policy is not configured and the OS default applies.
/// </summary>
public sealed record CredentialGuardState
{
    /// <summary>
    /// <c>RunAsPPL</c> under <c>HKLM\SYSTEM\CurrentControlSet\Control\Lsa</c> (LSA Protection), or
    /// <c>null</c> when not configured. 1 = enabled + UEFI lock, 2 = enabled without lock.
    /// </summary>
    public int? RunAsPPL { get; init; }

    /// <summary>
    /// <c>LsaCfgFlags</c> under <c>HKLM\SYSTEM\CurrentControlSet\Control\Lsa</c> (Credential Guard),
    /// or <c>null</c> when not configured. 1 = enabled + UEFI lock, 2 = enabled without lock.
    /// </summary>
    public int? LsaCfgFlags { get; init; }

    /// <summary>
    /// <c>UseLogonCredential</c> under
    /// <c>HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest</c>, or <c>null</c> when
    /// not configured. 1 = plaintext passwords cached in LSASS (unsafe); 0/absent = safe default.
    /// </summary>
    public int? WDigestUseLogonCredential { get; init; }
}
