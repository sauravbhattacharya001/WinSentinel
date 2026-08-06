using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing Kerberos client encryption-type hardening on a single
/// machine. When a Windows host negotiates Kerberos, the set of cipher suites it is willing to
/// use is controlled by the <c>SupportedEncryptionTypes</c> bitmask under
/// <c>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters</c>. Allowing the legacy
/// DES or RC4 suites keeps the door open to well-known downgrade / Kerberoasting attacks:
/// RC4-HMAC in particular lets an attacker who captures a service ticket crack the target
/// account's password offline much faster than against AES, and DES is cryptographically broken.
/// A hardened host should offer only the AES suites (AES128-CTS-HMAC-SHA1-96 and
/// AES256-CTS-HMAC-SHA1-96).
///
/// <para>The <c>SupportedEncryptionTypes</c> bitmask uses these flags (per MS-KILE):
/// <list type="bullet">
///   <item>0x1  = DES-CBC-CRC          (broken, must not be offered)</item>
///   <item>0x2  = DES-CBC-MD5          (broken, must not be offered)</item>
///   <item>0x4  = RC4-HMAC            (weak, enables fast offline Kerberoasting)</item>
///   <item>0x8  = AES128-CTS-HMAC-SHA1-96 (strong)</item>
///   <item>0x10 = AES256-CTS-HMAC-SHA1-96 (strong)</item>
/// </list>
/// The recommended value is 0x18 (both AES suites, no DES, no RC4).</para>
///
/// <para>The check reads only local Lsa/Kerberos policy state, so this module is single-machine
/// and therefore FREE / OSS: nothing multi-machine, nothing license-gated. Every rule operates
/// on a synthetic <see cref="KerberosHardeningState"/> so it can be unit tested directly,
/// mirroring the established <see cref="RdpHardeningAnalyzer"/> split (collector owns I/O,
/// analyzer owns decisions).</para>
/// </summary>
public static class KerberosHardeningAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Kerberos";

    /// <summary>DES-CBC-CRC bit in SupportedEncryptionTypes.</summary>
    public const int DesCbcCrc = 0x1;

    /// <summary>DES-CBC-MD5 bit in SupportedEncryptionTypes.</summary>
    public const int DesCbcMd5 = 0x2;

    /// <summary>RC4-HMAC bit in SupportedEncryptionTypes.</summary>
    public const int Rc4Hmac = 0x4;

    /// <summary>AES128-CTS-HMAC-SHA1-96 bit in SupportedEncryptionTypes.</summary>
    public const int Aes128 = 0x8;

    /// <summary>AES256-CTS-HMAC-SHA1-96 bit in SupportedEncryptionTypes.</summary>
    public const int Aes256 = 0x10;

    /// <summary>Combined mask of the two legacy DES suites.</summary>
    public const int DesMask = DesCbcCrc | DesCbcMd5;

    /// <summary>Combined mask of the two strong AES suites (the recommended value, 0x18).</summary>
    public const int AesMask = Aes128 | Aes256;

    /// <summary>
    /// Evaluate the collected Kerberos hardening state and return one finding per check (a Pass
    /// when the setting is already safe, otherwise Info/Warning). Ordering is stable and
    /// deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(KerberosHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeConfigured(state),
            AnalyzeDes(state),
            AnalyzeRc4(state),
            AnalyzeAes(state),
        };
    }

    /// <summary>
    /// Whether <c>SupportedEncryptionTypes</c> is explicitly configured at all. When absent the
    /// OS negotiates its default set (which on modern Windows still permits RC4), so an
    /// unconfigured host is reported as Info: the defaults are not fully hardened and the
    /// operator should set the value explicitly.
    /// </summary>
    public static Finding AnalyzeConfigured(KerberosHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.SupportedEncryptionTypes.HasValue)
        {
            return Finding.Pass(
                "Kerberos encryption types are explicitly configured",
                $"SupportedEncryptionTypes is set to 0x{state.SupportedEncryptionTypes.Value:X} on this machine, so the " +
                "Kerberos cipher suites the host will negotiate are governed by explicit local policy rather than the " +
                "OS defaults.",
                Category);
        }

        return Finding.Info(
            "Kerberos encryption types are not explicitly configured",
            "SupportedEncryptionTypes is not set under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters, " +
            "so this host negotiates the operating-system default Kerberos cipher suites. On current Windows the defaults " +
            "still permit the weak RC4-HMAC suite, which enables faster offline Kerberoasting of service accounts.",
            Category,
            remediation: "Explicitly restrict Kerberos to the AES suites only by setting SupportedEncryptionTypes = 0x18 " +
                "(AES128 + AES256), after confirming no legacy service in the environment still requires RC4/DES.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters' -Name SupportedEncryptionTypes -Value 0x18 -Type DWord");
    }

    /// <summary>
    /// Whether the broken DES suites (DES-CBC-CRC / DES-CBC-MD5) are offered. When the value is
    /// unconfigured this is a Pass (modern Windows does not offer DES by default). When
    /// configured, any DES bit set is a Warning.
    /// </summary>
    public static Finding AnalyzeDes(KerberosHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int etypes = state.SupportedEncryptionTypes ?? 0;
        bool desEnabled = state.SupportedEncryptionTypes.HasValue && (etypes & DesMask) != 0;

        if (!desEnabled)
        {
            return Finding.Pass(
                "Kerberos does not offer the broken DES suites",
                "The legacy DES Kerberos suites (DES-CBC-CRC / DES-CBC-MD5) are not offered by this host, so tickets " +
                "cannot be negotiated with cryptographically broken DES encryption.",
                Category);
        }

        return Finding.Warning(
            "Kerberos offers the broken DES suites",
            $"SupportedEncryptionTypes (0x{etypes:X}) enables one or more DES suites (DES-CBC-CRC / DES-CBC-MD5). DES is " +
            "cryptographically broken and trivially crackable; offering it lets an attacker force downgraded, weakly " +
            "encrypted Kerberos tickets.",
            Category,
            remediation: "Remove the DES bits from SupportedEncryptionTypes; offer only AES (0x18).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters' -Name SupportedEncryptionTypes -Value 0x18 -Type DWord");
    }

    /// <summary>
    /// Whether the weak RC4-HMAC suite is offered. When the value is unconfigured this is an
    /// Info (the OS default still permits RC4, but that is surfaced by
    /// <see cref="AnalyzeConfigured"/>). When configured with the RC4 bit set it is a Warning.
    /// </summary>
    public static Finding AnalyzeRc4(KerberosHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.SupportedEncryptionTypes.HasValue)
        {
            return Finding.Info(
                "Kerberos RC4 posture follows the OS default",
                "SupportedEncryptionTypes is not configured, so whether RC4-HMAC is offered follows the operating-system " +
                "default. On current Windows RC4 is still permitted by default, which enables faster offline Kerberoasting " +
                "of service-account passwords.",
                Category,
                remediation: "Set SupportedEncryptionTypes = 0x18 to offer only the AES suites and remove RC4 from the " +
                    "negotiation set (validate legacy dependencies first).");
        }

        int etypes = state.SupportedEncryptionTypes.Value;
        if ((etypes & Rc4Hmac) == 0)
        {
            return Finding.Pass(
                "Kerberos does not offer the weak RC4 suite",
                $"SupportedEncryptionTypes (0x{etypes:X}) does not enable RC4-HMAC, so service tickets cannot be negotiated " +
                "with the weak RC4 cipher that makes offline Kerberoasting fast.",
                Category);
        }

        return Finding.Warning(
            "Kerberos offers the weak RC4 suite",
            $"SupportedEncryptionTypes (0x{etypes:X}) enables RC4-HMAC. RC4 tickets can be cracked offline far faster than " +
            "AES, so any service account whose ticket an attacker can request becomes a Kerberoasting target. Modern " +
            "environments should offer only AES.",
            Category,
            remediation: "Remove the RC4 bit (0x4) from SupportedEncryptionTypes; offer only AES (0x18), after confirming " +
                "no legacy service still requires RC4.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters' -Name SupportedEncryptionTypes -Value 0x18 -Type DWord");
    }

    /// <summary>
    /// Whether at least one strong AES suite is offered. When the value is unconfigured this is
    /// a Pass (modern Windows offers AES by default). When configured with no AES bit set it is
    /// a Warning (the host cannot negotiate any strong suite).
    /// </summary>
    public static Finding AnalyzeAes(KerberosHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int etypes = state.SupportedEncryptionTypes ?? AesMask;
        if ((etypes & AesMask) != 0)
        {
            return Finding.Pass(
                "Kerberos offers a strong AES suite",
                $"SupportedEncryptionTypes (0x{etypes:X}) enables at least one AES suite (AES128 and/or AES256), so this " +
                "host can negotiate strong Kerberos encryption.",
                Category);
        }

        return Finding.Warning(
            "Kerberos offers no AES suite",
            $"SupportedEncryptionTypes (0x{etypes:X}) does not enable either AES suite (AES128 = 0x8, AES256 = 0x10). With " +
            "no strong suite available the host is forced onto legacy RC4/DES encryption for Kerberos, which is weak and " +
            "downgrade-prone.",
            Category,
            remediation: "Enable the AES suites in SupportedEncryptionTypes (set it to at least 0x18).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters' -Name SupportedEncryptionTypes -Value 0x18 -Type DWord");
    }
}

/// <summary>
/// Raw, collector-supplied Kerberos hardening state. Populated by the audit module's I/O layer
/// (reading <c>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\SupportedEncryptionTypes</c>)
/// and handed to <see cref="KerberosHardeningAnalyzer"/> for a pure decision. A <c>null</c>
/// value means the policy is not configured and the OS default applies.
/// </summary>
public sealed record KerberosHardeningState
{
    /// <summary>
    /// The <c>SupportedEncryptionTypes</c> bitmask, or <c>null</c> when the value is not
    /// configured (OS default). See <see cref="KerberosHardeningAnalyzer"/> for the flag layout.
    /// </summary>
    public int? SupportedEncryptionTypes { get; init; }
}
