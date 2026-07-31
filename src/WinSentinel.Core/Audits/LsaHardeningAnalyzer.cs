using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for LSA / credential-protection registry hardening on a
/// single machine.
///
/// These are the classic local settings that decide how hard it is for an
/// attacker who already has code execution to lift credentials out of LSASS,
/// replay cached logons offline, or find a plaintext password sitting in the
/// registry:
///
///   * RunAsPPL           - runs LSASS as a Protected Process Light so ordinary
///                          admin/SYSTEM tools (Mimikatz etc.) cannot open its
///                          memory. Off by default on most builds.
///   * WDigest UseLogonCredential - when 1, WDigest caches the plaintext
///                          password in LSASS memory (a Mimikatz favourite). It
///                          must be 0 / absent.
///   * NoLMHash           - stops the weak LM hash of the password from being
///                          stored. Should be 1.
///   * LmCompatibilityLevel - which NTLM dialects the box will send/accept. &lt;3
///                          still allows the weak LM/NTLMv1 responses that are
///                          trivially crackable / relayable; the hardened value
///                          is 5 (send NTLMv2 only, refuse LM &amp; NTLM).
///   * CachedLogonsCount  - number of domain logons cached for offline use; a
///                          large value means more replayable secrets on a lost
///                          laptop. 10 is the default; &gt;10 is worth flagging.
///   * AutoAdminLogon + DefaultPassword - autologon with the password stored in
///                          CLEARTEXT under Winlogon. Anyone who can read the
///                          registry reads the password.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// registry state only. Nothing multi-machine, nothing license-gated. All rules
/// operate on a synthetic <see cref="LsaHardeningState"/> so they can be unit
/// tested directly, mirroring the established
/// <see cref="PowerShellSecurityAnalyzer"/> / <see cref="EncryptionAnalyzer"/>
/// analyzer pattern (collector owns I/O, analyzer owns decisions).
/// </summary>
public static class LsaHardeningAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Credentials";

    /// <summary>
    /// The Windows default cached-logon count. Values above this keep more
    /// offline-replayable domain secrets on the box than necessary.
    /// </summary>
    public const int DefaultCachedLogons = 10;

    /// <summary>
    /// The hardened LmCompatibilityLevel: "Send NTLMv2 response only. Refuse LM
    /// &amp; NTLM." Anything below this still emits/accepts the weak LM or NTLMv1
    /// responses that are crackable offline and usable for NTLM relay.
    /// </summary>
    public const int HardenedLmCompatibilityLevel = 5;

    /// <summary>
    /// Evaluate the collected LSA hardening state and return one finding per
    /// check (a Pass when the setting is already safe, a Warning/Critical when
    /// it is not). Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(LsaHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var findings = new List<Finding>
        {
            AnalyzeRunAsPpl(state),
            AnalyzeWDigest(state),
            AnalyzeNoLmHash(state),
            AnalyzeLmCompatibilityLevel(state),
            AnalyzeCachedLogons(state),
            AnalyzeAutoLogon(state),
        };
        return findings;
    }

    /// <summary>LSASS Protected Process Light: RunAsPPL should be 1.</summary>
    public static Finding AnalyzeRunAsPpl(LsaHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.RunAsPpl == 1)
        {
            return Finding.Pass(
                "LSASS runs as a Protected Process (RunAsPPL)",
                "RunAsPPL is enabled, so LSASS runs as a Protected Process Light and " +
                "its memory cannot be read by ordinary admin/SYSTEM tooling.",
                Category);
        }

        return Finding.Warning(
            "LSASS is not a Protected Process (RunAsPPL off)",
            "RunAsPPL is not enabled. LSASS memory can be opened by an attacker who " +
            "already has local admin/SYSTEM, allowing credential theft (e.g. Mimikatz).",
            Category,
            remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 (DWORD) and reboot. " +
                         "Verify third-party security drivers are compatible first.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Type DWord -Value 1");
    }

    /// <summary>WDigest UseLogonCredential must be 0 (no plaintext creds in LSASS).</summary>
    public static Finding AnalyzeWDigest(LsaHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // Absent (null) is safe on modern Windows: WDigest plaintext caching is
        // off by default since Windows 8.1 / Server 2012 R2. Only a value of 1
        // re-enables the risk.
        if (state.WDigestUseLogonCredential == 1)
        {
            return Finding.Critical(
                "WDigest stores plaintext credentials in memory",
                "UseLogonCredential is set to 1, which forces WDigest to cache the " +
                "user's plaintext password in LSASS memory - trivially recoverable by " +
                "credential-dumping tools.",
                Category,
                remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0 (DWORD).",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Type DWord -Value 0");
        }

        return Finding.Pass(
            "WDigest plaintext credential caching is disabled",
            "UseLogonCredential is 0 or absent, so WDigest does not keep plaintext " +
            "passwords in LSASS memory.",
            Category);
    }

    /// <summary>NoLMHash should be 1 so the weak LM hash is not stored.</summary>
    public static Finding AnalyzeNoLmHash(LsaHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.NoLmHash == 1)
        {
            return Finding.Pass(
                "LM hash storage is disabled (NoLMHash)",
                "NoLMHash is enabled, so the weak, easily-cracked LM hash of account " +
                "passwords is not stored.",
                Category);
        }

        return Finding.Warning(
            "Weak LM hashes may be stored (NoLMHash off)",
            "NoLMHash is not enabled. Windows may store the legacy LM hash of " +
            "passwords, which is far weaker than NTLM and cracks almost instantly.",
            Category,
            remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash = 1 (DWORD) and have users change passwords once.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -Type DWord -Value 1");
    }

    /// <summary>
    /// LmCompatibilityLevel controls which NTLM authentication dialects the
    /// machine sends and accepts. The hardened setting is 5 (send NTLMv2 only,
    /// refuse LM &amp; NTLM). Levels 0-2 still SEND the weak LM/NTLMv1 responses;
    /// levels 3-4 send NTLMv2 but still ACCEPT the weak ones. Only level 5 both
    /// sends and refuses correctly. Absence is treated as the modern OS default
    /// (3), which is a Warning because it still accepts LM/NTLMv1 inbound.
    /// </summary>
    public static Finding AnalyzeLmCompatibilityLevel(LsaHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int level = state.LmCompatibilityLevel ?? 3; // modern OS default when unset
        if (level >= HardenedLmCompatibilityLevel)
        {
            return Finding.Pass(
                "NTLM is restricted to NTLMv2 (LmCompatibilityLevel 5)",
                $"LmCompatibilityLevel is {level}: the machine sends only NTLMv2 and refuses the weak " +
                "LM and NTLMv1 responses, which are crackable offline and usable for NTLM relay.",
                Category);
        }

        var severity = level <= 2 ? Severity.Critical : Severity.Warning;
        var detail = level <= 2
            ? $"LmCompatibilityLevel is {level}: the machine still SENDS the weak LM/NTLMv1 responses, " +
              "which can be captured and cracked offline in seconds or relayed to other hosts."
            : $"LmCompatibilityLevel is {level}: the machine sends NTLMv2 but still ACCEPTS inbound " +
              "LM/NTLMv1, leaving it exposed to downgrade and relay from weaker peers.";

        return new Finding
        {
            Title = "NTLM allows weak LM/NTLMv1 authentication",
            Description = detail,
            Severity = severity,
            Category = Category,
            Remediation = "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel = 5 (DWORD) " +
                          "to send NTLMv2 only and refuse LM & NTLM. Test legacy peers first.",
            FixCommand = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Type DWord -Value 5",
        };
    }

    /// <summary>Flag a cached-logon count above the Windows default of 10.</summary>
    public static Finding AnalyzeCachedLogons(LsaHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // Null / unparsed -> treat as the OS default (10); nothing to flag.
        int count = state.CachedLogonsCount ?? DefaultCachedLogons;
        if (count <= DefaultCachedLogons)
        {
            return Finding.Pass(
                "Cached domain logon count is at or below the default",
                $"CachedLogonsCount is {count}, at or below the Windows default of {DefaultCachedLogons}. " +
                "Fewer cached credentials means fewer offline-replayable secrets on a lost device.",
                Category);
        }

        return Finding.Warning(
            "Excessive cached domain logons",
            $"CachedLogonsCount is {count}, above the Windows default of {DefaultCachedLogons}. Each cached logon " +
            "leaves a domain credential that can be attacked offline if the device is lost or stolen.",
            Category,
            remediation: "Lower HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount " +
                         "(REG_SZ) to 10 or fewer (0 disables caching entirely, but breaks offline logon).");
    }

    /// <summary>
    /// AutoAdminLogon with a DefaultPassword stored in cleartext is a Critical
    /// finding; autologon without a stored password (e.g. via LSA secret) is a
    /// Warning; no autologon passes.
    /// </summary>
    public static Finding AnalyzeAutoLogon(LsaHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.AutoAdminLogon)
        {
            return Finding.Pass(
                "Automatic logon is disabled",
                "AutoAdminLogon is off, so no account is logged on automatically at boot.",
                Category);
        }

        if (!string.IsNullOrEmpty(state.DefaultPassword))
        {
            return Finding.Critical(
                "Automatic logon password stored in cleartext",
                "AutoAdminLogon is enabled and a DefaultPassword value is present under " +
                "Winlogon. The account password is stored in the registry in CLEARTEXT " +
                "and can be read by anyone with registry access.",
                Category,
                remediation: "Disable autologon (Winlogon\\AutoAdminLogon = 0) and delete the DefaultPassword value. " +
                             "If autologon is required, use sysinternals Autologon (LSA secret) instead of a plaintext value.",
                fixCommand: "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue; " +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0");
        }

        return Finding.Warning(
            "Automatic logon is enabled",
            "AutoAdminLogon is enabled (no cleartext password found in the registry). " +
            "Automatic logon bypasses the sign-in prompt; ensure it is intentional and " +
            "the machine is physically secured.",
            Category,
            remediation: "Disable autologon by setting Winlogon\\AutoAdminLogon = 0 unless it is required for a kiosk/appliance.");
    }
}

/// <summary>
/// Raw, collector-supplied LSA / credential-protection registry state. Populated
/// by the audit module's I/O layer and handed to
/// <see cref="LsaHardeningAnalyzer"/> for a pure decision. Null numeric fields
/// mean "value absent / not readable"; the analyzer treats absence as the OS
/// default for each key.
/// </summary>
public sealed record LsaHardeningState
{
    /// <summary>HKLM\SYSTEM\...\Control\Lsa\RunAsPPL (DWORD). 1 = LSASS is a PPL.</summary>
    public int? RunAsPpl { get; init; }

    /// <summary>HKLM\SYSTEM\...\SecurityProviders\WDigest\UseLogonCredential (DWORD). 1 = plaintext creds cached.</summary>
    public int? WDigestUseLogonCredential { get; init; }

    /// <summary>HKLM\SYSTEM\...\Control\Lsa\NoLMHash (DWORD). 1 = LM hash storage disabled.</summary>
    public int? NoLmHash { get; init; }

    /// <summary>HKLM\SYSTEM\...\Control\Lsa\LmCompatibilityLevel (DWORD). 5 = NTLMv2 only, refuse LM &amp; NTLM. Null = OS default (3).</summary>
    public int? LmCompatibilityLevel { get; init; }

    /// <summary>Winlogon\CachedLogonsCount (parsed from the REG_SZ). Null = unset/default.</summary>
    public int? CachedLogonsCount { get; init; }

    /// <summary>Winlogon\AutoAdminLogon is enabled (the REG_SZ value "1").</summary>
    public bool AutoAdminLogon { get; init; }

    /// <summary>Winlogon\DefaultPassword raw value, if present (indicates a cleartext stored password).</summary>
    public string? DefaultPassword { get; init; }
}
