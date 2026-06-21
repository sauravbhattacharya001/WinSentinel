using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="EncryptionAudit"/> module.
///
/// All encryption-posture decisions live here — the parsing and classification
/// rules that turn collected raw text / registry values into <see cref="Finding"/>
/// objects: BitLocker status parsing, TPM parsing, SChannel protocol enable/disable
/// rules, weak cipher-suite detection, certificate-store weakness classification,
/// Credential Guard classification, and DPAPI master-key protection classification.
///
/// Nothing here touches the registry, PowerShell, WMI, the certificate store, the
/// clock, or the console, so the security-relevant thresholds can be unit tested
/// directly with synthetic state. The audit module owns only the collection of raw
/// data and delegates every decision to this class.
///
/// Mirrors the established <see cref="IdentityCredentialAnalyzer"/> /
/// <see cref="EventLogAnalyzer"/> pattern.
/// </summary>
public static class EncryptionAnalyzer
{
    /// <summary>Category label shared with <see cref="EncryptionAudit"/>.</summary>
    public const string Category = "Encryption";

    /// <summary>RSA key sizes below this many bits are considered weak.</summary>
    public const int MinAcceptableRsaKeyBits = 2048;

    /// <summary>Certificates expiring within this many days are "expiring soon".</summary>
    public const int ExpiringSoonDays = 30;

    /// <summary>Self-signed user-root certs above this count escalate Info to Warning.</summary>
    public const int SuspiciousRootThreshold = 3;

    /// <summary>Encryption methods recognized in BitLocker status output, strongest first.</summary>
    public static readonly IReadOnlyList<string> KnownEncryptionMethods = new[]
    {
        "XTS-AES 256", "XTS-AES 128", "AES-CBC 256", "AES-CBC 128", "AES 256", "AES 128"
    };

    /// <summary>Key-protector labels recognized in BitLocker status output.</summary>
    public static readonly IReadOnlyList<string> KnownKeyProtectors = new[]
    {
        "TPM", "Numerical Password", "Password", "External Key", "Recovery Key", "Smart Card"
    };

    /// <summary>Weak cipher tokens; any cipher-suite name containing one is flagged.</summary>
    public static readonly IReadOnlyList<string> WeakCipherTokens = new[]
    {
        "RC4", "DES", "NULL", "EXPORT", "MD5"
    };

    /// <summary>Weak certificate signature-algorithm tokens.</summary>
    public static readonly IReadOnlyList<string> WeakSignatureTokens = new[] { "SHA1", "MD5", "MD2" };

    // === BitLocker =========================================================

    /// <summary>Normalized result of parsing a single drive's BitLocker status text.</summary>
    public enum BitLockerStatus
    {
        Unavailable,
        Encrypted,
        Partial,
        NotEncrypted,
        Unknown
    }

    /// <summary>Parsed BitLocker facts for one drive, derived purely from status text.</summary>
    public sealed class BitLockerDriveState
    {
        public BitLockerStatus Status { get; set; } = BitLockerStatus.Unknown;
        public string EncryptionMethod { get; set; } = "Unknown";
        public List<string> KeyProtectors { get; set; } = new();
    }

    /// <summary>
    /// Parse manage-bde / Get-BitLockerVolume output for a single drive into a
    /// normalized state. Null/blank or "not recognized" output maps to Unavailable.
    /// </summary>
    public static BitLockerDriveState ParseBitLockerStatus(string? output)
    {
        var state = new BitLockerDriveState();

        if (string.IsNullOrWhiteSpace(output) ||
            output.Contains("is not recognized", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("not found", StringComparison.OrdinalIgnoreCase))
        {
            state.Status = BitLockerStatus.Unavailable;
            return state;
        }

        var lower = output.ToLowerInvariant();

        bool isProtected = lower.Contains("protection on") ||
                           (lower.Contains("protectionstatus") && lower.Contains(": on")) ||
                           output.Contains("ProtectionStatus      : On", StringComparison.OrdinalIgnoreCase);

        bool isFullyEncrypted = lower.Contains("percentage encrypted:    100") ||
                                lower.Contains("percentage encrypted:   100") ||
                                lower.Contains("fully encrypted") ||
                                (lower.Contains("encryptionpercentage") && lower.Contains(": 100"));

        bool isNotEncrypted = lower.Contains("fully decrypted") ||
                              lower.Contains("percentage encrypted:    0.0%") ||
                              lower.Contains("percentage encrypted:    0%") ||
                              lower.Contains("percentage encrypted: 0.0%") ||
                              lower.Contains("percentage encrypted: 0%") ||
                              (lower.Contains("encryptionpercentage") && lower.Contains(": 0"));

        // A loose "percentage encrypted" match must not override an explicit
        // decrypted / protection-off signal, otherwise a fully-decrypted volume
        // would be misreported as partially encrypted.
        bool isPartiallyEncrypted = !isFullyEncrypted && !isNotEncrypted && (
            lower.Contains("encryption in progress") ||
            (lower.Contains("percentage encrypted") && !lower.Contains("percentage encrypted:    0")));

        foreach (var method in KnownEncryptionMethods)
        {
            if (output.Contains(method, StringComparison.OrdinalIgnoreCase))
            {
                state.EncryptionMethod = method;
                break;
            }
        }

        foreach (var protector in KnownKeyProtectors)
        {
            if (output.Contains(protector, StringComparison.OrdinalIgnoreCase))
                state.KeyProtectors.Add(protector);
        }

        if (isFullyEncrypted && isProtected) state.Status = BitLockerStatus.Encrypted;
        else if (isPartiallyEncrypted) state.Status = BitLockerStatus.Partial;
        else if (isNotEncrypted || !isProtected) state.Status = BitLockerStatus.NotEncrypted;
        else state.Status = BitLockerStatus.Unknown;

        return state;
    }

    /// <summary>True when the drive letter denotes the OS / system volume (C:).</summary>
    public static bool IsSystemDrive(string? driveLetter) =>
        !string.IsNullOrEmpty(driveLetter) &&
        driveLetter.TrimStart().StartsWith("C", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Build the per-drive BitLocker finding from a parsed state. An unencrypted
    /// system drive is Critical; any other unencrypted fixed drive is Warning.
    /// </summary>
    public static Finding BuildBitLockerFinding(string driveLetter, BitLockerDriveState state)
    {
        string protectorInfo = state.KeyProtectors.Count > 0
            ? string.Join(", ", state.KeyProtectors)
            : "None detected";

        switch (state.Status)
        {
            case BitLockerStatus.Unavailable:
                return Finding.Info(
                    $"BitLocker - {driveLetter}",
                    $"BitLocker tools not available on this system for drive {driveLetter}. This edition of Windows may not support BitLocker.",
                    Category,
                    "Upgrade to Windows 10/11 Pro or Enterprise for BitLocker support.");

            case BitLockerStatus.Encrypted:
                return Finding.Pass(
                    $"BitLocker - {driveLetter} Encrypted",
                    $"Drive {driveLetter} is fully encrypted with BitLocker. Method: {state.EncryptionMethod}. Protection: ON. Key protectors: {protectorInfo}.",
                    Category);

            case BitLockerStatus.Partial:
                return Finding.Warning(
                    $"BitLocker - {driveLetter} Partially Encrypted",
                    $"Drive {driveLetter} encryption is in progress. Method: {state.EncryptionMethod}. Key protectors: {protectorInfo}.",
                    Category,
                    "Wait for encryption to complete. Do not interrupt the process.");

            case BitLockerStatus.NotEncrypted:
                var severity = IsSystemDrive(driveLetter) ? Severity.Critical : Severity.Warning;
                return new Finding
                {
                    Title = $"BitLocker - {driveLetter} Not Encrypted",
                    Description = $"Drive {driveLetter} is NOT encrypted with BitLocker. Data on this drive is accessible if the device is stolen or lost.",
                    Severity = severity,
                    Category = Category,
                    Remediation = $"Enable BitLocker encryption on drive {driveLetter} via Settings, or use manage-bde.",
                    FixCommand = $"powershell -Command \"Enable-BitLocker -MountPoint '{driveLetter}' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector\""
                };

            default:
                return Finding.Info(
                    $"BitLocker - {driveLetter} Status",
                    $"Drive {driveLetter} BitLocker status could not be fully determined. Method: {state.EncryptionMethod}. Key protectors: {protectorInfo}.",
                    Category,
                    "Run 'manage-bde -status' as Administrator for detailed status.");
        }
    }

    // === TPM ===============================================================

    /// <summary>Normalized TPM facts derived from Get-Tpm text.</summary>
    public sealed class TpmState
    {
        public bool IsPresent { get; set; }
        public bool IsReady { get; set; }
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// TPM <b>spec</b> family ("1.2", "2.0", or "Unknown") — the value that
        /// determines whether the module is outdated. This is NOT the manufacturer
        /// firmware revision; see <see cref="FirmwareVersion"/>.
        /// </summary>
        public string Version { get; set; } = "Unknown";

        /// <summary>
        /// Manufacturer firmware revision (e.g. "7.2.2.0"), purely informational.
        /// Get-Tpm only exposes this via the <c>ManufacturerVersionFull20</c> field,
        /// which itself only exists on TPM 2.0 hardware. Never use this to decide the
        /// spec generation — that's what <see cref="Version"/> is for.
        /// </summary>
        public string FirmwareVersion { get; set; } = "Unknown";
    }

    /// <summary>
    /// Parse Get-Tpm output into a TpmState.
    ///
    /// Get-Tpm does not print a literal "spec version" field, but it does expose
    /// <c>ManufacturerVersionFull20</c> — and that field is only emitted by the
    /// TPM 2.0 WMI provider. So its mere presence is a reliable TPM-2.0 signal, and
    /// its value is the manufacturer <i>firmware</i> revision (e.g. 7.2.2.0), which
    /// must not be confused with the spec generation. We record the firmware string
    /// separately and infer the spec family (2.0) from the field's presence; a
    /// genuine TPM 1.2 lacks this field, so <see cref="TpmState.Version"/> stays
    /// "Unknown" rather than being mis-derived from a firmware number.
    /// </summary>
    public static TpmState ParseTpmPowerShell(string? output)
    {
        var state = new TpmState();
        if (string.IsNullOrWhiteSpace(output)) return state;

        state.IsPresent = output.Contains("TpmPresent", StringComparison.OrdinalIgnoreCase) &&
                          output.Contains(": True", StringComparison.OrdinalIgnoreCase);
        state.IsReady = output.Contains("TpmReady", StringComparison.OrdinalIgnoreCase) &&
                        output.Contains("TpmReady                        : True", StringComparison.OrdinalIgnoreCase);
        state.IsEnabled = !output.Contains("TpmEnabled                      : False", StringComparison.OrdinalIgnoreCase);

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("ManufacturerVersionFull20", StringComparison.OrdinalIgnoreCase))
            {
                var parts = trimmed.Split(':', 2);
                if (parts.Length == 2 && parts[1].Trim().Length > 0)
                {
                    state.FirmwareVersion = parts[1].Trim();
                    // The ...Full20 field is a TPM 2.0-only construct: its presence
                    // means the module reports the 2.0 spec generation.
                    state.Version = "2.0";
                }
            }
        }

        return state;
    }

    /// <summary>Build the TPM finding from PowerShell-derived state. When the module is
    /// present but reports the outdated 1.2 spec generation, that takes precedence
    /// over the otherwise-healthy "present &amp; ready" pass — a working TPM 1.2 is
    /// still a posture gap (no Credential Guard, no Windows 11 support).
    /// </summary>
    public static Finding BuildTpmPowerShellFinding(TpmState state)
    {
        if (state.IsPresent && IsOutdatedTpmVersion(state.Version))
        {
            return Finding.Warning(
                "TPM 1.2 Detected (Outdated)",
                $"TPM is present but reports spec version {state.Version} (firmware {state.FirmwareVersion}). TPM 2.0 is required for Credential Guard and Windows 11, and is recommended for all modern hardware-backed security.",
                Category,
                "Upgrade to hardware with TPM 2.0 (Intel PTT / AMD fTPM provide firmware TPM 2.0 on modern CPUs).");
        }
        if (state.IsPresent && state.IsReady && state.IsEnabled)
        {
            return Finding.Pass(
                "TPM Present & Ready",
                $"TPM is present, enabled, and ready. Firmware: {state.FirmwareVersion}. Hardware security features are available.",
                Category);
        }
        if (state.IsPresent && !state.IsEnabled)
        {
            return Finding.Warning(
                "TPM Present but Disabled",
                $"TPM is present but not enabled. Firmware: {state.FirmwareVersion}. Hardware security features are unavailable until TPM is enabled.",
                Category,
                "Enable TPM in BIOS/UEFI settings or via tpm.msc.",
                "powershell -Command \"Start-Process 'tpm.msc'\"");
        }
        if (state.IsPresent && !state.IsReady)
        {
            return Finding.Warning(
                "TPM Present but Not Ready",
                $"TPM is present and enabled but not fully ready. Firmware: {state.FirmwareVersion}. Some security features may not work.",
                Category,
                "Open TPM management (tpm.msc) to initialize the TPM.",
                "powershell -Command \"Initialize-Tpm\"");
        }
        return Finding.Warning(
            "TPM Not Available",
            "TPM (Trusted Platform Module) is not present or not enabled. Hardware-backed security features are unavailable.",
            Category,
            "Enable TPM in BIOS/UEFI settings. Modern CPUs have firmware TPM (Intel PTT / AMD fTPM).",
            "powershell -Command \"Start-Process 'tpm.msc'\"");
    }

    /// <summary>
    /// True when a TPM spec version string denotes the outdated 1.2 generation.
    ///
    /// Accepts both a bare family string ("1.2", "2.0") and a WMI
    /// <c>Win32_Tpm.SpecVersion</c> list such as "1.2, 2, 3" or "2.0, 0, 1.59" —
    /// only the <b>first</b> comma-delimited token is the spec family, so we must
    /// not let a trailing revision field that happens to start with "1.2" (e.g.
    /// "2.0, 0, 1.2") be misread as an outdated module.
    /// </summary>
    public static bool IsOutdatedTpmVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return false;
        var family = version.Split(',', 2)[0].Trim();
        return family.StartsWith("1.2", StringComparison.OrdinalIgnoreCase);
    }

    // === TLS / SChannel protocols ==========================================

    /// <summary>
    /// Decide whether a protocol is enabled given the SChannel Enabled and
    /// DisabledByDefault registry values (use -1 for "not present"). Explicit
    /// Enabled wins; a missing key is treated as not-enabled (system default).
    /// </summary>
    public static bool IsProtocolEnabled(int enabledValue, int disabledByDefaultValue)
    {
        if (enabledValue == 0) return false;
        if (enabledValue == 1) return true;
        if (disabledByDefaultValue == 1) return false;
        return false;
    }

    /// <summary>True only when Enabled is explicitly 0 (a modern protocol turned off).</summary>
    public static bool IsProtocolExplicitlyDisabled(int enabledValue) => enabledValue == 0;

    /// <summary>
    /// Build the legacy-protocol finding. SSL protocols are Critical when enabled,
    /// TLS 1.0/1.1 are Warning.
    /// </summary>
    public static Finding BuildLegacyProtocolFinding(string protocol, bool clientEnabled, bool serverEnabled, string schannelPath)
    {
        if (!clientEnabled && !serverEnabled)
        {
            return Finding.Pass(
                $"{protocol} Disabled",
                $"{protocol} is disabled or not configured (system default). This is the recommended setting.",
                Category);
        }

        var side = clientEnabled && serverEnabled ? "client and server"
            : clientEnabled ? "client" : "server";

        return new Finding
        {
            Title = $"{protocol} Still Enabled",
            Description = $"{protocol} is enabled for {side} connections. This protocol has known vulnerabilities (POODLE, BEAST, etc.) and should be disabled.",
            Severity = protocol.Contains("SSL", StringComparison.OrdinalIgnoreCase) ? Severity.Critical : Severity.Warning,
            Category = Category,
            Remediation = $"Disable {protocol} via registry or Group Policy. Path: {schannelPath}\\{protocol}",
            FixCommand = $"powershell -Command \"New-Item 'HKLM:\\{schannelPath}\\{protocol}\\Client' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\{schannelPath}\\{protocol}\\Client' -Name 'Enabled' -Value 0 -Type DWord\""
        };
    }

    /// <summary>
    /// Build the modern-protocol finding. Explicitly disabling TLS 1.2/1.3 is Critical;
    /// otherwise Pass.
    /// </summary>
    public static Finding BuildModernProtocolFinding(string protocol, bool clientDisabled, bool serverDisabled, string schannelPath)
    {
        if (!clientDisabled && !serverDisabled)
        {
            return Finding.Pass(
                $"{protocol} Enabled",
                $"{protocol} is enabled (system default or explicitly configured). Modern TLS is available.",
                Category);
        }

        var side = clientDisabled && serverDisabled ? "client and server"
            : clientDisabled ? "client" : "server";

        return Finding.Critical(
            $"{protocol} Disabled",
            $"{protocol} has been explicitly disabled for {side} connections. This weakens security and may cause connectivity issues with modern services.",
            Category,
            $"Re-enable {protocol} by removing or modifying the registry key at {schannelPath}\\{protocol}.",
            $"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\{schannelPath}\\{protocol}\\Client' -Name 'Enabled' -Value 1 -Type DWord -ErrorAction SilentlyContinue\"");
    }

    // === Cipher suites =====================================================

    /// <summary>
    /// From a comma-separated SChannel Functions cipher-suite list, return the suites
    /// that contain a known-weak token (RC4/DES/NULL/EXPORT/MD5), in order. Blank
    /// entries dropped. Null/blank input returns empty.
    /// </summary>
    public static IReadOnlyList<string> FindWeakCipherSuites(string? functions)
    {
        var weak = new List<string>();
        if (string.IsNullOrWhiteSpace(functions)) return weak;

        var suites = functions.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        foreach (var suite in suites)
        {
            foreach (var token in WeakCipherTokens)
            {
                if (suite.Contains(token, StringComparison.OrdinalIgnoreCase))
                {
                    weak.Add(suite);
                    break;
                }
            }
        }
        return weak;
    }

    /// <summary>
    /// Build the cipher-suite finding. Null/blank functions -> Info (system default).
    /// Any weak suite -> Warning; otherwise Pass.
    /// </summary>
    public static Finding BuildCipherSuiteFinding(string? functions)
    {
        if (string.IsNullOrEmpty(functions))
        {
            return Finding.Info(
                "Cipher Suite Order - System Default",
                "No custom cipher suite order configured. Windows is using its default cipher suite selection, which is generally secure on modern Windows versions.",
                Category);
        }

        var suites = functions.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var weak = FindWeakCipherSuites(functions);

        if (weak.Count > 0)
        {
            return Finding.Warning(
                $"Weak Cipher Suites Configured ({weak.Count})",
                $"Found {weak.Count} weak cipher suite(s) in the configured order: {string.Join(", ", weak.Take(5))}. These use broken cryptographic algorithms.",
                Category,
                "Remove weak cipher suites (RC4, DES, NULL, EXPORT, MD5) from the cipher suite order via Group Policy or registry.");
        }

        return Finding.Pass(
            "Cipher Suite Order Configured",
            $"Custom cipher suite order is configured with {suites.Length} suite(s), none using known-weak algorithms.",
            Category);
    }

    // === Certificate store =================================================

    /// <summary>Per-certificate facts the audit collects from the X509 store.</summary>
    public sealed class CertFact
    {
        /// <summary>Display name (FriendlyName or CN).</summary>
        public string DisplayName { get; set; } = "";
        /// <summary>Expiry (NotAfter), UTC.</summary>
        public DateTime NotAfter { get; set; }
        /// <summary>True when this is an RSA certificate.</summary>
        public bool IsRsa { get; set; }
        /// <summary>RSA key size in bits (0 when unknown / non-RSA).</summary>
        public int RsaKeyBits { get; set; }
        /// <summary>Signature-algorithm friendly name (e.g. "sha256RSA").</summary>
        public string SignatureAlgorithm { get; set; } = "";
    }

    /// <summary>Counts derived from classifying a personal-store certificate set.</summary>
    public sealed class CertStoreSummary
    {
        public int Total { get; set; }
        public int Expired { get; set; }
        public int ExpiringSoon { get; set; }
        public int WeakKey { get; set; }
        public int WeakSignature { get; set; }
        public List<string> Issues { get; } = new();
        public bool IsClean => Expired == 0 && ExpiringSoon == 0 && WeakKey == 0 && WeakSignature == 0;
    }

    /// <summary>True when an RSA key size is below <see cref="MinAcceptableRsaKeyBits"/>.</summary>
    public static bool IsWeakRsaKey(bool isRsa, int keyBits) => isRsa && keyBits > 0 && keyBits < MinAcceptableRsaKeyBits;

    /// <summary>True when a signature-algorithm name uses SHA1, MD5, or MD2.</summary>
    public static bool IsWeakSignature(string? signatureAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(signatureAlgorithm)) return false;
        foreach (var token in WeakSignatureTokens)
        {
            if (signatureAlgorithm.Contains(token, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>
    /// Classify a set of personal-store certificates against a reference clock.
    /// Pure: the caller supplies <paramref name="now"/> so expiry math is deterministic.
    /// </summary>
    public static CertStoreSummary ClassifyCertificates(IEnumerable<CertFact>? certs, DateTime now)
    {
        var summary = new CertStoreSummary();
        if (certs is null) return summary;

        var soonThreshold = now.AddDays(ExpiringSoonDays);

        foreach (var cert in certs)
        {
            if (cert is null) continue;
            summary.Total++;
            var name = string.IsNullOrWhiteSpace(cert.DisplayName) ? "(unnamed)" : cert.DisplayName;

            if (cert.NotAfter < now)
            {
                summary.Expired++;
                summary.Issues.Add($"EXPIRED: {name} (expired {cert.NotAfter:yyyy-MM-dd})");
            }
            else if (cert.NotAfter < soonThreshold)
            {
                summary.ExpiringSoon++;
                summary.Issues.Add($"EXPIRING SOON: {name} (expires {cert.NotAfter:yyyy-MM-dd})");
            }

            if (IsWeakRsaKey(cert.IsRsa, cert.RsaKeyBits))
            {
                summary.WeakKey++;
                summary.Issues.Add($"WEAK KEY: {name} (RSA {cert.RsaKeyBits}-bit)");
            }

            if (IsWeakSignature(cert.SignatureAlgorithm))
            {
                summary.WeakSignature++;
                summary.Issues.Add($"WEAK SIGNATURE: {name} ({cert.SignatureAlgorithm})");
            }
        }

        return summary;
    }

    /// <summary>
    /// Build the personal-certificate-store findings (zero..four warnings, or one Pass
    /// when clean) from a classified summary.
    /// </summary>
    public static IReadOnlyList<Finding> BuildCertificateFindings(CertStoreSummary summary)
    {
        var findings = new List<Finding>();

        if (summary.Expired > 0)
        {
            findings.Add(Finding.Warning(
                $"Expired Certificates ({summary.Expired})",
                $"Found {summary.Expired} expired certificate(s) in personal store. Expired certificates should be removed or renewed.",
                Category,
                "Remove expired certificates from the personal certificate store: certmgr.msc."));
        }
        if (summary.ExpiringSoon > 0)
        {
            findings.Add(Finding.Warning(
                $"Certificates Expiring Soon ({summary.ExpiringSoon})",
                $"Found {summary.ExpiringSoon} certificate(s) expiring within {ExpiringSoonDays} days. Renew or replace them before they expire.",
                Category,
                "Renew certificates before they expire to avoid service disruptions."));
        }
        if (summary.WeakKey > 0)
        {
            findings.Add(Finding.Warning(
                $"Weak Certificate Keys ({summary.WeakKey})",
                $"Found {summary.WeakKey} certificate(s) with RSA key size below {MinAcceptableRsaKeyBits} bits. These are considered cryptographically weak.",
                Category,
                "Replace certificates with RSA 2048-bit or stronger keys. Consider ECDSA P-256 or higher for new certificates."));
        }
        if (summary.WeakSignature > 0)
        {
            findings.Add(Finding.Warning(
                $"Weak Signature Algorithms ({summary.WeakSignature})",
                $"Found {summary.WeakSignature} certificate(s) using SHA1, MD5, or MD2 signature algorithms. These are considered insecure.",
                Category,
                "Replace certificates signed with SHA1/MD5 with SHA-256 or stronger algorithms."));
        }

        if (summary.IsClean)
        {
            findings.Add(Finding.Pass(
                "Personal Certificate Store Healthy",
                $"All {summary.Total} certificate(s) in the personal store are valid with adequate key sizes and modern signature algorithms.",
                Category));
        }

        return findings;
    }

    /// <summary>
    /// Build the user trusted-root finding from the count of self-signed user-root
    /// certs. 0 (and no certs at all) -> Pass; 1..threshold -> Info; above -> Warning.
    /// </summary>
    public static Finding BuildTrustedRootFinding(int userRootCertCount, int selfSignedCount, IEnumerable<string>? selfSignedNames)
    {
        if (userRootCertCount <= 0)
        {
            return Finding.Pass(
                "Trusted Root Store Clean",
                "No user-level trusted root certificates found. The trusted root store has not been modified.",
                Category);
        }

        var names = (selfSignedNames ?? Enumerable.Empty<string>()).Where(n => !string.IsNullOrWhiteSpace(n)).ToList();

        if (selfSignedCount > SuspiciousRootThreshold)
        {
            return Finding.Warning(
                $"Suspicious Trusted Root Certificates ({selfSignedCount})",
                $"Found {selfSignedCount} self-signed certificate(s) in the Current User trusted root store: {string.Join("; ", names.Take(5))}. These could be from MITM proxies, adware, or debugging tools.",
                Category,
                "Review user-level trusted root certificates via certmgr.msc. Remove any that are not recognized.");
        }

        if (selfSignedCount > 0)
        {
            return Finding.Info(
                $"User Trusted Root Certificates ({selfSignedCount})",
                $"Found {selfSignedCount} self-signed certificate(s) in the user trusted root store: {string.Join("; ", names)}. This is common for development tools (Fiddler, mitmproxy) or corporate environments.",
                Category,
                "Review certificates via certmgr.msc if unexpected.");
        }

        return Finding.Pass(
            "Trusted Root Store Clean",
            "User trusted root store contains no self-signed certificates of concern.",
            Category);
    }

    // === Credential Guard ==================================================

    /// <summary>Collected Credential Guard / VBS signals.</summary>
    public sealed class CredentialGuardState
    {
        /// <summary>LsaCfgFlags registry value (-1 = not present).</summary>
        public int LsaCfgFlags { get; set; } = -1;
        /// <summary>EnableVirtualizationBasedSecurity registry value (-1 = not present).</summary>
        public int DeviceGuardEnabled { get; set; } = -1;
        /// <summary>Human VBS status string ("Running", "Not enabled", "Unknown", ...).</summary>
        public string VbsStatus { get; set; } = "Unknown";
        /// <summary>True when SecurityServicesRunning includes Credential Guard (1).</summary>
        public bool CredentialGuardRunning { get; set; }
        /// <summary>True when configured-but-not-running was detected via WMI.</summary>
        public bool CredentialGuardConfigured { get; set; }
    }

    /// <summary>Build the Credential Guard finding from collected state.</summary>
    public static Finding BuildCredentialGuardFinding(CredentialGuardState state)
    {
        bool isRunning = state.CredentialGuardRunning;
        bool isConfigured = state.LsaCfgFlags > 0 || state.CredentialGuardConfigured || state.DeviceGuardEnabled == 1;

        if (isRunning)
        {
            return Finding.Pass(
                "Credential Guard Running",
                $"Windows Credential Guard is running (VBS: {state.VbsStatus}). Credentials are protected by virtualization-based security.",
                Category);
        }
        if (isConfigured)
        {
            return Finding.Warning(
                "Credential Guard Configured but Not Running",
                $"Credential Guard is configured (LsaCfgFlags: {state.LsaCfgFlags}, VBS: {state.VbsStatus}) but is not currently running. A reboot may be required, or hardware requirements may not be met.",
                Category,
                "Ensure UEFI Secure Boot, virtualization extensions, and TPM 2.0 are available. Reboot the system.",
                "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LsaCfgFlags' -Value 1 -Type DWord\"");
        }
        return Finding.Warning(
            "Credential Guard Not Enabled",
            "Windows Credential Guard is not enabled. Without it, credentials (NTLM hashes, Kerberos tickets) are stored in normal memory and vulnerable to theft by tools like Mimikatz.",
            Category,
            "Enable Credential Guard via Group Policy: Device Guard -> Turn On Virtualization Based Security. Requires UEFI, Secure Boot, and TPM 2.0.",
            "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LsaCfgFlags' -Value 1 -Type DWord\"");
    }

    // === DPAPI =============================================================

    /// <summary>Collected DPAPI master-key signals.</summary>
    public sealed class DpapiState
    {
        /// <summary>True when at least one master-key file was found.</summary>
        public bool MasterKeysExist { get; set; }
        /// <summary>Number of master-key files found.</summary>
        public int KeyFileCount { get; set; }
        /// <summary>True when the machine is domain-joined.</summary>
        public bool IsDomainJoined { get; set; }
        /// <summary>LsaCfgFlags value (>0 means Credential Guard configured).</summary>
        public int LsaCfgFlags { get; set; }
    }

    /// <summary>Build the DPAPI finding from collected state.</summary>
    public static Finding BuildDpapiFinding(DpapiState state)
    {
        if (!state.MasterKeysExist)
        {
            return Finding.Info(
                "DPAPI Master Keys Not Found",
                "No DPAPI master key files found. This may be normal for a fresh user profile, or the profile path may be non-standard.",
                Category);
        }

        if (state.LsaCfgFlags > 0)
        {
            return Finding.Pass(
                "DPAPI Protected by Credential Guard",
                $"DPAPI master keys exist ({state.KeyFileCount} key files) and Credential Guard is enabled, providing additional protection for derived credentials.",
                Category);
        }
        if (state.IsDomainJoined)
        {
            return Finding.Pass(
                "DPAPI Master Keys Present (Domain)",
                $"DPAPI master keys exist ({state.KeyFileCount} key files). Domain-joined machine - keys are backed up to the domain controller for recovery.",
                Category);
        }
        return Finding.Info(
            "DPAPI Master Keys Present",
            $"DPAPI master keys exist ({state.KeyFileCount} key files). Keys are protected by the user's password. Ensure a strong login password is used, as DPAPI key security depends on it.",
            Category,
            "Use a strong login password. Consider enabling Credential Guard for enhanced DPAPI protection.");
    }
}
