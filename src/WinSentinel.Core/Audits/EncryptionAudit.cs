using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits encryption configuration: BitLocker, TPM, EFS, certificate store health,
/// TLS/SSL protocol configuration, Credential Guard, and DPAPI protection.
/// </summary>
public class EncryptionAudit : IAuditModule
{
    public string Name => "Encryption Audit";
    public string Category => "Encryption";
    public string Description => "Checks BitLocker status, TPM availability, EFS usage, certificate store health, TLS/SSL configuration, Credential Guard, and DPAPI protection.";

    private const string SchannelProtocolsPath =
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    private static readonly string[] LegacyProtocols = { "TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0" };
    private static readonly string[] ModernProtocols = { "TLS 1.2", "TLS 1.3" };

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            await CheckBitLockerStatus(result, cancellationToken);
            await CheckTpmStatus(result, cancellationToken);
            CheckEfsAvailability(result);
            CheckCertificateStore(result);
            CheckTlsSslConfiguration(result);
            await CheckCredentialGuard(result, cancellationToken);
            await CheckDpapiProtection(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    #region BitLocker

    private async Task CheckBitLockerStatus(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Get fixed drives
            var drives = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                .ToList();

            if (drives.Count == 0)
            {
                result.Findings.Add(Finding.Info(
                    "No Fixed Drives",
                    "No fixed drives detected to check for BitLocker encryption.",
                    Category));
                return;
            }

            foreach (var drive in drives)
            {
                await CheckDriveBitLocker(result, drive.Name.TrimEnd('\\'), ct);
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "BitLocker Check Error",
                $"Could not check BitLocker status: {ex.Message}. This may require administrator privileges.",
                Category,
                "Run WinSentinel as Administrator to check BitLocker status."));
        }
    }

    private async Task CheckDriveBitLocker(AuditResult result, string driveLetter, CancellationToken ct)
    {
        try
        {
            // Use manage-bde -status to get BitLocker info
            var output = await ShellHelper.RunCmdAsync($"manage-bde -status {driveLetter}", ct);

            if (string.IsNullOrWhiteSpace(output))
            {
                // Fallback: try PowerShell Get-BitLockerVolume
                output = await PowerShellHelper.RunCommandAsync(
                    $"Get-BitLockerVolume -MountPoint '{driveLetter}' | Format-List *", ct);
            }

            if (string.IsNullOrWhiteSpace(output) ||
                output.Contains("is not recognized", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("not found", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Info(
                    $"BitLocker — {driveLetter}",
                    $"BitLocker tools not available on this system for drive {driveLetter}. This edition of Windows may not support BitLocker.",
                    Category,
                    "Upgrade to Windows 10/11 Pro or Enterprise for BitLocker support."));
                return;
            }

            var outputLower = output.ToLowerInvariant();

            // Parse protection status
            bool isProtected = outputLower.Contains("protection on") ||
                               outputLower.Contains("protectionstatus") && outputLower.Contains(": on") ||
                               output.Contains("ProtectionStatus      : On", StringComparison.OrdinalIgnoreCase);

            // Parse encryption status
            bool isFullyEncrypted = outputLower.Contains("percentage encrypted:    100") ||
                                    outputLower.Contains("percentage encrypted:   100") ||
                                    outputLower.Contains("fully encrypted") ||
                                    (outputLower.Contains("encryptionpercentage") && outputLower.Contains(": 100"));

            bool isPartiallyEncrypted = !isFullyEncrypted && (
                outputLower.Contains("encryption in progress") ||
                outputLower.Contains("percentage encrypted") && !outputLower.Contains("percentage encrypted:    0"));

            bool isNotEncrypted = outputLower.Contains("fully decrypted") ||
                                  outputLower.Contains("percentage encrypted:    0.0%") ||
                                  outputLower.Contains("percentage encrypted:    0%") ||
                                  (outputLower.Contains("encryptionpercentage") && outputLower.Contains(": 0"));

            // Parse encryption method
            string encryptionMethod = "Unknown";
            foreach (var method in new[] { "XTS-AES 256", "XTS-AES 128", "AES-CBC 256", "AES-CBC 128", "AES 256", "AES 128" })
            {
                if (output.Contains(method, StringComparison.OrdinalIgnoreCase))
                {
                    encryptionMethod = method;
                    break;
                }
            }

            // Parse key protectors
            var keyProtectors = new List<string>();
            foreach (var protector in new[] { "TPM", "Numerical Password", "Password", "External Key", "Recovery Key", "Smart Card" })
            {
                if (output.Contains(protector, StringComparison.OrdinalIgnoreCase))
                    keyProtectors.Add(protector);
            }

            // Build description
            string protectorInfo = keyProtectors.Count > 0
                ? string.Join(", ", keyProtectors)
                : "None detected";

            if (isFullyEncrypted && isProtected)
            {
                result.Findings.Add(Finding.Pass(
                    $"BitLocker — {driveLetter} Encrypted",
                    $"Drive {driveLetter} is fully encrypted with BitLocker. Method: {encryptionMethod}. Protection: ON. Key protectors: {protectorInfo}.",
                    Category));
            }
            else if (isPartiallyEncrypted)
            {
                result.Findings.Add(Finding.Warning(
                    $"BitLocker — {driveLetter} Partially Encrypted",
                    $"Drive {driveLetter} encryption is in progress. Method: {encryptionMethod}. Key protectors: {protectorInfo}.",
                    Category,
                    "Wait for encryption to complete. Do not interrupt the process."));
            }
            else if (isNotEncrypted || !isProtected)
            {
                bool isSystemDrive = driveLetter.StartsWith("C", StringComparison.OrdinalIgnoreCase);
                var severity = isSystemDrive ? Severity.Critical : Severity.Warning;

                result.Findings.Add(new Finding
                {
                    Title = $"BitLocker — {driveLetter} Not Encrypted",
                    Description = $"Drive {driveLetter} is NOT encrypted with BitLocker. Data on this drive is accessible if the device is stolen or lost.",
                    Severity = severity,
                    Category = Category,
                    Remediation = $"Enable BitLocker encryption on drive {driveLetter} via Settings → Privacy & Security → Device encryption, or use manage-bde.",
                    FixCommand = $"powershell -Command \"Enable-BitLocker -MountPoint '{driveLetter}' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector\""
                });
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    $"BitLocker — {driveLetter} Status",
                    $"Drive {driveLetter} BitLocker status could not be fully determined. Method: {encryptionMethod}. Key protectors: {protectorInfo}.",
                    Category,
                    "Run 'manage-bde -status' as Administrator for detailed status."));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                $"BitLocker — {driveLetter} Error",
                $"Could not check BitLocker status for {driveLetter}: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator for BitLocker checks."));
        }
    }

    #endregion

    #region TPM

    private async Task CheckTpmStatus(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Try PowerShell Get-Tpm first
            var tpmOutput = await PowerShellHelper.RunCommandAsync("Get-Tpm | Format-List *", ct);

            if (!string.IsNullOrWhiteSpace(tpmOutput) &&
                !tpmOutput.Contains("not recognized", StringComparison.OrdinalIgnoreCase) &&
                !tpmOutput.Contains("error", StringComparison.OrdinalIgnoreCase))
            {
                ParseTpmPowerShell(result, tpmOutput);
                return;
            }

            // Fallback: try WMI
            try
            {
                var tpmResults = WmiHelper.Query(
                    "SELECT * FROM Win32_Tpm",
                    @"root\cimv2\Security\MicrosoftTpm");

                if (tpmResults.Count > 0)
                {
                    ParseTpmWmi(result, tpmResults[0]);
                    return;
                }
            }
            catch
            {
                // WMI namespace may not exist
            }

            // Fallback: check registry
            var tpmRegVersion = RegistryHelper.GetValue<string>(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\TPM\WMI",
                "SpecVersion");

            if (!string.IsNullOrEmpty(tpmRegVersion))
            {
                result.Findings.Add(Finding.Info(
                    "TPM Detected (Registry)",
                    $"TPM detected via registry. Spec version: {tpmRegVersion}. Run as Administrator for full TPM status.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Warning(
                    "TPM Not Detected",
                    "No TPM (Trusted Platform Module) was detected on this system. TPM is required for BitLocker, Credential Guard, and hardware-backed security.",
                    Category,
                    "Check BIOS/UEFI settings to enable TPM. Modern systems typically have TPM 2.0 built into the CPU (Intel PTT / AMD fTPM).",
                    "powershell -Command \"Start-Process 'tpm.msc'\""));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "TPM Check Error",
                $"Could not determine TPM status: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator to check TPM status."));
        }
    }

    private void ParseTpmPowerShell(AuditResult result, string output)
    {
        bool isPresent = output.Contains("TpmPresent", StringComparison.OrdinalIgnoreCase) &&
                         output.Contains(": True", StringComparison.OrdinalIgnoreCase);
        bool isReady = output.Contains("TpmReady", StringComparison.OrdinalIgnoreCase) &&
                       output.Contains("TpmReady                        : True", StringComparison.OrdinalIgnoreCase);
        bool isEnabled = !output.Contains("TpmEnabled                      : False", StringComparison.OrdinalIgnoreCase);

        // Try to extract version from ManufacturerVersion or ManufacturerVersionFull20
        string version = "Unknown";
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("ManufacturerVersionFull20", StringComparison.OrdinalIgnoreCase))
            {
                var parts = trimmed.Split(':', 2);
                if (parts.Length == 2) version = parts[1].Trim();
            }
        }

        if (isPresent && isReady)
        {
            result.Findings.Add(Finding.Pass(
                "TPM Present & Ready",
                $"TPM is present, enabled, and ready. Version: {version}. Hardware security features are available.",
                Category));
        }
        else if (isPresent && !isReady)
        {
            result.Findings.Add(Finding.Warning(
                "TPM Present but Not Ready",
                $"TPM is present but not fully ready. Version: {version}. Some security features may not work.",
                Category,
                "Open TPM management (tpm.msc) to initialize the TPM.",
                "powershell -Command \"Initialize-Tpm\""));
        }
        else
        {
            result.Findings.Add(Finding.Warning(
                "TPM Not Available",
                "TPM (Trusted Platform Module) is not present or not enabled. Hardware-backed security features are unavailable.",
                Category,
                "Enable TPM in BIOS/UEFI settings. Modern CPUs have firmware TPM (Intel PTT / AMD fTPM).",
                "powershell -Command \"Start-Process 'tpm.msc'\""));
        }
    }

    private void ParseTpmWmi(AuditResult result, Dictionary<string, object?> tpm)
    {
        bool isEnabled = tpm.TryGetValue("IsEnabled_InitialValue", out var enabled) && enabled is true;
        bool isActivated = tpm.TryGetValue("IsActivated_InitialValue", out var activated) && activated is true;
        string version = tpm.TryGetValue("SpecVersion", out var ver) ? ver?.ToString() ?? "Unknown" : "Unknown";

        if (isEnabled && isActivated)
        {
            result.Findings.Add(Finding.Pass(
                "TPM Enabled & Activated",
                $"TPM is enabled and activated. Spec version: {version}.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning(
                "TPM Not Fully Active",
                $"TPM found (version: {version}) but is not fully enabled/activated. Enabled: {isEnabled}, Activated: {isActivated}.",
                Category,
                "Enable and activate TPM in BIOS/UEFI settings."));
        }

        // Check TPM version - flag 1.2 as warning
        if (version.StartsWith("1.2", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "TPM 1.2 Detected (Outdated)",
                "TPM version 1.2 is installed. TPM 2.0 is recommended for modern security features including Credential Guard and Windows 11 compatibility.",
                Category,
                "Consider upgrading hardware to support TPM 2.0."));
        }
    }

    #endregion

    #region EFS

    private void CheckEfsAvailability(AuditResult result)
    {
        try
        {
            // Check if EFS service is running
            bool efsServiceExists = false;
            try
            {
                var efsRegPath = @"SYSTEM\CurrentControlSet\Services\EFS";
                var startValue = RegistryHelper.GetValue<int>(
                    RegistryHive.LocalMachine, efsRegPath, "Start", -1);
                efsServiceExists = startValue >= 0;
            }
            catch { }

            // Check for EFS certificates in user's certificate store
            int efsCertCount = 0;
            var efsOid = "1.3.6.1.4.1.311.10.3.4"; // EFS OID
            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);
                foreach (var cert in store.Certificates)
                {
                    foreach (var ext in cert.Extensions)
                    {
                        if (ext is X509EnhancedKeyUsageExtension eku)
                        {
                            foreach (var oid in eku.EnhancedKeyUsages)
                            {
                                if (oid.Value == efsOid)
                                {
                                    efsCertCount++;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            // Check EFS disable policy
            var efsDisabled = RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\EFS",
                "EfsConfiguration", 0);

            if (efsDisabled == 1)
            {
                result.Findings.Add(Finding.Info(
                    "EFS Disabled by Policy",
                    "Encrypting File System (EFS) has been disabled by group policy. File-level encryption is not available.",
                    Category,
                    "Enable EFS via Group Policy if file-level encryption is needed."));
            }
            else if (efsCertCount > 0)
            {
                result.Findings.Add(Finding.Pass(
                    "EFS Available with Certificates",
                    $"EFS is available and {efsCertCount} EFS certificate(s) found in the user's personal store. File-level encryption is configured.",
                    Category));
            }
            else if (efsServiceExists)
            {
                result.Findings.Add(Finding.Info(
                    "EFS Available (No Certificates)",
                    "EFS service is available but no EFS certificates found. EFS can be used for file-level encryption on demand — a certificate will be auto-generated on first use.",
                    Category,
                    "To encrypt a file: right-click → Properties → Advanced → Encrypt contents."));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "EFS Not Available",
                    "EFS (Encrypting File System) does not appear to be available on this system edition.",
                    Category));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "EFS Check Error",
                $"Could not check EFS status: {ex.Message}",
                Category));
        }
    }

    #endregion

    #region Certificate Store

    private void CheckCertificateStore(AuditResult result)
    {
        try
        {
            var now = DateTime.UtcNow;
            var soonThreshold = now.AddDays(30);
            int expiredCount = 0;
            int expiringSoonCount = 0;
            int weakKeyCount = 0;
            int weakSigCount = 0;
            int totalCerts = 0;
            var issues = new List<string>();

            // Check personal certificate store
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                totalCerts = store.Certificates.Count;

                foreach (var cert in store.Certificates)
                {
                    // Check expired
                    if (cert.NotAfter < now)
                    {
                        expiredCount++;
                        issues.Add($"EXPIRED: {GetCertDisplayName(cert)} (expired {cert.NotAfter:yyyy-MM-dd})");
                    }
                    // Check expiring soon
                    else if (cert.NotAfter < soonThreshold)
                    {
                        expiringSoonCount++;
                        issues.Add($"EXPIRING SOON: {GetCertDisplayName(cert)} (expires {cert.NotAfter:yyyy-MM-dd})");
                    }

                    // Check weak key size (RSA < 2048)
                    if (cert.PublicKey.Oid.FriendlyName?.Contains("RSA", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        try
                        {
                            using var rsa = cert.GetRSAPublicKey();
                            if (rsa != null && rsa.KeySize < 2048)
                            {
                                weakKeyCount++;
                                issues.Add($"WEAK KEY: {GetCertDisplayName(cert)} (RSA {rsa.KeySize}-bit)");
                            }
                        }
                        catch { }
                    }

                    // Check weak signature algorithm
                    var sigAlg = cert.SignatureAlgorithm.FriendlyName ?? "";
                    if (sigAlg.Contains("SHA1", StringComparison.OrdinalIgnoreCase) ||
                        sigAlg.Contains("MD5", StringComparison.OrdinalIgnoreCase) ||
                        sigAlg.Contains("MD2", StringComparison.OrdinalIgnoreCase))
                    {
                        weakSigCount++;
                        issues.Add($"WEAK SIGNATURE: {GetCertDisplayName(cert)} ({sigAlg})");
                    }
                }
            }

            // Report personal store findings
            if (expiredCount > 0)
            {
                result.Findings.Add(Finding.Warning(
                    $"Expired Certificates ({expiredCount})",
                    $"Found {expiredCount} expired certificate(s) in personal store. Expired certificates should be removed or renewed.",
                    Category,
                    "Remove expired certificates from the personal certificate store: certmgr.msc → Personal → Certificates.",
                    "powershell -Command \"Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.NotAfter -lt (Get-Date) } | Format-List Subject, NotAfter\""));
            }

            if (expiringSoonCount > 0)
            {
                result.Findings.Add(Finding.Warning(
                    $"Certificates Expiring Soon ({expiringSoonCount})",
                    $"Found {expiringSoonCount} certificate(s) expiring within 30 days. Renew or replace them before they expire.",
                    Category,
                    "Renew certificates before they expire to avoid service disruptions."));
            }

            if (weakKeyCount > 0)
            {
                result.Findings.Add(Finding.Warning(
                    $"Weak Certificate Keys ({weakKeyCount})",
                    $"Found {weakKeyCount} certificate(s) with RSA key size below 2048 bits. These are considered cryptographically weak.",
                    Category,
                    "Replace certificates with RSA 2048-bit or stronger keys. Consider ECDSA P-256 or higher for new certificates."));
            }

            if (weakSigCount > 0)
            {
                result.Findings.Add(Finding.Warning(
                    $"Weak Signature Algorithms ({weakSigCount})",
                    $"Found {weakSigCount} certificate(s) using SHA1, MD5, or MD2 signature algorithms. These are considered insecure.",
                    Category,
                    "Replace certificates signed with SHA1/MD5 with SHA-256 or stronger algorithms."));
            }

            if (expiredCount == 0 && weakKeyCount == 0 && weakSigCount == 0 && expiringSoonCount == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "Personal Certificate Store Healthy",
                    $"All {totalCerts} certificate(s) in the personal store are valid with adequate key sizes and modern signature algorithms.",
                    Category));
            }

            // Check trusted root for suspicious self-signed certificates
            CheckTrustedRootStore(result);
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "Certificate Store Check Error",
                $"Could not fully audit certificate stores: {ex.Message}",
                Category));
        }
    }

    private void CheckTrustedRootStore(AuditResult result)
    {
        try
        {
            int suspiciousCount = 0;
            var suspiciousCerts = new List<string>();

            // Check user-installed trusted root certificates (not from Windows Update)
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            foreach (var cert in store.Certificates)
            {
                // User-level trusted root certs are suspicious — they're often from
                // adware, corporate proxies, or Fiddler/Burp/mitmproxy
                var subject = cert.Subject;
                var issuer = cert.Issuer;

                // Self-signed: subject == issuer
                bool selfSigned = string.Equals(subject, issuer, StringComparison.OrdinalIgnoreCase);

                if (selfSigned)
                {
                    suspiciousCount++;
                    suspiciousCerts.Add(GetCertDisplayName(cert));
                }
            }

            // User-level root certs are unusual
            if (store.Certificates.Count > 0)
            {
                if (suspiciousCount > 3)
                {
                    result.Findings.Add(Finding.Warning(
                        $"Suspicious Trusted Root Certificates ({suspiciousCount})",
                        $"Found {suspiciousCount} self-signed certificate(s) in the Current User trusted root store: {string.Join("; ", suspiciousCerts.Take(5))}. These could be from MITM proxies, adware, or debugging tools.",
                        Category,
                        "Review user-level trusted root certificates via certmgr.msc → Trusted Root Certification Authorities. Remove any that are not recognized.",
                        "powershell -Command \"Get-ChildItem Cert:\\CurrentUser\\Root | Format-List Subject, Issuer, NotAfter\""));
                }
                else if (suspiciousCount > 0)
                {
                    result.Findings.Add(Finding.Info(
                        $"User Trusted Root Certificates ({suspiciousCount})",
                        $"Found {suspiciousCount} self-signed certificate(s) in the user trusted root store: {string.Join("; ", suspiciousCerts)}. This is common for development tools (Fiddler, mitmproxy) or corporate environments.",
                        Category,
                        "Review certificates via certmgr.msc if unexpected."));
                }
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Trusted Root Store Clean",
                    "No user-level trusted root certificates found. The trusted root store has not been modified.",
                    Category));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "Trusted Root Check Error",
                $"Could not check trusted root store: {ex.Message}",
                Category));
        }
    }

    private static string GetCertDisplayName(X509Certificate2 cert)
    {
        if (!string.IsNullOrEmpty(cert.FriendlyName))
            return cert.FriendlyName;

        var subject = cert.Subject;
        // Extract CN= value
        var cnIndex = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
        if (cnIndex >= 0)
        {
            var start = cnIndex + 3;
            var end = subject.IndexOf(',', start);
            return end > start ? subject[start..end] : subject[start..];
        }

        return subject.Length > 50 ? subject[..50] + "..." : subject;
    }

    #endregion

    #region TLS/SSL Configuration

    private void CheckTlsSslConfiguration(AuditResult result)
    {
        try
        {
            // Check legacy protocols (should be disabled)
            foreach (var protocol in LegacyProtocols)
            {
                CheckLegacyProtocol(result, protocol);
            }

            // Check modern protocols (should be enabled)
            foreach (var protocol in ModernProtocols)
            {
                CheckModernProtocol(result, protocol);
            }

            // Check cipher suite configuration
            CheckCipherSuites(result);
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "TLS/SSL Check Error",
                $"Could not fully check TLS/SSL configuration: {ex.Message}",
                Category));
        }
    }

    private void CheckLegacyProtocol(AuditResult result, string protocol)
    {
        var clientPath = $@"{SchannelProtocolsPath}\{protocol}\Client";
        var serverPath = $@"{SchannelProtocolsPath}\{protocol}\Server";

        // Check if explicitly disabled. Default behavior varies by Windows version.
        bool clientEnabled = IsProtocolEnabled(clientPath);
        bool serverEnabled = IsProtocolEnabled(serverPath);

        if (clientEnabled || serverEnabled)
        {
            var side = clientEnabled && serverEnabled ? "client and server"
                : clientEnabled ? "client" : "server";

            result.Findings.Add(new Finding
            {
                Title = $"{protocol} Still Enabled",
                Description = $"{protocol} is enabled for {side} connections. This protocol has known vulnerabilities (POODLE, BEAST, etc.) and should be disabled.",
                Severity = protocol.Contains("SSL") ? Severity.Critical : Severity.Warning,
                Category = Category,
                Remediation = $"Disable {protocol} via registry or Group Policy. Path: {SchannelProtocolsPath}\\{protocol}",
                FixCommand = $"powershell -Command \"New-Item 'HKLM:\\{SchannelProtocolsPath}\\{protocol}\\Client' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\{SchannelProtocolsPath}\\{protocol}\\Client' -Name 'Enabled' -Value 0 -Type DWord; New-Item 'HKLM:\\{SchannelProtocolsPath}\\{protocol}\\Server' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\{SchannelProtocolsPath}\\{protocol}\\Server' -Name 'Enabled' -Value 0 -Type DWord\""
            });
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                $"{protocol} Disabled",
                $"{protocol} is disabled or not configured (system default). This is the recommended setting.",
                Category));
        }
    }

    private void CheckModernProtocol(AuditResult result, string protocol)
    {
        var clientPath = $@"{SchannelProtocolsPath}\{protocol}\Client";
        var serverPath = $@"{SchannelProtocolsPath}\{protocol}\Server";

        // Check if explicitly disabled (bad!)
        bool clientDisabled = IsProtocolExplicitlyDisabled(clientPath);
        bool serverDisabled = IsProtocolExplicitlyDisabled(serverPath);

        if (clientDisabled || serverDisabled)
        {
            var side = clientDisabled && serverDisabled ? "client and server"
                : clientDisabled ? "client" : "server";

            result.Findings.Add(Finding.Critical(
                $"{protocol} Disabled",
                $"{protocol} has been explicitly disabled for {side} connections. This weakens security and may cause connectivity issues with modern services.",
                Category,
                $"Re-enable {protocol} by removing or modifying the registry key at {SchannelProtocolsPath}\\{protocol}.",
                $"powershell -Command \"Set-ItemProperty -Path 'HKLM:\\{SchannelProtocolsPath}\\{protocol}\\Client' -Name 'Enabled' -Value 1 -Type DWord -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKLM:\\{SchannelProtocolsPath}\\{protocol}\\Server' -Name 'Enabled' -Value 1 -Type DWord -ErrorAction SilentlyContinue\""));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                $"{protocol} Enabled",
                $"{protocol} is enabled (system default or explicitly configured). Modern TLS is available.",
                Category));
        }
    }

    private bool IsProtocolEnabled(string registryPath)
    {
        // If Enabled explicitly set to 0, it's disabled
        // If key doesn't exist, check DisabledByDefault
        var enabled = RegistryHelper.GetValue<int>(
            RegistryHive.LocalMachine, registryPath, "Enabled", -1);

        if (enabled == 0) return false; // Explicitly disabled
        if (enabled == 1) return true;  // Explicitly enabled

        // Check DisabledByDefault
        var disabledByDefault = RegistryHelper.GetValue<int>(
            RegistryHive.LocalMachine, registryPath, "DisabledByDefault", -1);

        if (disabledByDefault == 1) return false;

        // For legacy protocols, if no explicit setting, check if the protocol
        // is disabled by default on modern Windows (TLS 1.0/1.1 are disabled by default on Win11+)
        // Return false for "not configured" — we treat system defaults as acceptable
        return enabled == -1 ? false : true;
    }

    private bool IsProtocolExplicitlyDisabled(string registryPath)
    {
        var enabled = RegistryHelper.GetValue<int>(
            RegistryHive.LocalMachine, registryPath, "Enabled", -1);

        return enabled == 0;
    }

    private void CheckCipherSuites(AuditResult result)
    {
        try
        {
            // Check for weak cipher suites in the configured order
            var cipherOrderPath = @"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002";
            var cipherOrder = RegistryHelper.GetValue<string>(
                RegistryHive.LocalMachine, cipherOrderPath, "Functions", null);

            if (!string.IsNullOrEmpty(cipherOrder))
            {
                var suites = cipherOrder.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                var weakSuites = suites.Where(s =>
                    s.Contains("RC4", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("DES", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("NULL", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("EXPORT", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("MD5", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (weakSuites.Count > 0)
                {
                    result.Findings.Add(Finding.Warning(
                        $"Weak Cipher Suites Configured ({weakSuites.Count})",
                        $"Found {weakSuites.Count} weak cipher suite(s) in the configured order: {string.Join(", ", weakSuites.Take(5))}. These use broken cryptographic algorithms.",
                        Category,
                        "Remove weak cipher suites (RC4, DES, NULL, EXPORT, MD5) from the cipher suite order via Group Policy or registry."));
                }
                else
                {
                    result.Findings.Add(Finding.Pass(
                        "Cipher Suite Order Configured",
                        $"Custom cipher suite order is configured with {suites.Length} suite(s), none using known-weak algorithms.",
                        Category));
                }
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "Cipher Suite Order — System Default",
                    "No custom cipher suite order configured. Windows is using its default cipher suite selection, which is generally secure on modern Windows versions.",
                    Category));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "Cipher Suite Check Error",
                $"Could not check cipher suite configuration: {ex.Message}",
                Category));
        }
    }

    #endregion

    #region Credential Guard

    private async Task CheckCredentialGuard(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Check registry for Credential Guard config
            var lsaCfg = RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\LSA",
                "LsaCfgFlags", -1);

            var deviceGuardEnabled = RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity", -1);

            // Try WMI DeviceGuard
            string vbsStatus = "Unknown";
            string cgStatus = "Unknown";

            try
            {
                var dgResults = WmiHelper.Query(
                    "SELECT * FROM Win32_DeviceGuard",
                    @"root\Microsoft\Windows\DeviceGuard");

                if (dgResults.Count > 0)
                {
                    var dg = dgResults[0];

                    if (dg.TryGetValue("VirtualizationBasedSecurityStatus", out var vbs))
                    {
                        vbsStatus = vbs switch
                        {
                            0 or 0u => "Not enabled",
                            1 or 1u => "Enabled but not running",
                            2 or 2u => "Running",
                            _ => $"Unknown ({vbs})"
                        };
                    }

                    // SecurityServicesRunning is an array — check for Credential Guard (1)
                    if (dg.TryGetValue("SecurityServicesRunning", out var services) && services is uint[] runningServices)
                    {
                        cgStatus = runningServices.Contains(1u) ? "Running" : "Not running";
                    }
                    else if (dg.TryGetValue("SecurityServicesConfigured", out var configured) && configured is uint[] configuredServices)
                    {
                        cgStatus = configuredServices.Contains(1u) ? "Configured but not running" : "Not configured";
                    }
                }
            }
            catch
            {
                // WMI namespace may not be available
            }

            // Also try PowerShell as fallback for status
            if (cgStatus == "Unknown")
            {
                try
                {
                    var psOutput = await PowerShellHelper.RunCommandAsync(
                        "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning", ct);

                    if (!string.IsNullOrWhiteSpace(psOutput))
                    {
                        cgStatus = psOutput.Contains("1") ? "Running" : "Not running";
                    }
                }
                catch { }
            }

            bool isRunning = cgStatus == "Running";
            bool isConfigured = lsaCfg > 0 || cgStatus.Contains("Configured") || deviceGuardEnabled == 1;

            if (isRunning)
            {
                result.Findings.Add(Finding.Pass(
                    "Credential Guard Running",
                    $"Windows Credential Guard is running (VBS: {vbsStatus}). Credentials are protected by virtualization-based security.",
                    Category));
            }
            else if (isConfigured)
            {
                result.Findings.Add(Finding.Warning(
                    "Credential Guard Configured but Not Running",
                    $"Credential Guard is configured (LsaCfgFlags: {lsaCfg}, VBS: {vbsStatus}) but is not currently running. A reboot may be required, or hardware requirements may not be met.",
                    Category,
                    "Ensure UEFI Secure Boot, virtualization extensions, and TPM 2.0 are available. Reboot the system.",
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LsaCfgFlags' -Value 1 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord\""));
            }
            else
            {
                result.Findings.Add(Finding.Warning(
                    "Credential Guard Not Enabled",
                    "Windows Credential Guard is not enabled. Without it, credentials (NTLM hashes, Kerberos tickets) are stored in normal memory and vulnerable to theft by tools like Mimikatz.",
                    Category,
                    "Enable Credential Guard via Group Policy: Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security. Requires UEFI, Secure Boot, and TPM 2.0.",
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA' -Name 'LsaCfgFlags' -Value 1 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord\""));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "Credential Guard Check Error",
                $"Could not determine Credential Guard status: {ex.Message}",
                Category,
                "Run WinSentinel as Administrator to check Credential Guard."));
        }
    }

    #endregion

    #region DPAPI Protection

    private async Task CheckDpapiProtection(AuditResult result, CancellationToken ct)
    {
        try
        {
            // Check if DPAPI master keys exist and are properly protected
            var dpapiPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Protect");

            bool masterKeysExist = false;
            int keyCount = 0;

            if (Directory.Exists(dpapiPath))
            {
                // Each user has a SID subfolder with master key files
                foreach (var dir in Directory.GetDirectories(dpapiPath))
                {
                    var files = Directory.GetFiles(dir);
                    keyCount += files.Length;
                    if (files.Length > 0) masterKeysExist = true;
                }
            }

            // Check DPAPI protection with domain backup (for domain-joined machines)
            bool isDomainJoined = false;
            try
            {
                var domainOutput = await PowerShellHelper.RunCommandAsync(
                    "(Get-WmiObject Win32_ComputerSystem).PartOfDomain", ct);
                isDomainJoined = domainOutput.Contains("True", StringComparison.OrdinalIgnoreCase);
            }
            catch { }

            // Check if DPAPI is backed by TPM or domain controller
            var protectPath = @"SOFTWARE\Microsoft\Cryptography\Protect\Providers";
            var providers = RegistryHelper.GetSubKeyNames(RegistryHive.LocalMachine, protectPath);

            if (masterKeysExist)
            {
                // Check Credential Manager vault for healthy DPAPI
                var credGuardReg = RegistryHelper.GetValue<int>(
                    RegistryHive.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Control\LSA",
                    "LsaCfgFlags", 0);

                if (credGuardReg > 0)
                {
                    result.Findings.Add(Finding.Pass(
                        "DPAPI Protected by Credential Guard",
                        $"DPAPI master keys exist ({keyCount} key files) and Credential Guard is enabled, providing additional protection for derived credentials.",
                        Category));
                }
                else if (isDomainJoined)
                {
                    result.Findings.Add(Finding.Pass(
                        "DPAPI Master Keys Present (Domain)",
                        $"DPAPI master keys exist ({keyCount} key files). Domain-joined machine — keys are backed up to the domain controller for recovery.",
                        Category));
                }
                else
                {
                    result.Findings.Add(Finding.Info(
                        "DPAPI Master Keys Present",
                        $"DPAPI master keys exist ({keyCount} key files). Keys are protected by the user's password. Ensure a strong login password is used, as DPAPI key security depends on it.",
                        Category,
                        "Use a strong login password. Consider enabling Credential Guard for enhanced DPAPI protection."));
                }
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "DPAPI Master Keys Not Found",
                    "No DPAPI master key files found. This may be normal for a fresh user profile, or the profile path may be non-standard.",
                    Category));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "DPAPI Check Error",
                $"Could not check DPAPI protection status: {ex.Message}",
                Category));
        }
    }

    #endregion
}
