using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits credential storage and exposure risks including:
/// - Windows Credential Manager entries (generic/domain/certificate)
/// - Git credential stores (plaintext, cache, manager)
/// - SSH key security (passphrase-less keys, weak algorithms, permissions)
/// - Plaintext credential files in common locations
/// - Saved RDP connection credentials (.rdp files with passwords)
/// - Browser credential store accessibility
/// - Sensitive file permission analysis
/// - Cloud CLI credential caches (AWS, Azure, GCP)
/// </summary>
public class CredentialExposureAudit : IAuditModule
{
    public string Name => "Credential Exposure Audit";
    public string Category => "Credentials";
    public string Description => "Scans for stored credentials, exposed secrets, and credential storage misconfigurations.";

    /// <summary>
    /// State DTO for testable analysis without live system access.
    /// </summary>
    public class CredentialState
    {
        // Windows Credential Manager
        public List<CredentialEntry> CredentialManagerEntries { get; set; } = new();

        // Git credential storage
        public GitCredentialConfig GitCredentials { get; set; } = new();

        // SSH keys
        public List<SshKeyInfo> SshKeys { get; set; } = new();

        // Plaintext credential files found
        public List<CredentialFileInfo> CredentialFiles { get; set; } = new();

        // RDP files with embedded credentials
        public List<RdpFileInfo> RdpFiles { get; set; } = new();

        // Browser credential stores
        public List<BrowserCredentialStore> BrowserStores { get; set; } = new();

        // Cloud CLI credentials
        public List<CloudCredentialInfo> CloudCredentials { get; set; } = new();

        // Sensitive file permissions
        public List<SensitiveFilePermission> SensitiveFilePermissions { get; set; } = new();
    }

    public class CredentialEntry
    {
        public string TargetName { get; set; } = string.Empty;
        public CredentialType Type { get; set; }
        public string UserName { get; set; } = string.Empty;
        public bool Persisted { get; set; }
        public int AgeDays { get; set; }
        public string Comment { get; set; } = string.Empty;
    }

    public enum CredentialType
    {
        Generic,
        DomainPassword,
        DomainCertificate,
        DomainVisiblePassword,
        GenericCertificate,
        DomainExtended,
        Unknown
    }

    public class GitCredentialConfig
    {
        public string HelperType { get; set; } = string.Empty; // "store", "cache", "manager", "manager-core", ""
        public bool StorePlaintextExists { get; set; }
        public string StorePlaintextPath { get; set; } = string.Empty;
        public int StorePlaintextEntryCount { get; set; }
        public bool GlobalConfigHasCredentials { get; set; }
    }

    public class SshKeyInfo
    {
        public string FileName { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty; // rsa, ed25519, ecdsa, dsa
        public int KeyBits { get; set; }
        public bool HasPassphrase { get; set; }
        public bool WorldReadable { get; set; }
        public int AgeDays { get; set; }
    }

    public class CredentialFileInfo
    {
        public string Path { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty; // "user_profile", "appdata", "documents", "desktop"
        public long SizeBytes { get; set; }
        public bool ContainsPlaintextSecrets { get; set; }
        public List<string> DetectedPatterns { get; set; } = new(); // "password=", "api_key=", etc.
    }

    public class RdpFileInfo
    {
        public string Path { get; set; } = string.Empty;
        public string ServerAddress { get; set; } = string.Empty;
        public bool HasEmbeddedPassword { get; set; }
        public bool HasSavedUsername { get; set; }
        public bool GatewayCredentialsSaved { get; set; }
    }

    public class BrowserCredentialStore
    {
        public string BrowserName { get; set; } = string.Empty;
        public string ProfilePath { get; set; } = string.Empty;
        public bool LoginDataExists { get; set; }
        public int StoredPasswordCount { get; set; }
        public bool EncryptedWithDPAPI { get; set; }
        public bool MasterPasswordEnabled { get; set; }
    }

    public class CloudCredentialInfo
    {
        public string Provider { get; set; } = string.Empty; // "AWS", "Azure", "GCP", "Docker"
        public string CredentialPath { get; set; } = string.Empty;
        public bool PlaintextTokens { get; set; }
        public bool MfaConfigured { get; set; }
        public int AgeDays { get; set; }
        public List<string> Profiles { get; set; } = new();
    }

    public class SensitiveFilePermission
    {
        public string Path { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool WorldReadable { get; set; }
        public bool OtherUsersCanRead { get; set; }
        public bool InheritedPermissions { get; set; }
    }

    // ── Known weak SSH algorithms ──
    private static readonly HashSet<string> WeakSshAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "dsa", "rsa-1024", "ecdsa-256"
    };

    // ── Patterns indicating plaintext secrets ──
    private static readonly string[] SecretFilePatterns = new[]
    {
        ".env", ".credentials", ".netrc", "_netrc", ".pgpass",
        "credentials.json", "secrets.json", "config.json",
        ".npmrc", ".pypirc", ".docker/config.json",
        "hub", ".gem/credentials"
    };

    // ── Stale credential threshold (days) ──
    private const int StaleCredentialDays = 365;
    private const int VeryStaleCredentialDays = 730;

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
            var state = await GatherStateAsync(cancellationToken);
            Analyze(state, result);
            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    internal async Task<CredentialState> GatherStateAsync(CancellationToken cancellationToken)
    {
        var state = new CredentialState();
        await Task.CompletedTask; // Placeholder for actual system queries

        // In a real implementation, this would:
        // 1. Enumerate Windows Credential Manager via cmdkey /list
        // 2. Check git config --global credential.helper
        // 3. Scan ~/.ssh/ for key files
        // 4. Search for known credential files
        // 5. Find .rdp files with embedded passwords
        // 6. Check browser profile directories
        // 7. Scan cloud CLI config directories

        return state;
    }

    /// <summary>
    /// Analyze gathered credential state and produce findings.
    /// Public for unit testing with synthetic state.
    /// </summary>
    public void Analyze(CredentialState state, AuditResult result)
    {
        AnalyzeCredentialManager(state, result);
        AnalyzeGitCredentials(state, result);
        AnalyzeSshKeys(state, result);
        AnalyzeCredentialFiles(state, result);
        AnalyzeRdpFiles(state, result);
        AnalyzeBrowserStores(state, result);
        AnalyzeCloudCredentials(state, result);
        AnalyzeSensitiveFilePermissions(state, result);
    }

    private void AnalyzeCredentialManager(CredentialState state, AuditResult result)
    {
        var entries = state.CredentialManagerEntries;

        if (entries.Count == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No Credential Manager entries",
                "Windows Credential Manager has no stored credentials.",
                Category));
            return;
        }

        // Check for excessive stored credentials
        if (entries.Count > 50)
        {
            result.Findings.Add(Finding.Warning(
                "Excessive stored credentials",
                $"Windows Credential Manager contains {entries.Count} entries. Large credential stores increase the blast radius if compromised.",
                Category,
                "Review and remove unused credentials: Control Panel > Credential Manager"));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Credential Manager entries",
                $"Windows Credential Manager contains {entries.Count} stored credential(s).",
                Category));
        }

        // Check for generic (less secure) credentials
        var genericCreds = entries.Where(e => e.Type == CredentialType.Generic).ToList();
        if (genericCreds.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Generic credentials stored",
                $"{genericCreds.Count} generic credential(s) found. These are application-stored passwords protected only by DPAPI.",
                Category,
                "Review generic credentials and remove those no longer needed."));
        }

        // Check for domain visible passwords (weakest protection)
        var visiblePwds = entries.Where(e => e.Type == CredentialType.DomainVisiblePassword).ToList();
        if (visiblePwds.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "Domain visible passwords stored",
                $"{visiblePwds.Count} domain visible password(s) found. These credentials have weaker protection than standard domain credentials.",
                Category,
                "Replace with domain password credentials where possible."));
        }

        // Check for very stale credentials
        var veryStale = entries.Where(e => e.AgeDays > VeryStaleCredentialDays).ToList();
        if (veryStale.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "Very stale credentials detected",
                $"{veryStale.Count} credential(s) older than {VeryStaleCredentialDays} days: {string.Join(", ", veryStale.Select(e => e.TargetName).Take(5))}. Old credentials may grant access to decommissioned or compromised services.",
                Category,
                "Remove or rotate credentials older than 2 years."));
        }

        // Check for stale credentials
        var stale = entries.Where(e => e.AgeDays > StaleCredentialDays && e.AgeDays <= VeryStaleCredentialDays).ToList();
        if (stale.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Stale credentials detected",
                $"{stale.Count} credential(s) older than {StaleCredentialDays} days. Consider rotating.",
                Category));
        }
    }

    private void AnalyzeGitCredentials(CredentialState state, AuditResult result)
    {
        var git = state.GitCredentials;

        if (string.IsNullOrEmpty(git.HelperType))
        {
            result.Findings.Add(Finding.Info(
                "No Git credential helper configured",
                "Git has no credential helper set. Credentials will be prompted each time.",
                Category,
                "Configure a secure credential helper: git config --global credential.helper manager"));
            return;
        }

        // Plaintext store is dangerous
        if (git.HelperType.Equals("store", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                "Git credentials stored in plaintext",
                $"Git is configured to use 'store' credential helper, which saves passwords in plaintext at {git.StorePlaintextPath}. " +
                $"Contains {git.StorePlaintextEntryCount} credential(s).",
                Category,
                "Switch to a secure credential helper: git config --global credential.helper manager",
                "git config --global credential.helper manager"));
        }
        else if (git.HelperType.Equals("cache", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Info(
                "Git credentials cached in memory",
                "Git uses 'cache' helper which stores credentials in memory temporarily. Reasonably secure but credentials are lost on reboot.",
                Category));
        }
        else if (git.HelperType.Contains("manager", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "Git credential manager configured",
                $"Git uses '{git.HelperType}' which stores credentials securely via the OS credential store.",
                Category));
        }

        // Check for plaintext store file even if not the active helper
        if (git.StorePlaintextExists && !git.HelperType.Equals("store", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "Git plaintext credential file exists",
                $"Plaintext credential file found at {git.StorePlaintextPath} with {git.StorePlaintextEntryCount} entries, " +
                "even though a different credential helper is active. This file may contain old credentials.",
                Category,
                $"Delete the plaintext credential file: Remove-Item '{git.StorePlaintextPath}'"));
        }

        // Credentials in global config
        if (git.GlobalConfigHasCredentials)
        {
            result.Findings.Add(Finding.Critical(
                "Credentials embedded in Git config",
                "Git global configuration contains hardcoded credentials (e.g., in remote URLs). These are visible to any process reading .gitconfig.",
                Category,
                "Remove credentials from .gitconfig and use a credential helper instead."));
        }
    }

    private void AnalyzeSshKeys(CredentialState state, AuditResult result)
    {
        var keys = state.SshKeys;

        if (keys.Count == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No SSH keys found",
                "No SSH private keys detected in the default SSH directory.",
                Category));
            return;
        }

        result.Findings.Add(Finding.Info(
            "SSH keys present",
            $"{keys.Count} SSH private key(s) found.",
            Category));

        // Check for passphrase-less keys
        var noPassphrase = keys.Where(k => !k.HasPassphrase).ToList();
        if (noPassphrase.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "SSH keys without passphrase",
                $"{noPassphrase.Count} SSH key(s) have no passphrase protection: {string.Join(", ", noPassphrase.Select(k => k.FileName).Take(5))}. " +
                "If the key file is stolen, it can be used immediately without any secret.",
                Category,
                "Add a passphrase: ssh-keygen -p -f <keyfile>"));
        }

        // Check for weak algorithms
        var weakKeys = keys.Where(k => IsWeakSshKey(k)).ToList();
        if (weakKeys.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "SSH keys with weak algorithms",
                $"{weakKeys.Count} SSH key(s) use weak or deprecated algorithms: {string.Join(", ", weakKeys.Select(k => $"{k.FileName} ({k.Algorithm} {k.KeyBits}-bit)"))}.",
                Category,
                "Generate new keys with strong algorithms: ssh-keygen -t ed25519"));
        }

        // Check for world-readable keys
        var worldReadable = keys.Where(k => k.WorldReadable).ToList();
        if (worldReadable.Count > 0)
        {
            result.Findings.Add(Finding.Critical(
                "SSH keys with excessive permissions",
                $"{worldReadable.Count} SSH key(s) are readable by other users: {string.Join(", ", worldReadable.Select(k => k.FileName))}. " +
                "SSH will refuse to use keys with open permissions, and other users can copy them.",
                Category,
                "Fix permissions: icacls <keyfile> /inheritance:r /grant:r \"%USERNAME%:R\""));
        }

        // Check for very old keys
        var oldKeys = keys.Where(k => k.AgeDays > StaleCredentialDays).ToList();
        if (oldKeys.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Old SSH keys detected",
                $"{oldKeys.Count} SSH key(s) older than {StaleCredentialDays} days. Consider rotating.",
                Category));
        }
    }

    private void AnalyzeCredentialFiles(CredentialState state, AuditResult result)
    {
        var files = state.CredentialFiles;

        if (files.Count == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No plaintext credential files found",
                "No common credential files detected in user directories.",
                Category));
            return;
        }

        var withSecrets = files.Where(f => f.ContainsPlaintextSecrets).ToList();
        var withoutSecrets = files.Where(f => !f.ContainsPlaintextSecrets).ToList();

        if (withSecrets.Count > 0)
        {
            result.Findings.Add(Finding.Critical(
                "Plaintext secrets in credential files",
                $"{withSecrets.Count} file(s) contain plaintext secrets: {string.Join(", ", withSecrets.Select(f => f.FileName).Take(5))}. " +
                $"Detected patterns: {string.Join(", ", withSecrets.SelectMany(f => f.DetectedPatterns).Distinct().Take(5))}.",
                Category,
                "Move secrets to Windows Credential Manager or a secrets vault. Delete plaintext files."));
        }

        if (withoutSecrets.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Credential-related files found",
                $"{withoutSecrets.Count} credential-related file(s) found but no plaintext secrets detected: {string.Join(", ", withoutSecrets.Select(f => f.FileName).Take(5))}.",
                Category));
        }
    }

    private void AnalyzeRdpFiles(CredentialState state, AuditResult result)
    {
        var rdpFiles = state.RdpFiles;

        if (rdpFiles.Count == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No RDP files with saved credentials",
                "No .rdp files with embedded credentials found.",
                Category));
            return;
        }

        var withPasswords = rdpFiles.Where(f => f.HasEmbeddedPassword).ToList();
        if (withPasswords.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "RDP files with embedded passwords",
                $"{withPasswords.Count} .rdp file(s) contain saved passwords: {string.Join(", ", withPasswords.Select(f => f.ServerAddress).Take(5))}. " +
                "RDP passwords are encrypted with DPAPI but can be decrypted by any process running as the same user.",
                Category,
                "Remove saved passwords from .rdp files and use credential prompt instead."));
        }

        var withGateway = rdpFiles.Where(f => f.GatewayCredentialsSaved).ToList();
        if (withGateway.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "RDP gateway credentials saved",
                $"{withGateway.Count} .rdp file(s) have saved gateway credentials for: {string.Join(", ", withGateway.Select(f => f.ServerAddress).Take(5))}.",
                Category,
                "Remove gateway credentials from .rdp files."));
        }

        var usernameOnly = rdpFiles.Where(f => f.HasSavedUsername && !f.HasEmbeddedPassword).ToList();
        if (usernameOnly.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "RDP files with saved usernames",
                $"{usernameOnly.Count} .rdp file(s) have saved usernames (no password). Low risk but reveals account names.",
                Category));
        }
    }

    private void AnalyzeBrowserStores(CredentialState state, AuditResult result)
    {
        var stores = state.BrowserStores;

        if (stores.Count == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No browser credential stores found",
                "No browser password databases detected.",
                Category));
            return;
        }

        foreach (var store in stores)
        {
            if (!store.LoginDataExists) continue;

            if (store.StoredPasswordCount > 0 && !store.MasterPasswordEnabled)
            {
                var severity = store.StoredPasswordCount > 50 ? Severity.Warning : Severity.Info;
                result.Findings.Add(new Finding
                {
                    Title = $"{store.BrowserName}: {store.StoredPasswordCount} passwords without master password",
                    Description = $"{store.BrowserName} stores {store.StoredPasswordCount} password(s) " +
                        $"protected only by DPAPI (no master password). Any local process running as this user can extract them.",
                    Severity = severity,
                    Category = Category,
                    Remediation = $"Enable master password in {store.BrowserName} settings, or use a dedicated password manager."
                });
            }
            else if (store.StoredPasswordCount > 0 && store.MasterPasswordEnabled)
            {
                result.Findings.Add(Finding.Pass(
                    $"{store.BrowserName}: master password enabled",
                    $"{store.BrowserName} stores {store.StoredPasswordCount} password(s) with master password protection.",
                    Category));
            }
        }

        var totalPasswords = stores.Sum(s => s.StoredPasswordCount);
        if (totalPasswords > 200)
        {
            result.Findings.Add(Finding.Warning(
                "Large browser password footprint",
                $"{totalPasswords} passwords stored across {stores.Count} browser(s). Consider migrating to a dedicated password manager for better security.",
                Category,
                "Export and migrate to a password manager like Bitwarden, 1Password, or KeePass."));
        }
    }

    private void AnalyzeCloudCredentials(CredentialState state, AuditResult result)
    {
        var creds = state.CloudCredentials;

        if (creds.Count == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No cloud CLI credentials found",
                "No AWS, Azure, GCP, or Docker credential caches detected.",
                Category));
            return;
        }

        foreach (var cred in creds)
        {
            if (cred.PlaintextTokens)
            {
                result.Findings.Add(Finding.Warning(
                    $"{cred.Provider} credentials with plaintext tokens",
                    $"{cred.Provider} credential cache at {cred.CredentialPath} contains plaintext tokens/keys " +
                    $"for {cred.Profiles.Count} profile(s): {string.Join(", ", cred.Profiles.Take(3))}." +
                    (cred.AgeDays > StaleCredentialDays ? $" Credentials are {cred.AgeDays} days old." : ""),
                    Category,
                    $"Rotate {cred.Provider} credentials and restrict file permissions."));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    $"{cred.Provider} credentials present",
                    $"{cred.Provider} credential cache found at {cred.CredentialPath} with {cred.Profiles.Count} profile(s).",
                    Category));
            }

            if (!cred.MfaConfigured && cred.PlaintextTokens)
            {
                result.Findings.Add(Finding.Warning(
                    $"{cred.Provider} credentials without MFA",
                    $"{cred.Provider} credentials appear to lack MFA configuration. Static credentials without MFA are high-risk.",
                    Category,
                    $"Enable MFA for {cred.Provider} accounts and use temporary session credentials."));
            }
        }
    }

    private void AnalyzeSensitiveFilePermissions(CredentialState state, AuditResult result)
    {
        var files = state.SensitiveFilePermissions;

        if (files.Count == 0) return;

        var worldReadable = files.Where(f => f.WorldReadable).ToList();
        if (worldReadable.Count > 0)
        {
            result.Findings.Add(Finding.Critical(
                "Sensitive files readable by all users",
                $"{worldReadable.Count} sensitive file(s) are world-readable: {string.Join(", ", worldReadable.Select(f => f.Path).Take(5))}.",
                Category,
                "Restrict file permissions to the owning user only."));
        }

        var otherUsers = files.Where(f => f.OtherUsersCanRead && !f.WorldReadable).ToList();
        if (otherUsers.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "Sensitive files accessible by other users",
                $"{otherUsers.Count} sensitive file(s) can be read by other local users: {string.Join(", ", otherUsers.Select(f => f.Path).Take(5))}.",
                Category,
                "Remove inherited permissions and restrict to owner only."));
        }
    }

    private static bool IsWeakSshKey(SshKeyInfo key)
    {
        if (key.Algorithm.Equals("dsa", StringComparison.OrdinalIgnoreCase))
            return true;
        if (key.Algorithm.Equals("rsa", StringComparison.OrdinalIgnoreCase) && key.KeyBits < 2048)
            return true;
        if (key.Algorithm.Equals("ecdsa", StringComparison.OrdinalIgnoreCase) && key.KeyBits < 384)
            return true;
        return false;
    }

    /// <summary>
    /// Generate a summary report of credential exposure.
    /// </summary>
    public static CredentialExposureReport GenerateReport(CredentialState state)
    {
        var report = new CredentialExposureReport
        {
            TotalCredentialManagerEntries = state.CredentialManagerEntries.Count,
            StaleCredentials = state.CredentialManagerEntries.Count(e => e.AgeDays > StaleCredentialDays),
            GitHelperType = state.GitCredentials.HelperType,
            GitPlaintextStore = state.GitCredentials.StorePlaintextExists,
            TotalSshKeys = state.SshKeys.Count,
            UnprotectedSshKeys = state.SshKeys.Count(k => !k.HasPassphrase),
            WeakSshKeys = state.SshKeys.Count(IsWeakSshKey),
            PlaintextCredentialFiles = state.CredentialFiles.Count(f => f.ContainsPlaintextSecrets),
            RdpFilesWithPasswords = state.RdpFiles.Count(f => f.HasEmbeddedPassword),
            TotalBrowserPasswords = state.BrowserStores.Sum(s => s.StoredPasswordCount),
            BrowsersWithoutMasterPassword = state.BrowserStores.Count(s => s.StoredPasswordCount > 0 && !s.MasterPasswordEnabled),
            CloudCredentialProviders = state.CloudCredentials.Select(c => c.Provider).ToList(),
            PlaintextCloudTokens = state.CloudCredentials.Count(c => c.PlaintextTokens),
            WorldReadableSensitiveFiles = state.SensitiveFilePermissions.Count(f => f.WorldReadable),
        };

        // Compute composite risk score (0-100, higher = more risk)
        report.ExposureRiskScore = ComputeRiskScore(report);
        report.RiskGrade = report.ExposureRiskScore switch
        {
            <= 10 => "A",
            <= 25 => "B",
            <= 45 => "C",
            <= 65 => "D",
            _ => "F"
        };

        return report;
    }

    private static int ComputeRiskScore(CredentialExposureReport report)
    {
        double score = 0;

        // Git plaintext store is very high risk
        if (report.GitPlaintextStore && report.GitHelperType.Equals("store", StringComparison.OrdinalIgnoreCase))
            score += 20;
        else if (report.GitPlaintextStore)
            score += 10;

        // SSH keys without passphrase
        score += Math.Min(report.UnprotectedSshKeys * 8, 20);

        // Weak SSH keys
        score += Math.Min(report.WeakSshKeys * 5, 10);

        // Plaintext credential files
        score += Math.Min(report.PlaintextCredentialFiles * 10, 20);

        // RDP files with passwords
        score += Math.Min(report.RdpFilesWithPasswords * 5, 10);

        // Browser passwords without master password
        if (report.BrowsersWithoutMasterPassword > 0)
            score += Math.Min(5 + report.TotalBrowserPasswords / 50.0, 10);

        // Cloud credentials with plaintext tokens
        score += Math.Min(report.PlaintextCloudTokens * 8, 15);

        // World-readable sensitive files
        score += Math.Min(report.WorldReadableSensitiveFiles * 10, 15);

        // Stale credentials
        score += Math.Min(report.StaleCredentials * 2, 10);

        return Math.Min((int)Math.Round(score), 100);
    }

    /// <summary>
    /// Summary report for credential exposure assessment.
    /// </summary>
    public class CredentialExposureReport
    {
        public int TotalCredentialManagerEntries { get; set; }
        public int StaleCredentials { get; set; }
        public string GitHelperType { get; set; } = string.Empty;
        public bool GitPlaintextStore { get; set; }
        public int TotalSshKeys { get; set; }
        public int UnprotectedSshKeys { get; set; }
        public int WeakSshKeys { get; set; }
        public int PlaintextCredentialFiles { get; set; }
        public int RdpFilesWithPasswords { get; set; }
        public int TotalBrowserPasswords { get; set; }
        public int BrowsersWithoutMasterPassword { get; set; }
        public List<string> CloudCredentialProviders { get; set; } = new();
        public int PlaintextCloudTokens { get; set; }
        public int WorldReadableSensitiveFiles { get; set; }
        public int ExposureRiskScore { get; set; }
        public string RiskGrade { get; set; } = string.Empty;

        public string ToSummary()
        {
            var lines = new List<string>
            {
                $"═══ Credential Exposure Report ═══",
                $"Risk Score: {ExposureRiskScore}/100 (Grade: {RiskGrade})",
                $"",
                $"Windows Credential Manager: {TotalCredentialManagerEntries} entries ({StaleCredentials} stale)",
                $"Git Credentials: helper={GitHelperType}, plaintext store={GitPlaintextStore}",
                $"SSH Keys: {TotalSshKeys} total, {UnprotectedSshKeys} unprotected, {WeakSshKeys} weak",
                $"Credential Files: {PlaintextCredentialFiles} with plaintext secrets",
                $"RDP Files: {RdpFilesWithPasswords} with embedded passwords",
                $"Browser Passwords: {TotalBrowserPasswords} total, {BrowsersWithoutMasterPassword} browser(s) without master password",
                $"Cloud Credentials: {string.Join(", ", CloudCredentialProviders)} ({PlaintextCloudTokens} with plaintext tokens)",
                $"Sensitive File Permissions: {WorldReadableSensitiveFiles} world-readable",
            };
            return string.Join(Environment.NewLine, lines);
        }
    }
}
