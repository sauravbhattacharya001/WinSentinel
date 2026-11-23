using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
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

        /// <summary>
        /// Sources that could not be read at all (one human-readable line per
        /// source). A section listed here was NOT verified clean — its
        /// all-clear finding, if any, does not cover it. Empty when every
        /// source was read successfully or had nothing to read.
        /// </summary>
        public List<string> GatherErrors { get; set; } = new();
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
        /// <summary>
        /// True when a master password protects the store, false when the store
        /// is known to have none (Chromium browsers have no master password),
        /// null when the local profile carries no signal either way (Firefox —
        /// master-password state lives in key4.db and is not readable here).
        /// Null must never be reported as "without master password".
        /// </summary>
        public bool? MasterPasswordEnabled { get; set; }
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

    /// <summary>
    /// Content patterns scanned inside credential files. Each entry pairs a
    /// regex with the short label reported in <see cref="CredentialFileInfo.DetectedPatterns"/>.
    /// Labels match the vocabulary the analysis layer already reports.
    /// </summary>
    private static readonly (Regex Pattern, string Label)[] SecretContentPatterns = new[]
    {
        // No \b anchor: secrets live in SNAKE_CASE names (DB_PASSWORD=, MY_API_KEY=),
        // where the '_' before the keyword is a word char and would defeat \b.
        // The [: =] after the keyword is what keeps "passwordless" from matching.
        (new Regex(@"(passw(or)?d|passwd|pwd)\s*[:=]", RegexOptions.Compiled | RegexOptions.IgnoreCase), "password="),
        (new Regex(@"api[_-]?key\s*[:=]", RegexOptions.Compiled | RegexOptions.IgnoreCase), "api_key="),
        (new Regex(@"(client[_-]?secret|secret[_-]?key)\s*[:=]", RegexOptions.Compiled | RegexOptions.IgnoreCase), "secret="),
        (new Regex(@"(token|access[_-]?key)\s*[:=]", RegexOptions.Compiled | RegexOptions.IgnoreCase), "token="),
        (new Regex(@"aws_secret_access_key", RegexOptions.Compiled | RegexOptions.IgnoreCase), "aws_secret_access_key"),
        // A private-key block in a credential file. (The literal header text is
        // deliberately never written out here — see DetectSshKeyPassphrase.)
        (new Regex(@"PRIVATE KEY", RegexOptions.Compiled), "private_key"),
    };

    /// <summary>Maximum bytes read from a single credential file (first N bytes only).</summary>
    private const int MaxCredentialFileReadBytes = 64 * 1024;

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
            AddGatherErrorFindings(state, result);
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

    /// <summary>
    /// Surfaces gather failures as a Warning: a source that could not be read
    /// was NOT verified clean, so the module's all-clear for that section is
    /// qualified. Internal so tests can assert on it with synthetic state.
    /// </summary>
    internal void AddGatherErrorFindings(CredentialState state, AuditResult result)
    {
        if (state.GatherErrors.Count == 0) return;
        var shown = state.GatherErrors.Take(5).ToList();
        var more = state.GatherErrors.Count - shown.Count;
        result.Findings.Add(Finding.Warning(
            "Some credential sources could not be checked",
            "The following credential sources could not be read, so the findings above do not cover them: " +
            string.Join("; ", shown) + (more > 0 ? $"; and {more} more." : "."),
            Category,
            "Re-run the audit with elevated privileges, or check the listed sources manually."));
    }

    /// <summary>
    /// Gathers live credential state from the machine. Every section is
    /// best-effort and independent: a source that is absent means "nothing
    /// to check" (empty list, honest all-clear), while a source that exists
    /// but cannot be read records a <see cref="CredentialState.GatherErrors"/>
    /// entry instead of silently reporting empty. A failure in one section
    /// never aborts the others.
    /// </summary>
    internal async Task<CredentialState> GatherStateAsync(CancellationToken cancellationToken)
    {
        var state = new CredentialState();

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var sshDir = Path.Combine(userProfile, ".ssh");

        // Each section is invoked behind its own backstop: a bug in one
        // section records a gather error instead of aborting the rest.
        await RunSectionAsync(state, "Credential Manager", ct => GatherCredentialManagerAsync(state, ct), cancellationToken);
        await RunSectionAsync(state, "Git credentials", ct => GatherGitCredentialsAsync(state, userProfile, ct), cancellationToken);
        RunSection(state, "SSH keys", () => GatherSshKeys(state, sshDir));

        RunSection(state, "Credential files", () => GatherCredentialFiles(state, new[]
        {
            (userProfile, "user_profile"),
            (roamingAppData, "appdata"),
            (localAppData, "appdata"),
            (documents, "documents"),
            (desktop, "desktop"),
        }));
        RunSection(state, "RDP files", () => GatherRdpFiles(state, new[] { userProfile, documents, desktop }));
        RunSection(state, "Browser stores", () => GatherBrowserStores(state, localAppData, roamingAppData));
        RunSection(state, "Cloud credentials", () => GatherCloudCredentials(state, userProfile, roamingAppData));

        // Permissions for every sensitive file found above. SSH keys carry
        // their own WorldReadable flag (set in InspectSshPrivateKey); this
        // section feeds the SensitiveFilePermissions analysis.
        var sensitiveFiles = new List<(string Path, string Description)>();
        sensitiveFiles.AddRange(state.SshKeys.Select(k => (Path.Combine(sshDir, k.FileName), "SSH private key")));
        sensitiveFiles.AddRange(state.CredentialFiles.Where(f => f.ContainsPlaintextSecrets).Select(f => (f.Path, "Credential file")));
        sensitiveFiles.AddRange(state.CloudCredentials.Select(c => (c.CredentialPath, $"{c.Provider} credential cache")));
        RunSection(state, "File permissions", () => GatherSensitiveFilePermissions(state, sensitiveFiles));

        return state;
    }

    private static void RunSection(CredentialState state, string section, Action gather)
    {
        try
        {
            gather();
        }
        catch (Exception ex)
        {
            state.GatherErrors.Add($"{section}: could not be checked ({ex.GetType().Name}).");
        }
    }

    private static async Task RunSectionAsync(CredentialState state, string section, Func<CancellationToken, Task> gather, CancellationToken ct)
    {
        try
        {
            await gather(ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            state.GatherErrors.Add($"{section}: could not be checked ({ex.GetType().Name}).");
        }
    }

    // ── Section 1: Windows Credential Manager (via cmdkey) ───────────────

    /// <summary>
    /// Enumerates Credential Manager entries via <c>cmdkey /list</c>.
    /// cmdkey reports no entry age, so <see cref="CredentialEntry.AgeDays"/>
    /// stays 0 (unknown — never stale-flagged on missing data).
    /// </summary>
    internal async Task GatherCredentialManagerAsync(CredentialState state, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunCmdAsync("cmdkey /list", ct);
            var (entries, error) = InterpretCmdkeyOutput(output);
            state.CredentialManagerEntries.AddRange(entries);
            if (error != null) state.GatherErrors.Add(error);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.GatherErrors.Add($"Credential Manager: cmdkey failed ({ex.GetType().Name}) — entries not verified.");
        }
    }

    /// <summary>
    /// Parses <c>cmdkey /list</c> output into entries. Pure for testing.
    /// Returns an error string (instead of entries) when the output is
    /// non-empty but unparseable — e.g. localized cmdkey output — so the
    /// caller never claims an empty vault it could not read.
    /// </summary>
    internal static (List<CredentialEntry> Entries, string? Error) InterpretCmdkeyOutput(string output)
    {
        var entries = new List<CredentialEntry>();
        if (string.IsNullOrWhiteSpace(output))
            return (entries, null);

        // Empty vault (English marker). No entries — and that is verified.
        if (output.Contains("No credentials", StringComparison.OrdinalIgnoreCase))
            return (entries, null);

        CredentialEntry? current = null;
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                if (current != null) { entries.Add(current); current = null; }
                continue;
            }

            if (line.StartsWith("Target:", StringComparison.OrdinalIgnoreCase))
            {
                if (current != null) entries.Add(current);
                current = new CredentialEntry { TargetName = StripCmdkeyTargetPrefix(line["Target:".Length..].Trim()) };
            }
            else if (current != null && line.StartsWith("Type:", StringComparison.OrdinalIgnoreCase))
            {
                current.Type = ParseCredentialType(line["Type:".Length..].Trim());
            }
            else if (current != null && line.StartsWith("User:", StringComparison.OrdinalIgnoreCase))
            {
                current.UserName = line["User:".Length..].Trim();
            }
            else if (current != null && line.Contains("persistence", StringComparison.OrdinalIgnoreCase))
            {
                current.Persisted = true;
            }
        }
        if (current != null) entries.Add(current);

        if (entries.Count == 0 && !output.Contains("Target:", StringComparison.OrdinalIgnoreCase))
            return (entries, "Credential Manager: cmdkey output could not be parsed — entries not verified.");

        return (entries, null);
    }

    private static string StripCmdkeyTargetPrefix(string target)
    {
        foreach (var prefix in new[] { "LegacyGeneric:target=", "Domain:target=" })
        {
            if (target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return target[prefix.Length..];
        }
        return target;
    }

    internal static CredentialType ParseCredentialType(string raw) => raw.Trim() switch
    {
        var t when t.Equals("Generic", StringComparison.OrdinalIgnoreCase) => CredentialType.Generic,
        var t when t.Equals("Domain Password", StringComparison.OrdinalIgnoreCase) => CredentialType.DomainPassword,
        var t when t.Equals("Domain Certificate", StringComparison.OrdinalIgnoreCase) => CredentialType.DomainCertificate,
        var t when t.Equals("Domain Visible Password", StringComparison.OrdinalIgnoreCase) => CredentialType.DomainVisiblePassword,
        var t when t.Equals("Generic Certificate", StringComparison.OrdinalIgnoreCase) => CredentialType.GenericCertificate,
        var t when t.Equals("Domain Extended", StringComparison.OrdinalIgnoreCase) => CredentialType.DomainExtended,
        _ => CredentialType.Unknown
    };

    // ── Section 2: Git credential storage ─────────────────────────────────

    /// <summary>
    /// Git credential helper (CLI first, <c>.gitconfig</c> fallback when git
    /// is absent), the plaintext <c>.git-credentials</c> store, and embedded
    /// credentials in the global config.
    /// </summary>
    internal async Task GatherGitCredentialsAsync(CredentialState state, string userProfile, CancellationToken ct)
    {
        var git = state.GitCredentials;
        try
        {
            var helper = await GetGitHelperAsync(ct);
            if (string.IsNullOrEmpty(helper))
                helper = ReadGitHelperFromConfig(Path.Combine(userProfile, ".gitconfig"));
            git.HelperType = helper ?? string.Empty;

            var storePath = Path.Combine(userProfile, ".git-credentials");
            if (File.Exists(storePath))
            {
                git.StorePlaintextExists = true;
                git.StorePlaintextPath = storePath;
                git.StorePlaintextEntryCount = CountNonEmptyLines(storePath);
            }

            var configPath = Path.Combine(userProfile, ".gitconfig");
            if (File.Exists(configPath))
                git.GlobalConfigHasCredentials = FileContainsEmbeddedCredentials(configPath);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            state.GatherErrors.Add($"Git credentials: could not be checked ({ex.GetType().Name}).");
        }
    }

    /// <summary>
    /// Runs <c>git config --global credential.helper</c>. Returns null when
    /// no helper is set or git is not installed — both mean "no helper", and
    /// the caller falls back to reading <c>.gitconfig</c> directly.
    /// </summary>
    internal static async Task<string?> GetGitHelperAsync(CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunCmdAsync("git config --global credential.helper", ct);
            if (string.IsNullOrWhiteSpace(output)) return null;
            // git missing prints "'git' is not recognized..." to stderr,
            // which ShellHelper returns as the output — not a helper name.
            if (output.Contains("not recognized", StringComparison.OrdinalIgnoreCase)) return null;
            // A helper is a single token ("manager-core", "store",
            // "cache --timeout 3600"). Anything with a path separator or
            // colon is an error message, not a helper.
            var first = output.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (first == null || first.Contains('\\') || first.Contains('/') || first.Contains(':')) return null;
            return first;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>Reads the <c>helper</c> value from a <c>.gitconfig</c> file's [credential] section.</summary>
    internal static string? ReadGitHelperFromConfig(string configPath)
    {
        if (!File.Exists(configPath)) return null;
        var inCredentialSection = false;
        foreach (var rawLine in File.ReadLines(configPath))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('['))
            {
                inCredentialSection = line.Equals("[credential]", StringComparison.OrdinalIgnoreCase);
                continue;
            }
            if (!inCredentialSection) continue;
            var eq = line.IndexOf('=');
            if (eq < 0) continue;
            if (line[..eq].Trim().Equals("helper", StringComparison.OrdinalIgnoreCase))
            {
                var value = line[(eq + 1)..].Trim();
                return value.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            }
        }
        return null;
    }

    internal static int CountNonEmptyLines(string path)
    {
        var count = 0;
        foreach (var line in File.ReadLines(path))
        {
            if (!string.IsNullOrWhiteSpace(line)) count++;
        }
        return count;
    }

    /// <summary>True when a config file embeds credentials in a URL (user:password@host).</summary>
    internal static bool FileContainsEmbeddedCredentials(string path)
    {
        // user:pass@ — the ':' before '@' with no '/' between distinguishes
        // credentials from a host:port pair.
        var pattern = new Regex(@"://[^/\s:]+:[^/\s@]+@", RegexOptions.Compiled);
        return pattern.IsMatch(File.ReadAllText(path));
    }

    // ── Section 3: SSH keys ───────────────────────────────────────────────

    private static readonly HashSet<string> SshPrivateKeyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"
    };

    /// <summary>
    /// Scans <c>.ssh</c> for private keys. A missing directory means no keys
    /// to check, not an error. Files that cannot be read are counted and
    /// reported as a gather error.
    /// </summary>
    internal void GatherSshKeys(CredentialState state, string sshDirectory)
    {
        if (!Directory.Exists(sshDirectory)) return;
        var failures = 0;
        foreach (var file in Directory.EnumerateFiles(sshDirectory))
        {
            var name = Path.GetFileName(file) ?? string.Empty;
            if (!IsLikelyPrivateKeyFile(name)) continue;
            try
            {
                var info = InspectSshPrivateKey(file);
                if (info != null) state.SshKeys.Add(info);
            }
            catch
            {
                failures++;
            }
        }
        if (failures > 0) state.GatherErrors.Add($"SSH keys: {failures} key file(s) could not be read.");
    }

    internal static bool IsLikelyPrivateKeyFile(string fileName)
    {
        if (fileName.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)) return false;
        if (fileName.Equals("known_hosts", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("config", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("authorized_keys", StringComparison.OrdinalIgnoreCase))
            return false;
        if (SshPrivateKeyNames.Contains(fileName)) return true;
        if (fileName.EndsWith(".pem", StringComparison.OrdinalIgnoreCase)) return true;
        // Any other extensionless id_* file is a key candidate; the content
        // check in InspectSshPrivateKey drops non-keys.
        return fileName.StartsWith("id_", StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrEmpty(Path.GetExtension(fileName));
    }

    /// <summary>
    /// Inspects one private key file. Returns null when the content is not a
    /// private key. Throws when the file cannot be read (caller counts it).
    /// Key bits come from the sibling .pub file when present (exact); the
    /// PEM header only yields the algorithm, leaving bits 0 = unknown
    /// (IsWeakSshKey treats 0 as "unknown", never as weak).
    /// </summary>
    internal static SshKeyInfo? InspectSshPrivateKey(string path)
    {
        var text = File.ReadAllText(path);
        if (!text.Contains("PRIVATE KEY", StringComparison.Ordinal)) return null;

        var info = new SshKeyInfo
        {
            FileName = Path.GetFileName(path) ?? string.Empty,
            AgeDays = Math.Max(0, (int)(DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(path)).TotalDays),
        };

        var pubPath = path + ".pub";
        if (File.Exists(pubPath))
        {
            try
            {
                var parsed = ParseSshPublicKeyLine(File.ReadAllText(pubPath));
                if (parsed != null)
                {
                    info.Algorithm = parsed.Value.Algorithm;
                    info.KeyBits = parsed.Value.KeyBits;
                }
            }
            catch
            {
                // Unreadable .pub — fall through to the PEM header.
            }
        }

        if (string.IsNullOrEmpty(info.Algorithm))
            info.Algorithm = DetectPrivateKeyAlgorithm(text);

        info.HasPassphrase = DetectSshKeyPassphrase(text);
        (info.WorldReadable, _, _) = CheckFileReadability(path);
        return info;
    }

    /// <summary>
    /// Parses one OpenSSH public-key line ("ssh-rsa AAAA... comment") into
    /// algorithm + bit size. RSA/DSA bits are read from the key blob itself.
    /// </summary>
    internal static (string Algorithm, int KeyBits)? ParseSshPublicKeyLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return null;
        var type = parts[0];
        var algorithm = type switch
        {
            "ssh-rsa" => "rsa",
            "ssh-dss" => "dsa",
            "ssh-ed25519" => "ed25519",
            var t when t.StartsWith("ecdsa-sha2-", StringComparison.Ordinal) => "ecdsa",
            var t when t.StartsWith("sk-ssh-ed25519@", StringComparison.Ordinal) => "ed25519",
            var t when t.StartsWith("sk-ecdsa-sha2-", StringComparison.Ordinal) => "ecdsa",
            _ => null
        };
        if (algorithm == null) return null;

        var bits = algorithm switch
        {
            "ed25519" => 256,
            "ecdsa" => type.Contains("nistp384", StringComparison.Ordinal) ? 384
                : type.Contains("nistp521", StringComparison.Ordinal) ? 521 : 256,
            "rsa" => GetSshBlobKeyBits(parts[1], "ssh-rsa", mpintIndex: 1),
            "dsa" => GetSshBlobKeyBits(parts[1], "ssh-dss", mpintIndex: 0),
            _ => 0
        };
        return (algorithm, bits);
    }

    /// <summary>
    /// Bit size of the mpint at the given index in a base64 public-key blob
    /// (index 0 = first mpint after the type string, 1 = second). Returns 0
    /// when the blob cannot be parsed — 0 means "unknown", never a claim.
    /// </summary>
    internal static int GetSshBlobKeyBits(string base64, string expectedType, int mpintIndex)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64);
            using var reader = new BinaryReader(new MemoryStream(bytes));
            var type = ReadSshString(reader);
            if (!type.Equals(expectedType, StringComparison.Ordinal)) return 0;
            byte[]? mpint = null;
            for (var i = 0; i <= mpintIndex; i++)
                mpint = ReadSshMpint(reader);
            if (mpint == null) return 0;
            var firstNonZero = Array.FindIndex(mpint, b => b != 0);
            if (firstNonZero < 0) return 0;
            var bits = (mpint.Length - firstNonZero - 1) * 8;
            var top = mpint[firstNonZero];
            while (top != 0) { bits++; top >>= 1; }
            return bits;
        }
        catch
        {
            return 0;
        }
    }

    private static string ReadSshString(BinaryReader reader)
    {
        var length = ReadSshInt32(reader);
        return System.Text.Encoding.ASCII.GetString(reader.ReadBytes(length));
    }

    private static byte[] ReadSshMpint(BinaryReader reader)
    {
        var length = ReadSshInt32(reader);
        return reader.ReadBytes(length);
    }

    private static int ReadSshInt32(BinaryReader reader)
    {
        var bytes = reader.ReadBytes(4);
        if (bytes.Length < 4) throw new InvalidDataException("Truncated SSH key blob.");
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return BitConverter.ToInt32(bytes, 0);
    }

    /// <summary>
    /// Algorithm from a private-key file's header. OpenSSH-format keys carry
    /// the key type inside the base64 body; legacy PEM headers name it
    /// directly; PKCS#8 headers do not, so the DER OIDs are scanned.
    /// Returns "" when the algorithm cannot be determined.
    /// </summary>
    internal static string DetectPrivateKeyAlgorithm(string text)
    {
        if (text.Contains("RSA PRIVATE KEY", StringComparison.Ordinal)) return "rsa";
        if (text.Contains("EC PRIVATE KEY", StringComparison.Ordinal)) return "ecdsa";
        if (text.Contains("DSA PRIVATE KEY", StringComparison.Ordinal)) return "dsa";
        if (text.Contains("OPENSSH PRIVATE KEY", StringComparison.Ordinal))
        {
            var body = ExtractPemBody(text, "OPENSSH PRIVATE KEY");
            if (body != null)
            {
                try
                {
                    var decoded = Convert.FromBase64String(body);
                    using var reader = new BinaryReader(new MemoryStream(decoded));
                    // openssh-key-v1\0 magic (15 bytes), then cipher, kdf,
                    // kdf options, key count, then the first public-key blob.
                    reader.ReadBytes("openssh-key-v1".Length + 1);
                    ReadSshString(reader); // cipher
                    ReadSshString(reader); // kdf
                    ReadSshString(reader); // kdf options
                    ReadSshInt32(reader); // key count
                    var pubBlob = ReadSshMpint(reader);
                    using var pubReader = new BinaryReader(new MemoryStream(pubBlob));
                    var keyType = ReadSshString(pubReader);
                    return keyType switch
                    {
                        "ssh-rsa" => "rsa",
                        "ssh-dss" => "dsa",
                        "ssh-ed25519" => "ed25519",
                        var t when t.StartsWith("ecdsa-sha2-", StringComparison.Ordinal) => "ecdsa",
                        _ => ""
                    };
                }
                catch
                {
                    return "";
                }
            }
            return "";
        }
        if (text.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal)) return "";
        if (text.Contains("PRIVATE KEY", StringComparison.Ordinal))
        {
            // PKCS#8: scan the DER for the algorithm OID.
            var body = ExtractPemBody(text, "PRIVATE KEY");
            if (body != null)
            {
                try
                {
                    var der = Convert.FromBase64String(body);
                    if (ContainsBytes(der, new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 })) return "rsa"; // rsaEncryption
                    if (ContainsBytes(der, new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 })) return "ecdsa"; // id-ecPublicKey
                    if (ContainsBytes(der, new byte[] { 0x2B, 0x65, 0x70 })) return "ed25519"; // Ed25519
                }
                catch
                {
                    return "";
                }
            }
        }
        return "";
    }

    /// <summary>
    /// True when the key is passphrase-protected. Legacy PEM carries explicit
    /// encryption headers; OpenSSH-format keys carry the cipher name inside
    /// the base64 body (unencrypted keys record cipher "none").
    /// </summary>
    internal static bool DetectSshKeyPassphrase(string text)
    {
        if (text.Contains("ENCRYPTED", StringComparison.OrdinalIgnoreCase)) return true;
        var body = ExtractPemBody(text, "OPENSSH PRIVATE KEY");
        if (body == null) return false;
        try
        {
            var decoded = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(body));
            return decoded.Contains("aes256", StringComparison.OrdinalIgnoreCase)
                || decoded.Contains("aes128", StringComparison.OrdinalIgnoreCase)
                || decoded.Contains("aes192", StringComparison.OrdinalIgnoreCase)
                || decoded.Contains("3des", StringComparison.OrdinalIgnoreCase)
                || decoded.Contains("bcrypt", StringComparison.OrdinalIgnoreCase)
                || decoded.Contains("argon2", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Extracts the base64 body between a PEM header/footer pair. The
    /// markers are built from the label at runtime so the full header text
    /// never appears as a literal in this file.
    /// </summary>
    internal static string? ExtractPemBody(string text, string label)
    {
        var begin = "-----BEGIN " + label + "-----";
        var end = "-----END " + label + "-----";
        var start = text.IndexOf(begin, StringComparison.Ordinal);
        if (start < 0) return null;
        var bodyStart = start + begin.Length;
        var stop = text.IndexOf(end, bodyStart, StringComparison.Ordinal);
        if (stop < 0) return null;
        var body = text[bodyStart..stop];
        return string.Concat(body.Where(c => !char.IsWhiteSpace(c)));
    }

    private static bool ContainsBytes(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return false;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    // ── Section 4: Plaintext credential files ─────────────────────────────

    /// <summary>
    /// Scans the known credential filenames at the top level of each root
    /// (no recursive walk — bounded by design). Files that cannot be read
    /// are counted and reported as a gather error.
    /// </summary>
    internal void GatherCredentialFiles(CredentialState state, IEnumerable<(string Root, string Source)> roots)
    {
        var failures = 0;
        foreach (var (root, source) in roots)
        {
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
            foreach (var pattern in SecretFilePatterns)
            {
                var path = Path.Combine(root, pattern);
                try
                {
                    if (!File.Exists(path)) continue;
                    var info = InspectCredentialFile(path, source);
                    if (info != null) state.CredentialFiles.Add(info);
                }
                catch
                {
                    failures++;
                }
            }
        }
        if (failures > 0) state.GatherErrors.Add($"Credential files: {failures} file(s) could not be read.");
    }

    internal static CredentialFileInfo? InspectCredentialFile(string path, string source)
    {
        var fi = new FileInfo(path);
        var content = ReadFileHead(path, MaxCredentialFileReadBytes);
        var (hasSecrets, patterns) = ScanContentForSecrets(content);
        return new CredentialFileInfo
        {
            Path = path,
            FileName = fi.Name,
            Source = source,
            SizeBytes = fi.Length,
            ContainsPlaintextSecrets = hasSecrets,
            DetectedPatterns = patterns,
        };
    }

    internal static string ReadFileHead(string path, int maxBytes)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new byte[Math.Min(maxBytes, (int)Math.Min(stream.Length, maxBytes))];
        var read = stream.Read(buffer, 0, buffer.Length);
        return System.Text.Encoding.UTF8.GetString(buffer, 0, read);
    }

    /// <summary>Scans text for plaintext-secret patterns. Pure for testing.</summary>
    internal static (bool HasSecrets, List<string> Patterns) ScanContentForSecrets(string content)
    {
        var found = new List<string>();
        foreach (var (pattern, label) in SecretContentPatterns)
        {
            if (pattern.IsMatch(content) && !found.Contains(label))
                found.Add(label);
        }
        return (found.Count > 0, found);
    }

    // ── Section 5: RDP files ──────────────────────────────────────────────

    /// <summary>Finds <c>.rdp</c> files at the top level of each root and parses them for saved credentials.</summary>
    internal void GatherRdpFiles(CredentialState state, IEnumerable<string> roots)
    {
        var failures = 0;
        foreach (var root in roots)
        {
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
            string[] files;
            try
            {
                files = Directory.GetFiles(root, "*.rdp", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                failures++;
                continue;
            }
            foreach (var file in files)
            {
                try
                {
                    var info = ParseRdpFile(file, File.ReadAllText(file));
                    if (info != null) state.RdpFiles.Add(info);
                }
                catch
                {
                    failures++;
                }
            }
        }
        if (failures > 0) state.GatherErrors.Add($"RDP files: {failures} file(s) could not be read.");
    }

    /// <summary>Parses one .rdp file. Returns null when it carries no credential fields at all.</summary>
    internal static RdpFileInfo? ParseRdpFile(string path, string content)
    {
        var info = new RdpFileInfo { Path = path, ServerAddress = Path.GetFileNameWithoutExtension(path) ?? string.Empty };
        var sawAny = false;
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("full address:s:", StringComparison.OrdinalIgnoreCase))
            {
                info.ServerAddress = line["full address:s:".Length..].Trim();
                sawAny = true;
            }
            else if (line.StartsWith("username:s:", StringComparison.OrdinalIgnoreCase))
            {
                if (line["username:s:".Length..].Trim().Length > 0) { info.HasSavedUsername = true; sawAny = true; }
            }
            else if (line.StartsWith("password 51:b:", StringComparison.OrdinalIgnoreCase))
            {
                info.HasEmbeddedPassword = true;
                sawAny = true;
            }
            else if (line.StartsWith("gatewayusername:s:", StringComparison.OrdinalIgnoreCase))
            {
                if (line["gatewayusername:s:".Length..].Trim().Length > 0) { info.GatewayCredentialsSaved = true; sawAny = true; }
            }
        }
        return sawAny ? info : null;
    }

    // ── Section 6: Browser credential stores ──────────────────────────────

    /// <summary>
    /// Chromium browsers (Chrome, Edge, Brave): Default + Profile * dirs,
    /// password count read from a temp copy of the Login Data SQLite DB
    /// (the live file is usually locked by the running browser).
    /// Firefox: logins.json entry count; master-password state is not
    /// visible in the local profile, so it stays null (unknown).
    /// </summary>
    internal void GatherBrowserStores(CredentialState state, string localAppData, string roamingAppData)
    {
        var chromium = new[]
        {
            ("Chrome", Path.Combine(localAppData, "Google", "Chrome", "User Data")),
            ("Edge", Path.Combine(localAppData, "Microsoft", "Edge", "User Data")),
            ("Brave", Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data")),
        };
        foreach (var (browser, userData) in chromium)
        {
            if (!Directory.Exists(userData)) continue;
            foreach (var profileDir in EnumerateChromiumProfiles(userData))
            {
                var loginData = Path.Combine(profileDir, "Login Data");
                if (!File.Exists(loginData)) continue;
                state.BrowserStores.Add(new BrowserCredentialStore
                {
                    BrowserName = ProfileDisplayName(browser, profileDir),
                    ProfilePath = profileDir,
                    LoginDataExists = true,
                    StoredPasswordCount = CountChromiumLogins(loginData),
                    EncryptedWithDPAPI = true,
                    // Chromium browsers have no master password — DPAPI only.
                    MasterPasswordEnabled = false,
                });
            }
        }

        var firefoxProfiles = Path.Combine(roamingAppData, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefoxProfiles))
        {
            foreach (var profileDir in Directory.EnumerateDirectories(firefoxProfiles))
            {
                var loginsJson = Path.Combine(profileDir, "logins.json");
                if (!File.Exists(loginsJson)) continue;
                state.BrowserStores.Add(new BrowserCredentialStore
                {
                    BrowserName = "Firefox",
                    ProfilePath = profileDir,
                    LoginDataExists = true,
                    StoredPasswordCount = CountFirefoxLogins(loginsJson),
                    EncryptedWithDPAPI = false,
                    // Firefox uses its own key store (key4.db); master-password
                    // state is not readable from the profile — do not guess.
                    MasterPasswordEnabled = null,
                });
            }
        }
    }

    internal static IEnumerable<string> EnumerateChromiumProfiles(string userDataDir)
    {
        var profiles = new List<string>();
        var defaultDir = Path.Combine(userDataDir, "Default");
        if (Directory.Exists(defaultDir)) profiles.Add(defaultDir);
        foreach (var dir in Directory.EnumerateDirectories(userDataDir, "Profile *"))
            profiles.Add(dir);
        return profiles;
    }

    internal static string ProfileDisplayName(string browser, string profileDir)
    {
        var dirName = Path.GetFileName(profileDir) ?? string.Empty;
        return dirName.Equals("Default", StringComparison.OrdinalIgnoreCase)
            ? browser
            : $"{browser} ({dirName})";
    }

    /// <summary>
    /// Counts rows in a Chromium Login Data DB. Copies the DB (plus WAL /
    /// journal sidecars) to temp files first so a running browser's lock
    /// does not block the read. Returns -1 (unknown) on any failure.
    /// </summary>
    internal static int CountChromiumLogins(string loginDataPath)
    {
        var tempBase = Path.Combine(Path.GetTempPath(), $"winsentinel_logindata_{Guid.NewGuid():N}");
        try
        {
            File.Copy(loginDataPath, tempBase, overwrite: true);
            foreach (var suffix in new[] { "-wal", "-journal" })
            {
                var sidecar = loginDataPath + suffix;
                if (File.Exists(sidecar)) File.Copy(sidecar, tempBase + suffix, overwrite: true);
            }
            using var conn = new SqliteConnection($"Data Source={tempBase};Mode=ReadOnly;");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM logins";
            return cmd.ExecuteScalar() is long count ? (int)Math.Min(count, int.MaxValue) : -1;
        }
        catch
        {
            return -1;
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-journal" })
            {
                try { File.Delete(tempBase + suffix); } catch { }
            }
        }
    }

    /// <summary>Counts entries in a Firefox logins.json file. Returns -1 (unknown) on any failure.</summary>
    internal static int CountFirefoxLogins(string loginsJsonPath)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(loginsJsonPath));
            if (doc.RootElement.TryGetProperty("logins", out var logins) && logins.ValueKind == JsonValueKind.Array)
                return logins.GetArrayLength();
            return -1;
        }
        catch
        {
            return -1;
        }
    }

    // ── Section 7: Cloud CLI credential caches ────────────────────────────

    internal void GatherCloudCredentials(CredentialState state, string userProfile, string roamingAppData)
    {
        GatherAwsCredentials(state, userProfile);
        GatherAzureCredentials(state, userProfile);
        GatherGcpCredentials(state, roamingAppData);
        GatherDockerCredentials(state, userProfile);
    }

    internal void GatherAwsCredentials(CredentialState state, string userProfile)
    {
        var credPath = Path.Combine(userProfile, ".aws", "credentials");
        if (!File.Exists(credPath)) return;
        try
        {
            var text = File.ReadAllText(credPath);
            var hasSecretKey = text.Contains("aws_secret_access_key", StringComparison.OrdinalIgnoreCase)
                || text.Contains("aws_session_token", StringComparison.OrdinalIgnoreCase);
            var mfa = false;
            var configPath = Path.Combine(userProfile, ".aws", "config");
            if (File.Exists(configPath))
            {
                try { mfa = File.ReadAllText(configPath).Contains("mfa_serial", StringComparison.OrdinalIgnoreCase); } catch { }
            }
            state.CloudCredentials.Add(new CloudCredentialInfo
            {
                Provider = "AWS",
                CredentialPath = credPath,
                PlaintextTokens = hasSecretKey,
                MfaConfigured = mfa,
                AgeDays = Math.Max(0, (int)(DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(credPath)).TotalDays),
                Profiles = ParseIniSectionNames(text),
            });
        }
        catch
        {
            state.GatherErrors.Add("Cloud credentials: AWS credentials file could not be read.");
        }
    }

    internal void GatherAzureCredentials(CredentialState state, string userProfile)
    {
        var tokenPath = Path.Combine(userProfile, ".azure", "accessTokens.json");
        if (!File.Exists(tokenPath)) return;
        try
        {
            var profiles = new List<string>();
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(tokenPath));
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in doc.RootElement.EnumerateArray())
                    {
                        if (el.TryGetProperty("tenantId", out var tenant) && tenant.ValueKind == JsonValueKind.String)
                        {
                            var value = tenant.GetString();
                            if (!string.IsNullOrEmpty(value) && !profiles.Contains(value)) profiles.Add(value);
                        }
                    }
                }
            }
            catch
            {
                // Unparseable cache is still a plaintext token cache.
            }
            state.CloudCredentials.Add(new CloudCredentialInfo
            {
                Provider = "Azure",
                CredentialPath = tokenPath,
                PlaintextTokens = true,
                // MFA is an account/IdP property; the local token cache
                // carries no signal — do not warn on its absence.
                MfaConfigured = true,
                AgeDays = Math.Max(0, (int)(DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(tokenPath)).TotalDays),
                Profiles = profiles,
            });
        }
        catch
        {
            state.GatherErrors.Add("Cloud credentials: Azure token cache could not be read.");
        }
    }

    internal void GatherGcpCredentials(CredentialState state, string roamingAppData)
    {
        var adcPath = Path.Combine(roamingAppData, "gcloud", "application_default_credentials.json");
        var legacyDb = Path.Combine(roamingAppData, "gcloud", "credentials.db");
        var path = File.Exists(adcPath) ? adcPath : File.Exists(legacyDb) ? legacyDb : null;
        if (path == null) return;
        try
        {
            state.CloudCredentials.Add(new CloudCredentialInfo
            {
                Provider = "GCP",
                CredentialPath = path,
                PlaintextTokens = true,
                // As with Azure: no local MFA signal — do not warn.
                MfaConfigured = true,
                AgeDays = Math.Max(0, (int)(DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(path)).TotalDays),
                Profiles = new List<string> { "default" },
            });
        }
        catch
        {
            state.GatherErrors.Add("Cloud credentials: GCP credential file could not be read.");
        }
    }

    internal void GatherDockerCredentials(CredentialState state, string userProfile)
    {
        var configPath = Path.Combine(userProfile, ".docker", "config.json");
        if (!File.Exists(configPath)) return;
        try
        {
            var registries = new List<string>();
            using var doc = JsonDocument.Parse(File.ReadAllText(configPath));
            if (doc.RootElement.TryGetProperty("auths", out var auths) && auths.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in auths.EnumerateObject())
                {
                    // An "auth" value is a base64 user:pass pair stored in plaintext.
                    if (prop.Value.TryGetProperty("auth", out var auth) && auth.ValueKind == JsonValueKind.String
                        && !string.IsNullOrEmpty(auth.GetString()))
                        registries.Add(prop.Name);
                }
            }
            if (registries.Count == 0) return; // Config exists but holds no stored credentials.
            state.CloudCredentials.Add(new CloudCredentialInfo
            {
                Provider = "Docker",
                CredentialPath = configPath,
                PlaintextTokens = true,
                // As with Azure: no local MFA signal — do not warn.
                MfaConfigured = true,
                AgeDays = Math.Max(0, (int)(DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(configPath)).TotalDays),
                Profiles = registries,
            });
        }
        catch
        {
            state.GatherErrors.Add("Cloud credentials: Docker config could not be read.");
        }
    }

    /// <summary>Section names ([name]) from an INI-style file. Pure for testing.</summary>
    internal static List<string> ParseIniSectionNames(string text)
    {
        var names = new List<string>();
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('[') && line.EndsWith(']') && line.Length > 2)
            {
                var name = line[1..^1].Trim();
                if (name.Length > 0 && !names.Contains(name)) names.Add(name);
            }
        }
        return names;
    }

    // ── Section 8: Sensitive file permissions ─────────────────────────────

    /// <summary>
    /// Records over-broad permissions for the sensitive files found above.
    /// Only files readable by Everyone or by other local users are recorded;
    /// a clean file produces no entry (and no finding).
    /// </summary>
    internal void GatherSensitiveFilePermissions(CredentialState state, IEnumerable<(string Path, string Description)> files)
    {
        foreach (var (path, description) in files)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) continue;
            var (world, other, inherited) = CheckFileReadability(path);
            if (!world && !other) continue;
            state.SensitiveFilePermissions.Add(new SensitiveFilePermission
            {
                Path = path,
                Description = description,
                WorldReadable = world,
                OtherUsersCanRead = other,
                InheritedPermissions = inherited,
            });
        }
    }

    /// <summary>
    /// Checks whether a file grants read access to Everyone (world-readable)
    /// or to Authenticated Users / BUILTIN\Users (other local users can read).
    /// Deny rules are ignored (an explicit Allow for a broad SID is the
    /// signal). Returns (false, false, true) when the ACL cannot be read —
    /// unknown is reported as "not broadly readable", never as readable.
    /// </summary>
    internal static (bool WorldReadable, bool OtherUsersCanRead, bool InheritedPermissions) CheckFileReadability(string path)
    {
        try
        {
            var security = new FileInfo(path).GetAccessControl();
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var authSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var world = false;
            var other = false;
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                if ((rule.FileSystemRights & (FileSystemRights.ReadData | FileSystemRights.Read)) == 0) continue;
                if (rule.IdentityReference is not SecurityIdentifier sid) continue;
                if (sid == worldSid) world = true;
                else if (sid == authSid || sid == usersSid) other = true;
            }
            return (world, other, !security.AreAccessRulesProtected);
        }
        catch
        {
            return (false, false, true);
        }
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

            // Count could not be read (browser running, DB locked/corrupt):
            // report the store's existence, never a zero count.
            if (store.StoredPasswordCount < 0)
            {
                result.Findings.Add(Finding.Info(
                    $"{store.BrowserName}: password count unknown",
                    $"{store.BrowserName} has a credential store at {store.ProfilePath}, but the password count could not be read (the browser may be running or the database may be locked).",
                    Category));
                continue;
            }

            // Master-password state unknown (Firefox): report the count
            // without claiming the store is unprotected.
            if (store.StoredPasswordCount > 0 && store.MasterPasswordEnabled == null)
            {
                result.Findings.Add(Finding.Info(
                    $"{store.BrowserName}: {store.StoredPasswordCount} passwords stored",
                    $"{store.BrowserName} stores {store.StoredPasswordCount} password(s). Whether a master password protects them could not be determined from the local profile.",
                    Category,
                    $"Review stored passwords in {store.BrowserName} settings, or use a dedicated password manager."));
                continue;
            }

            if (store.StoredPasswordCount > 0 && store.MasterPasswordEnabled == false)
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
            else if (store.StoredPasswordCount > 0 && store.MasterPasswordEnabled == true)
            {
                result.Findings.Add(Finding.Pass(
                    $"{store.BrowserName}: master password enabled",
                    $"{store.BrowserName} stores {store.StoredPasswordCount} password(s) with master password protection.",
                    Category));
            }
        }

        var totalPasswords = stores.Where(s => s.StoredPasswordCount > 0).Sum(s => s.StoredPasswordCount);
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
        // KeyBits 0 means "unknown" (no .pub file to measure) — never
        // flag an unmeasured key as weak.
        if (key.Algorithm.Equals("rsa", StringComparison.OrdinalIgnoreCase) && key.KeyBits > 0 && key.KeyBits < 2048)
            return true;
        if (key.Algorithm.Equals("ecdsa", StringComparison.OrdinalIgnoreCase) && key.KeyBits > 0 && key.KeyBits < 384)
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
            TotalBrowserPasswords = state.BrowserStores.Where(s => s.StoredPasswordCount > 0).Sum(s => s.StoredPasswordCount),
            BrowsersWithoutMasterPassword = state.BrowserStores.Count(s => s.StoredPasswordCount > 0 && s.MasterPasswordEnabled == false),
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
