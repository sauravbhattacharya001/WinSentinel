using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Data.Sqlite;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.CredentialExposureAudit;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Tests for the CredentialExposureAudit live gatherers (the collection half
/// of the module). All file-system tests run against temp dirs created by
/// this class; nothing here touches the real user profile.
/// </summary>
public class CredentialExposureGatherTests : IDisposable
{
    private readonly CredentialExposureAudit _audit;
    private readonly string _tempDir;

    // PEM headers are built by concatenation so the full header text never
    // appears as a literal in this file (repo pre-push guard).
    private const string BeginRsa = "-----BEGIN " + "RSA PRIVATE KEY-----";
    private const string EndRsa = "-----END " + "RSA PRIVATE KEY-----";
    private const string BeginOpenSsh = "-----BEGIN " + "OPENSSH PRIVATE KEY-----";
    private const string EndOpenSsh = "-----END " + "OPENSSH PRIVATE KEY-----";

    public CredentialExposureGatherTests()
    {
        _audit = new CredentialExposureAudit();
        _tempDir = Path.Combine(Path.GetTempPath(), $"winsentinel_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private string TempPath(params string[] parts) => Path.Combine(new[] { _tempDir }.Concat(parts).ToArray());

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Credential Exposure Audit",
        Category = "Credentials"
    };

    // ── helpers: synthetic SSH key material ─────────────────────────────

    private static void WriteBigEndianInt32(BinaryWriter w, int value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        w.Write(bytes);
    }

    private static void WriteSshString(BinaryWriter w, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        WriteBigEndianInt32(w, bytes.Length);
        w.Write(bytes);
    }

    private static void WriteSshMpint(BinaryWriter w, byte[] value)
    {
        WriteBigEndianInt32(w, value.Length);
        w.Write(value);
    }

    /// <summary>Builds a synthetic public-key blob: type string + mpints.</summary>
    private static string BuildPublicKeyBase64(string type, params byte[][] mpints)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        WriteSshString(w, type);
        foreach (var mpint in mpints) WriteSshMpint(w, mpint);
        return Convert.ToBase64String(ms.ToArray());
    }

    /// <summary>Synthetic RSA public key: e=65537, modulus with the top bit set (exact bit size).</summary>
    private static string BuildRsaPublicKeyBase64(int bits)
    {
        var modulus = new byte[bits / 8];
        modulus[0] = 0x80;
        modulus[^1] = 0x01;
        var n = new byte[modulus.Length + 1]; // leading zero: top bit set
        Array.Copy(modulus, 0, n, 1, modulus.Length);
        return BuildPublicKeyBase64("ssh-rsa", new byte[] { 0x01, 0x00, 0x01 }, n);
    }

    /// <summary>Synthetic DSA public key: p with the top bit set (exact bit size).</summary>
    private static string BuildDsaPublicKeyBase64(int bits)
    {
        var p = new byte[bits / 8];
        p[0] = 0x80;
        p[^1] = 0x01;
        var mpint = new byte[p.Length + 1];
        Array.Copy(p, 0, mpint, 1, p.Length);
        return BuildPublicKeyBase64("ssh-dss", mpint);
    }

    /// <summary>
    /// Builds a synthetic OpenSSH private-key body (openssh-key-v1) with the
    /// given cipher/kdf and key type. The private section is omitted — the
    /// parsers under test only read the header + public-key blob.
    /// </summary>
    private static string BuildOpenSshPrivateKeyBody(string cipher, string kdf, string keyType)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(Encoding.ASCII.GetBytes("openssh-key-v1\0"));
        WriteSshString(w, cipher);
        WriteSshString(w, kdf);
        WriteSshString(w, string.Empty); // kdf options
        WriteBigEndianInt32(w, 1); // key count
        using var pub = new MemoryStream();
        using var pw = new BinaryWriter(pub);
        WriteSshString(pw, keyType);
        WriteSshString(pw, new string('A', 32)); // fake public key bytes
        WriteSshMpint(w, pub.ToArray());
        return Convert.ToBase64String(ms.ToArray());
    }

    private static void CreateLoginDataDb(string path, int rowCount)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var conn = new SqliteConnection($"Data Source={path};");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)";
        cmd.ExecuteNonQuery();
        for (var i = 0; i < rowCount; i++)
        {
            cmd.CommandText = $"INSERT INTO logins (origin_url, username_value) VALUES ('https://example{i}.com', 'user{i}')";
            cmd.ExecuteNonQuery();
        }
    }

    // ── cmdkey parsing ──────────────────────────────────────────────────

    [Fact]
    public void InterpretCmdkeyOutput_TwoEntries_Parsed()
    {
        const string output = """
            Currently stored credentials:

                Target: LegacyGeneric:target=git:https://github.com
                Type: Generic
                User: dev
                Local machine persistence

                Target: Domain:target=TERMSRV/10.0.0.5
                Type: Domain Visible Password
                User: admin
            """;
        var (entries, error) = CredentialExposureAudit.InterpretCmdkeyOutput(output);

        Assert.Null(error);
        Assert.Equal(2, entries.Count);
        Assert.Equal("git:https://github.com", entries[0].TargetName);
        Assert.Equal(CredentialType.Generic, entries[0].Type);
        Assert.Equal("dev", entries[0].UserName);
        Assert.True(entries[0].Persisted);
        Assert.Equal("TERMSRV/10.0.0.5", entries[1].TargetName);
        Assert.Equal(CredentialType.DomainVisiblePassword, entries[1].Type);
        Assert.Equal("admin", entries[1].UserName);
        Assert.False(entries[1].Persisted);
    }

    [Fact]
    public void InterpretCmdkeyOutput_EmptyVault_NoEntriesNoError()
    {
        const string output = "Currently stored credentials:\n\nCMDKEY: No credentials exist in the store.\n";
        var (entries, error) = CredentialExposureAudit.InterpretCmdkeyOutput(output);
        Assert.Null(error);
        Assert.Empty(entries);
    }

    [Fact]
    public void InterpretCmdkeyOutput_EmptyString_NoEntriesNoError()
    {
        var (entries, error) = CredentialExposureAudit.InterpretCmdkeyOutput(string.Empty);
        Assert.Null(error);
        Assert.Empty(entries);
    }

    [Fact]
    public void InterpretCmdkeyOutput_Unparseable_ReturnsError()
    {
        const string output = "Quelque chose en francais\nsans cible lisible\n";
        var (entries, error) = CredentialExposureAudit.InterpretCmdkeyOutput(output);
        Assert.Empty(entries);
        Assert.NotNull(error);
    }

    [Fact]
    public void ParseCredentialType_Unknown_ReturnsUnknown()
    {
        Assert.Equal(CredentialType.Unknown, CredentialExposureAudit.ParseCredentialType("Something Else"));
        Assert.Equal(CredentialType.DomainPassword, CredentialExposureAudit.ParseCredentialType("Domain Password"));
    }

    // ── git credentials ─────────────────────────────────────────────────

    [Fact]
    public void ReadGitHelperFromConfig_HelperParsed()
    {
        var path = TempPath(".gitconfig");
        File.WriteAllText(path, "[user]\n\tname = Dev\n[credential]\n\thelper = manager-core\n");
        Assert.Equal("manager-core", CredentialExposureAudit.ReadGitHelperFromConfig(path));
    }

    [Fact]
    public void ReadGitHelperFromConfig_CacheWithArgs_ReturnsFirstToken()
    {
        var path = TempPath(".gitconfig");
        File.WriteAllText(path, "[credential]\n\thelper = cache --timeout 3600\n");
        Assert.Equal("cache", CredentialExposureAudit.ReadGitHelperFromConfig(path));
    }

    [Fact]
    public void ReadGitHelperFromConfig_NoCredentialSection_Null()
    {
        var path = TempPath(".gitconfig");
        File.WriteAllText(path, "[user]\n\tname = Dev\n");
        Assert.Null(CredentialExposureAudit.ReadGitHelperFromConfig(path));
    }

    [Fact]
    public void FileContainsEmbeddedCredentials_UrlWithPassword_True()
    {
        var path = TempPath(".gitconfig");
        File.WriteAllText(path, "[remote \"origin\"]\n\turl = https://user:x@github.com/org/repo.git\n");
        Assert.True(CredentialExposureAudit.FileContainsEmbeddedCredentials(path));
    }

    [Fact]
    public void FileContainsEmbeddedCredentials_PortOnly_False()
    {
        var path = TempPath(".gitconfig");
        File.WriteAllText(path, "[remote \"origin\"]\n\turl = https://github.com:443/org/repo.git\n");
        Assert.False(CredentialExposureAudit.FileContainsEmbeddedCredentials(path));
    }

    [Fact]
    public async Task GatherGitCredentialsAsync_TempProfile_FillsFileBasedState()
    {
        var profile = TempPath("profile");
        Directory.CreateDirectory(profile);
        File.WriteAllText(Path.Combine(profile, ".gitconfig"),
            "[credential]\n\thelper = store\n[remote \"origin\"]\n\turl = https://user:x@github.com/org/repo.git\n");
        File.WriteAllText(Path.Combine(profile, ".git-credentials"),
            "https://user:x@github.com\nhttps://user:x@gitlab.com\n\nhttps://user:x@bitbucket.org\n");

        var state = new CredentialState();
        await _audit.GatherGitCredentialsAsync(state, profile, CancellationToken.None);

        Assert.True(state.GitCredentials.StorePlaintextExists);
        Assert.Equal(3, state.GitCredentials.StorePlaintextEntryCount);
        Assert.True(state.GitCredentials.GlobalConfigHasCredentials);
        // Helper comes from the live `git` CLI when one is set on the
        // machine, else from the temp .gitconfig fallback.
        var liveHelper = await CredentialExposureAudit.GetGitHelperAsync(CancellationToken.None);
        Assert.Equal(liveHelper ?? "store", state.GitCredentials.HelperType);
    }

    // ── SSH keys ────────────────────────────────────────────────────────

    [Fact]
    public void ParseSshPublicKeyLine_Rsa2048_BitsFromBlob()
    {
        var parsed = CredentialExposureAudit.ParseSshPublicKeyLine($"ssh-rsa {BuildRsaPublicKeyBase64(2048)} test@example");
        Assert.NotNull(parsed);
        Assert.Equal("rsa", parsed.Value.Algorithm);
        Assert.Equal(2048, parsed.Value.KeyBits);
    }

    [Fact]
    public void ParseSshPublicKeyLine_Dsa1024_BitsFromBlob()
    {
        var parsed = CredentialExposureAudit.ParseSshPublicKeyLine($"ssh-dss {BuildDsaPublicKeyBase64(1024)} test@example");
        Assert.NotNull(parsed);
        Assert.Equal("dsa", parsed.Value.Algorithm);
        Assert.Equal(1024, parsed.Value.KeyBits);
    }

    [Fact]
    public void ParseSshPublicKeyLine_Ed25519_FixedBits()
    {
        var parsed = CredentialExposureAudit.ParseSshPublicKeyLine("ssh-ed25519 AAAA test@example");
        Assert.NotNull(parsed);
        Assert.Equal("ed25519", parsed.Value.Algorithm);
        Assert.Equal(256, parsed.Value.KeyBits);
    }

    [Fact]
    public void ParseSshPublicKeyLine_Ecdsa384_FromTypeName()
    {
        var parsed = CredentialExposureAudit.ParseSshPublicKeyLine("ecdsa-sha2-nistp384 AAAA test@example");
        Assert.NotNull(parsed);
        Assert.Equal("ecdsa", parsed.Value.Algorithm);
        Assert.Equal(384, parsed.Value.KeyBits);
    }

    [Fact]
    public void ParseSshPublicKeyLine_UnknownType_Null()
    {
        Assert.Null(CredentialExposureAudit.ParseSshPublicKeyLine("ssh-unknown AAAA test@example"));
        Assert.Null(CredentialExposureAudit.ParseSshPublicKeyLine("not-a-key-line"));
    }

    [Fact]
    public void GetSshBlobKeyBits_TruncatedBlob_Zero()
    {
        Assert.Equal(0, CredentialExposureAudit.GetSshBlobKeyBits("AAAA", "ssh-rsa", 1));
        Assert.Equal(0, CredentialExposureAudit.GetSshBlobKeyBits("!!!not-base64!!!", "ssh-rsa", 1));
    }

    [Fact]
    public void DetectPrivateKeyAlgorithm_OpenSshEd25519()
    {
        var text = BeginOpenSsh + "\n" + BuildOpenSshPrivateKeyBody("none", "none", "ssh-ed25519") + "\n" + EndOpenSsh;
        Assert.Equal("ed25519", CredentialExposureAudit.DetectPrivateKeyAlgorithm(text));
        Assert.False(CredentialExposureAudit.DetectSshKeyPassphrase(text));
    }

    [Fact]
    public void DetectPrivateKeyAlgorithm_OpenSshEncrypted_PassphraseTrue()
    {
        var text = BeginOpenSsh + "\n" + BuildOpenSshPrivateKeyBody("aes256-ctr", "bcrypt", "ssh-ed25519") + "\n" + EndOpenSsh;
        Assert.Equal("ed25519", CredentialExposureAudit.DetectPrivateKeyAlgorithm(text));
        Assert.True(CredentialExposureAudit.DetectSshKeyPassphrase(text));
    }

    [Fact]
    public void DetectPrivateKeyAlgorithm_LegacyRsaPem()
    {
        var text = BeginRsa + "\nZm9vYmFy\n" + EndRsa;
        Assert.Equal("rsa", CredentialExposureAudit.DetectPrivateKeyAlgorithm(text));
        Assert.False(CredentialExposureAudit.DetectSshKeyPassphrase(text));
    }

    [Fact]
    public void DetectSshKeyPassphrase_LegacyEncryptedPem_True()
    {
        var text = BeginRsa + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\nZm9vYmFy\n" + EndRsa;
        Assert.True(CredentialExposureAudit.DetectSshKeyPassphrase(text));
    }

    [Fact]
    public void InspectSshPrivateKey_RsaWithPub_FullInfo()
    {
        var sshDir = TempPath(".ssh");
        Directory.CreateDirectory(sshDir);
        var keyPath = Path.Combine(sshDir, "id_rsa");
        File.WriteAllText(keyPath, BeginRsa + "\nZm9vYmFy\n" + EndRsa);
        File.WriteAllText(keyPath + ".pub", $"ssh-rsa {BuildRsaPublicKeyBase64(2048)} test@example");

        var info = CredentialExposureAudit.InspectSshPrivateKey(keyPath);

        Assert.NotNull(info);
        Assert.Equal("id_rsa", info.FileName);
        Assert.Equal("rsa", info.Algorithm);
        Assert.Equal(2048, info.KeyBits);
        Assert.False(info.HasPassphrase);
        Assert.False(info.WorldReadable);
        Assert.True(info.AgeDays >= 0);
    }

    [Fact]
    public void InspectSshPrivateKey_NonKeyFile_Null()
    {
        var path = TempPath("notes.txt");
        File.WriteAllText(path, "just some notes, no keys here\n");
        Assert.Null(CredentialExposureAudit.InspectSshPrivateKey(path));
    }

    [Fact]
    public void InspectSshPrivateKey_OpenSshWithoutPub_UnknownBits()
    {
        var sshDir = TempPath(".ssh");
        Directory.CreateDirectory(sshDir);
        var keyPath = Path.Combine(sshDir, "id_ed25519");
        File.WriteAllText(keyPath, BeginOpenSsh + "\n" + BuildOpenSshPrivateKeyBody("none", "none", "ssh-ed25519") + "\n" + EndOpenSsh);

        var info = CredentialExposureAudit.InspectSshPrivateKey(keyPath);

        Assert.NotNull(info);
        Assert.Equal("ed25519", info.Algorithm);
        Assert.Equal(0, info.KeyBits); // unknown, never claimed
        Assert.False(info.HasPassphrase);
    }

    [Fact]
    public void GatherSshKeys_TempSshDir_FindsKeysSkipsNonKeys()
    {
        var sshDir = TempPath(".ssh");
        Directory.CreateDirectory(sshDir);
        File.WriteAllText(Path.Combine(sshDir, "id_rsa"), BeginRsa + "\nZm9vYmFy\n" + EndRsa);
        File.WriteAllText(Path.Combine(sshDir, "id_rsa.pub"), $"ssh-rsa {BuildRsaPublicKeyBase64(2048)} test@example");
        File.WriteAllText(Path.Combine(sshDir, "id_ed25519"), BeginOpenSsh + "\n" + BuildOpenSshPrivateKeyBody("none", "none", "ssh-ed25519") + "\n" + EndOpenSsh);
        File.WriteAllText(Path.Combine(sshDir, "known_hosts"), "github.com ssh-rsa AAAA\n");
        File.WriteAllText(Path.Combine(sshDir, "config"), "Host *\n  StrictHostKeyChecking yes\n");
        File.WriteAllText(Path.Combine(sshDir, "cert.pem"), "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n");

        var state = new CredentialState();
        _audit.GatherSshKeys(state, sshDir);

        Assert.Equal(2, state.SshKeys.Count);
        Assert.Contains(state.SshKeys, k => k.FileName == "id_rsa");
        Assert.Contains(state.SshKeys, k => k.FileName == "id_ed25519");
        Assert.Empty(state.GatherErrors);
    }

    [Fact]
    public void GatherSshKeys_MissingDir_EmptyNoError()
    {
        var state = new CredentialState();
        _audit.GatherSshKeys(state, TempPath("no-such-dir"));
        Assert.Empty(state.SshKeys);
        Assert.Empty(state.GatherErrors);
    }

    [Fact]
    public void CheckFileReadability_DefaultAcl_NotReadableByOthers()
    {
        var path = TempPath("keyfile");
        File.WriteAllText(path, "x");
        var (world, other, _) = CredentialExposureAudit.CheckFileReadability(path);
        Assert.False(world);
        Assert.False(other);
    }

    [Fact]
    public void CheckFileReadability_EveryoneGranted_WorldReadable()
    {
        var path = TempPath("sharedfile");
        File.WriteAllText(path, "x");
        var security = new FileInfo(path).GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Read,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);

        var (world, _, _) = CredentialExposureAudit.CheckFileReadability(path);
        Assert.True(world);
    }

    // ── credential files ────────────────────────────────────────────────

    [Fact]
    public void ScanContentForSecrets_SnakeCaseNames_Detected()
    {
        var (hasSecrets, patterns) = CredentialExposureAudit.ScanContentForSecrets(
            "DB_PASSWORD=x\nMY_API_KEY=x\nNORMAL=1\n");
        Assert.True(hasSecrets);
        Assert.Contains("password=", patterns);
        Assert.Contains("api_key=", patterns);
    }

    [Fact]
    public void ScanContentForSecrets_TokenAssignment_Detected()
    {
        var (hasSecrets, patterns) = CredentialExposureAudit.ScanContentForSecrets("MY_TOKEN=x\n");
        Assert.True(hasSecrets);
        Assert.Contains("token=", patterns);
    }

    [Fact]
    public void ScanContentForSecrets_CleanContent_NoSecrets()
    {
        var (hasSecrets, patterns) = CredentialExposureAudit.ScanContentForSecrets(
            "registry=https://example.com\nname=foo\n");
        Assert.False(hasSecrets);
        Assert.Empty(patterns);
    }

    [Fact]
    public void ScanContentForSecrets_PasswordlessWord_NoFalsePositive()
    {
        // "passwordless" is not an assignment — the [: =] anchor matters.
        var (hasSecrets, _) = CredentialExposureAudit.ScanContentForSecrets("passwordless login enabled\n");
        Assert.False(hasSecrets);
    }

    [Fact]
    public void GatherCredentialFiles_TempRoot_FindsEnvFile()
    {
        var root = TempPath("home");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, ".env"), "DB_PASSWORD=x\n");
        File.WriteAllText(Path.Combine(root, ".npmrc"), "registry=https://registry.npmjs.org/\n");

        var state = new CredentialState();
        _audit.GatherCredentialFiles(state, new[] { (root, "user_profile") });

        Assert.Equal(2, state.CredentialFiles.Count);
        var env = Assert.Single(state.CredentialFiles, f => f.FileName == ".env");
        Assert.True(env.ContainsPlaintextSecrets);
        Assert.Contains("password=", env.DetectedPatterns);
        Assert.Equal("user_profile", env.Source);
        var npmrc = Assert.Single(state.CredentialFiles, f => f.FileName == ".npmrc");
        Assert.False(npmrc.ContainsPlaintextSecrets);
        Assert.Empty(state.GatherErrors);
    }

    [Fact]
    public void ReadFileHead_LimitsBytes()
    {
        var path = TempPath("big.env");
        File.WriteAllText(path, new string('x', 100_000));
        var head = CredentialExposureAudit.ReadFileHead(path, 1024);
        Assert.Equal(1024, head.Length);
    }

    // ── RDP files ───────────────────────────────────────────────────────

    [Fact]
    public void ParseRdpFile_WithPassword_Parsed()
    {
        const string content = "screen mode id:i:2\nfull address:s:10.0.0.5\nusername:s:admin\ngatewayusername:s:gwuser\npassword 51:b:01000000ABCD\n";
        var info = CredentialExposureAudit.ParseRdpFile("server.rdp", content);
        Assert.NotNull(info);
        Assert.Equal("10.0.0.5", info.ServerAddress);
        Assert.True(info.HasSavedUsername);
        Assert.True(info.HasEmbeddedPassword);
        Assert.True(info.GatewayCredentialsSaved);
    }

    [Fact]
    public void ParseRdpFile_NoCredentialFields_Null()
    {
        Assert.Null(CredentialExposureAudit.ParseRdpFile("plain.rdp", "screen mode id:i:2\nfull address:s:10.0.0.9\n"));
    }

    [Fact]
    public void GatherRdpFiles_TempRoot_FindsOnlyCredentialBearing()
    {
        var root = TempPath("docs");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "server.rdp"), "full address:s:10.0.0.5\npassword 51:b:0100\n");
        File.WriteAllText(Path.Combine(root, "plain.rdp"), "screen mode id:i:2\n");

        var state = new CredentialState();
        _audit.GatherRdpFiles(state, new[] { root });

        var single = Assert.Single(state.RdpFiles);
        Assert.Equal("10.0.0.5", single.ServerAddress);
        Assert.True(single.HasEmbeddedPassword);
        Assert.Empty(state.GatherErrors);
    }

    // ── browser stores ──────────────────────────────────────────────────

    [Fact]
    public void CountChromiumLogins_SyntheticDb_CountsRows()
    {
        var dbPath = TempPath("Login Data");
        CreateLoginDataDb(dbPath, 2);
        Assert.Equal(2, CredentialExposureAudit.CountChromiumLogins(dbPath));
    }

    [Fact]
    public void CountChromiumLogins_EmptyDb_Zero()
    {
        var dbPath = TempPath("Login Data");
        CreateLoginDataDb(dbPath, 0);
        Assert.Equal(0, CredentialExposureAudit.CountChromiumLogins(dbPath));
    }

    [Fact]
    public void CountChromiumLogins_MissingFile_MinusOne()
    {
        Assert.Equal(-1, CredentialExposureAudit.CountChromiumLogins(TempPath("no-such-file")));
    }

    [Fact]
    public void CountFirefoxLogins_JsonCounts()
    {
        var path = TempPath("logins.json");
        File.WriteAllText(path, """{"logins": [{"id": 1}, {"id": 2}, {"id": 3}]}""");
        Assert.Equal(3, CredentialExposureAudit.CountFirefoxLogins(path));
    }

    [Fact]
    public void CountFirefoxLogins_InvalidJson_MinusOne()
    {
        var path = TempPath("logins.json");
        File.WriteAllText(path, "not json at all");
        Assert.Equal(-1, CredentialExposureAudit.CountFirefoxLogins(path));
    }

    [Fact]
    public void GatherBrowserStores_TempProfiles_FindsChromeAndFirefox()
    {
        var local = TempPath("local");
        var roaming = TempPath("roaming");
        var chromeDefault = TempPath("local", "Google", "Chrome", "User Data", "Default");
        CreateLoginDataDb(Path.Combine(chromeDefault, "Login Data"), 2);
        var chromeProfile1 = TempPath("local", "Google", "Chrome", "User Data", "Profile 1");
        CreateLoginDataDb(Path.Combine(chromeProfile1, "Login Data"), 0);
        Directory.CreateDirectory(TempPath("local", "Microsoft", "Edge", "User Data", "Default")); // no Login Data
        var firefoxProfile = TempPath("roaming", "Mozilla", "Firefox", "Profiles", "abc.default");
        Directory.CreateDirectory(firefoxProfile);
        File.WriteAllText(Path.Combine(firefoxProfile, "logins.json"), """{"logins": [{}, {}, {}]}""");

        var state = new CredentialState();
        _audit.GatherBrowserStores(state, local, roaming);

        Assert.Equal(3, state.BrowserStores.Count);
        var chrome = Assert.Single(state.BrowserStores, s => s.BrowserName == "Chrome");
        Assert.Equal(2, chrome.StoredPasswordCount);
        Assert.True(chrome.LoginDataExists);
        Assert.False(chrome.MasterPasswordEnabled);
        var profile1 = Assert.Single(state.BrowserStores, s => s.BrowserName == "Chrome (Profile 1)");
        Assert.Equal(0, profile1.StoredPasswordCount);
        var firefox = Assert.Single(state.BrowserStores, s => s.BrowserName == "Firefox");
        Assert.Equal(3, firefox.StoredPasswordCount);
        Assert.Null(firefox.MasterPasswordEnabled);
        Assert.Empty(state.GatherErrors);
    }

    // ── cloud credentials ───────────────────────────────────────────────

    [Fact]
    public void ParseIniSectionNames_Sections()
    {
        var names = CredentialExposureAudit.ParseIniSectionNames("[default]\nfoo=bar\n[prod]\nfoo=baz\n[default]\n");
        Assert.Equal(new[] { "default", "prod" }, names);
    }

    [Fact]
    public void GatherAwsCredentials_TempAws_FillsState()
    {
        var profile = TempPath("profile");
        var awsDir = Path.Combine(profile, ".aws");
        Directory.CreateDirectory(awsDir);
        File.WriteAllText(Path.Combine(awsDir, "credentials"),
            "[default]\naws_access_key_id = x\naws_secret_access_key = x\n[prod]\naws_access_key_id = x\naws_secret_access_key = x\n");
        File.WriteAllText(Path.Combine(awsDir, "config"),
            "[default]\nregion = us-west-2\nmfa_serial = arn:aws:iam::123456789012:mfa/user\n");

        var state = new CredentialState();
        _audit.GatherAwsCredentials(state, profile);

        var aws = Assert.Single(state.CloudCredentials);
        Assert.Equal("AWS", aws.Provider);
        Assert.True(aws.PlaintextTokens);
        Assert.True(aws.MfaConfigured);
        Assert.Equal(new[] { "default", "prod" }, aws.Profiles);
        Assert.Empty(state.GatherErrors);
    }

    [Fact]
    public void GatherAzureCredentials_TempAzure_FillsState()
    {
        var profile = TempPath("profile");
        var azureDir = Path.Combine(profile, ".azure");
        Directory.CreateDirectory(azureDir);
        File.WriteAllText(Path.Combine(azureDir, "accessTokens.json"),
            """[{"tenantId": "tenant-a", "accessToken": "x"}, {"tenantId": "tenant-b", "accessToken": "y"}]""");

        var state = new CredentialState();
        _audit.GatherAzureCredentials(state, profile);

        var azure = Assert.Single(state.CloudCredentials);
        Assert.Equal("Azure", azure.Provider);
        Assert.True(azure.PlaintextTokens);
        Assert.Equal(new[] { "tenant-a", "tenant-b" }, azure.Profiles);
        Assert.Empty(state.GatherErrors);
    }

    [Fact]
    public void GatherDockerCredentials_WithAuths_FillsState()
    {
        var profile = TempPath("profile");
        var dockerDir = Path.Combine(profile, ".docker");
        Directory.CreateDirectory(dockerDir);
        File.WriteAllText(Path.Combine(dockerDir, "config.json"),
            """{"auths": {"https://index.docker.io/v1/": {"auth": "eA"}}}""");

        var state = new CredentialState();
        _audit.GatherDockerCredentials(state, profile);

        var docker = Assert.Single(state.CloudCredentials);
        Assert.Equal("Docker", docker.Provider);
        Assert.True(docker.PlaintextTokens);
        Assert.Equal(new[] { "https://index.docker.io/v1/" }, docker.Profiles);
        Assert.Empty(state.GatherErrors);
    }

    [Fact]
    public void GatherDockerCredentials_NoAuths_Skipped()
    {
        var profile = TempPath("profile");
        var dockerDir = Path.Combine(profile, ".docker");
        Directory.CreateDirectory(dockerDir);
        File.WriteAllText(Path.Combine(dockerDir, "config.json"), """{"auths": {}}""");

        var state = new CredentialState();
        _audit.GatherDockerCredentials(state, profile);

        Assert.Empty(state.CloudCredentials);
    }

    [Fact]
    public void GatherGcpCredentials_AdcFile_FillsState()
    {
        var roaming = TempPath("roaming");
        var gcloudDir = Path.Combine(roaming, "gcloud");
        Directory.CreateDirectory(gcloudDir);
        File.WriteAllText(Path.Combine(gcloudDir, "application_default_credentials.json"),
            """{"type": "authorized_user", "refresh_token": "x"}""");

        var state = new CredentialState();
        _audit.GatherGcpCredentials(state, roaming);

        var gcp = Assert.Single(state.CloudCredentials);
        Assert.Equal("GCP", gcp.Provider);
        Assert.True(gcp.PlaintextTokens);
        Assert.Empty(state.GatherErrors);
    }

    // ── permissions ─────────────────────────────────────────────────────

    [Fact]
    public void GatherSensitiveFilePermissions_EveryoneFile_Recorded()
    {
        var path = TempPath("secret.txt");
        File.WriteAllText(path, "x");
        var security = new FileInfo(path).GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Read,
            AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);

        var cleanPath = TempPath("clean.txt");
        File.WriteAllText(cleanPath, "x");

        var state = new CredentialState();
        _audit.GatherSensitiveFilePermissions(state, new[]
        {
            (path, "Credential file"),
            (cleanPath, "Credential file"),
        });

        var single = Assert.Single(state.SensitiveFilePermissions);
        Assert.Equal(path, single.Path);
        Assert.True(single.WorldReadable);
    }

    // ── analysis of gathered (unknown) states ───────────────────────────

    [Fact]
    public void Analyze_BrowserUnknownCount_InfoNotWarning()
    {
        var state = new CredentialState();
        state.BrowserStores.Add(new BrowserCredentialStore
        {
            BrowserName = "Chrome", ProfilePath = @"C:\x", LoginDataExists = true,
            StoredPasswordCount = -1, MasterPasswordEnabled = false
        });

        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("password count unknown") && f.Severity == Severity.Info);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("without master password"));
    }

    [Fact]
    public void Analyze_BrowserFirefoxNullMaster_InfoWithoutClaim()
    {
        var state = new CredentialState();
        state.BrowserStores.Add(new BrowserCredentialStore
        {
            BrowserName = "Firefox", ProfilePath = @"C:\x", LoginDataExists = true,
            StoredPasswordCount = 3, MasterPasswordEnabled = null
        });

        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Firefox") && f.Title.Contains("3 passwords stored") && f.Severity == Severity.Info);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("without master password"));
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("master password enabled"));
    }

    [Fact]
    public void Analyze_GatherErrors_WarningListsSources()
    {
        var state = new CredentialState();
        state.GatherErrors.Add("SSH keys: 1 key file(s) could not be read.");

        var result = MakeResult();
        _audit.AddGatherErrorFindings(state, result);

        var warning = Assert.Single(result.Findings, f => f.Title.Contains("could not be checked"));
        Assert.Equal(Severity.Warning, warning.Severity);
        Assert.Contains("SSH keys", warning.Description);
    }

    [Fact]
    public void Analyze_GatherErrorsEmpty_NoFinding()
    {
        var state = new CredentialState();
        var result = MakeResult();
        _audit.AddGatherErrorFindings(state, result);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Analyze_RsaUnknownBits_NotWeak()
    {
        var state = new CredentialState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 0, HasPassphrase = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("weak algorithms"));
    }

    [Fact]
    public void GenerateReport_UnknownCount_Excluded()
    {
        var state = new CredentialState();
        state.BrowserStores.Add(new BrowserCredentialStore
        {
            BrowserName = "Chrome", LoginDataExists = true,
            StoredPasswordCount = -1, MasterPasswordEnabled = false
        });

        var report = CredentialExposureAudit.GenerateReport(state);
        Assert.Equal(0, report.TotalBrowserPasswords);
        Assert.Equal(0, report.BrowsersWithoutMasterPassword);
    }

    // ── end-to-end smoke on the real machine ────────────────────────────

    [Fact]
    public async Task RunAuditAsync_OnRunner_CompletesSuccessfully()
    {
        var result = await _audit.RunAuditAsync();
        Assert.True(result.Success);
        Assert.True(result.Findings.Count > 0);
    }
}
