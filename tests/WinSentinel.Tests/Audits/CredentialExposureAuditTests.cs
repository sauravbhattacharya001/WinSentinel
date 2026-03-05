using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.CredentialExposureAudit;

namespace WinSentinel.Tests.Audits;

public class CredentialExposureAuditTests
{
    private readonly CredentialExposureAudit _audit;

    public CredentialExposureAuditTests()
    {
        _audit = new CredentialExposureAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Credential Exposure Audit",
        Category = "Credentials"
    };

    private static CredentialState MakeCleanState() => new();

    private static CredentialState MakeRiskyState() => new()
    {
        CredentialManagerEntries = new List<CredentialEntry>
        {
            new() { TargetName = "git:https://github.com", Type = CredentialType.Generic, UserName = "dev", Persisted = true, AgeDays = 800 },
            new() { TargetName = "LegacyApp", Type = CredentialType.DomainVisiblePassword, UserName = "admin", Persisted = true, AgeDays = 400 },
        },
        GitCredentials = new GitCredentialConfig
        {
            HelperType = "store",
            StorePlaintextExists = true,
            StorePlaintextPath = @"C:\Users\dev\.git-credentials",
            StorePlaintextEntryCount = 3,
            GlobalConfigHasCredentials = true,
        },
        SshKeys = new List<SshKeyInfo>
        {
            new() { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 1024, HasPassphrase = false, WorldReadable = true, AgeDays = 500 },
            new() { FileName = "id_dsa", Algorithm = "dsa", KeyBits = 1024, HasPassphrase = false, WorldReadable = false, AgeDays = 200 },
        },
        CredentialFiles = new List<CredentialFileInfo>
        {
            new() { Path = @"C:\Users\dev\.env", FileName = ".env", Source = "user_profile", ContainsPlaintextSecrets = true, DetectedPatterns = new() { "password=", "api_key=" } },
        },
        RdpFiles = new List<RdpFileInfo>
        {
            new() { Path = @"C:\Users\dev\server.rdp", ServerAddress = "10.0.0.5", HasEmbeddedPassword = true, HasSavedUsername = true, GatewayCredentialsSaved = true },
        },
        BrowserStores = new List<BrowserCredentialStore>
        {
            new() { BrowserName = "Chrome", ProfilePath = @"C:\Users\dev\AppData\Local\Google\Chrome", LoginDataExists = true, StoredPasswordCount = 250, EncryptedWithDPAPI = true, MasterPasswordEnabled = false },
        },
        CloudCredentials = new List<CloudCredentialInfo>
        {
            new() { Provider = "AWS", CredentialPath = @"C:\Users\dev\.aws\credentials", PlaintextTokens = true, MfaConfigured = false, AgeDays = 400, Profiles = new() { "default", "prod" } },
        },
        SensitiveFilePermissions = new List<SensitiveFilePermission>
        {
            new() { Path = @"C:\Users\dev\.ssh\id_rsa", Description = "SSH private key", WorldReadable = true },
        },
    };

    // ── Module metadata ──

    [Fact]
    public void Name_ReturnsExpectedValue()
    {
        Assert.Equal("Credential Exposure Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsCredentials()
    {
        Assert.Equal("Credentials", _audit.Category);
    }

    // ── Clean state ──

    [Fact]
    public void Analyze_CleanState_AllPass()
    {
        var result = MakeResult();
        _audit.Analyze(MakeCleanState(), result);
        Assert.All(result.Findings, f => Assert.True(f.Severity == Severity.Pass || f.Severity == Severity.Info));
        Assert.True(result.Findings.Count > 0);
    }

    // ── Credential Manager ──

    [Fact]
    public void Analyze_ExcessiveCredentials_Warning()
    {
        var state = MakeCleanState();
        for (int i = 0; i < 55; i++)
            state.CredentialManagerEntries.Add(new CredentialEntry { TargetName = $"cred{i}", Type = CredentialType.Generic, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Excessive") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_DomainVisiblePasswords_Warning()
    {
        var state = MakeCleanState();
        state.CredentialManagerEntries.Add(new CredentialEntry { TargetName = "legacy", Type = CredentialType.DomainVisiblePassword, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("visible password") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_VeryStaleCredentials_Warning()
    {
        var state = MakeCleanState();
        state.CredentialManagerEntries.Add(new CredentialEntry { TargetName = "old-svc", Type = CredentialType.Generic, AgeDays = 800 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Very stale") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_StaleCredentials_Info()
    {
        var state = MakeCleanState();
        state.CredentialManagerEntries.Add(new CredentialEntry { TargetName = "aging-svc", Type = CredentialType.Generic, AgeDays = 500 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Stale credentials") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_GenericCredentials_Info()
    {
        var state = MakeCleanState();
        state.CredentialManagerEntries.Add(new CredentialEntry { TargetName = "app", Type = CredentialType.Generic, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Generic credentials"));
    }

    // ── Git credentials ──

    [Fact]
    public void Analyze_GitPlaintextStore_Critical()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "store", StorePlaintextExists = true, StorePlaintextPath = "/home/.git-credentials", StorePlaintextEntryCount = 2 };

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("plaintext") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_GitManager_Pass()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "manager-core" };

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("credential manager") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_GitCache_Info()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "cache" };

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("cached in memory") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_GitNoHelper_Info()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "" };

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No Git credential helper"));
    }

    [Fact]
    public void Analyze_GitPlaintextFileWithDifferentHelper_Warning()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "manager", StorePlaintextExists = true, StorePlaintextPath = "/home/.git-credentials", StorePlaintextEntryCount = 1 };

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("plaintext credential file exists") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_GitConfigHasCredentials_Critical()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "manager", GlobalConfigHasCredentials = true };

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("embedded in Git config") && f.Severity == Severity.Critical);
    }

    // ── SSH keys ──

    [Fact]
    public void Analyze_NoSshKeys_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No SSH keys") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_SshKeyNoPassphrase_Warning()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_ed25519", Algorithm = "ed25519", KeyBits = 256, HasPassphrase = false, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("without passphrase") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_SshKeyWeakAlgorithm_Warning()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_dsa", Algorithm = "dsa", KeyBits = 1024, HasPassphrase = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("weak algorithms") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_SshKeySmallRsa_Warning()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 1024, HasPassphrase = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("weak algorithms"));
    }

    [Fact]
    public void Analyze_SshKeyWorldReadable_Critical()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 4096, HasPassphrase = true, WorldReadable = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("excessive permissions") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_OldSshKeys_Info()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 4096, HasPassphrase = true, AgeDays = 500 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Old SSH keys") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_StrongSshKey_NoWeakWarning()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_ed25519", Algorithm = "ed25519", KeyBits = 256, HasPassphrase = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("weak algorithms"));
    }

    // ── Credential files ──

    [Fact]
    public void Analyze_PlaintextCredentialFiles_Critical()
    {
        var state = MakeCleanState();
        state.CredentialFiles.Add(new CredentialFileInfo { FileName = ".env", ContainsPlaintextSecrets = true, DetectedPatterns = new() { "password=" } });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Plaintext secrets") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_CredentialFilesNoSecrets_Info()
    {
        var state = MakeCleanState();
        state.CredentialFiles.Add(new CredentialFileInfo { FileName = ".npmrc", ContainsPlaintextSecrets = false });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Credential-related files") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_NoCredentialFiles_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No plaintext credential files"));
    }

    // ── RDP files ──

    [Fact]
    public void Analyze_RdpWithPassword_Warning()
    {
        var state = MakeCleanState();
        state.RdpFiles.Add(new RdpFileInfo { ServerAddress = "10.0.0.5", HasEmbeddedPassword = true });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("RDP files with embedded passwords") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_RdpWithGateway_Warning()
    {
        var state = MakeCleanState();
        state.RdpFiles.Add(new RdpFileInfo { ServerAddress = "10.0.0.5", GatewayCredentialsSaved = true });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("gateway credentials") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_RdpUsernameOnly_Info()
    {
        var state = MakeCleanState();
        state.RdpFiles.Add(new RdpFileInfo { ServerAddress = "10.0.0.5", HasSavedUsername = true, HasEmbeddedPassword = false });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("saved usernames") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_NoRdpFiles_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No RDP files"));
    }

    // ── Browser stores ──

    [Fact]
    public void Analyze_BrowserNoMasterPassword_FindingSeverityScales()
    {
        var state = MakeCleanState();
        state.BrowserStores.Add(new BrowserCredentialStore { BrowserName = "Chrome", LoginDataExists = true, StoredPasswordCount = 100, MasterPasswordEnabled = false });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Chrome") && f.Title.Contains("without master password") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_BrowserFewPasswordsNoMaster_Info()
    {
        var state = MakeCleanState();
        state.BrowserStores.Add(new BrowserCredentialStore { BrowserName = "Firefox", LoginDataExists = true, StoredPasswordCount = 10, MasterPasswordEnabled = false });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Firefox") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_BrowserWithMasterPassword_Pass()
    {
        var state = MakeCleanState();
        state.BrowserStores.Add(new BrowserCredentialStore { BrowserName = "Firefox", LoginDataExists = true, StoredPasswordCount = 50, MasterPasswordEnabled = true });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("master password enabled") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Analyze_LargeBrowserFootprint_Warning()
    {
        var state = MakeCleanState();
        state.BrowserStores.Add(new BrowserCredentialStore { BrowserName = "Chrome", LoginDataExists = true, StoredPasswordCount = 150, MasterPasswordEnabled = false });
        state.BrowserStores.Add(new BrowserCredentialStore { BrowserName = "Edge", LoginDataExists = true, StoredPasswordCount = 80, MasterPasswordEnabled = false });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Large browser password footprint") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_NoBrowserStores_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No browser credential stores"));
    }

    // ── Cloud credentials ──

    [Fact]
    public void Analyze_CloudPlaintextTokens_Warning()
    {
        var state = MakeCleanState();
        state.CloudCredentials.Add(new CloudCredentialInfo { Provider = "AWS", PlaintextTokens = true, Profiles = new() { "default" }, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("AWS") && f.Title.Contains("plaintext") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_CloudNoMfa_Warning()
    {
        var state = MakeCleanState();
        state.CloudCredentials.Add(new CloudCredentialInfo { Provider = "GCP", PlaintextTokens = true, MfaConfigured = false, Profiles = new() { "default" } });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("without MFA") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_CloudEncryptedTokens_Info()
    {
        var state = MakeCleanState();
        state.CloudCredentials.Add(new CloudCredentialInfo { Provider = "Azure", PlaintextTokens = false, Profiles = new() { "default" } });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("Azure") && f.Severity == Severity.Info);
    }

    [Fact]
    public void Analyze_NoCloudCredentials_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("No cloud CLI credentials"));
    }

    // ── Sensitive file permissions ──

    [Fact]
    public void Analyze_WorldReadableSensitiveFiles_Critical()
    {
        var state = MakeCleanState();
        state.SensitiveFilePermissions.Add(new SensitiveFilePermission { Path = @"C:\.ssh\id_rsa", WorldReadable = true });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("readable by all users") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_OtherUsersCanRead_Warning()
    {
        var state = MakeCleanState();
        state.SensitiveFilePermissions.Add(new SensitiveFilePermission { Path = @"C:\.aws\credentials", OtherUsersCanRead = true, WorldReadable = false });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("accessible by other users") && f.Severity == Severity.Warning);
    }

    // ── Report generation ──

    [Fact]
    public void GenerateReport_CleanState_LowRisk()
    {
        var report = CredentialExposureAudit.GenerateReport(MakeCleanState());
        Assert.Equal(0, report.ExposureRiskScore);
        Assert.Equal("A", report.RiskGrade);
    }

    [Fact]
    public void GenerateReport_RiskyState_HighRisk()
    {
        var report = CredentialExposureAudit.GenerateReport(MakeRiskyState());
        Assert.True(report.ExposureRiskScore > 50);
        Assert.True(report.RiskGrade == "D" || report.RiskGrade == "F");
    }

    [Fact]
    public void GenerateReport_CountsCorrect()
    {
        var state = MakeRiskyState();
        var report = CredentialExposureAudit.GenerateReport(state);
        Assert.Equal(2, report.TotalCredentialManagerEntries);
        Assert.Equal(2, report.TotalSshKeys);
        Assert.Equal(2, report.UnprotectedSshKeys);
        Assert.Equal(1, report.PlaintextCredentialFiles);
        Assert.Equal(1, report.RdpFilesWithPasswords);
        Assert.Equal(250, report.TotalBrowserPasswords);
        Assert.Equal(1, report.BrowsersWithoutMasterPassword);
        Assert.Contains("AWS", report.CloudCredentialProviders);
        Assert.Equal(1, report.PlaintextCloudTokens);
        Assert.Equal(1, report.WorldReadableSensitiveFiles);
    }

    [Fact]
    public void GenerateReport_Summary_ContainsKeyInfo()
    {
        var report = CredentialExposureAudit.GenerateReport(MakeRiskyState());
        var summary = report.ToSummary();
        Assert.Contains("Risk Score:", summary);
        Assert.Contains("SSH Keys:", summary);
        Assert.Contains("Browser Passwords:", summary);
        Assert.Contains("Cloud Credentials:", summary);
    }

    [Fact]
    public void GenerateReport_GitPlaintextOnlyFile_MediumRisk()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "manager", StorePlaintextExists = true, StorePlaintextPath = "~/.git-credentials", StorePlaintextEntryCount = 1 };
        var report = CredentialExposureAudit.GenerateReport(state);
        Assert.True(report.ExposureRiskScore >= 10);
        Assert.True(report.GitPlaintextStore);
    }

    [Fact]
    public void GenerateReport_RiskScoreCapped_At100()
    {
        var state = MakeRiskyState();
        // Add more risks
        for (int i = 0; i < 10; i++)
            state.CredentialFiles.Add(new CredentialFileInfo { ContainsPlaintextSecrets = true, DetectedPatterns = new() { "key=" } });
        for (int i = 0; i < 10; i++)
            state.SshKeys.Add(new SshKeyInfo { FileName = $"key{i}", HasPassphrase = false });
        for (int i = 0; i < 5; i++)
            state.SensitiveFilePermissions.Add(new SensitiveFilePermission { WorldReadable = true });
        for (int i = 0; i < 5; i++)
            state.CloudCredentials.Add(new CloudCredentialInfo { Provider = $"Cloud{i}", PlaintextTokens = true });

        var report = CredentialExposureAudit.GenerateReport(state);
        Assert.True(report.ExposureRiskScore <= 100);
    }

    // ── Risky state full analysis ──

    [Fact]
    public void Analyze_RiskyState_MultipleFindings()
    {
        var result = MakeResult();
        _audit.Analyze(MakeRiskyState(), result);

        Assert.True(result.Findings.Count >= 10);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical);
        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void Analyze_RiskyState_HasRemediations()
    {
        var result = MakeResult();
        _audit.Analyze(MakeRiskyState(), result);

        var criticalFindings = result.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        Assert.All(criticalFindings, f => Assert.False(string.IsNullOrEmpty(f.Remediation)));
    }

    // ── Edge cases ──

    [Fact]
    public void Analyze_BrowserStoreNoLoginData_NoFinding()
    {
        var state = MakeCleanState();
        state.BrowserStores.Add(new BrowserCredentialStore { BrowserName = "Brave", LoginDataExists = false, StoredPasswordCount = 0 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Brave"));
    }

    [Fact]
    public void Analyze_SmallEcdsaKey_Weak()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_ecdsa", Algorithm = "ecdsa", KeyBits = 256, HasPassphrase = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Title.Contains("weak algorithms"));
    }

    [Fact]
    public void Analyze_LargeRsaKey_NotWeak()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 4096, HasPassphrase = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("weak algorithms"));
    }

    [Fact]
    public void Analyze_Rsa2048_NotWeak()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 2048, HasPassphrase = true, AgeDays = 10 });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("weak algorithms"));
    }

    [Fact]
    public void Analyze_CloudStaleTokens_MentionsAge()
    {
        var state = MakeCleanState();
        state.CloudCredentials.Add(new CloudCredentialInfo { Provider = "AWS", PlaintextTokens = true, AgeDays = 500, Profiles = new() { "prod" } });

        var result = MakeResult();
        _audit.Analyze(state, result);
        Assert.Contains(result.Findings, f => f.Description.Contains("500 days"));
    }

    [Fact]
    public void GenerateReport_GradeB()
    {
        var state = MakeCleanState();
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 4096, HasPassphrase = false, AgeDays = 10 });
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_ed25519", Algorithm = "ed25519", KeyBits = 256, HasPassphrase = false, AgeDays = 10 });
        var report = CredentialExposureAudit.GenerateReport(state);
        Assert.Equal("B", report.RiskGrade);
    }

    [Fact]
    public void GenerateReport_GradeC()
    {
        var state = MakeCleanState();
        state.GitCredentials = new GitCredentialConfig { HelperType = "store", StorePlaintextExists = true, StorePlaintextPath = "x", StorePlaintextEntryCount = 1 };
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_rsa", Algorithm = "rsa", KeyBits = 4096, HasPassphrase = false, AgeDays = 10 });
        state.SshKeys.Add(new SshKeyInfo { FileName = "id_ed25519", Algorithm = "ed25519", KeyBits = 256, HasPassphrase = false, AgeDays = 10 });
        var report = CredentialExposureAudit.GenerateReport(state);
        Assert.Equal("C", report.RiskGrade);
    }
}
