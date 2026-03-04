using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.GroupPolicyAudit;

namespace WinSentinel.Tests.Audits;

public class GroupPolicyAuditTests
{
    private readonly GroupPolicyAudit _audit = new();

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Group Policy Security Audit",
        Category = "GroupPolicy"
    };

    private static GpoState MakeSecureState() => new()
    {
        LockoutThreshold = 5, LockoutDuration = 30, LockoutObservationWindow = 30,
        LmCompatibilityLevel = 5, RestrictNtlmOutgoing = 2,
        RestrictAnonymousSam = 1, RestrictAnonymous = 1, EveryoneIncludesAnonymous = 0,
        SmbServerRequireSigning = 1, SmbClientRequireSigning = 1,
        CredentialGuardConfig = 1, VbsEnabled = true, VbsRunning = true,
        AuditProcessCommandLine = 1, AuditProcessCreation = 3,
        AuditLogonEvents = 3, AuditPrivilegeUse = 1,
        RestrictedAdminMode = 0, AllowEncryptionOracle = 2,
        NlaRequired = 1, RdpEncryptionLevel = 3,
        AuEnabled = 4, WuManaged = true,
        AppLockerConfigured = true, AppLockerExeRuleCount = 12, SrpConfigured = false,
    };

    private static GpoState MakeInsecureState() => new()
    {
        LockoutThreshold = 0,
        LmCompatibilityLevel = 1,
        RestrictAnonymousSam = 0, EveryoneIncludesAnonymous = 1,
        SmbServerRequireSigning = 0, SmbClientRequireSigning = 0,
        VbsEnabled = false, VbsRunning = false,
        AuditProcessCommandLine = 0, AuditProcessCreation = 0,
        AllowEncryptionOracle = 0,
        NlaRequired = 0, RdpEncryptionLevel = 1,
        WuManaged = false,
        AppLockerConfigured = false, SrpConfigured = false,
    };

    [Fact]
    public void Name_ReturnsExpected() => Assert.Equal("Group Policy Security Audit", _audit.Name);

    [Fact]
    public void Category_ReturnsGroupPolicy() => Assert.Equal("GroupPolicy", _audit.Category);

    [Fact]
    public void Secure_HasNoWarningsOrCriticals()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeSecureState(), result);
        Assert.True(result.CriticalCount == 0,
            $"Expected 0 criticals: {string.Join(", ", result.Findings.Where(f => f.Severity == Severity.Critical).Select(f => f.Title))}");
        Assert.True(result.WarningCount == 0,
            $"Expected 0 warnings: {string.Join(", ", result.Findings.Where(f => f.Severity == Severity.Warning).Select(f => f.Title))}");
    }

    [Fact]
    public void Secure_HasMultipleFindings()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeSecureState(), result);
        Assert.True(result.Findings.Count >= 10);
    }

    [Fact]
    public void Insecure_HasCriticals()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeInsecureState(), result);
        Assert.True(result.CriticalCount >= 3);
    }

    [Fact]
    public void Insecure_HasWarnings()
    {
        var result = MakeResult();
        _audit.AnalyzeState(MakeInsecureState(), result);
        Assert.True(result.WarningCount >= 5);
    }

    // ── Account Lockout ──────────────────────────────────────────

    [Fact]
    public void Lockout_Zero_IsCritical()
    {
        var s = MakeSecureState(); s.LockoutThreshold = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Account Lockout Not Configured" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Lockout_Null_IsCritical()
    {
        var s = MakeSecureState(); s.LockoutThreshold = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Account Lockout Not Configured" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Lockout_HighThreshold_IsWarning()
    {
        var s = MakeSecureState(); s.LockoutThreshold = 50;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Weak Account Lockout Threshold" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Lockout_GoodThreshold_IsPass()
    {
        var s = MakeSecureState(); s.LockoutThreshold = 5;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Account Lockout Configured" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Lockout_ShortDuration_IsWarning()
    {
        var s = MakeSecureState(); s.LockoutDuration = 5;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Short Lockout Duration" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Lockout_AdequateDuration_NoWarning()
    {
        var s = MakeSecureState(); s.LockoutDuration = 30;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.DoesNotContain(r.Findings, f => f.Title == "Short Lockout Duration");
    }

    [Fact]
    public void Lockout_ExactlyTen_IsPass()
    {
        var s = MakeSecureState(); s.LockoutThreshold = 10;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Account Lockout Configured" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Lockout_Eleven_IsWarning()
    {
        var s = MakeSecureState(); s.LockoutThreshold = 11;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Weak Account Lockout Threshold" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Lockout_DurationZero_NoWarning()
    {
        var s = MakeSecureState(); s.LockoutDuration = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.DoesNotContain(r.Findings, f => f.Title == "Short Lockout Duration");
    }

    // ── NTLM ─────────────────────────────────────────────────────

    [Fact]
    public void Ntlm_NotConfigured_IsWarning()
    {
        var s = MakeSecureState(); s.LmCompatibilityLevel = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "NTLM Authentication Level Not Configured" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Ntlm_Level1_IsCritical()
    {
        var s = MakeSecureState(); s.LmCompatibilityLevel = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Weak NTLM Authentication Allowed" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Ntlm_Level0_IsCritical()
    {
        var s = MakeSecureState(); s.LmCompatibilityLevel = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Weak NTLM Authentication Allowed" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Ntlm_Level3_IsInfo()
    {
        var s = MakeSecureState(); s.LmCompatibilityLevel = 3;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "NTLM Partially Restricted" && f.Severity == Severity.Info);
    }

    [Fact]
    public void Ntlm_Level4_IsInfo()
    {
        var s = MakeSecureState(); s.LmCompatibilityLevel = 4;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "NTLM Partially Restricted" && f.Severity == Severity.Info);
    }

    [Fact]
    public void Ntlm_Level5_IsPass()
    {
        var s = MakeSecureState(); s.LmCompatibilityLevel = 5;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "NTLMv2 Only Authentication" && f.Severity == Severity.Pass);
    }

    // ── Anonymous Access ─────────────────────────────────────────

    [Fact]
    public void Anon_SamRestricted_IsPass()
    {
        var s = MakeSecureState(); s.RestrictAnonymousSam = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Anonymous SAM Enumeration Restricted" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Anon_SamNotRestricted_IsWarning()
    {
        var s = MakeSecureState(); s.RestrictAnonymousSam = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Anonymous SAM Enumeration Allowed" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Anon_EveryoneIncludesAnon_IsCritical()
    {
        var s = MakeSecureState(); s.EveryoneIncludesAnonymous = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Everyone Includes Anonymous" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Anon_EveryoneExcludesAnon_IsPass()
    {
        var s = MakeSecureState(); s.EveryoneIncludesAnonymous = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Everyone Excludes Anonymous" && f.Severity == Severity.Pass);
    }

    // ── SMB Signing ──────────────────────────────────────────────

    [Fact]
    public void SmbServer_Required_IsPass()
    {
        var s = MakeSecureState(); s.SmbServerRequireSigning = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "SMB Server Signing Required" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void SmbServer_NotRequired_IsWarning()
    {
        var s = MakeSecureState(); s.SmbServerRequireSigning = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "SMB Server Signing Not Required" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void SmbClient_Required_IsPass()
    {
        var s = MakeSecureState(); s.SmbClientRequireSigning = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "SMB Client Signing Required" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void SmbClient_NotRequired_IsWarning()
    {
        var s = MakeSecureState(); s.SmbClientRequireSigning = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "SMB Client Signing Not Required" && f.Severity == Severity.Warning);
    }

    // ── Credential Guard / VBS ───────────────────────────────────

    [Fact]
    public void Vbs_Running_IsPass()
    {
        var s = MakeSecureState(); s.VbsRunning = true;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Virtualization-Based Security Running" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Vbs_EnabledNotRunning_IsInfo()
    {
        var s = MakeSecureState(); s.VbsRunning = false; s.VbsEnabled = true;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "VBS Enabled But Not Running" && f.Severity == Severity.Info);
    }

    [Fact]
    public void Vbs_NotEnabled_IsWarning()
    {
        var s = MakeSecureState(); s.VbsRunning = false; s.VbsEnabled = false;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Virtualization-Based Security Not Enabled" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void CredGuard_Configured_IsPass()
    {
        var s = MakeSecureState(); s.CredentialGuardConfig = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Credential Guard Configured" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void CredGuard_ConfiguredNoLock_IsPass()
    {
        var s = MakeSecureState(); s.CredentialGuardConfig = 2;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Credential Guard Configured" && f.Severity == Severity.Pass
            && f.Description!.Contains("without UEFI lock"));
    }

    [Fact]
    public void CredGuard_NotConfiguredButVbsAvailable_IsInfo()
    {
        var s = MakeSecureState(); s.CredentialGuardConfig = null; s.VbsEnabled = true; s.VbsRunning = true;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Credential Guard Not Configured" && f.Severity == Severity.Info);
    }

    // ── Audit Policy ─────────────────────────────────────────────

    [Fact]
    public void AuditProcess_Enabled_IsPass()
    {
        var s = MakeSecureState(); s.AuditProcessCreation = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Process Creation Auditing Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AuditProcess_Disabled_IsWarning()
    {
        var s = MakeSecureState(); s.AuditProcessCreation = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Process Creation Auditing Not Enabled" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AuditCmdLine_Enabled_IsPass()
    {
        var s = MakeSecureState(); s.AuditProcessCommandLine = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Command-Line Process Auditing Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AuditCmdLine_Disabled_IsWarning()
    {
        var s = MakeSecureState(); s.AuditProcessCommandLine = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Command-Line Process Auditing Not Enabled" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AuditLogon_Enabled_IsPass()
    {
        var s = MakeSecureState(); s.AuditLogonEvents = 3;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Logon Auditing Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AuditLogon_NotEnabled_IsWarning()
    {
        var s = MakeSecureState(); s.AuditLogonEvents = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Logon Auditing Not Enabled" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AuditPrivilege_Enabled_IsPass()
    {
        var s = MakeSecureState(); s.AuditPrivilegeUse = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Privilege Use Auditing Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AuditPrivilege_NotEnabled_IsInfo()
    {
        var s = MakeSecureState(); s.AuditPrivilegeUse = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Privilege Use Auditing Not Enabled" && f.Severity == Severity.Info);
    }

    // ── CredSSP ──────────────────────────────────────────────────

    [Fact]
    public void CredSSP_Vulnerable_IsCritical()
    {
        var s = MakeSecureState(); s.AllowEncryptionOracle = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "CredSSP Vulnerable Configuration" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void CredSSP_Mitigated_IsWarning()
    {
        var s = MakeSecureState(); s.AllowEncryptionOracle = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "CredSSP Mitigated But Not Enforced" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void CredSSP_Enforced_IsPass()
    {
        var s = MakeSecureState(); s.AllowEncryptionOracle = 2;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "CredSSP Fully Patched" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void CredSSP_Null_NoFinding()
    {
        var s = MakeSecureState(); s.AllowEncryptionOracle = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.DoesNotContain(r.Findings, f => f.Title.Contains("CredSSP"));
    }

    [Fact]
    public void RestrictedAdmin_Available_IsPass()
    {
        var s = MakeSecureState(); s.RestrictedAdminMode = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Restricted Admin Mode Available" && f.Severity == Severity.Pass);
    }

    // ── Remote Desktop ───────────────────────────────────────────

    [Fact]
    public void Nla_Required_IsPass()
    {
        var s = MakeSecureState(); s.NlaRequired = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "NLA Required for Remote Desktop" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Nla_NotRequired_IsWarning()
    {
        var s = MakeSecureState(); s.NlaRequired = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "NLA Not Required for Remote Desktop" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Nla_Null_NoFinding()
    {
        var s = MakeSecureState(); s.NlaRequired = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.DoesNotContain(r.Findings, f => f.Title.Contains("NLA"));
    }

    [Fact]
    public void Rdp_LowEncryption_IsWarning()
    {
        var s = MakeSecureState(); s.RdpEncryptionLevel = 1;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Low RDP Encryption Level" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void Rdp_HighEncryption_IsPass()
    {
        var s = MakeSecureState(); s.RdpEncryptionLevel = 3;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "RDP Encryption Level: High" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Rdp_FipsEncryption_IsPass()
    {
        var s = MakeSecureState(); s.RdpEncryptionLevel = 4;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "RDP Encryption Level: FIPS" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Rdp_EncryptionNull_NoFinding()
    {
        var s = MakeSecureState(); s.RdpEncryptionLevel = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.DoesNotContain(r.Findings, f => f.Title.Contains("RDP Encryption"));
    }

    // ── Windows Update ───────────────────────────────────────────

    [Fact]
    public void WU_Managed_IsPass()
    {
        var s = MakeSecureState(); s.WuManaged = true;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Windows Update Managed by Policy" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void WU_AutoInstall_IsPass()
    {
        var s = MakeSecureState(); s.WuManaged = false; s.AuEnabled = 4;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Automatic Windows Updates Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void WU_DownloadOnly_IsInfo()
    {
        var s = MakeSecureState(); s.WuManaged = false; s.AuEnabled = 2;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Windows Update: Download Only" && f.Severity == Severity.Info);
    }

    [Fact]
    public void WU_NotConfigured_IsWarning()
    {
        var s = MakeSecureState(); s.WuManaged = false; s.AuEnabled = null;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Windows Update Policy Not Configured" && f.Severity == Severity.Warning);
    }

    // ── Application Control ──────────────────────────────────────

    [Fact]
    public void AppLocker_Configured_IsPass()
    {
        var s = MakeSecureState(); s.AppLockerConfigured = true; s.AppLockerExeRuleCount = 5;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "AppLocker Policies Configured" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Srp_Whitelist_IsPass()
    {
        var s = MakeSecureState(); s.AppLockerConfigured = false; s.SrpConfigured = true; s.SrpDefaultLevel = 0;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Software Restriction Policies: Whitelist Mode" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Srp_Unrestricted_IsInfo()
    {
        var s = MakeSecureState(); s.AppLockerConfigured = false; s.SrpConfigured = true; s.SrpDefaultLevel = 0x40000;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Software Restriction Policies: Unrestricted" && f.Severity == Severity.Info);
    }

    [Fact]
    public void NoAppControl_IsInfo()
    {
        var s = MakeSecureState(); s.AppLockerConfigured = false; s.SrpConfigured = false;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "No Application Control Policies" && f.Severity == Severity.Info);
    }

    // ── ParseAuditSetting ────────────────────────────────────────

    [Theory]
    [InlineData("Success and Failure", 3)]
    [InlineData("Success", 1)]
    [InlineData("Failure", 2)]
    [InlineData("No Auditing", 0)]
    [InlineData("none", 0)]
    [InlineData("", null)]
    [InlineData("  ", null)]
    public void ParseAuditSetting_ReturnsExpected(string input, int? expected)
    {
        Assert.Equal(expected, GroupPolicyAudit.ParseAuditSetting(input));
    }

    [Fact]
    public void ParseAuditSetting_Null_ReturnsNull()
    {
        Assert.Null(GroupPolicyAudit.ParseAuditSetting(null!));
    }

    // ── Edge cases ───────────────────────────────────────────────

    [Fact]
    public void EmptyState_ProducesFindings()
    {
        var s = new GpoState();
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.True(r.Findings.Count >= 5);
    }

    [Fact]
    public void AllFindings_HaveCategory()
    {
        var r = MakeResult(); _audit.AnalyzeState(MakeInsecureState(), r);
        Assert.All(r.Findings, f => Assert.Equal("GroupPolicy", f.Category));
    }

    [Fact]
    public void CriticalFindings_HaveRemediation()
    {
        var r = MakeResult(); _audit.AnalyzeState(MakeInsecureState(), r);
        var criticals = r.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        Assert.All(criticals, f => Assert.False(string.IsNullOrWhiteSpace(f.Remediation),
            $"Critical finding '{f.Title}' should have remediation"));
    }

    [Fact]
    public void Rdp_Level2_IsWarning()
    {
        var s = MakeSecureState(); s.RdpEncryptionLevel = 2;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Low RDP Encryption Level" && f.Severity == Severity.Warning);
    }

    [Fact]
    public void WU_AutoDownload_IsPass()
    {
        var s = MakeSecureState(); s.WuManaged = false; s.AuEnabled = 3;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Automatic Windows Updates Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AuditProcess_SuccessAndFailure_IsPass()
    {
        var s = MakeSecureState(); s.AuditProcessCreation = 3;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.Contains(r.Findings, f => f.Title == "Process Creation Auditing Enabled" && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Lockout_Duration15_NoWarning()
    {
        var s = MakeSecureState(); s.LockoutDuration = 15;
        var r = MakeResult(); _audit.AnalyzeState(s, r);
        Assert.DoesNotContain(r.Findings, f => f.Title == "Short Lockout Duration");
    }
}
