using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.SmbShareAudit;

namespace WinSentinel.Tests.Audits;

public class SmbShareAuditTests
{
    private readonly SmbShareAudit _audit;

    public SmbShareAuditTests()
    {
        _audit = new SmbShareAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "SMB & Network Share Security Audit",
        Category = "SMB"
    };

    private static SmbState MakeSecureState() => new()
    {
        Smb1Enabled = false,
        Smb2Enabled = true,
        SigningRequired = true,
        EncryptionEnabled = true,
        GuestAccessEnabled = false,
        RestrictAnonymous = true,
        RestrictAnonymousSam = true,
        NullSessionPipesEmpty = true,
        NullSessionSharesEmpty = true,
        MaxConcurrentConnections = 16777216,
        IdleTimeoutMinutes = 15,
        AutoDisconnectEnabled = true,
        AutoDisconnectMinutes = 15,
        Shares = new List<ShareInfo>(),
        CouldQuerySmbConfig = true,
        CouldQueryShares = true
    };

    private static SmbState MakeInsecureState() => new()
    {
        Smb1Enabled = true,
        Smb2Enabled = true,
        SigningRequired = false,
        EncryptionEnabled = false,
        GuestAccessEnabled = true,
        RestrictAnonymous = false,
        RestrictAnonymousSam = false,
        NullSessionPipesEmpty = false,
        NullSessionSharesEmpty = false,
        Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "PublicDocs",
                Path = @"C:\Shared\Public",
                Description = "Public documents",
                Type = 0,
                Permissions = new List<SharePermission>
                {
                    new() { Identity = "Everyone", AccessType = "Allow", Rights = "FullControl" }
                }
            },
            new()
            {
                Name = "Secret$",
                Path = @"C:\Sensitive",
                Description = "Hidden share",
                Type = 0,
                Permissions = new List<SharePermission>
                {
                    new() { Identity = "ANONYMOUS LOGON", AccessType = "Allow", Rights = "Read" }
                }
            }
        },
        CouldQuerySmbConfig = true,
        CouldQueryShares = true
    };

    // ── Module metadata ──

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("SMB & Network Share Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsSMB()
    {
        Assert.Equal("SMB", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ── SMBv1 ──

    [Fact]
    public void Smb1Enabled_ReportsCritical()
    {
        var state = MakeSecureState();
        state.Smb1Enabled = true;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("SMBv1") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Smb1Disabled_ReportsPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("SMBv1") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void Smb1Critical_HasRemediation()
    {
        var state = MakeSecureState();
        state.Smb1Enabled = true;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        var finding = result.Findings.First(f => f.Title.Contains("SMBv1") && f.Severity == Severity.Critical);
        Assert.False(string.IsNullOrWhiteSpace(finding.Remediation));
    }

    // ── SMB signing ──

    [Fact]
    public void SigningNotRequired_ReportsWarning()
    {
        var state = MakeSecureState();
        state.SigningRequired = false;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("signing") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void SigningRequired_ReportsPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("signing") && f.Severity == Severity.Pass);
    }

    // ── Encryption ──

    [Fact]
    public void EncryptionDisabled_ReportsInfo()
    {
        var state = MakeSecureState();
        state.EncryptionEnabled = false;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("encryption") && f.Severity == Severity.Info);
    }

    [Fact]
    public void EncryptionEnabled_ReportsPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("encryption") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void EncryptionCheck_SkippedWhenSmb2Disabled()
    {
        var state = MakeSecureState();
        state.Smb2Enabled = false;
        state.EncryptionEnabled = false;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("encryption") && f.Severity == Severity.Info);
    }

    // ── Guest access ──

    [Fact]
    public void GuestAccessEnabled_ReportsWarning()
    {
        var state = MakeSecureState();
        state.GuestAccessEnabled = true;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Guest") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void GuestAccessDisabled_ReportsPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Guest") && f.Severity == Severity.Pass);
    }

    // ── Null session ──

    [Fact]
    public void AnonymousEnumAllowed_ReportsWarning()
    {
        var state = MakeSecureState();
        state.RestrictAnonymous = false;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Anonymous") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnonymousEnumRestricted_ReportsPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Anonymous") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void NullSessionPipesExposed_ReportsWarning()
    {
        var state = MakeSecureState();
        state.NullSessionPipesEmpty = false;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Named pipes") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void NullSessionSharesExposed_ReportsCritical()
    {
        var state = MakeSecureState();
        state.NullSessionSharesEmpty = false;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("null sessions") && f.Severity == Severity.Critical);
    }

    // ── Share analysis ──

    [Fact]
    public void HiddenShare_ReportsWarning()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "Backup$",
                Path = @"D:\Backup",
                Permissions = new List<SharePermission>()
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Hidden share") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void StandardAdminShare_NotFlaggedAsHidden()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "ADMIN$",
                Path = @"C:\Windows",
                Permissions = new List<SharePermission>()
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Hidden share"));
    }

    [Fact]
    public void EveryoneFullControl_ReportsCritical()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "Shared",
                Path = @"C:\Shared",
                Permissions = new List<SharePermission>
                {
                    new() { Identity = "Everyone", AccessType = "Allow", Rights = "FullControl" }
                }
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Everyone") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void EveryoneReadOnly_ReportsWarning()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "ReadOnly",
                Path = @"C:\ReadOnly",
                Permissions = new List<SharePermission>
                {
                    new() { Identity = "Everyone", AccessType = "Allow", Rights = "Read" }
                }
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Everyone") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnonymousLogonAccess_ReportsWarning()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "AnonShare",
                Path = @"C:\Anon",
                Permissions = new List<SharePermission>
                {
                    new() { Identity = "ANONYMOUS LOGON", AccessType = "Allow", Rights = "Read" }
                }
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("ANONYMOUS LOGON") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void DenyPermission_NotFlagged()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "Restricted",
                Path = @"C:\Restricted",
                Permissions = new List<SharePermission>
                {
                    new() { Identity = "Everyone", AccessType = "Deny", Rights = "FullControl" }
                }
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Everyone") && f.Title.Contains("Restricted"));
    }

    [Fact]
    public void AuthenticatedUsersChange_ReportsCritical()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "Docs",
                Path = @"C:\Docs",
                Permissions = new List<SharePermission>
                {
                    new() { Identity = "Authenticated Users", AccessType = "Allow", Rights = "Change" }
                }
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Authenticated Users") && f.Severity == Severity.Critical);
    }

    // ── No shares ──

    [Fact]
    public void NoUserShares_ReportsPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No user-created shares") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void UserSharesExist_ReportsCount()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new() { Name = "Share1", Path = @"C:\S1", Permissions = new() },
            new() { Name = "Share2", Path = @"C:\S2", Permissions = new() },
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("2 user-created share"));
    }

    // ── Share enumeration failure ──

    [Fact]
    public void ShareQueryFailed_ReportsInfo()
    {
        var state = MakeSecureState();
        state.CouldQueryShares = false;
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Could not enumerate") && f.Severity == Severity.Info);
    }

    // ── Full secure state ──

    [Fact]
    public void FullySecureState_AllPass()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void FullySecureState_HasMultiplePassFindings()
    {
        var state = MakeSecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.True(result.Findings.Count(f => f.Severity == Severity.Pass) >= 5);
    }

    // ── Full insecure state ──

    [Fact]
    public void FullyInsecureState_HasCriticals()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.True(result.CriticalCount >= 2, $"Expected >=2 criticals, got {result.CriticalCount}");
    }

    [Fact]
    public void FullyInsecureState_HasWarnings()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.True(result.WarningCount >= 3, $"Expected >=3 warnings, got {result.WarningCount}");
    }

    [Fact]
    public void FullyInsecureState_FindingsHaveDescriptions()
    {
        var state = MakeInsecureState();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.All(result.Findings, f =>
            Assert.False(string.IsNullOrWhiteSpace(f.Description)));
    }

    // ── Edge cases ──

    [Fact]
    public void EmptyShareList_NoShareFindings()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>();
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Hidden share"));
        Assert.Contains(result.Findings, f => f.Title.Contains("No user-created shares"));
    }

    [Fact]
    public void OnlyAdminShares_NotCountedAsUserShares()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new() { Name = "C$", Path = @"C:\", Permissions = new() },
            new() { Name = "ADMIN$", Path = @"C:\Windows", Permissions = new() },
            new() { Name = "IPC$", Path = "", Permissions = new() }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No user-created shares"));
    }

    [Fact]
    public void MultipleSharesWithDangerousPerms_EachFlagged()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "A", Path = @"C:\A",
                Permissions = new() { new() { Identity = "Everyone", AccessType = "Allow", Rights = "Read" } }
            },
            new()
            {
                Name = "B", Path = @"C:\B",
                Permissions = new() { new() { Identity = "Everyone", AccessType = "Allow", Rights = "FullControl" } }
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        var everyoneFindings = result.Findings.Where(f => f.Title.Contains("Everyone")).ToList();
        Assert.Equal(2, everyoneFindings.Count);
    }

    [Fact]
    public void PrintShare_NotFlaggedAsHidden()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new() { Name = "print$", Path = @"C:\Windows\system32\spool\drivers", Permissions = new() }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Hidden share"));
    }

    // ── StandardAdminShares constant ──

    [Fact]
    public void StandardAdminShares_ContainsExpectedEntries()
    {
        Assert.Contains("ADMIN$", SmbShareAudit.StandardAdminShares);
        Assert.Contains("C$", SmbShareAudit.StandardAdminShares);
        Assert.Contains("IPC$", SmbShareAudit.StandardAdminShares);
        Assert.Contains("print$", SmbShareAudit.StandardAdminShares);
    }

    [Fact]
    public void DangerousPermissions_ContainsExpectedIdentities()
    {
        Assert.Contains("Everyone", SmbShareAudit.DangerousPermissions);
        Assert.Contains("ANONYMOUS LOGON", SmbShareAudit.DangerousPermissions);
        Assert.Contains("Authenticated Users", SmbShareAudit.DangerousPermissions);
    }

    // ── BUILTIN\Users permission ──

    [Fact]
    public void BuiltinUsersFullControl_ReportsCritical()
    {
        var state = MakeSecureState();
        state.Shares = new List<ShareInfo>
        {
            new()
            {
                Name = "AppData",
                Path = @"C:\AppData",
                Permissions = new()
                {
                    new() { Identity = @"BUILTIN\Users", AccessType = "Allow", Rights = "FullControl" }
                }
            }
        };
        var result = MakeResult();
        SmbShareAudit.AnalyzeState(state, result);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("BUILTIN") && f.Severity == Severity.Critical);
    }
}

