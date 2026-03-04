using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

public class EnvironmentAuditTests
{
    private readonly EnvironmentAudit _audit = new();

    private static EnvironmentAudit.EnvironmentState MakeCleanState()
    {
        return new EnvironmentAudit.EnvironmentState
        {
            SystemPathEntries = new List<string>
            {
                @"C:\Windows\System32",
                @"C:\Windows",
                @"C:\Program Files\dotnet",
            },
            UserPathEntries = new List<string>(),
            PathExtEntries = new List<string> { ".COM", ".EXE", ".BAT", ".CMD" },
            TempPath = @"C:\Users\TestUser\AppData\Local\Temp",
            TmpPath = @"C:\Users\TestUser\AppData\Local\Temp",
            SystemVariables = new Dictionary<string, string>
            {
                ["WINDIR"] = @"C:\Windows",
                ["COMSPEC"] = @"C:\Windows\System32\cmd.exe",
            },
            UserVariables = new Dictionary<string, string>(),
            PathDirectoryDetails = new Dictionary<string, EnvironmentAudit.PathDirectoryInfo>
            {
                [@"C:\Windows\System32"] = new()
                {
                    Path = @"C:\Windows\System32",
                    Exists = true,
                    IsWritable = false,
                    Scope = "System"
                },
                [@"C:\Windows"] = new()
                {
                    Path = @"C:\Windows",
                    Exists = true,
                    IsWritable = false,
                    Scope = "System"
                },
                [@"C:\Program Files\dotnet"] = new()
                {
                    Path = @"C:\Program Files\dotnet",
                    Exists = true,
                    IsWritable = false,
                    Scope = "System"
                },
            },
            WindowsDirectory = @"C:\Windows",
        };
    }

    private AuditResult RunAnalysis(EnvironmentAudit.EnvironmentState state)
    {
        var result = new AuditResult
        {
            ModuleName = _audit.Name,
            Category = _audit.Category,
            StartTime = DateTimeOffset.UtcNow
        };
        _audit.AnalyzeState(state, result);
        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    // ──────────────────── Module Metadata ────────────────────

    [Fact]
    public void Module_HasCorrectMetadata()
    {
        Assert.Equal("Environment Variable Security Audit", _audit.Name);
        Assert.Equal("Environment", _audit.Category);
        Assert.False(string.IsNullOrEmpty(_audit.Description));
    }

    // ──────────────────── Clean State ────────────────────

    [Fact]
    public void CleanState_ProducesNoWarningsOrCriticals()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.WarningCount);
        Assert.True(result.PassCount > 0);
    }

    [Fact]
    public void CleanState_HasSecurePathFinding()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("PATH order is secure"));
    }

    [Fact]
    public void CleanState_HasNoSecretsFinding()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("No secrets detected"));
    }

    [Fact]
    public void CleanState_HasNoProxyFinding()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("No proxy"));
    }

    [Fact]
    public void CleanState_HasPerUserTempFinding()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("per-user directory"));
    }

    // ──────────────────── PATH Hijacking ────────────────────

    [Fact]
    public void RelativePathInSystemPath_IsCritical()
    {
        var state = MakeCleanState();
        state.SystemPathEntries.Insert(0, "bin");
        state.PathDirectoryDetails["bin"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = "bin", IsRelative = true, Scope = "System"
        };

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Relative path") &&
            f.Description.Contains("T1574.007"));
    }

    [Fact]
    public void UncPathInSystemPath_IsWarning()
    {
        var state = MakeCleanState();
        state.SystemPathEntries.Add(@"\\fileserver\tools");
        state.PathDirectoryDetails[@"\\fileserver\tools"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"\\fileserver\tools", IsUnc = true, Exists = true, Scope = "System"
        };

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("UNC path"));
    }

    [Fact]
    public void NonExistentPathInSystemPath_IsWarning()
    {
        var state = MakeCleanState();
        state.SystemPathEntries.Add(@"C:\Nonexistent\Dir");
        state.PathDirectoryDetails[@"C:\Nonexistent\Dir"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"C:\Nonexistent\Dir", Exists = false, Scope = "System"
        };

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Non-existent"));
    }

    [Fact]
    public void WritableDirBeforeSystem32_IsCritical()
    {
        var state = MakeCleanState();
        // Insert writable dir before System32
        state.SystemPathEntries.Insert(0, @"C:\Users\Attacker\bin");
        state.PathDirectoryDetails[@"C:\Users\Attacker\bin"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"C:\Users\Attacker\bin",
            Exists = true,
            IsWritable = true,
            Scope = "System"
        };

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Writable directories before System32"));
    }

    [Fact]
    public void WritableDirAfterSystem32_IsWarningOnly()
    {
        var state = MakeCleanState();
        // Append writable dir after System32
        state.SystemPathEntries.Add(@"C:\Users\Dev\tools");
        state.PathDirectoryDetails[@"C:\Users\Dev\tools"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"C:\Users\Dev\tools",
            Exists = true,
            IsWritable = true,
            Scope = "System"
        };

        var result = RunAnalysis(state);
        // Should have a Warning for writable dir but NOT a Critical about "before System32"
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title == "Writable directory in system PATH");
        Assert.DoesNotContain(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("before System32"));
    }

    [Fact]
    public void TrustedPathPrefix_NotFlaggedAsWritable()
    {
        var state = MakeCleanState();
        // Even if writable, trusted prefixes are not flagged
        state.SystemPathEntries.Insert(0, @"C:\Program Files\CustomApp");
        state.PathDirectoryDetails[@"C:\Program Files\CustomApp"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"C:\Program Files\CustomApp",
            Exists = true,
            IsWritable = true, // writable but under trusted prefix
            Scope = "System"
        };

        var result = RunAnalysis(state);
        Assert.DoesNotContain(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Description.Contains("CustomApp"));
    }

    [Fact]
    public void RelativePathInUserPath_IsWarning()
    {
        var state = MakeCleanState();
        state.UserPathEntries.Add("scripts");
        state.PathDirectoryDetails["scripts"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = "scripts", IsRelative = true, Scope = "User"
        };

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Relative path in user PATH"));
    }

    [Fact]
    public void UncPathInUserPath_IsInfo()
    {
        var state = MakeCleanState();
        state.UserPathEntries.Add(@"\\nas\shared\tools");
        state.PathDirectoryDetails[@"\\nas\shared\tools"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"\\nas\shared\tools", IsUnc = true, Scope = "User"
        };

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("UNC path in user PATH"));
    }

    // ──────────────────── PATHEXT ────────────────────

    [Fact]
    public void StandardPathExt_PassesClear()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("only standard extensions"));
    }

    [Fact]
    public void RiskyPathExt_IsWarning()
    {
        var state = MakeCleanState();
        state.PathExtEntries.Add(".VBS");
        state.PathExtEntries.Add(".PS1");

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Risky extensions") &&
            f.Description.Contains(".VBS") &&
            f.Description.Contains(".PS1"));
    }

    [Fact]
    public void UnknownPathExt_IsInfo()
    {
        var state = MakeCleanState();
        state.PathExtEntries.Add(".CUSTOM");

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Unknown extensions") &&
            f.Description.Contains(".CUSTOM"));
    }

    [Fact]
    public void MultipleRiskyExtensions_AllListed()
    {
        var state = MakeCleanState();
        state.PathExtEntries.AddRange(new[] { ".JS", ".WSH", ".HTA" });

        var result = RunAnalysis(state);
        var finding = result.Findings.First(f =>
            f.Severity == Severity.Warning && f.Title.Contains("Risky"));
        Assert.Contains(".JS", finding.Description);
        Assert.Contains(".WSH", finding.Description);
        Assert.Contains(".HTA", finding.Description);
    }

    // ──────────────────── Secret Leakage ────────────────────

    [Fact]
    public void SecretInSystemVar_IsWarning()
    {
        var state = MakeCleanState();
        state.SystemVariables["MY_API_KEY"] = "sk-abc123def456";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("secret") &&
            f.Title.Contains("System") &&
            f.Description.Contains("MY_API_KEY"));
    }

    [Fact]
    public void SecretInUserVar_IsWarning()
    {
        var state = MakeCleanState();
        state.UserVariables["GITHUB_TOKEN"] = "ghp_abcdef123456";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("secret") &&
            f.Title.Contains("User"));
    }

    [Fact]
    public void SecretValue_IsMasked()
    {
        var state = MakeCleanState();
        state.UserVariables["AWS_SECRET_ACCESS_KEY"] = "MySecretValue123";

        var result = RunAnalysis(state);
        var finding = result.Findings.First(f =>
            f.Description.Contains("AWS_SECRET"));
        // Value should be partially masked
        Assert.DoesNotContain("MySecretValue123", finding.Description);
        Assert.Contains("**", finding.Description);
    }

    [Fact]
    public void ExcludedNames_NotFlaggedAsSecrets()
    {
        var state = MakeCleanState();
        state.SystemVariables["PATHEXT"] = ".COM;.EXE";
        state.SystemVariables["PROCESSOR_IDENTIFIER"] = "Intel64 Family";
        state.SystemVariables["COMPUTERNAME"] = "MYPC";

        var result = RunAnalysis(state);
        Assert.DoesNotContain(result.Findings, f =>
            f.Severity == Severity.Warning &&
            (f.Description.Contains("PATHEXT") ||
             f.Description.Contains("PROCESSOR_IDENTIFIER") ||
             f.Description.Contains("COMPUTERNAME")));
    }

    [Fact]
    public void EmptySecretValue_NotFlagged()
    {
        var state = MakeCleanState();
        state.UserVariables["API_KEY"] = "";

        var result = RunAnalysis(state);
        Assert.DoesNotContain(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Description.Contains("API_KEY"));
    }

    [Fact]
    public void MultipleSecrets_AllDetected()
    {
        var state = MakeCleanState();
        state.UserVariables["GH_TOKEN"] = "ghp_abc123";
        state.UserVariables["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE";
        state.SystemVariables["DATABASE_URL"] = "postgresql://user:pass@host/db";

        var result = RunAnalysis(state);
        var secretFindings = result.Findings.Where(f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("secret")).ToList();
        Assert.True(secretFindings.Count >= 3);
    }

    [Fact]
    public void ConnectionString_Detected()
    {
        var state = MakeCleanState();
        state.SystemVariables["MY_CONNECTION_STRING"] = "Server=myserver;Database=mydb;Password=secret";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Description.Contains("CONNECTION_STRING"));
    }

    // ──────────────────── Proxy Settings ────────────────────

    [Fact]
    public void HttpProxy_InsecureProtocol_IsWarning()
    {
        var state = MakeCleanState();
        state.UserVariables["HTTP_PROXY"] = "http://proxy.corp.com:8080";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Insecure proxy"));
    }

    [Fact]
    public void ProxyWithCredentials_IsCritical()
    {
        var state = MakeCleanState();
        state.UserVariables["HTTPS_PROXY"] = "https://user:pass@proxy.corp.com:8080";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Credentials embedded"));
    }

    [Fact]
    public void LocalhostProxy_IsInfo()
    {
        var state = MakeCleanState();
        state.UserVariables["HTTP_PROXY"] = "http://127.0.0.1:8888";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Localhost proxy"));
    }

    [Fact]
    public void NoProxy_IsPass()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("No proxy"));
    }

    [Fact]
    public void ProxyWithLocalhostName_IsInfo()
    {
        var state = MakeCleanState();
        state.UserVariables["HTTPS_PROXY"] = "https://localhost:9090";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Localhost proxy"));
    }

    [Fact]
    public void AllProxy_AlsoChecked()
    {
        var state = MakeCleanState();
        state.SystemVariables["ALL_PROXY"] = "http://proxy.evil.com:3128";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Insecure proxy") &&
            f.Title.Contains("ALL_PROXY"));
    }

    // ──────────────────── TEMP/TMP Directories ────────────────────

    [Fact]
    public void SharedTempDir_IsWarning()
    {
        var state = MakeCleanState();
        state.TempPath = @"C:\Temp";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("shared directory") &&
            f.Description.Contains("symlink"));
    }

    [Fact]
    public void WindowsTempDir_IsWarning()
    {
        var state = MakeCleanState();
        state.TempPath = @"C:\Windows\Temp";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("shared directory"));
    }

    [Fact]
    public void TempTmpMismatch_IsInfo()
    {
        var state = MakeCleanState();
        state.TempPath = @"C:\Users\TestUser\AppData\Local\Temp";
        state.TmpPath = @"C:\Tmp";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("TEMP and TMP point to different"));
    }

    [Fact]
    public void EmptyTemp_IsInfo()
    {
        var state = MakeCleanState();
        state.TempPath = "";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("TEMP is not set"));
    }

    [Fact]
    public void PerUserTemp_IsPass()
    {
        var result = RunAnalysis(MakeCleanState());
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("per-user directory"));
    }

    // ──────────────────── Combined Scenarios ────────────────────

    [Fact]
    public void WorstCase_MultipleCriticals()
    {
        var state = MakeCleanState();
        // Relative path
        state.SystemPathEntries.Insert(0, ".");
        state.PathDirectoryDetails["."] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = ".", IsRelative = true, Scope = "System"
        };
        // Secret
        state.SystemVariables["DB_PASSWORD"] = "hunter2";
        // Proxy with creds
        state.UserVariables["HTTPS_PROXY"] = "https://admin:pass@proxy:8080";

        var result = RunAnalysis(state);
        Assert.True(result.CriticalCount >= 2);
        Assert.True(result.WarningCount >= 1);
    }

    [Fact]
    public void MultipleWritableDirsBeforeSystem32_CountedCorrectly()
    {
        var state = MakeCleanState();
        // Two writable dirs before System32
        state.SystemPathEntries.Insert(0, @"C:\Users\Attacker\bin1");
        state.SystemPathEntries.Insert(1, @"C:\Users\Attacker\bin2");
        state.PathDirectoryDetails[@"C:\Users\Attacker\bin1"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"C:\Users\Attacker\bin1", Exists = true, IsWritable = true, Scope = "System"
        };
        state.PathDirectoryDetails[@"C:\Users\Attacker\bin2"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = @"C:\Users\Attacker\bin2", Exists = true, IsWritable = true, Scope = "System"
        };

        var result = RunAnalysis(state);
        var critical = result.Findings.First(f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Writable directories before System32"));
        Assert.Contains("2", critical.Description);
        Assert.Contains("bin1", critical.Description);
        Assert.Contains("bin2", critical.Description);
    }

    // ──────────────────── Edge Cases ────────────────────

    [Fact]
    public void EmptyState_DoesNotThrow()
    {
        var state = new EnvironmentAudit.EnvironmentState();
        var result = RunAnalysis(state);
        Assert.True(result.Findings.Count > 0);
    }

    [Fact]
    public void PathEntryNotInDetails_SkippedGracefully()
    {
        var state = MakeCleanState();
        state.SystemPathEntries.Add(@"C:\Unknown\Dir");
        // Intentionally NOT adding to PathDirectoryDetails

        // Should not throw
        var result = RunAnalysis(state);
        Assert.NotNull(result);
    }

    [Fact]
    public void ShortSecretValue_FullyMasked()
    {
        var state = MakeCleanState();
        state.UserVariables["MY_SECRET"] = "ab";

        var result = RunAnalysis(state);
        var finding = result.Findings.FirstOrDefault(f =>
            f.Description.Contains("MY_SECRET"));
        Assert.NotNull(finding);
        Assert.Contains("****", finding.Description);
    }

    [Fact]
    public void ProxyVar_CaseInsensitive()
    {
        var state = MakeCleanState();
        state.UserVariables["https_proxy"] = "http://proxy:3128";

        var result = RunAnalysis(state);
        // Should detect the lowercase variant
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Insecure proxy"));
    }

    [Fact]
    public void FindingRemediation_AlwaysPresent()
    {
        var state = MakeCleanState();
        state.SystemPathEntries.Insert(0, "bin");
        state.PathDirectoryDetails["bin"] = new EnvironmentAudit.PathDirectoryInfo
        {
            Path = "bin", IsRelative = true, Scope = "System"
        };

        var result = RunAnalysis(state);
        var critical = result.Findings.First(f => f.Severity == Severity.Critical);
        Assert.False(string.IsNullOrEmpty(critical.Remediation));
    }

    [Fact]
    public void SecretPattern_PASSWORD_MatchesSubstring()
    {
        var state = MakeCleanState();
        state.UserVariables["SMTP_PASSWORD"] = "mysmtppass123";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Description.Contains("SMTP_PASSWORD"));
    }

    [Fact]
    public void SecretPattern_TOKEN_MatchesGitlab()
    {
        var state = MakeCleanState();
        state.UserVariables["GITLAB_TOKEN"] = "glpat-abc123xyz";

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Description.Contains("GITLAB_TOKEN"));
    }

    [Fact]
    public void RiskyPathExt_SCR_Detected()
    {
        var state = MakeCleanState();
        state.PathExtEntries.Add(".SCR");

        var result = RunAnalysis(state);
        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Description.Contains(".SCR"));
    }
}
