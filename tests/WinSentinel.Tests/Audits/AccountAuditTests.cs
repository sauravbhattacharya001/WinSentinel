using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Integration tests for the AccountAudit module.
/// Validates all five audit checks: guest account status, admin accounts,
/// password policy (length + lockout), locked/expired accounts, and auto-logon.
/// </summary>
public class AccountAuditTests : IAsyncLifetime
{
    private readonly AccountAudit _audit = new();
    private AuditResult _result = null!;

    public async Task InitializeAsync()
    {
        _result = await _audit.RunAuditAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    // ──────────────────────────────────────────────
    // Properties
    // ──────────────────────────────────────────────

    [Fact]
    public void Properties_NameIsCorrect()
    {
        Assert.Equal("Account Audit", _audit.Name);
    }

    [Fact]
    public void Properties_CategoryIsAccounts()
    {
        Assert.Equal("Accounts", _audit.Category);
    }

    [Fact]
    public void Properties_DescriptionIsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    [Fact]
    public void Properties_DescriptionContainsKeyTerms()
    {
        Assert.Contains("account", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("password", _audit.Description, StringComparison.OrdinalIgnoreCase);
    }

    // ──────────────────────────────────────────────
    // Audit execution basics
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_Succeeds()
    {
        Assert.True(_result.Success, $"Audit failed: {_result.Error}");
    }

    [Fact]
    public void RunAuditAsync_ModuleNameIsSet()
    {
        Assert.Equal("Account Audit", _result.ModuleName);
    }

    [Fact]
    public void RunAuditAsync_CategoryIsSet()
    {
        Assert.Equal("Accounts", _result.Category);
    }

    [Fact]
    public void RunAuditAsync_ProducesFindings()
    {
        Assert.NotEmpty(_result.Findings);
    }

    [Fact]
    public void RunAuditAsync_ProducesMultipleFindings()
    {
        // Module has 5 check areas — even minimal runs produce multiple findings
        Assert.True(_result.Findings.Count >= 3,
            $"Expected at least 3 findings, got {_result.Findings.Count}");
    }

    // ──────────────────────────────────────────────
    // Finding quality
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_AllFindingsHaveTitle()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title),
                "A finding has an empty title");
        }
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveDescription()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Description),
                $"Finding '{finding.Title}' has no description");
        }
    }

    [Fact]
    public void RunAuditAsync_AllFindingsHaveCategory()
    {
        foreach (var finding in _result.Findings)
        {
            Assert.Equal("Accounts", finding.Category);
        }
    }

    [Fact]
    public void RunAuditAsync_FindingsHaveValidSeverity()
    {
        var validSeverities = new[] { Severity.Critical, Severity.Warning, Severity.Info, Severity.Pass };
        foreach (var finding in _result.Findings)
        {
            Assert.Contains(finding.Severity, validSeverities);
        }
    }

    // ──────────────────────────────────────────────
    // Check: Guest account
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksGuestAccount()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Guest", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_GuestFindingHasCorrectSeverity()
    {
        var guestFinding = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("Guest", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(guestFinding);
        // Should be either Critical (if enabled) or Pass (if disabled)
        Assert.True(
            guestFinding.Severity == Severity.Critical || guestFinding.Severity == Severity.Pass,
            $"Guest finding has unexpected severity: {guestFinding.Severity}");
    }

    [Fact]
    public void RunAuditAsync_GuestCriticalHasRemediation()
    {
        var guestCritical = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("Guest", StringComparison.OrdinalIgnoreCase) &&
                                 f.Severity == Severity.Critical);
        if (guestCritical != null)
        {
            Assert.False(string.IsNullOrWhiteSpace(guestCritical.Remediation),
                "Critical guest account finding must have remediation");
            Assert.False(string.IsNullOrWhiteSpace(guestCritical.FixCommand),
                "Critical guest account finding must have a fix command");
        }
    }

    // ──────────────────────────────────────────────
    // Check: Admin accounts
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksAdminAccounts()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Admin", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_AdminFindingReportsCount()
    {
        // The admin finding title or description includes a count
        var adminFindings = _result.Findings
            .Where(f => f.Title.Contains("Admin", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(adminFindings);
        // At least one admin finding should report member count or status
        Assert.True(
            adminFindings.Any(f => f.Title.Any(char.IsDigit) ||
                                    f.Description.Contains("Administrator", StringComparison.OrdinalIgnoreCase)),
            "Admin findings should include membership details");
    }

    [Fact]
    public void RunAuditAsync_BuiltInAdminChecked()
    {
        // Should check the built-in Administrator account specifically
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Administrator", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Built-in", StringComparison.OrdinalIgnoreCase));
    }

    // ──────────────────────────────────────────────
    // Check: Password policy
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ChecksPasswordPolicy()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_ChecksLockoutPolicy()
    {
        Assert.Contains(_result.Findings,
            f => f.Title.Contains("Lockout", StringComparison.OrdinalIgnoreCase) ||
                 f.Title.Contains("Lock", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunAuditAsync_PasswordLengthFindingReportsValue()
    {
        var pwFinding = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase) &&
                                  f.Title.Contains("Length", StringComparison.OrdinalIgnoreCase));
        if (pwFinding != null)
        {
            // Title should include the actual numeric length value
            Assert.True(pwFinding.Title.Any(char.IsDigit),
                "Password length finding should include the numeric value in title");
        }
    }

    [Fact]
    public void RunAuditAsync_WeakPasswordPolicyHasFixCommand()
    {
        var weakPw = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("Password", StringComparison.OrdinalIgnoreCase) &&
                                  f.Severity == Severity.Warning);
        if (weakPw != null)
        {
            Assert.False(string.IsNullOrWhiteSpace(weakPw.FixCommand),
                "Weak password policy warning must include a fix command");
        }
    }

    [Fact]
    public void RunAuditAsync_NoLockoutPolicyHasFixCommand()
    {
        var noLockout = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("Lockout", StringComparison.OrdinalIgnoreCase) &&
                                  f.Severity == Severity.Warning);
        if (noLockout != null)
        {
            Assert.False(string.IsNullOrWhiteSpace(noLockout.FixCommand),
                "No lockout policy warning must include a fix command");
            Assert.Contains("lockout", noLockout.FixCommand!, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ──────────────────────────────────────────────
    // Check: Auto-logon
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_AutoLogonChecked()
    {
        // Auto-logon check reads registry — finding may or may not appear depending on config
        // If present, it should have appropriate severity
        var autoLogon = _result.Findings
            .FirstOrDefault(f => f.Title.Contains("Auto-Logon", StringComparison.OrdinalIgnoreCase) ||
                                  f.Title.Contains("AutoLogon", StringComparison.OrdinalIgnoreCase) ||
                                  f.Title.Contains("Auto Logon", StringComparison.OrdinalIgnoreCase));
        if (autoLogon != null)
        {
            // If auto-logon is detected, it should be Warning or Critical
            Assert.True(
                autoLogon.Severity == Severity.Warning ||
                autoLogon.Severity == Severity.Critical ||
                autoLogon.Severity == Severity.Pass,
                $"Auto-logon finding has unexpected severity: {autoLogon.Severity}");
        }
    }

    [Fact]
    public void RunAuditAsync_AutoLogonCriticalHasRemediation()
    {
        var autoLogonCritical = _result.Findings
            .FirstOrDefault(f => (f.Title.Contains("Auto-Logon", StringComparison.OrdinalIgnoreCase) ||
                                   f.Title.Contains("AutoLogon", StringComparison.OrdinalIgnoreCase)) &&
                                  f.Severity == Severity.Critical);
        if (autoLogonCritical != null)
        {
            Assert.False(string.IsNullOrWhiteSpace(autoLogonCritical.Remediation),
                "Critical auto-logon finding must have remediation");
            Assert.False(string.IsNullOrWhiteSpace(autoLogonCritical.FixCommand),
                "Critical auto-logon finding must have fix command");
        }
    }

    // ──────────────────────────────────────────────
    // Remediation quality
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_CriticalFindingsHaveRemediation()
    {
        foreach (var finding in _result.Findings.Where(f => f.Severity == Severity.Critical))
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Critical finding '{finding.Title}' must have remediation guidance");
            Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand),
                $"Critical finding '{finding.Title}' must have a fix command");
        }
    }

    [Fact]
    public void RunAuditAsync_WarningFindingsHaveRemediation()
    {
        foreach (var finding in _result.Findings.Where(f => f.Severity == Severity.Warning))
        {
            Assert.True(
                !string.IsNullOrWhiteSpace(finding.Remediation) ||
                !string.IsNullOrWhiteSpace(finding.FixCommand),
                $"Warning finding '{finding.Title}' should have remediation or fix command");
        }
    }

    // ──────────────────────────────────────────────
    // Score
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_ScoreIsValid()
    {
        Assert.InRange(_result.Score, 0, 100);
    }

    [Fact]
    public void RunAuditAsync_ScoreReflectsSeverity()
    {
        // If all pass → score should be high; if critical findings exist → score should be lower
        var hasCritical = _result.Findings.Any(f => f.Severity == Severity.Critical);
        if (hasCritical)
        {
            Assert.True(_result.Score < 100,
                "Score should be less than 100 when critical findings exist");
        }
    }

    // ──────────────────────────────────────────────
    // Timestamps
    // ──────────────────────────────────────────────

    [Fact]
    public void RunAuditAsync_HasValidTimestamps()
    {
        Assert.True(_result.StartTime > DateTimeOffset.MinValue);
        Assert.True(_result.EndTime >= _result.StartTime);
        Assert.True(_result.Duration >= TimeSpan.Zero);
    }

    // ──────────────────────────────────────────────
    // Execution behavior
    // ──────────────────────────────────────────────

    [Fact]
    public async Task RunAuditAsync_CompletesWithinTimeout()
    {
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var result = await new AccountAudit().RunAuditAsync(cts.Token);
        Assert.NotNull(result);
        Assert.True(result.Success, $"Timed audit run failed: {result.Error}");
    }

    [Fact]
    public async Task RunAuditAsync_SupportsIdempotentExecution()
    {
        // Running twice should produce consistent results
        var result2 = await new AccountAudit().RunAuditAsync();
        Assert.Equal(_result.Success, result2.Success);
        Assert.Equal(_result.Findings.Count, result2.Findings.Count);
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();

        try
        {
            var result = await new AccountAudit().RunAuditAsync(cts.Token);
            // Acceptable if it completes despite cancellation (sync registry checks)
            Assert.NotNull(result);
        }
        catch (OperationCanceledException)
        {
            // Expected when cancellation is respected
        }
    }
}
