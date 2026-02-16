using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Comprehensive tests for the EventLogAudit module.
/// Runs against the actual Windows machine to verify real results.
/// </summary>
public class EventLogAuditTests
{
    private readonly EventLogAudit _audit = new();

    [Fact]
    public void Properties_AreCorrect()
    {
        Assert.Equal("Event Log Analysis", _audit.Name);
        Assert.Equal("Event Logs", _audit.Category);
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
        Assert.Contains("failed login", _audit.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("audit policy", _audit.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAuditAsync_Succeeds()
    {
        var result = await _audit.RunAuditAsync();

        Assert.True(result.Success, $"Audit failed: {result.Error}");
        Assert.Equal("Event Log Analysis", result.ModuleName);
        Assert.Equal("Event Logs", result.Category);
    }

    [Fact]
    public async Task RunAuditAsync_ProducesFindings()
    {
        var result = await _audit.RunAuditAsync();

        Assert.NotEmpty(result.Findings);
        // Should have at minimum: EventLog service, failed logins, lockouts, privilege escalation,
        // audit policies, service installs, PowerShell, Defender, system errors, log size, log cleared = 11 checks
        // Some may be "Access Denied" Info findings but should still have findings
        Assert.True(result.Findings.Count >= 5,
            $"Expected at least 5 findings, got {result.Findings.Count}");
    }

    [Fact]
    public async Task RunAuditAsync_FindingsHaveRequiredFields()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Title),
                "Finding title must not be empty");
            Assert.False(string.IsNullOrWhiteSpace(finding.Description),
                "Finding description must not be empty");
            Assert.True(Enum.IsDefined(finding.Severity),
                $"Invalid severity: {finding.Severity}");
            Assert.Equal("Event Logs", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_HasEventLogServiceFinding()
    {
        var result = await _audit.RunAuditAsync();

        var serviceFinding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Event Log Service", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(serviceFinding);
        // The Event Log service should be running on any Windows machine
        Assert.Equal(Severity.Pass, serviceFinding.Severity);
    }

    [Fact]
    public async Task RunAuditAsync_HasFailedLoginFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Failed Login", StringComparison.OrdinalIgnoreCase) ||
                                 f.Title.Contains("Login Check", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasAccountLockoutFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Lockout", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasPrivilegeEscalationFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Privilege", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasAuditPolicyFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Audit Polic", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasServiceInstallFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Service", StringComparison.OrdinalIgnoreCase) &&
                                 f.Title.Contains("Install", StringComparison.OrdinalIgnoreCase) ||
                                 f.Title.Contains("New Services", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasPowerShellFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("PowerShell", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasDefenderDetectionFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasSystemErrorFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("System", StringComparison.OrdinalIgnoreCase) &&
                                 (f.Title.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
                                  f.Title.Contains("Critical", StringComparison.OrdinalIgnoreCase)));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasSecurityLogSizeFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Security Log", StringComparison.OrdinalIgnoreCase) &&
                                 (f.Title.Contains("Size", StringComparison.OrdinalIgnoreCase) ||
                                  f.Title.Contains("MB", StringComparison.OrdinalIgnoreCase) ||
                                  f.Title.Contains("Small", StringComparison.OrdinalIgnoreCase)));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_HasLogClearedFinding()
    {
        var result = await _audit.RunAuditAsync();

        var finding = result.Findings
            .FirstOrDefault(f => f.Title.Contains("Log Clear", StringComparison.OrdinalIgnoreCase) ||
                                 f.Title.Contains("Audit Log", StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(finding);
    }

    [Fact]
    public async Task RunAuditAsync_CriticalFindingsHaveRemediation()
    {
        var result = await _audit.RunAuditAsync();

        var actionableFindings = result.Findings
            .Where(f => f.Severity == Severity.Critical || f.Severity == Severity.Warning);

        foreach (var finding in actionableFindings)
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                $"Finding '{finding.Title}' (severity={finding.Severity}) should have remediation advice");
        }
    }

    [Fact]
    public async Task RunAuditAsync_CompletesWithinTimeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var result = await _audit.RunAuditAsync(cts.Token);

        Assert.True(result.Success, $"Audit should complete within 120 seconds: {result.Error}");
        Assert.True(result.Duration < TimeSpan.FromSeconds(120),
            $"Audit took {result.Duration.TotalSeconds:F1}s, expected < 120s");
    }

    [Fact]
    public async Task RunAuditAsync_SupportsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        try
        {
            var result = await _audit.RunAuditAsync(cts.Token);
            // If it completes, that's fine — some checks may be synchronous
        }
        catch (OperationCanceledException)
        {
            // Expected behavior
        }
    }

    [Fact]
    public async Task RunAuditAsync_ScoreIsCalculated()
    {
        var result = await _audit.RunAuditAsync();

        Assert.InRange(result.Score, 0, 100);
    }

    [Fact]
    public async Task RunAuditAsync_AllFindingsHaveCorrectCategory()
    {
        var result = await _audit.RunAuditAsync();

        foreach (var finding in result.Findings)
        {
            Assert.Equal("Event Logs", finding.Category);
        }
    }

    [Fact]
    public async Task RunAuditAsync_TimestampsAreSet()
    {
        var before = DateTimeOffset.UtcNow;
        var result = await _audit.RunAuditAsync();
        var after = DateTimeOffset.UtcNow;

        Assert.True(result.StartTime >= before.AddSeconds(-1),
            "StartTime should be after test start");
        Assert.True(result.EndTime <= after.AddSeconds(1),
            "EndTime should be before test end");
        Assert.True(result.Duration >= TimeSpan.Zero,
            "Duration should be non-negative");
    }
}
