using WinSentinel.Core.Audits;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for the AuditEngine orchestration.
/// Unit tests use mock modules; integration test runs a single real module.
/// Full audit integration tests are excluded by default (too slow for CI).
/// </summary>
public class AuditEngineTests
{
    [Fact]
    public void DefaultConstructor_LoadsAllModules()
    {
        var engine = new AuditEngine();

        Assert.Equal(9, engine.Modules.Count);

        var categories = engine.Modules.Select(m => m.Category).ToHashSet();
        Assert.Contains("Firewall", categories);
        Assert.Contains("Updates", categories);
        Assert.Contains("Defender", categories);
        Assert.Contains("Accounts", categories);
        Assert.Contains("Network", categories);
        Assert.Contains("Processes", categories);
        Assert.Contains("Startup", categories);
        Assert.Contains("System", categories);
        Assert.Contains("Privacy", categories);
    }

    [Fact]
    public void CustomConstructor_UsesProvidedModules()
    {
        var modules = new IAuditModule[] { new FirewallAudit() };
        var engine = new AuditEngine(modules);

        Assert.Single(engine.Modules);
    }

    [Fact]
    public async Task RunFullAuditAsync_WithMockModules_ProducesReport()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockWarningAudit() };
        var engine = new AuditEngine(modules);

        var report = await engine.RunFullAuditAsync();

        Assert.Equal(2, report.Results.Count);
        Assert.True(report.Results.All(r => r.Success));
        Assert.Equal(2, report.TotalFindings);
        Assert.Equal(1, report.TotalPass);
        Assert.Equal(1, report.TotalWarnings);
        Assert.InRange(report.SecurityScore, 0, 100);
        Assert.True(report.GeneratedAt > DateTimeOffset.MinValue);
    }

    [Fact]
    public async Task RunFullAuditAsync_WithMockModules_HandlesFailure()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockFailingAudit() };
        var engine = new AuditEngine(modules);

        var report = await engine.RunFullAuditAsync();

        Assert.Equal(2, report.Results.Count);
        Assert.True(report.Results[0].Success);
        Assert.False(report.Results[1].Success);
        Assert.NotNull(report.Results[1].Error);
    }

    [Fact]
    public async Task RunFullAuditAsync_WithMockModules_ReportsProgress()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockWarningAudit() };
        var engine = new AuditEngine(modules);
        var progressUpdates = new List<(string module, int current, int total)>();

        var progress = new Progress<(string module, int current, int total)>(update =>
        {
            lock (progressUpdates) { progressUpdates.Add(update); }
        });

        await engine.RunFullAuditAsync(progress);

        // Small delay to let async Progress<T> callbacks fire
        await Task.Delay(100);

        Assert.Equal(2, progressUpdates.Count);
        Assert.Equal(1, progressUpdates[0].current);
        Assert.Equal(2, progressUpdates[0].total);
        Assert.Equal(2, progressUpdates[1].current);
        Assert.Equal(2, progressUpdates[1].total);
    }

    [Fact]
    public async Task RunSingleAuditAsync_ByCategory()
    {
        var engine = new AuditEngine();
        var result = await engine.RunSingleAuditAsync("Firewall");

        Assert.NotNull(result);
        Assert.Equal("Firewall Audit", result!.ModuleName);
        Assert.True(result.Success);
        Assert.NotEmpty(result.Findings);
    }

    [Fact]
    public async Task RunSingleAuditAsync_ByPartialName()
    {
        var engine = new AuditEngine();
        var result = await engine.RunSingleAuditAsync("Defender");

        Assert.NotNull(result);
        Assert.Equal("Defender Audit", result!.ModuleName);
    }

    [Fact]
    public async Task RunSingleAuditAsync_ReturnsNullForUnknown()
    {
        var engine = new AuditEngine();
        var result = await engine.RunSingleAuditAsync("NonExistentModule");

        Assert.Null(result);
    }

    [Fact]
    public async Task RunFullAuditAsync_CriticalFindingsHaveRemediations()
    {
        // Use mock modules with critical findings to test the invariant
        var modules = new IAuditModule[] { new MockCriticalAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings.Where(f => f.Severity == Severity.Critical))
            {
                Assert.False(string.IsNullOrWhiteSpace(finding.Remediation),
                    $"Critical finding '{finding.Title}' has no remediation");
            }
        }
    }

    [Fact]
    public async Task RunFullAuditAsync_ReportAggregationIsCorrect()
    {
        var modules = new IAuditModule[]
        {
            new MockPassAudit(),
            new MockWarningAudit(),
            new MockCriticalAudit()
        };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        int expectedTotal = report.Results.Sum(r => r.Findings.Count);
        Assert.Equal(expectedTotal, report.TotalFindings);

        int expectedCritical = report.Results.Sum(r => r.CriticalCount);
        Assert.Equal(expectedCritical, report.TotalCritical);
    }

    // --- Mock audit modules for fast unit testing ---

    private class MockPassAudit : IAuditModule
    {
        public string Name => "Mock Pass";
        public string Category => "MockPass";
        public string Description => "Always passes";
        public Task<AuditResult> RunAuditAsync(CancellationToken ct = default) =>
            Task.FromResult(new AuditResult
            {
                ModuleName = Name, Category = Category,
                StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow,
                Findings = { Finding.Pass("All Good", "Everything checks out", Category) }
            });
    }

    private class MockWarningAudit : IAuditModule
    {
        public string Name => "Mock Warning";
        public string Category => "MockWarn";
        public string Description => "Returns a warning";
        public Task<AuditResult> RunAuditAsync(CancellationToken ct = default) =>
            Task.FromResult(new AuditResult
            {
                ModuleName = Name, Category = Category,
                StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow,
                Findings = { Finding.Warning("Minor Issue", "Not great", Category, "Fix it") }
            });
    }

    private class MockCriticalAudit : IAuditModule
    {
        public string Name => "Mock Critical";
        public string Category => "MockCrit";
        public string Description => "Returns a critical finding";
        public Task<AuditResult> RunAuditAsync(CancellationToken ct = default) =>
            Task.FromResult(new AuditResult
            {
                ModuleName = Name, Category = Category,
                StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow,
                Findings = { Finding.Critical("Bad Thing", "Very bad", Category, "Fix now", "fix-cmd") }
            });
    }

    private class MockFailingAudit : IAuditModule
    {
        public string Name => "Mock Failing";
        public string Category => "MockFail";
        public string Description => "Always throws";
        public Task<AuditResult> RunAuditAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("Simulated audit failure");
    }
}
