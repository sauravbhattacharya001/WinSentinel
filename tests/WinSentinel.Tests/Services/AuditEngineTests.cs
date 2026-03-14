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

        Assert.Equal(23, engine.Modules.Count);

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
        Assert.Contains("Browser", categories);
        Assert.Contains("Applications", categories);
        Assert.Contains("Encryption", categories);
        Assert.Contains("Event Logs", categories);
        Assert.Contains("Software", categories);
        Assert.Contains("Certificates", categories);
        Assert.Contains("PowerShell", categories);
        Assert.Contains("DNS", categories);
        Assert.Contains("ScheduledTasks", categories);
        Assert.Contains("Services", categories);
        Assert.Contains("Registry", categories);
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

    // --- Additional unit tests ---

    [Fact]
    public async Task RunFullAuditAsync_EmptyModuleList_ReturnsEmptyReport()
    {
        var engine = new AuditEngine(Array.Empty<IAuditModule>());
        var report = await engine.RunFullAuditAsync();

        Assert.Empty(report.Results);
        Assert.Equal(0, report.TotalFindings);
        Assert.True(report.GeneratedAt > DateTimeOffset.MinValue);
    }

    [Fact]
    public async Task RunFullAuditAsync_CancellationRespected()
    {
        var modules = new IAuditModule[] { new MockSlowAudit() };
        var engine = new AuditEngine(modules);
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => engine.RunFullAuditAsync(cancellationToken: cts.Token));
    }

    [Fact]
    public async Task RunFullAuditAsync_TimingIsRecorded()
    {
        var modules = new IAuditModule[] { new MockPassAudit() };
        var engine = new AuditEngine(modules);
        var before = DateTimeOffset.UtcNow;

        var report = await engine.RunFullAuditAsync();

        Assert.True(report.GeneratedAt >= before);
        Assert.True(report.GeneratedAt <= DateTimeOffset.UtcNow);
        foreach (var result in report.Results)
        {
            Assert.True(result.EndTime >= result.StartTime);
        }
    }

    [Fact]
    public async Task RunFullAuditAsync_ScoreInValidRange()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockWarningAudit(), new MockCriticalAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        Assert.InRange(report.SecurityScore, 0, 100);
    }

    [Fact]
    public async Task RunFullAuditAsync_AllPassModules_HighScore()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockPassAudit(), new MockPassAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        // All passing should yield a high (likely 100) score
        Assert.True(report.SecurityScore >= 80,
            $"Expected high score for all-pass, got {report.SecurityScore}");
    }

    [Fact]
    public async Task RunFullAuditAsync_FailedModule_DoesNotPreventOthers()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockFailingAudit(), new MockWarningAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        Assert.Equal(3, report.Results.Count);
        var successes = report.Results.Count(r => r.Success);
        var failures = report.Results.Count(r => !r.Success);
        Assert.Equal(2, successes);
        Assert.Equal(1, failures);
    }

    [Fact]
    public async Task RunFullAuditAsync_FailedModule_HasErrorMessage()
    {
        var modules = new IAuditModule[] { new MockFailingAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        var result = report.Results.Single();
        Assert.False(result.Success);
        Assert.Contains("Simulated audit failure", result.Error);
    }

    [Fact]
    public async Task RunSingleAuditAsync_CaseInsensitiveMatch()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockWarningAudit() };
        var engine = new AuditEngine(modules);

        var result = await engine.RunSingleAuditAsync("mockpass");
        Assert.NotNull(result);
        Assert.Equal("Mock Pass", result!.ModuleName);
    }

    [Fact]
    public async Task RunSingleAuditAsync_PartialNameMatch()
    {
        var modules = new IAuditModule[] { new MockWarningAudit() };
        var engine = new AuditEngine(modules);

        // "Warning" appears in the module Name "Mock Warning"
        var result = await engine.RunSingleAuditAsync("Warning");
        Assert.NotNull(result);
    }

    [Fact]
    public void Modules_ReadOnlyList_CannotBeModified()
    {
        var modules = new IAuditModule[] { new MockPassAudit() };
        var engine = new AuditEngine(modules);

        var readOnly = engine.Modules;
        Assert.IsAssignableFrom<IReadOnlyList<IAuditModule>>(readOnly);
    }

    [Fact]
    public void SetHistoryService_SetsAndGets()
    {
        var engine = new AuditEngine(Array.Empty<IAuditModule>());
        Assert.Null(engine.HistoryService);

        var tempPath = Path.Combine(Path.GetTempPath(), $"audit_test_{Guid.NewGuid()}.db");
        try
        {
            var hs = new AuditHistoryService(tempPath);
            engine.SetHistoryService(hs);
            Assert.Same(hs, engine.HistoryService);
        }
        finally
        {
            try { File.Delete(tempPath); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        }
    }

    [Fact]
    public async Task GenerateTextSummary_ContainsScoreAndFindings()
    {
        var modules = new IAuditModule[] { new MockPassAudit(), new MockCriticalAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        var text = AuditEngine.GenerateTextSummary(report);

        Assert.Contains("WinSentinel Security Report", text);
        Assert.Contains("Score:", text);
        Assert.Contains("Grade:", text);
        Assert.Contains("Mock Pass", text);
        Assert.Contains("Mock Critical", text);
        Assert.Contains("Bad Thing", text);
        Assert.Contains("Critical:", text);
    }

    [Fact]
    public async Task GenerateTextSummary_FailedModule_ShowsError()
    {
        var modules = new IAuditModule[] { new MockFailingAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        var text = AuditEngine.GenerateTextSummary(report);

        Assert.Contains("Error", text);
        Assert.Contains("Simulated audit failure", text);
    }

    [Fact]
    public async Task GenerateTextSummary_ShowsRemediation()
    {
        var modules = new IAuditModule[] { new MockCriticalAudit() };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        var text = AuditEngine.GenerateTextSummary(report);

        Assert.Contains("Fix now", text);
    }

    [Fact]
    public async Task RunFullAuditAsync_MultipleModules_AllResultsPresent()
    {
        var modules = new IAuditModule[]
        {
            new MockPassAudit(),
            new MockWarningAudit(),
            new MockCriticalAudit(),
            new MockFailingAudit()
        };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        Assert.Equal(4, report.Results.Count);

        var names = report.Results.Select(r => r.ModuleName).ToHashSet();
        Assert.Contains("Mock Pass", names);
        Assert.Contains("Mock Warning", names);
        Assert.Contains("Mock Critical", names);
        Assert.Contains("Mock Failing", names);
    }

    [Fact]
    public async Task RunFullAuditAsync_FindingCounts_MatchCategories()
    {
        var modules = new IAuditModule[]
        {
            new MockPassAudit(),
            new MockWarningAudit(),
            new MockCriticalAudit()
        };
        var engine = new AuditEngine(modules);
        var report = await engine.RunFullAuditAsync();

        Assert.Equal(report.TotalPass, report.Results.Sum(r => r.Findings.Count(f => f.Severity == Severity.Pass)));
        Assert.Equal(report.TotalWarnings, report.Results.Sum(r => r.Findings.Count(f => f.Severity == Severity.Warning)));
        Assert.Equal(report.TotalCritical, report.Results.Sum(r => r.Findings.Count(f => f.Severity == Severity.Critical)));
    }

    [Fact]
    public async Task RunSingleAuditAsync_WhitespaceCategory_ReturnsFirstModule()
    {
        // Empty string matches via String.Contains — verifies no crash
        var engine = new AuditEngine(new IAuditModule[] { new MockPassAudit() });
        var result = await engine.RunSingleAuditAsync("");
        // Empty string matches any Name via Contains, so first module is returned
        Assert.NotNull(result);
    }

    // --- Additional mock for timeout/slow scenarios ---

    private class MockSlowAudit : IAuditModule
    {
        public string Name => "Mock Slow";
        public string Category => "MockSlow";
        public string Description => "Takes a long time";
        public async Task<AuditResult> RunAuditAsync(CancellationToken ct = default)
        {
            await Task.Delay(10000, ct); // 10 seconds, but should be cancelled
            return new AuditResult
            {
                ModuleName = Name, Category = Category,
                StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow,
                Findings = { Finding.Pass("OK", "Done", Category) }
            };
        }
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
