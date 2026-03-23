using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class DriftDetectionServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly BaselineService _baselineService;

    public DriftDetectionServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"winsentinel-drift-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _baselineService = new BaselineService(Path.Combine(_tempDir, "baselines"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    private SecurityReport CreateReport(int score, params (string module, string title, Severity severity)[] findings)
    {
        var results = new List<AuditResult>();
        var grouped = findings.GroupBy(f => f.module);
        foreach (var group in grouped)
        {
            var result = new AuditResult
            {
                ModuleName = group.Key,
                Category = group.Key,
                Findings = group.Select(f => new Finding
                {
                    Title = f.title,
                    Severity = f.severity,
                    Description = $"Description for {f.title}",
                    Remediation = $"Fix {f.title}"
                }).ToList()
            };
            results.Add(result);
        }

        return new SecurityReport
        {
            SecurityScore = score,
            Results = results,
            GeneratedAt = DateTimeOffset.Now
        };
    }

    [Fact]
    public void Analyze_NoDrift_ReturnsStable()
    {
        // Save baseline with one finding
        var baselineReport = CreateReport(85, ("Firewall", "Open Port 3389", Severity.Warning));
        _baselineService.SaveBaseline("test-baseline", baselineReport);

        // Current report has same finding
        var currentReport = CreateReport(85, ("Firewall", "Open Port 3389", Severity.Warning));

        using var historyService = new AuditHistoryService(Path.Combine(_tempDir, "history.db"));
        historyService.EnsureDatabase();

        var service = new DriftDetectionService(_baselineService, historyService);
        var result = service.Analyze(currentReport, "test-baseline");

        Assert.Equal("test-baseline", result.BaselineName);
        Assert.Equal(0, result.DriftScore);
        Assert.Equal("Stable", result.DriftLevel);
        Assert.Empty(result.DriftItems);
    }

    [Fact]
    public void Analyze_NewFinding_DetectsDrift()
    {
        var baselineReport = CreateReport(85, ("Firewall", "Open Port 3389", Severity.Warning));
        _baselineService.SaveBaseline("test-baseline", baselineReport);

        // Current report has additional finding
        var currentReport = CreateReport(70,
            ("Firewall", "Open Port 3389", Severity.Warning),
            ("Accounts", "Guest Account Enabled", Severity.Critical));

        using var historyService = new AuditHistoryService(Path.Combine(_tempDir, "history.db"));
        historyService.EnsureDatabase();

        var service = new DriftDetectionService(_baselineService, historyService);
        var result = service.Analyze(currentReport, "test-baseline");

        Assert.True(result.DriftScore > 0);
        Assert.Contains(result.DriftItems, d =>
            d.Title == "Guest Account Enabled" && d.Category == DriftCategory.NewFinding);
    }

    [Fact]
    public void Analyze_ResolvedFinding_DetectsDrift()
    {
        var baselineReport = CreateReport(70,
            ("Firewall", "Open Port 3389", Severity.Warning),
            ("Accounts", "Guest Account Enabled", Severity.Critical));
        _baselineService.SaveBaseline("test-baseline", baselineReport);

        // Current report has one finding resolved
        var currentReport = CreateReport(85, ("Firewall", "Open Port 3389", Severity.Warning));

        using var historyService = new AuditHistoryService(Path.Combine(_tempDir, "history.db"));
        historyService.EnsureDatabase();

        var service = new DriftDetectionService(_baselineService, historyService);
        var result = service.Analyze(currentReport, "test-baseline");

        Assert.Contains(result.DriftItems, d =>
            d.Title == "Guest Account Enabled" && d.Category == DriftCategory.Resolved);
    }

    [Fact]
    public void Analyze_SeverityChange_Detected()
    {
        var baselineReport = CreateReport(80, ("Firewall", "Open Port 3389", Severity.Info));
        _baselineService.SaveBaseline("test-baseline", baselineReport);

        // Same finding, escalated severity
        var currentReport = CreateReport(70, ("Firewall", "Open Port 3389", Severity.Critical));

        using var historyService = new AuditHistoryService(Path.Combine(_tempDir, "history.db"));
        historyService.EnsureDatabase();

        var service = new DriftDetectionService(_baselineService, historyService);
        var result = service.Analyze(currentReport, "test-baseline");

        Assert.Contains(result.DriftItems, d =>
            d.Title == "Open Port 3389" && d.Category == DriftCategory.SeverityChanged);
    }

    [Fact]
    public void Analyze_UsesLatestBaseline_WhenNoneSpecified()
    {
        var report1 = CreateReport(90);
        _baselineService.SaveBaseline("old-baseline", report1, "old");

        // Wait a tiny bit for timestamp ordering
        var report2 = CreateReport(80, ("Firewall", "Open Port 3389", Severity.Warning));
        _baselineService.SaveBaseline("new-baseline", report2, "new");

        var currentReport = CreateReport(80, ("Firewall", "Open Port 3389", Severity.Warning));

        using var historyService = new AuditHistoryService(Path.Combine(_tempDir, "history.db"));
        historyService.EnsureDatabase();

        var service = new DriftDetectionService(_baselineService, historyService);
        var result = service.Analyze(currentReport);

        // Should use latest baseline — and find no drift since findings match
        Assert.Equal("new-baseline", result.BaselineName);
    }

    [Fact]
    public void Analyze_ThrowsWhenNoBaselines()
    {
        var currentReport = CreateReport(80);

        using var historyService = new AuditHistoryService(Path.Combine(_tempDir, "history.db"));
        historyService.EnsureDatabase();

        var service = new DriftDetectionService(_baselineService, historyService);
        Assert.Throws<InvalidOperationException>(() => service.Analyze(currentReport));
    }

    [Fact]
    public void RenderText_ProducesOutput()
    {
        var report = new DriftReport
        {
            BaselineName = "my-baseline",
            BaselineCreatedAt = DateTimeOffset.Now.AddDays(-7),
            BaselineScore = 85,
            CurrentScore = 70,
            DriftScore = 35,
            DriftLevel = "Significant",
            AnalyzedAt = DateTimeOffset.Now,
            DriftItems =
            [
                new DriftItem
                {
                    Title = "Guest Account Enabled",
                    Module = "Accounts",
                    Severity = "Critical",
                    Category = DriftCategory.NewFinding,
                }
            ]
        };

        var text = DriftDetectionService.RenderText(report);

        Assert.Contains("Configuration Drift Report", text);
        Assert.Contains("my-baseline", text);
        Assert.Contains("Guest Account Enabled", text);
        Assert.Contains("Significant", text);
    }

    [Fact]
    public void RenderJson_ProducesValidJson()
    {
        var report = new DriftReport
        {
            BaselineName = "test",
            BaselineCreatedAt = DateTimeOffset.Now,
            BaselineScore = 80,
            CurrentScore = 75,
            DriftScore = 10,
            DriftLevel = "Minimal",
            AnalyzedAt = DateTimeOffset.Now,
        };

        var json = DriftDetectionService.RenderJson(report);

        Assert.Contains("\"BaselineName\"", json);
        Assert.Contains("\"DriftScore\"", json);
    }
}
