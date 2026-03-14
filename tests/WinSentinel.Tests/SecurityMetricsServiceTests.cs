using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class SecurityMetricsServiceTests
{
    private readonly SecurityMetricsService _svc = new();

    private static Finding MakeFinding(string title, Severity sev, string category = "Network") =>
        new() { Title = title, Description = "desc", Severity = sev, Category = category };

    private static List<(DateTimeOffset, List<Finding>)> MakeSnapshots(
        params (int dayOffset, List<Finding> findings)[] data)
    {
        var baseTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        return data.Select(d => (baseTime.AddDays(d.dayOffset), d.findings)).ToList();
    }

    // ── BuildTrackingHistory ─────────────────────────────────────

    [Fact]
    public void BuildTrackingHistory_EmptySnapshots_ReturnsEmpty()
    {
        var result = _svc.BuildTrackingHistory(new());
        Assert.Empty(result);
    }

    [Fact]
    public void BuildTrackingHistory_SingleScan_TracksAllFindings()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding>
            {
                MakeFinding("Open Port", Severity.Critical),
                MakeFinding("Weak Cipher", Severity.Warning)
            }));

        var result = _svc.BuildTrackingHistory(snapshots);

        Assert.Equal(2, result.Count);
        Assert.All(result, t => Assert.False(t.IsResolved));
    }

    [Fact]
    public void BuildTrackingHistory_IgnoresPassFindings()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding>
            {
                MakeFinding("All Good", Severity.Pass),
                MakeFinding("Minor Issue", Severity.Info)
            }));

        var result = _svc.BuildTrackingHistory(snapshots);
        Assert.Single(result);
        Assert.Equal("Minor Issue", result[0].Title);
    }

    [Fact]
    public void BuildTrackingHistory_DetectsResolution()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding> { MakeFinding("Bug", Severity.Warning) }),
            (7, new List<Finding>())); // Bug gone in second scan

        var result = _svc.BuildTrackingHistory(snapshots);

        Assert.Single(result);
        Assert.True(result[0].IsResolved);
        Assert.NotNull(result[0].TimeToRemediate);
        Assert.Equal(7, result[0].TimeToRemediate!.Value.TotalDays);
    }

    [Fact]
    public void BuildTrackingHistory_DetectsRecurrence()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding> { MakeFinding("Flaky", Severity.Warning) }),
            (7, new List<Finding>()),  // Resolved
            (14, new List<Finding> { MakeFinding("Flaky", Severity.Warning) })); // Back!

        var result = _svc.BuildTrackingHistory(snapshots);

        var flaky = result.Single(t => t.Title == "Flaky");
        Assert.True(flaky.RecurrenceCount >= 1);
        Assert.False(flaky.IsResolved); // Currently open again
    }

    [Fact]
    public void BuildTrackingHistory_MultipleCategories()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding>
            {
                MakeFinding("Port Open", Severity.Critical, "Network"),
                MakeFinding("Weak Password", Severity.Warning, "Account")
            }));

        var result = _svc.BuildTrackingHistory(snapshots);
        Assert.Equal(2, result.Count);
        Assert.Contains(result, t => t.Category == "Network");
        Assert.Contains(result, t => t.Category == "Account");
    }

    // ── ComputeMetrics ───────────────────────────────────────────

    [Fact]
    public void ComputeMetrics_EmptyTracked_ReturnsSummary()
    {
        var report = _svc.ComputeMetrics(new());
        Assert.Equal(0, report.TotalTracked);
        Assert.Contains("No findings", report.Summary);
    }

    [Fact]
    public void ComputeMetrics_FixRate_Correct()
    {
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Net", Severity = Severity.Warning,
                DetectedAt = DateTimeOffset.UtcNow.AddDays(-10),
                ResolvedAt = DateTimeOffset.UtcNow.AddDays(-3) },
            new() { Title = "B", Category = "Net", Severity = Severity.Critical,
                DetectedAt = DateTimeOffset.UtcNow.AddDays(-5) },
        };

        var report = _svc.ComputeMetrics(tracked);

        Assert.Equal(2, report.TotalTracked);
        Assert.Equal(1, report.ResolvedFindings);
        Assert.Equal(1, report.OpenFindings);
        Assert.Equal(50.0, report.FixRatePercent);
    }

    [Fact]
    public void ComputeMetrics_MTTR_Computed()
    {
        var now = DateTimeOffset.UtcNow;
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Net", Severity = Severity.Warning,
                DetectedAt = now.AddDays(-10), ResolvedAt = now.AddDays(-6) }, // 4 days
            new() { Title = "B", Category = "Net", Severity = Severity.Warning,
                DetectedAt = now.AddDays(-8), ResolvedAt = now.AddDays(-2) },  // 6 days
        };

        var report = _svc.ComputeMetrics(tracked);

        Assert.NotNull(report.MeanTimeToRemediate);
        Assert.Equal(5.0, report.MeanTimeToRemediate.Value.TotalDays, 0.1);
        Assert.NotNull(report.MedianTimeToRemediate);
    }

    [Fact]
    public void ComputeMetrics_MttrBySeverity()
    {
        var now = DateTimeOffset.UtcNow;
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Net", Severity = Severity.Critical,
                DetectedAt = now.AddDays(-4), ResolvedAt = now.AddDays(-2) },
            new() { Title = "B", Category = "Net", Severity = Severity.Warning,
                DetectedAt = now.AddDays(-10), ResolvedAt = now.AddDays(-3) },
        };

        var report = _svc.ComputeMetrics(tracked);

        Assert.True(report.MttrBySeverity.ContainsKey("Critical"));
        Assert.True(report.MttrBySeverity.ContainsKey("Warning"));
        Assert.Equal(2.0, report.MttrBySeverity["Critical"].TotalDays, 0.1);
        Assert.Equal(7.0, report.MttrBySeverity["Warning"].TotalDays, 0.1);
    }

    [Fact]
    public void ComputeMetrics_RecurrenceRate()
    {
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "Stable", Category = "Net", Severity = Severity.Info,
                DetectedAt = DateTimeOffset.UtcNow.AddDays(-10), RecurrenceCount = 0 },
            new() { Title = "Flaky", Category = "Net", Severity = Severity.Warning,
                DetectedAt = DateTimeOffset.UtcNow.AddDays(-5), RecurrenceCount = 2 },
        };

        var report = _svc.ComputeMetrics(tracked);
        Assert.Equal(50.0, report.RecurrenceRatePercent);
    }

    [Fact]
    public void ComputeMetrics_CategoryRisk_Ordered()
    {
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Network", Severity = Severity.Critical,
                DetectedAt = DateTimeOffset.UtcNow },
            new() { Title = "B", Category = "Network", Severity = Severity.Warning,
                DetectedAt = DateTimeOffset.UtcNow },
            new() { Title = "C", Category = "Account", Severity = Severity.Info,
                DetectedAt = DateTimeOffset.UtcNow },
        };

        var report = _svc.ComputeMetrics(tracked);

        Assert.Equal(2, report.CategoryRisks.Count);
        Assert.Equal("Network", report.CategoryRisks[0].Category);
        Assert.True(report.CategoryRisks[0].RiskScore > report.CategoryRisks[1].RiskScore);
        Assert.Equal(100.0, report.CategoryRisks.Sum(c => c.RiskPercentage), 0.1);
    }

    [Fact]
    public void ComputeMetrics_ScanInterval()
    {
        var baseTime = DateTimeOffset.UtcNow.AddDays(-30);
        var timestamps = Enumerable.Range(0, 10)
            .Select(i => baseTime.AddDays(i * 3)) // every 3 days
            .ToList();

        var report = _svc.ComputeMetrics(
            new List<SecurityMetricsService.TrackedFinding>
            {
                new() { Title = "X", Category = "Net", Severity = Severity.Warning,
                    DetectedAt = baseTime }
            },
            timestamps);

        Assert.NotNull(report.MeanScanInterval);
        Assert.Equal(3.0, report.MeanScanInterval.Value.TotalDays, 0.1);
    }

    [Fact]
    public void ComputeMetrics_Velocity_HasEntries()
    {
        var now = DateTimeOffset.UtcNow;
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Net", Severity = Severity.Warning,
                DetectedAt = now.AddDays(-20), ResolvedAt = now.AddDays(-10) },
            new() { Title = "B", Category = "Net", Severity = Severity.Critical,
                DetectedAt = now.AddDays(-5) },
        };

        var report = _svc.ComputeMetrics(tracked, velocityPeriod: TimeSpan.FromDays(7));
        Assert.NotEmpty(report.Velocity);
    }

    // ── Analyze (convenience) ────────────────────────────────────

    [Fact]
    public void Analyze_EndToEnd()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding>
            {
                MakeFinding("Port 22 Open", Severity.Critical),
                MakeFinding("TLS 1.0 Enabled", Severity.Warning),
            }),
            (7, new List<Finding>
            {
                MakeFinding("Port 22 Open", Severity.Critical),
                // TLS 1.0 resolved
            }),
            (14, new List<Finding>
            {
                // Port 22 also resolved
                MakeFinding("DNS Rebinding", Severity.Info),
            }));

        var report = _svc.Analyze(snapshots);

        Assert.Equal(3, report.TotalTracked);
        Assert.Equal(2, report.ResolvedFindings);
        Assert.Equal(1, report.OpenFindings);
        Assert.True(report.FixRatePercent > 60);
        Assert.NotNull(report.MeanTimeToRemediate);
        Assert.NotEmpty(report.Summary);
    }

    // ── Direction ────────────────────────────────────────────────

    [Fact]
    public void Direction_Improving_WhenResolvingMoreThanAdding()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding>
            {
                MakeFinding("A", Severity.Critical),
                MakeFinding("B", Severity.Warning),
                MakeFinding("C", Severity.Warning),
            }),
            (7, new List<Finding>
            {
                MakeFinding("A", Severity.Critical),
            }),
            (14, new List<Finding>()),
            (21, new List<Finding>()));

        var report = _svc.Analyze(snapshots, velocityPeriod: TimeSpan.FromDays(7));
        Assert.Equal(SecurityMetricsService.PostureDirection.Improving, report.Direction);
    }

    [Fact]
    public void Direction_Degrading_WhenAddingMoreThanResolving()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding>()),
            (7, new List<Finding>
            {
                MakeFinding("A", Severity.Critical),
                MakeFinding("B", Severity.Warning),
            }),
            (14, new List<Finding>
            {
                MakeFinding("A", Severity.Critical),
                MakeFinding("B", Severity.Warning),
                MakeFinding("C", Severity.Critical),
                MakeFinding("D", Severity.Warning),
            }),
            (21, new List<Finding>
            {
                MakeFinding("A", Severity.Critical),
                MakeFinding("B", Severity.Warning),
                MakeFinding("C", Severity.Critical),
                MakeFinding("D", Severity.Warning),
                MakeFinding("E", Severity.Info),
                MakeFinding("F", Severity.Warning),
            }));

        var report = _svc.Analyze(snapshots, velocityPeriod: TimeSpan.FromDays(7));
        Assert.Equal(SecurityMetricsService.PostureDirection.Degrading, report.Direction);
    }

    // ── Reporting ────────────────────────────────────────────────

    [Fact]
    public void ToTextReport_ContainsKPIs()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding> { MakeFinding("Bug", Severity.Warning) }),
            (7, new List<Finding>()));

        var report = _svc.Analyze(snapshots);
        var text = _svc.ToTextReport(report);

        Assert.Contains("SECURITY METRICS REPORT", text);
        Assert.Contains("Fix Rate:", text);
        Assert.Contains("Recurrence Rate:", text);
        Assert.Contains("Mean TTR:", text);
    }

    [Fact]
    public void ToTextReport_ContainsCategoryRisk()
    {
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Firewall", Severity = Severity.Critical,
                DetectedAt = DateTimeOffset.UtcNow },
        };

        var report = _svc.ComputeMetrics(tracked);
        var text = _svc.ToTextReport(report);
        Assert.Contains("Firewall", text);
        Assert.Contains("Category Risk Distribution", text);
    }

    [Fact]
    public void ToJson_ValidJson()
    {
        var snapshots = MakeSnapshots(
            (0, new List<Finding> { MakeFinding("X", Severity.Info) }),
            (7, new List<Finding>()));

        var report = _svc.Analyze(snapshots);
        var json = _svc.ToJson(report);

        Assert.NotEmpty(json);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotNull(doc.RootElement.GetProperty("TotalTracked"));
        Assert.NotNull(doc.RootElement.GetProperty("FixRatePercent"));
        Assert.NotNull(doc.RootElement.GetProperty("Direction"));
    }

    [Fact]
    public void ToJson_RoundTrips()
    {
        var report = new SecurityMetricsService.MetricsReport
        {
            TotalTracked = 5,
            OpenFindings = 2,
            ResolvedFindings = 3,
            FixRatePercent = 60.0,
            Direction = SecurityMetricsService.PostureDirection.Improving,
            Summary = "Test summary"
        };

        var json = _svc.ToJson(report);
        var deserialized = System.Text.Json.JsonSerializer
            .Deserialize<SecurityMetricsService.MetricsReport>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(5, deserialized!.TotalTracked);
        Assert.Equal(60.0, deserialized.FixRatePercent);
    }

    // ── Edge cases ───────────────────────────────────────────────

    [Fact]
    public void ComputeMetrics_AllOpen_ZeroFixRate()
    {
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Net", Severity = Severity.Warning,
                DetectedAt = DateTimeOffset.UtcNow },
            new() { Title = "B", Category = "Net", Severity = Severity.Critical,
                DetectedAt = DateTimeOffset.UtcNow },
        };

        var report = _svc.ComputeMetrics(tracked);
        Assert.Equal(0.0, report.FixRatePercent);
        Assert.Null(report.MeanTimeToRemediate);
    }

    [Fact]
    public void ComputeMetrics_AllResolved_FullFixRate()
    {
        var now = DateTimeOffset.UtcNow;
        var tracked = new List<SecurityMetricsService.TrackedFinding>
        {
            new() { Title = "A", Category = "Net", Severity = Severity.Warning,
                DetectedAt = now.AddDays(-10), ResolvedAt = now.AddDays(-5) },
            new() { Title = "B", Category = "Net", Severity = Severity.Critical,
                DetectedAt = now.AddDays(-8), ResolvedAt = now.AddDays(-1) },
        };

        var report = _svc.ComputeMetrics(tracked);
        Assert.Equal(100.0, report.FixRatePercent);
    }

    [Fact]
    public void BuildTrackingHistory_NullThrows()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _svc.BuildTrackingHistory(null!));
    }

    [Fact]
    public void ComputeMetrics_NullThrows()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _svc.ComputeMetrics(null!));
    }

    [Fact]
    public void ToTextReport_NullThrows()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _svc.ToTextReport(null!));
    }

    [Fact]
    public void ToJson_NullThrows()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _svc.ToJson(null!));
    }
}
