using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class RegressionDetectorTests
{
    private static AuditRunRecord MakeRun(int id, int daysAgo, params (string title, string severity, string module)[] findings)
    {
        var run = new AuditRunRecord
        {
            Id = id,
            Timestamp = DateTimeOffset.UtcNow.AddDays(-daysAgo),
            OverallScore = 80,
            Grade = "B",
            TotalFindings = findings.Length,
            Findings = findings.Select(f => new FindingRecord
            {
                RunId = id,
                Title = f.title,
                Severity = f.severity,
                ModuleName = f.module,
                Description = $"Description for {f.title}"
            }).ToList()
        };
        return run;
    }

    [Fact]
    public void Analyze_TooFewRuns_ReturnsNoData()
    {
        var detector = new RegressionDetector();
        var runs = new List<AuditRunRecord> { MakeRun(1, 5, ("A", "Warning", "Firewall")) };

        var report = detector.Analyze(runs);

        Assert.False(report.HasData);
    }

    [Fact]
    public void Analyze_NoRegressions_ReturnsEmpty()
    {
        var detector = new RegressionDetector();
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, 10, ("A", "Warning", "Firewall")),
            MakeRun(2, 5, ("A", "Warning", "Firewall")),
        };

        var report = detector.Analyze(runs);

        Assert.True(report.HasData);
        Assert.Equal(0, report.TotalRegressions);
    }

    [Fact]
    public void Analyze_DetectsRegression()
    {
        var detector = new RegressionDetector();
        var runs = new List<AuditRunRecord>
        {
            // Run 1: finding present
            MakeRun(1, 15, ("Firewall disabled", "Critical", "Firewall")),
            // Run 2: finding resolved
            MakeRun(2, 10),
            // Run 3: finding reappears — regression!
            MakeRun(3, 5, ("Firewall disabled", "Critical", "Firewall")),
        };

        var report = detector.Analyze(runs);

        Assert.True(report.HasData);
        Assert.Equal(1, report.TotalRegressions);
        Assert.Equal(1, report.CriticalRegressions);
        Assert.Equal("Firewall disabled", report.Regressions[0].Title);
        Assert.Equal(1, report.Regressions[0].RegressionCount);
    }

    [Fact]
    public void Analyze_DetectsRepeatOffenders()
    {
        var detector = new RegressionDetector();
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, 20, ("Bad setting", "Warning", "System")),
            MakeRun(2, 15), // resolved
            MakeRun(3, 10, ("Bad setting", "Warning", "System")), // regressed
            MakeRun(4, 5), // resolved again
            MakeRun(5, 1, ("Bad setting", "Warning", "System")), // regressed again!
        };

        var report = detector.Analyze(runs);

        Assert.Equal(1, report.TotalRegressions);
        Assert.Equal(2, report.Regressions[0].RegressionCount);
        Assert.Single(report.RepeatOffenders);
    }

    [Fact]
    public void Analyze_IdentifiesActiveRegressions()
    {
        var detector = new RegressionDetector();
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, 15, ("Issue A", "Critical", "Network")),
            MakeRun(2, 10), // resolved
            MakeRun(3, 5, ("Issue A", "Critical", "Network")), // regressed & still present in latest
        };

        var report = detector.Analyze(runs);

        Assert.Single(report.ActiveRegressions);
        Assert.Equal("Issue A", report.ActiveRegressions[0].Title);
    }

    [Fact]
    public void Analyze_DoesNotFlagNewFindings()
    {
        var detector = new RegressionDetector();
        var runs = new List<AuditRunRecord>
        {
            MakeRun(1, 10, ("Old issue", "Warning", "Firewall")),
            MakeRun(2, 5, ("Old issue", "Warning", "Firewall"), ("New issue", "Critical", "Network")),
        };

        var report = detector.Analyze(runs);

        // "New issue" is new, not a regression
        Assert.Equal(0, report.TotalRegressions);
    }

    [Fact]
    public void FormatText_NoRegressions_ShowsAllClear()
    {
        var report = new RegressionReport
        {
            HasData = true,
            TotalRegressions = 0,
            Regressions = [],
            ActiveRegressions = [],
            RepeatOffenders = [],
        };

        var text = RegressionDetector.FormatText(report);
        Assert.Contains("No regressions detected", text);
    }

    [Fact]
    public void ToDict_ContainsExpectedKeys()
    {
        var report = new RegressionReport
        {
            HasData = true,
            AnalyzedRuns = 3,
            AnalyzedDays = 15,
            TotalRegressions = 1,
            Regressions = [new RegressionFinding { Title = "Test", Severity = "Warning", ModuleName = "Firewall" }],
            ActiveRegressions = [],
            RepeatOffenders = [],
        };

        var dict = RegressionDetector.ToDict(report);

        Assert.True((bool)dict["hasData"]!);
        Assert.Equal(3, dict["analyzedRuns"]);
        Assert.Equal(1, dict["totalRegressions"]);
    }
}
