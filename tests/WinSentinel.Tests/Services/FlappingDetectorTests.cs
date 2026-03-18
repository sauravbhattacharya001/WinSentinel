using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class FlappingDetectorTests
{
    private static List<AuditRunRecord> CreateRuns(params string[][] findingTitlesPerRun)
    {
        var runs = new List<AuditRunRecord>();
        var baseTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        for (int i = 0; i < findingTitlesPerRun.Length; i++)
        {
            var run = new AuditRunRecord
            {
                Id = i + 1,
                Timestamp = baseTime.AddDays(i),
                OverallScore = 80,
                Grade = "B",
                Findings = findingTitlesPerRun[i].Select(t => new FindingRecord
                {
                    Title = t,
                    ModuleName = "TestModule",
                    Severity = "Warning"
                }).ToList()
            };
            runs.Add(run);
        }

        return runs;
    }

    [Fact]
    public void Analyze_TooFewRuns_ReturnsNoData()
    {
        var detector = new FlappingDetector();
        var runs = CreateRuns(["A"], ["B"]);

        var report = detector.Analyze(runs);

        Assert.False(report.HasData);
    }

    [Fact]
    public void Analyze_StableFinding_NotFlapping()
    {
        var detector = new FlappingDetector();
        // Finding "A" present in all 5 runs — no transitions
        var runs = CreateRuns(["A"], ["A"], ["A"], ["A"], ["A"]);

        var report = detector.Analyze(runs);

        Assert.True(report.HasData);
        Assert.Empty(report.Findings); // No flapping
    }

    [Fact]
    public void Analyze_HighlyFlappingFinding_Detected()
    {
        var detector = new FlappingDetector();
        // Finding "A" alternates every run: present, absent, present, absent, present
        var runs = CreateRuns(["A"], [], ["A"], [], ["A"]);

        var report = detector.Analyze(runs);

        Assert.True(report.HasData);
        Assert.Single(report.Findings);
        var flapping = report.Findings[0];
        Assert.Equal("A", flapping.Title);
        Assert.Equal(4, flapping.Transitions); // 4 state changes
        Assert.True(flapping.FlapRate >= 0.7);
        Assert.Equal("Highly Unstable", flapping.Classification);
        Assert.True(flapping.CurrentlyPresent);
    }

    [Fact]
    public void Analyze_IntermittentFinding_Detected()
    {
        var detector = new FlappingDetector();
        // Finding appears in runs 1,2,3 then disappears in 4, reappears in 5
        // Transitions: none, none, none, absent, present = 2 transitions out of 4 gaps = 0.5
        var runs = CreateRuns(["A"], ["A"], ["A"], [], ["A"]);

        var report = detector.Analyze(runs);

        Assert.True(report.HasData);
        Assert.Single(report.Findings);
        Assert.True(report.Findings[0].FlapRate >= 0.2);
    }

    [Fact]
    public void Analyze_MultipleFindings_SortedByFlapRate()
    {
        var detector = new FlappingDetector();
        // "A" flaps every run, "B" flaps less
        var runs = CreateRuns(
            ["A", "B"],
            ["B"],
            ["A", "B"],
            ["B"],
            ["A"]);

        var report = detector.Analyze(runs);

        Assert.True(report.HasData);
        // "A" should have higher flap rate than "B"
        if (report.Findings.Count >= 2)
        {
            Assert.True(report.Findings[0].FlapRate >= report.Findings[1].FlapRate);
        }
    }

    [Fact]
    public void Analyze_PatternString_Generated()
    {
        var detector = new FlappingDetector();
        var runs = CreateRuns(["A"], [], ["A"], [], ["A"]);

        var report = detector.Analyze(runs);

        Assert.Single(report.Findings);
        Assert.Equal("█░█░█", report.Findings[0].Pattern);
    }

    [Fact]
    public void Analyze_Summary_CorrectGrade()
    {
        var detector = new FlappingDetector();
        // Only 1 finding, and it flaps — but ratio is low if total findings is 1
        var runs = CreateRuns(["A"], [], ["A"], [], ["A"]);

        var report = detector.Analyze(runs);

        Assert.NotNull(report.Summary);
        Assert.Equal(1, report.Summary.FlappingCount);
        Assert.True(report.Summary.RunsAnalyzed >= 3);
        Assert.NotEqual("N/A", report.Summary.StabilityGrade);
    }

    [Fact]
    public void FormatReport_NoData_ReturnsMessage()
    {
        var report = new FlappingReport { HasData = false };
        var text = FlappingDetector.FormatReport(report);
        Assert.Contains("Not enough", text);
    }

    [Fact]
    public void FormatReport_WithData_ContainsHeader()
    {
        var report = new FlappingReport
        {
            HasData = true,
            Summary = new FlappingSummary
            {
                TotalFindings = 5,
                FlappingCount = 2,
                RunsAnalyzed = 10,
                StabilityGrade = "B"
            },
            Findings =
            [
                new FlappingFinding
                {
                    Title = "Test Finding",
                    ModuleName = "Test",
                    Severity = "Warning",
                    Transitions = 5,
                    PresentCount = 5,
                    AbsentCount = 5,
                    TotalRuns = 10,
                    Pattern = "█░█░█░█░█░"
                }
            ]
        };

        var text = FlappingDetector.FormatReport(report);
        Assert.Contains("Flapping Detection", text);
        Assert.Contains("Test Finding", text);
    }
}
