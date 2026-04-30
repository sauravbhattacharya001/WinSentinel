using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class PostureMomentumAnalyzerTests
{
    private static AuditHistoryService MakeHistory() => new();

    private static SecurityReport MakeReport(int criticals = 2, int warnings = 5)
    {
        var report = new SecurityReport();
        // Set the basic report properties
        for (int i = 0; i < criticals; i++)
        {
            report.Results.Add(new AuditResult
            {
                ModuleName = $"Module{i}",
                Category = "Security",
                Findings = [new Finding
                {
                    Title = $"Critical Finding {i}",
                    Description = "Test critical",
                    Category = "Security",
                    Severity = Severity.Critical
                }]
            });
        }
        for (int i = 0; i < warnings; i++)
        {
            report.Results.Add(new AuditResult
            {
                ModuleName = $"WarnModule{i}",
                Category = "Config",
                Findings = [new Finding
                {
                    Title = $"Warning Finding {i}",
                    Description = "Test warning",
                    Category = "Config",
                    Severity = Severity.Warning
                }]
            });
        }
        return report;
    }

    [Fact]
    public void Analyze_InsufficientData_ReturnsCorrectPhase()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(new SecurityReport(), historyDays: 7);

        Assert.Equal(MomentumPhase.InsufficientData, report.Phase);
        Assert.Contains("Need at least", report.Summary);
    }

    [Fact]
    public void Analyze_BasicReport_ReturnsValidReport()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(MakeReport(), historyDays: 30);

        Assert.NotNull(report);
        Assert.True(report.AnalyzedDays > 0);
        Assert.NotNull(report.Summary);
        Assert.NotNull(report.Kinematics);
    }

    [Fact]
    public void Analyze_SetsAnalyzedAt()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var before = DateTimeOffset.UtcNow;
        var report = analyzer.Analyze(MakeReport(), historyDays: 30);

        Assert.True(report.AnalyzedAt >= before);
    }

    [Fact]
    public void MomentumScore_InRange()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(MakeReport(), historyDays: 30);

        Assert.InRange(report.MomentumScore, 0, 100);
    }

    [Fact]
    public void Kinematics_PositionMatchesCurrentScore()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var secReport = MakeReport();
        var report = analyzer.Analyze(secReport, historyDays: 30);

        // Position should be the current security score
        if (report.Phase != MomentumPhase.InsufficientData)
        {
            Assert.Equal(secReport.SecurityScore, report.Kinematics.Position);
        }
    }

    [Fact]
    public void Patterns_ListIsNotNull()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(MakeReport(), historyDays: 30);

        Assert.NotNull(report.Patterns);
    }

    [Fact]
    public void ModuleMomentum_ListIsNotNull()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(MakeReport(), historyDays: 30);

        Assert.NotNull(report.ModuleMomentum);
    }

    [Fact]
    public void Interventions_ListIsNotNull()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(MakeReport(), historyDays: 30);

        Assert.NotNull(report.Interventions);
    }

    [Fact]
    public void Phase_AllValuesAreDefined()
    {
        // Verify all enum values are valid
        foreach (MomentumPhase phase in Enum.GetValues<MomentumPhase>())
        {
            Assert.True(Enum.IsDefined(phase));
        }
    }

    [Fact]
    public void KinematicState_DefaultsAreZero()
    {
        var state = new KinematicState();
        Assert.Equal(0, state.Position);
        Assert.Equal(0.0, state.Velocity);
        Assert.Equal(0.0, state.Acceleration);
        Assert.Equal(0.0, state.Jerk);
        Assert.Equal(0.0, state.Variance);
    }

    [Fact]
    public void MomentumPattern_HasRequiredFields()
    {
        var pattern = new MomentumPattern
        {
            Name = "Test",
            Description = "A test pattern",
            Severity = "High",
            Occurrences = 3,
            Emoji = "🔥"
        };

        Assert.Equal("Test", pattern.Name);
        Assert.Equal("High", pattern.Severity);
        Assert.Equal(3, pattern.Occurrences);
    }

    [Fact]
    public void MomentumIntervention_HasSteps()
    {
        var intervention = new MomentumIntervention
        {
            Priority = "Critical",
            Action = "Emergency Review",
            Rationale = "Things are bad",
            Steps = ["Step 1", "Step 2"],
            ExpectedImpact = "Fix things"
        };

        Assert.Equal(2, intervention.Steps.Count);
        Assert.Equal("Critical", intervention.Priority);
    }

    [Fact]
    public void ModuleMomentumInfo_DefaultDirection()
    {
        var info = new ModuleMomentumInfo();
        Assert.Equal("", info.ModuleName);
        Assert.Equal("", info.Direction);
        Assert.Equal(0, info.CurrentScore);
    }

    [Fact]
    public void MomentumReport_DefaultPhaseIsInsufficientData()
    {
        var report = new MomentumReport();
        Assert.Equal(MomentumPhase.InsufficientData, report.Phase);
        Assert.Empty(report.Patterns);
        Assert.Empty(report.ModuleMomentum);
        Assert.Empty(report.Interventions);
    }

    [Fact]
    public void Analyze_HistoryDays_Respected()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(MakeReport(), historyDays: 180);

        Assert.Equal(180, report.AnalyzedDays);
    }

    [Fact]
    public void PostureDataPoint_HasTimestamp()
    {
        var point = new PostureDataPoint
        {
            Timestamp = DateTimeOffset.UtcNow,
            Score = 85,
            CriticalCount = 1,
            WarningCount = 3,
            TotalFindings = 10
        };

        Assert.Equal(85, point.Score);
        Assert.Equal(1, point.CriticalCount);
    }

    [Fact]
    public void Summary_IsNeverNull()
    {
        var analyzer = new PostureMomentumAnalyzer(MakeHistory());
        var report = analyzer.Analyze(MakeReport(), historyDays: 30);

        Assert.NotNull(report.Summary);
        Assert.NotEmpty(report.Summary);
    }
}
