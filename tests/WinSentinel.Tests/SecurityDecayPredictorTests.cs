using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class SecurityDecayPredictorTests
{
    private static SecurityReport MakeReport(params (string title, Severity severity, string category, int ageDays)[] findings)
    {
        var report = new SecurityReport();
        var now = DateTimeOffset.UtcNow;
        foreach (var (title, severity, category, ageDays) in findings)
        {
            report.Results.Add(new AuditResult
            {
                ModuleName = $"{category}Module",
                Category = category,
                Findings =
                [
                    new Finding
                    {
                        Title = title,
                        Description = $"Test finding: {title}",
                        Category = category,
                        Severity = severity,
                        Timestamp = now.AddDays(-ageDays)
                    }
                ]
            });
        }
        return report;
    }

    [Fact]
    public void Predict_EmptyReport_ReturnsHealthy()
    {
        var predictor = new SecurityDecayPredictor();
        var report = predictor.Predict(new SecurityReport());

        Assert.Equal(100, report.HealthScore);
        Assert.Equal(0, report.TotalFindings);
        Assert.Empty(report.Predictions);
    }

    [Fact]
    public void Predict_PassFindings_AreExcluded()
    {
        var report = new SecurityReport();
        report.Results.Add(new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Security",
            Findings =
            [
                new Finding { Title = "Good config", Description = "OK", Category = "Security", Severity = Severity.Pass }
            ]
        });

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(100, result.HealthScore);
    }

    [Fact]
    public void Predict_CriticalFinding_NoEscalation()
    {
        var report = MakeReport(("Critical issue", Severity.Critical, "Firewall", 30));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Single(result.Predictions);
        var p = result.Predictions[0];
        Assert.Equal(Severity.Critical, p.CurrentSeverity);
        Assert.Equal(Severity.Critical, p.PredictedNextSeverity);
        Assert.Equal(DecayTrajectory.Stable, p.Trajectory);
        Assert.Equal(-1, p.DaysToEscalation); // No escalation possible
    }

    [Fact]
    public void Predict_NewWarning_HasTimeBeforeEscalation()
    {
        var report = MakeReport(("New warning", Severity.Warning, "Registry", 1));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Single(result.Predictions);
        var p = result.Predictions[0];
        Assert.Equal(Severity.Warning, p.CurrentSeverity);
        Assert.Equal(Severity.Critical, p.PredictedNextSeverity);
        Assert.True(p.DaysToEscalation > 0);
        Assert.Equal(DecayTrajectory.SlowDecay, p.Trajectory); // 1 day old, Registry (1.0x) = ~49 days to escalation
    }

    [Fact]
    public void Predict_OldWarning_HighExposure_EscalatesFaster()
    {
        // Credentials category has 2.0x multiplier
        var report = MakeReport(("Exposed creds", Severity.Warning, "Credentials", 20));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        var p = result.Predictions[0];
        Assert.Equal(2.0, p.ExposureMultiplier);
        // At day 20: pressure = 20 * 0.02 * 2.0 = 0.8, threshold = 1.0
        // Remaining = 0.2, daily = 0.04, days left = 5
        Assert.True(p.DaysToEscalation <= 10);
        Assert.True(p.Urgency >= DecayUrgency.High);
    }

    [Fact]
    public void Predict_VeryOldWarning_IsOverdue()
    {
        // Credentials: 50 days * 0.02 * 2.0 = 2.0 > 1.0 threshold
        var report = MakeReport(("Ancient credential issue", Severity.Warning, "Credentials", 50));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        var p = result.Predictions[0];
        Assert.Equal(DecayTrajectory.Overdue, p.Trajectory);
        Assert.Equal(DecayUrgency.Critical, p.Urgency);
        Assert.Equal(0, p.DaysToEscalation);
    }

    [Fact]
    public void Predict_InfoFinding_DecaysSlowly()
    {
        var report = MakeReport(("Info item", Severity.Info, "EventLog", 10));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        var p = result.Predictions[0];
        Assert.Equal(Severity.Info, p.CurrentSeverity);
        Assert.Equal(Severity.Warning, p.PredictedNextSeverity);
        // EventLog = 0.7x, Info rate = 0.005, day 10: pressure = 10*0.005*0.7 = 0.035
        // Very far from threshold
        Assert.True(p.DaysToEscalation > 100);
        Assert.Equal(DecayTrajectory.Stable, p.Trajectory);
    }

    [Fact]
    public void Predict_MultipleFindings_SortedByUrgency()
    {
        var report = MakeReport(
            ("Low priority info", Severity.Info, "Backup", 5),
            ("Old credential warning", Severity.Warning, "Credentials", 40),
            ("New network warning", Severity.Warning, "Network", 2),
            ("Stable critical", Severity.Critical, "Firewall", 10)
        );

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Equal(4, result.TotalFindings);
        // Most urgent should be first (old credential warning is overdue)
        Assert.Equal("Old credential warning", result.Predictions[0].FindingTitle);
        Assert.Equal(DecayUrgency.Critical, result.Predictions[0].Urgency);
    }

    [Fact]
    public void Predict_CategorySummaries_Generated()
    {
        var report = MakeReport(
            ("Issue 1", Severity.Warning, "Firewall", 10),
            ("Issue 2", Severity.Warning, "Firewall", 20),
            ("Issue 3", Severity.Warning, "Network", 5)
        );

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Equal(2, result.CategorySummaries.Count);
        Assert.Contains(result.CategorySummaries, c => c.Category == "Firewall" && c.FindingCount == 2);
        Assert.Contains(result.CategorySummaries, c => c.Category == "Network" && c.FindingCount == 1);
    }

    [Fact]
    public void Predict_HealthScore_DegradesWithUrgentFindings()
    {
        var report = MakeReport(
            ("Overdue 1", Severity.Warning, "Credentials", 60),
            ("Overdue 2", Severity.Warning, "RemoteAccess", 60),
            ("Overdue 3", Severity.Warning, "Credentials", 55)
        );

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.True(result.HealthScore < 60, $"Expected health < 60, got {result.HealthScore}");
        Assert.True(result.OverdueCount >= 2);
    }

    [Fact]
    public void Predict_Recommendations_IncludeOverdueAlert()
    {
        var report = MakeReport(("Overdue item", Severity.Warning, "Credentials", 100));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Contains(result.Recommendations, r => r.Contains("OVERDUE"));
    }

    [Fact]
    public void Predict_Recommendations_IncludeHighExposureWarning()
    {
        var report = MakeReport(
            ("Remote risk", Severity.Warning, "RemoteAccess", 15),
            ("Network risk", Severity.Warning, "Network", 20)
        );

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Contains(result.Recommendations, r => r.Contains("high-exposure") || r.Contains("escalation"));
    }

    [Fact]
    public void Predict_Summary_ContainsKeyMetrics()
    {
        var report = MakeReport(
            ("Item 1", Severity.Warning, "Firewall", 10),
            ("Item 2", Severity.Info, "DNS", 5)
        );

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Contains("2 findings", result.Summary);
        Assert.Contains("Health:", result.Summary);
    }

    [Fact]
    public void Predict_UnknownCategory_UsesDefaultMultiplier()
    {
        var report = MakeReport(("Unknown cat", Severity.Warning, "SomeNewCategory", 10));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        var p = result.Predictions[0];
        Assert.Equal(1.0, p.ExposureMultiplier);
    }

    [Fact]
    public void Predict_EmptyCategory_HandledGracefully()
    {
        var report = MakeReport(("No category", Severity.Warning, "", 10));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Single(result.Predictions);
        Assert.Equal(1.0, result.Predictions[0].ExposureMultiplier);
        Assert.Contains(result.CategorySummaries, c => c.Category == "Uncategorized");
    }

    [Fact]
    public void Predict_Confidence_IncreasesWithAge()
    {
        var report1 = MakeReport(("Young", Severity.Warning, "Firewall", 1));
        var report2 = MakeReport(("Old", Severity.Warning, "Firewall", 30));

        var predictor = new SecurityDecayPredictor();
        var result1 = predictor.Predict(report1);
        var result2 = predictor.Predict(report2);

        Assert.True(result2.Predictions[0].Confidence >= result1.Predictions[0].Confidence);
    }

    [Fact]
    public void Predict_EscalatingWithin7Days_Count()
    {
        // Network (1.7x), Warning (0.02 rate)
        // Threshold = 1.0, daily pressure = 0.034
        // Full time to escalate = 1.0 / 0.034 ≈ 29.4 days
        // At day 25: pressure = 25 * 0.034 = 0.85, remaining = 0.15/0.034 ≈ 4.4 days
        var report = MakeReport(("Almost escalated", Severity.Warning, "Network", 25));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Equal(1, result.EscalatingWithin7Days);
    }

    [Fact]
    public void Predict_DecayVelocity_CalculatedCorrectly()
    {
        var report = MakeReport(("Test", Severity.Warning, "Credentials", 5));

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        var p = result.Predictions[0];
        // Warning rate (0.02) * Credentials multiplier (2.0) = 0.04
        Assert.Equal(0.04, p.DecayVelocity);
    }

    [Fact]
    public void Predict_InterventionWindow_DescribesCorrectly()
    {
        var report = MakeReport(
            ("Overdue item", Severity.Warning, "Credentials", 100),
            ("Rapid item", Severity.Warning, "RemoteAccess", 22),
            ("Stable item", Severity.Info, "Backup", 2)
        );

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        var overdue = result.Predictions.First(p => p.FindingTitle == "Overdue item");
        Assert.Contains("immediate", overdue.InterventionWindow, StringComparison.OrdinalIgnoreCase);

        var stable = result.Predictions.First(p => p.FindingTitle == "Stable item");
        Assert.Contains("monitor", stable.InterventionWindow, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Predict_LargeReport_HandlesPerformance()
    {
        var findings = new List<(string, Severity, string, int)>();
        var categories = new[] { "Firewall", "Network", "Accounts", "Services", "Registry" };
        for (int i = 0; i < 100; i++)
        {
            findings.Add(($"Finding {i}", Severity.Warning, categories[i % categories.Length], i % 50));
        }

        var report = MakeReport(findings.ToArray());
        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        Assert.Equal(100, result.TotalFindings);
        Assert.True(result.CategorySummaries.Count <= 5);
        Assert.InRange(result.HealthScore, 0, 100);
    }

    [Fact]
    public void Predict_AllSeverities_HandledCorrectly()
    {
        var report = MakeReport(
            ("Pass check", Severity.Pass, "Security", 10),   // Should be excluded
            ("Info note", Severity.Info, "Config", 10),
            ("Warning item", Severity.Warning, "Network", 10),
            ("Critical alert", Severity.Critical, "Firewall", 10)
        );

        var predictor = new SecurityDecayPredictor();
        var result = predictor.Predict(report);

        // Pass is excluded
        Assert.Equal(3, result.TotalFindings);
    }
}
