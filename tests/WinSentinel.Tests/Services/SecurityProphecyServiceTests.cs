using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityProphecyServiceTests : IDisposable
{
    private readonly string _dbPath;
    private readonly AuditHistoryService _history;
    private readonly SecurityProphecyService _svc;

    public SecurityProphecyServiceTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"winsentinel_prophecy_test_{Guid.NewGuid():N}.db");
        _history = new AuditHistoryService(_dbPath);
        _svc = new SecurityProphecyService(_history);
    }

    public void Dispose()
    {
        _history.Dispose();
        if (File.Exists(_dbPath))
        {
            try { File.Delete(_dbPath); } catch { }
        }
    }

    // ── Helper: build SecurityReport with configurable findings ──

    private SecurityReport CreateReport(DateTimeOffset timestamp, int score, params (string module, string title, string severity)[] findings)
    {
        var report = new SecurityReport
        {
            GeneratedAt = timestamp,
            SecurityScore = score
        };

        var grouped = findings.GroupBy(f => f.module);
        foreach (var grp in grouped)
        {
            var findingList = grp.Select(f => f.severity switch
            {
                "Critical" => Finding.Critical(f.title, $"{f.title} description", f.module),
                "Warning" => Finding.Warning(f.title, $"{f.title} description", f.module, "Fix it"),
                "Info" => Finding.Info(f.title, $"{f.title} description", f.module),
                _ => Finding.Pass(f.title, $"{f.title} description", f.module)
            }).ToList();

            report.Results.Add(new AuditResult
            {
                ModuleName = grp.Key,
                Category = grp.Key,
                Findings = findingList,
                Success = true,
                StartTime = timestamp.AddSeconds(-3),
                EndTime = timestamp
            });
        }

        return report;
    }

    private void SeedHistoryWithRisingThreat(int runCount = 10)
    {
        // Simulate a rising firewall threat over time
        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < runCount; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();

            // Firewall issues increase over time
            var firewallCount = i < runCount / 3 ? 1 : (i < runCount * 2 / 3 ? 2 : 4);
            for (int f = 0; f < firewallCount; f++)
                findings.Add(("Firewall Audit", $"Firewall Issue {f + 1}", "Critical"));

            // Network issues stay constant
            findings.Add(("Network Audit", "Open Port 445", "Warning"));

            _history.SaveAuditResult(CreateReport(ts, 85 - firewallCount * 5, findings.ToArray()));
        }
    }

    private void SeedHistoryWithFadingThreat(int runCount = 10)
    {
        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < runCount; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();

            // Update issues decrease over time
            var updateCount = i < runCount / 3 ? 4 : (i < runCount * 2 / 3 ? 2 : 0);
            for (int f = 0; f < updateCount; f++)
                findings.Add(("Update Audit", $"Missing Update {f + 1}", "Warning"));

            // Encryption issues stay constant
            findings.Add(("Encryption Audit", "BitLocker not enabled", "Critical"));

            _history.SaveAuditResult(CreateReport(ts, 70 + (4 - updateCount) * 5, findings.ToArray()));
        }
    }

    private void SeedHistoryWithDormantThreat(int runCount = 10)
    {
        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < runCount; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();

            // USB issues only in older runs (first half)
            if (i < runCount / 2)
            {
                findings.Add(("USB Audit", "Unauthorized USB device", "Critical"));
                findings.Add(("USB Audit", "AutoRun enabled", "Warning"));
            }

            // Always have some baseline finding
            findings.Add(("Defender Audit", "Definitions outdated", "Info"));

            _history.SaveAuditResult(CreateReport(ts, 80, findings.ToArray()));
        }
    }

    // ── Basic Prediction Behavior ──────────────────────────────────

    [Fact]
    public void Predict_WithNoHistory_ReturnsEmptyReport()
    {
        var report = CreateReport(DateTimeOffset.UtcNow, 85, ("Firewall Audit", "Open port", "Warning"));
        var prophecy = _svc.Predict(report);

        Assert.NotNull(prophecy);
        Assert.Equal(0, prophecy.AnalyzedRuns);
        Assert.Empty(prophecy.RisingThreats);
        Assert.Empty(prophecy.FadingThreats);
        Assert.Empty(prophecy.DormantThreats);
        Assert.Empty(prophecy.Prophecies);
        Assert.Empty(prophecy.Recommendations);
    }

    [Fact]
    public void Predict_WithTooFewRuns_ReturnsEmptyReport()
    {
        // Only 2 runs — need at least 3
        var ts = DateTimeOffset.UtcNow.AddDays(-10);
        _history.SaveAuditResult(CreateReport(ts, 80, ("Firewall Audit", "Issue 1", "Warning")));
        _history.SaveAuditResult(CreateReport(ts.AddDays(5), 82, ("Firewall Audit", "Issue 1", "Warning")));

        var report = CreateReport(DateTimeOffset.UtcNow, 85);
        var prophecy = _svc.Predict(report);

        Assert.Equal(2, prophecy.AnalyzedRuns);
        Assert.Empty(prophecy.RisingThreats);
        Assert.Empty(prophecy.FadingThreats);
    }

    [Fact]
    public void Predict_WithThreeRuns_ProducesValidReport()
    {
        var ts = DateTimeOffset.UtcNow.AddDays(-20);
        _history.SaveAuditResult(CreateReport(ts, 80, ("Firewall Audit", "Issue 1", "Warning")));
        _history.SaveAuditResult(CreateReport(ts.AddDays(7), 75, ("Firewall Audit", "Issue 1", "Warning"), ("Firewall Audit", "Issue 2", "Critical")));
        _history.SaveAuditResult(CreateReport(ts.AddDays(14), 70, ("Firewall Audit", "Issue 1", "Warning"), ("Firewall Audit", "Issue 2", "Critical"), ("Firewall Audit", "Issue 3", "Critical")));

        var report = CreateReport(DateTimeOffset.UtcNow, 70);
        var prophecy = _svc.Predict(report);

        Assert.Equal(3, prophecy.AnalyzedRuns);
        Assert.True(prophecy.ForecastDays > 0);
    }

    [Fact]
    public void Predict_UsesCorrectForecastDays()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy7 = _svc.Predict(report, forecastDays: 7);
        var prophecy60 = _svc.Predict(report, forecastDays: 60);

        Assert.Equal(7, prophecy7.ForecastDays);
        Assert.Equal(60, prophecy60.ForecastDays);
    }

    [Fact]
    public void Predict_RespectsHistoryDaysParameter()
    {
        // Seed 10 runs over 60 days
        SeedHistoryWithRisingThreat(10);

        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        // With 90-day window, should see all runs
        var prophecyFull = _svc.Predict(report, historyDays: 90);
        // With 20-day window, should see fewer runs
        var prophecyShort = _svc.Predict(report, historyDays: 20);

        Assert.True(prophecyFull.AnalyzedRuns >= prophecyShort.AnalyzedRuns);
    }

    // ── Rising Threat Detection ─────────────────────────────────────

    [Fact]
    public void Predict_DetectsRisingThreats()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        Assert.NotEmpty(prophecy.RisingThreats);
        var rising = prophecy.RisingThreats.First();
        Assert.True(rising.Momentum > 0);
    }

    [Fact]
    public void Predict_RisingThreats_HavePositiveMomentum()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        foreach (var threat in prophecy.RisingThreats)
        {
            Assert.True(threat.Momentum > 0.1, $"Rising threat '{threat.Category}' should have momentum > 0.1, got {threat.Momentum}");
        }
    }

    [Fact]
    public void Predict_RisingThreats_OrderedByMomentumDescending()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        if (prophecy.RisingThreats.Count > 1)
        {
            for (int i = 0; i < prophecy.RisingThreats.Count - 1; i++)
            {
                Assert.True(prophecy.RisingThreats[i].Momentum >= prophecy.RisingThreats[i + 1].Momentum);
            }
        }
    }

    [Fact]
    public void Predict_RisingThreats_HaveValidProperties()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        foreach (var threat in prophecy.RisingThreats)
        {
            Assert.NotEmpty(threat.Category);
            Assert.NotEmpty(threat.Module);
            Assert.NotEmpty(threat.Description);
            Assert.NotEmpty(threat.Severity);
            Assert.NotEmpty(threat.Confidence);
            Assert.Contains(threat.Severity, new[] { "Critical", "Warning", "Info" });
            Assert.Contains(threat.Confidence, new[] { "High", "Medium", "Low" });
        }
    }

    [Fact]
    public void Predict_RisingThreats_SeverityWeightAmplifiesMomentum()
    {
        // Critical findings should produce higher momentum than Info findings
        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < 10; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();

            // Critical issues increase
            var critCount = i < 3 ? 0 : i - 2;
            for (int f = 0; f < critCount; f++)
                findings.Add(("Critical Module", $"Critical Issue {f}", "Critical"));

            // Info issues also increase at same rate
            for (int f = 0; f < critCount; f++)
                findings.Add(("Info Module", $"Info Issue {f}", "Info"));

            if (findings.Count == 0)
                findings.Add(("Baseline", "Baseline finding", "Info"));

            _history.SaveAuditResult(CreateReport(ts, 80, findings.ToArray()));
        }

        var report = CreateReport(DateTimeOffset.UtcNow, 70);
        var prophecy = _svc.Predict(report);

        var criticalRising = prophecy.RisingThreats.FirstOrDefault(t => t.Module == "Critical Module");
        var infoRising = prophecy.RisingThreats.FirstOrDefault(t => t.Module == "Info Module");

        if (criticalRising != null && infoRising != null)
        {
            Assert.True(criticalRising.Momentum > infoRising.Momentum,
                $"Critical momentum ({criticalRising.Momentum}) should exceed Info momentum ({infoRising.Momentum})");
        }
    }

    // ── Fading Threat Detection ─────────────────────────────────────

    [Fact]
    public void Predict_DetectsFadingThreats()
    {
        SeedHistoryWithFadingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 85);

        var prophecy = _svc.Predict(report);

        Assert.NotEmpty(prophecy.FadingThreats);
        var fading = prophecy.FadingThreats.First();
        Assert.True(fading.Momentum < -0.1);
    }

    [Fact]
    public void Predict_FadingThreats_HaveNegativeMomentum()
    {
        SeedHistoryWithFadingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 85);

        var prophecy = _svc.Predict(report);

        foreach (var threat in prophecy.FadingThreats)
        {
            Assert.True(threat.Momentum < -0.1, $"Fading threat '{threat.Category}' should have momentum < -0.1, got {threat.Momentum}");
        }
    }

    [Fact]
    public void Predict_FadingThreats_OrderedByMomentumAscending()
    {
        SeedHistoryWithFadingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 85);

        var prophecy = _svc.Predict(report);

        if (prophecy.FadingThreats.Count > 1)
        {
            for (int i = 0; i < prophecy.FadingThreats.Count - 1; i++)
            {
                Assert.True(prophecy.FadingThreats[i].Momentum <= prophecy.FadingThreats[i + 1].Momentum);
            }
        }
    }

    // ── Dormant Threat Detection ────────────────────────────────────

    [Fact]
    public void Predict_DetectsDormantThreats()
    {
        SeedHistoryWithDormantThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 80);

        var prophecy = _svc.Predict(report);

        Assert.NotEmpty(prophecy.DormantThreats);
    }

    [Fact]
    public void Predict_DormantThreats_HaveRecurrenceProbability()
    {
        SeedHistoryWithDormantThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 80);

        var prophecy = _svc.Predict(report);

        foreach (var dormant in prophecy.DormantThreats)
        {
            Assert.True(dormant.RecurrenceProbability > 0.2,
                $"Dormant threat '{dormant.Category}' should have recurrence > 0.2, got {dormant.RecurrenceProbability}");
            Assert.True(dormant.RecurrenceProbability <= 1.0);
        }
    }

    [Fact]
    public void Predict_DormantThreats_OrderedByRecurrenceDescending()
    {
        SeedHistoryWithDormantThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 80);

        var prophecy = _svc.Predict(report);

        if (prophecy.DormantThreats.Count > 1)
        {
            for (int i = 0; i < prophecy.DormantThreats.Count - 1; i++)
            {
                Assert.True(prophecy.DormantThreats[i].RecurrenceProbability >= prophecy.DormantThreats[i + 1].RecurrenceProbability);
            }
        }
    }

    [Fact]
    public void Predict_DormantThreats_WerePresentInOlderRunsButAbsentRecently()
    {
        SeedHistoryWithDormantThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 80);

        var prophecy = _svc.Predict(report);

        foreach (var dormant in prophecy.DormantThreats)
        {
            Assert.True(dormant.OccurrencesOlder > 0, $"Dormant '{dormant.Category}' should have older occurrences");
            Assert.Equal(0, dormant.OccurrencesRecent);
        }
    }

    // ── Storm Probability & Outlook ─────────────────────────────────

    [Fact]
    public void Predict_StormProbability_IsBetween0And100()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        Assert.InRange(prophecy.StormProbability, 0, 100);
    }

    [Fact]
    public void Predict_StormProbability_HigherWithRisingThreats()
    {
        // Heavily rising scenario
        SeedHistoryWithRisingThreat(10);
        var report = CreateReport(DateTimeOffset.UtcNow, 60);
        var risingProphecy = _svc.Predict(report);

        // Reset for fading scenario
        _history.Dispose();
        var fadingDbPath = Path.Combine(Path.GetTempPath(), $"winsentinel_prophecy_fading_{Guid.NewGuid():N}.db");
        using var fadingHistory = new AuditHistoryService(fadingDbPath);
        var fadingSvc = new SecurityProphecyService(fadingHistory);

        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < 10; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();
            var count = i < 3 ? 5 : (i < 7 ? 2 : 0);
            for (int f = 0; f < count; f++)
                findings.Add(("Fading Module", $"Issue {f}", "Warning"));
            if (findings.Count == 0)
                findings.Add(("Baseline", "Pass", "Pass"));
            fadingHistory.SaveAuditResult(CreateReport(ts, 85, findings.ToArray()));
        }

        var fadingProphecy = fadingSvc.Predict(report);

        Assert.True(risingProphecy.StormProbability >= fadingProphecy.StormProbability,
            $"Rising storm ({risingProphecy.StormProbability}) should be >= fading storm ({fadingProphecy.StormProbability})");

        try { File.Delete(fadingDbPath); } catch { }
    }

    [Fact]
    public void Predict_Outlook_IsValidCategory()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        Assert.Contains(prophecy.Outlook, new[] { "Clearing", "Stable", "Gathering", "Stormy", "Critical" });
    }

    [Fact]
    public void Predict_Outlook_MatchesStormProbability()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        var expectedOutlook = prophecy.StormProbability switch
        {
            <= 15 => "Clearing",
            <= 35 => "Stable",
            <= 55 => "Gathering",
            <= 80 => "Stormy",
            _ => "Critical"
        };

        Assert.Equal(expectedOutlook, prophecy.Outlook);
    }

    // ── Prophecy Text Generation ────────────────────────────────────

    [Fact]
    public void Predict_GeneratesProphecyStrings()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        Assert.NotEmpty(prophecy.Prophecies);
        foreach (var text in prophecy.Prophecies)
        {
            Assert.NotNull(text);
            Assert.NotEmpty(text);
            Assert.True(text.Length > 10, "Prophecy text should be a real sentence");
        }
    }

    [Fact]
    public void Predict_PropheciesReferenceRisingThreats()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        // At least one prophecy should mention "accelerating" for rising threats
        var hasAccelerating = prophecy.Prophecies.Any(p => p.Contains("accelerating"));
        Assert.True(hasAccelerating, "Should have prophecy about accelerating threats");
    }

    [Fact]
    public void Predict_PropheciesReferDormantThreats()
    {
        SeedHistoryWithDormantThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 80);

        var prophecy = _svc.Predict(report);

        // Should mention recurrence for dormant threats
        var hasRecurrence = prophecy.Prophecies.Any(p => p.Contains("recur"));
        Assert.True(hasRecurrence, "Should have prophecy about recurring dormant threats");
    }

    [Fact]
    public void Predict_PropheciesLimitedToTop3Rising()
    {
        // Create many different rising threats
        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < 10; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();
            var count = i < 3 ? 0 : i;
            for (int m = 0; m < 5; m++)
            {
                for (int f = 0; f < count; f++)
                    findings.Add(($"Module{m}", $"Issue {f}", "Warning"));
            }
            if (findings.Count == 0) findings.Add(("Baseline", "Pass", "Pass"));
            _history.SaveAuditResult(CreateReport(ts, 80, findings.ToArray()));
        }

        var report = CreateReport(DateTimeOffset.UtcNow, 60);
        var prophecy = _svc.Predict(report);

        // "accelerating" prophecies limited to top 3
        var acceleratingCount = prophecy.Prophecies.Count(p => p.Contains("accelerating"));
        Assert.True(acceleratingCount <= 3);
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Predict_GeneratesRecommendations()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        Assert.NotEmpty(prophecy.Recommendations);
        foreach (var rec in prophecy.Recommendations)
        {
            Assert.NotNull(rec);
            Assert.NotEmpty(rec);
        }
    }

    [Fact]
    public void Predict_RecommendationsPrioritizeRisingModules()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        // Should recommend prioritizing the rising module
        var hasPrioritize = prophecy.Recommendations.Any(r => r.Contains("Prioritize") || r.Contains("trending upward"));
        Assert.True(hasPrioritize, "Should recommend prioritizing rising modules");
    }

    [Fact]
    public void Predict_RecommendationsMonitorDormantThreats()
    {
        SeedHistoryWithDormantThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 80);

        var prophecy = _svc.Predict(report);

        // Should recommend monitoring dormant threats
        var hasMonitor = prophecy.Recommendations.Any(r => r.Contains("monitoring") || r.Contains("recur"));
        Assert.True(hasMonitor, "Should recommend monitoring dormant threats");
    }

    [Fact]
    public void Predict_HighStorm_RecommendsIncreasedFrequency()
    {
        // Create a heavily deteriorating scenario
        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < 10; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();
            var count = i * 3; // Rapidly growing
            for (int f = 0; f < count; f++)
                findings.Add(("Critical Module", $"Critical Issue {f}", "Critical"));
            if (findings.Count == 0) findings.Add(("Baseline", "OK", "Pass"));
            _history.SaveAuditResult(CreateReport(ts, 90 - count * 2, findings.ToArray()));
        }

        var report = CreateReport(DateTimeOffset.UtcNow, 30);
        var prophecy = _svc.Predict(report);

        if (prophecy.StormProbability > 50)
        {
            var hasFrequency = prophecy.Recommendations.Any(r => r.Contains("audit frequency"));
            Assert.True(hasFrequency, "High storm probability should recommend increased audit frequency");
        }
    }

    // ── Module Momentum ─────────────────────────────────────────────

    [Fact]
    public void Predict_CalculatesModuleMomentum()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        Assert.NotEmpty(prophecy.ModuleMomentum);
    }

    [Fact]
    public void Predict_ModuleMomentum_ReflectsIncreasingFindings()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        // Firewall Audit should have positive module momentum (finding count increased)
        if (prophecy.ModuleMomentum.TryGetValue("Firewall Audit", out var firewallMomentum))
        {
            Assert.True(firewallMomentum > 0,
                $"Firewall Audit module momentum should be positive, got {firewallMomentum}");
        }
    }

    [Fact]
    public void Predict_ModuleMomentum_ValuesAreRounded()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        foreach (var (_, momentum) in prophecy.ModuleMomentum)
        {
            // Rounded to 2 decimal places
            Assert.Equal(momentum, Math.Round(momentum, 2));
        }
    }

    // ── Confidence Levels ───────────────────────────────────────────

    [Fact]
    public void Predict_Confidence_LowWithFewRuns()
    {
        // Exactly 3 runs
        var ts = DateTimeOffset.UtcNow.AddDays(-20);
        _history.SaveAuditResult(CreateReport(ts, 80, ("Firewall Audit", "Issue", "Warning")));
        _history.SaveAuditResult(CreateReport(ts.AddDays(7), 75, ("Firewall Audit", "Issue", "Warning"), ("Firewall Audit", "Issue 2", "Critical")));
        _history.SaveAuditResult(CreateReport(ts.AddDays(14), 70, ("Firewall Audit", "Issue", "Warning"), ("Firewall Audit", "Issue 2", "Critical"), ("Firewall Audit", "Issue 3", "Critical")));

        var report = CreateReport(DateTimeOffset.UtcNow, 70);
        var prophecy = _svc.Predict(report);

        // With only 3 runs, confidence should be Low
        foreach (var threat in prophecy.RisingThreats.Concat(prophecy.FadingThreats).Concat(prophecy.DormantThreats))
        {
            Assert.Equal("Low", threat.Confidence);
        }
    }

    [Fact]
    public void Predict_Confidence_MediumWith5To9Runs()
    {
        // Exactly 6 runs
        var baseTime = DateTimeOffset.UtcNow.AddDays(-30);
        for (int i = 0; i < 6; i++)
        {
            var ts = baseTime.AddDays(i * 4);
            var count = i < 2 ? 1 : 3;
            var findings = new List<(string, string, string)>();
            for (int f = 0; f < count; f++)
                findings.Add(("Rising Module", $"Issue {f}", "Critical"));
            _history.SaveAuditResult(CreateReport(ts, 80, findings.ToArray()));
        }

        var report = CreateReport(DateTimeOffset.UtcNow, 70);
        var prophecy = _svc.Predict(report);

        foreach (var threat in prophecy.RisingThreats.Concat(prophecy.FadingThreats).Concat(prophecy.DormantThreats))
        {
            Assert.Equal("Medium", threat.Confidence);
        }
    }

    [Fact]
    public void Predict_Confidence_HighWith10PlusRuns()
    {
        SeedHistoryWithRisingThreat(10);
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        foreach (var threat in prophecy.RisingThreats.Concat(prophecy.FadingThreats).Concat(prophecy.DormantThreats))
        {
            Assert.Equal("High", threat.Confidence);
        }
    }

    // ── Occurrence Counts ────────────────────────────────────────────

    [Fact]
    public void Predict_RisingThreats_TrackRecentAndOlderOccurrences()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report);

        foreach (var threat in prophecy.RisingThreats)
        {
            // Rising threats should have more recent occurrences than older
            Assert.True(threat.OccurrencesRecent > 0 || threat.OccurrencesOlder > 0,
                $"Threat '{threat.Category}' should have some occurrences");
        }
    }

    // ── Edge Cases ───────────────────────────────────────────────────

    [Fact]
    public void Predict_AllRunsIdentical_NoRisingOrFading()
    {
        // All 5 runs have the exact same findings — no momentum
        var baseTime = DateTimeOffset.UtcNow.AddDays(-30);
        for (int i = 0; i < 5; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            _history.SaveAuditResult(CreateReport(ts, 80,
                ("Firewall Audit", "Open port 80", "Warning"),
                ("Update Audit", "Missing KB", "Warning")));
        }

        var report = CreateReport(DateTimeOffset.UtcNow, 80);
        var prophecy = _svc.Predict(report);

        // No significant momentum when everything is stable
        Assert.Empty(prophecy.RisingThreats);
        Assert.Empty(prophecy.FadingThreats);
    }

    [Fact]
    public void Predict_MixedScenario_DetectsAllThreeCategories()
    {
        var baseTime = DateTimeOffset.UtcNow.AddDays(-60);
        for (int i = 0; i < 10; i++)
        {
            var ts = baseTime.AddDays(i * 5);
            var findings = new List<(string, string, string)>();

            // Rising: firewall issues increase
            var firewallCount = i < 3 ? 1 : 4;
            for (int f = 0; f < firewallCount; f++)
                findings.Add(("Firewall Audit", $"FW Issue {f}", "Critical"));

            // Fading: update issues decrease
            var updateCount = i < 3 ? 4 : (i < 7 ? 2 : 0);
            for (int f = 0; f < updateCount; f++)
                findings.Add(("Update Audit", $"Update Issue {f}", "Warning"));

            // Dormant: USB only in first half
            if (i < 5)
                findings.Add(("USB Audit", "USB device found", "Critical"));

            _history.SaveAuditResult(CreateReport(ts, 70, findings.ToArray()));
        }

        var report = CreateReport(DateTimeOffset.UtcNow, 60);
        var prophecy = _svc.Predict(report);

        Assert.NotEmpty(prophecy.RisingThreats);
        Assert.NotEmpty(prophecy.FadingThreats);
        Assert.NotEmpty(prophecy.DormantThreats);
    }

    [Fact]
    public void Predict_Idempotent_SameInputSameOutput()
    {
        SeedHistoryWithRisingThreat();
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy1 = _svc.Predict(report);
        var prophecy2 = _svc.Predict(report);

        Assert.Equal(prophecy1.StormProbability, prophecy2.StormProbability);
        Assert.Equal(prophecy1.Outlook, prophecy2.Outlook);
        Assert.Equal(prophecy1.RisingThreats.Count, prophecy2.RisingThreats.Count);
        Assert.Equal(prophecy1.FadingThreats.Count, prophecy2.FadingThreats.Count);
        Assert.Equal(prophecy1.DormantThreats.Count, prophecy2.DormantThreats.Count);
    }

    [Fact]
    public void Predict_AnalyzedRunsCount_MatchesActualHistory()
    {
        SeedHistoryWithRisingThreat(8);
        var report = CreateReport(DateTimeOffset.UtcNow, 65);

        var prophecy = _svc.Predict(report, historyDays: 90);

        Assert.Equal(8, prophecy.AnalyzedRuns);
    }
}