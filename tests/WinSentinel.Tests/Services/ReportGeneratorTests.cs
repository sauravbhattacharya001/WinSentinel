using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ReportGeneratorTests
{
    private readonly ReportGenerator _generator = new();

    private static SecurityReport CreateTestReport(int criticals = 1, int warnings = 2, int infos = 1, int passes = 3)
    {
        var report = new SecurityReport
        {
            GeneratedAt = new DateTimeOffset(2026, 2, 15, 12, 0, 0, TimeSpan.Zero)
        };

        var result = new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall & Network Protection",
            StartTime = report.GeneratedAt,
            EndTime = report.GeneratedAt.AddSeconds(2)
        };

        for (int i = 0; i < criticals; i++)
            result.Findings.Add(Finding.Critical($"Critical Issue {i + 1}", $"Critical finding description {i + 1}", "Firewall",
                $"Fix critical issue {i + 1}", $"Set-NetFirewallProfile -Enabled True"));

        for (int i = 0; i < warnings; i++)
            result.Findings.Add(Finding.Warning($"Warning Issue {i + 1}", $"Warning finding description {i + 1}", "Firewall",
                $"Fix warning issue {i + 1}"));

        for (int i = 0; i < infos; i++)
            result.Findings.Add(Finding.Info($"Info Item {i + 1}", $"Informational finding {i + 1}", "Firewall"));

        for (int i = 0; i < passes; i++)
            result.Findings.Add(Finding.Pass($"Pass Check {i + 1}", $"Passed check {i + 1}", "Firewall"));

        report.Results.Add(result);

        // Add a second module
        var result2 = new AuditResult
        {
            ModuleName = "UpdateAudit",
            Category = "Windows Update",
            StartTime = report.GeneratedAt.AddSeconds(2),
            EndTime = report.GeneratedAt.AddSeconds(4)
        };
        result2.Findings.Add(Finding.Pass("Updates Current", "All updates installed", "Updates"));
        report.Results.Add(result2);

        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    private static ScoreTrendSummary CreateTestTrend()
    {
        return new ScoreTrendSummary
        {
            CurrentScore = 75,
            PreviousScore = 80,
            TotalScans = 5,
            AverageScore = 78.0,
            BestScore = 90,
            BestScoreDate = DateTimeOffset.UtcNow.AddDays(-3),
            BestScoreGrade = "A",
            WorstScore = 65,
            WorstScoreDate = DateTimeOffset.UtcNow.AddDays(-7),
            WorstScoreGrade = "D",
            Points =
            [
                new ScoreTrendPoint { Timestamp = DateTimeOffset.UtcNow.AddDays(-7), Score = 65, Grade = "D" },
                new ScoreTrendPoint { Timestamp = DateTimeOffset.UtcNow.AddDays(-5), Score = 70, Grade = "C" },
                new ScoreTrendPoint { Timestamp = DateTimeOffset.UtcNow.AddDays(-3), Score = 90, Grade = "A" },
                new ScoreTrendPoint { Timestamp = DateTimeOffset.UtcNow.AddDays(-1), Score = 80, Grade = "B" },
                new ScoreTrendPoint { Timestamp = DateTimeOffset.UtcNow, Score = 75, Grade = "C" },
            ]
        };
    }

    // ── HTML Report Tests ───────────────────────────────────────────

    [Fact]
    public void GenerateHtmlReport_ContainsDoctype()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.StartsWith("<!DOCTYPE html>", html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsTitle()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("<title>WinSentinel Security Report", html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsInlineCSS()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("<style>", html);
        Assert.Contains("background: #0d1117", html);
        // No external CSS links
        Assert.DoesNotContain("<link rel=\"stylesheet\"", html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsMachineName()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains(Environment.MachineName, html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsScore()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains(report.SecurityScore.ToString(), html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsGradeBadge()
    {
        var report = CreateTestReport();
        var grade = SecurityScorer.GetGrade(report.SecurityScore);
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains($"class=\"grade-badge\"", html);
        Assert.Contains(grade, html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsModuleBreakdown()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("Module Breakdown", html);
        Assert.Contains("Firewall &amp; Network Protection", html);
        Assert.Contains("Windows Update", html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsFindings()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("Critical Issue 1", html);
        Assert.Contains("Warning Issue 1", html);
        Assert.Contains("Detailed Findings", html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsRemediation()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("Fix critical issue 1", html);
        Assert.Contains("Remediation", html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsSeverityBadges()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("severity-badge critical", html);
        Assert.Contains("severity-badge warning", html);
    }

    [Fact]
    public void GenerateHtmlReport_ContainsFooter()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("<footer>", html);
        Assert.Contains("Generated by WinSentinel", html);
    }

    [Fact]
    public void GenerateHtmlReport_WithTrend_ContainsTrendSection()
    {
        var report = CreateTestReport();
        var trend = CreateTestTrend();
        var html = _generator.GenerateHtmlReport(report, trend);
        Assert.Contains("Score Trend", html);
        Assert.Contains("trend-chart", html);
        Assert.Contains("trend-bar", html);
    }

    [Fact]
    public void GenerateHtmlReport_WithoutTrend_NoTrendSection()
    {
        var report = CreateTestReport();
        var html = _generator.GenerateHtmlReport(report);
        // The trend section heading should not appear when no trend data
        Assert.DoesNotContain("class=\"trend-section\"", html);
        Assert.DoesNotContain("<div class=\"trend-row\">", html);
    }

    [Fact]
    public void GenerateHtmlReport_HtmlEncodesSpecialChars()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow
        };
        var result = new AuditResult
        {
            ModuleName = "Test<Module>",
            Category = "Test & \"Category\"",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow
        };
        result.Findings.Add(Finding.Warning("<script>alert(1)</script>", "XSS attempt & <b>bold</b>", "Test"));
        report.Results.Add(result);
        report.SecurityScore = SecurityScorer.CalculateScore(report);

        var html = _generator.GenerateHtmlReport(report);
        Assert.DoesNotContain("<script>alert(1)</script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("Test &amp; &quot;Category&quot;", html);
    }

    // ── JSON Report Tests ───────────────────────────────────────────

    [Fact]
    public void GenerateJsonReport_IsValidJson()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotNull(doc);
    }

    [Fact]
    public void GenerateJsonReport_ContainsRequiredFields()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("reportVersion", out _));
        Assert.True(root.TryGetProperty("generatedAt", out _));
        Assert.True(root.TryGetProperty("machineName", out _));
        Assert.True(root.TryGetProperty("overallScore", out _));
        Assert.True(root.TryGetProperty("grade", out _));
        Assert.True(root.TryGetProperty("summary", out _));
        Assert.True(root.TryGetProperty("modules", out _));
    }

    [Fact]
    public void GenerateJsonReport_CorrectScore()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.Equal(report.SecurityScore, doc.RootElement.GetProperty("overallScore").GetInt32());
    }

    [Fact]
    public void GenerateJsonReport_ContainsModules()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        var modules = doc.RootElement.GetProperty("modules");
        Assert.Equal(2, modules.GetArrayLength());
    }

    [Fact]
    public void GenerateJsonReport_ContainsFindings()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        var module0 = doc.RootElement.GetProperty("modules")[0];
        var findings = module0.GetProperty("findings");
        Assert.True(findings.GetArrayLength() > 0);
    }

    [Fact]
    public void GenerateJsonReport_ContainsFindingSeverity()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        Assert.Contains("\"severity\": \"Critical\"", json);
        Assert.Contains("\"severity\": \"Warning\"", json);
    }

    [Fact]
    public void GenerateJsonReport_ContainsMachineName()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        Assert.Contains(Environment.MachineName, json);
    }

    [Fact]
    public void GenerateJsonReport_WithTrend_ContainsTrendData()
    {
        var report = CreateTestReport();
        var trend = CreateTestTrend();
        var json = _generator.GenerateJsonReport(report, trend);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("trend", out var trendProp));
        Assert.Equal(5, trendProp.GetProperty("totalScans").GetInt32());
    }

    [Fact]
    public void GenerateJsonReport_WithoutTrend_NoTrendData()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        // trend should be null/absent
        if (doc.RootElement.TryGetProperty("trend", out var trendProp))
        {
            Assert.Equal(System.Text.Json.JsonValueKind.Null, trendProp.ValueKind);
        }
    }

    // ── Text Report Tests ───────────────────────────────────────────

    [Fact]
    public void GenerateTextReport_ContainsHeader()
    {
        var report = CreateTestReport();
        var text = _generator.GenerateTextReport(report);
        Assert.Contains("WinSentinel Security Report", text);
    }

    [Fact]
    public void GenerateTextReport_ContainsMachineName()
    {
        var report = CreateTestReport();
        var text = _generator.GenerateTextReport(report);
        Assert.Contains(Environment.MachineName, text);
    }

    [Fact]
    public void GenerateTextReport_ContainsScore()
    {
        var report = CreateTestReport();
        var text = _generator.GenerateTextReport(report);
        Assert.Contains($"{report.SecurityScore}/100", text);
    }

    [Fact]
    public void GenerateTextReport_ContainsModuleBreakdown()
    {
        var report = CreateTestReport();
        var text = _generator.GenerateTextReport(report);
        Assert.Contains("Module Breakdown", text);
        Assert.Contains("Firewall & Network Protection", text);
        Assert.Contains("Windows Update", text);
    }

    [Fact]
    public void GenerateTextReport_ContainsFindings()
    {
        var report = CreateTestReport();
        var text = _generator.GenerateTextReport(report);
        Assert.Contains("[CRITICAL]", text);
        Assert.Contains("[WARNING]", text);
        Assert.Contains("Critical Issue 1", text);
    }

    [Fact]
    public void GenerateTextReport_ContainsRemediation()
    {
        var report = CreateTestReport();
        var text = _generator.GenerateTextReport(report);
        Assert.Contains("Fix critical issue 1", text);
    }

    [Fact]
    public void GenerateTextReport_ContainsSummary()
    {
        var report = CreateTestReport();
        var text = _generator.GenerateTextReport(report);
        Assert.Contains("Summary", text);
        Assert.Contains("Critical:", text);
        Assert.Contains("Warnings:", text);
    }

    [Fact]
    public void GenerateTextReport_WithTrend_ContainsTrend()
    {
        var report = CreateTestReport();
        var trend = CreateTestTrend();
        var text = _generator.GenerateTextReport(report, trend);
        Assert.Contains("Score Trend", text);
        Assert.Contains("Best:", text);
        Assert.Contains("Worst:", text);
        Assert.Contains("Average:", text);
    }

    // ── SaveReport Tests ────────────────────────────────────────────

    [Fact]
    public void SaveReport_HtmlFormat_CreatesFile()
    {
        var report = CreateTestReport();
        var path = Path.Combine(Path.GetTempPath(), $"test-report-{Guid.NewGuid()}.html");

        try
        {
            _generator.SaveReport(path, report, ReportFormat.Html);
            Assert.True(File.Exists(path));
            var content = File.ReadAllText(path);
            Assert.Contains("<!DOCTYPE html>", content);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void SaveReport_JsonFormat_CreatesValidJson()
    {
        var report = CreateTestReport();
        var path = Path.Combine(Path.GetTempPath(), $"test-report-{Guid.NewGuid()}.json");

        try
        {
            _generator.SaveReport(path, report, ReportFormat.Json);
            Assert.True(File.Exists(path));
            var content = File.ReadAllText(path);
            var doc = System.Text.Json.JsonDocument.Parse(content);
            Assert.NotNull(doc);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void SaveReport_TextFormat_CreatesFile()
    {
        var report = CreateTestReport();
        var path = Path.Combine(Path.GetTempPath(), $"test-report-{Guid.NewGuid()}.txt");

        try
        {
            _generator.SaveReport(path, report, ReportFormat.Text);
            Assert.True(File.Exists(path));
            var content = File.ReadAllText(path);
            Assert.Contains("WinSentinel Security Report", content);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void SaveReport_CreatesDirectoryIfNeeded()
    {
        var report = CreateTestReport();
        var dir = Path.Combine(Path.GetTempPath(), $"winsentinel-test-{Guid.NewGuid()}");
        var path = Path.Combine(dir, "report.html");

        try
        {
            _generator.SaveReport(path, report, ReportFormat.Html);
            Assert.True(File.Exists(path));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    // ── GenerateFilename Tests ──────────────────────────────────────

    [Fact]
    public void GenerateFilename_HtmlFormat_CorrectExtension()
    {
        var filename = ReportGenerator.GenerateFilename(ReportFormat.Html);
        Assert.EndsWith(".html", filename);
        Assert.StartsWith("WinSentinel-Report-", filename);
    }

    [Fact]
    public void GenerateFilename_JsonFormat_CorrectExtension()
    {
        var filename = ReportGenerator.GenerateFilename(ReportFormat.Json);
        Assert.EndsWith(".json", filename);
    }

    [Fact]
    public void GenerateFilename_TextFormat_CorrectExtension()
    {
        var filename = ReportGenerator.GenerateFilename(ReportFormat.Text);
        Assert.EndsWith(".txt", filename);
    }

    [Fact]
    public void GenerateFilename_UsesProvidedTimestamp()
    {
        var ts = new DateTimeOffset(2026, 1, 15, 14, 30, 0, TimeSpan.Zero);
        var filename = ReportGenerator.GenerateFilename(ReportFormat.Html, ts);
        Assert.Contains("2026-01-15-1430", filename);
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    [Fact]
    public void GenerateHtmlReport_EmptyReport_DoesNotThrow()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            SecurityScore = 100
        };

        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("100", html);
    }

    [Fact]
    public void GenerateJsonReport_EmptyReport_IsValidJson()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            SecurityScore = 100
        };

        var json = _generator.GenerateJsonReport(report);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.Equal(0, doc.RootElement.GetProperty("modules").GetArrayLength());
    }

    [Fact]
    public void GenerateTextReport_EmptyReport_DoesNotThrow()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            SecurityScore = 100
        };

        var text = _generator.GenerateTextReport(report);
        Assert.Contains("WinSentinel Security Report", text);
    }

    [Fact]
    public void GenerateHtmlReport_FailedModule_ShowsError()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow
        };
        report.Results.Add(new AuditResult
        {
            ModuleName = "FailedModule",
            Category = "Test Failed",
            Success = false,
            Error = "Access denied",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow
        });
        report.SecurityScore = SecurityScorer.CalculateScore(report);

        var html = _generator.GenerateHtmlReport(report);
        Assert.Contains("Module Error", html);
        Assert.Contains("Access denied", html);
    }

    [Fact]
    public void GenerateTextReport_FailedModule_ShowsError()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow
        };
        report.Results.Add(new AuditResult
        {
            ModuleName = "FailedModule",
            Category = "Test Failed",
            Success = false,
            Error = "Access denied",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow
        });
        report.SecurityScore = SecurityScorer.CalculateScore(report);

        var text = _generator.GenerateTextReport(report);
        Assert.Contains("[ERROR]", text);
        Assert.Contains("Access denied", text);
    }

    [Fact]
    public void GenerateJsonReport_ContainsRemediation()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        Assert.Contains("\"remediation\":", json);
        Assert.Contains("Fix critical issue 1", json);
    }

    [Fact]
    public void GenerateJsonReport_ContainsFixCommand()
    {
        var report = CreateTestReport();
        var json = _generator.GenerateJsonReport(report);
        Assert.Contains("\"fixCommand\":", json);
        Assert.Contains("Set-NetFirewallProfile", json);
    }
}
