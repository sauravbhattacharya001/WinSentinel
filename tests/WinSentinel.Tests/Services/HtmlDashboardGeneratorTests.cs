using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for HtmlDashboardGenerator.
/// </summary>
public class HtmlDashboardGeneratorTests : IDisposable
{
    private readonly HtmlDashboardGenerator _generator = new();
    private readonly List<string> _tempFiles = new();

    public void Dispose()
    {
        foreach (var f in _tempFiles)
        {
            try { if (File.Exists(f)) File.Delete(f); } catch { }
            try { var d = Path.GetDirectoryName(f); if (d != null && Directory.Exists(d) && !Directory.EnumerateFileSystemEntries(d).Any()) Directory.Delete(d); } catch { }
        }
    }

    private static SecurityReport CreateTestReport(int criticals = 1, int warnings = 2, int infos = 1, int passes = 1)
    {
        var report = new SecurityReport { GeneratedAt = new DateTimeOffset(2025, 6, 15, 10, 30, 0, TimeSpan.Zero) };
        var result1 = new AuditResult { ModuleName = "Firewall", Category = "Network" };
        for (int i = 0; i < criticals; i++)
            result1.Findings.Add(Finding.Critical($"Critical{i}", $"Critical issue {i}", "Network", "Fix it", "Set-NetFirewall"));
        for (int i = 0; i < warnings; i++)
            result1.Findings.Add(Finding.Warning($"Warning{i}", $"Warning issue {i}", "Network", "Check config"));
        var result2 = new AuditResult { ModuleName = "Defender", Category = "Antivirus" };
        for (int i = 0; i < infos; i++)
            result2.Findings.Add(Finding.Info($"Info{i}", $"Info note {i}", "Antivirus"));
        for (int i = 0; i < passes; i++)
            result2.Findings.Add(Finding.Pass($"Pass{i}", $"All good {i}", "Antivirus"));
        report.Results.Add(result1);
        report.Results.Add(result2);
        return report;
    }

    private static SecurityReport CreateEmptyReport()
    {
        return new SecurityReport { GeneratedAt = new DateTimeOffset(2025, 6, 15, 10, 30, 0, TimeSpan.Zero) };
    }

    // ── Generate Basics ──

    [Fact]
    public void Generate_ContainsDoctype()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<!DOCTYPE html>", html);
    }

    [Fact]
    public void Generate_ContainsHtmlTag()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<html", html);
        Assert.Contains("</html>", html);
    }

    [Fact]
    public void Generate_ContainsHeadTag()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<head>", html);
        Assert.Contains("</head>", html);
    }

    [Fact]
    public void Generate_ContainsBodyTag()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<body>", html);
        Assert.Contains("</body>", html);
    }

    [Fact]
    public void Generate_ContainsMetaCharset()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("meta charset=\"UTF-8\"", html);
    }

    [Fact]
    public void Generate_ContainsViewportMeta()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("viewport", html);
        Assert.Contains("width=device-width", html);
    }

    // ── Score Gauge ──

    [Fact]
    public void Generate_ShowsScoreValue()
    {
        var report = CreateTestReport(criticals: 0, warnings: 0, infos: 0, passes: 2);
        var html = _generator.Generate(report);
        Assert.Contains("100", html);
    }

    [Fact]
    public void Generate_ScoreGreenForHighScore()
    {
        var report = CreateTestReport(criticals: 0, warnings: 0, infos: 1, passes: 1);
        var html = _generator.Generate(report);
        Assert.Contains("#22c55e", html);
    }

    [Fact]
    public void Generate_ScoreYellowForMediumScore()
    {
        // 2 warnings = score 90 (one module), 0 (other empty-ish) => depends on setup
        // Let's make a report with score in 70-89 range
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "Test", Category = "C" };
        // 3 warnings = -15, score = 85
        r.Findings.Add(Finding.Warning("W1", "D", "C"));
        r.Findings.Add(Finding.Warning("W2", "D", "C"));
        r.Findings.Add(Finding.Warning("W3", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("#eab308", html);
    }

    [Fact]
    public void Generate_ScoreOrangeForLowScore()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "Test", Category = "C" };
        // 3 criticals = -60, score = 40 => will be < 50 actually, let's do 2 critical + 2 warning = -50 => 50
        r.Findings.Add(Finding.Critical("C1", "D", "C"));
        r.Findings.Add(Finding.Critical("C2", "D", "C"));
        r.Findings.Add(Finding.Warning("W1", "D", "C"));
        r.Findings.Add(Finding.Warning("W2", "D", "C"));
        report.Results.Add(r);
        // Score = 100 - 40 - 10 = 50 => orange
        var html = _generator.Generate(report);
        Assert.Contains("#f97316", html);
    }

    [Fact]
    public void Generate_ScoreRedForVeryLowScore()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "Test", Category = "C" };
        for (int i = 0; i < 5; i++)
            r.Findings.Add(Finding.Critical($"C{i}", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("#ef4444", html);
    }

    // ── Grade Display ──

    [Theory]
    [InlineData(0, 0, "A")]
    public void Generate_ShowsGradeA(int crit, int warn, string grade)
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "T", Category = "C" };
        for (int i = 0; i < crit; i++) r.Findings.Add(Finding.Critical($"C{i}", "D", "C"));
        for (int i = 0; i < warn; i++) r.Findings.Add(Finding.Warning($"W{i}", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains($"grade-{grade.ToLowerInvariant()}", html);
    }

    [Fact]
    public void Generate_ShowsGradeB()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "T", Category = "C" };
        // 1 critical = 80 => B
        r.Findings.Add(Finding.Critical("C1", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("grade-b", html);
    }

    [Fact]
    public void Generate_ShowsGradeC()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "T", Category = "C" };
        // 1 critical + 2 warnings = -30, score=70 => C
        r.Findings.Add(Finding.Critical("C1", "D", "C"));
        r.Findings.Add(Finding.Warning("W1", "D", "C"));
        r.Findings.Add(Finding.Warning("W2", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("grade-c", html);
    }

    [Fact]
    public void Generate_ShowsGradeD()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "T", Category = "C" };
        // 2 criticals = -40, score=60 => D
        r.Findings.Add(Finding.Critical("C1", "D", "C"));
        r.Findings.Add(Finding.Critical("C2", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("grade-d", html);
    }

    [Fact]
    public void Generate_ShowsGradeF()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "T", Category = "C" };
        // 3 criticals = -60, score=40 => F
        for (int i = 0; i < 3; i++) r.Findings.Add(Finding.Critical($"C{i}", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("grade-f", html);
    }

    // ── Summary Cards ──

    [Fact]
    public void Generate_ShowsTotalFindings()
    {
        var report = CreateTestReport(criticals: 2, warnings: 3, infos: 1, passes: 1);
        var html = _generator.Generate(report);
        Assert.Contains("Total Findings", html);
    }

    [Fact]
    public void Generate_ShowsCriticalCount()
    {
        var report = CreateTestReport(criticals: 2, warnings: 0, infos: 0, passes: 0);
        var html = _generator.Generate(report);
        Assert.Contains("Critical", html);
        Assert.Contains("card-critical", html);
    }

    [Fact]
    public void Generate_ShowsWarningCount()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Warning", html);
        Assert.Contains("card-warning", html);
    }

    [Fact]
    public void Generate_ShowsInfoCount()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Info", html);
        Assert.Contains("card-info", html);
    }

    [Fact]
    public void Generate_ShowsPassCount()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Pass", html);
        Assert.Contains("card-pass", html);
    }

    [Fact]
    public void Generate_ShowsModulesScanned()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Modules Scanned", html);
    }

    // ── Module Table ──

    [Fact]
    public void Generate_ModuleTableListsAllModules()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Firewall", html);
        Assert.Contains("Defender", html);
    }

    [Fact]
    public void Generate_ModuleTableShowsScores()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("module-table", html);
        Assert.Contains("<th>Score</th>", html);
    }

    [Fact]
    public void Generate_ModuleTableShowsFindingCounts()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<th>Critical</th>", html);
        Assert.Contains("<th>Warning</th>", html);
        Assert.Contains("<th>Info</th>", html);
        Assert.Contains("<th>Pass</th>", html);
    }

    // ── Findings ──

    [Fact]
    public void Generate_FindingsGroupedByModule()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Firewall", html);
    }

    [Fact]
    public void Generate_FindingsHaveSeverityBadges()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("badge-critical", html);
        Assert.Contains("badge-warning", html);
    }

    [Fact]
    public void Generate_FindingsShowRemediation()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Fix it", html);
        Assert.Contains("finding-remediation", html);
    }

    [Fact]
    public void Generate_FindingsShowFixCommand()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Set-NetFirewall", html);
        Assert.Contains("fix-command", html);
    }

    [Fact]
    public void Generate_FixCommandInCodeBlock()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<code class=\"fix-command\">", html);
    }

    // ── Passed Checks ──

    [Fact]
    public void Generate_ExcludesPassedChecksByDefault()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.DoesNotContain("<section class=\"passed-checks\">", html);
    }

    [Fact]
    public void Generate_IncludesPassedChecksWhenOptionSet()
    {
        var options = new HtmlDashboardOptions { IncludePassedChecks = true };
        var html = _generator.Generate(CreateTestReport(), options);
        Assert.Contains("passed-checks", html);
        Assert.Contains("Passed Checks", html);
    }

    [Fact]
    public void Generate_PassedChecksListsPassFindings()
    {
        var options = new HtmlDashboardOptions { IncludePassedChecks = true };
        var html = _generator.Generate(CreateTestReport(), options);
        Assert.Contains("Pass0", html);
    }

    // ── Dark Mode ──

    [Fact]
    public void Generate_LightModeByDefault()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("class=\"light\"", html);
    }

    [Fact]
    public void Generate_DarkModeApplied()
    {
        var options = new HtmlDashboardOptions { DarkMode = true };
        var html = _generator.Generate(CreateTestReport(), options);
        Assert.Contains("class=\"dark\"", html);
    }

    [Fact]
    public void Generate_DarkModeCssPresent()
    {
        var html = _generator.Generate(CreateTestReport(), new HtmlDashboardOptions { DarkMode = true });
        Assert.Contains("html.dark", html);
    }

    // ── Custom Title ──

    [Fact]
    public void Generate_DefaultTitle()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("WinSentinel Security Dashboard", html);
    }

    [Fact]
    public void Generate_CustomTitleInHeader()
    {
        var options = new HtmlDashboardOptions { Title = "My Custom Report" };
        var html = _generator.Generate(CreateTestReport(), options);
        Assert.Contains("My Custom Report", html);
    }

    [Fact]
    public void Generate_CustomTitleInPageTitle()
    {
        var options = new HtmlDashboardOptions { Title = "Custom Title" };
        var html = _generator.Generate(CreateTestReport(), options);
        Assert.Contains("<title>Custom Title</title>", html);
    }

    // ── Timestamp ──

    [Fact]
    public void Generate_TimestampShownByDefault()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("scan-timestamp", html);
        Assert.Contains("2025-06-15", html);
    }

    [Fact]
    public void Generate_TimestampHiddenWhenDisabled()
    {
        var options = new HtmlDashboardOptions { IncludeTimestamp = false };
        var html = _generator.Generate(CreateTestReport(), options);
        Assert.DoesNotContain("scan-timestamp", html);
    }

    // ── Collapsible Sections ──

    [Fact]
    public void Generate_CollapsibleSectionsUsesDetailsSummary()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<details", html);
        Assert.Contains("<summary>", html);
    }

    [Fact]
    public void Generate_CollapsibleSectionsDisabled()
    {
        var options = new HtmlDashboardOptions { CollapsibleSections = false };
        var html = _generator.Generate(CreateTestReport(), options);
        // Findings section should use div instead of details
        Assert.Contains("module-group", html);
    }

    // ── Options Defaults ──

    [Fact]
    public void Generate_DefaultOptionsProduceValidHtml()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("</html>", html);
        Assert.Contains("<style>", html);
    }

    [Fact]
    public void Generate_NullOptionsUsesDefaults()
    {
        var html = _generator.Generate(CreateTestReport(), null);
        Assert.Contains("WinSentinel Security Dashboard", html);
    }

    // ── Empty Report ──

    [Fact]
    public void Generate_EmptyReportHandledGracefully()
    {
        var html = _generator.Generate(CreateEmptyReport());
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("</html>", html);
    }

    [Fact]
    public void Generate_EmptyReportShowsScore100()
    {
        var html = _generator.Generate(CreateEmptyReport());
        Assert.Contains("100", html);
    }

    [Fact]
    public void Generate_EmptyReportShowsZeroFindings()
    {
        var html = _generator.Generate(CreateEmptyReport());
        // Total findings should be 0
        Assert.Contains("Total Findings", html);
    }

    // ── Special Characters ──

    [Fact]
    public void Generate_HtmlEncodesLessThan()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "Test<Module>", Category = "C" };
        r.Findings.Add(Finding.Warning("Title <script>", "Desc & more", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("<script>", html);
    }

    [Fact]
    public void Generate_HtmlEncodesAmpersand()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "Test", Category = "C" };
        r.Findings.Add(Finding.Warning("A & B", "X & Y", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("A &amp; B", html);
    }

    [Fact]
    public void Generate_HtmlEncodesQuotes()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "Test", Category = "C" };
        r.Findings.Add(Finding.Warning("Say \"hello\"", "Desc", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("&quot;hello&quot;", html);
    }

    [Fact]
    public void Generate_HtmlEncodesGreaterThan()
    {
        var report = new SecurityReport { GeneratedAt = DateTimeOffset.UtcNow };
        var r = new AuditResult { ModuleName = "Test", Category = "C" };
        r.Findings.Add(Finding.Warning("A > B", "D", "C"));
        report.Results.Add(r);
        var html = _generator.Generate(report);
        Assert.Contains("A &gt; B", html);
    }

    // ── SaveDashboard ──

    [Fact]
    public void SaveDashboard_WritesToFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ws_test_{Guid.NewGuid()}.html");
        _tempFiles.Add(path);
        _generator.SaveDashboard("<html></html>", path);
        Assert.True(File.Exists(path));
        Assert.Equal("<html></html>", File.ReadAllText(path));
    }

    [Fact]
    public void SaveDashboard_CreatesDirectories()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"ws_test_dir_{Guid.NewGuid()}");
        var path = Path.Combine(dir, "report.html");
        _tempFiles.Add(path);
        _generator.SaveDashboard("<html></html>", path);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void SaveDashboard_NoBom()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ws_test_bom_{Guid.NewGuid()}.html");
        _tempFiles.Add(path);
        _generator.SaveDashboard("<html></html>", path);
        var bytes = File.ReadAllBytes(path);
        // UTF-8 BOM is 0xEF, 0xBB, 0xBF
        Assert.False(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);
    }

    // ── GenerateFilename ──

    [Fact]
    public void GenerateFilename_IncludesDate()
    {
        var report = CreateTestReport();
        var filename = _generator.GenerateFilename(report);
        Assert.Contains("2025-06-15", filename);
    }

    [Fact]
    public void GenerateFilename_IncludesMachineName()
    {
        var filename = _generator.GenerateFilename(CreateTestReport());
        Assert.Contains(Environment.MachineName, filename);
    }

    [Fact]
    public void GenerateFilename_EndsWithHtml()
    {
        var filename = _generator.GenerateFilename(CreateTestReport());
        Assert.EndsWith(".html", filename);
    }

    // ── CSS Presence ──

    [Fact]
    public void Generate_ContainsStyleTag()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("<style>", html);
        Assert.Contains("</style>", html);
    }

    [Fact]
    public void Generate_CssContainsFontStack()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("-apple-system", html);
        Assert.Contains("Segoe UI", html);
    }

    [Fact]
    public void Generate_CssContainsConicGradient()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("conic-gradient", html);
    }

    [Fact]
    public void Generate_CustomCssIncluded()
    {
        var options = new HtmlDashboardOptions { CustomCss = ".custom-class { color: purple; }" };
        var html = _generator.Generate(CreateTestReport(), options);
        Assert.Contains(".custom-class", html);
    }

    // ── Print Styles ──

    [Fact]
    public void Generate_ContainsPrintStyles()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("@media print", html);
    }

    // ── Responsive ──

    [Fact]
    public void Generate_ContainsResponsiveMediaQuery()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("@media (max-width:", html);
    }

    // ── Footer ──

    [Fact]
    public void Generate_FooterContainsPoweredBy()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Powered by WinSentinel", html);
    }

    [Fact]
    public void Generate_FooterPresent()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("dashboard-footer", html);
    }

    // ── Header ──

    [Fact]
    public void Generate_HeaderContainsMachineName()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains(Environment.MachineName, html);
    }

    [Fact]
    public void Generate_HeaderContainsVersion()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("WinSentinel v1.0", html);
    }

    // ── Severity Distribution ──

    [Fact]
    public void Generate_SeverityDistributionPresent()
    {
        var html = _generator.Generate(CreateTestReport());
        Assert.Contains("Severity Distribution", html);
        Assert.Contains("bar-chart", html);
    }

    // ── Score Color Helper ──

    [Theory]
    [InlineData(100, "#22c55e")]
    [InlineData(90, "#22c55e")]
    [InlineData(89, "#eab308")]
    [InlineData(70, "#eab308")]
    [InlineData(69, "#f97316")]
    [InlineData(50, "#f97316")]
    [InlineData(49, "#ef4444")]
    [InlineData(0, "#ef4444")]
    public void GetDashboardScoreColor_ReturnsCorrectColor(int score, string expected)
    {
        Assert.Equal(expected, HtmlDashboardGenerator.GetDashboardScoreColor(score));
    }

    // ── HtmlEncode Helper ──

    [Fact]
    public void HtmlEncode_EncodesAllSpecialChars()
    {
        var result = HtmlDashboardGenerator.HtmlEncode("<script>alert(\"x&y\")</script>");
        Assert.Equal("&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;", result);
    }

    [Fact]
    public void HtmlEncode_HandlesNull()
    {
        Assert.Equal(string.Empty, HtmlDashboardGenerator.HtmlEncode(null!));
    }

    [Fact]
    public void HtmlEncode_HandlesEmpty()
    {
        Assert.Equal(string.Empty, HtmlDashboardGenerator.HtmlEncode(""));
    }
}
