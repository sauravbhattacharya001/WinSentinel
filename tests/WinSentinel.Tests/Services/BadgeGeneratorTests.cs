using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class BadgeGeneratorTests
{
    private readonly BadgeGenerator _generator = new();

    // ── Test Helpers ────────────────────────────────────────────────

    private static SecurityReport CreateReport(int score, int criticals = 0, int warnings = 0, int infos = 0, int passes = 0)
    {
        var report = new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = new DateTimeOffset(2026, 2, 23, 12, 0, 0, TimeSpan.Zero)
        };

        var result = new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall & Network Protection",
            StartTime = report.GeneratedAt,
            EndTime = report.GeneratedAt.AddSeconds(2)
        };

        for (int i = 0; i < criticals; i++)
            result.Findings.Add(Finding.Critical($"Critical {i + 1}", $"Desc {i + 1}", "Firewall"));
        for (int i = 0; i < warnings; i++)
            result.Findings.Add(Finding.Warning($"Warning {i + 1}", $"Desc {i + 1}", "Firewall"));
        for (int i = 0; i < infos; i++)
            result.Findings.Add(Finding.Info($"Info {i + 1}", $"Desc {i + 1}", "Firewall"));
        for (int i = 0; i < passes; i++)
            result.Findings.Add(Finding.Pass($"Pass {i + 1}", $"Desc {i + 1}", "Firewall"));

        report.Results.Add(result);
        return report;
    }

    private static SecurityReport CreateMultiModuleReport()
    {
        var report = new SecurityReport
        {
            SecurityScore = 75,
            GeneratedAt = new DateTimeOffset(2026, 2, 23, 12, 0, 0, TimeSpan.Zero)
        };

        var fw = new AuditResult { ModuleName = "FirewallAudit", Category = "Firewall", StartTime = report.GeneratedAt, EndTime = report.GeneratedAt.AddSeconds(1) };
        fw.Findings.Add(Finding.Warning("FW Warning", "Test", "Firewall"));
        report.Results.Add(fw);

        var upd = new AuditResult { ModuleName = "UpdateAudit", Category = "Updates", StartTime = report.GeneratedAt, EndTime = report.GeneratedAt.AddSeconds(1) };
        upd.Findings.Add(Finding.Pass("Updates OK", "Test", "Updates"));
        report.Results.Add(upd);

        var enc = new AuditResult { ModuleName = "EncryptionAudit", Category = "Encryption", StartTime = report.GeneratedAt, EndTime = report.GeneratedAt.AddSeconds(1) };
        enc.Findings.Add(Finding.Critical("No Encryption", "Test", "Encryption"));
        report.Results.Add(enc);

        return report;
    }

    // ── GenerateScoreBadge ──────────────────────────────────────────

    [Fact]
    public void GenerateScoreBadge_ReturnsValidSvg()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateScoreBadge(report);

        Assert.Contains("<svg", svg);
        Assert.Contains("</svg>", svg);
        Assert.Contains("WinSentinel", svg);
        Assert.Contains("85/100", svg);
        Assert.Contains("B", svg);
    }

    [Fact]
    public void GenerateScoreBadge_GradeA_ShowsGreenColor()
    {
        var report = CreateReport(95);
        var svg = _generator.GenerateScoreBadge(report);

        Assert.Contains("95/100 A", svg);
        Assert.Contains("#4c1", svg); // bright green
    }

    [Fact]
    public void GenerateScoreBadge_GradeF_ShowsRedColor()
    {
        var report = CreateReport(30);
        var svg = _generator.GenerateScoreBadge(report);

        Assert.Contains("30/100 F", svg);
        Assert.Contains("#e05d44", svg); // red
    }

    [Fact]
    public void GenerateScoreBadge_FlatSquareStyle()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateScoreBadge(report, BadgeGenerator.BadgeStyle.FlatSquare);

        Assert.Contains("<svg", svg);
        Assert.DoesNotContain("linearGradient", svg); // No gradient in flat-square
        Assert.DoesNotContain("clipPath", svg);
        Assert.Contains("85/100 B", svg);
    }

    [Fact]
    public void GenerateScoreBadge_ForTheBadgeStyle()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateScoreBadge(report, BadgeGenerator.BadgeStyle.ForTheBadge);

        Assert.Contains("<svg", svg);
        Assert.Contains("WINSENTINEL", svg); // Uppercase for this style
        Assert.Contains("height=\"28\"", svg); // Taller badge
    }

    [Theory]
    [InlineData(95, "#4c1")]      // A: bright green
    [InlineData(85, "#97ca00")]   // B: green
    [InlineData(75, "#a4a61d")]   // C: yellow-green
    [InlineData(65, "#dfb317")]   // D: yellow
    [InlineData(50, "#fe7d37")]   // F-high: orange
    [InlineData(20, "#e05d44")]   // F-low: red
    public void GenerateScoreBadge_CorrectColorForScore(int score, string expectedColor)
    {
        var report = CreateReport(score);
        var svg = _generator.GenerateScoreBadge(report);

        Assert.Contains(expectedColor, svg);
    }

    [Fact]
    public void GenerateScoreBadge_ZeroScore()
    {
        var report = CreateReport(0);
        var svg = _generator.GenerateScoreBadge(report);

        Assert.Contains("0/100 F", svg);
        Assert.Contains("#e05d44", svg);
    }

    [Fact]
    public void GenerateScoreBadge_PerfectScore()
    {
        var report = CreateReport(100);
        var svg = _generator.GenerateScoreBadge(report);

        Assert.Contains("100/100 A", svg);
        Assert.Contains("#4c1", svg);
    }

    // ── GenerateGradeBadge ──────────────────────────────────────────

    [Fact]
    public void GenerateGradeBadge_ShowsGradeLabel()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateGradeBadge(report);

        Assert.Contains("security", svg);
        Assert.Contains("grade B", svg);
    }

    [Fact]
    public void GenerateGradeBadge_ForTheBadge_IsUppercase()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateGradeBadge(report, BadgeGenerator.BadgeStyle.ForTheBadge);

        Assert.Contains("SECURITY", svg);
        Assert.Contains("GRADE B", svg);
    }

    [Theory]
    [InlineData(95, "grade A")]
    [InlineData(85, "grade B")]
    [InlineData(75, "grade C")]
    [InlineData(65, "grade D")]
    [InlineData(30, "grade F")]
    public void GenerateGradeBadge_CorrectGradeText(int score, string expectedText)
    {
        var report = CreateReport(score);
        var svg = _generator.GenerateGradeBadge(report);

        Assert.Contains(expectedText, svg);
    }

    // ── GenerateFindingsBadge ───────────────────────────────────────

    [Fact]
    public void GenerateFindingsBadge_WithCriticals()
    {
        var report = CreateReport(50, criticals: 2, warnings: 3);
        var svg = _generator.GenerateFindingsBadge(report);

        Assert.Contains("findings", svg);
        Assert.Contains("2 critical", svg);
        Assert.Contains("3 warnings", svg);
        Assert.Contains("#e05d44", svg); // red for criticals
    }

    [Fact]
    public void GenerateFindingsBadge_WarningsOnly()
    {
        var report = CreateReport(80, warnings: 4);
        var svg = _generator.GenerateFindingsBadge(report);

        Assert.Contains("4 warnings", svg);
        Assert.DoesNotContain("critical", svg);
        Assert.Contains("#dfb317", svg); // yellow for warnings
    }

    [Fact]
    public void GenerateFindingsBadge_AllClear()
    {
        var report = CreateReport(100, passes: 5);
        var svg = _generator.GenerateFindingsBadge(report);

        Assert.Contains("all clear", svg);
        Assert.Contains("#4c1", svg); // green
    }

    [Fact]
    public void GenerateFindingsBadge_InfoOnly_ShowsAllClear()
    {
        var report = CreateReport(100, infos: 3);
        var svg = _generator.GenerateFindingsBadge(report);

        // Info doesn't count as critical or warning
        Assert.Contains("all clear", svg);
    }

    // ── GenerateModuleBadge ─────────────────────────────────────────

    [Fact]
    public void GenerateModuleBadge_ShowsModuleScore()
    {
        var result = new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        result.Findings.Add(Finding.Warning("Test", "Test", "Firewall"));

        var svg = _generator.GenerateModuleBadge(result);

        Assert.Contains("firewall", svg); // lowercase label
        Assert.Contains("95 A", svg); // 100 - 5 (1 warning)
    }

    [Fact]
    public void GenerateModuleBadge_CriticalFindings()
    {
        var result = new AuditResult
        {
            ModuleName = "EncryptionAudit",
            Category = "Encryption",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        result.Findings.Add(Finding.Critical("No BitLocker", "Not encrypted", "Encryption"));
        result.Findings.Add(Finding.Critical("No TPM", "TPM missing", "Encryption"));

        var svg = _generator.GenerateModuleBadge(result);

        Assert.Contains("encryption", svg);
        Assert.Contains("60 D", svg); // 100 - 40 (2 criticals)
    }

    [Fact]
    public void GenerateModuleBadge_PerfectModule()
    {
        var result = new AuditResult
        {
            ModuleName = "UpdateAudit",
            Category = "Updates",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        result.Findings.Add(Finding.Pass("Up to date", "All current", "Updates"));

        var svg = _generator.GenerateModuleBadge(result);

        Assert.Contains("updates", svg);
        Assert.Contains("100 A", svg);
    }

    // ── GenerateAllModuleBadges ─────────────────────────────────────

    [Fact]
    public void GenerateAllModuleBadges_StacksMultipleModules()
    {
        var report = CreateMultiModuleReport();
        var svg = _generator.GenerateAllModuleBadges(report);

        // Should contain a wrapping SVG
        Assert.StartsWith("<svg", svg);
        // Should contain all 3 modules
        Assert.Contains("firewall", svg.ToLowerInvariant());
        Assert.Contains("updates", svg.ToLowerInvariant());
        Assert.Contains("encryption", svg.ToLowerInvariant());
    }

    [Fact]
    public void GenerateAllModuleBadges_EmptyReport_ReturnsFallback()
    {
        var report = new SecurityReport { SecurityScore = 100 };
        var svg = _generator.GenerateAllModuleBadges(report);

        Assert.Contains("modules", svg);
        Assert.Contains("none", svg);
    }

    [Fact]
    public void GenerateAllModuleBadges_OrderedByScoreDescending()
    {
        var report = CreateMultiModuleReport();
        var svg = _generator.GenerateAllModuleBadges(report);

        // Updates (100) should appear before Firewall (95) before Encryption (80)
        var updatesPos = svg.IndexOf("updates", StringComparison.OrdinalIgnoreCase);
        var firewallPos = svg.IndexOf("firewall", StringComparison.OrdinalIgnoreCase);
        var encryptionPos = svg.IndexOf("encryption", StringComparison.OrdinalIgnoreCase);

        Assert.True(updatesPos < firewallPos, "Updates (100) should appear before Firewall (95)");
        Assert.True(firewallPos < encryptionPos, "Firewall (95) should appear before Encryption (80)");
    }

    // ── SVG Structure ───────────────────────────────────────────────

    [Fact]
    public void FlatSvg_HasGradientAndClipPath()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateScoreBadge(report, BadgeGenerator.BadgeStyle.Flat);

        Assert.Contains("linearGradient", svg);
        Assert.Contains("clipPath", svg);
        Assert.Contains("rx=\"3\"", svg); // rounded corners
    }

    [Fact]
    public void FlatSquareSvg_NoGradientNoClipPath()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateScoreBadge(report, BadgeGenerator.BadgeStyle.FlatSquare);

        Assert.DoesNotContain("linearGradient", svg);
        Assert.DoesNotContain("clipPath", svg);
    }

    [Fact]
    public void ForTheBadgeSvg_HasLargerHeight()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateScoreBadge(report, BadgeGenerator.BadgeStyle.ForTheBadge);

        Assert.Contains("height=\"28\"", svg);
        Assert.Contains("font-weight=\"bold\"", svg);
    }

    // ── EstimateTextWidth ───────────────────────────────────────────

    [Fact]
    public void EstimateTextWidth_EmptyString_ReturnsZero()
    {
        Assert.Equal(0, BadgeGenerator.EstimateTextWidth("", 11));
    }

    [Fact]
    public void EstimateTextWidth_NullString_ReturnsZero()
    {
        Assert.Equal(0, BadgeGenerator.EstimateTextWidth(null!, 11));
    }

    [Fact]
    public void EstimateTextWidth_NarrowChars_SmallerWidth()
    {
        var narrowWidth = BadgeGenerator.EstimateTextWidth("iii", 11);
        var wideWidth = BadgeGenerator.EstimateTextWidth("MMM", 11);

        Assert.True(narrowWidth < wideWidth, "Narrow chars (iii) should be narrower than wide chars (MMM)");
    }

    [Fact]
    public void EstimateTextWidth_BoldWider()
    {
        var normal = BadgeGenerator.EstimateTextWidth("test", 11, false);
        var bold = BadgeGenerator.EstimateTextWidth("test", 11, true);

        Assert.True(bold > normal, "Bold text should be wider");
    }

    [Fact]
    public void EstimateTextWidth_LongerTextWider()
    {
        var shortWidth = BadgeGenerator.EstimateTextWidth("hi", 11);
        var longWidth = BadgeGenerator.EstimateTextWidth("hello world", 11);

        Assert.True(longWidth > shortWidth);
    }

    // ── GetBadgeColor ───────────────────────────────────────────────

    [Theory]
    [InlineData(100, "#4c1")]
    [InlineData(90, "#4c1")]
    [InlineData(89, "#97ca00")]
    [InlineData(80, "#97ca00")]
    [InlineData(79, "#a4a61d")]
    [InlineData(70, "#a4a61d")]
    [InlineData(69, "#dfb317")]
    [InlineData(60, "#dfb317")]
    [InlineData(59, "#fe7d37")]
    [InlineData(40, "#fe7d37")]
    [InlineData(39, "#e05d44")]
    [InlineData(0, "#e05d44")]
    public void GetBadgeColor_ReturnsCorrectColor(int score, string expected)
    {
        Assert.Equal(expected, BadgeGenerator.GetBadgeColor(score));
    }

    // ── SvgEscape ───────────────────────────────────────────────────

    [Theory]
    [InlineData("hello", "hello")]
    [InlineData("a & b", "a &amp; b")]
    [InlineData("<script>", "&lt;script&gt;")]
    [InlineData("it's", "it&#39;s")]
    [InlineData("a\"b", "a&quot;b")]
    [InlineData("a & <b> \"c\" 'd'", "a &amp; &lt;b&gt; &quot;c&quot; &#39;d&#39;")]
    public void SvgEscape_EscapesCorrectly(string input, string expected)
    {
        Assert.Equal(expected, BadgeGenerator.SvgEscape(input));
    }

    // ── GetMarkdownEmbed ────────────────────────────────────────────

    [Fact]
    public void GetMarkdownEmbed_BasicImage()
    {
        var md = BadgeGenerator.GetMarkdownEmbed("badge.svg");
        Assert.Equal("![WinSentinel Security Score](badge.svg)", md);
    }

    [Fact]
    public void GetMarkdownEmbed_CustomAltText()
    {
        var md = BadgeGenerator.GetMarkdownEmbed("badge.svg", "Security Badge");
        Assert.Equal("![Security Badge](badge.svg)", md);
    }

    [Fact]
    public void GetMarkdownEmbed_WithLink()
    {
        var md = BadgeGenerator.GetMarkdownEmbed("badge.svg", "Score", "https://example.com");
        Assert.Equal("[![Score](badge.svg)](https://example.com)", md);
    }

    [Fact]
    public void GetMarkdownEmbed_EmptyUrl_Throws()
    {
        Assert.Throws<ArgumentException>(() => BadgeGenerator.GetMarkdownEmbed(""));
    }

    [Fact]
    public void GetMarkdownEmbed_NullUrl_Throws()
    {
        Assert.Throws<ArgumentException>(() => BadgeGenerator.GetMarkdownEmbed(null!));
    }

    // ── SaveBadge ───────────────────────────────────────────────────

    [Fact]
    public void SaveBadge_CreatesFile()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"badge-test-{Guid.NewGuid()}.svg");
        try
        {
            var report = CreateReport(85);
            var svg = _generator.GenerateScoreBadge(report);
            _generator.SaveBadge(tempPath, svg);

            Assert.True(File.Exists(tempPath));
            var content = File.ReadAllText(tempPath);
            Assert.Contains("<svg", content);
            Assert.Contains("85/100", content);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    [Fact]
    public void SaveBadge_CreatesDirectory()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"badge-test-dir-{Guid.NewGuid()}");
        var tempPath = Path.Combine(tempDir, "score.svg");
        try
        {
            var report = CreateReport(90);
            var svg = _generator.GenerateScoreBadge(report);
            _generator.SaveBadge(tempPath, svg);

            Assert.True(File.Exists(tempPath));
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public void SaveBadge_NoBom()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"badge-bom-{Guid.NewGuid()}.svg");
        try
        {
            _generator.SaveBadge(tempPath, "<svg></svg>");

            var bytes = File.ReadAllBytes(tempPath);
            // UTF-8 BOM is EF BB BF — should NOT be present
            Assert.False(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
                "SVG file should not have BOM");
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    // ── All Three Styles Produce Valid SVG ───────────────────────────

    [Theory]
    [InlineData(BadgeGenerator.BadgeStyle.Flat)]
    [InlineData(BadgeGenerator.BadgeStyle.FlatSquare)]
    [InlineData(BadgeGenerator.BadgeStyle.ForTheBadge)]
    public void AllBadgeTypes_ProduceValidSvg_AllStyles(BadgeGenerator.BadgeStyle style)
    {
        var report = CreateReport(75, criticals: 1, warnings: 2, passes: 3);

        var scoreSvg = _generator.GenerateScoreBadge(report, style);
        var gradeSvg = _generator.GenerateGradeBadge(report, style);
        var findingsSvg = _generator.GenerateFindingsBadge(report, style);

        foreach (var svg in new[] { scoreSvg, gradeSvg, findingsSvg })
        {
            Assert.Contains("<svg", svg);
            Assert.Contains("</svg>", svg);
            Assert.Contains("xmlns=\"http://www.w3.org/2000/svg\"", svg);
        }
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    [Fact]
    public void GenerateScoreBadge_XmlDeclaration()
    {
        var report = CreateReport(85);
        var svg = _generator.GenerateScoreBadge(report);

        Assert.Contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", svg);
    }

    [Fact]
    public void GenerateModuleBadge_SpecialCharsInCategory()
    {
        var result = new AuditResult
        {
            ModuleName = "Test",
            Category = "Firewall & Network Protection",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };

        var svg = _generator.GenerateModuleBadge(result);

        // & should be escaped to &amp; in SVG
        Assert.Contains("&amp;", svg);
        Assert.DoesNotContain("& ", svg.Replace("&amp;", ""));
    }

    [Fact]
    public void GenerateFindingsBadge_BothCriticalAndWarnings_HasMiddleDot()
    {
        var report = CreateReport(50, criticals: 1, warnings: 2);
        var svg = _generator.GenerateFindingsBadge(report);

        // Middle dot (·) used as separator, HTML-encoded
        Assert.Contains("1 critical", svg);
        Assert.Contains("2 warnings", svg);
    }
}
