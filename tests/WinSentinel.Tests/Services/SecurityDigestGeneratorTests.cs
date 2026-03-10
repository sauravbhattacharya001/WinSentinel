using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityDigestGeneratorTests
{
    // --- Pulse computation tests ---

    [Fact]
    public void ComputePulse_Critical_WhenManyCriticals()
    {
        var digest = new SecurityDigest { CriticalCount = 5, CurrentScore = 20 };
        Assert.Equal(DigestPulse.Critical, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Critical_WhenVeryLowScore()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 25 };
        Assert.Equal(DigestPulse.Critical, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Unhealthy_WhenTwoCriticals()
    {
        var digest = new SecurityDigest { CriticalCount = 2, CurrentScore = 60 };
        Assert.Equal(DigestPulse.Unhealthy, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Unhealthy_WhenLowScore()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 45 };
        Assert.Equal(DigestPulse.Unhealthy, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_NeedsAttention_WhenOneCritical()
    {
        var digest = new SecurityDigest { CriticalCount = 1, CurrentScore = 75 };
        Assert.Equal(DigestPulse.NeedsAttention, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_NeedsAttention_WhenDeclining()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 80, Trend = DigestTrend.Declining };
        Assert.Equal(DigestPulse.NeedsAttention, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_NeedsAttention_WhenMediumScore()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 65 };
        Assert.Equal(DigestPulse.NeedsAttention, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Excellent_WhenHighScoreAndStable()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 95, Trend = DigestTrend.Stable };
        Assert.Equal(DigestPulse.Excellent, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Excellent_WhenHighScoreAndImproving()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 92, Trend = DigestTrend.Improving };
        Assert.Equal(DigestPulse.Excellent, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Healthy_WhenGoodScoreNoCriticals()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 80, Trend = DigestTrend.Stable };
        Assert.Equal(DigestPulse.Healthy, SecurityDigestGenerator.ComputePulse(digest));
    }

    // --- Text rendering tests ---

    [Fact]
    public void RenderText_ContainsBanner()
    {
        var digest = new SecurityDigest { MachineName = "TEST-PC", CurrentScore = 75, CurrentGrade = "C", Pulse = DigestPulse.Healthy };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("WinSentinel Security Digest", text);
        Assert.Contains("TEST-PC", text);
    }

    [Fact]
    public void RenderText_ShowsScoreAndGrade()
    {
        var digest = new SecurityDigest { CurrentScore = 85, CurrentGrade = "B", Pulse = DigestPulse.Healthy };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("85/100", text);
        Assert.Contains("(B)", text);
    }

    [Fact]
    public void RenderText_ShowsTrendArrow_Improving()
    {
        var digest = new SecurityDigest { CurrentScore = 85, CurrentGrade = "B", Trend = DigestTrend.Improving, ScoreDelta = 10, Pulse = DigestPulse.Healthy };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("↑", text);
        Assert.Contains("+10", text);
    }

    [Fact]
    public void RenderText_ShowsTrendArrow_Declining()
    {
        var digest = new SecurityDigest { CurrentScore = 60, CurrentGrade = "D", Trend = DigestTrend.Declining, ScoreDelta = -15, Pulse = DigestPulse.NeedsAttention };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("↓", text);
        Assert.Contains("-15", text);
    }

    [Fact]
    public void RenderText_ShowsFindingCounts()
    {
        var digest = new SecurityDigest { CriticalCount = 3, WarningCount = 5, InfoCount = 10, PassCount = 20, TotalFindings = 38, Pulse = DigestPulse.NeedsAttention };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("Critical: 3", text);
        Assert.Contains("Warning:  5", text);
        Assert.Contains("38 total", text);
    }

    [Fact]
    public void RenderText_ShowsFindingDeltas()
    {
        var digest = new SecurityDigest { CriticalCount = 3, CriticalDelta = 1, WarningCount = 5, WarningDelta = -2, Pulse = DigestPulse.NeedsAttention };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("+1", text);
        Assert.Contains("-2", text);
    }

    [Fact]
    public void RenderText_ShowsTopRisks()
    {
        var digest = new SecurityDigest
        {
            Pulse = DigestPulse.NeedsAttention,
            TopRisks = new()
            {
                new DigestRiskItem { Title = "Open RDP Port", Severity = Severity.Critical, Category = "Network", HasAutoFix = true },
                new DigestRiskItem { Title = "Weak Password Policy", Severity = Severity.Warning, Category = "Account" }
            }
        };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("Open RDP Port", text);
        Assert.Contains("[auto-fixable]", text);
        Assert.Contains("Weak Password Policy", text);
    }

    [Fact]
    public void RenderText_ShowsModuleBreakdown()
    {
        var digest = new SecurityDigest
        {
            Pulse = DigestPulse.Healthy,
            ModuleBreakdown = new() { new DigestModuleEntry { ModuleName = "Firewall", Score = 90 }, new DigestModuleEntry { ModuleName = "Network", Score = 45 } }
        };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("Firewall", text);
        Assert.Contains("Network", text);
        Assert.Contains("Module Scores", text);
    }

    [Fact]
    public void RenderText_ShowsNewFindings()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.NeedsAttention, NewFindings = new() { "New vuln found", "Another issue" } };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("New Issues", text);
        Assert.Contains("New vuln found", text);
    }

    [Fact]
    public void RenderText_ShowsResolvedFindings()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Healthy, ResolvedFindings = new() { "Fixed something" } };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("Resolved", text);
        Assert.Contains("Fixed something", text);
    }

    [Fact]
    public void RenderText_ShowsActions()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Healthy, AutoFixableCount = 4, ManualActionCount = 7 };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("Auto-fixable: 4", text);
        Assert.Contains("Manual:       7", text);
    }

    [Fact]
    public void RenderText_ShowsSparkline_WhenHistoryExists()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Healthy, ScoreHistory = new() { 60, 65, 70, 75, 80 } };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("Trend:", text);
    }

    [Fact]
    public void RenderText_NoSparkline_WhenSingleHistory()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Healthy, ScoreHistory = new() { 80 } };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.DoesNotContain("Trend:", text);
    }

    [Fact]
    public void RenderText_ShowsPreviousScore()
    {
        var digest = new SecurityDigest { CurrentScore = 80, CurrentGrade = "B", PreviousScore = 70, PreviousGrade = "C", Pulse = DigestPulse.Healthy };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.Contains("Previous: 70/100 (C)", text);
    }

    [Fact]
    public void RenderText_NoPreviousScore_WhenNull()
    {
        var digest = new SecurityDigest { CurrentScore = 80, CurrentGrade = "B", Pulse = DigestPulse.Healthy };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.DoesNotContain("Previous:", text);
    }

    // --- HTML rendering tests ---

    [Fact]
    public void RenderHtml_IsValidHtml()
    {
        var digest = new SecurityDigest { MachineName = "TEST-PC", CurrentScore = 85, CurrentGrade = "B", Pulse = DigestPulse.Healthy };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.StartsWith("<!DOCTYPE html>", html);
        Assert.Contains("</html>", html);
        Assert.Contains("TEST-PC", html);
    }

    [Fact]
    public void RenderHtml_ContainsPulseClass()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Critical };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains("pulse-critical", html);
    }

    [Fact]
    public void RenderHtml_ContainsScoreCard()
    {
        var digest = new SecurityDigest { CurrentScore = 72, CurrentGrade = "C", Pulse = DigestPulse.NeedsAttention };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains("72", html);
        Assert.Contains("/100", html);
    }

    [Fact]
    public void RenderHtml_ShowsScoreDelta_Positive()
    {
        var digest = new SecurityDigest { CurrentScore = 80, CurrentGrade = "B", ScoreDelta = 8, Trend = DigestTrend.Improving, Pulse = DigestPulse.Healthy };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains("delta-positive", html);
        Assert.Contains("+8", html);
    }

    [Fact]
    public void RenderHtml_ShowsScoreDelta_Negative()
    {
        var digest = new SecurityDigest { CurrentScore = 55, CurrentGrade = "D", ScoreDelta = -12, Trend = DigestTrend.Declining, Pulse = DigestPulse.NeedsAttention };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains("delta-negative", html);
        Assert.Contains("-12", html);
    }

    [Fact]
    public void RenderHtml_ShowsRisksTable()
    {
        var digest = new SecurityDigest
        {
            Pulse = DigestPulse.NeedsAttention,
            TopRisks = new() { new DigestRiskItem { Title = "Test Risk", Severity = Severity.Critical, Category = "Test", HasAutoFix = true } }
        };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains("Test Risk", html);
        Assert.Contains("badge-critical", html);
        Assert.Contains("badge-auto", html);
    }

    [Fact]
    public void RenderHtml_ShowsModuleTable()
    {
        var digest = new SecurityDigest
        {
            Pulse = DigestPulse.Healthy,
            ModuleBreakdown = new() { new DigestModuleEntry { ModuleName = "TestMod", Score = 88 } }
        };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains("TestMod", html);
        Assert.Contains("88", html);
    }

    [Fact]
    public void RenderHtml_EscapesSpecialChars()
    {
        var digest = new SecurityDigest
        {
            Pulse = DigestPulse.Healthy,
            TopRisks = new() { new DigestRiskItem { Title = "<script>alert('xss')</script>", Severity = Severity.Warning, Category = "Test" } }
        };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    // --- JSON rendering tests ---

    [Fact]
    public void RenderJson_IsValidJson()
    {
        var digest = new SecurityDigest { MachineName = "TEST-PC", CurrentScore = 75, CurrentGrade = "C", Pulse = DigestPulse.Healthy, Trend = DigestTrend.Stable };
        var json = SecurityDigestGenerator.RenderJson(digest);
        Assert.Contains("\"machineName\"", json);
        Assert.Contains("\"currentScore\": 75", json);
        Assert.Contains("\"Healthy\"", json);
    }

    [Fact]
    public void RenderJson_ContainsTopRisks()
    {
        var digest = new SecurityDigest
        {
            Pulse = DigestPulse.Healthy,
            TopRisks = new() { new DigestRiskItem { Title = "Risk1", Severity = Severity.Critical, Category = "Cat" } }
        };
        var json = SecurityDigestGenerator.RenderJson(digest);
        Assert.Contains("Risk1", json);
        Assert.Contains("\"Critical\"", json);
    }

    // --- Pulse boundary tests ---

    [Fact]
    public void ComputePulse_Excellent_At90_NotDeclining()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 90, Trend = DigestTrend.Stable };
        Assert.Equal(DigestPulse.Excellent, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_NeedsAttention_At90_Declining()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 90, Trend = DigestTrend.Declining };
        Assert.Equal(DigestPulse.NeedsAttention, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Healthy_At89()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 89, Trend = DigestTrend.Stable };
        Assert.Equal(DigestPulse.Healthy, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Critical_AtScore29()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 29 };
        Assert.Equal(DigestPulse.Critical, SecurityDigestGenerator.ComputePulse(digest));
    }

    [Fact]
    public void ComputePulse_Unhealthy_AtScore30()
    {
        var digest = new SecurityDigest { CriticalCount = 0, CurrentScore = 30 };
        Assert.Equal(DigestPulse.Unhealthy, SecurityDigestGenerator.ComputePulse(digest));
    }

    // --- Empty data handling ---

    [Fact]
    public void RenderText_HandlesEmptyDigest()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Healthy };
        var text = SecurityDigestGenerator.RenderText(digest);
        Assert.NotEmpty(text);
        Assert.Contains("WinSentinel Security Digest", text);
    }

    [Fact]
    public void RenderHtml_HandlesEmptyDigest()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Healthy };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("</html>", html);
    }

    [Fact]
    public void RenderJson_HandlesEmptyDigest()
    {
        var digest = new SecurityDigest { Pulse = DigestPulse.Healthy };
        var json = SecurityDigestGenerator.RenderJson(digest);
        Assert.Contains("\"pulse\"", json);
    }

    // --- All pulse values render correctly ---

    [Theory]
    [InlineData(DigestPulse.Excellent, "pulse-excellent")]
    [InlineData(DigestPulse.Healthy, "pulse-healthy")]
    [InlineData(DigestPulse.NeedsAttention, "pulse-attention")]
    [InlineData(DigestPulse.Unhealthy, "pulse-unhealthy")]
    [InlineData(DigestPulse.Critical, "pulse-critical")]
    public void RenderHtml_AllPulseClasses(DigestPulse pulse, string expectedClass)
    {
        var digest = new SecurityDigest { Pulse = pulse };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains(expectedClass, html);
    }

    [Theory]
    [InlineData(DigestTrend.Improving, "trend-up")]
    [InlineData(DigestTrend.Declining, "trend-down")]
    [InlineData(DigestTrend.Stable, "trend-stable")]
    public void RenderHtml_AllTrendArrows(DigestTrend trend, string expectedClass)
    {
        var digest = new SecurityDigest { Trend = trend, Pulse = DigestPulse.Healthy };
        var html = SecurityDigestGenerator.RenderHtml(digest);
        Assert.Contains(expectedClass, html);
    }
}
