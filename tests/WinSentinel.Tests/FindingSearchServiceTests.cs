using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class FindingSearchServiceTests
{
    private static SecurityReport CreateTestReport()
    {
        var report = new SecurityReport();
        report.Results.Add(new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall",
            Findings = new List<Finding>
            {
                new()
                {
                    Title = "Windows Firewall is disabled",
                    Description = "The Windows Defender Firewall is currently turned off for the public profile.",
                    Severity = Severity.Critical,
                    Remediation = "Enable Windows Firewall via Control Panel or PowerShell.",
                    FixCommand = "Set-NetFirewallProfile -Profile Public -Enabled True",
                    Category = "Firewall"
                },
                new()
                {
                    Title = "Inbound rules allow all traffic",
                    Description = "Several inbound firewall rules are configured to allow all traffic.",
                    Severity = Severity.Warning,
                    Category = "Firewall"
                }
            }
        });
        report.Results.Add(new AuditResult
        {
            ModuleName = "UpdateAudit",
            Category = "Updates",
            Findings = new List<Finding>
            {
                new()
                {
                    Title = "System updates are outdated",
                    Description = "Windows Update has not checked for updates in 45 days.",
                    Severity = Severity.Warning,
                    Remediation = "Run Windows Update to install pending patches.",
                    Category = "Updates"
                },
                new()
                {
                    Title = "Automatic updates disabled",
                    Description = "Windows Update automatic download and install is disabled.",
                    Severity = Severity.Info,
                    Category = "Updates"
                }
            }
        });
        return report;
    }

    [Fact]
    public void Search_FindsMatchingTitle()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions { Query = "firewall" });

        Assert.True(result.Matches.Count >= 2);
        Assert.All(result.Matches.Take(2), m =>
            Assert.Contains("Firewall", m.ModuleCategory, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Search_FindsMatchInDescription()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions { Query = "45 days" });

        Assert.Single(result.Matches);
        Assert.Contains("outdated", result.Matches[0].Finding.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Search_FiltersBySeverity()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions
        {
            Query = "firewall",
            SeverityFilter = "Critical"
        });

        Assert.Single(result.Matches);
        Assert.Equal(Severity.Critical, result.Matches[0].Finding.Severity);
    }

    [Fact]
    public void Search_FiltersByModule()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions
        {
            Query = "disabled",
            ModuleFilter = "Updates"
        });

        Assert.Single(result.Matches);
        Assert.Contains("Updates", result.Matches[0].ModuleCategory);
    }

    [Fact]
    public void Search_RespectsLimit()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions
        {
            Query = "firewall",
            Limit = 1
        });

        Assert.Single(result.Matches);
    }

    [Fact]
    public void Search_ReturnsEmptyForNoMatch()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions { Query = "xyznonexistent" });

        Assert.Empty(result.Matches);
    }

    [Fact]
    public void Search_RanksHigherRelevanceFirst()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        // "disabled" appears in title for two findings: firewall and updates
        var result = service.Search(report, new SearchOptions { Query = "disabled" });

        Assert.True(result.Matches.Count >= 2);
        // Critical finding should rank higher
        Assert.True(result.Matches[0].RelevanceScore >= result.Matches[1].RelevanceScore);
    }

    [Fact]
    public void Search_IncludesSeverityBreakdown()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions { Query = "disabled" });

        Assert.NotEmpty(result.SeverityBreakdown);
    }

    [Fact]
    public void Search_IncludesModuleBreakdown()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions { Query = "disabled" });

        Assert.NotEmpty(result.ModuleBreakdown);
    }

    [Fact]
    public void HighlightMatches_SplitsCorrectly()
    {
        var segments = FindingSearchService.HighlightMatches("Windows Firewall is disabled", "firewall");

        Assert.Equal(3, segments.Count);
        Assert.False(segments[0].isMatch); // "Windows "
        Assert.True(segments[1].isMatch);  // "Firewall"
        Assert.False(segments[2].isMatch); // " is disabled"
    }

    [Fact]
    public void HighlightMatches_EmptyQuery()
    {
        var segments = FindingSearchService.HighlightMatches("some text", "");

        Assert.Single(segments);
        Assert.False(segments[0].isMatch);
    }

    [Fact]
    public void Search_EmptyQuery_ReturnsEmpty()
    {
        var service = new FindingSearchService();
        var report = CreateTestReport();

        var result = service.Search(report, new SearchOptions { Query = "" });

        Assert.Empty(result.Matches);
    }

    [Fact]
    public void CliParser_ParsesSearchCommand()
    {
        var options = WinSentinel.Cli.CliParser.Parse(new[] { "--search", "firewall" });

        Assert.Equal(WinSentinel.Cli.CliCommand.Search, options.Command);
        Assert.Equal("firewall", options.SearchQuery);
        Assert.Null(options.Error);
    }

    [Fact]
    public void CliParser_ParsesSearchWithFilters()
    {
        var options = WinSentinel.Cli.CliParser.Parse(new[]
        {
            "--search", "disabled",
            "--search-severity", "Critical",
            "--search-module", "Firewall",
            "--search-limit", "10",
            "--no-highlight",
            "--show-remediation"
        });

        Assert.Equal(WinSentinel.Cli.CliCommand.Search, options.Command);
        Assert.Equal("disabled", options.SearchQuery);
        Assert.Equal("Critical", options.SearchSeverityFilter);
        Assert.Equal("Firewall", options.SearchModuleFilter);
        Assert.Equal(10, options.SearchLimit);
        Assert.False(options.SearchHighlight);
        Assert.True(options.SearchIncludeRemediation);
        Assert.Null(options.Error);
    }

    [Fact]
    public void CliParser_SearchRequiresQuery()
    {
        var options = WinSentinel.Cli.CliParser.Parse(new[] { "--search" });

        Assert.NotNull(options.Error);
        Assert.Contains("Missing search query", options.Error);
    }
}
