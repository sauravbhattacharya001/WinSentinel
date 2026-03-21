using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class FindingDependencyGraphTests
{
    private static Finding MakeFinding(string title, string category, Severity sev = Severity.Warning) =>
        new() { Title = title, Description = $"Description for {title}", Category = category, Severity = sev };

    [Fact]
    public void Analyze_NoFindings_ReturnsEmpty()
    {
        var graph = new FindingDependencyGraph();
        var result = graph.Analyze([]);

        Assert.Empty(result.RootCauses);
        Assert.Empty(result.IndependentFindings);
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.TotalLinks);
    }

    [Fact]
    public void Analyze_FirewallRootCause_FindsDependents()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Windows Firewall Disabled", "Firewall", Severity.Critical),
            MakeFinding("Open Port 3389 (RDP Exposed)", "Network", Severity.Warning),
            MakeFinding("SMB Port Open to Internet", "Network", Severity.Warning),
            MakeFinding("Unrelated Finding", "Accounts", Severity.Info)
        };

        var graph = new FindingDependencyGraph();
        var result = graph.Analyze(findings);

        Assert.Single(result.RootCauses);
        Assert.Equal("Windows Firewall Disabled", result.RootCauses[0].RootCause.Title);
        Assert.Equal(2, result.RootCauses[0].Impact);
        Assert.Single(result.IndependentFindings);
        Assert.Equal("Unrelated Finding", result.IndependentFindings[0].Title);
    }

    [Fact]
    public void Analyze_MultipleRootCauses_SortedByImpact()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Windows Firewall Disabled", "Firewall", Severity.Critical),
            MakeFinding("Open Port 445 (SMB)", "Network"),
            MakeFinding("RDP Exposed", "Network"),
            MakeFinding("Inbound Rule Too Broad", "Firewall"),
            MakeFinding("Password Policy Weak", "Accounts", Severity.Critical),
            MakeFinding("Weak Password Length", "Accounts"),
            MakeFinding("Account Lockout Not Configured", "Accounts"),
        };

        var graph = new FindingDependencyGraph();
        var result = graph.Analyze(findings);

        Assert.True(result.RootCauses.Count >= 2);
        // First root cause should have the most dependents
        Assert.True(result.RootCauses[0].Impact >= result.RootCauses[1].Impact);
    }

    [Fact]
    public void Analyze_NoDependencyMatches_AllIndependent()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Something Unique", "Custom"),
            MakeFinding("Another Unique", "Custom"),
        };

        var graph = new FindingDependencyGraph();
        var result = graph.Analyze(findings);

        Assert.Empty(result.RootCauses);
        Assert.Equal(2, result.IndependentFindings.Count);
    }

    [Fact]
    public void FormatText_ProducesOutput()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Windows Firewall Disabled", "Firewall", Severity.Critical),
            MakeFinding("Open Port 3389", "Network"),
        };

        var graph = new FindingDependencyGraph();
        var result = graph.Analyze(findings);
        var text = FindingDependencyGraph.FormatText(result);

        Assert.Contains("FINDING DEPENDENCY GRAPH", text);
        Assert.Contains("Root Causes:", text);
        Assert.Contains("PRIORITY FIX ORDER", text);
    }

    [Fact]
    public void FormatJson_ProducesValidJson()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Windows Firewall Disabled", "Firewall", Severity.Critical),
            MakeFinding("Open Port 3389", "Network"),
        };

        var graph = new FindingDependencyGraph();
        var result = graph.Analyze(findings);
        var json = FindingDependencyGraph.FormatJson(result);

        Assert.Contains("\"rootCauses\"", json);
        Assert.Contains("\"dependencyDensity\"", json);
        // Should be valid JSON
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotNull(doc);
    }

    [Fact]
    public void FormatMarkdown_ProducesOutput()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Windows Firewall Disabled", "Firewall", Severity.Critical),
            MakeFinding("Open Port 3389", "Network"),
        };

        var graph = new FindingDependencyGraph();
        var result = graph.Analyze(findings);
        var md = FindingDependencyGraph.FormatMarkdown(result);

        Assert.Contains("# Finding Dependency Graph", md);
        Assert.Contains("## Priority Fix Order", md);
    }

    [Fact]
    public void DependencyDensity_CalculatedCorrectly()
    {
        var findings = new List<Finding>
        {
            MakeFinding("Windows Firewall Disabled", "Firewall"),
            MakeFinding("Open Port 3389", "Network"),
            MakeFinding("Unrelated", "Other"),
        };

        var graph = new FindingDependencyGraph();
        var result = graph.Analyze(findings);

        // Density = (rootCauses + dependents) / total
        Assert.True(result.DependencyDensity > 0);
        Assert.True(result.DependencyDensity <= 1.0);
    }
}
