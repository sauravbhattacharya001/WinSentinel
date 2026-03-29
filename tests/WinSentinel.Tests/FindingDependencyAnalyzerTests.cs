using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests;

public class FindingDependencyAnalyzerTests
{
    private readonly FindingDependencyAnalyzer _analyzer = new();

    [Fact]
    public void Analyze_EmptyResults_ReturnsEmptyGraph()
    {
        var result = _analyzer.Analyze(new List<AuditResult>());
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.RootFindings);
        Assert.Empty(result.Clusters);
        Assert.Empty(result.TopCascadeImpacts);
    }

    [Fact]
    public void Analyze_NoRelatedFindings_NoClusters()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "TestModule",
                Category = "Test",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Warning("Unique finding A", "Desc A", "CategoryA"),
                    Finding.Warning("Unique finding B", "Desc B", "CategoryB"),
                }
            }
        };

        var result = _analyzer.Analyze(results);
        Assert.Equal(2, result.TotalFindings);
        // No rule-based clusters and not enough in same category (need 3+)
        Assert.Equal(0, result.RootFindings);
    }

    [Fact]
    public void Analyze_FirewallDisabled_CascadesToNetworkFindings()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "FirewallAudit",
                Category = "Network",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Critical("Firewall is disabled", "Windows Firewall is turned off", "Network"),
                }
            },
            new()
            {
                ModuleName = "NetworkAudit",
                Category = "Network",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Warning("SMB port exposed", "Port 445 is listening", "Network"),
                    Finding.Warning("Remote Desktop accessible", "RDP port 3389 open", "Network"),
                }
            }
        };

        var result = _analyzer.Analyze(results);
        Assert.True(result.RootFindings > 0);
        Assert.True(result.EstimatedAutoResolve > 0);

        // The firewall finding should be a root cause
        var firewallCluster = result.Clusters.FirstOrDefault(c =>
            c.RootTitle.Contains("Firewall", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(firewallCluster);
        Assert.True(firewallCluster.CascadeCount > 0);
    }

    [Fact]
    public void Analyze_CategoryGrouping_ClustersRelatedFindings()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "AccountAudit",
                Category = "Accounts",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Critical("Account issue 1", "Desc 1", "Accounts"),
                    Finding.Warning("Account issue 2", "Desc 2", "Accounts"),
                    Finding.Warning("Account issue 3", "Desc 3", "Accounts"),
                    Finding.Warning("Account issue 4", "Desc 4", "Accounts"),
                }
            }
        };

        var result = _analyzer.Analyze(results);
        // Should form at least one category-based cluster (4 findings in same category)
        Assert.True(result.Clusters.Count > 0);
    }

    [Fact]
    public void Analyze_TopCascadeImpacts_SortedByCount()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "FirewallAudit",
                Category = "Network",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Critical("Firewall is disabled", "Off", "Network"),
                }
            },
            new()
            {
                ModuleName = "NetworkAudit",
                Category = "Network",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Warning("SMB share exposed", "Open", "Network"),
                    Finding.Warning("Remote Desktop enabled externally", "Open", "Network"),
                    Finding.Warning("Network listening port 8080", "Open", "Network"),
                }
            }
        };

        var result = _analyzer.Analyze(results);
        if (result.TopCascadeImpacts.Count >= 2)
        {
            Assert.True(result.TopCascadeImpacts[0].CascadeCount >=
                        result.TopCascadeImpacts[1].CascadeCount);
        }
    }

    [Fact]
    public void Analyze_FailedModules_Excluded()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "FailedModule",
                Category = "Test",
                Success = false,
                Error = "Access denied",
                Findings = new List<Finding>
                {
                    Finding.Critical("Should be ignored", "Desc", "Test"),
                }
            }
        };

        var result = _analyzer.Analyze(results);
        Assert.Equal(0, result.TotalFindings);
    }

    [Fact]
    public void Analyze_PassAndInfoFindings_Excluded()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "TestModule",
                Category = "Test",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Pass("All good", "Desc", "Test"),
                    Finding.Info("FYI", "Desc", "Test"),
                }
            }
        };

        var result = _analyzer.Analyze(results);
        Assert.Equal(0, result.TotalFindings);
    }

    [Fact]
    public void Analyze_ScoreImpact_Calculated()
    {
        var results = new List<AuditResult>
        {
            new()
            {
                ModuleName = "FirewallAudit",
                Category = "Network",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Critical("Firewall is disabled", "Off", "Network"),
                }
            },
            new()
            {
                ModuleName = "NetworkAudit",
                Category = "Network",
                Success = true,
                Findings = new List<Finding>
                {
                    Finding.Warning("SMB exposed", "Open", "Network"),
                }
            }
        };

        var result = _analyzer.Analyze(results);
        foreach (var impact in result.TopCascadeImpacts)
        {
            Assert.True(impact.ScoreImpact > 0);
        }
    }
}
