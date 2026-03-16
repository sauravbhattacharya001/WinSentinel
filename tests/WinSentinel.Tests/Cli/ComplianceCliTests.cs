using WinSentinel.Cli;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Cli;

public class ComplianceCliTests
{
    // ── CLI Parser Tests ─────────────────────────────────────────────

    [Fact]
    public void Parse_Compliance_SetsCommand()
    {
        var opts = CliParser.Parse(new[] { "--compliance" });
        Assert.Equal(CliCommand.Compliance, opts.Command);
        Assert.Null(opts.Error);
    }

    [Fact]
    public void Parse_Compliance_WithFramework_SetsFrameworkId()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--framework", "nist" });
        Assert.Equal(CliCommand.Compliance, opts.Command);
        Assert.Equal("nist", opts.ComplianceFramework);
    }

    [Fact]
    public void Parse_Compliance_WithPciDss_SetsFrameworkId()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--framework", "pci-dss" });
        Assert.Equal("pci-dss", opts.ComplianceFramework);
    }

    [Fact]
    public void Parse_Compliance_WithHipaa_SetsFrameworkId()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--framework", "hipaa" });
        Assert.Equal("hipaa", opts.ComplianceFramework);
    }

    [Fact]
    public void Parse_Compliance_CrossFramework_SetsFlag()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--cross-framework" });
        Assert.Equal(CliCommand.Compliance, opts.Command);
        Assert.True(opts.ComplianceCrossFramework);
    }

    [Fact]
    public void Parse_Compliance_WithJson_SetsJsonFlag()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--json" });
        Assert.Equal(CliCommand.Compliance, opts.Command);
        Assert.True(opts.Json);
    }

    [Fact]
    public void Parse_Compliance_WithCsv_SetsCsvFlag()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--csv" });
        Assert.Equal(CliCommand.Compliance, opts.Command);
        Assert.True(opts.Csv);
    }

    [Fact]
    public void Parse_Compliance_WithOutput_SetsOutputFile()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "-o", "report.json", "--json" });
        Assert.Equal("report.json", opts.OutputFile);
    }

    [Fact]
    public void Parse_Compliance_FrameworkAll_EquivalentToCrossFramework()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--framework", "all" });
        Assert.Equal("all", opts.ComplianceFramework);
        // In handler, framework=="all" triggers cross-framework mode
    }

    [Fact]
    public void Parse_Compliance_MissingFrameworkValue_ReturnsError()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--framework" });
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void Parse_Compliance_WithQuiet_SetsQuietFlag()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--quiet" });
        Assert.True(opts.Quiet);
    }

    [Fact]
    public void Parse_Compliance_WithModulesFilter_SetsFilter()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--modules", "firewall,network" });
        Assert.Equal("firewall,network", opts.ModulesFilter);
    }

    [Fact]
    public void Parse_Compliance_CrossFrameworkAndJson_BothSet()
    {
        var opts = CliParser.Parse(new[] { "--compliance", "--cross-framework", "--json" });
        Assert.True(opts.ComplianceCrossFramework);
        Assert.True(opts.Json);
    }

    // ── ConsoleFormatter CSV Tests ───────────────────────────────────

    [Fact]
    public void RenderComplianceCsv_IncludesHeader()
    {
        var report = new ComplianceReport
        {
            FrameworkId = "cis",
            FrameworkName = "CIS",
            FrameworkVersion = "3.0",
            Controls = new List<ControlResult>
            {
                new()
                {
                    ControlId = "CIS-1.1",
                    ControlTitle = "Password Policy",
                    Status = ControlStatus.Pass,
                    RelatedFindings = new List<Finding>(),
                    Remediation = new List<string>()
                }
            },
            Summary = new ComplianceSummary { TotalControls = 1, PassCount = 1 }
        };

        var csv = ConsoleFormatter.RenderComplianceCsv(report);
        Assert.Contains("ControlId,ControlTitle,Status,FindingCount,Remediation", csv);
        Assert.Contains("CIS-1.1", csv);
        Assert.Contains("Pass", csv);
    }

    [Fact]
    public void RenderComplianceCsv_CountsNonPassFindings()
    {
        var report = new ComplianceReport
        {
            FrameworkId = "nist",
            FrameworkName = "NIST",
            FrameworkVersion = "5",
            Controls = new List<ControlResult>
            {
                new()
                {
                    ControlId = "AC-2",
                    ControlTitle = "Account Management",
                    Status = ControlStatus.Fail,
                    RelatedFindings = new List<Finding>
                    {
                        Finding.Critical("Test1", "Desc", "Accounts"),
                        Finding.Warning("Test2", "Desc", "Accounts"),
                        Finding.Pass("Test3", "Desc", "Accounts")
                    },
                    Remediation = new List<string> { "Fix accounts" }
                }
            },
            Summary = new ComplianceSummary { TotalControls = 1, FailCount = 1 }
        };

        var csv = ConsoleFormatter.RenderComplianceCsv(report);
        // 2 non-pass findings
        Assert.Contains(",2,", csv);
    }

    [Fact]
    public void RenderComplianceCrossFrameworkCsv_IncludesAllFrameworks()
    {
        var summary = new CrossFrameworkSummary
        {
            SecurityScore = 75,
            FrameworkResults = new List<FrameworkResult>
            {
                new()
                {
                    FrameworkId = "cis",
                    FrameworkName = "CIS Benchmarks",
                    CompliancePercentage = 80.0,
                    Verdict = ComplianceVerdict.PartiallyCompliant,
                    PassCount = 8,
                    FailCount = 1,
                    PartialCount = 1,
                    NotAssessedCount = 3,
                    CriticalGaps = new List<string> { "CIS-1.1: Password Policy" }
                },
                new()
                {
                    FrameworkId = "nist",
                    FrameworkName = "NIST 800-53",
                    CompliancePercentage = 70.0,
                    Verdict = ComplianceVerdict.NonCompliant,
                    PassCount = 7,
                    FailCount = 3,
                    PartialCount = 0,
                    NotAssessedCount = 6,
                    CriticalGaps = new List<string>()
                }
            }
        };

        var csv = ConsoleFormatter.RenderComplianceCrossFrameworkCsv(summary);
        Assert.Contains("FrameworkId,FrameworkName", csv);
        Assert.Contains("cis", csv);
        Assert.Contains("nist", csv);
        Assert.Contains("80.0", csv);
        Assert.Contains("70.0", csv);
    }

    [Fact]
    public void RenderComplianceCsv_EscapesQuotesInRemediation()
    {
        var report = new ComplianceReport
        {
            FrameworkId = "cis",
            FrameworkName = "CIS",
            FrameworkVersion = "3.0",
            Controls = new List<ControlResult>
            {
                new()
                {
                    ControlId = "CIS-1.1",
                    ControlTitle = "Test",
                    Status = ControlStatus.Fail,
                    RelatedFindings = new List<Finding>
                    {
                        Finding.Critical("F1", "Desc", "Accounts")
                    },
                    Remediation = new List<string> { "Run \"secpol.msc\" to fix" }
                }
            },
            Summary = new ComplianceSummary { TotalControls = 1, FailCount = 1 }
        };

        var csv = ConsoleFormatter.RenderComplianceCsv(report);
        // Quotes should be doubled for CSV escaping
        Assert.Contains("\"\"secpol.msc\"\"", csv);
    }

    [Fact]
    public void RenderComplianceCrossFrameworkCsv_IncludesCriticalGapCount()
    {
        var summary = new CrossFrameworkSummary
        {
            SecurityScore = 50,
            FrameworkResults = new List<FrameworkResult>
            {
                new()
                {
                    FrameworkId = "hipaa",
                    FrameworkName = "HIPAA",
                    CompliancePercentage = 60.0,
                    Verdict = ComplianceVerdict.NonCompliant,
                    PassCount = 3,
                    FailCount = 5,
                    PartialCount = 2,
                    NotAssessedCount = 1,
                    CriticalGaps = new List<string> { "Gap1", "Gap2", "Gap3" }
                }
            }
        };

        var csv = ConsoleFormatter.RenderComplianceCrossFrameworkCsv(summary);
        Assert.Contains("CriticalGapCount", csv);
        Assert.Contains(",3", csv);  // 3 critical gaps
    }
}
