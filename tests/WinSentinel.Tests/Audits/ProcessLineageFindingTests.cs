using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Finding-generation tests for <see cref="ProcessLineageAnalyzer"/>: the Pass /
/// Critical / Warning / Info bucketing for lineage matches, the orphan-count and
/// deep-nesting thresholds, command-line truncation, plus a light integration test
/// confirming <see cref="ProcessLineageAudit"/> still produces a coherent result
/// after delegating its logic to the analyzer.
/// </summary>
public class ProcessLineageFindingTests
{
    // ----------------------------------------------------------------------
    // BuildLineageFindings
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildLineageFindings_NoMatches_SinglePass()
    {
        var findings = ProcessLineageAnalyzer.BuildLineageFindings(Array.Empty<ProcessLineageAnalyzer.LineageMatch>());
        Assert.Single(findings);
        Assert.Equal(Severity.Pass, findings[0].Severity);
        Assert.Equal("Process Lineage Clean", findings[0].Title);
        Assert.Equal(ProcessLineageAnalyzer.Category, findings[0].Category);
    }

    [Fact]
    public void BuildLineageFindings_Null_SinglePass()
    {
        var findings = ProcessLineageAnalyzer.BuildLineageFindings(null!);
        Assert.Single(findings);
        Assert.Equal(Severity.Pass, findings[0].Severity);
    }

    [Fact]
    public void BuildLineageFindings_CriticalOnly_OneCriticalFinding()
    {
        var matches = ProcessLineageAnalyzer.MatchRecords(new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "winword", 2, "powershell -enc AAAA"),
            new ProcessLineageAnalyzer.ProcessRecord("cmd", 3, "excel", 4, ""),
        });

        var findings = ProcessLineageAnalyzer.BuildLineageFindings(matches);
        Assert.Single(findings);
        Assert.Equal(Severity.Critical, findings[0].Severity);
        Assert.Contains("(2)", findings[0].Title);
        Assert.Contains("PID 1", findings[0].Description);
        Assert.Contains("->", findings[0].Description.Replace("\u2192", "->")); // arrow rendered
        Assert.NotNull(findings[0].FixCommand);
        Assert.Contains("Stop-Process -Id 1", findings[0].FixCommand!);
    }

    [Fact]
    public void BuildLineageFindings_CriticalWithCommandLine_IncludesSampleSection()
    {
        var matches = ProcessLineageAnalyzer.MatchRecords(new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "winword", 2, "powershell -enc PAYLOAD"),
        });

        var findings = ProcessLineageAnalyzer.BuildLineageFindings(matches);
        Assert.Contains("Sample command lines:", findings[0].Description);
        Assert.Contains("PAYLOAD", findings[0].Description);
    }

    [Fact]
    public void BuildLineageFindings_CriticalWithoutCommandLine_NoSampleSection()
    {
        var matches = ProcessLineageAnalyzer.MatchRecords(new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "winword", 2, ""),
        });

        var findings = ProcessLineageAnalyzer.BuildLineageFindings(matches);
        Assert.DoesNotContain("Sample command lines:", findings[0].Description);
    }

    [Fact]
    public void BuildLineageFindings_MixedSeverities_ThreeFindingsInSeverityOrder()
    {
        var matches = ProcessLineageAnalyzer.MatchRecords(new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "winword", 2, ""), // Critical
            new ProcessLineageAnalyzer.ProcessRecord("certutil", 3, "cmd", 4, ""),        // Warning
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 5, "cmd", 6, ""),      // Info
        });

        var findings = ProcessLineageAnalyzer.BuildLineageFindings(matches);
        Assert.Equal(3, findings.Count);
        Assert.Equal(Severity.Critical, findings[0].Severity);
        Assert.Equal(Severity.Warning, findings[1].Severity);
        Assert.Equal(Severity.Info, findings[2].Severity);
    }

    [Fact]
    public void BuildLineageFindings_WarningOnly_NoCriticalOrInfo()
    {
        var matches = ProcessLineageAnalyzer.MatchRecords(new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("certutil", 1, "cmd", 2, ""),
        });

        var findings = ProcessLineageAnalyzer.BuildLineageFindings(matches);
        Assert.Single(findings);
        Assert.Equal(Severity.Warning, findings[0].Severity);
        Assert.Contains("Suspicious Process Lineage Patterns", findings[0].Title);
    }

    [Fact]
    public void BuildLineageFindings_InfoOnly_RendersArrowList()
    {
        var matches = ProcessLineageAnalyzer.MatchRecords(new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "cmd", 2, ""),
        });

        var findings = ProcessLineageAnalyzer.BuildLineageFindings(matches);
        Assert.Single(findings);
        Assert.Equal(Severity.Info, findings[0].Severity);
        Assert.Contains("cmd", findings[0].Description);
        Assert.Contains("powershell", findings[0].Description);
    }

    [Fact]
    public void BuildLineageFindings_LongCommandLine_TruncatedInBody()
    {
        var longCmd = new string('A', 300);
        var matches = ProcessLineageAnalyzer.MatchRecords(new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "winword", 2, longCmd),
        });

        var findings = ProcessLineageAnalyzer.BuildLineageFindings(matches);
        Assert.Contains("...", findings[0].Description);
        // The full 300-char string must NOT appear verbatim (it was truncated to 120 + ellipsis).
        Assert.DoesNotContain(longCmd, findings[0].Description);
    }

    // ----------------------------------------------------------------------
    // BuildOrphanFinding -- threshold behaviour (Pass / Info / Warning)
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildOrphanFinding_None_Pass()
    {
        var f = ProcessLineageAnalyzer.BuildOrphanFinding(Array.Empty<ProcessLineageAnalyzer.OrphanRecord>());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("No Orphaned Processes", f.Title);
    }

    [Fact]
    public void BuildOrphanFinding_Null_Pass()
    {
        var f = ProcessLineageAnalyzer.BuildOrphanFinding(null!);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(10)]
    public void BuildOrphanFinding_TenOrFewer_Info(int count)
    {
        var records = Enumerable.Range(1, count)
            .Select(i => new ProcessLineageAnalyzer.OrphanRecord($"proc{i}", i, 9999))
            .ToList();

        var f = ProcessLineageAnalyzer.BuildOrphanFinding(records);
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains($"({count})", f.Title);
    }

    [Theory]
    [InlineData(11)]
    [InlineData(15)]
    [InlineData(20)]
    public void BuildOrphanFinding_MoreThanTen_Warning_WithSample(int count)
    {
        var records = Enumerable.Range(1, count)
            .Select(i => new ProcessLineageAnalyzer.OrphanRecord($"proc{i}", i, 9999))
            .ToList();

        var f = ProcessLineageAnalyzer.BuildOrphanFinding(records);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains($"({count})", f.Title);
        Assert.Contains("proc1 (PID 1)", f.Description); // first of the 8-item sample
        Assert.NotNull(f.Remediation);
    }

    // ----------------------------------------------------------------------
    // BuildDeepNestFinding -- Pass / Warning
    // ----------------------------------------------------------------------

    [Fact]
    public void BuildDeepNestFinding_None_Pass()
    {
        var f = ProcessLineageAnalyzer.BuildDeepNestFinding(Array.Empty<ProcessLineageAnalyzer.DeepNestRecord>());
        Assert.Equal(Severity.Pass, f.Severity);
        Assert.Equal("No Deep Interpreter Nesting", f.Title);
    }

    [Fact]
    public void BuildDeepNestFinding_Null_Pass()
    {
        var f = ProcessLineageAnalyzer.BuildDeepNestFinding(null!);
        Assert.Equal(Severity.Pass, f.Severity);
    }

    [Fact]
    public void BuildDeepNestFinding_WithChains_Warning_WithDepth_AndFixCommand()
    {
        var records = new[]
        {
            new ProcessLineageAnalyzer.DeepNestRecord("powershell", 100, 4),
            new ProcessLineageAnalyzer.DeepNestRecord("cmd", 200, 5),
        };

        var f = ProcessLineageAnalyzer.BuildDeepNestFinding(records);
        Assert.Equal(Severity.Warning, f.Severity);
        Assert.Contains("(2)", f.Title);
        Assert.Contains("depth 4", f.Description);
        Assert.Contains("depth 5", f.Description);
        Assert.NotNull(f.FixCommand);
        Assert.Contains("Win32_Process", f.FixCommand!);
    }

    // ----------------------------------------------------------------------
    // Truncate helper
    // ----------------------------------------------------------------------

    [Fact]
    public void Truncate_ShortString_Unchanged()
    {
        Assert.Equal("hello", ProcessLineageAnalyzer.Truncate("hello", 120));
    }

    [Fact]
    public void Truncate_ExactLength_Unchanged()
    {
        var s = new string('x', 10);
        Assert.Equal(s, ProcessLineageAnalyzer.Truncate(s, 10));
    }

    [Fact]
    public void Truncate_LongString_AppendsEllipsis()
    {
        var s = new string('x', 50);
        var result = ProcessLineageAnalyzer.Truncate(s, 10);
        Assert.Equal(new string('x', 10) + "...", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Truncate_NullOrEmpty_ReturnsEmptyString(string? value)
    {
        Assert.Equal(string.Empty, ProcessLineageAnalyzer.Truncate(value!, 120));
    }

    // ----------------------------------------------------------------------
    // End-to-end: the audit module still runs and produces findings
    // ----------------------------------------------------------------------

    [Fact]
    public async Task ProcessLineageAudit_RunAudit_ProducesResult()
    {
        var audit = new ProcessLineageAudit();
        var result = await audit.RunAuditAsync();

        Assert.Equal("Process Lineage Audit", audit.Name);
        Assert.Equal("Processes", audit.Category);
        Assert.NotNull(result);
        // The three checks each emit at least one finding (a Pass at minimum), so a
        // successful run is never empty. We don't assert on live process state.
        if (result.Success)
        {
            Assert.NotEmpty(result.Findings);
            Assert.All(result.Findings, f => Assert.Equal("Processes", f.Category));
        }
    }
}
