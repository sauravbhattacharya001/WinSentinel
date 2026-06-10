using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Unit tests for <see cref="ProcessLineageAnalyzer"/> — the pure, I/O-free logic
/// behind the <see cref="ProcessLineageAudit"/> module (the only audit module that
/// previously had no test coverage). Covers WMI line parsing, suspicious parent->child
/// rule matching, safe-exclusion handling, and severity-grouped finding generation.
///
/// All tests are deterministic and exercise the security-relevant decision logic
/// directly, without spawning PowerShell or touching live process state.
/// </summary>
public class ProcessLineageAnalyzerTests
{
    // ----------------------------------------------------------------------
    // ParseProcessLine
    // ----------------------------------------------------------------------

    [Fact]
    public void ParseProcessLine_WellFormed_AllFields()
    {
        var r = ProcessLineageAnalyzer.ParseProcessLine("powershell|1234|winword|999|powershell -enc ABCD");
        Assert.NotNull(r);
        Assert.Equal("powershell", r!.ChildName);
        Assert.Equal(1234, r.ChildPid);
        Assert.Equal("winword", r.ParentName);
        Assert.Equal(999, r.ParentPid);
        Assert.Equal("powershell -enc ABCD", r.CommandLine);
    }

    [Fact]
    public void ParseProcessLine_NoCommandLine_FourFields_EmptyCommand()
    {
        var r = ProcessLineageAnalyzer.ParseProcessLine("cmd|10|explorer|20");
        Assert.NotNull(r);
        Assert.Equal("cmd", r!.ChildName);
        Assert.Equal(string.Empty, r.CommandLine);
    }

    [Fact]
    public void ParseProcessLine_CommandLineWithPipes_PreservedByLimitedSplit()
    {
        // Split('|', 5) keeps everything after the 4th pipe intact so trailing
        // command-line content is never lost even if a stray pipe slips through.
        var r = ProcessLineageAnalyzer.ParseProcessLine("cmd|1|explorer|2|a | b | c");
        Assert.NotNull(r);
        Assert.Equal("a | b | c", r!.CommandLine);
    }

    [Fact]
    public void ParseProcessLine_TrimsWhitespace()
    {
        var r = ProcessLineageAnalyzer.ParseProcessLine("  cmd | 1 | explorer | 2 | foo ");
        Assert.NotNull(r);
        Assert.Equal("cmd", r!.ChildName);
        Assert.Equal(1, r.ChildPid);
        Assert.Equal("explorer", r.ParentName);
        Assert.Equal("foo", r.CommandLine);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("onlythree|1|2")]               // < 4 fields
    [InlineData("|1|explorer|2")]               // empty child name
    [InlineData("cmd|1||2")]                     // empty parent name
    [InlineData("cmd|notanint|explorer|2")]      // bad child pid
    [InlineData("cmd|1|explorer|notanint")]      // bad parent pid
    public void ParseProcessLine_Malformed_ReturnsNull(string? line)
    {
        Assert.Null(ProcessLineageAnalyzer.ParseProcessLine(line));
    }

    [Fact]
    public void ParseProcessLines_MixedValidAndJunk_KeepsOnlyValid()
    {
        var output = string.Join("\n", new[]
        {
            "winword|100|explorer|50|opened doc",   // valid
            "garbage line with no pipes",            // invalid
            "",                                       // blank
            "cmd|notint|explorer|2",                 // invalid pid
            "powershell|200|winword|100|enc",        // valid
        });

        var records = ProcessLineageAnalyzer.ParseProcessLines(output);
        Assert.Equal(2, records.Count);
        Assert.Equal("winword", records[0].ChildName);
        Assert.Equal("powershell", records[1].ChildName);
    }

    [Fact]
    public void ParseProcessLines_HandlesCrLf()
    {
        var output = "cmd|1|explorer|2|x\r\npowershell|3|cmd|1|y\r\n";
        var records = ProcessLineageAnalyzer.ParseProcessLines(output);
        Assert.Equal(2, records.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ParseProcessLines_NullOrEmpty_ReturnsEmpty(string? output)
    {
        Assert.Empty(ProcessLineageAnalyzer.ParseProcessLines(output));
    }

    // ----------------------------------------------------------------------
    // ParseOrphanLine / ParseDeepNestLine
    // ----------------------------------------------------------------------

    [Fact]
    public void ParseOrphanLine_WellFormed()
    {
        var r = ProcessLineageAnalyzer.ParseOrphanLine("malware|4321|9999");
        Assert.NotNull(r);
        Assert.Equal("malware", r!.Name);
        Assert.Equal(4321, r.Pid);
        Assert.Equal(9999, r.ParentPid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("name|1")]            // too few fields
    [InlineData("|1|2")]              // empty name
    [InlineData("name|x|2")]          // bad pid
    [InlineData("name|1|y")]          // bad parent pid
    public void ParseOrphanLine_Malformed_ReturnsNull(string? line)
    {
        Assert.Null(ProcessLineageAnalyzer.ParseOrphanLine(line));
    }

    [Fact]
    public void ParseDeepNestLine_WellFormed()
    {
        var r = ProcessLineageAnalyzer.ParseDeepNestLine("powershell|555|4");
        Assert.NotNull(r);
        Assert.Equal("powershell", r!.Name);
        Assert.Equal(555, r.Pid);
        Assert.Equal(4, r.Depth);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("name|1")]
    [InlineData("|1|2")]
    [InlineData("name|1|notdepth")]
    public void ParseDeepNestLine_Malformed_ReturnsNull(string? line)
    {
        Assert.Null(ProcessLineageAnalyzer.ParseDeepNestLine(line));
    }

    [Fact]
    public void ParseOrphanLines_And_ParseDeepNestLines_DropJunk()
    {
        var orphans = ProcessLineageAnalyzer.ParseOrphanLines("a|1|2\njunk\nb|3|4");
        Assert.Equal(2, orphans.Count);

        var deep = ProcessLineageAnalyzer.ParseDeepNestLines("a|1|3\njunk\nb|2|5");
        Assert.Equal(2, deep.Count);
        Assert.Equal(5, deep[1].Depth);
    }

    // ----------------------------------------------------------------------
    // Rule matching -- the core security logic
    // ----------------------------------------------------------------------

    [Fact]
    public void MatchRecord_OfficeSpawningPowerShell_IsCritical()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "winword", 2, "");
        var match = ProcessLineageAnalyzer.MatchRecord(rec);
        Assert.NotNull(match);
        Assert.Equal(Severity.Critical, match!.Rule.Severity);
        Assert.Contains("Office", match.Rule.Title);
        Assert.Contains("T1204", match.Rule.MitreId);
    }

    [Fact]
    public void MatchRecord_BrowserSpawningCmd_IsCritical()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("cmd", 1, "chrome", 2, "");
        var match = ProcessLineageAnalyzer.MatchRecord(rec);
        Assert.NotNull(match);
        Assert.Equal(Severity.Critical, match!.Rule.Severity);
        Assert.Contains("Browser", match.Rule.Title);
    }

    [Fact]
    public void MatchRecord_WmiSpawningPowerShell_IsCritical()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "wmiprvse", 2, "");
        var match = ProcessLineageAnalyzer.MatchRecord(rec);
        Assert.NotNull(match);
        Assert.Equal(Severity.Critical, match!.Rule.Severity);
        Assert.Contains("WMI", match.Rule.Title);
    }

    [Fact]
    public void MatchRecord_ScriptEngineDownloading_IsCritical()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("certutil", 1, "powershell", 2, "");
        var match = ProcessLineageAnalyzer.MatchRecord(rec);
        Assert.NotNull(match);
        // certutil child under a script-engine parent matches "Script Engine Downloading
        // Content" (Critical), which precedes the "LOLBin Abuse: certutil" (Warning) rule;
        // first match wins.
        Assert.Equal(Severity.Critical, match!.Rule.Severity);
        Assert.Contains("Downloading", match.Rule.Title);
    }

    [Fact]
    public void MatchRecord_CmdSpawningCertutil_IsWarning()
    {
        // cmd is not a script-engine parent for the Critical download rule, so this falls
        // through to the Warning "LOLBin Abuse: certutil" rule.
        var rec = new ProcessLineageAnalyzer.ProcessRecord("certutil", 1, "cmd", 2, "");
        var match = ProcessLineageAnalyzer.MatchRecord(rec);
        Assert.NotNull(match);
        Assert.Equal(Severity.Warning, match!.Rule.Severity);
        Assert.Contains("certutil", match.Rule.Title);
    }

    [Fact]
    public void MatchRecord_CmdSpawningPowerShell_IsInfo()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("powershell", 1, "cmd", 2, "");
        var match = ProcessLineageAnalyzer.MatchRecord(rec);
        Assert.NotNull(match);
        Assert.Equal(Severity.Info, match!.Rule.Severity);
    }

    [Fact]
    public void MatchRecord_BenignPair_NoMatch()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("notepad", 1, "explorer", 2, "");
        Assert.Null(ProcessLineageAnalyzer.MatchRecord(rec));
    }

    [Fact]
    public void MatchRecord_IsCaseInsensitive()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("POWERSHELL", 1, "WINWORD", 2, "");
        var match = ProcessLineageAnalyzer.MatchRecord(rec);
        Assert.NotNull(match);
        Assert.Equal(Severity.Critical, match!.Rule.Severity);
    }

    [Fact]
    public void MatchRecord_SafeExclusion_ExplorerCmd_IsSuppressed()
    {
        // explorer->cmd would otherwise match the Info "Explorer Spawning Command Interpreter"
        // rule, but it's on the safe-exclusion allow-list (user right-click -> open command window).
        var rec = new ProcessLineageAnalyzer.ProcessRecord("cmd", 1, "explorer", 2, "");
        Assert.Null(ProcessLineageAnalyzer.MatchRecord(rec));
    }

    [Fact]
    public void MatchRecord_SafeExclusion_IsCaseInsensitive()
    {
        var rec = new ProcessLineageAnalyzer.ProcessRecord("CMD", 1, "Explorer", 2, "");
        Assert.Null(ProcessLineageAnalyzer.MatchRecord(rec));
    }

    [Fact]
    public void IsSafeExclusion_KnownPairs()
    {
        Assert.True(ProcessLineageAnalyzer.IsSafeExclusion("explorer", "cmd"));
        Assert.True(ProcessLineageAnalyzer.IsSafeExclusion("services", "svchost"));
        Assert.True(ProcessLineageAnalyzer.IsSafeExclusion("svchost", "taskhostw"));
        Assert.False(ProcessLineageAnalyzer.IsSafeExclusion("winword", "powershell"));
    }

    [Fact]
    public void MatchRecords_PreservesInputOrder_AndSkipsNonMatches()
    {
        var records = new[]
        {
            new ProcessLineageAnalyzer.ProcessRecord("notepad", 1, "explorer", 2, ""),   // no match
            new ProcessLineageAnalyzer.ProcessRecord("powershell", 3, "winword", 4, ""), // critical
            new ProcessLineageAnalyzer.ProcessRecord("cmd", 5, "explorer", 6, ""),        // excluded
            new ProcessLineageAnalyzer.ProcessRecord("certutil", 7, "cmd", 8, ""),        // warning
        };

        var matches = ProcessLineageAnalyzer.MatchRecords(records);
        Assert.Equal(2, matches.Count);
        Assert.Equal(3, matches[0].ChildPid);   // powershell critical first
        Assert.Equal(7, matches[1].ChildPid);   // certutil warning second
    }

    [Fact]
    public void MatchRecords_Null_ReturnsEmpty()
    {
        Assert.Empty(ProcessLineageAnalyzer.MatchRecords(null!));
    }

    [Fact]
    public void Rules_AreNonEmpty_AndEveryRuleHasMitreId()
    {
        Assert.NotEmpty(ProcessLineageAnalyzer.Rules);
        Assert.All(ProcessLineageAnalyzer.Rules, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.Title));
            Assert.False(string.IsNullOrWhiteSpace(r.MitreId));
            Assert.Contains("MITRE", r.MitreId);
        });
    }
}
