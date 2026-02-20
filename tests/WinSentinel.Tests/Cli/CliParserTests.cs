using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

public class CliParserTests
{
    [Fact]
    public void Parse_NoArgs_ReturnsNone()
    {
        var result = CliParser.Parse([]);
        Assert.Equal(CliCommand.None, result.Command);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_Help_ReturnsHelp()
    {
        var result = CliParser.Parse(["--help"]);
        Assert.Equal(CliCommand.Help, result.Command);
        Assert.True(result.ShowHelp);
        Assert.Null(result.Error);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("/?")]
    [InlineData("/h")]
    public void Parse_HelpVariants_AllReturnHelp(string arg)
    {
        var result = CliParser.Parse([arg]);
        Assert.Equal(CliCommand.Help, result.Command);
        Assert.True(result.ShowHelp);
    }

    [Fact]
    public void Parse_Version_ReturnsVersion()
    {
        var result = CliParser.Parse(["--version"]);
        Assert.Equal(CliCommand.Version, result.Command);
        Assert.True(result.ShowVersion);
    }

    [Theory]
    [InlineData("--version")]
    [InlineData("-v")]
    public void Parse_VersionVariants_AllReturnVersion(string arg)
    {
        var result = CliParser.Parse([arg]);
        Assert.Equal(CliCommand.Version, result.Command);
    }

    [Fact]
    public void Parse_Audit_ReturnsAudit()
    {
        var result = CliParser.Parse(["--audit"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.Null(result.Error);
    }

    [Theory]
    [InlineData("--audit")]
    [InlineData("-a")]
    public void Parse_AuditVariants(string arg)
    {
        var result = CliParser.Parse([arg]);
        Assert.Equal(CliCommand.Audit, result.Command);
    }

    [Fact]
    public void Parse_Score_ReturnsScore()
    {
        var result = CliParser.Parse(["--score"]);
        Assert.Equal(CliCommand.Score, result.Command);
    }

    [Theory]
    [InlineData("--score")]
    [InlineData("-s")]
    public void Parse_ScoreVariants(string arg)
    {
        var result = CliParser.Parse([arg]);
        Assert.Equal(CliCommand.Score, result.Command);
    }

    [Fact]
    public void Parse_FixAll_ReturnsFixAll()
    {
        var result = CliParser.Parse(["--fix-all"]);
        Assert.Equal(CliCommand.FixAll, result.Command);
    }

    [Theory]
    [InlineData("--fix-all")]
    [InlineData("-f")]
    public void Parse_FixAllVariants(string arg)
    {
        var result = CliParser.Parse([arg]);
        Assert.Equal(CliCommand.FixAll, result.Command);
    }

    [Fact]
    public void Parse_AuditWithJson_SetsJsonFlag()
    {
        var result = CliParser.Parse(["--audit", "--json"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Json);
    }

    [Fact]
    public void Parse_AuditWithHtml_SetsHtmlFlag()
    {
        var result = CliParser.Parse(["--audit", "--html"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Html);
    }

    [Fact]
    public void Parse_AuditWithOutputFile_SetsOutputFile()
    {
        var result = CliParser.Parse(["--audit", "--html", "-o", "report.html"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Html);
        Assert.Equal("report.html", result.OutputFile);
    }

    [Fact]
    public void Parse_AuditWithModulesFilter_SetsModulesFilter()
    {
        var result = CliParser.Parse(["--audit", "--modules", "firewall,network,privacy"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.Equal("firewall,network,privacy", result.ModulesFilter);
    }

    [Fact]
    public void Parse_AuditWithQuiet_SetsQuietFlag()
    {
        var result = CliParser.Parse(["--audit", "--quiet"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Quiet);
    }

    [Fact]
    public void Parse_AuditWithThreshold_SetsThreshold()
    {
        var result = CliParser.Parse(["--audit", "--threshold", "90"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.Equal(90, result.Threshold);
    }

    [Fact]
    public void Parse_InvalidThreshold_ReturnsError()
    {
        var result = CliParser.Parse(["--audit", "--threshold", "abc"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Invalid threshold", result.Error);
    }

    [Fact]
    public void Parse_ThresholdOutOfRange_ReturnsError()
    {
        var result = CliParser.Parse(["--audit", "--threshold", "150"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Invalid threshold", result.Error);
    }

    [Fact]
    public void Parse_MissingOutputValue_ReturnsError()
    {
        var result = CliParser.Parse(["--audit", "-o"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing value", result.Error);
    }

    [Fact]
    public void Parse_MissingModulesValue_ReturnsError()
    {
        var result = CliParser.Parse(["--audit", "--modules"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing value", result.Error);
    }

    [Fact]
    public void Parse_MissingThresholdValue_ReturnsError()
    {
        var result = CliParser.Parse(["--audit", "--threshold"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing value", result.Error);
    }

    [Fact]
    public void Parse_UnknownOption_ReturnsError()
    {
        var result = CliParser.Parse(["--unknown"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Unknown option", result.Error);
    }

    [Fact]
    public void Parse_JsonOnly_DefaultsToAudit()
    {
        var result = CliParser.Parse(["--json"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Json);
    }

    [Fact]
    public void Parse_QuietOnly_DefaultsToAudit()
    {
        var result = CliParser.Parse(["--quiet"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Quiet);
    }

    [Fact]
    public void Parse_ModulesOnly_DefaultsToAudit()
    {
        var result = CliParser.Parse(["--modules", "firewall"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.Equal("firewall", result.ModulesFilter);
    }

    [Fact]
    public void Parse_ComplexCommand_AllFlagsSet()
    {
        var result = CliParser.Parse(["--audit", "--json", "--modules", "firewall,network", "--threshold", "85", "-o", "out.json"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Json);
        Assert.Equal("firewall,network", result.ModulesFilter);
        Assert.Equal(85, result.Threshold);
        Assert.Equal("out.json", result.OutputFile);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_ShortFlags_Work()
    {
        var result = CliParser.Parse(["-a", "-j", "-q", "-m", "firewall", "-t", "80"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Json);
        Assert.True(result.Quiet);
        Assert.Equal("firewall", result.ModulesFilter);
        Assert.Equal(80, result.Threshold);
    }

    [Fact]
    public void Parse_HelpStopsProcessing()
    {
        // --help should return immediately, ignoring other args
        var result = CliParser.Parse(["--audit", "--help", "--json"]);
        // Because --help is encountered, it should still set Help
        // But actually our parser processes sequentially
        // --audit sets command to Audit, then --help overrides to Help and returns
        Assert.Equal(CliCommand.Help, result.Command);
        Assert.True(result.ShowHelp);
    }

    [Fact]
    public void Parse_VersionStopsProcessing()
    {
        var result = CliParser.Parse(["--version", "--audit"]);
        Assert.Equal(CliCommand.Version, result.Command);
        Assert.True(result.ShowVersion);
    }

    [Fact]
    public void Parse_ThresholdZero_IsValid()
    {
        var result = CliParser.Parse(["--audit", "--threshold", "0"]);
        Assert.Equal(0, result.Threshold);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_Threshold100_IsValid()
    {
        var result = CliParser.Parse(["--audit", "--threshold", "100"]);
        Assert.Equal(100, result.Threshold);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_NegativeThreshold_ReturnsError()
    {
        var result = CliParser.Parse(["--audit", "--threshold", "-5"]);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Parse_LongOutput_SetsOutputFile()
    {
        var result = CliParser.Parse(["--audit", "--output", "my-report.json"]);
        Assert.Equal("my-report.json", result.OutputFile);
    }

    [Fact]
    public void CliOptions_DefaultValues_AreCorrect()
    {
        var options = new CliOptions();
        Assert.Equal(CliCommand.None, options.Command);
        Assert.False(options.Json);
        Assert.False(options.Html);
        Assert.False(options.Quiet);
        Assert.False(options.ShowHelp);
        Assert.False(options.ShowVersion);
        Assert.False(options.Compare);
        Assert.False(options.Diff);
        Assert.Equal(30, options.HistoryDays);
        Assert.Equal(20, options.HistoryLimit);
        Assert.Null(options.OutputFile);
        Assert.Null(options.ModulesFilter);
        Assert.Null(options.Threshold);
        Assert.Null(options.Error);
    }

    // ── History Command Tests ────────────────────────────────────────

    [Fact]
    public void Parse_History_ReturnsHistory()
    {
        var result = CliParser.Parse(["--history"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryWithCompare_SetsCompareFlag()
    {
        var result = CliParser.Parse(["--history", "--compare"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.True(result.Compare);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryWithDiff_SetsDiffFlag()
    {
        var result = CliParser.Parse(["--history", "--diff"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.True(result.Diff);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryWithJson_SetsJsonFlag()
    {
        var result = CliParser.Parse(["--history", "--json"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.True(result.Json);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryWithDays_SetsDays()
    {
        var result = CliParser.Parse(["--history", "--days", "7"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.Equal(7, result.HistoryDays);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryWithLimit_SetsLimit()
    {
        var result = CliParser.Parse(["--history", "--limit", "5"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.Equal(5, result.HistoryLimit);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryWithLimitShort_SetsLimit()
    {
        var result = CliParser.Parse(["--history", "-l", "10"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.Equal(10, result.HistoryLimit);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_CompareOnly_DefaultsToHistory()
    {
        var result = CliParser.Parse(["--compare"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.True(result.Compare);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_DiffOnly_DefaultsToHistory()
    {
        var result = CliParser.Parse(["--diff"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.True(result.Diff);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryCompareWithJson_AllFlagsSet()
    {
        var result = CliParser.Parse(["--history", "--compare", "--json", "-o", "compare.json"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.True(result.Compare);
        Assert.True(result.Json);
        Assert.Equal("compare.json", result.OutputFile);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_InvalidDays_ReturnsError()
    {
        var result = CliParser.Parse(["--history", "--days", "abc"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Invalid days", result.Error);
    }

    [Fact]
    public void Parse_DaysOutOfRange_ReturnsError()
    {
        var result = CliParser.Parse(["--history", "--days", "500"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Invalid days", result.Error);
    }

    [Fact]
    public void Parse_DaysZero_ReturnsError()
    {
        var result = CliParser.Parse(["--history", "--days", "0"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Invalid days", result.Error);
    }

    [Fact]
    public void Parse_MissingDaysValue_ReturnsError()
    {
        var result = CliParser.Parse(["--history", "--days"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing value", result.Error);
    }

    [Fact]
    public void Parse_InvalidLimit_ReturnsError()
    {
        var result = CliParser.Parse(["--history", "--limit", "abc"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Invalid limit", result.Error);
    }

    [Fact]
    public void Parse_LimitOutOfRange_ReturnsError()
    {
        var result = CliParser.Parse(["--history", "--limit", "200"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Invalid limit", result.Error);
    }

    [Fact]
    public void Parse_MissingLimitValue_ReturnsError()
    {
        var result = CliParser.Parse(["--history", "-l"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing value", result.Error);
    }

    [Fact]
    public void Parse_Days1_IsValid()
    {
        var result = CliParser.Parse(["--history", "--days", "1"]);
        Assert.Equal(1, result.HistoryDays);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_Days365_IsValid()
    {
        var result = CliParser.Parse(["--history", "--days", "365"]);
        Assert.Equal(365, result.HistoryDays);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_Limit1_IsValid()
    {
        var result = CliParser.Parse(["--history", "--limit", "1"]);
        Assert.Equal(1, result.HistoryLimit);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_Limit100_IsValid()
    {
        var result = CliParser.Parse(["--history", "--limit", "100"]);
        Assert.Equal(100, result.HistoryLimit);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryDiffWithDaysAndLimit_AllOptionsSet()
    {
        var result = CliParser.Parse(["--history", "--diff", "--days", "14", "--limit", "50", "--json", "-o", "diff.json"]);
        Assert.Equal(CliCommand.History, result.Command);
        Assert.True(result.Diff);
        Assert.Equal(14, result.HistoryDays);
        Assert.Equal(50, result.HistoryLimit);
        Assert.True(result.Json);
        Assert.Equal("diff.json", result.OutputFile);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_HistoryDefaultDays_Is30()
    {
        var result = CliParser.Parse(["--history"]);
        Assert.Equal(30, result.HistoryDays);
    }

    [Fact]
    public void Parse_HistoryDefaultLimit_Is20()
    {
        var result = CliParser.Parse(["--history"]);
        Assert.Equal(20, result.HistoryLimit);
    }

    // ── Markdown Flag Tests ─────────────────────────────────────────

    [Fact]
    public void Parse_AuditWithMarkdown_SetsMarkdownFlag()
    {
        var result = CliParser.Parse(["--audit", "--markdown"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Markdown);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_AuditWithMdShorthand_SetsMarkdownFlag()
    {
        var result = CliParser.Parse(["--audit", "--md"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Markdown);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_MarkdownOnly_DefaultsToAudit()
    {
        var result = CliParser.Parse(["--markdown"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Markdown);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_MdOnly_DefaultsToAudit()
    {
        var result = CliParser.Parse(["--md"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Markdown);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_MarkdownWithOutput_AllFlagsSet()
    {
        var result = CliParser.Parse(["--audit", "--markdown", "-o", "report.md"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Markdown);
        Assert.Equal("report.md", result.OutputFile);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_MarkdownWithModules_AllFlagsSet()
    {
        var result = CliParser.Parse(["--audit", "--md", "--modules", "firewall,network", "-o", "sec.md"]);
        Assert.Equal(CliCommand.Audit, result.Command);
        Assert.True(result.Markdown);
        Assert.Equal("firewall,network", result.ModulesFilter);
        Assert.Equal("sec.md", result.OutputFile);
        Assert.Null(result.Error);
    }

    [Fact]
    public void CliOptions_MarkdownDefault_IsFalse()
    {
        var options = new CliOptions();
        Assert.False(options.Markdown);
    }

    // ── Baseline Command Tests ──

    [Fact]
    public void Parse_BaselineSave_ParsesNameCorrectly()
    {
        var result = CliParser.Parse(["--baseline", "save", "production"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.Save, result.BaselineAction);
        Assert.Equal("production", result.BaselineName);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineList_Works()
    {
        var result = CliParser.Parse(["--baseline", "list"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.List, result.BaselineAction);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineCheck_ParsesName()
    {
        var result = CliParser.Parse(["--baseline", "check", "my-baseline"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.Check, result.BaselineAction);
        Assert.Equal("my-baseline", result.BaselineName);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineDelete_ParsesName()
    {
        var result = CliParser.Parse(["--baseline", "delete", "old-baseline"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.Delete, result.BaselineAction);
        Assert.Equal("old-baseline", result.BaselineName);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineNoAction_DefaultsList()
    {
        var result = CliParser.Parse(["--baseline"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.List, result.BaselineAction);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineInvalidAction_ReturnsError()
    {
        var result = CliParser.Parse(["--baseline", "invalid"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Unknown baseline action", result.Error);
    }

    [Fact]
    public void Parse_BaselineSave_MissingName_ReturnsError()
    {
        var result = CliParser.Parse(["--baseline", "save"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing baseline name", result.Error);
    }

    [Fact]
    public void Parse_BaselineCheck_MissingName_ReturnsError()
    {
        var result = CliParser.Parse(["--baseline", "check"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing baseline name", result.Error);
    }

    [Fact]
    public void Parse_BaselineDelete_MissingName_ReturnsError()
    {
        var result = CliParser.Parse(["--baseline", "delete"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing baseline name", result.Error);
    }

    [Fact]
    public void Parse_BaselineSave_WithDesc()
    {
        var result = CliParser.Parse(["--baseline", "save", "prod", "--desc", "After hardening"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.Save, result.BaselineAction);
        Assert.Equal("prod", result.BaselineName);
        Assert.Equal("After hardening", result.BaselineDescription);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineSave_WithForce()
    {
        var result = CliParser.Parse(["--baseline", "save", "prod", "--force"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.True(result.Force);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineCheck_WithJson()
    {
        var result = CliParser.Parse(["--baseline", "check", "prod", "--json"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.Check, result.BaselineAction);
        Assert.True(result.Json);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineCheck_WithJsonOutput()
    {
        var result = CliParser.Parse(["--baseline", "check", "prod", "--json", "-o", "result.json"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal(BaselineAction.Check, result.BaselineAction);
        Assert.True(result.Json);
        Assert.Equal("result.json", result.OutputFile);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_BaselineSave_WithModulesFilter()
    {
        var result = CliParser.Parse(["--baseline", "save", "fw-only", "--modules", "firewall"]);
        Assert.Equal(CliCommand.Baseline, result.Command);
        Assert.Equal("firewall", result.ModulesFilter);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_DescMissingValue_ReturnsError()
    {
        var result = CliParser.Parse(["--baseline", "save", "test", "--desc"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing value for --desc", result.Error);
    }

    [Fact]
    public void Parse_BaselineSave_NameNotFlag()
    {
        // Make sure --json after "save" is not treated as the name
        var result = CliParser.Parse(["--baseline", "save", "--json"]);
        Assert.NotNull(result.Error);
        Assert.Contains("Missing baseline name", result.Error);
    }

    [Fact]
    public void CliOptions_BaselineDefaults()
    {
        var options = new CliOptions();
        Assert.Equal(BaselineAction.None, options.BaselineAction);
        Assert.Null(options.BaselineName);
        Assert.Null(options.BaselineDescription);
        Assert.False(options.Force);
    }

    // ── Checklist Command Tests ─────────────────────────────────────

    [Fact]
    public void Parse_Checklist_ReturnsChecklist()
    {
        var result = CliParser.Parse(["--checklist"]);
        Assert.Equal(CliCommand.Checklist, result.Command);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_ChecklistWithJson_ReturnsChecklist()
    {
        var result = CliParser.Parse(["--checklist", "--json"]);
        Assert.Equal(CliCommand.Checklist, result.Command);
        Assert.True(result.Json);
    }

    [Fact]
    public void Parse_ChecklistWithModules_ReturnsChecklist()
    {
        var result = CliParser.Parse(["--checklist", "-m", "firewall,network"]);
        Assert.Equal(CliCommand.Checklist, result.Command);
        Assert.Equal("firewall,network", result.ModulesFilter);
    }

    [Fact]
    public void Parse_ChecklistWithOutput_ReturnsChecklist()
    {
        var result = CliParser.Parse(["--checklist", "--json", "-o", "plan.json"]);
        Assert.Equal(CliCommand.Checklist, result.Command);
        Assert.True(result.Json);
        Assert.Equal("plan.json", result.OutputFile);
    }

    [Fact]
    public void Parse_ChecklistWithQuiet_ReturnsChecklist()
    {
        var result = CliParser.Parse(["--checklist", "--quiet"]);
        Assert.Equal(CliCommand.Checklist, result.Command);
        Assert.True(result.Quiet);
    }
}
