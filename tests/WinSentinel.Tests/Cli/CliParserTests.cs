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
        Assert.Null(options.OutputFile);
        Assert.Null(options.ModulesFilter);
        Assert.Null(options.Threshold);
        Assert.Null(options.Error);
    }
}
