using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Tests for `winsentinel export &lt;format&gt;` (Free roadmap F11).
/// Format may be supplied positionally or via --format. Aliases (md, yml) normalized.
/// Unknown / missing formats are caught at parse time (Error set) or at handler time.
/// </summary>
public class ExportCliParserTests
{
    [Fact]
    public void Parse_ExportNoFormat_ParsesAsExportWithEmptyFormat()
    {
        // Handler emits the "Missing format" error so the parser allows None here.
        var result = CliParser.Parse(["export"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Null(result.ExportFormat);
        Assert.Null(result.Error);
    }

    [Theory]
    [InlineData("json")]
    [InlineData("csv")]
    [InlineData("sarif")]
    [InlineData("markdown")]
    [InlineData("md")]
    public void Parse_ExportWithPositionalFormat_StoresLowercaseFormat(string fmt)
    {
        var result = CliParser.Parse(["export", fmt]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal(fmt.ToLowerInvariant(), result.ExportFormat);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_ExportFormatUppercase_IsNormalizedToLower()
    {
        var result = CliParser.Parse(["export", "JSON"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal("json", result.ExportFormat);
    }

    [Fact]
    public void Parse_ExportWithFormatFlag_StoresFormat()
    {
        var result = CliParser.Parse(["export", "--format", "sarif"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal("sarif", result.ExportFormat);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_FormatFlagOverridesPositional()
    {
        // --format wins when supplied alongside a positional.
        var result = CliParser.Parse(["export", "json", "--format", "csv"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal("csv", result.ExportFormat);
    }

    [Fact]
    public void Parse_FormatFlagMissingValue_ReturnsError()
    {
        var result = CliParser.Parse(["export", "--format"]);
        Assert.NotNull(result.Error);
        Assert.Contains("--format", result.Error);
    }

    [Fact]
    public void Parse_ExportWithOutputFile_StoresPath()
    {
        var result = CliParser.Parse(["export", "json", "-o", "report.json"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal("json", result.ExportFormat);
        Assert.Equal("report.json", result.OutputFile);
    }

    [Fact]
    public void Parse_ExportWithLongOutputFlag_StoresPath()
    {
        var result = CliParser.Parse(["export", "csv", "--output", "findings.csv"]);
        Assert.Equal("findings.csv", result.OutputFile);
    }

    [Fact]
    public void Parse_ExportWithIncludePass_SetsFlag()
    {
        var result = CliParser.Parse(["export", "sarif", "--include-pass"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.True(result.ExportIncludePass);
    }

    [Fact]
    public void Parse_ExportWithoutIncludePass_DefaultsFalse()
    {
        var result = CliParser.Parse(["export", "json"]);
        Assert.False(result.ExportIncludePass);
    }

    [Fact]
    public void Parse_ExportWithModulesFilter_StoresFilter()
    {
        var result = CliParser.Parse(["export", "json", "--modules", "firewall,bitlocker"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal("firewall,bitlocker", result.ModulesFilter);
    }

    [Fact]
    public void Parse_ExportWithQuiet_StoresQuiet()
    {
        var result = CliParser.Parse(["export", "csv", "--quiet"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.True(result.Quiet);
    }

    [Fact]
    public void Parse_ExportUnknownFormat_ParsesButLeavesFormatString()
    {
        // Validation lives in the handler (HandleExport) so unknown values
        // reach the handler verbatim and trigger a user-friendly error there.
        var result = CliParser.Parse(["export", "yaml"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal("yaml", result.ExportFormat);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_ExportFlagBeforePositional_AllArgsConsumed()
    {
        // export --format json -o out.json --include-pass
        var result = CliParser.Parse(["export", "--format", "json", "-o", "out.json", "--include-pass"]);
        Assert.Equal(CliCommand.Export, result.Command);
        Assert.Equal("json", result.ExportFormat);
        Assert.Equal("out.json", result.OutputFile);
        Assert.True(result.ExportIncludePass);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_ExportDoesNotCollideWithPolicyExport()
    {
        // `--policy export <file>` is a separate path. `export` alone must not
        // accidentally claim the policy subcommand.
        var result = CliParser.Parse(["--policy", "export", "policy.json"]);
        Assert.Equal(CliCommand.Policy, result.Command);
        Assert.NotEqual(CliCommand.Export, result.Command);
    }

    [Fact]
    public void Parse_ExportWithoutOutput_LeavesOutputNull()
    {
        var result = CliParser.Parse(["export", "json"]);
        Assert.Null(result.OutputFile);
    }
}
