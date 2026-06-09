// SPDX-License-Identifier: Apache-2.0
using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Tests for <see cref="ExportCommandHelpers"/>, the unit-testable core of
/// <c>winsentinel export</c> (F11).
///
/// Covers:
/// <list type="bullet">
///   <item>Explicit format wins (positional or <c>--format</c>).</item>
///   <item>Flag inference (<c>--json</c> / <c>--csv</c> / <c>--sarif</c> / <c>--markdown</c>).</item>
///   <item>Default to JSON when nothing is supplied (CI-friendly).</item>
///   <item>Alias normalization (<c>md</c> -> <c>markdown</c>).</item>
///   <item>Conflict surfacing on multiple flag forms.</item>
///   <item>Auto-extension on output paths.</item>
/// </list>
/// </summary>
public class ExportCommandHelpersTests
{
    [Fact]
    public void ResolveExportFormat_ExplicitFormatWins()
    {
        var opts = new CliOptions { ExportFormat = "sarif", Json = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("sarif", fmt);
    }

    [Fact]
    public void ResolveExportFormat_PositionalNormalizedToLowercase()
    {
        var opts = new CliOptions { ExportFormat = "JSON" };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("json", fmt);
    }

    [Theory]
    [InlineData("md", "markdown")]
    [InlineData("yml", "yaml")]
    public void ResolveExportFormat_NormalizesAliases(string input, string expected)
    {
        var opts = new CliOptions { ExportFormat = input };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal(expected, fmt);
    }

    [Fact]
    public void ResolveExportFormat_NothingSupplied_DefaultsToJson()
    {
        var opts = new CliOptions();
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("json", fmt);
    }

    [Fact]
    public void ResolveExportFormat_JsonFlagAlone_ResolvesJson()
    {
        var opts = new CliOptions { Json = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("json", fmt);
    }

    [Fact]
    public void ResolveExportFormat_CsvFlagAlone_ResolvesCsv()
    {
        var opts = new CliOptions { Csv = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("csv", fmt);
    }

    [Fact]
    public void ResolveExportFormat_SarifFlagAlone_ResolvesSarif()
    {
        var opts = new CliOptions { Sarif = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("sarif", fmt);
    }

    [Fact]
    public void ResolveExportFormat_MarkdownFlagAlone_ResolvesMarkdown()
    {
        var opts = new CliOptions { Markdown = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("markdown", fmt);
    }

    [Fact]
    public void ResolveExportFormat_TwoFlags_ReturnsConflictError()
    {
        var opts = new CliOptions { Json = true, Sarif = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(fmt);
        Assert.NotNull(err);
        Assert.Contains("Conflicting format flags", err);
        Assert.Contains("--json", err);
        Assert.Contains("--sarif", err);
    }

    [Fact]
    public void ResolveExportFormat_FourFlags_ListsAllInError()
    {
        var opts = new CliOptions { Json = true, Sarif = true, Csv = true, Markdown = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(fmt);
        Assert.NotNull(err);
        Assert.Contains("--json", err);
        Assert.Contains("--sarif", err);
        Assert.Contains("--csv", err);
        Assert.Contains("--markdown", err);
    }

    [Fact]
    public void ResolveExportFormat_EmptyExplicitFormat_FallsThroughToFlags()
    {
        // Whitespace-only / empty ExportFormat should not block flag inference.
        var opts = new CliOptions { ExportFormat = "   ", Csv = true };
        var (fmt, err) = ExportCommandHelpers.ResolveExportFormat(opts);
        Assert.Null(err);
        Assert.Equal("csv", fmt);
    }

    [Theory]
    [InlineData("json", ".json")]
    [InlineData("csv", ".csv")]
    [InlineData("sarif", ".sarif")]
    [InlineData("markdown", ".md")]
    public void ExtensionForFormat_KnownFormats(string fmt, string expected)
    {
        Assert.Equal(expected, ExportCommandHelpers.ExtensionForFormat(fmt));
    }

    [Theory]
    [InlineData("yaml")]
    [InlineData("xml")]
    [InlineData("")]
    [InlineData("unknown")]
    public void ExtensionForFormat_UnknownFormats_ReturnsEmpty(string fmt)
    {
        Assert.Equal(string.Empty, ExportCommandHelpers.ExtensionForFormat(fmt));
    }
}
