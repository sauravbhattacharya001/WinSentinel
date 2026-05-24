using System;
using Xunit;
using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Parser coverage for the `pro` command surface and the global `--license` flag
/// (CLI roadmap item #6 \u2014 license activation / status / trial).
/// </summary>
public class ProCliParserTests
{
    [Fact]
    public void Bare_Pro_Defaults_To_Status()
    {
        var opts = CliParser.Parse(new[] { "pro" });
        Assert.Null(opts.Error);
        Assert.Equal(CliCommand.Pro, opts.Command);
        Assert.Equal(ProAction.Status, opts.ProAction);
    }

    [Theory]
    [InlineData("status", ProAction.Status)]
    [InlineData("activate", ProAction.Activate)]
    [InlineData("deactivate", ProAction.Deactivate)]
    [InlineData("start-trial", ProAction.StartTrial)]
    [InlineData("trial", ProAction.StartTrial)]
    [InlineData("help", ProAction.Help)]
    public void Pro_Subcommands_Map_Correctly(string sub, ProAction expected)
    {
        var opts = CliParser.Parse(new[] { "pro", sub });
        Assert.Null(opts.Error);
        Assert.Equal(CliCommand.Pro, opts.Command);
        Assert.Equal(expected, opts.ProAction);
    }

    [Fact]
    public void Pro_UnknownSubcommand_SetsError()
    {
        var opts = CliParser.Parse(new[] { "pro", "rename" });
        Assert.NotNull(opts.Error);
        Assert.Contains("rename", opts.Error);
    }

    [Fact]
    public void Pro_Activate_CapturesKeyAndOptions()
    {
        var opts = CliParser.Parse(new[] {
            "pro", "activate", "WSP-ABCD-EFGH-JKMN",
            "--pro-tier", "team",
            "--pro-email", "buyer@example.com",
            "--pro-expires", "2027-06-01",
        });
        Assert.Null(opts.Error);
        Assert.Equal(CliCommand.Pro, opts.Command);
        Assert.Equal(ProAction.Activate, opts.ProAction);
        Assert.Equal("WSP-ABCD-EFGH-JKMN", opts.ProKey);
        Assert.Equal("team", opts.ProTier);
        Assert.Equal("buyer@example.com", opts.ProEmail);
        Assert.NotNull(opts.ProExpiresAt);
        Assert.Equal(2027, opts.ProExpiresAt!.Value.Year);
    }

    [Fact]
    public void Pro_Format_AcceptsJson()
    {
        var opts = CliParser.Parse(new[] { "pro", "status", "--pro-format", "json" });
        Assert.Null(opts.Error);
        Assert.Equal("json", opts.ProFormat);
    }

    [Fact]
    public void Pro_Format_RejectsUnknown()
    {
        var opts = CliParser.Parse(new[] { "pro", "status", "--pro-format", "yaml" });
        Assert.NotNull(opts.Error);
        Assert.Contains("--pro-format", opts.Error);
    }

    [Fact]
    public void Pro_Expires_BadDate_SetsError()
    {
        var opts = CliParser.Parse(new[] { "pro", "activate", "WSP-ABCD-EFGH-JKMN", "--pro-expires", "never" });
        Assert.NotNull(opts.Error);
        Assert.Contains("--pro-expires", opts.Error);
    }

    [Fact]
    public void GlobalLicense_Flag_Capture()
    {
        var opts = CliParser.Parse(new[] { "--license", "WSP-ABCD-EFGH-JKMN", "--audit" });
        Assert.Null(opts.Error);
        Assert.Equal(CliCommand.Audit, opts.Command);
        Assert.Equal("WSP-ABCD-EFGH-JKMN", opts.TransientLicenseKey);
    }

    [Fact]
    public void GlobalLicense_Flag_MissingValue_SetsError()
    {
        var opts = CliParser.Parse(new[] { "--license" });
        Assert.NotNull(opts.Error);
        Assert.Contains("--license", opts.Error);
    }

    [Fact]
    public void GlobalLicense_Flag_RejectsFlagAsValue()
    {
        var opts = CliParser.Parse(new[] { "--license", "--audit" });
        Assert.NotNull(opts.Error);
    }
}
