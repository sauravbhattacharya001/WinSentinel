using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Tests for `winsentinel self-update` (Free roadmap F15).
/// Parser-level only: the actual NuGet HTTP / dotnet process call is integration-tested
/// out-of-band on Shubho's box (smoke). These tests pin the wire-level flag handling
/// plus the pure helpers in <see cref="SelfUpdateCommandHandler"/>.
/// </summary>
public class SelfUpdateCliParserTests
{
    [Fact]
    public void Parse_SelfUpdate_SetsCommand()
    {
        var result = CliParser.Parse(["self-update"]);
        Assert.Equal(CliCommand.SelfUpdate, result.Command);
        Assert.False(result.SelfUpdateCheckOnly);
        Assert.Null(result.SelfUpdateSource);
        Assert.Null(result.SelfUpdateVersion);
        Assert.False(result.SelfUpdatePrerelease);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_SelfUpdateNoHyphenAlias_Works()
    {
        // We accept the conventional `self-update` plus the hyphen-free
        // `selfupdate` alias so users don't get an unhelpful error for a typo.
        var result = CliParser.Parse(["selfupdate"]);
        Assert.Equal(CliCommand.SelfUpdate, result.Command);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_SelfUpdateCheck_SetsCheckOnly()
    {
        var result = CliParser.Parse(["self-update", "--check"]);
        Assert.Equal(CliCommand.SelfUpdate, result.Command);
        Assert.True(result.SelfUpdateCheckOnly);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_SelfUpdateSource_StoresFeed()
    {
        var result = CliParser.Parse(["self-update", "--source", "https://api.nuget.org/v3/index.json"]);
        Assert.Equal(CliCommand.SelfUpdate, result.Command);
        Assert.Equal("https://api.nuget.org/v3/index.json", result.SelfUpdateSource);
    }

    [Fact]
    public void Parse_SelfUpdateSourceMissingValue_ReturnsError()
    {
        var result = CliParser.Parse(["self-update", "--source"]);
        Assert.NotNull(result.Error);
        Assert.Contains("--source", result.Error);
    }

    [Fact]
    public void Parse_SelfUpdateTo_StoresExplicitVersion()
    {
        // `--to 1.16.2` is preferred over piggy-backing on `--version` (which
        // is the top-level "print version banner" flag and would otherwise be
        // swallowed by the version handler).
        var result = CliParser.Parse(["self-update", "--to", "1.16.2"]);
        Assert.Equal(CliCommand.SelfUpdate, result.Command);
        Assert.Equal("1.16.2", result.SelfUpdateVersion);
    }

    [Fact]
    public void Parse_SelfUpdateToMissingValue_ReturnsError()
    {
        var result = CliParser.Parse(["self-update", "--to"]);
        Assert.NotNull(result.Error);
        Assert.Contains("--to", result.Error);
    }

    [Fact]
    public void Parse_SelfUpdatePrerelease_SetsFlag()
    {
        var result = CliParser.Parse(["self-update", "--prerelease"]);
        Assert.Equal(CliCommand.SelfUpdate, result.Command);
        Assert.True(result.SelfUpdatePrerelease);
    }

    [Fact]
    public void Parse_SelfUpdateCombinedFlags_AllSet()
    {
        var result = CliParser.Parse([
            "self-update", "--check", "--source", "https://nuget.example/v3", "--to", "1.16.2", "--prerelease"
        ]);
        Assert.Equal(CliCommand.SelfUpdate, result.Command);
        Assert.True(result.SelfUpdateCheckOnly);
        Assert.Equal("https://nuget.example/v3", result.SelfUpdateSource);
        Assert.Equal("1.16.2", result.SelfUpdateVersion);
        Assert.True(result.SelfUpdatePrerelease);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Parse_SelfUpdateWithQuietAndJson_AreCarried()
    {
        var result = CliParser.Parse(["self-update", "--check", "--json"]);
        Assert.True(result.Json);
        Assert.True(result.SelfUpdateCheckOnly);
    }

    [Fact]
    public void Parse_SelfUpdateDoesNotShadowVersionCommand()
    {
        // `--version` remains the top-level "print version" command and must
        // not be silently captured as the self-update --to value.
        var result = CliParser.Parse(["--version"]);
        Assert.Equal(CliCommand.Version, result.Command);
    }

    [Fact]
    public void BuildToolUpdateArgs_DefaultIsGlobalUpdate()
    {
        var opts = new CliOptions { Command = CliCommand.SelfUpdate };
        var args = SelfUpdateCommandHandler.BuildToolUpdateArgs(opts);
        Assert.Equal(new[] { "tool", "update", "--global", "WinSentinel.Cli" }, args);
    }

    [Fact]
    public void BuildToolUpdateArgs_PassesSourceVersionPrerelease()
    {
        var opts = new CliOptions
        {
            Command = CliCommand.SelfUpdate,
            SelfUpdateSource = "https://nuget.example/v3",
            SelfUpdateVersion = "1.16.2",
            SelfUpdatePrerelease = true,
        };
        var args = SelfUpdateCommandHandler.BuildToolUpdateArgs(opts);
        Assert.Equal(new[]
        {
            "tool", "update", "--global", "WinSentinel.Cli",
            "--source", "https://nuget.example/v3",
            "--version", "1.16.2",
            "--prerelease",
        }, args);
    }

    [Theory]
    [InlineData("1.0.0", "0.9.9", true)]
    [InlineData("1.16.2", "1.16.1", true)]
    [InlineData("1.16.1", "1.16.1", false)]
    [InlineData("1.16.0", "1.16.1", false)]
    [InlineData("2.0.0", "1.99.99", true)]
    public void IsNewerVersion_HandlesNumericOrdering(string candidate, string current, bool expected)
    {
        Assert.Equal(expected, SelfUpdateCommandHandler.IsNewerVersion(candidate, current));
    }

    [Fact]
    public void IsNewerVersion_PrereleaseIsOlderThanRelease()
    {
        // SemVer: 1.0.0-beta < 1.0.0
        Assert.False(SelfUpdateCommandHandler.IsNewerVersion("1.0.0-beta", "1.0.0"));
        Assert.True(SelfUpdateCommandHandler.IsNewerVersion("1.0.0", "1.0.0-beta"));
    }

    [Fact]
    public void IsNewerVersion_EmptyCurrentAlwaysWins()
    {
        Assert.True(SelfUpdateCommandHandler.IsNewerVersion("1.0.0", ""));
    }

    [Fact]
    public void IsNewerVersion_EmptyCandidateIsNeverNewer()
    {
        Assert.False(SelfUpdateCommandHandler.IsNewerVersion("", "1.0.0"));
    }

    [Fact]
    public void GetCurrentVersion_ReturnsNonEmptyStringWithoutBuildMetadata()
    {
        var v = SelfUpdateCommandHandler.GetCurrentVersion();
        Assert.False(string.IsNullOrWhiteSpace(v));
        Assert.DoesNotContain("+", v);
    }
}
