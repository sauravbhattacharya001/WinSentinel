using System;
using System.IO;
using System.Linq;
using Xunit;

namespace WinSentinel.Tests;

/// <summary>
/// Guards the published GitHub Action manifests (<c>action.yml</c> at the repo
/// root and the <c>action/action.yml</c> alias) against drift and against the
/// use of CLI flags/subcommands that do not exist in <c>winsentinel</c>.
///
/// Background: the action invokes the CLI via <c>pwsh</c>, so a typo'd flag is a
/// hard error (<c>Unknown option: ...</c>) that produces no SARIF and a 0/F
/// score for every adopter — but nothing in the .NET build catches it. These
/// tests pin the contract.
/// </summary>
public class GitHubActionManifestTests
{
    // Real CLI surface (see WinSentinel.Cli/CliParser.cs):
    //   - output file is `-o` / `--output`  (NOT `--sarif-output` / `--export-output`)
    //   - SARIF/JSON/etc. are produced by the `export <format>` command
    //   - there is no `--export` flag
    private static readonly string[] ForbiddenFlags =
    {
        "--sarif-output",
        "--export-output",
        "--export ",   // `--export <fmt>` is not a flag; `export` is a subcommand
    };

    private static string RepoRoot()
    {
        // Walk up from the test assembly until we find the repo-root marker.
        var dir = new DirectoryInfo(Path.GetDirectoryName(typeof(GitHubActionManifestTests).Assembly.Location)!);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "action.yml")) &&
                Directory.Exists(Path.Combine(dir.FullName, "src", "WinSentinel.Cli")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repo root (no action.yml + src/WinSentinel.Cli above test assembly).");
    }

    private static string RootActionPath() => Path.Combine(RepoRoot(), "action.yml");
    private static string AliasActionPath() => Path.Combine(RepoRoot(), "action", "action.yml");

    [Fact]
    public void RootActionManifest_Exists()
    {
        Assert.True(File.Exists(RootActionPath()), $"Missing action manifest at {RootActionPath()}");
    }

    [Fact]
    public void AliasAndRootManifests_AreIdentical()
    {
        // The two entry points (`owner/repo@ref` and `owner/repo/action@ref`)
        // must behave identically; the simplest guarantee is byte-equality.
        var root = File.ReadAllText(RootActionPath());
        var alias = File.ReadAllText(AliasActionPath());
        Assert.Equal(root, alias);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ActionManifest_DoesNotUseNonExistentCliFlags(bool useAlias)
    {
        var path = useAlias ? AliasActionPath() : RootActionPath();
        var text = File.ReadAllText(path);
        foreach (var flag in ForbiddenFlags)
        {
            Assert.False(text.Contains(flag, StringComparison.Ordinal),
                $"{Path.GetFileName(path)} references non-existent CLI flag '{flag.Trim()}'. " +
                "Use the `export <format> -o <file>` subcommand instead.");
        }
    }

    [Fact]
    public void ActionManifest_UsesExportSubcommandForSarif()
    {
        var text = File.ReadAllText(RootActionPath());
        // The headline feature is SARIF -> Code Scanning; it must go through the
        // silent `export sarif` command (audit chrome would corrupt a stream).
        Assert.Contains("export', 'sarif'", text, StringComparison.Ordinal);
        Assert.Contains("'-o', $sarifFile", text, StringComparison.Ordinal);
    }

    [Fact]
    public void ActionManifest_ParsesDocumentedJsonSchema()
    {
        var text = File.ReadAllText(RootActionPath());
        // Score/findings come from the documented JSON schema produced by
        // ReportGenerator.GenerateJsonReport: overallScore / summary.*.
        Assert.Contains("overallScore", text, StringComparison.Ordinal);
        Assert.Contains("summary.totalFindings", text, StringComparison.Ordinal);
        Assert.Contains("summary.critical", text, StringComparison.Ordinal);
    }

    [Fact]
    public void ActionManifest_UploadsSarifOnlyWhenProduced()
    {
        var text = File.ReadAllText(RootActionPath());
        // Guard against uploading a path that was never written.
        Assert.Contains("upload-sarif@v3", text, StringComparison.Ordinal);
        Assert.Contains("steps.audit.outputs.sarif_file != ''", text, StringComparison.Ordinal);
    }
}
