using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace WinSentinel.Cli;

/// <summary>
/// Handles <c>winsentinel self-update</c> (Free roadmap F15).
///
/// Wraps <c>dotnet tool update --global WinSentinel.Cli</c>. The user can
/// already do this by hand — the point of the subcommand is to keep the
/// upgrade story discoverable from the CLI itself ("how do I upgrade?" →
/// "winsentinel self-update") and to add a <c>--check</c> path that compares
/// the running version against NuGet without performing the upgrade.
///
/// Exit codes:
/// <list type="bullet">
///   <item><c>0</c> — already up to date, or update succeeded.</item>
///   <item><c>10</c> — <c>--check</c> and an update is available.</item>
///   <item><c>2</c> — user error (bad flag, malformed version).</item>
///   <item><c>20</c> — <c>dotnet</c> SDK not found on PATH.</item>
///   <item><c>21</c> — <c>dotnet tool update</c> failed.</item>
///   <item><c>22</c> — NuGet lookup failed during <c>--check</c>.</item>
/// </list>
/// </summary>
public static class SelfUpdateCommandHandler
{
    public const string PackageId = "WinSentinel.Cli";
    public const string NuGetIndexUrlTemplate = "https://api.nuget.org/v3-flatcontainer/{0}/index.json";

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    /// <summary>
    /// Real entry point. Resolves the running version, optionally queries NuGet,
    /// and either reports availability (<c>--check</c>) or shells out to
    /// <c>dotnet tool update -g</c>.
    /// </summary>
    public static async Task<int> HandleAsync(CliOptions options)
    {
        var current = GetCurrentVersion();

        // --check: query NuGet, compare, report. Never invoke dotnet.
        if (options.SelfUpdateCheckOnly)
        {
            string? latest;
            try
            {
                latest = await TryGetLatestVersionAsync(options.SelfUpdateSource, options.SelfUpdatePrerelease).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                EmitJsonOrText(options, new
                {
                    action = "check",
                    current,
                    latest = (string?)null,
                    update_available = false,
                    error = ex.Message,
                }, $"Failed to query NuGet for {PackageId}: {ex.Message}");
                return 22;
            }

            if (string.IsNullOrEmpty(latest))
            {
                EmitJsonOrText(options, new
                {
                    action = "check",
                    current,
                    latest = (string?)null,
                    update_available = false,
                    error = "no_versions_returned",
                }, $"No versions of {PackageId} returned from NuGet. Check your --source.");
                return 22;
            }

            var newer = IsNewerVersion(latest, current);
            EmitJsonOrText(options, new
            {
                action = "check",
                current,
                latest,
                update_available = newer,
            }, newer
                ? $"Update available: {current} → {latest}. Run `winsentinel self-update` to install."
                : $"Already on the latest version ({current}).");
            return newer ? 10 : 0;
        }

        // Real update: shell out to `dotnet tool update --global <pkg>`.
        var dotnet = ResolveDotnetExecutable();
        if (dotnet == null)
        {
            EmitJsonOrText(options, new
            {
                action = "update",
                current,
                error = "dotnet_not_found",
            }, "Could not find `dotnet` on PATH. Install the .NET SDK from https://dot.net to use `self-update`.");
            return 20;
        }

        var args = BuildToolUpdateArgs(options);

        if (!options.Quiet && !options.Json)
        {
            Console.WriteLine();
            Console.WriteLine($"  winsentinel self-update");
            Console.WriteLine($"  Current: {current}");
            Console.WriteLine($"  Running: {dotnet} {string.Join(' ', args)}");
            Console.WriteLine();
        }

        int exitCode;
        string stdout, stderr;
        try
        {
            (exitCode, stdout, stderr) = await RunProcessAsync(dotnet, args).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            EmitJsonOrText(options, new
            {
                action = "update",
                current,
                error = "process_launch_failed",
                message = ex.Message,
            }, $"Failed to launch dotnet: {ex.Message}");
            return 21;
        }

        if (exitCode != 0)
        {
            EmitJsonOrText(options, new
            {
                action = "update",
                current,
                error = "dotnet_tool_update_failed",
                exit_code = exitCode,
                stdout,
                stderr,
            }, $"`dotnet tool update` exited with code {exitCode}. stderr:\n{stderr}");
            return 21;
        }

        EmitJsonOrText(options, new
        {
            action = "update",
            current,
            success = true,
            stdout,
        }, $"WinSentinel updated. Re-run `winsentinel --version` to confirm.\n{stdout.Trim()}");
        return 0;
    }

    /// <summary>
    /// Builds the argument list passed to the <c>dotnet</c> executable. Exposed
    /// internal so the parser tests can pin the wire format.
    /// </summary>
    public static string[] BuildToolUpdateArgs(CliOptions options)
    {
        var list = new System.Collections.Generic.List<string>
        {
            "tool",
            "update",
            "--global",
            PackageId,
        };
        if (!string.IsNullOrWhiteSpace(options.SelfUpdateSource))
        {
            list.Add("--source");
            list.Add(options.SelfUpdateSource!);
        }
        if (!string.IsNullOrWhiteSpace(options.SelfUpdateVersion))
        {
            list.Add("--version");
            list.Add(options.SelfUpdateVersion!);
        }
        if (options.SelfUpdatePrerelease)
        {
            list.Add("--prerelease");
        }
        return list.ToArray();
    }

    /// <summary>
    /// Returns the running CLI version, stripped of any SourceLink build
    /// metadata (anything after <c>+</c>). Mirrors the logic in
    /// <see cref="ConsoleFormatter.GetInformationalVersion"/> so the two
    /// surfaces never disagree.
    /// </summary>
    public static string GetCurrentVersion()
    {
        var asm = typeof(CliParser).Assembly;
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        var raw = !string.IsNullOrWhiteSpace(info) ? info : (asm.GetName().Version?.ToString() ?? "0.0.0");
        var plus = raw.IndexOf('+');
        return plus >= 0 ? raw[..plus] : raw;
    }

    /// <summary>
    /// Compares two version strings using <see cref="Version"/>-style ordering.
    /// Falls back to ordinal compare when either side is non-numeric (e.g. a
    /// SemVer prerelease tag). Returns <c>true</c> when <paramref name="candidate"/>
    /// is strictly newer than <paramref name="current"/>.
    /// </summary>
    public static bool IsNewerVersion(string candidate, string current)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return false;
        if (string.IsNullOrWhiteSpace(current)) return true;
        if (string.Equals(candidate, current, StringComparison.OrdinalIgnoreCase)) return false;

        var candCore = StripPrereleaseTag(candidate);
        var currCore = StripPrereleaseTag(current);
        if (Version.TryParse(NormalizeForVersionParse(candCore), out var c) &&
            Version.TryParse(NormalizeForVersionParse(currCore), out var n))
        {
            var cmp = c.CompareTo(n);
            if (cmp != 0) return cmp > 0;
            // Cores equal — a prereleased version (1.0.0-beta) is OLDER than the release (1.0.0).
            var candHasPre = candidate.Contains('-');
            var currHasPre = current.Contains('-');
            if (candHasPre && !currHasPre) return false;
            if (!candHasPre && currHasPre) return true;
            return string.CompareOrdinal(candidate, current) > 0;
        }
        return string.CompareOrdinal(candidate, current) > 0;
    }

    private static string StripPrereleaseTag(string v)
    {
        var dash = v.IndexOf('-');
        return dash >= 0 ? v[..dash] : v;
    }

    private static string NormalizeForVersionParse(string v)
    {
        // System.Version requires at least Major.Minor; pad single-segment versions.
        return v.Contains('.') ? v : v + ".0";
    }

    private static string? ResolveDotnetExecutable()
    {
        // PATH-resolved name; ProcessStartInfo will search PATH.
        // We also do a sanity probe via `where`/`which` so we can fail fast with
        // a friendly error rather than the cryptic Win32Exception.
        var probe = OperatingSystem.IsWindows() ? "where" : "which";
        try
        {
            var psi = new ProcessStartInfo(probe, "dotnet")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            p.WaitForExit(3000);
            if (p.ExitCode != 0) return null;
        }
        catch
        {
            return null;
        }
        return "dotnet";
    }

    private static async Task<(int exitCode, string stdout, string stderr)> RunProcessAsync(string exe, string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = new Process { StartInfo = psi };
        p.Start();
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync().ConfigureAwait(false);
        return (p.ExitCode, await stdoutTask.ConfigureAwait(false), await stderrTask.ConfigureAwait(false));
    }

    /// <summary>
    /// Hits the NuGet v3 flat-container index for <see cref="PackageId"/> and
    /// returns the highest version. Honors <paramref name="source"/> when
    /// supplied (treated as the v3 root, e.g. <c>https://api.nuget.org/v3/index.json</c>
    /// or a flat-container base). Stable-only by default; <paramref name="prerelease"/>
    /// opts into SemVer prereleases.
    /// </summary>
    public static async Task<string?> TryGetLatestVersionAsync(string? source, bool prerelease)
    {
        var url = ResolveIndexUrl(source);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"WinSentinel.Cli/{GetCurrentVersion()} (+https://winsentinel.ai)");
        using var resp = await http.GetAsync(url).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        var stream = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false);
        var doc = await JsonDocument.ParseAsync(stream).ConfigureAwait(false);
        if (!doc.RootElement.TryGetProperty("versions", out var versions) || versions.ValueKind != JsonValueKind.Array)
            return null;
        var all = versions.EnumerateArray().Select(v => v.GetString() ?? string.Empty).Where(s => s.Length > 0).ToList();
        var filtered = prerelease ? all : all.Where(v => !v.Contains('-')).ToList();
        if (filtered.Count == 0) return null;
        // Sort descending by IsNewerVersion semantics.
        filtered.Sort((a, b) => IsNewerVersion(a, b) ? -1 : (IsNewerVersion(b, a) ? 1 : 0));
        return filtered[0];
    }

    private static string ResolveIndexUrl(string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return string.Format(System.Globalization.CultureInfo.InvariantCulture, NuGetIndexUrlTemplate, PackageId.ToLowerInvariant());
        }
        // If source looks like a flat-container base, trust it. Otherwise just
        // tack the package path on (best-effort — non-nuget.org feeds vary).
        var trimmed = source.TrimEnd('/');
        return $"{trimmed}/{PackageId.ToLowerInvariant()}/index.json";
    }

    private static void EmitJsonOrText(CliOptions options, object jsonPayload, string text)
    {
        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(jsonPayload, JsonOpts));
            return;
        }
        if (!options.Quiet)
        {
            Console.WriteLine();
            Console.WriteLine("  " + text);
            Console.WriteLine();
        }
    }
}
