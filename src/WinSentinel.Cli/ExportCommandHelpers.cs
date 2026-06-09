// SPDX-License-Identifier: Apache-2.0
namespace WinSentinel.Cli;

/// <summary>
/// Helpers for the <c>winsentinel export</c> command (F11).
///
/// Lives in its own type so the format-resolution logic is unit-testable
/// without standing up a full audit run. The handler in
/// <c>Program.cs</c> calls into here for both format selection and
/// auto-extension on output paths.
/// </summary>
public static class ExportCommandHelpers
{
    /// <summary>
    /// Derive the export format from positional/flag inputs.
    /// </summary>
    /// <remarks>
    /// Precedence:
    /// <list type="number">
    ///   <item>Explicit <see cref="CliOptions.ExportFormat"/> (positional or <c>--format</c>) wins.</item>
    ///   <item>Otherwise infer from the boolean flag(s) on <see cref="CliOptions"/>
    ///         (<c>--json</c>, <c>--csv</c>, <c>--sarif</c>, <c>--markdown</c>).</item>
    ///   <item>Nothing set => default to <c>"json"</c> (CI-friendly).</item>
    /// </list>
    /// Two or more flag forms at once is a hard error to avoid silent surprises.
    /// </remarks>
    /// <returns>
    /// (Format, Error). Exactly one is non-null on a clean call:
    /// Format is the resolved/normalized format string, Error is a user-facing message.
    /// </returns>
    public static (string? Format, string? Error) ResolveExportFormat(CliOptions options)
    {
        var fmt = (options.ExportFormat ?? string.Empty).Trim().ToLowerInvariant();
        if (!string.IsNullOrEmpty(fmt))
        {
            fmt = fmt switch
            {
                "md" => "markdown",
                "yml" => "yaml",
                _ => fmt,
            };
            return (fmt, null);
        }

        var flagFormats = new List<string>();
        if (options.Json) flagFormats.Add("json");
        if (options.Sarif) flagFormats.Add("sarif");
        if (options.Csv) flagFormats.Add("csv");
        if (options.Markdown) flagFormats.Add("markdown");

        if (flagFormats.Count > 1)
        {
            return (null, $"Conflicting format flags: {string.Join(", ", flagFormats.Select(f => "--" + f))}. Pick one.");
        }
        return (flagFormats.Count == 1 ? flagFormats[0] : "json", null);
    }

    /// <summary>
    /// The conventional file extension for a given export format.
    /// </summary>
    /// <remarks>
    /// Used to auto-extend an output path when <c>-o file</c> has no extension,
    /// so <c>winsentinel export --sarif -o report</c> lands as <c>report.sarif</c>.
    /// </remarks>
    public static string ExtensionForFormat(string fmt) => fmt switch
    {
        "json" => ".json",
        "csv" => ".csv",
        "sarif" => ".sarif",
        "markdown" => ".md",
        _ => string.Empty,
    };
}
