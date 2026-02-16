namespace WinSentinel.Cli;

/// <summary>
/// Parsed command-line options for WinSentinel CLI.
/// </summary>
public class CliOptions
{
    public CliCommand Command { get; set; } = CliCommand.None;
    public bool Json { get; set; }
    public bool Html { get; set; }
    public string? OutputFile { get; set; }
    public string? ModulesFilter { get; set; }
    public bool Quiet { get; set; }
    public int? Threshold { get; set; }
    public bool ShowHelp { get; set; }
    public bool ShowVersion { get; set; }
    public string? Error { get; set; }
}

public enum CliCommand
{
    None,
    Audit,
    Score,
    FixAll,
    Help,
    Version
}

/// <summary>
/// Parses command-line arguments into <see cref="CliOptions"/>.
/// </summary>
public static class CliParser
{
    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();

        if (args.Length == 0)
        {
            options.Command = CliCommand.None;
            return options;
        }

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i].ToLowerInvariant();

            switch (arg)
            {
                case "--help" or "-h" or "/?" or "/h":
                    options.Command = CliCommand.Help;
                    options.ShowHelp = true;
                    return options;

                case "--version" or "-v":
                    options.Command = CliCommand.Version;
                    options.ShowVersion = true;
                    return options;

                case "--audit" or "-a":
                    options.Command = CliCommand.Audit;
                    break;

                case "--score" or "-s":
                    options.Command = CliCommand.Score;
                    break;

                case "--fix-all" or "-f":
                    options.Command = CliCommand.FixAll;
                    break;

                case "--json" or "-j":
                    options.Json = true;
                    break;

                case "--html":
                    options.Html = true;
                    break;

                case "--quiet" or "-q":
                    options.Quiet = true;
                    break;

                case "-o" or "--output":
                    if (i + 1 < args.Length)
                    {
                        options.OutputFile = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --output (-o).";
                        return options;
                    }
                    break;

                case "--modules" or "-m":
                    if (i + 1 < args.Length)
                    {
                        options.ModulesFilter = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --modules (-m).";
                        return options;
                    }
                    break;

                case "--threshold" or "-t":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int threshold) && threshold >= 0 && threshold <= 100)
                        {
                            options.Threshold = threshold;
                        }
                        else
                        {
                            options.Error = "Invalid threshold value. Must be 0-100.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --threshold (-t).";
                        return options;
                    }
                    break;

                default:
                    options.Error = $"Unknown option: {args[i]}";
                    return options;
            }
        }

        // If no command was specified but flags were set, default to audit
        if (options.Command == CliCommand.None && (options.Json || options.Html || options.Quiet || options.ModulesFilter != null))
        {
            options.Command = CliCommand.Audit;
        }

        if (options.Command == CliCommand.None)
        {
            options.Error = "No command specified. Use --help for usage information.";
        }

        return options;
    }
}
