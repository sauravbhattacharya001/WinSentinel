namespace WinSentinel.Cli;

/// <summary>
/// Parsed command-line options for WinSentinel CLI.
/// </summary>
public class CliOptions
{
    public CliCommand Command { get; set; } = CliCommand.None;
    public bool Json { get; set; }
    public bool Html { get; set; }
    public bool Markdown { get; set; }
    public string? OutputFile { get; set; }
    public string? ModulesFilter { get; set; }
    public bool Quiet { get; set; }
    public int? Threshold { get; set; }
    public bool ShowHelp { get; set; }
    public bool ShowVersion { get; set; }
    public bool Compare { get; set; }
    public bool Diff { get; set; }
    public int HistoryDays { get; set; } = 30;
    public int HistoryLimit { get; set; } = 20;
    public string? Error { get; set; }
    public BaselineAction BaselineAction { get; set; } = BaselineAction.None;
    public string? BaselineName { get; set; }
    public string? BaselineDescription { get; set; }
    public bool Force { get; set; }
}

public enum CliCommand
{
    None,
    Audit,
    Score,
    FixAll,
    History,
    Baseline,
    Help,
    Version
}

public enum BaselineAction
{
    None,
    Save,
    List,
    Check,
    Delete
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

                case "--history":
                    options.Command = CliCommand.History;
                    break;

                case "--baseline":
                    options.Command = CliCommand.Baseline;
                    // Next arg should be the action: save, list, check, delete
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var action = args[++i].ToLowerInvariant();
                        options.BaselineAction = action switch
                        {
                            "save" => BaselineAction.Save,
                            "list" => BaselineAction.List,
                            "check" => BaselineAction.Check,
                            "delete" => BaselineAction.Delete,
                            _ => BaselineAction.None
                        };
                        if (options.BaselineAction == BaselineAction.None)
                        {
                            options.Error = $"Unknown baseline action: {action}. Use save, list, check, or delete.";
                            return options;
                        }
                        // For save, check, delete: next arg is the name
                        if (options.BaselineAction is BaselineAction.Save or BaselineAction.Check or BaselineAction.Delete)
                        {
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                            {
                                options.BaselineName = args[++i];
                            }
                            else
                            {
                                options.Error = $"Missing baseline name for '{action}'. Usage: --baseline {action} <name>";
                                return options;
                            }
                        }
                    }
                    else
                    {
                        // No action specified, default to list
                        options.BaselineAction = BaselineAction.List;
                    }
                    break;

                case "--desc":
                    if (i + 1 < args.Length)
                    {
                        options.BaselineDescription = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --desc.";
                        return options;
                    }
                    break;

                case "--force":
                    options.Force = true;
                    break;

                case "--compare":
                    options.Compare = true;
                    break;

                case "--diff":
                    options.Diff = true;
                    break;

                case "--days":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int days) && days >= 1 && days <= 365)
                        {
                            options.HistoryDays = days;
                        }
                        else
                        {
                            options.Error = "Invalid days value. Must be 1-365.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --days.";
                        return options;
                    }
                    break;

                case "--limit" or "-l":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int limit) && limit >= 1 && limit <= 100)
                        {
                            options.HistoryLimit = limit;
                        }
                        else
                        {
                            options.Error = "Invalid limit value. Must be 1-100.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --limit (-l).";
                        return options;
                    }
                    break;

                case "--json" or "-j":
                    options.Json = true;
                    break;

                case "--html":
                    options.Html = true;
                    break;

                case "--markdown" or "--md":
                    options.Markdown = true;
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
        if (options.Command == CliCommand.None && (options.Json || options.Html || options.Markdown || options.Quiet || options.ModulesFilter != null))
        {
            options.Command = CliCommand.Audit;
        }

        // If compare or diff flags set without command, default to history
        if (options.Command == CliCommand.None && (options.Compare || options.Diff))
        {
            options.Command = CliCommand.History;
        }

        if (options.Command == CliCommand.None)
        {
            options.Error = "No command specified. Use --help for usage information.";
        }

        return options;
    }
}
