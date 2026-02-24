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
    public bool Sarif { get; set; }
    public bool SarifIncludePass { get; set; }
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
    public string? ProfileName { get; set; }
    public IgnoreAction IgnoreAction { get; set; } = IgnoreAction.None;
    public string? IgnorePattern { get; set; }
    public string? IgnoreModule { get; set; }
    public string? IgnoreSeverity { get; set; }
    public string? IgnoreReason { get; set; }
    public string? IgnoreMatchMode { get; set; }
    public string? IgnoreRuleId { get; set; }
    public int? IgnoreExpireDays { get; set; }
    public bool ShowIgnored { get; set; }
    public int TrendDays { get; set; } = 30;
    public int? TrendAlertThreshold { get; set; }
    public bool TrendModules { get; set; }
    public BadgeBadgeAction BadgeAction { get; set; } = BadgeBadgeAction.None;
    public string? BadgeStyle { get; set; }
}

public enum CliCommand
{
    None,
    Audit,
    Score,
    FixAll,
    History,
    Baseline,
    Checklist,
    Profiles,
    Ignore,
    Trend,
    Badge,
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

public enum IgnoreAction
{
    None,
    Add,
    List,
    Remove,
    Clear,
    Purge
}

public enum BadgeBadgeAction
{
    None,
    Score,
    Grade,
    Findings,
    Module,
    All
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

                case "--checklist":
                    options.Command = CliCommand.Checklist;
                    break;

                case "--profiles":
                    options.Command = CliCommand.Profiles;
                    break;

                case "--trend":
                    options.Command = CliCommand.Trend;
                    break;

                case "--badge":
                    options.Command = CliCommand.Badge;
                    // Next arg should be the badge type: score, grade, findings, module, all
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var badgeType = args[++i].ToLowerInvariant();
                        options.BadgeAction = badgeType switch
                        {
                            "score" => BadgeBadgeAction.Score,
                            "grade" => BadgeBadgeAction.Grade,
                            "findings" => BadgeBadgeAction.Findings,
                            "module" => BadgeBadgeAction.Module,
                            "all" => BadgeBadgeAction.All,
                            _ => BadgeBadgeAction.None
                        };
                        if (options.BadgeAction == BadgeBadgeAction.None)
                        {
                            options.Error = $"Unknown badge type: {badgeType}. Use score, grade, findings, module, or all.";
                            return options;
                        }
                        // For module: next arg is the module filter
                        if (options.BadgeAction == BadgeBadgeAction.Module)
                        {
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                            {
                                options.ModulesFilter = args[++i];
                            }
                        }
                    }
                    else
                    {
                        // Default to score badge
                        options.BadgeAction = BadgeBadgeAction.Score;
                    }
                    break;

                case "--badge-style":
                    if (i + 1 < args.Length)
                    {
                        var s = args[++i].ToLowerInvariant();
                        if (s is "flat" or "flat-square" or "for-the-badge")
                        {
                            options.BadgeStyle = s;
                        }
                        else
                        {
                            options.Error = "Invalid badge style. Use flat, flat-square, or for-the-badge.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --badge-style. Use flat, flat-square, or for-the-badge.";
                        return options;
                    }
                    break;

                case "--ignore":
                    options.Command = CliCommand.Ignore;
                    // Next arg should be the action: add, list, remove, clear, purge
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var action = args[++i].ToLowerInvariant();
                        options.IgnoreAction = action switch
                        {
                            "add" => IgnoreAction.Add,
                            "list" => IgnoreAction.List,
                            "remove" or "rm" => IgnoreAction.Remove,
                            "clear" => IgnoreAction.Clear,
                            "purge" => IgnoreAction.Purge,
                            _ => IgnoreAction.None
                        };
                        if (options.IgnoreAction == IgnoreAction.None)
                        {
                            options.Error = $"Unknown ignore action: {action}. Use add, list, remove, clear, or purge.";
                            return options;
                        }
                        // For add: next arg is the pattern
                        if (options.IgnoreAction == IgnoreAction.Add)
                        {
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                            {
                                options.IgnorePattern = args[++i];
                            }
                            else
                            {
                                options.Error = "Missing pattern for 'ignore add'. Usage: --ignore add <pattern>";
                                return options;
                            }
                        }
                        // For remove: next arg is the rule ID
                        if (options.IgnoreAction == IgnoreAction.Remove)
                        {
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                            {
                                options.IgnoreRuleId = args[++i];
                            }
                            else
                            {
                                options.Error = "Missing rule ID for 'ignore remove'. Usage: --ignore remove <id>";
                                return options;
                            }
                        }
                    }
                    else
                    {
                        // No action specified, default to list
                        options.IgnoreAction = IgnoreAction.List;
                    }
                    break;

                case "--ignore-module":
                    if (i + 1 < args.Length)
                    {
                        options.IgnoreModule = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --ignore-module.";
                        return options;
                    }
                    break;

                case "--ignore-severity":
                    if (i + 1 < args.Length)
                    {
                        options.IgnoreSeverity = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --ignore-severity.";
                        return options;
                    }
                    break;

                case "--ignore-reason":
                    if (i + 1 < args.Length)
                    {
                        options.IgnoreReason = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --ignore-reason.";
                        return options;
                    }
                    break;

                case "--match-mode":
                    if (i + 1 < args.Length)
                    {
                        options.IgnoreMatchMode = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --match-mode. Use exact, contains, or regex.";
                        return options;
                    }
                    break;

                case "--expire-days":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int expDays) && expDays >= 1 && expDays <= 3650)
                        {
                            options.IgnoreExpireDays = expDays;
                        }
                        else
                        {
                            options.Error = "Invalid expire-days value. Must be 1-3650.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --expire-days.";
                        return options;
                    }
                    break;

                case "--show-ignored":
                    options.ShowIgnored = true;
                    break;

                case "--profile" or "-p":
                    if (i + 1 < args.Length)
                    {
                        options.ProfileName = args[++i];
                    }
                    else
                    {
                        options.Error = "Missing value for --profile (-p). Available: home, developer, enterprise, server";
                        return options;
                    }
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

                case "--sarif":
                    options.Sarif = true;
                    break;

                case "--sarif-include-pass":
                    options.SarifIncludePass = true;
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

                case "--trend-days":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int trendDays) && trendDays >= 1 && trendDays <= 365)
                        {
                            options.TrendDays = trendDays;
                        }
                        else
                        {
                            options.Error = "Invalid trend-days value. Must be 1-365.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --trend-days.";
                        return options;
                    }
                    break;

                case "--alert-below":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int alertThreshold) && alertThreshold >= 0 && alertThreshold <= 100)
                        {
                            options.TrendAlertThreshold = alertThreshold;
                        }
                        else
                        {
                            options.Error = "Invalid alert-below value. Must be 0-100.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --alert-below.";
                        return options;
                    }
                    break;

                case "--trend-modules":
                    options.TrendModules = true;
                    break;

                default:
                    options.Error = $"Unknown option: {args[i]}";
                    return options;
            }
        }

        // If no command was specified but flags were set, default to audit
        if (options.Command == CliCommand.None && (options.Json || options.Html || options.Markdown || options.Sarif || options.Quiet || options.ModulesFilter != null))
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
