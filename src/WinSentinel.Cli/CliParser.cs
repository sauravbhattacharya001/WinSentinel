namespace WinSentinel.Cli;

/// <summary>
/// Parsed command-line options for WinSentinel CLI.
/// </summary>
public class CliOptions
{
    public CliCommand Command { get; set; } = CliCommand.None;
    public bool Json { get; set; }
    public bool Html { get; set; }
    public bool HtmlDark { get; set; }
    public bool HtmlIncludePass { get; set; }
    public string? HtmlTitle { get; set; }
    public bool Markdown { get; set; }
    public bool Csv { get; set; }
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
    public BadgeAction BadgeAction { get; set; } = BadgeAction.None;
    public string? BadgeStyle { get; set; }
    public string? TimelineSeverityFilter { get; set; }
    public int? TimelineMaxEvents { get; set; }
    public string? TimelineModuleFilter { get; set; }
    public FindingAgeAction AgeAction { get; set; } = FindingAgeAction.None;
    public string? AgeSeverityFilter { get; set; }
    public string? AgeModuleFilter { get; set; }
    public string? AgeClassification { get; set; }
    public int AgeDays { get; set; } = 90;
    public int AgeTop { get; set; } = 10;
    public bool HardenInteractive { get; set; } = true;
    public bool HardenDryRun { get; set; }
    public bool HardenIncludeInfo { get; set; }
    public PolicyAction PolicyAction { get; set; } = PolicyAction.None;
    public string? PolicyFile { get; set; }
    public string? PolicyName { get; set; }
    public string? PolicyDescription { get; set; }
    public ExemptionAction ExemptionAction { get; set; } = ExemptionAction.None;
    public int ExemptionWarningDays { get; set; } = 7;
    public int ExemptionStaleDays { get; set; } = 90;
    public int QuizQuestionCount { get; set; } = 10;
    public string? QuizDifficulty { get; set; }
    public string? QuizCategory { get; set; }
    public bool QuizExport { get; set; }
    public RootCauseAction RootCauseAction { get; set; } = RootCauseAction.None;
    public int RootCauseTop { get; set; } = 10;
    public string? RootCauseSeverityFilter { get; set; }
    public int ScheduleOptimizeDays { get; set; } = 90;
    public int DigestHistoryDays { get; set; } = 30;
    public string DigestFormat { get; set; } = "text";
    public WhatIfAction WhatIfAction { get; set; } = WhatIfAction.None;
    public string? WhatIfSeverity { get; set; }
    public string? WhatIfModule { get; set; }
    public string? WhatIfPattern { get; set; }
    public int WhatIfTopN { get; set; } = 5;
    public string SummaryFormat { get; set; } = "text";
    public int SummaryTrendDays { get; set; } = 30;
    public int CostHourlyRate { get; set; } = 85;
    public double CostSprintHours { get; set; } = 4.0;
    public string CostFormat { get; set; } = "text";
    public int CostTop { get; set; } = 10;
    public string BenchmarkGroup { get; set; } = "auto";
    public string BenchmarkFormat { get; set; } = "text";
    public bool BenchmarkAll { get; set; }
    public string? ComplianceFramework { get; set; }
    public string ComplianceFormat { get; set; } = "text";
    public bool ComplianceGapsOnly { get; set; }
    public bool ComplianceAll { get; set; }
    public string InventoryFormat { get; set; } = "text";
    public bool InventoryNoApps { get; set; }
    public bool InventoryNoServices { get; set; }
    public bool InventoryNoPorts { get; set; }
    public bool InventoryNoStartup { get; set; }
    public bool InventoryNoTasks { get; set; }
    public TagAction TagAction { get; set; } = TagAction.None;
    public string? TagFindingTitle { get; set; }
    public string? TagFindingCategory { get; set; }
    public List<string> TagValues { get; set; } = [];
    public string? TagSearchQuery { get; set; }
    public string? TagRenameFrom { get; set; }
    public string? TagRenameTo { get; set; }
    public string? TagAnnotation { get; set; }
    public string? TagAuthor { get; set; }
    public string? TagImportFile { get; set; }
    public bool TagMerge { get; set; } = true;
    public int HotspotDays { get; set; } = 90;
    public int HotspotMaxRuns { get; set; } = 0;
    public int HotspotTop { get; set; } = 10;
    public string HotspotFormat { get; set; } = "text";
    public int KpiDays { get; set; } = 90;
    public string KpiFormat { get; set; } = "text";
    public SlaAction SlaAction { get; set; } = SlaAction.None;
    public string SlaPolicy { get; set; } = "enterprise";
    public string SlaFormat { get; set; } = "text";
    public string? SlaResolveId { get; set; }
    public string? SlaResolveNotes { get; set; }
    public string? SlaSeverityFilter { get; set; }
    public int SlaTop { get; set; } = 10;
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
    Timeline,
    FindingAge,
    Status,
    Harden,
    Policy,
    Exemptions,
    Quiz,
    RootCause,
    Threats,
    ScheduleOptimize,
    Digest,
    AttackPaths,
    WhatIf,
    Summary,
    Cost,
    Benchmark,
    Compliance,
    Inventory,
    Tag,
    Hotspots,
    Kpi,
    Sla,
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

public enum BadgeAction
{
    None,
    Score,
    Grade,
    Findings,
    Module,
    All
}

public enum FindingAgeAction
{
    None,
    Report,
    Priority,
    Chronic,
    New,
    Resolved
}

public enum PolicyAction
{
    None,
    Export,
    Import,
    Validate,
    Diff
}

public enum ExemptionAction
{
    None,
    Review,
    Expiring,
    Stale,
    Unused,
    Summary
}

public enum RootCauseAction
{
    None,
    Report,
    Top,
    Causes,
    Ungrouped
}

public enum WhatIfAction
{
    None,
    All,
    Severity,
    Module,
    Pattern,
    TopN
}

public enum TagAction
{
    None,
    Add,
    Remove,
    List,
    Search,
    Report,
    AutoTag,
    Rename,
    Delete,
    Export,
    Import
}

public enum SlaAction
{
    None,
    Report,
    Overdue,
    Approaching,
    Track,
    Export
}

/// <summary>
/// Parses command-line arguments into <see cref="CliOptions"/>.
/// </summary>
public static class CliParser
{
    /// <summary>
    /// Consume the next argument as a string value.
    /// Returns true and advances <paramref name="i"/> if successful;
    /// sets <paramref name="error"/> on failure.
    /// </summary>
    private static bool TryConsumeArg(string[] args, ref int i, string flag, out string value, out string? error)
    {
        error = null;
        if (i + 1 < args.Length)
        {
            value = args[++i];
            return true;
        }
        value = "";
        error = $"Missing value for {flag}.";
        return false;
    }

    /// <summary>
    /// Consume the next argument as an integer within [<paramref name="min"/>, <paramref name="max"/>].
    /// Returns true and advances <paramref name="i"/> if successful;
    /// sets <paramref name="error"/> on failure.
    /// </summary>
    private static bool TryConsumeInt(string[] args, ref int i, string flag, int min, int max, out int value, out string? error)
    {
        error = null;
        value = 0;
        if (i + 1 < args.Length)
        {
            if (int.TryParse(args[++i], out value) && value >= min && value <= max)
                return true;
            error = $"Invalid {flag.TrimStart('-')} value. Must be {min}-{max}.";
            return false;
        }
        error = $"Missing value for {flag}.";
        return false;
    }

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

                case "--timeline":
                    options.Command = CliCommand.Timeline;
                    break;

                case "--status":
                    options.Command = CliCommand.Status;
                    break;

                case "--harden":
                    options.Command = CliCommand.Harden;
                    break;

                case "--policy":
                    options.Command = CliCommand.Policy;
                    break;

                case "--exemptions":
                    options.Command = CliCommand.Exemptions;
                    // Next arg should be the action: review, expiring, stale, unused, summary
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var exemptionAction = args[++i].ToLowerInvariant();
                        options.ExemptionAction = exemptionAction switch
                        {
                            "review" => ExemptionAction.Review,
                            "expiring" => ExemptionAction.Expiring,
                            "stale" => ExemptionAction.Stale,
                            "unused" => ExemptionAction.Unused,
                            "summary" => ExemptionAction.Summary,
                            _ => ExemptionAction.None
                        };
                        if (options.ExemptionAction == ExemptionAction.None)
                        {
                            options.Error = $"Unknown exemption action: {exemptionAction}. Use review, expiring, stale, unused, or summary.";
                            return options;
                        }
                    }
                    else
                    {
                        // Default to full review
                        options.ExemptionAction = ExemptionAction.Review;
                    }
                    break;

                case "--warning-days":
                    if (!TryConsumeInt(args, ref i, "--warning-days", 1, 365, out var warnDays, out var warnErr))
                    { options.Error = warnErr; return options; }
                    options.ExemptionWarningDays = warnDays;
                    break;

                case "--stale-days":
                    if (!TryConsumeInt(args, ref i, "--stale-days", 1, 3650, out var staleDays, out var staleErr))
                    { options.Error = staleErr; return options; }
                    options.ExemptionStaleDays = staleDays;
                    break;

                case "--quiz":
                    options.Command = CliCommand.Quiz;
                    break;

                case "--quiz-count":
                    if (!TryConsumeInt(args, ref i, "--quiz-count", 1, 50, out var qCount, out var qcErr))
                    { options.Error = qcErr; return options; }
                    options.QuizQuestionCount = qCount;
                    break;

                case "--quiz-difficulty":
                    if (!TryConsumeArg(args, ref i, "--quiz-difficulty", out var qDiff, out var qdErr))
                    { options.Error = qdErr; return options; }
                    options.QuizDifficulty = qDiff.ToLowerInvariant();
                    break;

                case "--quiz-category":
                    if (!TryConsumeArg(args, ref i, "--quiz-category", out var qCat, out var qcatErr))
                    { options.Error = qcatErr; return options; }
                    options.QuizCategory = qCat;
                    break;

                case "--quiz-export":
                    options.QuizExport = true;
                    break;

                case "--rootcause":
                    options.Command = CliCommand.RootCause;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var rcAction = args[++i].ToLowerInvariant();
                        options.RootCauseAction = rcAction switch
                        {
                            "report" => RootCauseAction.Report,
                            "top" => RootCauseAction.Top,
                            "causes" => RootCauseAction.Causes,
                            "ungrouped" => RootCauseAction.Ungrouped,
                            _ => RootCauseAction.None
                        };
                        if (options.RootCauseAction == RootCauseAction.None)
                        {
                            options.Error = $"Unknown rootcause action: {rcAction}. Use report, top, causes, or ungrouped.";
                            return options;
                        }
                    }
                    else
                    {
                        options.RootCauseAction = RootCauseAction.Report;
                    }
                    break;

                case "--rootcause-top":
                    if (!TryConsumeInt(args, ref i, "--rootcause-top", 1, 50, out var rcTop, out var rcTopErr))
                    { options.Error = rcTopErr; return options; }
                    options.RootCauseTop = rcTop;
                    break;

                case "--rootcause-severity":
                    if (!TryConsumeArg(args, ref i, "--rootcause-severity", out var rcSev, out var rcSevErr))
                    { options.Error = rcSevErr; return options; }
                    options.RootCauseSeverityFilter = rcSev;
                    break;

                case "--threats":
                    options.Command = CliCommand.Threats;
                    break;

                case "--schedule-optimize":
                    options.Command = CliCommand.ScheduleOptimize;
                    break;

                case "--digest":
                    options.Command = CliCommand.Digest;
                    break;

                case "--attack-paths":
                    options.Command = CliCommand.AttackPaths;
                    break;

                case "--summary":
                    options.Command = CliCommand.Summary;
                    break;

                case "--cost":
                    options.Command = CliCommand.Cost;
                    break;

                case "--cost-rate":
                    if (!TryConsumeInt(args, ref i, "--cost-rate", 1, 1000, out var cRate, out var cRateErr))
                    { options.Error = cRateErr; return options; }
                    options.CostHourlyRate = cRate;
                    break;

                case "--cost-sprint-hours":
                    if (i + 1 < args.Length && double.TryParse(args[++i], out var cSprint) && cSprint >= 0.5 && cSprint <= 40)
                        options.CostSprintHours = cSprint;
                    else
                    { options.Error = "Invalid --cost-sprint-hours value. Must be 0.5-40."; return options; }
                    break;

                case "--cost-format":
                    if (!TryConsumeArg(args, ref i, "--cost-format", out var cFmt, out var cFmtErr))
                    { options.Error = cFmtErr; return options; }
                    options.CostFormat = cFmt.ToLowerInvariant();
                    break;

                case "--cost-top":
                    if (!TryConsumeInt(args, ref i, "--cost-top", 1, 100, out var cTop, out var cTopErr))
                    { options.Error = cTopErr; return options; }
                    options.CostTop = cTop;
                    break;

                case "--summary-format":
                    if (!TryConsumeArg(args, ref i, "--summary-format", out var sumFmt, out var sumFmtErr))
                    { options.Error = sumFmtErr; return options; }
                    options.SummaryFormat = sumFmt.ToLowerInvariant();
                    break;

                case "--summary-trend-days":
                    if (!TryConsumeInt(args, ref i, "--summary-trend-days", 1, 365, out var sumTrDays, out var sumTrErr))
                    { options.Error = sumTrErr; return options; }
                    options.SummaryTrendDays = sumTrDays;
                    break;

                case "--whatif":
                    options.Command = CliCommand.WhatIf;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var wiAction = args[++i].ToLowerInvariant();
                        options.WhatIfAction = wiAction switch
                        {
                            "all" => WhatIfAction.All,
                            "severity" => WhatIfAction.Severity,
                            "module" => WhatIfAction.Module,
                            "pattern" => WhatIfAction.Pattern,
                            "top" => WhatIfAction.TopN,
                            _ => WhatIfAction.None
                        };
                        if (options.WhatIfAction == WhatIfAction.None)
                        {
                            options.Error = $"Unknown whatif action: {wiAction}. Use all, severity, module, pattern, or top.";
                            return options;
                        }
                        // For severity: next arg is the severity level
                        if (options.WhatIfAction == WhatIfAction.Severity)
                        {
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                                options.WhatIfSeverity = args[++i].ToLowerInvariant();
                            else
                            {
                                options.Error = "Missing severity for 'whatif severity'. Usage: --whatif severity critical|warning";
                                return options;
                            }
                        }
                        // For module: next arg is the module name
                        if (options.WhatIfAction == WhatIfAction.Module)
                        {
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                                options.WhatIfModule = args[++i];
                            else
                            {
                                options.Error = "Missing module name for 'whatif module'. Usage: --whatif module <name>";
                                return options;
                            }
                        }
                        // For pattern: next arg is the search pattern
                        if (options.WhatIfAction == WhatIfAction.Pattern)
                        {
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                                options.WhatIfPattern = args[++i];
                            else
                            {
                                options.Error = "Missing pattern for 'whatif pattern'. Usage: --whatif pattern <text>";
                                return options;
                            }
                        }
                    }
                    else
                    {
                        // Default to top-N
                        options.WhatIfAction = WhatIfAction.TopN;
                    }
                    break;

                case "--whatif-top":
                    if (!TryConsumeInt(args, ref i, "--whatif-top", 1, 100, out var wiTop, out var wiTopErr))
                    { options.Error = wiTopErr; return options; }
                    options.WhatIfTopN = wiTop;
                    break;

                case "--digest-days":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out var digestDays))
                        options.DigestHistoryDays = digestDays;
                    break;

                case "--digest-format":
                    if (i + 1 < args.Length)
                        options.DigestFormat = args[++i].ToLowerInvariant();
                    break;

                case "export" when options.Command == CliCommand.Policy:
                    options.PolicyAction = PolicyAction.Export;
                    break;

                case "import" when options.Command == CliCommand.Policy:
                    options.PolicyAction = PolicyAction.Import;
                    break;

                case "validate" when options.Command == CliCommand.Policy:
                    options.PolicyAction = PolicyAction.Validate;
                    break;

                case "diff" when options.Command == CliCommand.Policy:
                    options.PolicyAction = PolicyAction.Diff;
                    break;

                case "--policy-file":
                    if (i + 1 < args.Length) options.PolicyFile = args[++i];
                    break;

                case "--policy-name":
                    if (i + 1 < args.Length) options.PolicyName = args[++i];
                    break;

                case "--policy-desc":
                    if (i + 1 < args.Length) options.PolicyDescription = args[++i];
                    break;

                case "--no-prompt":
                    options.HardenInteractive = false;
                    break;

                case "--dry-run":
                    options.HardenDryRun = true;
                    break;

                case "--include-info":
                    options.HardenIncludeInfo = true;
                    break;

                case "--age":
                    options.Command = CliCommand.FindingAge;
                    // Next arg should be the action: report, priority, chronic, new, resolved
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var ageAction = args[++i].ToLowerInvariant();
                        options.AgeAction = ageAction switch
                        {
                            "report" => FindingAgeAction.Report,
                            "priority" => FindingAgeAction.Priority,
                            "chronic" => FindingAgeAction.Chronic,
                            "new" => FindingAgeAction.New,
                            "resolved" => FindingAgeAction.Resolved,
                            _ => FindingAgeAction.None
                        };
                        if (options.AgeAction == FindingAgeAction.None)
                        {
                            options.Error = $"Unknown age action: {ageAction}. Use report, priority, chronic, new, or resolved.";
                            return options;
                        }
                    }
                    else
                    {
                        // Default to full report
                        options.AgeAction = FindingAgeAction.Report;
                    }
                    break;

                case "--age-severity":
                    if (!TryConsumeArg(args, ref i, "--age-severity", out var ageSev, out var ageSevErr))
                    { options.Error = ageSevErr; return options; }
                    options.AgeSeverityFilter = ageSev;
                    break;

                case "--age-module":
                    if (!TryConsumeArg(args, ref i, "--age-module", out var ageMod, out var ageModErr))
                    { options.Error = ageModErr; return options; }
                    options.AgeModuleFilter = ageMod;
                    break;

                case "--age-class":
                    if (!TryConsumeArg(args, ref i, "--age-class", out var ageCls, out var ageClsErr))
                    { options.Error = ageClsErr ?? "Missing value for --age-class. Use chronic, recurring, new, or intermittent."; return options; }
                    options.AgeClassification = ageCls;
                    break;

                case "--age-days":
                    if (!TryConsumeInt(args, ref i, "--age-days", 1, 365, out var ageDays, out var ageDErr))
                    { options.Error = ageDErr; return options; }
                    options.AgeDays = ageDays;
                    break;

                case "--age-top":
                    if (!TryConsumeInt(args, ref i, "--age-top", 1, 100, out var ageTop, out var ageTErr))
                    { options.Error = ageTErr; return options; }
                    options.AgeTop = ageTop;
                    break;

                case "--timeline-severity":
                    if (!TryConsumeArg(args, ref i, "--timeline-severity", out var tlSev, out var tlSevErr))
                    { options.Error = tlSevErr ?? "Missing value for --timeline-severity. Use info, notice, warning, or critical."; return options; }
                    options.TimelineSeverityFilter = tlSev;
                    break;

                case "--timeline-max":
                    if (i + 1 < args.Length)
                    {
                        if (int.TryParse(args[++i], out int tlMax) && tlMax >= 1)
                        {
                            options.TimelineMaxEvents = tlMax;
                        }
                        else
                        {
                            options.Error = "Invalid timeline-max value. Must be a positive integer.";
                            return options;
                        }
                    }
                    else
                    {
                        options.Error = "Missing value for --timeline-max.";
                        return options;
                    }
                    break;

                case "--timeline-module":
                    if (!TryConsumeArg(args, ref i, "--timeline-module", out var tlMod, out var tlModErr))
                    { options.Error = tlModErr; return options; }
                    options.TimelineModuleFilter = tlMod;
                    break;

                case "--badge":
                    options.Command = CliCommand.Badge;
                    // Next arg should be the badge type: score, grade, findings, module, all
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var badgeType = args[++i].ToLowerInvariant();
                        options.BadgeAction = badgeType switch
                        {
                            "score" => BadgeAction.Score,
                            "grade" => BadgeAction.Grade,
                            "findings" => BadgeAction.Findings,
                            "module" => BadgeAction.Module,
                            "all" => BadgeAction.All,
                            _ => BadgeAction.None
                        };
                        if (options.BadgeAction == BadgeAction.None)
                        {
                            options.Error = $"Unknown badge type: {badgeType}. Use score, grade, findings, module, or all.";
                            return options;
                        }
                        // For module: next arg is the module filter
                        if (options.BadgeAction == BadgeAction.Module)
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
                        options.BadgeAction = BadgeAction.Score;
                    }
                    break;

                case "--badge-style":
                    if (!TryConsumeArg(args, ref i, "--badge-style", out var bStyle, out var bsErr))
                    { options.Error = bsErr ?? "Missing value for --badge-style. Use flat, flat-square, or for-the-badge."; return options; }
                    var bStyleLower = bStyle.ToLowerInvariant();
                    if (bStyleLower is not ("flat" or "flat-square" or "for-the-badge"))
                    {
                        options.Error = "Invalid badge style. Use flat, flat-square, or for-the-badge.";
                        return options;
                    }
                    options.BadgeStyle = bStyleLower;
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
                    if (!TryConsumeArg(args, ref i, "--ignore-module", out var igMod, out var igModErr))
                    { options.Error = igModErr; return options; }
                    options.IgnoreModule = igMod;
                    break;

                case "--ignore-severity":
                    if (!TryConsumeArg(args, ref i, "--ignore-severity", out var igSev, out var igSevErr))
                    { options.Error = igSevErr; return options; }
                    options.IgnoreSeverity = igSev;
                    break;

                case "--ignore-reason":
                    if (!TryConsumeArg(args, ref i, "--ignore-reason", out var igRsn, out var igRsnErr))
                    { options.Error = igRsnErr; return options; }
                    options.IgnoreReason = igRsn;
                    break;

                case "--match-mode":
                    if (!TryConsumeArg(args, ref i, "--match-mode", out var mm, out var mmErr))
                    { options.Error = mmErr ?? "Missing value for --match-mode. Use exact, contains, or regex."; return options; }
                    options.IgnoreMatchMode = mm;
                    break;

                case "--expire-days":
                    if (!TryConsumeInt(args, ref i, "--expire-days", 1, 3650, out var expDays, out var expErr))
                    { options.Error = expErr; return options; }
                    options.IgnoreExpireDays = expDays;
                    break;

                case "--show-ignored":
                    options.ShowIgnored = true;
                    break;

                case "--profile" or "-p":
                    if (!TryConsumeArg(args, ref i, "--profile (-p)", out var prof, out var profErr))
                    { options.Error = profErr ?? "Missing value for --profile (-p). Available: home, developer, enterprise, server"; return options; }
                    options.ProfileName = prof;
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
                    if (!TryConsumeArg(args, ref i, "--desc", out var descVal, out var descErr))
                    { options.Error = descErr; return options; }
                    options.BaselineDescription = descVal;
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
                    if (!TryConsumeInt(args, ref i, "--days", 1, 365, out var days, out var daysErr))
                    { options.Error = daysErr; return options; }
                    options.HistoryDays = days;
                    break;

                case "--limit" or "-l":
                    if (!TryConsumeInt(args, ref i, "--limit (-l)", 1, 100, out var limit, out var limitErr))
                    { options.Error = limitErr; return options; }
                    options.HistoryLimit = limit;
                    break;

                case "--json" or "-j":
                    options.Json = true;
                    break;

                case "--html":
                    options.Html = true;
                    break;

                case "--html-dark":
                    options.HtmlDark = true;
                    break;

                case "--html-include-pass":
                    options.HtmlIncludePass = true;
                    break;

                case "--html-title":
                    if (!TryConsumeArg(args, ref i, "--html-title", out var htmlTitle, out var htErr))
                    { options.Error = htErr; return options; }
                    options.HtmlTitle = htmlTitle;
                    break;

                case "--markdown" or "--md":
                    options.Markdown = true;
                    break;

                case "--csv":
                    options.Csv = true;
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
                    if (!TryConsumeArg(args, ref i, "--output (-o)", out var outFile, out var outErr))
                    { options.Error = outErr; return options; }
                    options.OutputFile = outFile;
                    break;

                case "--modules" or "-m":
                    if (!TryConsumeArg(args, ref i, "--modules (-m)", out var modFilter, out var modErr))
                    { options.Error = modErr; return options; }
                    options.ModulesFilter = modFilter;
                    break;

                case "--threshold" or "-t":
                    if (!TryConsumeInt(args, ref i, "--threshold (-t)", 0, 100, out var threshold, out var thrErr))
                    { options.Error = thrErr; return options; }
                    options.Threshold = threshold;
                    break;

                case "--trend-days":
                    if (!TryConsumeInt(args, ref i, "--trend-days", 1, 365, out var trendDays, out var tdErr))
                    { options.Error = tdErr; return options; }
                    options.TrendDays = trendDays;
                    break;

                case "--opt-days":
                    if (!TryConsumeInt(args, ref i, "--opt-days", 1, 365, out var optDays, out var odErr))
                    { options.Error = odErr; return options; }
                    options.ScheduleOptimizeDays = optDays;
                    break;

                case "--alert-below":
                    if (!TryConsumeInt(args, ref i, "--alert-below", 0, 100, out var alertThreshold, out var abErr))
                    { options.Error = abErr; return options; }
                    options.TrendAlertThreshold = alertThreshold;
                    break;

                case "--trend-modules":
                    options.TrendModules = true;
                    break;

                case "--benchmark":
                    options.Command = CliCommand.Benchmark;
                    break;

                case "--benchmark-group":
                    if (!TryConsumeArg(args, ref i, "--benchmark-group", out var bgVal, out var bgErr))
                    { options.Error = bgErr; return options; }
                    options.BenchmarkGroup = bgVal.ToLowerInvariant();
                    break;

                case "--benchmark-format":
                    if (!TryConsumeArg(args, ref i, "--benchmark-format", out var bfVal, out var bfErr))
                    { options.Error = bfErr; return options; }
                    options.BenchmarkFormat = bfVal.ToLowerInvariant();
                    break;

                case "--benchmark-all":
                    options.BenchmarkAll = true;
                    break;

                case "--compliance":
                    options.Command = CliCommand.Compliance;
                    break;

                case "--compliance-framework":
                    if (!TryConsumeArg(args, ref i, "--compliance-framework", out var cfVal, out var cfErr))
                    { options.Error = cfErr; return options; }
                    options.ComplianceFramework = cfVal.ToLowerInvariant();
                    break;

                case "--compliance-format":
                    if (!TryConsumeArg(args, ref i, "--compliance-format", out var cffVal, out var cffErr))
                    { options.Error = cffErr; return options; }
                    options.ComplianceFormat = cffVal.ToLowerInvariant();
                    break;

                case "--compliance-gaps":
                    options.ComplianceGapsOnly = true;
                    break;

                case "--compliance-all":
                    options.ComplianceAll = true;
                    break;

                case "--inventory":
                    options.Command = CliCommand.Inventory;
                    break;

                case "--inventory-format":
                    if (!TryConsumeArg(args, ref i, "--inventory-format", out var invFmt, out var invFmtErr))
                    { options.Error = invFmtErr; return options; }
                    options.InventoryFormat = invFmt.ToLowerInvariant();
                    break;

                case "--no-apps":
                    options.InventoryNoApps = true;
                    break;

                case "--no-services":
                    options.InventoryNoServices = true;
                    break;

                case "--no-ports":
                    options.InventoryNoPorts = true;
                    break;

                case "--no-startup":
                    options.InventoryNoStartup = true;
                    break;

                case "--no-tasks":
                    options.InventoryNoTasks = true;
                    break;

                case "--tag":
                    options.Command = CliCommand.Tag;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var tagAction = args[++i].ToLowerInvariant();
                        options.TagAction = tagAction switch
                        {
                            "add" => TagAction.Add,
                            "remove" => TagAction.Remove,
                            "list" => TagAction.List,
                            "search" => TagAction.Search,
                            "report" => TagAction.Report,
                            "autotag" => TagAction.AutoTag,
                            "rename" => TagAction.Rename,
                            "delete" => TagAction.Delete,
                            "export" => TagAction.Export,
                            "import" => TagAction.Import,
                            _ => TagAction.None
                        };
                        if (options.TagAction == TagAction.None)
                        {
                            options.Error = $"Unknown tag action: {tagAction}. Use add, remove, list, search, report, autotag, rename, delete, export, or import.";
                            return options;
                        }
                    }
                    else
                    {
                        options.TagAction = TagAction.Report;
                    }
                    break;

                case "--tag-finding":
                    if (!TryConsumeArg(args, ref i, "--tag-finding", out var tagFinding, out var tagFindErr))
                    { options.Error = tagFindErr; return options; }
                    options.TagFindingTitle = tagFinding;
                    break;

                case "--tag-category":
                    if (!TryConsumeArg(args, ref i, "--tag-category", out var tagCat, out var tagCatErr))
                    { options.Error = tagCatErr; return options; }
                    options.TagFindingCategory = tagCat;
                    break;

                case "--tag-value":
                    if (!TryConsumeArg(args, ref i, "--tag-value", out var tagVal, out var tagValErr))
                    { options.Error = tagValErr; return options; }
                    options.TagValues.Add(tagVal);
                    break;

                case "--tag-search":
                    if (!TryConsumeArg(args, ref i, "--tag-search", out var tagSearch, out var tagSearchErr))
                    { options.Error = tagSearchErr; return options; }
                    options.TagSearchQuery = tagSearch;
                    break;

                case "--tag-rename-from":
                    if (!TryConsumeArg(args, ref i, "--tag-rename-from", out var tagRFrom, out var tagRFromErr))
                    { options.Error = tagRFromErr; return options; }
                    options.TagRenameFrom = tagRFrom;
                    break;

                case "--tag-rename-to":
                    if (!TryConsumeArg(args, ref i, "--tag-rename-to", out var tagRTo, out var tagRToErr))
                    { options.Error = tagRToErr; return options; }
                    options.TagRenameTo = tagRTo;
                    break;

                case "--tag-note":
                    if (!TryConsumeArg(args, ref i, "--tag-note", out var tagNote, out var tagNoteErr))
                    { options.Error = tagNoteErr; return options; }
                    options.TagAnnotation = tagNote;
                    break;

                case "--tag-author":
                    if (!TryConsumeArg(args, ref i, "--tag-author", out var tagAuthor, out var tagAuthorErr))
                    { options.Error = tagAuthorErr; return options; }
                    options.TagAuthor = tagAuthor;
                    break;

                case "--tag-file":
                    if (!TryConsumeArg(args, ref i, "--tag-file", out var tagFile, out var tagFileErr))
                    { options.Error = tagFileErr; return options; }
                    options.TagImportFile = tagFile;
                    break;

                case "--tag-no-merge":
                    options.TagMerge = false;
                    break;

                case "--hotspots":
                    options.Command = CliCommand.Hotspots;
                    break;

                case "--hotspots-days":
                    if (!TryConsumeInt(args, ref i, "--hotspots-days", 1, 365, out var hsDays, out var hsDaysErr))
                    { options.Error = hsDaysErr; return options; }
                    options.HotspotDays = hsDays;
                    break;

                case "--hotspots-runs":
                    if (!TryConsumeInt(args, ref i, "--hotspots-runs", 1, 500, out var hsRuns, out var hsRunsErr))
                    { options.Error = hsRunsErr; return options; }
                    options.HotspotMaxRuns = hsRuns;
                    break;

                case "--hotspots-top":
                    if (!TryConsumeInt(args, ref i, "--hotspots-top", 1, 50, out var hsTop, out var hsTopErr))
                    { options.Error = hsTopErr; return options; }
                    options.HotspotTop = hsTop;
                    break;

                case "--hotspots-format":
                    if (!TryConsumeArg(args, ref i, "--hotspots-format", out var hsFmt, out var hsFmtErr))
                    { options.Error = hsFmtErr; return options; }
                    options.HotspotFormat = hsFmt.ToLowerInvariant();
                    break;

                case "--kpi":
                    options.Command = CliCommand.Kpi;
                    break;

                case "--kpi-days":
                    if (!TryConsumeInt(args, ref i, "--kpi-days", 1, 365, out var kpiDays, out var kpiDaysErr))
                    { options.Error = kpiDaysErr; return options; }
                    options.KpiDays = kpiDays;
                    break;

                case "--kpi-format":
                    if (!TryConsumeArg(args, ref i, "--kpi-format", out var kpiFmt, out var kpiFmtErr))
                    { options.Error = kpiFmtErr; return options; }
                    options.KpiFormat = kpiFmt.ToLowerInvariant();
                    break;

                case "--sla":
                    options.Command = CliCommand.Sla;
                    // Check for sub-action
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                    {
                        options.SlaAction = args[++i].ToLowerInvariant() switch
                        {
                            "report" => SlaAction.Report,
                            "overdue" => SlaAction.Overdue,
                            "approaching" => SlaAction.Approaching,
                            "track" => SlaAction.Track,
                            "export" => SlaAction.Export,
                            _ => SlaAction.Report
                        };
                    }
                    else
                    {
                        options.SlaAction = SlaAction.Report;
                    }
                    break;

                case "--sla-policy":
                    if (!TryConsumeArg(args, ref i, "--sla-policy", out var slaPol, out var slaPolErr))
                    { options.Error = slaPolErr; return options; }
                    options.SlaPolicy = slaPol.ToLowerInvariant();
                    break;

                case "--sla-format":
                    if (!TryConsumeArg(args, ref i, "--sla-format", out var slaFmt, out var slaFmtErr))
                    { options.Error = slaFmtErr; return options; }
                    options.SlaFormat = slaFmt.ToLowerInvariant();
                    break;

                case "--sla-severity":
                    if (!TryConsumeArg(args, ref i, "--sla-severity", out var slaSev, out var slaSevErr))
                    { options.Error = slaSevErr; return options; }
                    options.SlaSeverityFilter = slaSev.ToLowerInvariant();
                    break;

                case "--sla-top":
                    if (!TryConsumeInt(args, ref i, "--sla-top", 1, 100, out var slaTop, out var slaTopErr))
                    { options.Error = slaTopErr; return options; }
                    options.SlaTop = slaTop;
                    break;

                default:
                    options.Error = $"Unknown option: {args[i]}";
                    return options;
            }
        }

        // If no command was specified but flags were set, default to audit
        if (options.Command == CliCommand.None && (options.Json || options.Html || options.Markdown || options.Csv || options.Sarif || options.Quiet || options.ModulesFilter != null))
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
