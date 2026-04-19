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
    public string CoverageFormat { get; set; } = "text";
    public bool CoverageGapsOnly { get; set; }
    public string RiskMatrixFormat { get; set; } = "text";
    public bool RiskMatrixCounts { get; set; }
    public int NoiseDays { get; set; } = 90;
    public int NoiseTop { get; set; } = 15;
    public string NoiseFormat { get; set; } = "text";
    public int GamifyDays { get; set; } = 365;
    public string GamifyFormat { get; set; } = "text";
    public HabitAction HabitAction { get; set; } = HabitAction.Report;
    public string? HabitName { get; set; }
    public string? HabitCategory { get; set; }
    public string? HabitFrequency { get; set; }
    public string? HabitDate { get; set; }
    public int HabitDays { get; set; } = 30;
    public int HeatmapWeeks { get; set; } = 26;
    public string HeatmapFormat { get; set; } = "text";
    public string MaturityFormat { get; set; } = "text";
    public bool MaturityGapsOnly { get; set; }
    public int WatchIntervalSeconds { get; set; } = 300;
    public int WatchMaxRuns { get; set; } = 0;
    public bool WatchBeep { get; set; }
    public string AttackSurfaceFormat { get; set; } = "text";
    public int AttackSurfaceTop { get; set; } = 10;
    public string PlaybookFormat { get; set; } = "text";
    public string? PlaybookId { get; set; }
    public bool PlaybookListAll { get; set; }
    public bool PlaybookVerbose { get; set; }
    public string? GrepPattern { get; set; }
    public string? GrepSeverityFilter { get; set; }
    public string? GrepModuleFilter { get; set; }
    public bool GrepCaseSensitive { get; set; }
    public bool GrepCountOnly { get; set; }
    public bool GrepShowContext { get; set; } = true;
    public string GrepFormat { get; set; } = "text";
    public int GrepMaxResults { get; set; } = 100;
    public int DepGraphTop { get; set; } = 10;
    public string DepGraphFormat { get; set; } = "text";
    public int TriageTop { get; set; } = 20;
    public string CookbookFormat { get; set; } = "text";
    public string? CookbookSeverityFilter { get; set; }
    public string? CookbookModuleFilter { get; set; }
    public string? CookbookCategoryFilter { get; set; }
    public bool CookbookFixableOnly { get; set; }
    public string? TriageSeverityFilter { get; set; }
    public string? TriageModuleFilter { get; set; }
    public bool TriageFixableOnly { get; set; }
    public string DebtSortBy { get; set; } = "roi";
    public string? DebtSeverityFilter { get; set; }
    public string? DebtModuleFilter { get; set; }
    public int DebtTop { get; set; } = 50;
    public int WatchdogDays { get; set; } = 30;
    public double WatchdogWarnZ { get; set; } = 1.5;
    public double WatchdogCritZ { get; set; } = 2.5;
    public int ClusterTop { get; set; } = 15;
    public double ClusterThreshold { get; set; } = 0.6;
    public string ClusterFormat { get; set; } = "text";
    public string? ClusterSeverityFilter { get; set; }
    public string? ClusterModuleFilter { get; set; }
    public int ForecastDays { get; set; } = 30;
    public int ForecastHistoryDays { get; set; } = 90;
    public string ForecastFormat { get; set; } = "text";
    public bool ForecastWeekly { get; set; }
    public string ReportCardFormat { get; set; } = "text";
    public int ReportCardDays { get; set; } = 30;
    public int BurndownDays { get; set; } = 90;
    public int BurndownWidth { get; set; } = 60;
    public string BurndownFormat { get; set; } = "text";
    public string? BurndownSeverityFilter { get; set; }
    public int ChangelogDays { get; set; } = 30;
    public string ChangelogFormat { get; set; } = "text";
    public string ChangelogGroupBy { get; set; } = "week";
    public int PatrolDays { get; set; } = 30;
    public string PatrolFormat { get; set; } = "text";
    public int RadarDays { get; set; } = 90;
    public string RadarFormat { get; set; } = "text";
    public int GenomeDays { get; set; } = 90;
    public string GenomeFormat { get; set; } = "text";
    public int CorrelateMinModules { get; set; } = 2;
    public string? CorrelateSeverityFilter { get; set; }
    public int CorrelateTop { get; set; } = 15;
    public int RadarSize { get; set; } = 14;
    public int PulseDays { get; set; } = 60;
    public int PulseWidth { get; set; } = 60;
    public string PulseFormat { get; set; } = "text";
    public int PulseAlertBelow { get; set; } = 50;
    public bool PulseShowFindings { get; set; }
    public int CalendarDays { get; set; } = 90;
    public int CalendarForecastDays { get; set; } = 30;
    public string CalendarFormat { get; set; } = "text";
    public bool CalendarIncludeSla { get; set; } = true;
    public bool CalendarIncludeAudits { get; set; } = true;
    public bool CalendarIncludeReviews { get; set; } = true;
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
    Coverage,
    RiskMatrix,
    Noise,
    Gamify,
    Heatmap,
    Maturity,
    Watch,
    AttackSurface,
    Playbook,
    Quick,
    Habits,
    Grep,
    DepGraph,
    Triage,
    Cookbook,
    Cluster,
    Forecast,
    ReportCard,
    Burndown,
    Changelog,
    Pulse,
    Calendar,
    Debt,
    Watchdog,
    Patrol,
    Radar,
    Genome,
    Correlate,
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

public enum HabitAction
{
    Report,
    Add,
    Remove,
    Complete,
    List
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

                case "--coverage":
                    options.Command = CliCommand.Coverage;
                    break;

                case "--coverage-format":
                    if (!TryConsumeArg(args, ref i, "--coverage-format", out var covFmt, out var covFmtErr))
                    { options.Error = covFmtErr; return options; }
                    options.CoverageFormat = covFmt.ToLowerInvariant();
                    break;

                case "--coverage-gaps":
                    options.CoverageGapsOnly = true;
                    break;

                case "--risk-matrix":
                    options.Command = CliCommand.RiskMatrix;
                    break;

                case "--risk-matrix-format":
                    if (!TryConsumeArg(args, ref i, "--risk-matrix-format", out var rmFmt, out var rmFmtErr))
                    { options.Error = rmFmtErr; return options; }
                    options.RiskMatrixFormat = rmFmt.ToLowerInvariant();
                    break;

                case "--risk-matrix-counts":
                    options.RiskMatrixCounts = true;
                    break;

                case "--noise":
                    options.Command = CliCommand.Noise;
                    break;

                case "--noise-days":
                    if (!TryConsumeArg(args, ref i, "--noise-days", out var noiseDaysStr, out var noiseDaysErr))
                    { options.Error = noiseDaysErr; return options; }
                    if (int.TryParse(noiseDaysStr, out var noiseDays))
                        options.NoiseDays = noiseDays;
                    break;

                case "--noise-top":
                    if (!TryConsumeArg(args, ref i, "--noise-top", out var noiseTopStr, out var noiseTopErr))
                    { options.Error = noiseTopErr; return options; }
                    if (int.TryParse(noiseTopStr, out var noiseTop))
                        options.NoiseTop = noiseTop;
                    break;

                case "--noise-format":
                    if (!TryConsumeArg(args, ref i, "--noise-format", out var noiseFmt, out var noiseFmtErr))
                    { options.Error = noiseFmtErr; return options; }
                    options.NoiseFormat = noiseFmt.ToLowerInvariant();
                    break;

                case "--gamify":
                    options.Command = CliCommand.Gamify;
                    break;

                case "--gamify-days":
                    if (!TryConsumeArg(args, ref i, "--gamify-days", out var gamifyDaysStr, out var gamifyDaysErr))
                    { options.Error = gamifyDaysErr; return options; }
                    if (int.TryParse(gamifyDaysStr, out var gamifyDays))
                        options.GamifyDays = gamifyDays;
                    break;

                case "--gamify-format":
                    if (!TryConsumeArg(args, ref i, "--gamify-format", out var gamifyFmt, out var gamifyFmtErr))
                    { options.Error = gamifyFmtErr; return options; }
                    options.GamifyFormat = gamifyFmt.ToLowerInvariant();
                    break;

                case "--heatmap":
                    options.Command = CliCommand.Heatmap;
                    break;

                case "--habits":
                    options.Command = CliCommand.Habits;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        var sub = args[++i].ToLowerInvariant();
                        options.HabitAction = sub switch
                        {
                            "add" => HabitAction.Add,
                            "remove" => HabitAction.Remove,
                            "complete" or "done" => HabitAction.Complete,
                            "list" => HabitAction.List,
                            "report" => HabitAction.Report,
                            _ => HabitAction.Report
                        };
                    }
                    break;

                case "--habit-name":
                    if (!TryConsumeArg(args, ref i, "--habit-name", out var habitName, out var habitNameErr))
                    { options.Error = habitNameErr; return options; }
                    options.HabitName = habitName;
                    break;

                case "--habit-category":
                    if (!TryConsumeArg(args, ref i, "--habit-category", out var habitCat, out var habitCatErr))
                    { options.Error = habitCatErr; return options; }
                    options.HabitCategory = habitCat;
                    break;

                case "--habit-frequency":
                    if (!TryConsumeArg(args, ref i, "--habit-frequency", out var habitFreq, out var habitFreqErr))
                    { options.Error = habitFreqErr; return options; }
                    options.HabitFrequency = habitFreq;
                    break;

                case "--habit-date":
                    if (!TryConsumeArg(args, ref i, "--habit-date", out var habitDate, out var habitDateErr))
                    { options.Error = habitDateErr; return options; }
                    options.HabitDate = habitDate;
                    break;

                case "--habit-days":
                    if (!TryConsumeArg(args, ref i, "--habit-days", out var habitDaysStr, out var habitDaysErr))
                    { options.Error = habitDaysErr; return options; }
                    if (int.TryParse(habitDaysStr, out var habitDays))
                        options.HabitDays = habitDays;
                    break;

                case "--heatmap-weeks":
                    if (!TryConsumeArg(args, ref i, "--heatmap-weeks", out var heatmapWeeksStr, out var heatmapWeeksErr))
                    { options.Error = heatmapWeeksErr; return options; }
                    if (int.TryParse(heatmapWeeksStr, out var heatmapWeeks))
                        options.HeatmapWeeks = heatmapWeeks;
                    break;

                case "--heatmap-format":
                    if (!TryConsumeArg(args, ref i, "--heatmap-format", out var heatmapFmt, out var heatmapFmtErr))
                    { options.Error = heatmapFmtErr; return options; }
                    options.HeatmapFormat = heatmapFmt.ToLowerInvariant();
                    break;

                case "--maturity":
                    options.Command = CliCommand.Maturity;
                    break;

                case "--maturity-format":
                    if (!TryConsumeArg(args, ref i, "--maturity-format", out var maturityFmt, out var maturityFmtErr))
                    { options.Error = maturityFmtErr; return options; }
                    options.MaturityFormat = maturityFmt.ToLowerInvariant();
                    break;

                case "--maturity-gaps-only":
                    options.MaturityGapsOnly = true;
                    break;

                case "--watch":
                    options.Command = CliCommand.Watch;
                    break;

                case "--watch-interval":
                    if (!TryConsumeArg(args, ref i, "--watch-interval", out var watchInt, out var watchIntErr))
                    { options.Error = watchIntErr; return options; }
                    if (!int.TryParse(watchInt, out var watchSec) || watchSec < 10)
                    { options.Error = "--watch-interval must be >= 10 seconds"; return options; }
                    options.WatchIntervalSeconds = watchSec;
                    break;

                case "--watch-max":
                    if (!TryConsumeArg(args, ref i, "--watch-max", out var watchMax, out var watchMaxErr))
                    { options.Error = watchMaxErr; return options; }
                    if (!int.TryParse(watchMax, out var maxRuns) || maxRuns < 1)
                    { options.Error = "--watch-max must be >= 1"; return options; }
                    options.WatchMaxRuns = maxRuns;
                    break;

                case "--watch-beep":
                    options.WatchBeep = true;
                    break;

                case "--quick":
                    options.Command = CliCommand.Quick;
                    break;

                case "--attack-surface":
                    options.Command = CliCommand.AttackSurface;
                    break;

                case "--attack-surface-format":
                    if (!TryConsumeArg(args, ref i, "--attack-surface-format", out var asFmt, out var asFmtErr))
                    { options.Error = asFmtErr; return options; }
                    options.AttackSurfaceFormat = asFmt.ToLowerInvariant();
                    break;

                case "--attack-surface-top":
                    if (!TryConsumeInt(args, ref i, "--attack-surface-top", 1, 50, out var asTop, out var asTopErr))
                    { options.Error = asTopErr; return options; }
                    options.AttackSurfaceTop = asTop;
                    break;

                case "--playbook":
                    options.Command = CliCommand.Playbook;
                    break;

                case "--playbook-format":
                    if (!TryConsumeArg(args, ref i, "--playbook-format", out var pbFmt, out var pbFmtErr))
                    { options.Error = pbFmtErr; return options; }
                    options.PlaybookFormat = pbFmt.ToLowerInvariant();
                    break;

                case "--playbook-id":
                    if (!TryConsumeArg(args, ref i, "--playbook-id", out var pbId, out var pbIdErr))
                    { options.Error = pbIdErr; return options; }
                    options.PlaybookId = pbId;
                    break;

                case "--playbook-list":
                    options.Command = CliCommand.Playbook;
                    options.PlaybookListAll = true;
                    break;

                case "--playbook-verbose":
                    options.PlaybookVerbose = true;
                    break;

                case "--grep":
                case "grep":
                    options.Command = CliCommand.Grep;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        options.GrepPattern = args[++i];
                    }
                    break;

                case "--grep-pattern":
                    if (!TryConsumeArg(args, ref i, "--grep-pattern", out var gPat, out var gPatErr))
                    { options.Error = gPatErr; return options; }
                    options.GrepPattern = gPat;
                    break;

                case "--grep-severity":
                    if (!TryConsumeArg(args, ref i, "--grep-severity", out var gSev, out var gSevErr))
                    { options.Error = gSevErr; return options; }
                    options.GrepSeverityFilter = gSev.ToLowerInvariant();
                    break;

                case "--grep-module":
                    if (!TryConsumeArg(args, ref i, "--grep-module", out var gMod, out var gModErr))
                    { options.Error = gModErr; return options; }
                    options.GrepModuleFilter = gMod.ToLowerInvariant();
                    break;

                case "--grep-case-sensitive":
                    options.GrepCaseSensitive = true;
                    break;

                case "--grep-count":
                    options.GrepCountOnly = true;
                    break;

                case "--grep-no-context":
                    options.GrepShowContext = false;
                    break;

                case "--grep-format":
                    if (!TryConsumeArg(args, ref i, "--grep-format", out var gFmt, out var gFmtErr))
                    { options.Error = gFmtErr; return options; }
                    options.GrepFormat = gFmt.ToLowerInvariant();
                    break;

                case "--grep-max":
                    if (!TryConsumeInt(args, ref i, "--grep-max", 1, 1000, out var gMax, out var gMaxErr))
                    { options.Error = gMaxErr; return options; }
                    options.GrepMaxResults = gMax;
                    break;

                case "--depgraph":
                case "depgraph":
                    options.Command = CliCommand.DepGraph;
                    break;

                case "--depgraph-top":
                    if (!TryConsumeInt(args, ref i, "--depgraph-top", 1, 100, out var dgTop, out var dgTopErr))
                    { options.Error = dgTopErr; return options; }
                    options.DepGraphTop = dgTop;
                    break;

                case "--depgraph-format":
                    if (!TryConsumeArg(args, ref i, "--depgraph-format", out var dgFmt, out var dgFmtErr))
                    { options.Error = dgFmtErr; return options; }
                    options.DepGraphFormat = dgFmt.ToLowerInvariant();
                    break;

                case "--triage":
                case "triage":
                    options.Command = CliCommand.Triage;
                    break;

                case "--triage-top":
                    if (!TryConsumeInt(args, ref i, "--triage-top", 1, 200, out var trTop, out var trTopErr))
                    { options.Error = trTopErr; return options; }
                    options.TriageTop = trTop;
                    break;

                case "--triage-severity":
                    if (!TryConsumeArg(args, ref i, "--triage-severity", out var trSev, out var trSevErr))
                    { options.Error = trSevErr; return options; }
                    options.TriageSeverityFilter = trSev;
                    break;

                case "--triage-module":
                    if (!TryConsumeArg(args, ref i, "--triage-module", out var trMod, out var trModErr))
                    { options.Error = trModErr; return options; }
                    options.TriageModuleFilter = trMod;
                    break;

                case "--triage-fixable":
                    options.TriageFixableOnly = true;
                    break;

                case "--debt":
                case "debt":
                    options.Command = CliCommand.Debt;
                    break;

                case "--debt-sort":
                    if (!TryConsumeArg(args, ref i, "--debt-sort", out var debtSort, out var debtSortErr))
                    { options.Error = debtSortErr; return options; }
                    options.DebtSortBy = debtSort;
                    break;

                case "--debt-severity":
                    if (!TryConsumeArg(args, ref i, "--debt-severity", out var debtSev, out var debtSevErr))
                    { options.Error = debtSevErr; return options; }
                    options.DebtSeverityFilter = debtSev;
                    break;

                case "--debt-module":
                    if (!TryConsumeArg(args, ref i, "--debt-module", out var debtMod, out var debtModErr))
                    { options.Error = debtModErr; return options; }
                    options.DebtModuleFilter = debtMod;
                    break;

                case "--debt-top":
                    if (!TryConsumeInt(args, ref i, "--debt-top", 1, 500, out var debtTop, out var debtTopErr))
                    { options.Error = debtTopErr; return options; }
                    options.DebtTop = debtTop;
                    break;

                case "--watchdog":
                case "watchdog":
                    options.Command = CliCommand.Watchdog;
                    break;

                case "--watchdog-days":
                    if (!TryConsumeInt(args, ref i, "--watchdog-days", 7, 365, out var wdDays, out var wdDaysErr))
                    { options.Error = wdDaysErr; return options; }
                    options.WatchdogDays = wdDays;
                    break;

                case "--watchdog-warn-z":
                    if (!TryConsumeArg(args, ref i, "--watchdog-warn-z", out var wdWarn, out var wdWarnErr))
                    { options.Error = wdWarnErr; return options; }
                    if (double.TryParse(wdWarn, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var wdWarnVal))
                        options.WatchdogWarnZ = wdWarnVal;
                    break;

                case "--watchdog-crit-z":
                    if (!TryConsumeArg(args, ref i, "--watchdog-crit-z", out var wdCrit, out var wdCritErr))
                    { options.Error = wdCritErr; return options; }
                    if (double.TryParse(wdCrit, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var wdCritVal))
                        options.WatchdogCritZ = wdCritVal;
                    break;

                case "--cookbook":
                case "cookbook":
                    options.Command = CliCommand.Cookbook;
                    break;

                case "--cookbook-format":
                    if (!TryConsumeArg(args, ref i, "--cookbook-format", out var cbFmt, out var cbFmtErr))
                    { options.Error = cbFmtErr; return options; }
                    options.CookbookFormat = cbFmt.ToLowerInvariant();
                    break;

                case "--cookbook-severity":
                    if (!TryConsumeArg(args, ref i, "--cookbook-severity", out var cbSev, out var cbSevErr))
                    { options.Error = cbSevErr; return options; }
                    options.CookbookSeverityFilter = cbSev;
                    break;

                case "--cookbook-module":
                    if (!TryConsumeArg(args, ref i, "--cookbook-module", out var cbMod, out var cbModErr))
                    { options.Error = cbModErr; return options; }
                    options.CookbookModuleFilter = cbMod;
                    break;

                case "--cookbook-category":
                    if (!TryConsumeArg(args, ref i, "--cookbook-category", out var cbCat, out var cbCatErr))
                    { options.Error = cbCatErr; return options; }
                    options.CookbookCategoryFilter = cbCat;
                    break;

                case "--cookbook-fixable":
                    options.CookbookFixableOnly = true;
                    break;

                case "--cluster":
                case "cluster":
                    options.Command = CliCommand.Cluster;
                    break;

                case "--cluster-top":
                    if (!TryConsumeArg(args, ref i, "--cluster-top", out var clTop, out var clTopErr))
                    { options.Error = clTopErr; return options; }
                    if (int.TryParse(clTop, out var clTopVal))
                        options.ClusterTop = clTopVal;
                    break;

                case "--cluster-threshold":
                    if (!TryConsumeArg(args, ref i, "--cluster-threshold", out var clThresh, out var clThreshErr))
                    { options.Error = clThreshErr; return options; }
                    if (double.TryParse(clThresh, System.Globalization.CultureInfo.InvariantCulture, out var clThreshVal))
                        options.ClusterThreshold = Math.Clamp(clThreshVal, 0.1, 1.0);
                    break;

                case "--cluster-format":
                    if (!TryConsumeArg(args, ref i, "--cluster-format", out var clFmt, out var clFmtErr))
                    { options.Error = clFmtErr; return options; }
                    options.ClusterFormat = clFmt.ToLowerInvariant();
                    break;

                case "--cluster-severity":
                    if (!TryConsumeArg(args, ref i, "--cluster-severity", out var clSev, out var clSevErr))
                    { options.Error = clSevErr; return options; }
                    options.ClusterSeverityFilter = clSev;
                    break;

                case "--cluster-module":
                    if (!TryConsumeArg(args, ref i, "--cluster-module", out var clMod, out var clModErr))
                    { options.Error = clModErr; return options; }
                    options.ClusterModuleFilter = clMod;
                    break;

                case "--forecast":
                case "forecast":
                    options.Command = CliCommand.Forecast;
                    break;

                case "--forecast-days":
                    if (!TryConsumeArg(args, ref i, "--forecast-days", out var fcDays, out var fcDaysErr))
                    { options.Error = fcDaysErr; return options; }
                    if (int.TryParse(fcDays, out var fcDaysVal))
                        options.ForecastDays = Math.Clamp(fcDaysVal, 1, 365);
                    break;

                case "--forecast-history":
                    if (!TryConsumeArg(args, ref i, "--forecast-history", out var fcHist, out var fcHistErr))
                    { options.Error = fcHistErr; return options; }
                    if (int.TryParse(fcHist, out var fcHistVal))
                        options.ForecastHistoryDays = Math.Clamp(fcHistVal, 7, 365);
                    break;

                case "--forecast-format":
                    if (!TryConsumeArg(args, ref i, "--forecast-format", out var fcFmt, out var fcFmtErr))
                    { options.Error = fcFmtErr; return options; }
                    options.ForecastFormat = fcFmt.ToLowerInvariant();
                    break;

                case "--forecast-weekly":
                    options.ForecastWeekly = true;
                    break;

                case "--reportcard":
                case "reportcard":
                    options.Command = CliCommand.ReportCard;
                    break;

                case "--reportcard-format":
                    if (!TryConsumeArg(args, ref i, "--reportcard-format", out var rcFmt, out var rcFmtErr))
                    { options.Error = rcFmtErr; return options; }
                    options.ReportCardFormat = rcFmt.ToLowerInvariant();
                    break;

                case "--reportcard-days":
                    if (!TryConsumeArg(args, ref i, "--reportcard-days", out var rcDays, out var rcDaysErr))
                    { options.Error = rcDaysErr; return options; }
                    if (int.TryParse(rcDays, out var rcDaysVal))
                        options.ReportCardDays = Math.Clamp(rcDaysVal, 1, 365);
                    break;

                case "--burndown":
                case "burndown":
                    options.Command = CliCommand.Burndown;
                    break;

                case "--burndown-days":
                    if (!TryConsumeArg(args, ref i, "--burndown-days", out var bdDays, out var bdDaysErr))
                    { options.Error = bdDaysErr; return options; }
                    if (int.TryParse(bdDays, out var bdDaysVal))
                        options.BurndownDays = Math.Clamp(bdDaysVal, 7, 365);
                    break;

                case "--burndown-width":
                    if (!TryConsumeArg(args, ref i, "--burndown-width", out var bdW, out var bdWErr))
                    { options.Error = bdWErr; return options; }
                    if (int.TryParse(bdW, out var bdWVal))
                        options.BurndownWidth = Math.Clamp(bdWVal, 20, 120);
                    break;

                case "--burndown-format":
                    if (!TryConsumeArg(args, ref i, "--burndown-format", out var bdFmt, out var bdFmtErr))
                    { options.Error = bdFmtErr; return options; }
                    options.BurndownFormat = bdFmt.ToLowerInvariant();
                    break;

                case "--burndown-severity":
                    if (!TryConsumeArg(args, ref i, "--burndown-severity", out var bdSev, out var bdSevErr))
                    { options.Error = bdSevErr; return options; }
                    options.BurndownSeverityFilter = bdSev.ToLowerInvariant();
                    break;

                case "--changelog":
                case "changelog":
                    options.Command = CliCommand.Changelog;
                    break;

                case "--changelog-days":
                    if (!TryConsumeArg(args, ref i, "--changelog-days", out var clDays, out var clDaysErr))
                    { options.Error = clDaysErr; return options; }
                    if (int.TryParse(clDays, out var clDaysVal))
                        options.ChangelogDays = Math.Clamp(clDaysVal, 7, 365);
                    break;

                case "--changelog-format":
                    if (!TryConsumeArg(args, ref i, "--changelog-format", out var chgFmt, out var chgFmtErr))
                    { options.Error = chgFmtErr; return options; }
                    options.ChangelogFormat = chgFmt.ToLowerInvariant();
                    break;

                case "--changelog-group":
                    if (!TryConsumeArg(args, ref i, "--changelog-group", out var chgGrp, out var chgGrpErr))
                    { options.Error = chgGrpErr; return options; }
                    options.ChangelogGroupBy = chgGrp.ToLowerInvariant();
                    break;

                case "--pulse":
                case "pulse":
                    options.Command = CliCommand.Pulse;
                    break;

                case "--pulse-days":
                    if (!TryConsumeArg(args, ref i, "--pulse-days", out var plDays, out var plDaysErr))
                    { options.Error = plDaysErr; return options; }
                    if (int.TryParse(plDays, out var plDaysVal))
                        options.PulseDays = Math.Clamp(plDaysVal, 7, 365);
                    break;

                case "--pulse-width":
                    if (!TryConsumeArg(args, ref i, "--pulse-width", out var plW, out var plWErr))
                    { options.Error = plWErr; return options; }
                    if (int.TryParse(plW, out var plWVal))
                        options.PulseWidth = Math.Clamp(plWVal, 20, 120);
                    break;

                case "--pulse-format":
                    if (!TryConsumeArg(args, ref i, "--pulse-format", out var plFmt, out var plFmtErr))
                    { options.Error = plFmtErr; return options; }
                    options.PulseFormat = plFmt.ToLowerInvariant();
                    break;

                case "--pulse-alert-below":
                    if (!TryConsumeArg(args, ref i, "--pulse-alert-below", out var plAlert, out var plAlertErr))
                    { options.Error = plAlertErr; return options; }
                    if (int.TryParse(plAlert, out var plAlertVal))
                        options.PulseAlertBelow = Math.Clamp(plAlertVal, 0, 100);
                    break;

                case "--pulse-findings":
                    options.PulseShowFindings = true;
                    break;

                case "--calendar":
                case "calendar":
                    options.Command = CliCommand.Calendar;
                    break;

                case "--calendar-days":
                    if (!TryConsumeArg(args, ref i, "--calendar-days", out var calDays, out var calDaysErr))
                    { options.Error = calDaysErr; return options; }
                    if (int.TryParse(calDays, out var calDaysVal))
                        options.CalendarDays = Math.Max(calDaysVal, 7);
                    break;

                case "--calendar-forecast":
                    if (!TryConsumeArg(args, ref i, "--calendar-forecast", out var calFc, out var calFcErr))
                    { options.Error = calFcErr; return options; }
                    if (int.TryParse(calFc, out var calFcVal))
                        options.CalendarForecastDays = Math.Max(calFcVal, 7);
                    break;

                case "--calendar-format":
                    if (!TryConsumeArg(args, ref i, "--calendar-format", out var calFmt, out var calFmtErr))
                    { options.Error = calFmtErr; return options; }
                    options.CalendarFormat = calFmt.ToLowerInvariant();
                    break;

                case "--calendar-no-sla":
                    options.CalendarIncludeSla = false;
                    break;

                case "--calendar-no-audits":
                    options.CalendarIncludeAudits = false;
                    break;

                case "--calendar-no-reviews":
                    options.CalendarIncludeReviews = false;
                    break;

                case "--patrol":
                case "patrol":
                    options.Command = CliCommand.Patrol;
                    break;

                case "--radar":
                case "radar":
                    options.Command = CliCommand.Radar;
                    break;

                case "--radar-days":
                    if (!TryConsumeArg(args, ref i, "--radar-days", out var radarDaysVal, out var radarDaysErr))
                    { options.Error = radarDaysErr; return options; }
                    if (int.TryParse(radarDaysVal, out var radarDaysInt))
                        options.RadarDays = Math.Clamp(radarDaysInt, 7, 365);
                    break;

                case "--radar-format":
                    if (!TryConsumeArg(args, ref i, "--radar-format", out var radarFmt, out var radarFmtErr))
                    { options.Error = radarFmtErr; return options; }
                    options.RadarFormat = radarFmt.ToLowerInvariant();
                    break;

                case "--radar-size":
                    if (!TryConsumeArg(args, ref i, "--radar-size", out var radarSz, out var radarSzErr))
                    { options.Error = radarSzErr; return options; }
                    if (int.TryParse(radarSz, out var radarSzInt))
                        options.RadarSize = Math.Clamp(radarSzInt, 8, 30);
                    break;

                case "--genome":
                case "genome":
                    options.Command = CliCommand.Genome;
                    break;

                case "--genome-days":
                    if (!TryConsumeArg(args, ref i, "--genome-days", out var genomeDaysVal, out var genomeDaysErr))
                    { options.Error = genomeDaysErr; return options; }
                    if (int.TryParse(genomeDaysVal, out var genomeDaysInt))
                        options.GenomeDays = Math.Clamp(genomeDaysInt, 7, 365);
                    break;

                case "--genome-format":
                    if (!TryConsumeArg(args, ref i, "--genome-format", out var genomeFmt, out var genomeFmtErr))
                    { options.Error = genomeFmtErr; return options; }
                    options.GenomeFormat = genomeFmt.ToLowerInvariant();
                    break;

                case "--correlate":
                case "correlate":
                    options.Command = CliCommand.Correlate;
                    break;

                case "--correlate-min-modules":
                    if (!TryConsumeArg(args, ref i, "--correlate-min-modules", out var corrMinVal, out var corrMinErr))
                    { options.Error = corrMinErr; return options; }
                    if (int.TryParse(corrMinVal, out var corrMinInt))
                        options.CorrelateMinModules = Math.Clamp(corrMinInt, 2, 10);
                    break;

                case "--correlate-severity":
                    if (!TryConsumeArg(args, ref i, "--correlate-severity", out var corrSevVal, out var corrSevErr))
                    { options.Error = corrSevErr; return options; }
                    options.CorrelateSeverityFilter = corrSevVal;
                    break;

                case "--correlate-top":
                    if (!TryConsumeArg(args, ref i, "--correlate-top", out var corrTopVal, out var corrTopErr))
                    { options.Error = corrTopErr; return options; }
                    if (int.TryParse(corrTopVal, out var corrTopInt))
                        options.CorrelateTop = Math.Clamp(corrTopInt, 1, 50);
                    break;

                case "--patrol-days":
                    if (!TryConsumeArg(args, ref i, "--patrol-days", out var patDays, out var patDaysErr))
                    { options.Error = patDaysErr; return options; }
                    if (int.TryParse(patDays, out var patDaysVal))
                        options.PatrolDays = Math.Clamp(patDaysVal, 7, 365);
                    break;

                case "--patrol-format":
                    if (!TryConsumeArg(args, ref i, "--patrol-format", out var patFmt, out var patFmtErr))
                    { options.Error = patFmtErr; return options; }
                    options.PatrolFormat = patFmt.ToLowerInvariant();
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
