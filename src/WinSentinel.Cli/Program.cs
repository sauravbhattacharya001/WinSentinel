using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Cli;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

// ── Entry Point ──────────────────────────────────────────────────────

var options = CliParser.Parse(args);

if (options.Error != null)
{
    ConsoleFormatter.PrintError(options.Error);
    return 3;
}

return options.Command switch
{
    CliCommand.Help => HandleHelp(),
    CliCommand.Version => HandleVersion(),
    CliCommand.Score => await HandleScore(options),
    CliCommand.Audit => await HandleAudit(options),
    CliCommand.FixAll => await HandleFixAll(options),
    CliCommand.History => HandleHistory(options),
    CliCommand.Baseline => await HandleBaseline(options),
    CliCommand.Checklist => await HandleChecklist(options),
    CliCommand.Profiles => HandleProfiles(options),
    CliCommand.Ignore => HandleIgnore(options),
    CliCommand.Trend => HandleTrend(options),
    CliCommand.Timeline => HandleTimeline(options),
    CliCommand.FindingAge => HandleFindingAge(options),
    CliCommand.Status => HandleStatus(options),
    CliCommand.Harden => await HandleHarden(options),
    CliCommand.Policy => PolicyCommandHandler.Handle(options),
    CliCommand.Exemptions => HandleExemptions(options),
    CliCommand.Quiz => await HandleQuiz(options),
    CliCommand.RootCause => await HandleRootCause(options),
    CliCommand.Threats => await HandleThreats(options),
    CliCommand.ScheduleOptimize => HandleScheduleOptimize(options),
    CliCommand.Digest => await HandleDigest(options),
    CliCommand.AttackPaths => await HandleAttackPaths(options),
    CliCommand.Summary => await HandleSummary(options),
    _ => HandleHelp()
};

// ── Harden Script Generator ──────────────────────────────────────────

static async Task<int> HandleHarden(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit to generate hardening script...");
        Console.WriteLine();
    }

    var progress = options.Quiet
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
        ConsoleFormatter.PrintScore(report.SecurityScore);
    }

    var generator = new HardenScriptGenerator();
    var hardenOptions = new HardenScriptOptions
    {
        Interactive = options.HardenInteractive,
        DryRun = options.HardenDryRun,
        IncludeInfo = options.HardenIncludeInfo,
    };

    var script = generator.Generate(report, hardenOptions);

    var outputFile = options.OutputFile ?? "harden.ps1";
    var dir = Path.GetDirectoryName(Path.GetFullPath(outputFile));
    if (!string.IsNullOrEmpty(dir))
    {
        Directory.CreateDirectory(dir);
    }
    File.WriteAllText(outputFile, script);

    if (!options.Quiet)
    {
        var fixableCount = report.Results
            .SelectMany(r => r.Findings)
            .Count(f => f.Severity is Severity.Critical or Severity.Warning && !string.IsNullOrWhiteSpace(f.FixCommand));

        var original = Console.ForegroundColor;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Hardening script saved to {outputFile}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"    {fixableCount} fixable findings included");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine();
        Console.WriteLine("  Usage:");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"    .\\{outputFile}              # Interactive mode (prompts per fix)");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine();
        Console.WriteLine("  Generation options:");
        Console.WriteLine("    --no-prompt       Skip prompts (auto-apply all)");
        Console.WriteLine("    --dry-run         Preview without executing");
        Console.WriteLine("    --include-info    Include info-level fixes too");
        Console.WriteLine("    -o <file>         Custom output path (default: harden.ps1)");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    return 0;
}

// ── Status Dashboard ─────────────────────────────────────────────────

static int HandleStatus(CliOptions options)
{
    using var historyService = new AuditHistoryService();
    historyService.EnsureDatabase();

    var ignoreService = new IgnoreRuleService();
    var baselineService = new BaselineService();

    // Gather data
    var recentRuns = historyService.GetRecentRuns(5);
    var ignoreRules = ignoreService.GetActiveRules();
    var baselines = baselineService.ListBaselines();
    var totalScans = historyService.GetRunCount();

    var lastRun = recentRuns.Count > 0 ? recentRuns[0] : null;
    var previousRun = recentRuns.Count > 1 ? recentRuns[1] : null;

    ScoreTrendSummary? trend = null;
    if (recentRuns.Count > 0)
    {
        trend = historyService.GetTrend(30);
    }

    if (options.Json)
    {
        var statusObj = new
        {
            system = new
            {
                machine = Environment.MachineName,
                os = Environment.OSVersion.ToString(),
                user = Environment.UserName,
                is64bit = Environment.Is64BitOperatingSystem,
                processors = Environment.ProcessorCount,
                uptime = TimeSpan.FromMilliseconds(Environment.TickCount64).ToString(@"d\.hh\:mm\:ss"),
                timestamp = DateTimeOffset.Now
            },
            lastScan = lastRun != null ? new
            {
                timestamp = lastRun.Timestamp,
                score = lastRun.OverallScore,
                grade = lastRun.Grade,
                critical = lastRun.CriticalCount,
                warnings = lastRun.WarningCount,
                totalFindings = lastRun.TotalFindings,
                ago = FormatTimeAgo(lastRun.Timestamp)
            } : null,
            scoreTrend = trend != null ? new
            {
                current = trend.CurrentScore,
                previous = trend.PreviousScore,
                change = trend.ScoreChange,
                direction = trend.ChangeDirection,
                best = trend.BestScore,
                bestDate = trend.BestScoreDate,
                worst = trend.WorstScore,
                worstDate = trend.WorstScoreDate,
                average = Math.Round(trend.AverageScore, 1),
                totalScans = trend.TotalScans
            } : null,
            ignoreRules = new
            {
                active = ignoreRules.Count,
            },
            baselines = new
            {
                saved = baselines.Count,
                names = baselines.Select(b => b.Name).ToList()
            },
            totalScans
        };

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(statusObj, jsonOptions);
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    // Console output
    var orig = Console.ForegroundColor;

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("  ╔══════════════════════════════════════════════╗");
    Console.WriteLine("  ║       🛡️  WinSentinel Status Dashboard      ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════╝");
    Console.ForegroundColor = orig;
    Console.WriteLine();

    // ── System Info ──
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("  SYSTEM");
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  ──────────────────────────────────────────");
    Console.ForegroundColor = orig;
    Console.Write("  Machine:    ");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine(Environment.MachineName);
    Console.ForegroundColor = orig;
    Console.Write("  OS:         ");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine(Environment.OSVersion);
    Console.ForegroundColor = orig;
    Console.Write("  User:       ");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine(Environment.UserName);
    Console.ForegroundColor = orig;
    var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
    Console.Write("  Uptime:     ");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine($"{(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m");
    Console.ForegroundColor = orig;
    Console.WriteLine();

    // ── Last Scan ──
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("  LAST SCAN");
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  ──────────────────────────────────────────");
    Console.ForegroundColor = orig;

    if (lastRun != null)
    {
        Console.Write("  Score:      ");
        var scoreColor = GetScoreColor(lastRun.OverallScore);
        Console.ForegroundColor = scoreColor;
        Console.WriteLine($"{lastRun.OverallScore}/100 ({lastRun.Grade})");
        Console.ForegroundColor = orig;

        Console.Write("  When:       ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{lastRun.Timestamp.LocalDateTime:g} ({FormatTimeAgo(lastRun.Timestamp)})");
        Console.ForegroundColor = orig;

        Console.Write("  Findings:   ");
        if (lastRun.CriticalCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"{lastRun.CriticalCount} critical");
            Console.ForegroundColor = orig;
            Console.Write(", ");
        }
        if (lastRun.WarningCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"{lastRun.WarningCount} warnings");
            Console.ForegroundColor = orig;
        }
        if (lastRun.CriticalCount == 0 && lastRun.WarningCount == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("All clear!");
            Console.ForegroundColor = orig;
        }
        Console.WriteLine();

        if (previousRun != null)
        {
            var delta = lastRun.OverallScore - previousRun.OverallScore;
            Console.Write("  Change:     ");
            if (delta > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"↑ +{delta} points (was {previousRun.OverallScore})");
            }
            else if (delta < 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"↓ {delta} points (was {previousRun.OverallScore})");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"→ No change ({previousRun.OverallScore})");
            }
            Console.ForegroundColor = orig;
        }
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  No scans yet. Run: winsentinel --audit");
        Console.ForegroundColor = orig;
    }
    Console.WriteLine();

    // ── 30-Day Trend ──
    if (trend != null && trend.TotalScans >= 2)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  30-DAY TREND");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ──────────────────────────────────────────");
        Console.ForegroundColor = orig;

        Console.Write("  Scans:      ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(trend.TotalScans);
        Console.ForegroundColor = orig;

        Console.Write("  Average:    ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"{trend.AverageScore:F0}/100");
        Console.ForegroundColor = orig;

        if (trend.BestScore.HasValue)
        {
            Console.Write("  Best:       ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{trend.BestScore}/100");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($" ({trend.BestScoreDate?.LocalDateTime:d})");
            Console.ForegroundColor = orig;
        }

        if (trend.WorstScore.HasValue)
        {
            Console.Write("  Worst:      ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"{trend.WorstScore}/100");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($" ({trend.WorstScoreDate?.LocalDateTime:d})");
            Console.ForegroundColor = orig;
        }

        // Mini sparkline of recent scores
        if (recentRuns.Count >= 2)
        {
            Console.Write("  Recent:     ");
            var recent = recentRuns.AsEnumerable().Reverse().ToList();
            foreach (var run in recent)
            {
                Console.ForegroundColor = GetScoreColor(run.OverallScore);
                Console.Write($"{run.OverallScore} ");
            }
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("(oldest → newest)");
            Console.ForegroundColor = orig;
            Console.WriteLine();
        }

        Console.WriteLine();
    }

    // ── Active Rules & Baselines ──
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("  CONFIGURATION");
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  ──────────────────────────────────────────");
    Console.ForegroundColor = orig;

    Console.Write("  Ignore rules: ");
    Console.ForegroundColor = ignoreRules.Count > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
    Console.WriteLine(ignoreRules.Count > 0 ? $"{ignoreRules.Count} active" : "none");
    Console.ForegroundColor = orig;

    Console.Write("  Baselines:    ");
    Console.ForegroundColor = baselines.Count > 0 ? ConsoleColor.Cyan : ConsoleColor.DarkGray;
    Console.WriteLine(baselines.Count > 0 ? $"{baselines.Count} saved ({string.Join(", ", baselines.Select(b => b.Name))})" : "none");
    Console.ForegroundColor = orig;

    Console.Write("  Total scans:  ");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine(totalScans);
    Console.ForegroundColor = orig;

    Console.Write("  History DB:   ");
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine(AuditHistoryService.GetDefaultDbPath());
    Console.ForegroundColor = orig;

    Console.WriteLine();

    return 0;
}

static string FormatTimeAgo(DateTimeOffset timestamp)
{
    var elapsed = DateTimeOffset.Now - timestamp;
    if (elapsed.TotalMinutes < 1) return "just now";
    if (elapsed.TotalMinutes < 60) return $"{(int)elapsed.TotalMinutes}m ago";
    if (elapsed.TotalHours < 24) return $"{(int)elapsed.TotalHours}h ago";
    if (elapsed.TotalDays < 7) return $"{(int)elapsed.TotalDays}d ago";
    return $"{(int)(elapsed.TotalDays / 7)}w ago";
}

static ConsoleColor GetScoreColor(int score)
{
    return score switch
    {
        >= 80 => ConsoleColor.Green,
        >= 60 => ConsoleColor.Yellow,
        _ => ConsoleColor.Red
    };
}

// ── Command Handlers ─────────────────────────────────────────────────
static int HandleHelp()
{
    ConsoleFormatter.PrintHelp();
    return 0;
}

static int HandleVersion()
{
    ConsoleFormatter.PrintVersion();
    return 0;
}

static async Task<int> HandleScore(CliOptions options)
{
    // If a profile is specified, route to profile audit
    if (!string.IsNullOrEmpty(options.ProfileName))
    {
        return await HandleProfileAudit(options);
    }

    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
    }

    var progress = options.Quiet || options.Json
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    if (options.Json)
    {
        var scoreResult = new
        {
            score = report.SecurityScore,
            grade = SecurityScorer.GetGrade(report.SecurityScore),
            critical = report.TotalCritical,
            warnings = report.TotalWarnings,
            totalFindings = report.TotalFindings,
            machine = Environment.MachineName,
            timestamp = DateTimeOffset.UtcNow
        };
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(scoreResult, jsonOptions);
        WriteOutput(json, options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintScore(report.SecurityScore, options.Quiet);
    }

    return DetermineExitCode(report, options.Threshold);
}

static async Task<int> HandleAudit(CliOptions options)
{
    // If a profile is specified, route to profile audit
    if (!string.IsNullOrEmpty(options.ProfileName))
    {
        return await HandleProfileAudit(options);
    }

    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json && !options.Html && !options.Markdown && !options.Csv && !options.Sarif)
    {
        ConsoleFormatter.PrintBanner();
    }

    var progress = options.Quiet || options.Json || options.Html || options.Markdown || options.Csv || options.Sarif
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    // Apply ignore rules if any exist
    var ignoreService = new IgnoreRuleService();
    var activeIgnoreRules = ignoreService.GetActiveRules();
    List<IgnoredFinding>? ignoredFindings = null;
    if (activeIgnoreRules.Count > 0)
    {
        report = ignoreService.ApplyRulesToReport(report, out ignoredFindings);
    }

    if (options.Json)
    {
        var generator = new ReportGenerator();
        var json = generator.GenerateJsonReport(report);
        WriteOutput(json, options.OutputFile);
    }
    else if (options.Html)
    {
        var dashGen = new HtmlDashboardGenerator();
        var dashOptions = new HtmlDashboardOptions
        {
            DarkMode = options.HtmlDark,
            IncludePassedChecks = options.HtmlIncludePass,
            Title = options.HtmlTitle ?? "WinSentinel Security Dashboard"
        };
        var html = dashGen.Generate(report, dashOptions);
        if (options.OutputFile != null)
        {
            dashGen.SaveDashboard(html, options.OutputFile);
        }
        else
        {
            Console.Write(html);
        }

        if (!options.Quiet && options.OutputFile != null)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ HTML dashboard saved to {options.OutputFile}");
            Console.ForegroundColor = original;
        }
    }
    else if (options.Markdown)
    {
        var generator = new ReportGenerator();
        var markdown = generator.GenerateMarkdownReport(report);
        WriteOutput(markdown, options.OutputFile);

        if (!options.Quiet && options.OutputFile != null)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Markdown report saved to {options.OutputFile}");
            Console.ForegroundColor = original;
        }
    }
    else if (options.Sarif)
    {
        var exporter = new SarifExporter();
        var sarif = exporter.GenerateSarif(report, options.SarifIncludePass);
        WriteOutput(sarif, options.OutputFile);

        if (!options.Quiet && options.OutputFile != null)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ SARIF report saved to {options.OutputFile}");
            Console.ForegroundColor = original;
        }
    }
    else if (options.Csv)
    {
        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(report);
        WriteOutput(csv, options.OutputFile);

        if (!options.Quiet && options.OutputFile != null)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ CSV report saved to {options.OutputFile}");
            Console.ForegroundColor = original;
        }
    }
    else if (options.Quiet)
    {
        ConsoleFormatter.PrintScore(report.SecurityScore, quiet: true);
    }
    else
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
        ConsoleFormatter.PrintScore(report.SecurityScore);
        ConsoleFormatter.PrintSummary(report);
        if (ignoredFindings != null && ignoredFindings.Count > 0)
        {
            ConsoleFormatter.PrintIgnoredSummary(ignoredFindings.Count);
        }
        ConsoleFormatter.PrintModuleTable(report);
        ConsoleFormatter.PrintFindings(report);
        if (options.ShowIgnored && ignoredFindings != null && ignoredFindings.Count > 0)
        {
            ConsoleFormatter.PrintIgnoredFindings(ignoredFindings);
        }
    }

    return DetermineExitCode(report, options.Threshold);
}

static async Task<int> HandleFixAll(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var fixEngine = new FixEngine();
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit before fix...");
        Console.WriteLine();
    }

    var progress = options.Quiet || options.Json
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
        ConsoleFormatter.PrintScore(report.SecurityScore);
    }

    // Collect fixable findings
    var fixableFindings = report.Results
        .SelectMany(r => r.Findings)
        .Where(f => f.Severity is Severity.Critical or Severity.Warning)
        .Where(f => !string.IsNullOrWhiteSpace(f.FixCommand))
        .ToList();

    if (fixableFindings.Count == 0)
    {
        if (!options.Quiet && !options.Json)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ No fixable findings — system is secure!");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return DetermineExitCode(report, options.Threshold);
    }

    if (!options.Quiet && !options.Json)
    {
        Console.WriteLine($"  Fixing {fixableFindings.Count} findings...");
        Console.WriteLine();
    }

    var fixResults = new List<(Finding finding, FixResult result)>();

    foreach (var finding in fixableFindings)
    {
        if (!options.Quiet && !options.Json)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"\r  Fixing: {finding.Title,-40}");
            Console.ForegroundColor = original;
        }

        var result = await fixEngine.ExecuteFixAsync(finding);
        fixResults.Add((finding, result));
    }

    if (!options.Quiet && !options.Json)
    {
        Console.Write("\r" + new string(' ', 60) + "\r");
        ConsoleFormatter.PrintFixResults(fixResults);
    }
    else if (options.Json)
    {
        var jsonResults = fixResults.Select(r => new
        {
            finding = r.finding.Title,
            severity = r.finding.Severity.ToString(),
            success = r.result.Success,
            error = r.result.Error,
            command = r.result.Command,
            duration = r.result.Duration.TotalSeconds
        });

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(new
        {
            preFix = new { score = report.SecurityScore, grade = SecurityScorer.GetGrade(report.SecurityScore) },
            fixes = jsonResults,
            totalFixed = fixResults.Count(r => r.result.Success),
            totalFailed = fixResults.Count(r => !r.result.Success)
        }, jsonOptions);
        WriteOutput(json, options.OutputFile);
    }

    return DetermineExitCode(report, options.Threshold);
}

// ── Helpers ──────────────────────────────────────────────────────────

static int HandleIgnore(CliOptions options)
{
    var service = new IgnoreRuleService();

    return options.IgnoreAction switch
    {
        IgnoreAction.Add => HandleIgnoreAdd(service, options),
        IgnoreAction.List => HandleIgnoreList(service, options),
        IgnoreAction.Remove => HandleIgnoreRemove(service, options),
        IgnoreAction.Clear => HandleIgnoreClear(service, options),
        IgnoreAction.Purge => HandleIgnorePurge(service, options),
        _ => HandleIgnoreList(service, options)
    };
}

static int HandleIgnoreAdd(IgnoreRuleService service, CliOptions options)
{
    var pattern = options.IgnorePattern!;

    // Parse match mode
    var matchMode = IgnoreMatchMode.Contains;
    if (!string.IsNullOrEmpty(options.IgnoreMatchMode))
    {
        matchMode = options.IgnoreMatchMode.ToLowerInvariant() switch
        {
            "exact" => IgnoreMatchMode.Exact,
            "contains" => IgnoreMatchMode.Contains,
            "regex" => IgnoreMatchMode.Regex,
            _ => IgnoreMatchMode.Contains
        };
    }

    // Parse severity
    Severity? severity = null;
    if (!string.IsNullOrEmpty(options.IgnoreSeverity))
    {
        severity = options.IgnoreSeverity.ToLowerInvariant() switch
        {
            "critical" => Severity.Critical,
            "warning" => Severity.Warning,
            "info" => Severity.Info,
            "pass" => Severity.Pass,
            _ => null
        };
        if (severity == null)
        {
            ConsoleFormatter.PrintError($"Unknown severity: {options.IgnoreSeverity}. Use critical, warning, info, or pass.");
            return 3;
        }
    }

    // Parse expiration
    DateTimeOffset? expiresAt = null;
    if (options.IgnoreExpireDays.HasValue)
    {
        expiresAt = DateTimeOffset.UtcNow.AddDays(options.IgnoreExpireDays.Value);
    }

    try
    {
        var rule = service.AddRule(pattern, matchMode, options.IgnoreModule, severity,
            options.IgnoreReason, expiresAt);

        if (options.Json)
        {
            var jsonResult = new
            {
                action = "added",
                id = rule.Id,
                pattern = rule.Pattern,
                matchMode = rule.MatchMode.ToString(),
                module = rule.Module,
                severity = rule.Severity?.ToString(),
                reason = rule.Reason,
                expiresAt = rule.ExpiresAt,
                createdAt = rule.CreatedAt
            };
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
            var json = JsonSerializer.Serialize(jsonResult, jsonOptions);
            WriteOutput(json, options.OutputFile);
        }
        else if (!options.Quiet)
        {
            ConsoleFormatter.PrintIgnoreRuleAdded(rule);
        }

        return 0;
    }
    catch (ArgumentException ex)
    {
        ConsoleFormatter.PrintError(ex.Message);
        return 3;
    }
}

static int HandleIgnoreList(IgnoreRuleService service, CliOptions options)
{
    var rules = service.GetAllRules();

    if (rules.Count == 0)
    {
        if (options.Json)
        {
            WriteOutput("[]", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No ignore rules defined. Add one with: winsentinel --ignore add <pattern>");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return 0;
    }

    if (options.Json)
    {
        var jsonRules = rules.Select(r => new
        {
            id = r.Id,
            pattern = r.Pattern,
            matchMode = r.MatchMode.ToString(),
            module = r.Module,
            severity = r.Severity?.ToString(),
            reason = r.Reason,
            enabled = r.Enabled,
            isActive = r.IsActive,
            isExpired = r.IsExpired,
            createdAt = r.CreatedAt,
            expiresAt = r.ExpiresAt
        });
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(jsonRules, jsonOptions);
        WriteOutput(json, options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintIgnoreRuleList(rules, options.Quiet);
    }

    return 0;
}

static int HandleIgnoreRemove(IgnoreRuleService service, CliOptions options)
{
    var id = options.IgnoreRuleId!;

    if (service.RemoveRule(id))
    {
        if (options.Json)
        {
            WriteOutput($"{{\"action\": \"removed\", \"id\": \"{id}\"}}", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Ignore rule '{id}' removed.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return 0;
    }
    else
    {
        if (options.Json)
        {
            WriteOutput($"{{\"error\": \"Rule '{id}' not found.\"}}", options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintError($"Ignore rule '{id}' not found. Use --ignore list to see rules.");
        }
        return 3;
    }
}

static int HandleIgnoreClear(IgnoreRuleService service, CliOptions options)
{
    var count = service.ClearAllRules();

    if (options.Json)
    {
        WriteOutput($"{{\"action\": \"cleared\", \"removed\": {count}}}", options.OutputFile);
    }
    else if (!options.Quiet)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Cleared {count} ignore rule(s).");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    return 0;
}

static int HandleIgnorePurge(IgnoreRuleService service, CliOptions options)
{
    var count = service.PurgeExpiredRules();

    if (options.Json)
    {
        WriteOutput($"{{\"action\": \"purged\", \"removed\": {count}}}", options.OutputFile);
    }
    else if (!options.Quiet)
    {
        var original = Console.ForegroundColor;
        if (count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Purged {count} expired ignore rule(s).");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  No expired rules to purge.");
        }
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    return 0;
}

// ── Helpers ──────────────────────────────────────────────────────────

static int HandleProfiles(CliOptions options)
{
    var profileService = new ComplianceProfileService();

    if (options.Json)
    {
        var profiles = profileService.Profiles.Select(p => new
        {
            name = p.Name,
            displayName = p.DisplayName,
            description = p.Description,
            targetAudience = p.TargetAudience,
            complianceThreshold = p.ComplianceThreshold,
            moduleWeights = p.ModuleWeights,
            severityOverrides = p.SeverityOverrides.Count,
            skippedModules = p.SkippedModules.Count,
            recommendations = p.Recommendations
        });
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(profiles, jsonOptions);
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    ConsoleFormatter.PrintProfileList(profileService.Profiles, options.Quiet);
    return 0;
}

static async Task<int> HandleProfileAudit(CliOptions options)
{
    var profileService = new ComplianceProfileService();
    var profile = profileService.GetProfile(options.ProfileName!);

    if (profile == null)
    {
        ConsoleFormatter.PrintError(
            $"Unknown profile: '{options.ProfileName}'. Available: {string.Join(", ", profileService.ProfileNames)}");
        return 3;
    }

    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"  Profile: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(profile.DisplayName);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  (threshold: {profile.ComplianceThreshold}/100)");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }

    var progress = options.Quiet || options.Json
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    var complianceResult = profileService.ApplyProfile(profile, report);

    if (options.Json)
    {
        var jsonResult = new
        {
            profile = new
            {
                name = profile.Name,
                displayName = profile.DisplayName,
                complianceThreshold = profile.ComplianceThreshold
            },
            originalScore = complianceResult.OriginalScore,
            originalGrade = complianceResult.OriginalGrade,
            adjustedScore = complianceResult.AdjustedScore,
            adjustedGrade = complianceResult.AdjustedGrade,
            isCompliant = complianceResult.IsCompliant,
            overridesApplied = complianceResult.OverridesApplied,
            modulesSkipped = complianceResult.ModulesSkipped,
            modulesWeighted = complianceResult.ModulesWeighted,
            moduleScores = complianceResult.ModuleScores.Select(m => new
            {
                category = m.Category,
                originalScore = m.OriginalScore,
                weight = m.Weight,
                skipped = m.Skipped,
                findings = m.FindingCount,
                overrides = m.OverridesInModule
            }),
            appliedOverrides = complianceResult.AppliedOverrides.Select(o => new
            {
                finding = o.FindingTitle,
                originalSeverity = o.OriginalSeverity.ToString(),
                newSeverity = o.NewSeverity.ToString(),
                reason = o.Reason,
                module = o.ModuleCategory
            }),
            recommendations = complianceResult.Recommendations,
            timestamp = complianceResult.CheckedAt
        };
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(jsonResult, jsonOptions);
        WriteOutput(json, options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintComplianceResult(complianceResult, options.Quiet);
    }

    // Exit code: 0 if compliant, 1 if not, 2 if critical issues
    if (report.TotalCritical > 0 && !complianceResult.IsCompliant) return 2;
    return complianceResult.IsCompliant ? 0 : 1;
}

static async Task<int> HandleChecklist(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var planner = new RemediationPlanner();
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit to generate remediation checklist...");
        Console.WriteLine();
    }

    var progress = options.Quiet || options.Json
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    var plan = planner.GeneratePlan(report);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(new
        {
            generatedAt = plan.GeneratedAt,
            currentScore = plan.CurrentScore,
            currentGrade = plan.CurrentGrade,
            projectedScore = plan.ProjectedScore,
            projectedGrade = plan.ProjectedGrade,
            totalImpact = plan.TotalImpact,
            totalItems = plan.TotalItems,
            autoFixableCount = plan.AutoFixableCount,
            quickWins = plan.QuickWins.Select(FormatChecklistItem),
            mediumEffort = plan.MediumEffort.Select(FormatChecklistItem),
            majorChanges = plan.MajorChanges.Select(FormatChecklistItem)
        }, jsonOptions);
        WriteOutput(json, options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintChecklist(plan, options.Quiet);
    }

    return DetermineExitCode(report, options.Threshold);
}

static object FormatChecklistItem(RemediationItem item) => new
{
    step = item.StepNumber,
    title = item.Title,
    description = item.Description,
    severity = item.Severity.ToString(),
    category = item.Category,
    impact = item.Impact,
    effort = item.Effort,
    estimatedTime = item.EstimatedTime,
    remediation = item.Remediation,
    fixCommand = item.FixCommand,
    hasAutoFix = item.HasAutoFix
};

static async Task<int> HandleBaseline(CliOptions options)
{
    var baselineService = new BaselineService();

    return options.BaselineAction switch
    {
        BaselineAction.Save => await HandleBaselineSave(baselineService, options),
        BaselineAction.List => HandleBaselineList(baselineService, options),
        BaselineAction.Check => await HandleBaselineCheck(baselineService, options),
        BaselineAction.Delete => HandleBaselineDelete(baselineService, options),
        _ => HandleBaselineList(baselineService, options)
    };
}

static async Task<int> HandleBaselineSave(BaselineService baselineService, CliOptions options)
{
    var name = options.BaselineName!;
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit to capture baseline...");
        Console.WriteLine();
    }

    var progress = options.Quiet || options.Json
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    try
    {
        var baseline = baselineService.SaveBaseline(name, report, options.BaselineDescription, options.Force);

        if (options.Json)
        {
            var jsonResult = new
            {
                action = "saved",
                name = baseline.Name,
                description = baseline.Description,
                score = baseline.OverallScore,
                grade = baseline.Grade,
                totalFindings = baseline.TotalFindings,
                critical = baseline.CriticalCount,
                warnings = baseline.WarningCount,
                modules = baseline.ModuleScores.Count,
                createdAt = baseline.CreatedAt,
                machine = baseline.MachineName
            };
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
            var json = JsonSerializer.Serialize(jsonResult, jsonOptions);
            WriteOutput(json, options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintBaselineSaved(baseline);
        }

        return 0;
    }
    catch (InvalidOperationException ex)
    {
        if (options.Json)
        {
            WriteOutput($"{{\"error\": \"{ex.Message}\"}}", options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintError(ex.Message);
        }
        return 3;
    }
    catch (ArgumentException ex)
    {
        if (options.Json)
        {
            WriteOutput($"{{\"error\": \"{ex.Message}\"}}", options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintError(ex.Message);
        }
        return 3;
    }
}

static int HandleBaselineList(BaselineService baselineService, CliOptions options)
{
    var baselines = baselineService.ListBaselines();

    if (baselines.Count == 0)
    {
        if (options.Json)
        {
            WriteOutput("[]", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No saved baselines found. Create one with: winsentinel --baseline save <name>");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return 0;
    }

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(baselines.Select(b => new
        {
            name = b.Name,
            description = b.Description,
            score = b.OverallScore,
            grade = b.Grade,
            totalFindings = b.TotalFindings,
            critical = b.CriticalCount,
            warnings = b.WarningCount,
            createdAt = b.CreatedAt,
            machine = b.MachineName
        }), jsonOptions);
        WriteOutput(json, options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintBaselineList(baselines, options.Quiet);
    }

    return 0;
}

static async Task<int> HandleBaselineCheck(BaselineService baselineService, CliOptions options)
{
    var name = options.BaselineName!;

    if (!baselineService.BaselineExists(name))
    {
        if (options.Json)
        {
            WriteOutput($"{{\"error\": \"Baseline '{name}' not found.\"}}", options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintError($"Baseline '{name}' not found. Use --baseline list to see saved baselines.");
        }
        return 3;
    }

    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine($"  Checking against baseline '{name}'...");
        Console.WriteLine();
    }

    var progress = options.Quiet || options.Json
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    var checkResult = baselineService.CheckBaseline(name, report);

    if (options.Json)
    {
        var jsonResult = new
        {
            baseline = new
            {
                name = checkResult.Baseline.Name,
                score = checkResult.Baseline.OverallScore,
                grade = checkResult.Baseline.Grade,
                createdAt = checkResult.Baseline.CreatedAt
            },
            current = new
            {
                score = checkResult.CurrentScore,
                grade = SecurityScorer.GetGrade(checkResult.CurrentScore)
            },
            scoreChange = checkResult.ScoreChange,
            passed = checkResult.Passed,
            regressions = checkResult.Regressions.Select(f => new
            {
                title = f.Title,
                severity = f.Severity,
                module = f.ModuleName,
                description = f.Description,
                remediation = f.Remediation
            }),
            resolved = checkResult.Resolved.Select(f => new
            {
                title = f.Title,
                severity = f.Severity,
                module = f.ModuleName
            }),
            moduleDeviations = checkResult.ModuleDeviations.Select(d => new
            {
                module = d.Category,
                baselineScore = d.BaselineScore,
                currentScore = d.CurrentScore,
                change = d.ScoreChange,
                status = d.Status
            }),
            summary = new
            {
                regressions = checkResult.Regressions.Count,
                criticalRegressions = checkResult.CriticalRegressions,
                warningRegressions = checkResult.WarningRegressions,
                resolved = checkResult.Resolved.Count,
                unchanged = checkResult.Unchanged.Count
            }
        };
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(jsonResult, jsonOptions);
        WriteOutput(json, options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintBaselineCheck(checkResult, options.Quiet);
    }

    // Exit code: 0 if baseline check passed, 1 if regressions found, 2 if critical regressions
    if (checkResult.CriticalRegressions > 0) return 2;
    if (!checkResult.Passed) return 1;
    return 0;
}

static int HandleBaselineDelete(BaselineService baselineService, CliOptions options)
{
    var name = options.BaselineName!;

    if (baselineService.DeleteBaseline(name))
    {
        if (options.Json)
        {
            WriteOutput($"{{\"action\": \"deleted\", \"name\": \"{name}\"}}", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Baseline '{name}' deleted.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return 0;
    }
    else
    {
        if (options.Json)
        {
            WriteOutput($"{{\"error\": \"Baseline '{name}' not found.\"}}", options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintError($"Baseline '{name}' not found.");
        }
        return 3;
    }
}

static int HandleHistory(CliOptions options)
{
    using var historyService = new AuditHistoryService();
    historyService.EnsureDatabase();

    if (options.Diff)
    {
        return HandleHistoryDiff(historyService, options);
    }
    else if (options.Compare)
    {
        return HandleHistoryCompare(historyService, options);
    }
    else
    {
        return HandleHistoryList(historyService, options);
    }
}

static int HandleHistoryList(AuditHistoryService historyService, CliOptions options)
{
    var runs = historyService.GetHistory(options.HistoryDays);

    if (runs.Count == 0)
    {
        if (options.Json)
        {
            WriteOutput("[]", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No audit history found. Run an audit first with: winsentinel --audit");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return 0;
    }

    // Limit to requested count
    var displayRuns = runs.Take(options.HistoryLimit).ToList();

    if (options.Json)
    {
        var jsonRuns = displayRuns.Select(r => new
        {
            id = r.Id,
            timestamp = r.Timestamp,
            score = r.OverallScore,
            grade = r.Grade,
            totalFindings = r.TotalFindings,
            critical = r.CriticalCount,
            warnings = r.WarningCount,
            info = r.InfoCount,
            pass = r.PassCount,
            scheduled = r.IsScheduled
        });
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(new { totalRuns = runs.Count, displayed = displayRuns.Count, days = options.HistoryDays, runs = jsonRuns }, jsonOptions);
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintHistoryBanner(runs.Count, options.HistoryDays);
    }

    ConsoleFormatter.PrintHistoryTable(displayRuns, options.Quiet);

    // Show trend summary
    if (!options.Quiet && displayRuns.Count >= 2)
    {
        var trend = historyService.GetTrend(options.HistoryDays);
        ConsoleFormatter.PrintHistoryTrend(trend);
    }

    return 0;
}

static int HandleHistoryCompare(AuditHistoryService historyService, CliOptions options)
{
    var recentRuns = historyService.GetRecentRuns(2);

    if (recentRuns.Count < 2)
    {
        if (options.Json)
        {
            WriteOutput("{\"error\": \"Need at least 2 audit runs to compare. Run more audits first.\"}", options.OutputFile);
        }
        else
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  Need at least 2 audit runs to compare. Run more audits first.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return 0;
    }

    // Get full details for both runs (recentRuns[0] is newest, [1] is previous)
    var currentRun = historyService.GetRunDetails(recentRuns[0].Id)!;
    var previousRun = historyService.GetRunDetails(recentRuns[1].Id)!;

    if (options.Json)
    {
        var comparison = BuildComparisonJson(previousRun, currentRun);
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(comparison, jsonOptions);
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    ConsoleFormatter.PrintComparisonReport(previousRun, currentRun, options.Quiet);
    return 0;
}

static int HandleHistoryDiff(AuditHistoryService historyService, CliOptions options)
{
    var recentRuns = historyService.GetRecentRuns(2);

    if (recentRuns.Count < 2)
    {
        if (options.Json)
        {
            WriteOutput("{\"error\": \"Need at least 2 audit runs to diff. Run more audits first.\"}", options.OutputFile);
        }
        else
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  Need at least 2 audit runs to diff. Run more audits first.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
        return 0;
    }

    var currentRun = historyService.GetRunDetails(recentRuns[0].Id)!;
    var previousRun = historyService.GetRunDetails(recentRuns[1].Id)!;

    // Calculate diffs
    var previousTitles = new HashSet<string>(previousRun.Findings.Select(f => f.Title));
    var currentTitles = new HashSet<string>(currentRun.Findings.Select(f => f.Title));

    var newFindings = currentRun.Findings.Where(f => !previousTitles.Contains(f.Title)).ToList();
    var resolvedFindings = previousRun.Findings.Where(f => !currentTitles.Contains(f.Title)).ToList();
    var persistentFindings = currentRun.Findings.Where(f => previousTitles.Contains(f.Title)).ToList();

    if (options.Json)
    {
        var diffResult = new
        {
            previousRun = new { id = previousRun.Id, timestamp = previousRun.Timestamp, score = previousRun.OverallScore },
            currentRun = new { id = currentRun.Id, timestamp = currentRun.Timestamp, score = currentRun.OverallScore },
            scoreChange = currentRun.OverallScore - previousRun.OverallScore,
            newFindings = newFindings.Select(f => new { f.Title, f.Severity, f.ModuleName, f.Description, f.Remediation }),
            resolvedFindings = resolvedFindings.Select(f => new { f.Title, f.Severity, f.ModuleName, f.Description }),
            persistentCount = persistentFindings.Count,
            summary = new
            {
                added = newFindings.Count,
                resolved = resolvedFindings.Count,
                persistent = persistentFindings.Count
            }
        };
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var json = JsonSerializer.Serialize(diffResult, jsonOptions);
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    ConsoleFormatter.PrintDiffReport(previousRun, currentRun, newFindings, resolvedFindings, persistentFindings, options.Quiet);
    return 0;
}

static object BuildComparisonJson(AuditRunRecord previousRun, AuditRunRecord currentRun)
{
    var moduleComparisons = new List<object>();

    var prevModules = previousRun.ModuleScores.ToDictionary(m => m.ModuleName, m => m);
    var currModules = currentRun.ModuleScores.ToDictionary(m => m.ModuleName, m => m);
    var allModuleNames = prevModules.Keys.Union(currModules.Keys).OrderBy(n => n);

    foreach (var name in allModuleNames)
    {
        prevModules.TryGetValue(name, out var prev);
        currModules.TryGetValue(name, out var curr);

        moduleComparisons.Add(new
        {
            module = curr?.Category ?? prev?.Category ?? name,
            previousScore = prev?.Score,
            currentScore = curr?.Score,
            change = (curr?.Score ?? 0) - (prev?.Score ?? 0),
            previousCritical = prev?.CriticalCount ?? 0,
            currentCritical = curr?.CriticalCount ?? 0,
            previousWarnings = prev?.WarningCount ?? 0,
            currentWarnings = curr?.WarningCount ?? 0
        });
    }

    return new
    {
        previousRun = new { id = previousRun.Id, timestamp = previousRun.Timestamp, score = previousRun.OverallScore, grade = previousRun.Grade },
        currentRun = new { id = currentRun.Id, timestamp = currentRun.Timestamp, score = currentRun.OverallScore, grade = currentRun.Grade },
        scoreChange = currentRun.OverallScore - previousRun.OverallScore,
        modules = moduleComparisons,
        summary = new
        {
            previousFindings = previousRun.TotalFindings,
            currentFindings = currentRun.TotalFindings,
            findingsChange = currentRun.TotalFindings - previousRun.TotalFindings,
            previousCritical = previousRun.CriticalCount,
            currentCritical = currentRun.CriticalCount,
            previousWarnings = previousRun.WarningCount,
            currentWarnings = currentRun.WarningCount
        }
    };
}

static AuditEngine BuildEngine(string? modulesFilter)
{
    if (string.IsNullOrWhiteSpace(modulesFilter))
    {
        return new AuditEngine();
    }

    var requested = modulesFilter
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(m => m.ToLowerInvariant())
        .ToHashSet();

    var allModules = new List<IAuditModule>
    {
        new FirewallAudit(),
        new UpdateAudit(),
        new DefenderAudit(),
        new AccountAudit(),
        new NetworkAudit(),
        new ProcessAudit(),
        new StartupAudit(),
        new SystemAudit(),
        new PrivacyAudit(),
        new BrowserAudit(),
        new AppSecurityAudit(),
        new EncryptionAudit(),
        new EventLogAudit(),
        new SoftwareInventoryAudit(),
        new CertificateAudit(),
        new PowerShellAudit(),
        new DnsAudit(),
        new ScheduledTaskAudit(),
        new ServiceAudit(),
        new RegistryAudit(),
    };

    var filtered = allModules.Where(m =>
        requested.Contains(m.Category.ToLowerInvariant()) ||
        requested.Contains(m.Name.ToLowerInvariant()) ||
        requested.Any(r => m.Category.Contains(r, StringComparison.OrdinalIgnoreCase)) ||
        requested.Any(r => m.Name.Contains(r, StringComparison.OrdinalIgnoreCase))
    ).ToList();

    if (filtered.Count == 0)
    {
        ConsoleFormatter.PrintError($"No modules matched filter: {modulesFilter}");
        ConsoleFormatter.PrintError("Available: firewall, updates, defender, accounts, network, processes, startup, system, privacy, browser, appsecurity, encryption, eventlog, softwareinventory, certificate, powershell, dns, scheduledtask, service, registry, softwareinventory, certificate, powershell, dns, scheduledtask, service, registry");
        Environment.Exit(3);
    }

    return new AuditEngine(filtered);
}

static int DetermineExitCode(SecurityReport report, int? threshold)
{
    // If threshold is set, check against it
    if (threshold.HasValue)
    {
        return report.SecurityScore >= threshold.Value ? 0 : 1;
    }

    // Default exit code logic
    if (report.TotalCritical > 0) return 2;
    if (report.TotalWarnings > 0) return 1;
    return 0;
}

static void WriteOutput(string content, string? outputFile)
{
    if (outputFile != null)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(outputFile));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllText(outputFile, content);
    }
    else
    {
        Console.WriteLine(content);
    }
}

// ── Trend Analysis ───────────────────────────────────────────────────

static int HandleTrend(CliOptions options)
{
    using var history = new AuditHistoryService();
    history.EnsureDatabase();

    var runs = history.GetHistory(options.TrendDays);

    // Load module scores for the last 2 runs (for module trend comparison)
    if (options.TrendModules && runs.Count > 0)
    {
        var runIdsToLoad = runs.Take(2).Select(r => r.Id).ToList();
        foreach (var runId in runIdsToLoad)
        {
            var fullRun = history.GetRunDetails(runId);
            if (fullRun != null)
            {
                var match = runs.FirstOrDefault(r => r.Id == runId);
                if (match != null)
                {
                    match.ModuleScores = fullRun.ModuleScores;
                }
            }
        }
    }

    var analyzer = new TrendAnalyzer();
    var trendOptions = new TrendOptions
    {
        AlertThreshold = options.TrendAlertThreshold,
    };
    var report = analyzer.Analyze(runs, trendOptions);

    if (!report.HasData)
    {
        ConsoleFormatter.PrintWarning("No audit history found. Run --score or --audit first to generate data.");
        return 1;
    }

    if (options.Json)
    {
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        });
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    ConsoleFormatter.PrintTrendReport(report, options.TrendModules);

    return report.Alerts.Any(a => a.Level == AlertLevel.Critical) ? 2 : 0;
}

// ── Security Timeline ────────────────────────────────────────────────

static int HandleTimeline(CliOptions options)
{
    using var history = new AuditHistoryService();
    history.EnsureDatabase();

    var runs = history.GetHistory(options.HistoryDays);

    if (runs.Count == 0)
    {
        ConsoleFormatter.PrintWarning("No audit history found. Run --score or --audit first to generate data.");
        return 1;
    }

    // Load full details (findings + module scores) for each run
    for (int i = 0; i < runs.Count; i++)
    {
        var fullRun = history.GetRunDetails(runs[i].Id);
        if (fullRun != null)
        {
            runs[i].Findings = fullRun.Findings;
            runs[i].ModuleScores = fullRun.ModuleScores;
        }
    }

    var timeline = new SecurityTimeline();
    var timelineOptions = new TimelineOptions
    {
        MaxEvents = options.TimelineMaxEvents,
        ModuleFilter = options.TimelineModuleFilter,
    };

    // Parse severity filter
    if (!string.IsNullOrEmpty(options.TimelineSeverityFilter))
    {
        timelineOptions.MinSeverity = options.TimelineSeverityFilter.ToLowerInvariant() switch
        {
            "info" => TimelineSeverity.Info,
            "notice" => TimelineSeverity.Notice,
            "warning" => TimelineSeverity.Warning,
            "critical" => TimelineSeverity.Critical,
            _ => null,
        };
    }

    var report = timeline.Build(runs, timelineOptions);

    if (options.Json)
    {
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        });
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    var text = SecurityTimeline.FormatText(report);
    WriteOutput(text, options.OutputFile);
    return 0;
}

// ── Finding Age Tracker ──────────────────────────────────────────────

static int HandleFindingAge(CliOptions options)
{
    using var history = new AuditHistoryService();
    history.EnsureDatabase();

    var runs = history.GetHistory(options.AgeDays);

    if (runs.Count == 0)
    {
        ConsoleFormatter.PrintWarning("No audit history found. Run --score or --audit first to generate data.");
        return 1;
    }

    // Load full details (findings) for each run
    for (int i = 0; i < runs.Count; i++)
    {
        var fullRun = history.GetRunDetails(runs[i].Id);
        if (fullRun != null)
        {
            runs[i].Findings = fullRun.Findings;
            runs[i].ModuleScores = fullRun.ModuleScores;
        }
    }

    var tracker = new FindingAgeTracker();
    var report = tracker.Analyze(runs);

    // Apply filters if specified
    if (!string.IsNullOrEmpty(options.AgeSeverityFilter))
    {
        report.Findings = report.Findings
            .Where(f => f.Severity.Equals(options.AgeSeverityFilter, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    if (!string.IsNullOrEmpty(options.AgeModuleFilter))
    {
        report.Findings = report.Findings
            .Where(f => f.ModuleName.Contains(options.AgeModuleFilter, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    if (!string.IsNullOrEmpty(options.AgeClassification))
    {
        report.Findings = report.Findings
            .Where(f => f.Classification.Equals(options.AgeClassification, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    if (options.Json)
    {
        var dict = tracker.ToDict(report);
        var json = JsonSerializer.Serialize(dict, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        });
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    // Format based on sub-action
    switch (options.AgeAction)
    {
        case FindingAgeAction.Priority:
            PrintFindingList("Priority Queue (fix these first)", report.PriorityQueue, options.AgeTop);
            break;
        case FindingAgeAction.Chronic:
            PrintFindingList("Chronic Findings (90%+ persistence)", report.ChronicFindings, options.AgeTop);
            break;
        case FindingAgeAction.New:
            PrintFindingList("New Findings", report.NewFindings, options.AgeTop);
            break;
        case FindingAgeAction.Resolved:
            PrintFindingList("Resolved Findings", report.ResolvedFindings, options.AgeTop);
            break;
        default:
            var text = tracker.FormatReport(report);
            WriteOutput(text, options.OutputFile);
            break;
    }

    return 0;
}

static void PrintFindingList(string header, List<FindingLifecycle> findings, int top)
{
    Console.WriteLine();
    Console.WriteLine($"  {header}:");
    Console.WriteLine($"  {new string('─', header.Length + 1)}");
    Console.WriteLine();

    if (findings.Count == 0)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    (none)");
        Console.ForegroundColor = original;
        Console.WriteLine();
        return;
    }

    var display = findings.Take(top).ToList();
    for (int i = 0; i < display.Count; i++)
    {
        var f = display[i];
        var severityColor = f.Severity.ToUpperInvariant() switch
        {
            "CRITICAL" => ConsoleColor.Red,
            "WARNING" => ConsoleColor.Yellow,
            "INFO" => ConsoleColor.Cyan,
            _ => ConsoleColor.Gray
        };

        var original = Console.ForegroundColor;
        Console.Write($"  {i + 1,3}. ");
        Console.ForegroundColor = severityColor;
        Console.Write($"[{f.Severity}]");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($" {f.Title}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"       Module: {f.ModuleName} | Age: {f.AgeText} | Runs: {f.ConsecutiveRuns}/{f.TotalRunsAnalyzed} | {f.Classification}");
        Console.ForegroundColor = original;
    }

    if (findings.Count > top)
    {
        Console.WriteLine($"  ... and {findings.Count - top} more");
    }
    Console.WriteLine();
}

// ── Exemption Review ─────────────────────────────────────────────────

static int HandleExemptions(CliOptions options)
{
    var ignoreService = new IgnoreRuleService();
    var reviewService = new ExemptionReviewService(ignoreService)
    {
        ExpiryWarningDays = options.ExemptionWarningDays,
        StaleDays = options.ExemptionStaleDays
    };

    var result = reviewService.Review();

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
        var json = JsonSerializer.Serialize(new
        {
            summary = result.Summary,
            expiringSoon = result.ExpiringSoon.Select(r => FormatReviewedRuleJson(r)),
            recentlyExpired = result.RecentlyExpired.Select(r => FormatReviewedRuleJson(r)),
            stale = result.Stale.Select(r => FormatReviewedRuleJson(r)),
            unused = result.Unused.Select(r => FormatReviewedRuleJson(r)),
            disabled = result.Disabled.Select(r => FormatReviewedRuleJson(r))
        }, jsonOptions);
        WriteOutput(json, options.OutputFile);
        return 0;
    }

    return options.ExemptionAction switch
    {
        ExemptionAction.Review => HandleExemptionReview(result),
        ExemptionAction.Expiring => HandleExemptionExpiring(result),
        ExemptionAction.Stale => HandleExemptionStale(result),
        ExemptionAction.Unused => HandleExemptionUnused(result),
        ExemptionAction.Summary => HandleExemptionSummary(result),
        _ => HandleExemptionReview(result)
    };
}

static int HandleExemptionReview(ExemptionReviewService.ReviewResult result)
{
    HandleExemptionSummary(result);

    if (result.ExpiringSoon.Count > 0)
    {
        PrintExemptionSection("EXPIRING SOON", result.ExpiringSoon, ConsoleColor.Yellow);
    }

    if (result.RecentlyExpired.Count > 0)
    {
        PrintExemptionSection("RECENTLY EXPIRED", result.RecentlyExpired, ConsoleColor.Red);
    }

    if (result.Stale.Count > 0)
    {
        PrintExemptionSection("STALE (needs review)", result.Stale, ConsoleColor.DarkYellow);
    }

    if (result.Unused.Count > 0)
    {
        PrintExemptionSection("UNUSED (no current matches)", result.Unused, ConsoleColor.Gray);
    }

    if (result.Disabled.Count > 0)
    {
        PrintExemptionSection("DISABLED", result.Disabled, ConsoleColor.DarkGray);
    }

    if (result.ExpiringSoon.Count == 0 && result.RecentlyExpired.Count == 0 &&
        result.Stale.Count == 0 && result.Unused.Count == 0 && result.Disabled.Count == 0)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  All exemptions are current and healthy. No action needed.");
        Console.ResetColor();
        Console.WriteLine();
    }

    return 0;
}

static int HandleExemptionExpiring(ExemptionReviewService.ReviewResult result)
{
    if (result.ExpiringSoon.Count == 0)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  No exemptions expiring soon.");
        Console.ResetColor();
        return 0;
    }
    PrintExemptionSection("EXPIRING SOON", result.ExpiringSoon, ConsoleColor.Yellow);
    return 0;
}

static int HandleExemptionStale(ExemptionReviewService.ReviewResult result)
{
    if (result.Stale.Count == 0)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  No stale exemptions found.");
        Console.ResetColor();
        return 0;
    }
    PrintExemptionSection("STALE (needs review)", result.Stale, ConsoleColor.DarkYellow);
    return 0;
}

static int HandleExemptionUnused(ExemptionReviewService.ReviewResult result)
{
    if (result.Unused.Count == 0)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  No unused exemptions found. All rules match current findings.");
        Console.ResetColor();
        return 0;
    }
    PrintExemptionSection("UNUSED (no current matches)", result.Unused, ConsoleColor.Gray);
    return 0;
}

static int HandleExemptionSummary(ExemptionReviewService.ReviewResult result)
{
    var s = result.Summary;
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("  ╔══════════════════════════════════════════╗");
    Console.WriteLine("  ║       EXEMPTION REVIEW DASHBOARD        ║");
    Console.WriteLine("  ╚══════════════════════════════════════════╝");
    Console.ResetColor();
    Console.WriteLine();

    // Health score with color
    var healthColor = s.HealthScore switch
    {
        >= 90 => ConsoleColor.Green,
        >= 70 => ConsoleColor.Yellow,
        >= 50 => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };

    Console.Write("  Health: ");
    Console.ForegroundColor = healthColor;
    Console.Write($"{s.HealthGrade} ({s.HealthScore:F0}%)");
    Console.ResetColor();
    Console.WriteLine($"  |  Total Rules: {s.TotalRules}  |  Active: {s.ActiveRules}");
    Console.WriteLine();

    Console.WriteLine($"  {"Category",-25} {"Count",6}  Status");
    Console.WriteLine($"  {"─────────────────────────",-25} {"──────",6}  ──────────────");

    PrintSummaryRow("Expiring Soon", s.ExpiringSoon, s.ExpiringSoon > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
    PrintSummaryRow("Recently Expired", s.RecentlyExpired, s.RecentlyExpired > 0 ? ConsoleColor.Red : ConsoleColor.Green);
    PrintSummaryRow("Stale (no expiry)", s.StaleRules, s.StaleRules > 0 ? ConsoleColor.DarkYellow : ConsoleColor.Green);
    PrintSummaryRow("Unused (0 matches)", s.UnusedRules, s.UnusedRules > 0 ? ConsoleColor.Gray : ConsoleColor.Green);
    PrintSummaryRow("Disabled", s.DisabledRules, s.DisabledRules > 0 ? ConsoleColor.DarkGray : ConsoleColor.Green);
    Console.WriteLine();

    return 0;
}

static void PrintSummaryRow(string label, int count, ConsoleColor color)
{
    Console.Write($"  {label,-25} ");
    Console.ForegroundColor = color;
    Console.Write($"{count,6}");
    Console.ResetColor();
    var statusText = count == 0 ? "  OK" : "  Needs attention";
    Console.WriteLine(statusText);
}

static void PrintExemptionSection(string title, List<ExemptionReviewService.ReviewedRule> rules, ConsoleColor color)
{
    Console.WriteLine();
    Console.ForegroundColor = color;
    Console.WriteLine($"  ── {title} ({rules.Count}) ──");
    Console.ResetColor();
    Console.WriteLine();

    foreach (var r in rules)
    {
        var rule = r.Rule;
        Console.ForegroundColor = color;
        Console.Write($"  [{rule.Id}] ");
        Console.ResetColor();
        Console.Write($"\"{rule.Pattern}\"");

        if (rule.Module != null)
            Console.Write($" (module: {rule.Module})");
        if (rule.Severity.HasValue)
            Console.Write($" (severity: {rule.Severity})");

        Console.WriteLine();

        Console.Write("    ");
        if (r.DaysUntilExpiry.HasValue)
        {
            var days = r.DaysUntilExpiry.Value;
            if (days < 0)
                Console.Write($"Expired {-days}d ago  |  ");
            else if (days == 0)
                Console.Write("Expires today  |  ");
            else
                Console.Write($"Expires in {days}d  |  ");
        }
        else
        {
            Console.Write("No expiry  |  ");
        }

        Console.Write($"Age: {r.AgeDays}d  |  Matches: {r.MatchCount}");

        if (rule.Reason != null)
            Console.Write($"  |  Reason: {rule.Reason}");

        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine($"    → {r.Recommendation}");
        Console.ResetColor();
        Console.WriteLine();
    }
}

static object FormatReviewedRuleJson(ExemptionReviewService.ReviewedRule r)
{
    return new
    {
        id = r.Rule.Id,
        pattern = r.Rule.Pattern,
        matchMode = r.Rule.MatchMode.ToString(),
        module = r.Rule.Module,
        severity = r.Rule.Severity?.ToString(),
        reason = r.Rule.Reason,
        enabled = r.Rule.Enabled,
        createdAt = r.Rule.CreatedAt,
        expiresAt = r.Rule.ExpiresAt,
        status = r.Status.ToString(),
        daysUntilExpiry = r.DaysUntilExpiry,
        ageDays = r.AgeDays,
        matchCount = r.MatchCount,
        recommendation = r.Recommendation
    };
}

// ── Security Quiz ────────────────────────────────────────────────────

static async Task<int> HandleQuiz(CliOptions options)
{
    ConsoleFormatter.PrintBanner();

    var auditEngine = new AuditEngine();
    var report = await auditEngine.RunFullAuditAsync();

    var quizService = new SecurityQuizService();
    var quizOptions = new QuizOptions
    {
        QuestionCount = options.QuizQuestionCount
    };

    if (!string.IsNullOrEmpty(options.QuizDifficulty))
    {
        if (Enum.TryParse<QuizDifficulty>(options.QuizDifficulty, true, out var diff))
            quizOptions.Difficulty = diff;
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Unknown difficulty: {options.QuizDifficulty}. Use easy, medium, or hard.");
            Console.ResetColor();
            return 1;
        }
    }

    if (!string.IsNullOrEmpty(options.QuizCategory))
    {
        quizOptions.Categories.Add(options.QuizCategory);
    }

    var quiz = quizService.GenerateQuiz(report, quizOptions);

    if (options.QuizExport)
    {
        var json = quizService.ExportToJson(quiz);
        if (!string.IsNullOrEmpty(options.OutputFile))
        {
            File.WriteAllText(options.OutputFile, json);
            Console.WriteLine($"  Quiz exported to {options.OutputFile}");
        }
        else
        {
            Console.WriteLine(json);
        }
        return 0;
    }

    if (options.Json)
    {
        var json = quizService.ExportToJson(quiz);
        Console.WriteLine(json);
        return 0;
    }

    // Print quiz with answers shown (non-interactive review mode)
    ConsoleFormatter.PrintQuiz(quiz, showAnswers: true);

    // Show available categories
    var categories = quizService.GetAvailableCategories(report);
    if (categories.Count > 0)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Available categories: {string.Join(", ", categories)}");
        Console.WriteLine("  Use --quiz-category <name> to filter by category.");
        Console.ResetColor();
    }

    return 0;
}

static async Task<int> HandleRootCause(CliOptions options)
{
    ConsoleFormatter.PrintBanner();

    var auditEngine = new AuditEngine();
    var report = await auditEngine.RunFullAuditAsync();

    var analyzer = new RootCauseAnalyzer();
    var rcReport = analyzer.Analyze(report);

    // Apply severity filter if specified
    if (!string.IsNullOrEmpty(options.RootCauseSeverityFilter))
    {
        if (Enum.TryParse<Severity>(options.RootCauseSeverityFilter, true, out var sevFilter))
        {
            rcReport = rcReport with
            {
                RootCauses = rcReport.RootCauses
                    .Where(rc => rc.WorstSeverity >= sevFilter)
                    .ToList()
            };
        }
    }

    if (options.Json)
    {
        var jsonOpts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };
        Console.WriteLine(JsonSerializer.Serialize(rcReport, jsonOpts));
        return 0;
    }

    switch (options.RootCauseAction)
    {
        case RootCauseAction.Report:
            ConsoleFormatter.PrintRootCauseReport(rcReport);
            break;
        case RootCauseAction.Top:
            ConsoleFormatter.PrintRootCauseSummary(rcReport, options.RootCauseTop);
            break;
        case RootCauseAction.Causes:
            ConsoleFormatter.PrintRootCauseReport(rcReport);
            break;
        case RootCauseAction.Ungrouped:
            ConsoleFormatter.PrintUngroupedFindings(rcReport);
            break;
    }

    return 0;
}

// ── Threat Model ─────────────────────────────────────────────────────

static async Task<int> HandleThreats(CliOptions options)
{
    ConsoleFormatter.PrintBanner();

    var auditEngine = new AuditEngine();
    var report = await auditEngine.RunFullAuditAsync();

    var service = new ThreatModelService();
    var model = service.Analyze(report);

    if (options.Json)
    {
        var jsonOpts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };
        Console.WriteLine(JsonSerializer.Serialize(model, jsonOpts));
        return 0;
    }

    ConsoleFormatter.PrintThreatModel(model);
    return 0;
}

// ── Schedule Optimize ─────────────────────────────────────────────

static int HandleScheduleOptimize(CliOptions options)
{
    ConsoleFormatter.PrintBanner();

    using var history = new AuditHistoryService();
    var optimizer = new AuditScheduleOptimizer();
    var result = optimizer.Analyze(history, options.ScheduleOptimizeDays);

    if (options.Json)
    {
        var jsonOpts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };
        Console.WriteLine(JsonSerializer.Serialize(result, jsonOpts));
        return 0;
    }

    ConsoleFormatter.PrintScheduleOptimizeResult(result);
    return 0;
}

// ── Digest ────────────────────────────────────────────────────────

static async Task<int> HandleDigest(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for security digest...");
        Console.WriteLine();
    }

    var progress = options.Quiet
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    using var historyService = new AuditHistoryService();
    var digestGenerator = new SecurityDigestGenerator(historyService);
    var digest = digestGenerator.Generate(report, options.DigestHistoryDays);

    var output = options.DigestFormat switch
    {
        "html" => SecurityDigestGenerator.RenderHtml(digest),
        "json" => SecurityDigestGenerator.RenderJson(digest),
        _ => SecurityDigestGenerator.RenderText(digest)
    };

    if (!string.IsNullOrWhiteSpace(options.OutputFile))
    {
        await File.WriteAllTextAsync(options.OutputFile, output);
        if (!options.Quiet)
            Console.WriteLine($"  Digest saved to {options.OutputFile}");
    }
    else
    {
        Console.WriteLine(output);
    }

    // Save this run to history
    historyService.SaveAuditResult(report);

    return 0;
}

// ── Attack Path Analyzer ─────────────────────────────────────────

static async Task<int> HandleAttackPaths(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for attack path analysis...");
        Console.WriteLine();
    }

    var progress = options.Quiet
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    // MITRE mapping first
    var mitreMapper = new MitreAttackMapper();
    var attackReport = mitreMapper.Analyze(report);

    // Attack path analysis
    var pathAnalyzer = new AttackPathAnalyzer();
    var pathReport = pathAnalyzer.Analyze(report, attackReport);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
        var json = JsonSerializer.Serialize(pathReport, jsonOptions);

        if (!string.IsNullOrWhiteSpace(options.OutputFile))
        {
            await File.WriteAllTextAsync(options.OutputFile, json);
            if (!options.Quiet)
                Console.WriteLine($"  Attack path report saved to {options.OutputFile}");
        }
        else
        {
            Console.WriteLine(json);
        }
    }
    else
    {
        ConsoleFormatter.PrintAttackPaths(pathReport);
    }

    // Save this run to history
    using var historyService = new AuditHistoryService();
    historyService.SaveAuditResult(report);

    return 0;
}

// ── Executive Summary ────────────────────────────────────────────

static async Task<int> HandleSummary(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for executive summary...");
        Console.WriteLine();
    }

    var progress = options.Quiet
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
    }

    // Try to get trend data from history
    ScoreTrendSummary? trend = null;
    try
    {
        using var historyService = new AuditHistoryService();
        historyService.EnsureDatabase();
        trend = historyService.GetTrend(30);

        // Save this run to history
        historyService.SaveAuditResult(report);
    }
    catch
    {
        // History unavailable, proceed without trend
    }

    var summaryService = new ExecutiveSummaryService();
    var summary = summaryService.Generate(report, trend);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
        var json = JsonSerializer.Serialize(summary, jsonOptions);
        WriteOutput(json, options.OutputFile);
    }
    else if (options.SummaryFormat == "html" || options.Html)
    {
        var html = ExecutiveSummaryService.RenderHtml(summary);
        if (!string.IsNullOrWhiteSpace(options.OutputFile))
        {
            await File.WriteAllTextAsync(options.OutputFile, html);
            if (!options.Quiet)
                Console.WriteLine($"  Executive summary saved to {options.OutputFile}");
        }
        else
        {
            Console.WriteLine(html);
        }
    }
    else
    {
        // Console-formatted output with colors
        ConsoleFormatter.PrintExecutiveSummary(summary);
    }

    return DetermineExitCode(report, options.Threshold);
}
