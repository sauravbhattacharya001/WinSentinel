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
    CliCommand.Exemptions => ExemptionCommandHandler.Handle(options),
    CliCommand.Quiz => await HandleQuiz(options),
    CliCommand.RootCause => await HandleRootCause(options),
    CliCommand.Threats => await HandleThreats(options),
    CliCommand.ScheduleOptimize => HandleScheduleOptimize(options),
    CliCommand.Digest => await HandleDigest(options),
    CliCommand.AttackPaths => await HandleAttackPaths(options),
    CliCommand.WhatIf => await HandleWhatIf(options),
    CliCommand.Summary => await HandleSummary(options),
    CliCommand.Cost => await HandleCost(options),
    CliCommand.Benchmark => await HandleBenchmark(options),
    CliCommand.Compliance => await HandleCompliance(options),
    CliCommand.Inventory => HandleInventory(options),
    CliCommand.Tag => HandleTag(options),
    CliCommand.Hotspots => HandleHotspots(options),
    CliCommand.Kpi => HandleKpi(options),
    CliCommand.Sla => await HandleSla(options),
    CliCommand.Coverage => await HandleCoverage(options),
    CliCommand.RiskMatrix => await HandleRiskMatrix(options),
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

// ── What-If Simulator ────────────────────────────────────────────────

static async Task<int> HandleWhatIf(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for what-if simulation...");
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

    var simulator = new WhatIfSimulator();
    WhatIfSimulator.SimulationResult result;
    string scenario;

    switch (options.WhatIfAction)
    {
        case WhatIfAction.All:
            result = simulator.SimulateFixAll(report);
            scenario = "Fix ALL critical and warning findings (best-case)";
            break;

        case WhatIfAction.Severity:
            var severity = options.WhatIfSeverity?.ToLowerInvariant() switch
            {
                "critical" or "crt" => Severity.Critical,
                "warning" or "wrn" => Severity.Warning,
                _ => Severity.Warning
            };
            result = simulator.SimulateBySeverity(report, severity);
            scenario = $"Fix all {severity} findings";
            break;

        case WhatIfAction.Module:
            result = simulator.SimulateByModule(report, options.WhatIfModule ?? "");
            scenario = $"Fix all findings in module matching '{options.WhatIfModule}'";
            break;

        case WhatIfAction.Pattern:
            result = simulator.SimulateByPattern(report, options.WhatIfPattern ?? "");
            scenario = $"Fix findings matching pattern '{options.WhatIfPattern}'";
            break;

        case WhatIfAction.TopN:
        default:
            result = simulator.SimulateTopN(report, options.WhatIfTopN);
            scenario = $"Fix top {options.WhatIfTopN} highest-impact findings";
            break;
    }

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
        var output = new
        {
            Scenario = scenario,
            result.CurrentScore,
            result.ProjectedScore,
            result.ScoreDelta,
            result.CurrentGrade,
            result.ProjectedGrade,
            result.GradeImproved,
            result.CriticalResolved,
            result.WarningResolved,
            result.ResolvedFindings,
            result.ModuleImpacts
        };
        var json = JsonSerializer.Serialize(output, jsonOptions);

        if (!string.IsNullOrWhiteSpace(options.OutputFile))
        {
            await File.WriteAllTextAsync(options.OutputFile, json);
            if (!options.Quiet)
                Console.WriteLine($"  What-if report saved to {options.OutputFile}");
        }
        else
        {
            Console.WriteLine(json);
        }
    }
    else if (options.Csv)
    {
        var lines = new List<string> { "Module,ScoreBefore,ScoreAfter,Delta,FindingsResolved" };
        foreach (var impact in result.ModuleImpacts)
            lines.Add($"{impact.Module},{impact.ScoreBefore},{impact.ScoreAfter},{impact.Delta},{impact.FindingsResolved}");

        var csv = string.Join(Environment.NewLine, lines);
        if (!string.IsNullOrWhiteSpace(options.OutputFile))
        {
            await File.WriteAllTextAsync(options.OutputFile, csv);
            if (!options.Quiet)
                Console.WriteLine($"  What-if CSV saved to {options.OutputFile}");
        }
        else
        {
            Console.WriteLine(csv);
        }
    }
    else
    {
        ConsoleFormatter.PrintWhatIfResult(result, scenario);
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

    using var historyService = new AuditHistoryService();
    var generator = new ExecutiveSummaryGenerator(historyService);
    var summary = generator.Generate(report, options.SummaryTrendDays);

    var output = options.SummaryFormat switch
    {
        "json" => ExecutiveSummaryGenerator.RenderJson(summary),
        "md" or "markdown" => ExecutiveSummaryGenerator.RenderMarkdown(summary),
        _ => ExecutiveSummaryGenerator.RenderText(summary)
    };

    if (!string.IsNullOrWhiteSpace(options.OutputFile))
    {
        await File.WriteAllTextAsync(options.OutputFile, output);
        if (!options.Quiet)
            Console.WriteLine($"  Summary saved to {options.OutputFile}");
    }
    else
    {
        Console.WriteLine(output);
    }

    // Save this run to history
    historyService.SaveAuditResult(report);

    return 0;
}

// ── Remediation Cost Estimator ───────────────────────────────────────

static async Task<int> HandleCost(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for remediation cost estimation...");
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

    var estimator = new RemediationCostEstimator();
    var costOptions = new CostOptions
    {
        HourlyRate = options.CostHourlyRate,
        SprintHours = options.CostSprintHours,
    };

    var costReport = estimator.Estimate(report, costOptions);

    var output = options.CostFormat switch
    {
        "json" => RemediationCostEstimator.RenderJson(costReport),
        "csv" => RemediationCostEstimator.RenderCsv(costReport),
        _ => RemediationCostEstimator.RenderText(costReport)
    };

    if (!string.IsNullOrWhiteSpace(options.OutputFile))
    {
        await File.WriteAllTextAsync(options.OutputFile, output);
        if (!options.Quiet)
            Console.WriteLine($"  Cost report saved to {options.OutputFile}");
    }
    else
    {
        Console.WriteLine(output);
    }

    // Save this run to history
    using var historyService = new AuditHistoryService();
    historyService.SaveAuditResult(report);

    return 0;
}

// ── Peer Benchmark ───────────────────────────────────────────────────

static async Task<int> HandleBenchmark(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for peer benchmark comparison...");
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
        Console.WriteLine();
    }

    var benchService = new PeerBenchmarkService();

    if (options.BenchmarkAll)
    {
        var allResults = benchService.CompareAll(report);
        if (options.BenchmarkFormat == "json")
        {
            var jsonOpts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() }
            };
            var jsonOutput = JsonSerializer.Serialize(allResults, jsonOpts);
            if (!string.IsNullOrWhiteSpace(options.OutputFile))
                await File.WriteAllTextAsync(options.OutputFile, jsonOutput);
            else
                Console.WriteLine(jsonOutput);
        }
        else
        {
            foreach (var (_, benchResult) in allResults)
            {
                ConsoleFormatter.PrintBenchmarkResult(benchResult);
                Console.WriteLine();
            }
        }
    }
    else
    {
        PeerBenchmarkService.PeerGroup peerGroup;
        if (options.BenchmarkGroup == "auto")
            peerGroup = benchService.SuggestPeerGroup(report);
        else if (!Enum.TryParse<PeerBenchmarkService.PeerGroup>(options.BenchmarkGroup, true, out peerGroup))
        {
            ConsoleFormatter.PrintError(
                $"Unknown benchmark group '{options.BenchmarkGroup}'. Valid: home, developer, enterprise, server, auto");
            return 3;
        }

        var benchResult = benchService.Compare(report, peerGroup);

        if (options.BenchmarkFormat == "json")
        {
            var jsonOpts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() }
            };
            var jsonOutput = JsonSerializer.Serialize(benchResult, jsonOpts);
            if (!string.IsNullOrWhiteSpace(options.OutputFile))
                await File.WriteAllTextAsync(options.OutputFile, jsonOutput);
            else
                Console.WriteLine(jsonOutput);
        }
        else
        {
            ConsoleFormatter.PrintBenchmarkResult(benchResult);
        }
    }

    if (!string.IsNullOrWhiteSpace(options.OutputFile) && !options.Quiet)
        Console.WriteLine($"  Benchmark saved to {options.OutputFile}");

    // Save audit to history
    using var benchHistoryService = new AuditHistoryService();
    benchHistoryService.SaveAuditResult(report);

    return 0;
}

// ── Compliance Mapper ────────────────────────────────────────────────

static async Task<int> HandleCompliance(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for compliance mapping...");
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
        Console.WriteLine();
    }

    var mapper = new ComplianceMapper();

    if (options.ComplianceAll || options.ComplianceFramework == null)
    {
        // Cross-framework analysis
        var crossSummary = mapper.CrossFrameworkAnalysis(report);

        if (options.ComplianceFormat == "json")
        {
            var jsonOpts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() }
            };
            var jsonOutput = JsonSerializer.Serialize(crossSummary, jsonOpts);
            WriteOutput(jsonOutput, options.OutputFile);
        }
        else if (options.ComplianceFormat == "markdown")
        {
            var md = GenerateComplianceMarkdown(crossSummary, mapper, report, options.ComplianceGapsOnly);
            WriteOutput(md, options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintCrossFrameworkSummary(crossSummary);
            Console.WriteLine();

            // Show detailed reports for each framework
            foreach (var fr in crossSummary.FrameworkResults)
            {
                var detailedReport = mapper.Evaluate(report, fr.FrameworkId);
                ConsoleFormatter.PrintComplianceReport(detailedReport, options.ComplianceGapsOnly);
                Console.WriteLine();
            }
        }
    }
    else
    {
        // Single framework
        var framework = mapper.GetFramework(options.ComplianceFramework);
        if (framework == null)
        {
            ConsoleFormatter.PrintError(
                $"Unknown framework: '{options.ComplianceFramework}'. Available: {string.Join(", ", mapper.FrameworkIds)}");
            return 3;
        }

        var compReport = mapper.Evaluate(report, options.ComplianceFramework);

        if (options.ComplianceFormat == "json")
        {
            var jsonOpts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() }
            };
            var jsonOutput = JsonSerializer.Serialize(compReport, jsonOpts);
            WriteOutput(jsonOutput, options.OutputFile);
        }
        else if (options.ComplianceFormat == "markdown")
        {
            var md = GenerateSingleFrameworkMarkdown(compReport, options.ComplianceGapsOnly);
            WriteOutput(md, options.OutputFile);
        }
        else
        {
            ConsoleFormatter.PrintComplianceReport(compReport, options.ComplianceGapsOnly);
        }
    }

    if (!string.IsNullOrWhiteSpace(options.OutputFile) && !options.Quiet)
        Console.WriteLine($"\n  Compliance report saved to {options.OutputFile}");

    // Save audit to history
    using var compHistoryService = new AuditHistoryService();
    compHistoryService.SaveAuditResult(report);

    return 0;
}

static string GenerateComplianceMarkdown(CrossFrameworkSummary summary, ComplianceMapper mapper, SecurityReport report, bool gapsOnly)
{
    var sb = new System.Text.StringBuilder();
    sb.AppendLine("# WinSentinel Compliance Report");
    sb.AppendLine();
    sb.AppendLine($"**Security Score:** {summary.SecurityScore}/100");
    sb.AppendLine($"**Generated:** {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}");
    sb.AppendLine();
    sb.AppendLine("## Cross-Framework Summary");
    sb.AppendLine();
    sb.AppendLine("| Framework | Compliance | Verdict | Pass | Fail | Partial | N/A |");
    sb.AppendLine("|-----------|-----------|---------|------|------|---------|-----|");

    foreach (var fr in summary.FrameworkResults)
    {
        sb.AppendLine($"| {fr.FrameworkName} | {fr.CompliancePercentage}% | {fr.Verdict} | {fr.PassCount} | {fr.FailCount} | {fr.PartialCount} | {fr.NotAssessedCount} |");
    }

    sb.AppendLine();

    foreach (var fr in summary.FrameworkResults)
    {
        var detailedReport = mapper.Evaluate(report, fr.FrameworkId);
        sb.AppendLine($"## {detailedReport.FrameworkName} (v{detailedReport.FrameworkVersion})");
        sb.AppendLine();
        sb.AppendLine($"Compliance: **{detailedReport.Summary.CompliancePercentage}%** — {detailedReport.Summary.OverallVerdict}");
        sb.AppendLine();
        sb.AppendLine("| Control | Title | Status | Remediation |");
        sb.AppendLine("|---------|-------|--------|-------------|");

        foreach (var ctrl in detailedReport.Controls)
        {
            if (gapsOnly && ctrl.Status == ControlStatus.Pass) continue;
            var remediation = ctrl.Remediation.Count > 0
                ? string.Join("; ", ctrl.Remediation.Take(2))
                : "—";
            sb.AppendLine($"| {ctrl.ControlId} | {ctrl.ControlTitle} | {ctrl.Status} | {remediation} |");
        }
        sb.AppendLine();
    }

    return sb.ToString();
}

static string GenerateSingleFrameworkMarkdown(ComplianceReport compReport, bool gapsOnly)
{
    var sb = new System.Text.StringBuilder();
    sb.AppendLine($"# {compReport.FrameworkName} Compliance Report");
    sb.AppendLine();
    sb.AppendLine($"**Version:** {compReport.FrameworkVersion}");
    sb.AppendLine($"**Generated:** {compReport.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
    sb.AppendLine($"**Compliance:** {compReport.Summary.CompliancePercentage}% — {compReport.Summary.OverallVerdict}");
    sb.AppendLine();
    sb.AppendLine("## Control Results");
    sb.AppendLine();
    sb.AppendLine("| Control | Title | Status | Remediation |");
    sb.AppendLine("|---------|-------|--------|-------------|");

    foreach (var ctrl in compReport.Controls)
    {
        if (gapsOnly && ctrl.Status == ControlStatus.Pass) continue;
        var remediation = ctrl.Remediation.Count > 0
            ? string.Join("; ", ctrl.Remediation.Take(2))
            : "—";
        sb.AppendLine($"| {ctrl.ControlId} | {ctrl.ControlTitle} | {ctrl.Status} | {remediation} |");
    }
    sb.AppendLine();

    sb.AppendLine("## Summary");
    sb.AppendLine();
    sb.AppendLine($"- **Pass:** {compReport.Summary.PassCount}");
    sb.AppendLine($"- **Fail:** {compReport.Summary.FailCount}");
    sb.AppendLine($"- **Partial:** {compReport.Summary.PartialCount}");
    sb.AppendLine($"- **Not Assessed:** {compReport.Summary.NotAssessedCount}");

    return sb.ToString();
}

// ── System Inventory ─────────────────────────────────────────────────

static int HandleInventory(CliOptions options)
{
    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Collecting system inventory...");
        Console.WriteLine();
    }

    var inventory = CollectInventory(options);

    if (options.Json || options.InventoryFormat == "json")
    {
        WriteOutput(ConsoleFormatter.FormatInventoryJson(inventory), options.OutputFile);
        return 0;
    }

    if (options.Markdown || options.InventoryFormat is "markdown" or "md")
    {
        WriteOutput(ConsoleFormatter.FormatInventoryMarkdown(inventory), options.OutputFile);
        return 0;
    }

    ConsoleFormatter.PrintInventory(inventory);
    return 0;
}

static ConsoleFormatter.SystemInventory CollectInventory(CliOptions options)
{
    var apps = new List<ConsoleFormatter.InstalledApp>();
    var services = new List<ConsoleFormatter.ServiceEntry>();
    var startupPrograms = new List<ConsoleFormatter.StartupEntry>();
    var listeningPorts = new List<ConsoleFormatter.ListeningPort>();
    var scheduledTasks = new List<ConsoleFormatter.ScheduledTaskEntry>();
    var envVars = new Dictionary<string, string>();

    if (!options.InventoryNoApps)
    {
        apps = CollectInstalledApps();
        if (!options.Quiet) Console.WriteLine($"  ✓ Found {apps.Count} installed applications");
    }

    if (!options.InventoryNoServices)
    {
        services = CollectServices();
        if (!options.Quiet) Console.WriteLine($"  ✓ Found {services.Count} services");
    }

    if (!options.InventoryNoPorts)
    {
        listeningPorts = CollectListeningPorts();
        if (!options.Quiet) Console.WriteLine($"  ✓ Found {listeningPorts.Count} listening ports");
    }

    if (!options.InventoryNoStartup)
    {
        startupPrograms = CollectStartupPrograms();
        if (!options.Quiet) Console.WriteLine($"  ✓ Found {startupPrograms.Count} startup programs");
    }

    if (!options.InventoryNoTasks)
    {
        scheduledTasks = CollectScheduledTasks();
        if (!options.Quiet) Console.WriteLine($"  ✓ Found {scheduledTasks.Count} scheduled tasks");
    }

    foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
    {
        if (entry.Key is string key && entry.Value is string val)
            envVars[key] = val;
    }

    if (!options.Quiet) Console.WriteLine();

    long totalMemoryMB = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
    var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

    return new ConsoleFormatter.SystemInventory(
        Environment.MachineName,
        Environment.OSVersion.ToString(),
        Environment.UserName,
        Environment.ProcessorCount,
        totalMemoryMB,
        $"{uptime.Days}d {uptime.Hours}h {uptime.Minutes}m",
        DateTimeOffset.Now,
        apps, services, startupPrograms, listeningPorts, scheduledTasks, envVars
    );
}

static List<ConsoleFormatter.InstalledApp> CollectInstalledApps()
{
    var apps = new List<ConsoleFormatter.InstalledApp>();
    var regPaths = new[]
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    };

    foreach (var regPath in regPaths)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath);
            if (key == null) continue;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                try
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    if (subKey == null) continue;

                    var name = subKey.GetValue("DisplayName")?.ToString();
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    if (apps.Any(a => a.Name == name)) continue;

                    var version = subKey.GetValue("DisplayVersion")?.ToString() ?? "";
                    var publisher = subKey.GetValue("Publisher")?.ToString() ?? "";
                    var installDate = subKey.GetValue("InstallDate")?.ToString() ?? "";

                    if (installDate.Length == 8 && int.TryParse(installDate, out _))
                        installDate = $"{installDate[..4]}-{installDate[4..6]}-{installDate[6..]}";

                    apps.Add(new ConsoleFormatter.InstalledApp(name, version, publisher, installDate));
                }
                catch { }
            }
        }
        catch { }
    }

    return apps;
}

static List<ConsoleFormatter.ServiceEntry> CollectServices()
{
    var services = new List<ConsoleFormatter.ServiceEntry>();
    try
    {
        foreach (var svc in System.ServiceProcess.ServiceController.GetServices())
        {
            try
            {
                services.Add(new ConsoleFormatter.ServiceEntry(
                    svc.ServiceName, svc.DisplayName, svc.Status.ToString(), svc.StartType.ToString()
                ));
            }
            catch { }
            finally { svc.Dispose(); }
        }
    }
    catch { }
    return services;
}

static List<ConsoleFormatter.ListeningPort> CollectListeningPorts()
{
    var ports = new List<ConsoleFormatter.ListeningPort>();
    try
    {
        var ipProps = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
        foreach (var ep in ipProps.GetActiveTcpListeners())
            ports.Add(new ConsoleFormatter.ListeningPort(ep.Port, "TCP", "—", 0));
        foreach (var ep in ipProps.GetActiveUdpListeners())
            ports.Add(new ConsoleFormatter.ListeningPort(ep.Port, "UDP", "—", 0));

        ports = ports.GroupBy(p => new { p.Port, p.Protocol }).Select(g => g.First()).ToList();
    }
    catch { }

    // Enrich with process names via netstat
    try
    {
        var psi = new System.Diagnostics.ProcessStartInfo("netstat", "-bno")
        {
            RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
        };
        using var proc = System.Diagnostics.Process.Start(psi);
        if (proc != null)
        {
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            var lines = output.Split('\n');
            for (int li = 0; li < lines.Length; li++)
            {
                var line = lines[li].Trim();
                if (!line.Contains("LISTENING")) continue;
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5) continue;
                var proto = parts[0];
                var localAddr = parts[1];
                var colonIdx = localAddr.LastIndexOf(':');
                if (colonIdx < 0) continue;
                if (!int.TryParse(localAddr[(colonIdx + 1)..], out var port)) continue;
                if (!int.TryParse(parts[^1], out var pid)) continue;
                var processName = "—";
                if (li + 1 < lines.Length)
                {
                    var nextLine = lines[li + 1].Trim();
                    if (nextLine.StartsWith("[") && nextLine.EndsWith("]"))
                        processName = nextLine[1..^1];
                }
                var existing = ports.FirstOrDefault(p => p.Port == port && p.Protocol == proto);
                if (existing != null) ports.Remove(existing);
                ports.Add(new ConsoleFormatter.ListeningPort(port, proto, processName, pid));
            }
        }
    }
    catch { }

    return ports;
}

static List<ConsoleFormatter.StartupEntry> CollectStartupPrograms()
{
    var entries = new List<ConsoleFormatter.StartupEntry>();
    var regPaths = new (Microsoft.Win32.RegistryKey root, string path, string location)[]
    {
        (Microsoft.Win32.Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (Microsoft.Win32.Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (Microsoft.Win32.Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (x86)"),
    };

    foreach (var (root, path, location) in regPaths)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key == null) continue;
            foreach (var valueName in key.GetValueNames())
            {
                var cmd = key.GetValue(valueName)?.ToString() ?? "";
                if (!string.IsNullOrWhiteSpace(valueName) && !string.IsNullOrWhiteSpace(cmd))
                    entries.Add(new ConsoleFormatter.StartupEntry(valueName, cmd, location));
            }
        }
        catch { }
    }
    return entries;
}

static List<ConsoleFormatter.ScheduledTaskEntry> CollectScheduledTasks()
{
    var tasks = new List<ConsoleFormatter.ScheduledTaskEntry>();
    try
    {
        var psi = new System.Diagnostics.ProcessStartInfo("schtasks", "/query /fo CSV /nh")
        {
            RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
        };
        using var proc = System.Diagnostics.Process.Start(psi);
        if (proc != null)
        {
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;
                var fields = ParseCsvLine(trimmed);
                if (fields.Count < 3) continue;
                var name = fields[0].Trim('"');
                var nextRun = fields[1].Trim('"');
                var state = fields[2].Trim('"');
                if (name.StartsWith(@"\Microsoft\Windows\")) continue;
                if (name == "TaskName") continue;
                tasks.Add(new ConsoleFormatter.ScheduledTaskEntry(name, state, nextRun, "—"));
            }
        }
    }
    catch { }
    return tasks;
}

static List<string> ParseCsvLine(string line)
{
    var fields = new List<string>();
    var current = new System.Text.StringBuilder();
    bool inQuotes = false;
    foreach (var ch in line)
    {
        if (ch == '"') { inQuotes = !inQuotes; current.Append(ch); }
        else if (ch == ',' && !inQuotes) { fields.Add(current.ToString()); current.Clear(); }
        else { current.Append(ch); }
    }
    fields.Add(current.ToString());
    return fields;
}

// ── Tag Management ───────────────────────────────────────────────

static string GetTagStorePath() =>
    Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSentinel", "tags.json");

static FindingTagManager LoadTagManager()
{
    var manager = new FindingTagManager();
    var path = GetTagStorePath();
    if (File.Exists(path))
    {
        var json = File.ReadAllText(path);
        manager.ImportJson(json, merge: false);
    }
    return manager;
}

static void SaveTagManager(FindingTagManager manager)
{
    var path = GetTagStorePath();
    var dir = Path.GetDirectoryName(path)!;
    if (!Directory.Exists(dir))
        Directory.CreateDirectory(dir);
    File.WriteAllText(path, manager.ExportJson());
}

static int HandleTag(CliOptions options)
{
    var manager = LoadTagManager();

    return options.TagAction switch
    {
        TagAction.Add => HandleTagAdd(manager, options),
        TagAction.Remove => HandleTagRemove(manager, options),
        TagAction.List => HandleTagList(manager, options),
        TagAction.Search => HandleTagSearch(manager, options),
        TagAction.Report => HandleTagReport(manager, options),
        TagAction.AutoTag => HandleTagAutoTag(manager, options),
        TagAction.Rename => HandleTagRename(manager, options),
        TagAction.Delete => HandleTagDelete(manager, options),
        TagAction.Export => HandleTagExport(manager, options),
        TagAction.Import => HandleTagImport(manager, options),
        _ => HandleTagReport(manager, options)
    };
}

static int HandleTagAdd(FindingTagManager manager, CliOptions options)
{
    if (string.IsNullOrWhiteSpace(options.TagFindingTitle))
    {
        ConsoleFormatter.PrintError("--tag-finding is required for 'add'. Specify the finding title.");
        return 3;
    }
    if (options.TagValues.Count == 0)
    {
        ConsoleFormatter.PrintError("At least one --tag-value is required for 'add'.");
        return 3;
    }

    var category = options.TagFindingCategory ?? "Unknown";
    var tagged = manager.Tag(options.TagFindingTitle, category, options.TagValues.ToArray());

    // Also add annotation if provided
    if (!string.IsNullOrWhiteSpace(options.TagAnnotation))
    {
        manager.Annotate(options.TagFindingTitle, category, options.TagAnnotation, options.TagAuthor);
    }

    SaveTagManager(manager);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            action = "tagged",
            finding = options.TagFindingTitle,
            category,
            tags = tagged.Tags.ToList(),
            totalTags = tagged.Tags.Count
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagAdded(options.TagFindingTitle, category, options.TagValues);
    }

    return 0;
}

static int HandleTagRemove(FindingTagManager manager, CliOptions options)
{
    if (string.IsNullOrWhiteSpace(options.TagFindingTitle))
    {
        ConsoleFormatter.PrintError("--tag-finding is required for 'remove'.");
        return 3;
    }
    if (options.TagValues.Count == 0)
    {
        ConsoleFormatter.PrintError("At least one --tag-value is required for 'remove'.");
        return 3;
    }

    var category = options.TagFindingCategory ?? "Unknown";
    var removed = manager.Untag(options.TagFindingTitle, category, options.TagValues.ToArray());

    SaveTagManager(manager);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            action = "untagged",
            finding = options.TagFindingTitle,
            category,
            removedTags = options.TagValues,
            success = removed
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagRemoved(options.TagFindingTitle, category, options.TagValues, removed);
    }

    return 0;
}

static int HandleTagList(FindingTagManager manager, CliOptions options)
{
    IReadOnlyList<FindingTagManager.TaggedFinding> findings;

    if (options.TagValues.Count > 0)
    {
        // Filter by specific tag(s)
        findings = manager.GetByAnyTag(options.TagValues.ToArray());
    }
    else
    {
        findings = manager.Findings.Values
            .OrderByDescending(f => f.LastModifiedAt)
            .ToList();
    }

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            count = findings.Count,
            filter = options.TagValues.Count > 0 ? options.TagValues : null,
            findings = findings.Select(f => new
            {
                title = f.Title,
                category = f.Category,
                tags = f.Tags.ToList(),
                annotations = f.Annotations.Count,
                lastModified = f.LastModifiedAt
            })
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagList(findings, options.TagValues);
    }

    return 0;
}

static int HandleTagSearch(FindingTagManager manager, CliOptions options)
{
    var query = options.TagSearchQuery ?? options.TagFindingTitle ?? "";
    if (string.IsNullOrWhiteSpace(query))
    {
        ConsoleFormatter.PrintError("Provide a search query with --tag-search.");
        return 3;
    }

    var results = manager.Search(query);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            query,
            count = results.Count,
            results = results.Select(f => new
            {
                title = f.Title,
                category = f.Category,
                tags = f.Tags.ToList(),
                annotations = f.Annotations.Count
            })
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagSearch(results, query);
    }

    return 0;
}

static int HandleTagReport(FindingTagManager manager, CliOptions options)
{
    var report = manager.GenerateReport();

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            generatedAt = report.GeneratedAt,
            totalFindings = report.TotalFindings,
            totalTags = report.TotalTags,
            totalAnnotations = report.TotalAnnotations,
            untaggedCount = report.UntaggedCount,
            tagCounts = report.TagCounts,
            recentlyModified = report.RecentlyModified.Select(f => new
            {
                title = f.Title,
                category = f.Category,
                tags = f.Tags.ToList(),
                lastModified = f.LastModifiedAt
            })
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagReport(report);
    }

    return 0;
}

static int HandleTagAutoTag(FindingTagManager manager, CliOptions options)
{
    // Run an audit and auto-tag all findings by severity
    var engine = BuildEngine(options.ModulesFilter);

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for auto-tagging...");
        Console.WriteLine();
    }

    var progress = options.Quiet || options.Json
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = engine.RunFullAuditAsync(progress).GetAwaiter().GetResult();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, TimeSpan.Zero);
    }

    var count = manager.AutoTagBySeverity(report);

    // Also apply any custom tags from --tag-value
    if (options.TagValues.Count > 0)
    {
        count += manager.TagFromReport(report, options.TagValues.ToArray());
    }

    SaveTagManager(manager);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            action = "auto-tagged",
            findingsTagged = count,
            totalTracked = manager.Count
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagAutoTagged(count, manager.Count);
    }

    return 0;
}

static int HandleTagRename(FindingTagManager manager, CliOptions options)
{
    if (string.IsNullOrWhiteSpace(options.TagRenameFrom) || string.IsNullOrWhiteSpace(options.TagRenameTo))
    {
        ConsoleFormatter.PrintError("Both --tag-rename-from and --tag-rename-to are required.");
        return 3;
    }

    var affected = manager.RenameTag(options.TagRenameFrom, options.TagRenameTo);
    SaveTagManager(manager);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            action = "renamed",
            from = options.TagRenameFrom,
            to = options.TagRenameTo,
            findingsAffected = affected
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagRenamed(options.TagRenameFrom, options.TagRenameTo, affected);
    }

    return 0;
}

static int HandleTagDelete(FindingTagManager manager, CliOptions options)
{
    if (options.TagValues.Count == 0)
    {
        ConsoleFormatter.PrintError("At least one --tag-value is required for 'delete'.");
        return 3;
    }

    int total = 0;
    foreach (var tag in options.TagValues)
    {
        total += manager.DeleteTag(tag);
    }

    SaveTagManager(manager);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            action = "deleted",
            deletedTags = options.TagValues,
            findingsAffected = total
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        ConsoleFormatter.PrintTagDeleted(options.TagValues, total);
    }

    return 0;
}

static int HandleTagExport(FindingTagManager manager, CliOptions options)
{
    var json = manager.ExportJson();
    var outputPath = options.OutputFile ?? options.TagImportFile;

    if (outputPath != null)
    {
        File.WriteAllText(outputPath, json);
        if (!options.Quiet)
        {
            var orig = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ Tags exported to {outputPath} ({manager.Count} findings)");
            Console.ForegroundColor = orig;
        }
    }
    else
    {
        WriteOutput(json, null);
    }

    return 0;
}

static int HandleTagImport(FindingTagManager manager, CliOptions options)
{
    var importPath = options.TagImportFile ?? options.OutputFile;
    if (string.IsNullOrWhiteSpace(importPath) || !File.Exists(importPath))
    {
        ConsoleFormatter.PrintError("Provide a valid file path with --tag-file for import.");
        return 3;
    }

    var json = File.ReadAllText(importPath);
    var count = manager.ImportJson(json, options.TagMerge);
    SaveTagManager(manager);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(new
        {
            action = "imported",
            file = importPath,
            findingsImported = count,
            merge = options.TagMerge,
            totalTracked = manager.Count
        }, jsonOptions), options.OutputFile);
    }
    else
    {
        var orig = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Imported {count} findings from {importPath} (merge: {options.TagMerge})");
        Console.ForegroundColor = orig;
        Console.WriteLine($"  Total tracked findings: {manager.Count}");
        Console.WriteLine();
    }

    return 0;
}

// ── Hotspot Analysis ────────────────────────────────────────────────

static int HandleHotspots(CliOptions options)
{
    var historyService = new AuditHistoryService();
    historyService.EnsureDatabase();

    var runs = historyService.GetHistory(options.HotspotDays);

    if (runs.Count == 0)
    {
        if (options.Json)
        {
            WriteOutput("{\"error\": \"No audit history found. Run some audits first.\"}", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine();
            ConsoleFormatter.PrintError("No audit history found. Run some audits first.");
        }
        return 1;
    }

    // Load full details for each run
    var detailedRuns = new List<AuditRunRecord>();
    foreach (var run in runs)
    {
        var detailed = historyService.GetRunDetails(run.Id);
        if (detailed != null)
            detailedRuns.Add(detailed);
    }

    var analyzer = new HotspotAnalyzer();
    var result = analyzer.Analyze(detailedRuns, options.HotspotMaxRuns);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(result, jsonOptions), options.OutputFile);
        return 0;
    }

    if (options.Markdown)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# 🔥 Security Hotspot Analysis");
        sb.AppendLine();
        sb.AppendLine($"**Runs analyzed:** {result.RunsAnalyzed} (over {result.DaysSpan} days)");
        sb.AppendLine($"**Overall heat:** {result.OverallHeatLevel} ({result.OverallHeat:F1})");
        sb.AppendLine($"**Hottest category:** {result.HottestCategory}");
        sb.AppendLine($"**Hottest module:** {result.HottestModule}");
        sb.AppendLine();

        if (result.CategoryHotspots.Count > 0)
        {
            sb.AppendLine("## Category Hotspots");
            sb.AppendLine();
            sb.AppendLine("| # | Category | Heat | Level | Rate | C | W | I | Avg | Trend |");
            sb.AppendLine("|---|----------|------|-------|------|---|---|---|-----|-------|");
            var idx = 0;
            foreach (var h in result.CategoryHotspots.Take(options.HotspotTop))
            {
                idx++;
                sb.AppendLine($"| {idx} | {h.Name} | {h.HeatScore:F1} | {h.HeatLevel} | {h.AppearanceRate:F0}% | {h.CriticalFindings} | {h.WarningFindings} | {h.InfoFindings} | {h.AvgFindingsPerRun:F1} | {h.Trend} |");
            }
            sb.AppendLine();
        }

        if (result.ModuleHotspots.Count > 0)
        {
            sb.AppendLine("## Module Hotspots");
            sb.AppendLine();
            sb.AppendLine("| # | Module | Heat | Level | Rate | C | W | I | Avg | Trend |");
            sb.AppendLine("|---|--------|------|-------|------|---|---|---|-----|-------|");
            var idx = 0;
            foreach (var h in result.ModuleHotspots.Take(options.HotspotTop))
            {
                idx++;
                sb.AppendLine($"| {idx} | {h.Name} | {h.HeatScore:F1} | {h.HeatLevel} | {h.AppearanceRate:F0}% | {h.CriticalFindings} | {h.WarningFindings} | {h.InfoFindings} | {h.AvgFindingsPerRun:F1} | {h.Trend} |");
            }
        }

        WriteOutput(sb.ToString(), options.OutputFile);
        return 0;
    }

    ConsoleFormatter.PrintHotspotResult(result, options.Quiet, options.HotspotTop);
    return 0;
}

// ── KPI Dashboard ────────────────────────────────────────────────────

static int HandleKpi(CliOptions options)
{
    var historyService = new AuditHistoryService();
    historyService.EnsureDatabase();

    var runs = historyService.GetHistory(options.KpiDays);

    if (runs.Count == 0)
    {
        if (options.Json)
        {
            WriteOutput("{\"error\": \"No audit history found. Run some audits first.\"}", options.OutputFile);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine();
            ConsoleFormatter.PrintError("No audit history found. Run some audits first.");
        }
        return 1;
    }

    // Load full details for each run
    var detailedRuns = new List<AuditRunRecord>();
    foreach (var run in runs)
    {
        var detailed = historyService.GetRunDetails(run.Id);
        if (detailed != null)
            detailedRuns.Add(detailed);
    }

    var kpiService = new SecurityKpiService();
    var result = kpiService.Compute(detailedRuns, options.KpiDays);

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(result, jsonOptions), options.OutputFile);
        return 0;
    }

    if (options.Markdown)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# 📊 Security KPI Dashboard");
        sb.AppendLine();
        sb.AppendLine($"**Period:** {result.PeriodStart:yyyy-MM-dd} → {result.PeriodEnd:yyyy-MM-dd} ({result.DaysSpan} days, {result.RunsAnalyzed} scans)");
        sb.AppendLine($"**Health:** {result.HealthRating} ({result.HealthScore}/100)");
        sb.AppendLine();

        sb.AppendLine("## Score KPIs");
        sb.AppendLine();
        sb.AppendLine($"| Metric | Value |");
        sb.AppendLine($"|--------|-------|");
        sb.AppendLine($"| Current Score | {result.CurrentScore} |");
        sb.AppendLine($"| Average Score | {result.AverageScore:F1} |");
        sb.AppendLine($"| Score Trend | {result.ScoreTrend} ({result.ScoreChange:+#;-#;0}) |");
        sb.AppendLine($"| Score Volatility | {result.ScoreVolatility} |");
        sb.AppendLine();

        sb.AppendLine("## Finding KPIs");
        sb.AppendLine();
        sb.AppendLine($"| Metric | Value |");
        sb.AppendLine($"|--------|-------|");
        sb.AppendLine($"| Current Findings | {result.CurrentFindings} |");
        sb.AppendLine($"| New Findings | {result.NewFindings} |");
        sb.AppendLine($"| Resolved Findings | {result.ResolvedFindings} |");
        sb.AppendLine($"| Net Change | {result.FindingNetChange:+#;-#;0} |");
        sb.AppendLine($"| Recurring Findings | {result.RecurringFindings} ({result.RecurrenceRate}%) |");
        sb.AppendLine();

        sb.AppendLine("## Severity & MTTR");
        sb.AppendLine();
        sb.AppendLine($"| Metric | Value |");
        sb.AppendLine($"|--------|-------|");
        sb.AppendLine($"| Current Critical | {result.CurrentCritical} |");
        sb.AppendLine($"| Current Warnings | {result.CurrentWarnings} |");
        sb.AppendLine($"| Peak Critical | {result.PeakCritical} |");
        sb.AppendLine($"| Avg Critical/Scan | {result.AvgCriticalPerScan} |");
        sb.AppendLine($"| MTTR Critical | {(result.MeanTimeToRemediateCritical.HasValue ? $"{result.MeanTimeToRemediateCritical:F1} days" : "N/A")} |");
        sb.AppendLine($"| MTTR Warning | {(result.MeanTimeToRemediateWarning.HasValue ? $"{result.MeanTimeToRemediateWarning:F1} days" : "N/A")} |");
        sb.AppendLine();

        sb.AppendLine("## Security Debt");
        sb.AppendLine();
        sb.AppendLine($"| Metric | Value |");
        sb.AppendLine($"|--------|-------|");
        sb.AppendLine($"| Current Debt | {result.SecurityDebt} |");
        sb.AppendLine($"| Debt Trend | {result.DebtTrend} ({result.DebtChange:+#.#;-#.#;0}) |");
        sb.AppendLine();

        sb.AppendLine("## Scan Cadence");
        sb.AppendLine();
        sb.AppendLine($"| Metric | Value |");
        sb.AppendLine($"|--------|-------|");
        sb.AppendLine($"| Scans/Week | {result.ScansPerWeek} |");
        sb.AppendLine($"| Avg Gap | {result.AvgDaysBetweenScans} days |");
        sb.AppendLine($"| Max Gap | {result.MaxScanGap} days |");
        sb.AppendLine();

        if (result.Recommendations.Count > 0)
        {
            sb.AppendLine("## Recommendations");
            sb.AppendLine();
            foreach (var rec in result.Recommendations)
                sb.AppendLine($"- {rec}");
        }

        WriteOutput(sb.ToString(), options.OutputFile);
        return 0;
    }

    ConsoleFormatter.PrintKpiReport(result, options.Quiet);
    return 0;
}

// ── SLA Tracker ──────────────────────────────────────────────────────

static async Task<int> HandleSla(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit for SLA tracking...");
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
        ConsoleFormatter.PrintScore(report.SecurityScore);
        Console.WriteLine();
    }

    // Select SLA policy
    var policy = options.SlaPolicy switch
    {
        "strict" => SlaTracker.SlaPolicy.Strict,
        "relaxed" => SlaTracker.SlaPolicy.Relaxed,
        _ => SlaTracker.SlaPolicy.Enterprise
    };

    var tracker = new SlaTracker(policy);

    // Load existing tracked findings from history if available
    var slaDataPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSentinel", "sla-tracking.json");

    if (File.Exists(slaDataPath))
    {
        try
        {
            var existingJson = File.ReadAllText(slaDataPath);
            tracker.ImportJson(existingJson);
        }
        catch
        {
            // Ignore corrupt data, start fresh
        }
    }

    // Track new findings from current scan
    var tracked = tracker.TrackReport(report);

    // Auto-resolve findings that are no longer present
    var currentTitles = new HashSet<string>(
        report.Results.SelectMany(r => r.Findings)
            .Where(f => f.Severity != Severity.Pass)
            .Select(f => f.Title));

    var autoResolved = 0;
    foreach (var finding in tracker.GetOpen())
    {
        if (!currentTitles.Contains(finding.Title))
        {
            finding.ResolvedAt = DateTimeOffset.UtcNow;
            finding.ResolutionNotes = "Auto-resolved: finding no longer present in scan";
            autoResolved++;
        }
    }

    // Save updated tracking data
    var dir = Path.GetDirectoryName(slaDataPath);
    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    File.WriteAllText(slaDataPath, tracker.ExportJson());

    // Generate output based on action
    switch (options.SlaAction)
    {
        case SlaAction.Overdue:
            return HandleSlaOverdue(tracker, options);

        case SlaAction.Approaching:
            return HandleSlaApproaching(tracker, options);

        case SlaAction.Export:
            var exportJson = tracker.ExportJson();
            WriteOutput(exportJson, options.OutputFile);
            if (!options.Quiet && options.OutputFile != null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ SLA tracking data exported to {options.OutputFile}");
                Console.ResetColor();
            }
            return 0;

        case SlaAction.Report:
        default:
            return HandleSlaReport(tracker, options, tracked, autoResolved);
    }
}

static int HandleSlaReport(SlaTracker tracker, CliOptions options, int newlyTracked, int autoResolved)
{
    var slaReport = tracker.GenerateReport();

    if (options.Json)
    {
        var jsonResult = new
        {
            policy = slaReport.PolicyName,
            generatedAt = slaReport.GeneratedAt,
            totalTracked = slaReport.TotalTracked,
            openCount = slaReport.OpenCount,
            resolvedCount = slaReport.ResolvedCount,
            overdueCount = slaReport.OverdueCount,
            approachingCount = slaReport.ApproachingCount,
            compliancePercent = slaReport.CompliancePercent,
            meanTimeToRemediate = slaReport.MeanTimeToRemediate?.TotalHours,
            newlyTracked,
            autoResolved,
            bySeverity = slaReport.BySeverity.ToDictionary(
                kv => kv.Key.ToString(),
                kv => new
                {
                    total = kv.Value.Total,
                    metSla = kv.Value.MetSla,
                    missedSla = kv.Value.MissedSla,
                    onTrack = kv.Value.OnTrack,
                    compliancePercent = kv.Value.CompliancePercent
                }),
            overdue = slaReport.TopOverdue.Select(a => new
            {
                id = a.Finding.Id,
                title = a.Finding.Title,
                severity = a.Finding.Severity.ToString(),
                category = a.Finding.Category,
                urgency = a.UrgencyLabel
            }),
            approaching = slaReport.ApproachingDeadline.Select(a => new
            {
                id = a.Finding.Id,
                title = a.Finding.Title,
                severity = a.Finding.Severity.ToString(),
                category = a.Finding.Category,
                urgency = a.UrgencyLabel
            })
        };

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(jsonResult, jsonOptions), options.OutputFile);
        return 0;
    }

    // Text report
    var orig = Console.ForegroundColor;

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("  ╔══════════════════════════════════════════════╗");
    Console.WriteLine("  ║       ⏱️  SLA Compliance Dashboard          ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════╝");
    Console.ForegroundColor = orig;
    Console.WriteLine();

    // Policy info
    Console.Write("  Policy:         ");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine(slaReport.PolicyName);
    Console.ForegroundColor = orig;

    // Compliance
    Console.Write("  SLA Compliance: ");
    Console.ForegroundColor = slaReport.CompliancePercent >= 90 ? ConsoleColor.Green :
                               slaReport.CompliancePercent >= 70 ? ConsoleColor.Yellow : ConsoleColor.Red;
    Console.WriteLine($"{slaReport.CompliancePercent}%");
    Console.ForegroundColor = orig;

    // Counts
    Console.Write("  Total Tracked:  ");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine(slaReport.TotalTracked);
    Console.ForegroundColor = orig;

    Console.Write("  Open:           ");
    Console.ForegroundColor = slaReport.OpenCount > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
    Console.WriteLine(slaReport.OpenCount);
    Console.ForegroundColor = orig;

    Console.Write("  Resolved:       ");
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine(slaReport.ResolvedCount);
    Console.ForegroundColor = orig;

    Console.Write("  Overdue:        ");
    Console.ForegroundColor = slaReport.OverdueCount > 0 ? ConsoleColor.Red : ConsoleColor.Green;
    Console.WriteLine(slaReport.OverdueCount);
    Console.ForegroundColor = orig;

    Console.Write("  Approaching:    ");
    Console.ForegroundColor = slaReport.ApproachingCount > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
    Console.WriteLine(slaReport.ApproachingCount);
    Console.ForegroundColor = orig;

    if (slaReport.MeanTimeToRemediate.HasValue)
    {
        Console.Write("  Mean TTR:       ");
        Console.ForegroundColor = ConsoleColor.White;
        var mttr = slaReport.MeanTimeToRemediate.Value;
        if (mttr.TotalDays >= 1)
            Console.WriteLine($"{mttr.Days}d {mttr.Hours}h");
        else
            Console.WriteLine($"{(int)mttr.TotalHours}h {mttr.Minutes}m");
        Console.ForegroundColor = orig;
    }

    if (newlyTracked > 0 || autoResolved > 0)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  This scan: +{newlyTracked} tracked, {autoResolved} auto-resolved");
        Console.ForegroundColor = orig;
    }

    // Severity breakdown
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("  BY SEVERITY");
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  ──────────────────────────────────────────");
    Console.ForegroundColor = orig;

    foreach (var (sev, comp) in slaReport.BySeverity.OrderByDescending(kv => (int)kv.Key))
    {
        if (comp.Total == 0) continue;
        var sevColor = sev switch
        {
            Severity.Critical => ConsoleColor.Red,
            Severity.Warning => ConsoleColor.Yellow,
            _ => ConsoleColor.Cyan
        };
        Console.ForegroundColor = sevColor;
        Console.Write($"  {sev,-10}");
        Console.ForegroundColor = orig;
        Console.Write($"  Total: {comp.Total} | Met SLA: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(comp.MetSla);
        Console.ForegroundColor = orig;
        Console.Write(" | Missed: ");
        Console.ForegroundColor = comp.MissedSla > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray;
        Console.Write(comp.MissedSla);
        Console.ForegroundColor = orig;
        Console.Write(" | On Track: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(comp.OnTrack);
        Console.ForegroundColor = orig;
        Console.Write($" | {comp.CompliancePercent}%");
        Console.WriteLine();
    }

    // Overdue items
    if (slaReport.TopOverdue.Count > 0)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  ⚠️  OVERDUE FINDINGS");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ──────────────────────────────────────────");
        Console.ForegroundColor = orig;

        foreach (var a in slaReport.TopOverdue.Take(options.SlaTop))
        {
            var sevColor = a.Finding.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
            Console.Write("  ");
            Console.ForegroundColor = sevColor;
            Console.Write($"[{a.Finding.Severity}]");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($" {a.Finding.Title}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  ({a.Finding.Category})");
            Console.ForegroundColor = orig;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"    {a.UrgencyLabel}");
            Console.ForegroundColor = orig;
        }
    }

    // Approaching deadline
    if (slaReport.ApproachingDeadline.Count > 0)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  ⏳ APPROACHING DEADLINE");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ──────────────────────────────────────────");
        Console.ForegroundColor = orig;

        foreach (var a in slaReport.ApproachingDeadline.Take(options.SlaTop))
        {
            var sevColor = a.Finding.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;
            Console.Write("  ");
            Console.ForegroundColor = sevColor;
            Console.Write($"[{a.Finding.Severity}]");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($" {a.Finding.Title}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  ({a.Finding.Category})");
            Console.ForegroundColor = orig;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"    {a.UrgencyLabel}");
            Console.ForegroundColor = orig;
        }
    }

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  Options: --sla overdue | --sla approaching | --sla export");
    Console.WriteLine("           --sla-policy strict|enterprise|relaxed");
    Console.ForegroundColor = orig;
    Console.WriteLine();

    // Save audit to history
    using var historyService = new AuditHistoryService();
    historyService.EnsureDatabase();

    return slaReport.OverdueCount > 0 ? 1 : 0;
}

static int HandleSlaOverdue(SlaTracker tracker, CliOptions options)
{
    var overdue = tracker.GetOverdue();

    if (options.Json)
    {
        var jsonResult = overdue.Select(f => new
        {
            id = f.Id,
            title = f.Title,
            severity = f.Severity.ToString(),
            category = f.Category,
            detectedAt = f.DetectedAt,
            deadline = f.Deadline,
            overdueBy = (DateTimeOffset.UtcNow - f.Deadline).TotalHours
        });
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(jsonResult, jsonOptions), options.OutputFile);
        return 0;
    }

    var orig = Console.ForegroundColor;
    Console.WriteLine();

    if (overdue.Count == 0)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  ✓ No overdue findings. All within SLA!");
        Console.ForegroundColor = orig;
        Console.WriteLine();
        return 0;
    }

    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"  ⚠️  {overdue.Count} OVERDUE FINDING(S)");
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  ──────────────────────────────────────────");
    Console.ForegroundColor = orig;
    Console.WriteLine();

    foreach (var f in overdue.Take(options.SlaTop))
    {
        var overdueBy = DateTimeOffset.UtcNow - f.Deadline;
        var sevColor = f.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;

        Console.Write($"  {f.Id}  ");
        Console.ForegroundColor = sevColor;
        Console.Write($"[{f.Severity}]");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($" {f.Title}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"    Category: {f.Category}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"  | Overdue by: ");
        if (overdueBy.TotalDays >= 1)
            Console.Write($"{overdueBy.Days}d {overdueBy.Hours}h");
        else
            Console.Write($"{(int)overdueBy.TotalHours}h {overdueBy.Minutes}m");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    Console.WriteLine();
    return 1;
}

static int HandleSlaApproaching(SlaTracker tracker, CliOptions options)
{
    var approaching = tracker.GetApproaching();

    if (options.Json)
    {
        var jsonResult = approaching.Select(f => new
        {
            id = f.Id,
            title = f.Title,
            severity = f.Severity.ToString(),
            category = f.Category,
            detectedAt = f.DetectedAt,
            deadline = f.Deadline,
            hoursRemaining = (f.Deadline - DateTimeOffset.UtcNow).TotalHours
        });
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(jsonResult, jsonOptions), options.OutputFile);
        return 0;
    }

    var orig = Console.ForegroundColor;
    Console.WriteLine();

    if (approaching.Count == 0)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  ✓ No findings approaching their deadline.");
        Console.ForegroundColor = orig;
        Console.WriteLine();
        return 0;
    }

    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"  ⏳ {approaching.Count} FINDING(S) APPROACHING DEADLINE");
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  ──────────────────────────────────────────");
    Console.ForegroundColor = orig;
    Console.WriteLine();

    foreach (var f in approaching.Take(options.SlaTop))
    {
        var remaining = f.Deadline - DateTimeOffset.UtcNow;
        var sevColor = f.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.Yellow;

        Console.Write($"  {f.Id}  ");
        Console.ForegroundColor = sevColor;
        Console.Write($"[{f.Severity}]");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($" {f.Title}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"    Category: {f.Category}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"  | Time left: ");
        if (remaining.TotalDays >= 1)
            Console.Write($"{remaining.Days}d {remaining.Hours}h");
        else
            Console.Write($"{(int)remaining.TotalHours}h {remaining.Minutes}m");
        Console.ForegroundColor = orig;
        Console.WriteLine();
    }

    Console.WriteLine();
    return 0;
}

// ── Coverage Map ─────────────────────────────────────────────────────

static async Task<int> HandleCoverage(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit to generate coverage map...");
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

    var coverageService = new SecurityCoverageService();
    var coverage = coverageService.Analyze(report);

    // Filter to gaps only if requested
    if (options.CoverageGapsOnly)
    {
        coverage = coverage with
        {
            Domains = coverage.Domains.Where(d => d.HasGap).ToList()
        };
    }

    if (options.Json)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        WriteOutput(JsonSerializer.Serialize(coverage, jsonOptions), options.OutputFile);
        return 0;
    }

    if (options.Markdown)
    {
        WriteOutput(ConsoleFormatter.FormatCoverageMarkdown(coverage), options.OutputFile);
        return 0;
    }

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintCoverage(coverage);
    }

    return coverage.GapDomains > 0 ? 1 : 0;
}

// ── Risk Matrix ──────────────────────────────────────────────────────

static async Task<int> HandleRiskMatrix(CliOptions options)
{
    var engine = BuildEngine(options.ModulesFilter);

    if (!options.Quiet)
    {
        ConsoleFormatter.PrintBanner();
        Console.WriteLine("  Running audit to build risk matrix...");
        Console.WriteLine();
    }

    var progress = options.Quiet
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);

    if (options.Json)
    {
        // Build the matrix data as JSON
        var matrixData = BuildRiskMatrixData(report);
        var jsonOpts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };
        Console.WriteLine(JsonSerializer.Serialize(matrixData, jsonOpts));
        return 0;
    }

    ConsoleFormatter.PrintRiskMatrix(report, options.RiskMatrixCounts);
    return 0;
}

static object BuildRiskMatrixData(SecurityReport report)
{
    // Classify findings into a likelihood × impact matrix
    // Impact: derived from severity (Critical=High, Warning=Medium, Info=Low)
    // Likelihood: derived from category frequency (how many findings in that category)
    var allFindings = report.Results.SelectMany(r => r.Findings)
        .Where(f => f.Severity != Severity.Pass)
        .ToList();

    var categoryGroups = allFindings.GroupBy(f => f.Category).ToList();
    var maxCount = categoryGroups.Any() ? categoryGroups.Max(g => g.Count()) : 0;

    var cells = new List<object>();
    foreach (var group in categoryGroups)
    {
        var likelihood = maxCount <= 1 ? "Low"
            : group.Count() >= maxCount * 0.66 ? "High"
            : group.Count() >= maxCount * 0.33 ? "Medium"
            : "Low";

        foreach (var finding in group)
        {
            var impact = finding.Severity switch
            {
                Severity.Critical => "High",
                Severity.Warning => "Medium",
                _ => "Low"
            };
            cells.Add(new { finding.Title, finding.Category, Impact = impact, Likelihood = likelihood, finding.Severity });
        }
    }

    return new
    {
        GeneratedAt = DateTimeOffset.UtcNow,
        TotalFindings = allFindings.Count,
        Matrix = cells
    };
}