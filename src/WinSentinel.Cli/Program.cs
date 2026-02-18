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
    _ => HandleHelp()
};

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
    var engine = BuildEngine(options.ModulesFilter);
    var sw = Stopwatch.StartNew();

    if (!options.Quiet && !options.Json && !options.Html && !options.Markdown)
    {
        ConsoleFormatter.PrintBanner();
    }

    var progress = options.Quiet || options.Json || options.Html || options.Markdown
        ? null
        : new Progress<(string module, int current, int total)>(p =>
            ConsoleFormatter.PrintProgress(p.module, p.current, p.total));

    var report = await engine.RunFullAuditAsync(progress);
    sw.Stop();

    if (options.Json)
    {
        var generator = new ReportGenerator();
        var json = generator.GenerateJsonReport(report);
        WriteOutput(json, options.OutputFile);
    }
    else if (options.Html)
    {
        var generator = new ReportGenerator();
        var html = generator.GenerateHtmlReport(report);
        WriteOutput(html, options.OutputFile);

        if (!options.Quiet && options.OutputFile != null)
        {
            var original = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ HTML report saved to {options.OutputFile}");
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
    else if (options.Quiet)
    {
        ConsoleFormatter.PrintScore(report.SecurityScore, quiet: true);
    }
    else
    {
        ConsoleFormatter.PrintProgressDone(engine.Modules.Count, sw.Elapsed);
        ConsoleFormatter.PrintScore(report.SecurityScore);
        ConsoleFormatter.PrintSummary(report);
        ConsoleFormatter.PrintModuleTable(report);
        ConsoleFormatter.PrintFindings(report);
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
        ConsoleFormatter.PrintError("Available: firewall, updates, defender, accounts, network, processes, startup, system, privacy, browser, appsecurity, encryption, eventlog");
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
