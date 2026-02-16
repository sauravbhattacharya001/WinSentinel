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

    if (!options.Quiet && !options.Json && !options.Html)
    {
        ConsoleFormatter.PrintBanner();
    }

    var progress = options.Quiet || options.Json || options.Html
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
