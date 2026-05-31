namespace WinSentinel.Cli.ScheduledScans;

/// <summary>
/// Handles `winsentinel schedule` subcommands: create, remove, status, results.
/// No license gate — free feature.
/// </summary>
public static class ScheduleCommandHandler
{
    public static int Handle(CliOptions options)
    {
        return options.ScheduleAction switch
        {
            ScheduleAction.Create => HandleCreate(options),
            ScheduleAction.Remove => HandleRemove(),
            ScheduleAction.Status => HandleStatus(options),
            ScheduleAction.Results => HandleResults(options),
            _ => HandleHelp()
        };
    }

    private static int HandleCreate(CliOptions options)
    {
        var config = new ScheduleConfig
        {
            Cadence = options.ScheduleCadence ?? "daily",
            Time = options.ScheduleTime ?? "03:00",
            DayOfWeek = options.ScheduleDayOfWeek,
            AutoFix = options.ScheduleAutoFix,
            Quiet = options.Quiet,
            Modules = options.ModulesFilter
        };

        var (ok, message) = ScheduleEngine.CreateSchedule(config);
        Console.WriteLine(ok ? $"✅ {message}" : $"❌ {message}");
        return ok ? 0 : 1;
    }

    private static int HandleRemove()
    {
        var (ok, message) = ScheduleEngine.RemoveSchedule();
        Console.WriteLine(ok ? $"✅ {message}" : $"❌ {message}");
        return ok ? 0 : 1;
    }

    private static int HandleStatus(CliOptions options)
    {
        var (ok, active, message, config) = ScheduleEngine.GetStatus();
        if (options.Json)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(new { ok, active, message, config });
            Console.WriteLine(json);
        }
        else
        {
            Console.WriteLine(active ? $"📅 {message}" : $"ℹ️  {message}");
        }
        return 0;
    }

    private static int HandleResults(CliOptions options)
    {
        var results = ScheduleEngine.ListResults(options.ScheduleResultsLimit);
        if (options.Json)
        {
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(results));
            return 0;
        }

        if (results.Count == 0)
        {
            Console.WriteLine("No scheduled scan results found.");
            return 0;
        }

        Console.WriteLine($"{"File",-30} {"Score",6} {"Grade",6} {"Findings",9}");
        Console.WriteLine(new string('─', 55));
        foreach (var r in results)
        {
            Console.WriteLine($"{r.File,-30} {r.Score?.ToString() ?? "-",6} {r.Grade ?? "-",6} {r.FindingsCount?.ToString() ?? "-",9}");
        }
        return 0;
    }

    private static int HandleHelp()
    {
        Console.WriteLine(@"Usage: winsentinel schedule <action> [options]

Actions:
  create    Create or update a scheduled scan
  remove    Remove the scheduled scan task
  status    Show current schedule configuration
  results   List recent scan results

Options (for create):
  --cadence <hourly|daily|weekly>   Scan frequency (default: daily)
  --time <HH:MM>                    Time to run (default: 03:00)
  --day <MON|TUE|...|SUN>           Day of week (for weekly cadence)
  --auto-fix                        Enable auto-remediation
  --modules <list>                  Comma-separated module filter
  --quiet                           Suppress notifications

Options (for results):
  --limit <N>                       Number of results to show (default: 10)
  --json                            Output as JSON");
        return 0;
    }
}
