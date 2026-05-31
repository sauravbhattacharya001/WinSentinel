using System.Diagnostics;

namespace WinSentinel.Cli.Monitor;

/// <summary>
/// Handles `winsentinel monitor` subcommands: start, stop, status.
/// No license gate — free feature.
/// </summary>
public static class MonitorCommandHandler
{
    public static int Handle(CliOptions options)
    {
        return options.MonitorAction switch
        {
            MonitorAction.Start => HandleStart(options),
            MonitorAction.Stop => HandleStop(),
            MonitorAction.Status => HandleStatus(options),
            _ => HandleHelp()
        };
    }

    private static int HandleStart(CliOptions options)
    {
        var existingPid = MonitorEngine.GetRunningPid();
        if (existingPid != null)
        {
            Console.WriteLine($"⚠️  Monitor already running (PID {existingPid}). Use `winsentinel monitor stop` first.");
            return 1;
        }

        Console.WriteLine("🛡️  WinSentinel Real-Time Monitor");
        Console.WriteLine("   Watching filesystem and registry for security-relevant changes.");
        Console.WriteLine("   Press Ctrl+C to stop.\n");

        using var engine = new MonitorEngine();
        engine.OnLog += msg => Console.WriteLine($"[monitor] {msg}");
        engine.OnFinding += finding =>
        {
            var icon = finding.Severity switch
            {
                "critical" => "🚨",
                "warning" => "⚠️",
                _ => "ℹ️"
            };
            Console.WriteLine($"{icon} [{finding.Timestamp:HH:mm:ss}] {finding.Title}");
            Console.WriteLine($"   {finding.Description}");
        };

        engine.Start();

        // Block until Ctrl+C
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try { Task.Delay(Timeout.Infinite, cts.Token).Wait(); }
        catch (AggregateException) { /* expected on cancel */ }

        engine.Stop();
        Console.WriteLine("\n✅ Monitor stopped.");
        return 0;
    }

    private static int HandleStop()
    {
        var pid = MonitorEngine.GetRunningPid();
        if (pid == null)
        {
            Console.WriteLine("ℹ️  No monitor process running.");
            return 0;
        }

        try
        {
            var proc = Process.GetProcessById(pid.Value);
            proc.Kill(entireProcessTree: true);
            Console.WriteLine($"✅ Monitor process (PID {pid}) stopped.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️  Could not stop monitor (PID {pid}): {ex.Message}");
            return 1;
        }

        // Clean up PID file
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var pidPath = Path.Combine(appData, "WinSentinel", "monitor.pid");
        try { File.Delete(pidPath); } catch { }

        return 0;
    }

    private static int HandleStatus(CliOptions options)
    {
        var pid = MonitorEngine.GetRunningPid();
        if (pid == null)
        {
            Console.WriteLine("ℹ️  Monitor is not running.");
            if (options.Json)
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { running = false }));
        }
        else
        {
            Console.WriteLine($"🛡️  Monitor is running (PID {pid}).");
            if (options.Json)
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { running = true, pid }));
        }
        return 0;
    }

    private static int HandleHelp()
    {
        Console.WriteLine(@"Usage: winsentinel monitor <action>

Actions:
  start     Start the real-time security monitor (foreground)
  stop      Stop the running monitor process
  status    Check if the monitor is running

The monitor watches:
  - Security-sensitive filesystem paths (hosts, drivers, startup folders)
  - Registry keys (Defender, Firewall, UAC, Remote Desktop)
  - Shows Windows toast notifications on security-relevant changes");
        return 0;
    }
}
