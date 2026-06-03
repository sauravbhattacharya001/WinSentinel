using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace WinSentinel.Cli;

/// <summary>
/// Handles 'winsentinel agent start|stop|status|install|uninstall' subcommands.
/// The agent runs as either a background process or a Windows Service.
/// This is FREE functionality — no license required for standalone mode.
/// Fleet registration (phoning home to a central node) requires a Pro license.
/// </summary>
public static class AgentCommandHandler
{
    private const string ServiceName = "WinSentinel Agent";
    private const string AgentExeName = "WinSentinel.Agent.exe";
    private static readonly string AgentDataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSentinel");
    private static readonly string PidFile = Path.Combine(AgentDataDir, "agent.pid");

    public static async Task<int> HandleAsync(CliOptions options)
    {
        return options.AgentAction switch
        {
            AgentAction.Start => await StartAgent(options),
            AgentAction.Stop => await StopAgent(),
            AgentAction.Status => await ShowStatus(),
            AgentAction.Install => InstallService(),
            AgentAction.Uninstall => UninstallService(),
            _ => ShowHelp()
        };
    }

    private static async Task<int> StartAgent(CliOptions options)
    {
        // Check if already running
        var (running, pid) = IsAgentRunning();
        if (running)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  WinSentinel Agent is already running (PID {pid})");
            Console.ResetColor();
            return 0;
        }

        // Find the agent executable
        var agentPath = FindAgentExecutable();
        if (agentPath == null)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  Error: Could not locate WinSentinel.Agent.exe");
            Console.WriteLine("  Ensure the Agent is installed alongside the CLI.");
            Console.ResetColor();
            return 1;
        }

        // Build args for the agent process
        var agentArgs = new List<string>();
        if (options.FleetEndpoint != null)
        {
            agentArgs.Add($"--fleet-endpoint={options.FleetEndpoint}");
        }
        if (options.TransientLicenseKey != null)
        {
            agentArgs.Add($"--license={options.TransientLicenseKey}");
        }

        // Launch as background process
        Directory.CreateDirectory(AgentDataDir);
        var startInfo = new ProcessStartInfo
        {
            FileName = agentPath,
            Arguments = string.Join(' ', agentArgs),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
            WorkingDirectory = AgentDataDir
        };

        try
        {
            var process = Process.Start(startInfo);
            if (process == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  Error: Failed to start agent process");
                Console.ResetColor();
                return 1;
            }

            // Write PID file
            await File.WriteAllTextAsync(PidFile, process.Id.ToString());

            // Wait briefly to ensure it doesn't immediately crash
            await Task.Delay(1500);
            if (process.HasExited)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  Error: Agent exited immediately with code {process.ExitCode}");
                Console.WriteLine($"  Check logs at: {Path.Combine(AgentDataDir, "logs")}");
                Console.ResetColor();
                File.Delete(PidFile);
                return 1;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ WinSentinel Agent started (PID {process.Id})");
            Console.ResetColor();
            Console.WriteLine($"    Logs: {Path.Combine(AgentDataDir, "logs")}");
            Console.WriteLine($"    Config: {Path.Combine(AgentDataDir, "agent-config.json")}");

            if (options.FleetEndpoint != null)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"    Fleet endpoint: {options.FleetEndpoint}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("    Running in standalone mode (no fleet registration)");
                Console.ResetColor();
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Error starting agent: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static async Task<int> StopAgent()
    {
        var (running, pid) = IsAgentRunning();
        if (!running)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  WinSentinel Agent is not running");
            Console.ResetColor();
            return 0;
        }

        try
        {
            var process = Process.GetProcessById(pid);
            // Send graceful shutdown signal via named pipe or just kill
            // The Agent handles SIGTERM/Ctrl+C via the .NET host
            process.Kill(entireProcessTree: true);

            // Wait for exit (up to 10s)
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  Warning: Agent did not exit gracefully, force-killed");
                Console.ResetColor();
            }

            // Clean up PID file
            if (File.Exists(PidFile))
                File.Delete(PidFile);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ WinSentinel Agent stopped (was PID {pid})");
            Console.ResetColor();
            return 0;
        }
        catch (ArgumentException)
        {
            // Process already gone
            if (File.Exists(PidFile))
                File.Delete(PidFile);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  Agent process not found (stale PID file cleaned up)");
            Console.ResetColor();
            return 0;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Error stopping agent: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static Task<int> ShowStatus()
    {
        var (running, pid) = IsAgentRunning();

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  WinSentinel Agent");
        Console.ResetColor();
        Console.WriteLine("  ─────────────────");

        if (running)
        {
            try
            {
                var process = Process.GetProcessById(pid);
                var uptime = DateTime.Now - process.StartTime;

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("  Status: ");
                Console.WriteLine("● Running");
                Console.ResetColor();
                Console.WriteLine($"  PID:    {pid}");
                Console.WriteLine($"  Uptime: {FormatUptime(uptime)}");
                Console.WriteLine($"  Memory: {process.WorkingSet64 / 1024 / 1024} MB");
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("  Status: ");
                Console.WriteLine("○ Unknown (stale PID)");
                Console.ResetColor();
                if (File.Exists(PidFile))
                    File.Delete(PidFile);
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  Status: ");
            Console.WriteLine("○ Stopped");
            Console.ResetColor();
        }

        // Check config
        var configPath = Path.Combine(AgentDataDir, "agent-config.json");
        if (File.Exists(configPath))
        {
            Console.WriteLine($"  Config: {configPath}");
        }

        // Check logs
        var logDir = Path.Combine(AgentDataDir, "logs");
        if (Directory.Exists(logDir))
        {
            var latestLog = Directory.GetFiles(logDir, "agent-*.log")
                .OrderByDescending(f => f)
                .FirstOrDefault();
            if (latestLog != null)
            {
                var logInfo = new FileInfo(latestLog);
                Console.WriteLine($"  Log:    {logInfo.Name} ({logInfo.Length / 1024} KB)");
            }
        }

        Console.WriteLine();

        // Service status
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                using var sc = new ServiceController(ServiceName);
                Console.WriteLine($"  Service: {sc.Status}");
            }
            catch (InvalidOperationException)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  Service: Not installed (use 'winsentinel agent install' for Windows Service mode)");
                Console.ResetColor();
            }
        }

        Console.WriteLine();
        return Task.FromResult(0);
    }

    private static int InstallService()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  Windows Service mode is only available on Windows");
            Console.ResetColor();
            return 1;
        }

        var agentPath = FindAgentExecutable();
        if (agentPath == null)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  Error: Could not locate WinSentinel.Agent.exe");
            Console.ResetColor();
            return 1;
        }

        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = $"create \"{ServiceName}\" binPath=\"{agentPath}\" start=delayed-auto",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        try
        {
            var proc = Process.Start(psi)!;
            proc.WaitForExit(15000);
            if (proc.ExitCode == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ Service '{ServiceName}' installed (delayed auto-start)");
                Console.ResetColor();
                Console.WriteLine("  Start with: sc start \"WinSentinel Agent\"");
                return 0;
            }
            else
            {
                var err = proc.StandardError.ReadToEnd();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  Error: sc.exe returned {proc.ExitCode}");
                if (!string.IsNullOrEmpty(err)) Console.WriteLine($"  {err.Trim()}");
                Console.ResetColor();
                Console.WriteLine("  Tip: Run as Administrator to install the service.");
                return 1;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Error: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static int UninstallService()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = $"delete \"{ServiceName}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        try
        {
            var proc = Process.Start(psi)!;
            proc.WaitForExit(15000);
            if (proc.ExitCode == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ Service '{ServiceName}' removed");
                Console.ResetColor();
                return 0;
            }
            else
            {
                var err = proc.StandardError.ReadToEnd();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  Error: sc.exe returned {proc.ExitCode}");
                if (!string.IsNullOrEmpty(err)) Console.WriteLine($"  {err.Trim()}");
                Console.ResetColor();
                return 1;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Error: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static int ShowHelp()
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  WinSentinel Agent — continuous security monitoring daemon");
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine("  Usage: winsentinel agent <command> [options]");
        Console.WriteLine();
        Console.WriteLine("  Commands:");
        Console.WriteLine("    start      Start the agent in the background");
        Console.WriteLine("    stop       Stop the running agent");
        Console.WriteLine("    status     Show agent status and health");
        Console.WriteLine("    install    Install as a Windows Service (requires admin)");
        Console.WriteLine("    uninstall  Remove the Windows Service (requires admin)");
        Console.WriteLine();
        Console.WriteLine("  Options:");
        Console.WriteLine("    --fleet-endpoint <url>  Register with a fleet control plane (Pro)");
        Console.WriteLine("    --license <key>         License key for fleet features");
        Console.WriteLine();
        Console.WriteLine("  The agent runs locally for free — real-time threat monitoring,");
        Console.WriteLine("  scheduled audits, and auto-remediation on your machine.");
        Console.WriteLine();
        Console.WriteLine("  With a Pro license and --fleet-endpoint, the agent also reports");
        Console.WriteLine("  to your organization's central control plane for fleet management.");
        Console.WriteLine();
        return 0;
    }

    private static (bool running, int pid) IsAgentRunning()
    {
        if (!File.Exists(PidFile))
            return (false, 0);

        if (!int.TryParse(File.ReadAllText(PidFile).Trim(), out var pid))
        {
            File.Delete(PidFile);
            return (false, 0);
        }

        try
        {
            var process = Process.GetProcessById(pid);
            // Verify it's actually our agent (not a recycled PID)
            if (process.ProcessName.Contains("WinSentinel", StringComparison.OrdinalIgnoreCase))
                return (true, pid);
            // Stale PID recycled by another process
            File.Delete(PidFile);
            return (false, 0);
        }
        catch (ArgumentException)
        {
            File.Delete(PidFile);
            return (false, 0);
        }
    }

    private static string? FindAgentExecutable()
    {
        // 1. Same directory as the CLI
        var cliDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(cliDir, AgentExeName);
        if (File.Exists(candidate)) return candidate;

        // 2. Sibling directory (common in dev layouts)
        var parentDir = Path.GetDirectoryName(cliDir);
        if (parentDir != null)
        {
            candidate = Path.Combine(parentDir, "WinSentinel.Agent", AgentExeName);
            if (File.Exists(candidate)) return candidate;
        }

        // 3. On PATH
        var pathDirs = Environment.GetEnvironmentVariable("PATH")?.Split(Path.PathSeparator) ?? [];
        foreach (var dir in pathDirs)
        {
            candidate = Path.Combine(dir, AgentExeName);
            if (File.Exists(candidate)) return candidate;
        }

        // 4. Program Files
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        candidate = Path.Combine(programFiles, "WinSentinel", AgentExeName);
        if (File.Exists(candidate)) return candidate;

        return null;
    }

    private static string FormatUptime(TimeSpan ts)
    {
        if (ts.TotalDays >= 1) return $"{(int)ts.TotalDays}d {ts.Hours}h {ts.Minutes}m";
        if (ts.TotalHours >= 1) return $"{ts.Hours}h {ts.Minutes}m";
        return $"{ts.Minutes}m {ts.Seconds}s";
    }
}
