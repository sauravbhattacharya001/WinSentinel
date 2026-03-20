using System.Text;
using System.Text.Json;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Represents a discovered installed application.
    /// </summary>
    public record InstalledApp(string Name, string Version, string Publisher, string InstallDate);

    /// <summary>
    /// Represents a Windows service entry.
    /// </summary>
    public record ServiceEntry(string Name, string DisplayName, string Status, string StartType);

    /// <summary>
    /// Represents a startup program entry.
    /// </summary>
    public record StartupEntry(string Name, string Command, string Location);

    /// <summary>
    /// Represents a listening network port.
    /// </summary>
    public record ListeningPort(int Port, string Protocol, string Process, int Pid);

    /// <summary>
    /// Represents a scheduled task.
    /// </summary>
    public record ScheduledTaskEntry(string Name, string State, string NextRun, string Author);

    /// <summary>
    /// Represents the full system inventory snapshot.
    /// </summary>
    public record SystemInventory(
        string MachineName,
        string OsVersion,
        string UserName,
        int ProcessorCount,
        long TotalMemoryMB,
        string Uptime,
        DateTimeOffset Timestamp,
        List<InstalledApp> InstalledApps,
        List<ServiceEntry> Services,
        List<StartupEntry> StartupPrograms,
        List<ListeningPort> ListeningPorts,
        List<ScheduledTaskEntry> ScheduledTasks,
        Dictionary<string, string> EnvironmentVariables
    );

    /// <summary>
    /// Print system inventory to console in a human-readable format.
    /// </summary>
    public static void PrintInventory(SystemInventory inventory)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       📋 WinSentinel System Inventory       ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // ── System Overview ──
        WriteLineColored("  SYSTEM OVERVIEW", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        WriteEntry("Machine", inventory.MachineName);
        WriteEntry("OS", inventory.OsVersion);
        WriteEntry("User", inventory.UserName);
        WriteEntry("Processors", inventory.ProcessorCount.ToString());
        WriteEntry("Memory", $"{inventory.TotalMemoryMB:N0} MB");
        WriteEntry("Uptime", inventory.Uptime);
        WriteEntry("Snapshot", inventory.Timestamp.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        Console.WriteLine();

        // ── Installed Applications ──
        WriteLineColored($"  INSTALLED APPLICATIONS ({inventory.InstalledApps.Count})", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        if (inventory.InstalledApps.Count == 0)
        {
            WriteLineColored("  (none found)", ConsoleColor.DarkGray);
        }
        else
        {
            // Table header
            var fmt = "  {0,-40} {1,-15} {2,-25} {3,-12}";
            WriteLineColored(string.Format(fmt, "Name", "Version", "Publisher", "Installed"), ConsoleColor.DarkGray);
            WriteLineColored("  " + new string('─', 95), ConsoleColor.DarkGray);
            foreach (var app in inventory.InstalledApps.OrderBy(a => a.Name))
            {
                var name = Truncate(app.Name, 38);
                var ver = Truncate(app.Version, 13);
                var pub = Truncate(app.Publisher, 23);
                var date = string.IsNullOrEmpty(app.InstallDate) ? "—" : app.InstallDate;
                Console.WriteLine(string.Format(fmt, name, ver, pub, date));
            }
        }
        Console.WriteLine();

        // ── Running Services ──
        var runningServices = inventory.Services.Where(s => s.Status == "Running").ToList();
        var stoppedAutoServices = inventory.Services
            .Where(s => s.Status != "Running" && s.StartType == "Automatic")
            .ToList();

        WriteLineColored($"  SERVICES (Running: {runningServices.Count}, Stopped-Auto: {stoppedAutoServices.Count}, Total: {inventory.Services.Count})", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);

        if (stoppedAutoServices.Count > 0)
        {
            WriteLineColored("  ⚠ Auto-start services NOT running:", ConsoleColor.Yellow);
            foreach (var svc in stoppedAutoServices.OrderBy(s => s.DisplayName))
            {
                Console.Write("    ");
                WriteColored("●", ConsoleColor.Red);
                Console.Write($" {Truncate(svc.DisplayName, 45)}");
                WriteLineColored($"  ({svc.Name})", ConsoleColor.DarkGray);
            }
            Console.WriteLine();
        }

        WriteLineColored("  Running services:", ConsoleColor.DarkGray);
        var svcFmt = "  {0,-45} {1,-30} {2,-10}";
        WriteLineColored(string.Format(svcFmt, "Display Name", "Service Name", "Start"), ConsoleColor.DarkGray);
        WriteLineColored("  " + new string('─', 87), ConsoleColor.DarkGray);
        foreach (var svc in runningServices.OrderBy(s => s.DisplayName).Take(50))
        {
            Console.Write("    ");
            WriteColored("●", ConsoleColor.Green);
            Console.WriteLine($" {Truncate(svc.DisplayName, 43)}  {Truncate(svc.Name, 28)}  {svc.StartType}");
        }
        if (runningServices.Count > 50)
            WriteLineColored($"  ... and {runningServices.Count - 50} more", ConsoleColor.DarkGray);
        Console.WriteLine();

        // ── Listening Ports ──
        WriteLineColored($"  LISTENING PORTS ({inventory.ListeningPorts.Count})", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        if (inventory.ListeningPorts.Count == 0)
        {
            WriteLineColored("  (none found)", ConsoleColor.DarkGray);
        }
        else
        {
            var portFmt = "  {0,-8} {1,-8} {2,-30} {3,-8}";
            WriteLineColored(string.Format(portFmt, "Port", "Proto", "Process", "PID"), ConsoleColor.DarkGray);
            WriteLineColored("  " + new string('─', 56), ConsoleColor.DarkGray);
            foreach (var port in inventory.ListeningPorts.OrderBy(p => p.Port))
            {
                var color = port.Port < 1024 ? ConsoleColor.Yellow : ConsoleColor.Gray;
                WriteColored(string.Format("  {0,-8}", port.Port), color);
                Console.WriteLine($" {port.Protocol,-8} {Truncate(port.Process, 28),-30} {port.Pid}");
            }
        }
        Console.WriteLine();

        // ── Startup Programs ──
        WriteLineColored($"  STARTUP PROGRAMS ({inventory.StartupPrograms.Count})", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        if (inventory.StartupPrograms.Count == 0)
        {
            WriteLineColored("  (none found)", ConsoleColor.DarkGray);
        }
        else
        {
            foreach (var entry in inventory.StartupPrograms.OrderBy(e => e.Name))
            {
                WriteColored($"  {Truncate(entry.Name, 35),-35}", ConsoleColor.White);
                WriteLineColored($"  [{entry.Location}]", ConsoleColor.DarkGray);
                WriteLineColored($"    {Truncate(entry.Command, 90)}", ConsoleColor.Gray);
            }
        }
        Console.WriteLine();

        // ── Scheduled Tasks ──
        WriteLineColored($"  SCHEDULED TASKS ({inventory.ScheduledTasks.Count})", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        if (inventory.ScheduledTasks.Count == 0)
        {
            WriteLineColored("  (none found)", ConsoleColor.DarkGray);
        }
        else
        {
            var taskFmt = "  {0,-40} {1,-10} {2,-22} {3}";
            WriteLineColored(string.Format(taskFmt, "Task Name", "State", "Next Run", "Author"), ConsoleColor.DarkGray);
            WriteLineColored("  " + new string('─', 95), ConsoleColor.DarkGray);
            foreach (var task in inventory.ScheduledTasks.OrderBy(t => t.Name).Take(50))
            {
                var stateColor = task.State == "Ready" ? ConsoleColor.Green
                    : task.State == "Disabled" ? ConsoleColor.DarkGray
                    : ConsoleColor.Yellow;
                Console.Write($"  {Truncate(task.Name, 38),-40} ");
                WriteColored($"{task.State,-10}", stateColor);
                Console.WriteLine($" {Truncate(task.NextRun, 20),-22} {Truncate(task.Author, 25)}");
            }
            if (inventory.ScheduledTasks.Count > 50)
                WriteLineColored($"  ... and {inventory.ScheduledTasks.Count - 50} more", ConsoleColor.DarkGray);
        }
        Console.WriteLine();

        // ── Security-Relevant Environment Variables ──
        var securityVars = new[] {
            "PATH", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "APPDATA",
            "PROGRAMFILES", "PROGRAMFILES(X86)", "WINDIR", "SYSTEMROOT",
            "PSModulePath", "PROCESSOR_ARCHITECTURE"
        };
        var relevantEnvVars = inventory.EnvironmentVariables
            .Where(kv => securityVars.Contains(kv.Key, StringComparer.OrdinalIgnoreCase))
            .OrderBy(kv => kv.Key)
            .ToList();

        WriteLineColored($"  ENVIRONMENT VARIABLES (security-relevant)", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        foreach (var kv in relevantEnvVars)
        {
            WriteColored($"  {kv.Key,-30}", ConsoleColor.White);
            var val = kv.Value;
            if (val.Length > 80)
                val = val[..77] + "...";
            WriteLineColored(val, ConsoleColor.Gray);
        }
        Console.WriteLine();

        // ── Summary ──
        WriteLineColored("  SUMMARY", ConsoleColor.White);
        WriteLineColored("  ──────────────────────────────────────────", ConsoleColor.DarkGray);
        Console.Write("  Installed apps:    "); WriteLineColored(inventory.InstalledApps.Count.ToString(), ConsoleColor.White);
        Console.Write("  Running services:  "); WriteLineColored(runningServices.Count.ToString(), ConsoleColor.White);
        Console.Write("  Listening ports:   "); WriteLineColored(inventory.ListeningPorts.Count.ToString(), ConsoleColor.White);
        Console.Write("  Startup programs:  "); WriteLineColored(inventory.StartupPrograms.Count.ToString(), ConsoleColor.White);
        Console.Write("  Scheduled tasks:   "); WriteLineColored(inventory.ScheduledTasks.Count.ToString(), ConsoleColor.White);

        if (stoppedAutoServices.Count > 0)
        {
            Console.Write("  ⚠ Stopped auto:   ");
            WriteLineColored(stoppedAutoServices.Count.ToString(), ConsoleColor.Yellow);
        }

        var wellKnownPorts = inventory.ListeningPorts.Where(p => p.Port < 1024).ToList();
        if (wellKnownPorts.Count > 0)
        {
            Console.Write("  ⚠ Well-known ports:");
            WriteLineColored($" {string.Join(", ", wellKnownPorts.Select(p => p.Port).Distinct().OrderBy(p => p))}", ConsoleColor.Yellow);
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Format system inventory as JSON.
    /// </summary>
    public static string FormatInventoryJson(SystemInventory inventory)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        return JsonSerializer.Serialize(inventory, jsonOptions);
    }

    /// <summary>
    /// Format system inventory as Markdown.
    /// </summary>
    public static string FormatInventoryMarkdown(SystemInventory inventory)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# WinSentinel System Inventory");
        sb.AppendLine();
        sb.AppendLine($"**Generated:** {inventory.Timestamp:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine();

        sb.AppendLine("## System Overview");
        sb.AppendLine();
        sb.AppendLine($"| Property | Value |");
        sb.AppendLine($"|----------|-------|");
        sb.AppendLine($"| Machine | {inventory.MachineName} |");
        sb.AppendLine($"| OS | {inventory.OsVersion} |");
        sb.AppendLine($"| User | {inventory.UserName} |");
        sb.AppendLine($"| Processors | {inventory.ProcessorCount} |");
        sb.AppendLine($"| Memory | {inventory.TotalMemoryMB:N0} MB |");
        sb.AppendLine($"| Uptime | {inventory.Uptime} |");
        sb.AppendLine();

        sb.AppendLine($"## Installed Applications ({inventory.InstalledApps.Count})");
        sb.AppendLine();
        sb.AppendLine("| Name | Version | Publisher | Installed |");
        sb.AppendLine("|------|---------|-----------|-----------|");
        foreach (var app in inventory.InstalledApps.OrderBy(a => a.Name))
        {
            sb.AppendLine($"| {EscapeMdCell(app.Name)} | {EscapeMdCell(app.Version)} | {EscapeMdCell(app.Publisher)} | {app.InstallDate} |");
        }
        sb.AppendLine();

        sb.AppendLine($"## Listening Ports ({inventory.ListeningPorts.Count})");
        sb.AppendLine();
        sb.AppendLine("| Port | Protocol | Process | PID |");
        sb.AppendLine("|------|----------|---------|-----|");
        foreach (var port in inventory.ListeningPorts.OrderBy(p => p.Port))
        {
            sb.AppendLine($"| {port.Port} | {port.Protocol} | {EscapeMdCell(port.Process)} | {port.Pid} |");
        }
        sb.AppendLine();

        sb.AppendLine($"## Startup Programs ({inventory.StartupPrograms.Count})");
        sb.AppendLine();
        foreach (var entry in inventory.StartupPrograms.OrderBy(e => e.Name))
        {
            sb.AppendLine($"- **{EscapeMdCell(entry.Name)}** ({entry.Location}): `{entry.Command}`");
        }
        sb.AppendLine();

        sb.AppendLine($"## Scheduled Tasks ({inventory.ScheduledTasks.Count})");
        sb.AppendLine();
        sb.AppendLine("| Task | State | Next Run | Author |");
        sb.AppendLine("|------|-------|----------|--------|");
        foreach (var task in inventory.ScheduledTasks.OrderBy(t => t.Name))
        {
            sb.AppendLine($"| {EscapeMdCell(task.Name)} | {task.State} | {task.NextRun} | {EscapeMdCell(task.Author)} |");
        }
        sb.AppendLine();

        // Summary
        var stoppedAuto = inventory.Services.Count(s => s.Status != "Running" && s.StartType == "Automatic");
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- **Installed apps:** {inventory.InstalledApps.Count}");
        sb.AppendLine($"- **Running services:** {inventory.Services.Count(s => s.Status == "Running")}");
        sb.AppendLine($"- **Listening ports:** {inventory.ListeningPorts.Count}");
        sb.AppendLine($"- **Startup programs:** {inventory.StartupPrograms.Count}");
        sb.AppendLine($"- **Scheduled tasks:** {inventory.ScheduledTasks.Count}");
        if (stoppedAuto > 0)
            sb.AppendLine($"- ⚠ **Stopped auto-start services:** {stoppedAuto}");

        return sb.ToString();
    }

    private static void WriteEntry(string label, string value)
    {
        Console.Write($"  {label + ":",-14}");
        WriteLineColored(value, ConsoleColor.White);
    }

    private static string EscapeMdCell(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "—";
        return s.Replace("|", "\\|").Replace("<", "&lt;").Replace(">", "&gt;");
    }
}
