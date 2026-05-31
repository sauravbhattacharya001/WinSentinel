using System.Diagnostics;

namespace WinSentinel.Cli.Monitor;

/// <summary>
/// Real-time security monitor daemon. Watches filesystem paths and polls registry
/// keys for security-relevant changes. Shows Windows toast notifications on findings.
/// No license gate — free feature.
/// </summary>
public class MonitorEngine : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<Timer> _timers = new();
    private readonly Dictionary<string, string?> _registryBaseline = new();
    private bool _running;

    public event Action<MonitorFinding>? OnFinding;
    public event Action<string>? OnLog;

    private static readonly string[] WatchedPaths =
    {
        @"C:\Windows\System32\drivers\etc",
        @"C:\Windows\System32\drivers",
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    };

    private static readonly RegistryKeyDef[] RegistryKeys =
    {
        new("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", true, "Windows Defender Real-Time Protection"),
        new("HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", "EnableFirewall", true, "Windows Firewall (Standard)"),
        new("HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile", "EnableFirewall", true, "Windows Firewall (Public)"),
        new("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", true, "UAC"),
        new("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections", false, "Remote Desktop"),
    };

    public string GetPidFilePath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        return Path.Combine(appData, "WinSentinel", "monitor.pid");
    }

    public void Start()
    {
        if (_running) return;
        _running = true;

        // Write PID file
        var pidPath = GetPidFilePath();
        Directory.CreateDirectory(Path.GetDirectoryName(pidPath)!);
        File.WriteAllText(pidPath, Environment.ProcessId.ToString());

        OnLog?.Invoke("Monitor started.");

        // Snapshot registry baseline
        SnapshotRegistry();

        // Start filesystem watchers
        StartFileWatchers();

        // Start registry polling (every 30s)
        var regTimer = new Timer(_ => PollRegistry(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        _timers.Add(regTimer);

        OnLog?.Invoke($"Watching {_watchers.Count} paths, polling {RegistryKeys.Length} registry keys.");
    }

    public void Stop()
    {
        if (!_running) return;
        _running = false;

        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();

        foreach (var t in _timers) t.Dispose();
        _timers.Clear();

        // Remove PID file
        try { File.Delete(GetPidFilePath()); } catch { }

        OnLog?.Invoke("Monitor stopped.");
    }

    public bool IsRunning => _running;

    public static int? GetRunningPid()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var pidPath = Path.Combine(appData, "WinSentinel", "monitor.pid");
        if (!File.Exists(pidPath)) return null;
        if (int.TryParse(File.ReadAllText(pidPath).Trim(), out var pid))
        {
            try { Process.GetProcessById(pid); return pid; }
            catch { File.Delete(pidPath); return null; }
        }
        return null;
    }

    private void StartFileWatchers()
    {
        var paths = WatchedPaths.ToList();
        var userStartup = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Start Menu\Programs\Startup");
        if (Directory.Exists(userStartup)) paths.Add(userStartup);

        foreach (var path in paths)
        {
            if (!Directory.Exists(path) && !File.Exists(path)) continue;
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true,
                    IncludeSubdirectories = false
                };
                watcher.Changed += (_, e) => OnFileChange(path, "changed", e.Name);
                watcher.Created += (_, e) => OnFileChange(path, "created", e.Name);
                watcher.Deleted += (_, e) => OnFileChange(path, "deleted", e.Name);
                watcher.Renamed += (_, e) => OnFileChange(path, "renamed", e.Name);
                _watchers.Add(watcher);
            }
            catch { /* path may require elevation */ }
        }
    }

    private void OnFileChange(string dir, string eventType, string? filename)
    {
        var severity = ClassifyFileChange(dir, filename);
        var finding = new MonitorFinding
        {
            Type = "filesystem",
            Severity = severity,
            Title = $"File {eventType}: {filename ?? dir}",
            Description = $"Detected {eventType} in monitored path: {Path.Combine(dir, filename ?? "")}",
            Timestamp = DateTime.UtcNow
        };
        OnFinding?.Invoke(finding);

        if (severity is "critical" or "warning")
            ShowToast(finding.Title, finding.Description, severity);
    }

    private static string ClassifyFileChange(string dir, string? filename)
    {
        var lower = (filename ?? "").ToLowerInvariant();
        if (lower == "hosts") return "critical";
        if (dir.Contains("drivers") && lower.EndsWith(".sys")) return "critical";
        if (dir.Contains("Startup")) return "warning";
        return "info";
    }

    private void SnapshotRegistry()
    {
        foreach (var key in RegistryKeys)
        {
            var val = ReadRegistryValue(key.Path, key.Value);
            _registryBaseline[$"{key.Path}\\{key.Value}"] = val;
        }
    }

    private void PollRegistry()
    {
        foreach (var key in RegistryKeys)
        {
            var fullKey = $"{key.Path}\\{key.Value}";
            var current = ReadRegistryValue(key.Path, key.Value);
            _registryBaseline.TryGetValue(fullKey, out var baseline);

            if (current != baseline)
            {
                _registryBaseline[fullKey] = current;
                var finding = new MonitorFinding
                {
                    Type = "registry",
                    Severity = key.Critical ? "critical" : "warning",
                    Title = $"Registry changed: {key.Label}",
                    Description = $"{key.Label} changed from \"{baseline}\" to \"{current}\"",
                    Timestamp = DateTime.UtcNow
                };
                OnFinding?.Invoke(finding);
                ShowToast(finding.Title, finding.Description, finding.Severity);
            }
        }
    }

    private static string? ReadRegistryValue(string keyPath, string valueName)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var psi = new ProcessStartInfo("reg", $"query \"{keyPath}\" /v \"{valueName}\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit(5000);
            var match = System.Text.RegularExpressions.Regex.Match(output, $@"{valueName}\s+REG_\w+\s+(.+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : null;
        }
        catch { return null; }
    }

    private static void ShowToast(string title, string body, string severity)
    {
        if (!OperatingSystem.IsWindows()) return;
        var icon = severity == "critical" ? "🚨" : severity == "warning" ? "⚠️" : "ℹ️";
        try
        {
            var ps = $@"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
$xml.LoadXml('<toast><visual><binding template=""ToastGeneric""><text>{icon} {title.Replace("'", "''")}</text><text>{body.Replace("'", "''")}</text></binding></visual></toast>')
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('WinSentinel').Show([Windows.UI.Notifications.ToastNotification]::new($xml))
";
            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -Command \"{ps.Replace("\"", "\\\"")}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);
        }
        catch
        {
            Console.WriteLine($"[NOTIFY] {icon} {title}: {body}");
        }
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }

    private record RegistryKeyDef(string Path, string Value, bool Critical, string Label);
}

public class MonitorFinding
{
    public string Type { get; set; } = "";
    public string Severity { get; set; } = "info";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime Timestamp { get; set; }
}
