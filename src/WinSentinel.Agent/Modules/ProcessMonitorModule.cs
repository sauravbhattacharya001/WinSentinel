using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Modules;

/// <summary>
/// Real-time process monitoring module using WMI event subscriptions.
/// Detects suspicious process creation, LOLBins, macro attacks, unsigned executables,
/// and privilege escalation — all in real-time.
/// </summary>
public class ProcessMonitorModule : IAgentModule
{
    public string Name => "ProcessMonitor";
    public bool IsActive { get; private set; }

    private readonly ILogger<ProcessMonitorModule> _logger;
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;
    private CancellationTokenSource? _cts;

    // ── Performance: caches & rate limiting ──

    /// <summary>Cache of Authenticode signature results (path → isSigned). Cleared periodically.</summary>
    private readonly ConcurrentDictionary<string, bool> _signatureCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Recent alert keys with last-alert timestamp for rate limiting.</summary>
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentAlerts = new();

    /// <summary>Debounce: track rapid process creation counts per image name.</summary>
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> _processBurst = new();

    /// <summary>Known-safe system processes that we skip entirely.</summary>
    private static readonly HashSet<string> SafeProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "conhost.exe",
        "RuntimeBroker.exe", "SearchHost.exe", "ShellExperienceHost.exe",
        "StartMenuExperienceHost.exe", "TextInputHost.exe", "ctfmon.exe",
        "dllhost.exe", "sihost.exe", "taskhostw.exe", "WmiPrvSE.exe",
        "System", "Idle", "Registry", "Memory Compression", "spoolsv.exe",
        "SecurityHealthService.exe", "MsMpEng.exe", "NisSrv.exe",
        "WinSentinel.Agent.exe", "WinSentinel.App.exe"
    };

    /// <summary>Suspicious paths — processes launched from here are suspicious (user-specific).</summary>
    private static readonly string[] SuspiciousPaths;

    /// <summary>Suspicious path patterns — generic patterns that work for any user.</summary>
    private static readonly string[] SuspiciousPathPatterns = new[]
    {
        @"\AppData\Local\Temp\",
        @"\AppData\Roaming\",
        @"\Downloads\",
        @"\Desktop\",
        @"\Temp\",
    };

    /// <summary>LOLBins — legitimate Windows tools frequently abused by attackers.</summary>
    private static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe",
        "msiexec.exe", "regsvr32.exe", "rundll32.exe", "installutil.exe",
        "msbuild.exe", "cmstp.exe", "wmic.exe", "forfiles.exe", "pcalua.exe",
        "presentationhost.exe", "xwizard.exe", "ieexec.exe", "hh.exe"
    };

    /// <summary>Parent processes of Office / PDF readers (macro attack detection).</summary>
    private static readonly HashSet<string> OfficeProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "mspub.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe",
        "foxitphantompdf.exe", "sumatrapdf.exe"
    };

    /// <summary>Child processes that are suspicious when spawned by Office/PDF apps.</summary>
    private static readonly HashSet<string> SuspiciousChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "certutil.exe", "bitsadmin.exe", "net.exe", "net1.exe",
        "reg.exe", "schtasks.exe", "taskkill.exe"
    };

    /// <summary>Rate-limit: minimum seconds between identical alerts.</summary>
    private const int RateLimitSeconds = 30;

    /// <summary>Burst threshold: if same image starts > N times in window, suppress individual alerts.</summary>
    private const int BurstThreshold = 10;

    /// <summary>Burst window in seconds.</summary>
    private const int BurstWindowSeconds = 5;

    /// <summary>How often to purge caches (minutes).</summary>
    private const int CachePurgeIntervalMinutes = 30;

    static ProcessMonitorModule()
    {
        var temp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Temp";
        var userTemp = Path.GetTempPath();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

        SuspiciousPaths = new[]
        {
            temp,
            userTemp,
            appData,
            localAppData + "\\Temp",
            downloads,
            desktop,
            @"C:\$Recycle.Bin",
            @"C:\Windows\Temp",
            @"C:\ProgramData"   // unusual for user-started processes
        };
    }

    public ProcessMonitorModule(
        ILogger<ProcessMonitorModule> logger,
        ThreatLog threatLog,
        AgentConfig config)
    {
        _logger = logger;
        _threatLog = threatLog;
        _config = config;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("ProcessMonitor starting — setting up WMI event watchers...");
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        try
        {
            // Watch for new process creation
            // Using Win32_ProcessStartTrace (requires admin/elevated) — most reliable.
            // Fallback: __InstanceCreationEvent on Win32_Process with a polling interval.
            _startWatcher = CreateProcessStartWatcher();
            _startWatcher.EventArrived += OnProcessStarted;
            _startWatcher.Start();
            _logger.LogInformation("Process start watcher active");
        }
        catch (ManagementException ex) when (ex.ErrorCode == ManagementStatus.AccessDenied)
        {
            _logger.LogWarning("Win32_ProcessStartTrace requires elevation, falling back to WQL polling watcher");
            _startWatcher?.Dispose();
            _startWatcher = CreateProcessStartWatcherFallback();
            _startWatcher.EventArrived += OnProcessStartedFallback;
            _startWatcher.Start();
            _logger.LogInformation("Process start watcher active (fallback mode, 2s polling)");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start process start watcher");
        }

        try
        {
            _stopWatcher = CreateProcessStopWatcher();
            _stopWatcher.EventArrived += OnProcessStopped;
            _stopWatcher.Start();
            _logger.LogInformation("Process stop watcher active");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Process stop watcher not available (not critical)");
        }

        // Background cache cleanup
        _ = Task.Run(() => CacheCleanupLoopAsync(_cts.Token), _cts.Token);

        IsActive = true;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("ProcessMonitor stopping...");
        IsActive = false;
        _cts?.Cancel();

        try
        {
            if (_startWatcher != null)
            {
                _startWatcher.Stop();
                _startWatcher.Dispose();
                _startWatcher = null;
            }
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Error stopping start watcher"); }

        try
        {
            if (_stopWatcher != null)
            {
                _stopWatcher.Stop();
                _stopWatcher.Dispose();
                _stopWatcher = null;
            }
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Error stopping stop watcher"); }

        _signatureCache.Clear();
        _recentAlerts.Clear();
        _processBurst.Clear();

        return Task.CompletedTask;
    }

    // ── WMI Watcher Creation ──

    private static ManagementEventWatcher CreateProcessStartWatcher()
    {
        // Win32_ProcessStartTrace — real-time ETW-based, requires elevation
        var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
        return new ManagementEventWatcher(query);
    }

    private static ManagementEventWatcher CreateProcessStartWatcherFallback()
    {
        // Polling-based fallback (works without admin, but has ~2s latency)
        var query = new WqlEventQuery(
            "__InstanceCreationEvent",
            TimeSpan.FromSeconds(2),
            "TargetInstance ISA 'Win32_Process'");
        return new ManagementEventWatcher(query);
    }

    private static ManagementEventWatcher CreateProcessStopWatcher()
    {
        var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace");
        return new ManagementEventWatcher(query);
    }

    // ── Event Handlers ──

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var processName = e.NewEvent["ProcessName"]?.ToString() ?? "";
            var processId = Convert.ToInt32(e.NewEvent["ProcessID"] ?? 0);
            var parentId = Convert.ToInt32(e.NewEvent["ParentProcessID"] ?? 0);

            // Skip known-safe system processes
            if (SafeProcesses.Contains(processName))
                return;

            // Debounce rapid creation
            if (IsBurst(processName))
                return;

            // Get the full executable path from the running process
            string? executablePath = null;
            string? commandLine = null;
            string? parentName = null;
            string? owner = null;

            try
            {
                using var proc = Process.GetProcessById(processId);
                executablePath = proc.MainModule?.FileName;
            }
            catch { /* process may have already exited */ }

            // Query WMI for additional details
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    executablePath ??= obj["ExecutablePath"]?.ToString();
                    commandLine = obj["CommandLine"]?.ToString();
                }
            }
            catch { }

            // Get parent process name
            parentName = GetProcessName(parentId);

            // Get process owner
            owner = GetProcessOwner(processId);

            AnalyzeProcess(new ProcessInfo
            {
                ProcessId = processId,
                ParentProcessId = parentId,
                ProcessName = processName,
                ExecutablePath = executablePath ?? "",
                CommandLine = commandLine ?? "",
                ParentName = parentName ?? "",
                Owner = owner ?? ""
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error processing WMI start event");
        }
    }

    private void OnProcessStartedFallback(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var processName = Path.GetFileName(targetInstance["Name"]?.ToString() ?? "");
            var processId = Convert.ToInt32(targetInstance["ProcessId"] ?? 0);
            var parentId = Convert.ToInt32(targetInstance["ParentProcessId"] ?? 0);
            var executablePath = targetInstance["ExecutablePath"]?.ToString() ?? "";
            var commandLine = targetInstance["CommandLine"]?.ToString() ?? "";

            if (SafeProcesses.Contains(processName))
                return;

            if (IsBurst(processName))
                return;

            var parentName = GetProcessName(parentId);
            var owner = GetProcessOwner(processId);

            AnalyzeProcess(new ProcessInfo
            {
                ProcessId = processId,
                ParentProcessId = parentId,
                ProcessName = processName,
                ExecutablePath = executablePath,
                CommandLine = commandLine,
                ParentName = parentName ?? "",
                Owner = owner ?? ""
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error processing WMI fallback start event");
        }
    }

    private void OnProcessStopped(object sender, EventArrivedEventArgs e)
    {
        // Currently we just log termination for tracking; no threat analysis needed
        try
        {
            var processName = e.NewEvent["ProcessName"]?.ToString() ?? "";
            var processId = Convert.ToInt32(e.NewEvent["ProcessID"] ?? 0);
            _logger.LogTrace("Process stopped: {Name} (PID {Pid})", processName, processId);
        }
        catch { }
    }

    // ── Threat Analysis Engine ──

    /// <summary>
    /// Run all threat detection rules against a newly-started process.
    /// </summary>
    internal void AnalyzeProcess(ProcessInfo proc)
    {
        var threats = new List<ThreatEvent>();

        // Rule 1: Suspicious launch path
        CheckSuspiciousPath(proc, threats);

        // Rule 2: LOLBins
        CheckLolBins(proc, threats);

        // Rule 3: Encoded PowerShell commands
        CheckEncodedPowerShell(proc, threats);

        // Rule 4: Child process anomalies (macro attacks)
        CheckChildProcessAnomalies(proc, threats);

        // Rule 5: Privilege escalation — new process running as SYSTEM
        CheckPrivilegeEscalation(proc, threats);

        // Rule 6: Unsigned executable
        CheckUnsignedExecutable(proc, threats);

        // Emit threats
        foreach (var threat in threats)
        {
            if (!ShouldRateLimit(threat))
            {
                _threatLog.Add(threat);
                _logger.LogWarning(
                    "[{Severity}] {Title}: {Desc} (PID {Pid})",
                    threat.Severity, threat.Title, threat.Description, proc.ProcessId);

                HandleResponse(threat, proc);
            }
        }
    }

    // ── Detection Rules ──

    private static void CheckSuspiciousPath(ProcessInfo proc, List<ThreatEvent> threats)
    {
        if (string.IsNullOrEmpty(proc.ExecutablePath))
            return;

        // Check Recycle Bin first (always critical, no false-positive concern)
        if (proc.ExecutablePath.Contains(@"$Recycle.Bin", StringComparison.OrdinalIgnoreCase))
        {
            threats.Add(new ThreatEvent
            {
                Source = "ProcessMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Suspicious Launch Path",
                Description = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) launched from Recycle Bin: {proc.ExecutablePath}",
                AutoFixable = true,
                FixCommand = $"taskkill /F /PID {proc.ProcessId}"
            });
            return;
        }

        // Check absolute suspicious paths (current user's environment)
        foreach (var suspPath in SuspiciousPaths)
        {
            if (proc.ExecutablePath.StartsWith(suspPath, StringComparison.OrdinalIgnoreCase))
            {
                if (suspPath.Contains("AppData", StringComparison.OrdinalIgnoreCase) &&
                    IsKnownAppDataApp(proc.ExecutablePath))
                    return;

                threats.Add(new ThreatEvent
                {
                    Source = "ProcessMonitor",
                    Severity = ThreatSeverity.Medium,
                    Title = "Suspicious Launch Path",
                    Description = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) launched from suspicious location: {proc.ExecutablePath}",
                    AutoFixable = true,
                    FixCommand = $"taskkill /F /PID {proc.ProcessId}"
                });
                return;
            }
        }

        // Check generic path patterns (works for any user profile)
        foreach (var pattern in SuspiciousPathPatterns)
        {
            if (proc.ExecutablePath.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                if (pattern.Contains("AppData", StringComparison.OrdinalIgnoreCase) &&
                    IsKnownAppDataApp(proc.ExecutablePath))
                    return;

                threats.Add(new ThreatEvent
                {
                    Source = "ProcessMonitor",
                    Severity = ThreatSeverity.Medium,
                    Title = "Suspicious Launch Path",
                    Description = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) launched from suspicious location: {proc.ExecutablePath}",
                    AutoFixable = true,
                    FixCommand = $"taskkill /F /PID {proc.ProcessId}"
                });
                return;
            }
        }
    }

    private static void CheckLolBins(ProcessInfo proc, List<ThreatEvent> threats)
    {
        if (!LolBins.Contains(proc.ProcessName))
            return;

        // Some LOLBins are fine if used by system processes — be contextual
        var severity = proc.ProcessName.ToLowerInvariant() switch
        {
            "mshta.exe" => ThreatSeverity.High,
            "certutil.exe" when proc.CommandLine.Contains("-urlcache", StringComparison.OrdinalIgnoreCase) => ThreatSeverity.Critical,
            "certutil.exe" when proc.CommandLine.Contains("-decode", StringComparison.OrdinalIgnoreCase) => ThreatSeverity.High,
            "bitsadmin.exe" when proc.CommandLine.Contains("/transfer", StringComparison.OrdinalIgnoreCase) => ThreatSeverity.High,
            "regsvr32.exe" when proc.CommandLine.Contains("/s /u /i:", StringComparison.OrdinalIgnoreCase) => ThreatSeverity.Critical,
            "rundll32.exe" when proc.CommandLine.Contains("javascript:", StringComparison.OrdinalIgnoreCase) => ThreatSeverity.Critical,
            "wscript.exe" or "cscript.exe" => ThreatSeverity.Medium,
            _ => ThreatSeverity.Low
        };

        threats.Add(new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = severity,
            Title = "LOLBin Execution Detected",
            Description = $"Living-Off-the-Land Binary '{proc.ProcessName}' (PID {proc.ProcessId}) started. " +
                          $"Command: {TruncateCommandLine(proc.CommandLine)}. Parent: {proc.ParentName}.",
            AutoFixable = severity >= ThreatSeverity.High,
            FixCommand = severity >= ThreatSeverity.High ? $"taskkill /F /PID {proc.ProcessId}" : null
        });
    }

    private static void CheckEncodedPowerShell(ProcessInfo proc, List<ThreatEvent> threats)
    {
        var name = proc.ProcessName.ToLowerInvariant();
        if (name != "powershell.exe" && name != "pwsh.exe")
            return;

        var cmdLower = proc.CommandLine.ToLowerInvariant();

        // Check for encoded commands
        if (cmdLower.Contains("-enc") || cmdLower.Contains("-encodedcommand") ||
            cmdLower.Contains("-e ") || cmdLower.Contains("-ec "))
        {
            threats.Add(new ThreatEvent
            {
                Source = "ProcessMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Encoded PowerShell Command",
                Description = $"PowerShell (PID {proc.ProcessId}) launched with encoded command — common malware technique. " +
                              $"Command: {TruncateCommandLine(proc.CommandLine)}. Parent: {proc.ParentName}.",
                AutoFixable = true,
                FixCommand = $"taskkill /F /PID {proc.ProcessId}"
            });
            return;
        }

        // Check for other suspicious PowerShell flags
        if ((cmdLower.Contains("-noprofile") && cmdLower.Contains("-windowstyle hidden")) ||
            cmdLower.Contains("downloadstring") || cmdLower.Contains("downloadfile") ||
            cmdLower.Contains("invoke-expression") || cmdLower.Contains("iex ") ||
            (cmdLower.Contains("bypass") && cmdLower.Contains("executionpolicy")))
        {
            threats.Add(new ThreatEvent
            {
                Source = "ProcessMonitor",
                Severity = ThreatSeverity.High,
                Title = "Suspicious PowerShell Execution",
                Description = $"PowerShell (PID {proc.ProcessId}) launched with suspicious arguments. " +
                              $"Command: {TruncateCommandLine(proc.CommandLine)}. Parent: {proc.ParentName}.",
                AutoFixable = true,
                FixCommand = $"taskkill /F /PID {proc.ProcessId}"
            });
        }
    }

    private static void CheckChildProcessAnomalies(ProcessInfo proc, List<ThreatEvent> threats)
    {
        // Macro attack pattern: Office/PDF app spawning cmd/powershell
        if (string.IsNullOrEmpty(proc.ParentName))
            return;

        if (OfficeProcesses.Contains(proc.ParentName) && SuspiciousChildren.Contains(proc.ProcessName))
        {
            threats.Add(new ThreatEvent
            {
                Source = "ProcessMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Potential Macro Attack",
                Description = $"'{proc.ParentName}' spawned '{proc.ProcessName}' (PID {proc.ProcessId}) — " +
                              $"this is a classic macro/document exploit pattern. " +
                              $"Command: {TruncateCommandLine(proc.CommandLine)}",
                AutoFixable = true,
                FixCommand = $"taskkill /F /PID {proc.ProcessId}"
            });
        }
    }

    private static void CheckPrivilegeEscalation(ProcessInfo proc, List<ThreatEvent> threats)
    {
        if (string.IsNullOrEmpty(proc.Owner))
            return;

        if (proc.Owner.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
            !IsExpectedSystemProcess(proc.ProcessName))
        {
            threats.Add(new ThreatEvent
            {
                Source = "ProcessMonitor",
                Severity = ThreatSeverity.High,
                Title = "Unexpected SYSTEM Process",
                Description = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) running as SYSTEM — " +
                              $"this may indicate privilege escalation. Path: {proc.ExecutablePath}",
                AutoFixable = false
            });
        }
    }

    private void CheckUnsignedExecutable(ProcessInfo proc, List<ThreatEvent> threats)
    {
        if (string.IsNullOrEmpty(proc.ExecutablePath) || !File.Exists(proc.ExecutablePath))
            return;

        // Skip if in Windows directory (all signed by Microsoft)
        if (proc.ExecutablePath.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase))
            return;

        // Skip known-safe AppData apps
        if (IsKnownAppDataApp(proc.ExecutablePath))
            return;

        // Check signature cache first
        if (_signatureCache.TryGetValue(proc.ExecutablePath, out var isSigned))
        {
            if (isSigned) return; // Already verified as signed
        }
        else
        {
            // Verify Authenticode signature
            isSigned = VerifyAuthenticodeSignature(proc.ExecutablePath);
            _signatureCache.TryAdd(proc.ExecutablePath, isSigned);
        }

        if (!isSigned)
        {
            threats.Add(new ThreatEvent
            {
                Source = "ProcessMonitor",
                Severity = ThreatSeverity.Low,
                Title = "Unsigned Executable",
                Description = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) is not digitally signed. " +
                              $"Path: {proc.ExecutablePath}",
                AutoFixable = false
            });
        }
    }

    // ── Response Actions ──

    private void HandleResponse(ThreatEvent threat, ProcessInfo proc)
    {
        switch (_config.RiskTolerance)
        {
            case RiskTolerance.Low:
                // Aggressive: auto-kill critical threats
                if (threat.Severity >= ThreatSeverity.Critical && threat.AutoFixable)
                {
                    try
                    {
                        using var process = Process.GetProcessById(proc.ProcessId);
                        process.Kill(entireProcessTree: true);
                        threat.ResponseTaken = $"Auto-killed process PID {proc.ProcessId}";
                        _logger.LogWarning("Auto-killed suspicious process: {Name} (PID {Pid})",
                            proc.ProcessName, proc.ProcessId);
                    }
                    catch (Exception ex)
                    {
                        threat.ResponseTaken = $"Kill failed: {ex.Message}";
                        _logger.LogWarning(ex, "Failed to kill suspicious process PID {Pid}", proc.ProcessId);
                    }
                }
                else
                {
                    threat.ResponseTaken = "Alert sent to UI";
                }
                break;

            case RiskTolerance.Medium:
                // Balanced: alert on everything, suggest fixes
                threat.ResponseTaken = threat.AutoFixable
                    ? "Alert sent — fix available"
                    : "Alert sent — manual review recommended";
                break;

            case RiskTolerance.High:
                // Relaxed: log only, no action
                threat.ResponseTaken = "Logged only (high risk tolerance)";
                break;
        }
    }

    // ── Helpers ──

    private static string? GetProcessName(int pid)
    {
        try
        {
            if (pid <= 0) return null;
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName + ".exe";
        }
        catch { return null; }
    }

    private static string? GetProcessOwner(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                var outParams = obj.InvokeMethod("GetOwner", null, null);
                if (outParams != null)
                {
                    var domain = outParams["Domain"]?.ToString() ?? "";
                    var user = outParams["User"]?.ToString() ?? "";
                    return string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
                }
            }
        }
        catch { }
        return null;
    }

    private static bool VerifyAuthenticodeSignature(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return cert != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Rate-limit: returns true if this alert was already sent recently.</summary>
    private bool ShouldRateLimit(ThreatEvent threat)
    {
        // Key = Source + Title + first 50 chars of description
        var key = $"{threat.Source}|{threat.Title}|{threat.Description?[..Math.Min(threat.Description.Length, 50)]}";

        if (_recentAlerts.TryGetValue(key, out var lastAlert))
        {
            if ((DateTimeOffset.UtcNow - lastAlert).TotalSeconds < RateLimitSeconds)
                return true;
        }

        _recentAlerts[key] = DateTimeOffset.UtcNow;
        return false;
    }

    /// <summary>Debounce rapid process creation. Returns true if we should suppress.</summary>
    private bool IsBurst(string processName)
    {
        var now = DateTimeOffset.UtcNow;

        _processBurst.AddOrUpdate(
            processName,
            _ => (1, now),
            (_, existing) =>
            {
                if ((now - existing.WindowStart).TotalSeconds > BurstWindowSeconds)
                    return (1, now); // Reset window
                return (existing.Count + 1, existing.WindowStart);
            });

        if (_processBurst.TryGetValue(processName, out var info) && info.Count > BurstThreshold)
        {
            // Log once per burst
            if (info.Count == BurstThreshold + 1)
            {
                _logger.LogInformation(
                    "Process burst detected: {Name} started {Count} times in {Secs}s — suppressing individual alerts",
                    processName, info.Count, BurstWindowSeconds);
            }
            return true;
        }

        return false;
    }

    /// <summary>Known legitimate apps that live in AppData.</summary>
    private static bool IsKnownAppDataApp(string path)
    {
        var pathLower = path.ToLowerInvariant();
        return pathLower.Contains(@"\discord\") ||
               pathLower.Contains(@"\slack\") ||
               pathLower.Contains(@"\spotify\") ||
               pathLower.Contains(@"\teams\") ||
               pathLower.Contains(@"\vscode\") ||
               pathLower.Contains(@"\code\") ||
               pathLower.Contains(@"\programs\python") ||
               pathLower.Contains(@"\microsoft\windowsapps\") ||
               pathLower.Contains(@"\1password\") ||
               pathLower.Contains(@"\zoom\") ||
               pathLower.Contains(@"\steam\") ||
               pathLower.Contains(@"\epic games\") ||
               pathLower.Contains(@"\gitkraken\") ||
               pathLower.Contains(@"\postman\") ||
               pathLower.Contains(@"\notion\") ||
               pathLower.Contains(@"\obsidian\") ||
               pathLower.Contains(@"\signal\") ||
               pathLower.Contains(@"\telegram") ||
               pathLower.Contains(@"\whatsapp\") ||
               pathLower.Contains(@"\brave") ||
               pathLower.Contains(@"\google\chrome\") ||
               pathLower.Contains(@"\microsoft\edge\") ||
               pathLower.Contains(@"\mozilla firefox\");
    }

    /// <summary>Processes that are expected to run as SYSTEM.</summary>
    private static bool IsExpectedSystemProcess(string processName)
    {
        var name = processName.ToLowerInvariant();
        return SafeProcesses.Contains(processName) ||
               name.StartsWith("windows") ||
               name.Contains("update") ||
               name.Contains("defender") ||
               name.Contains("antimalware") ||
               name.Contains("security") ||
               name == "trustedinstaller.exe" ||
               name == "tiworker.exe" ||
               name == "msiexec.exe" ||
               name == "wuauclt.exe";
    }

    private static string TruncateCommandLine(string? cmdLine)
    {
        if (string.IsNullOrEmpty(cmdLine)) return "(no command line)";
        return cmdLine.Length > 200 ? cmdLine[..200] + "..." : cmdLine;
    }

    /// <summary>Periodically clean up stale cache entries.</summary>
    private async Task CacheCleanupLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(CachePurgeIntervalMinutes), ct);
            }
            catch (OperationCanceledException) { return; }

            // Purge old rate-limit entries
            var cutoff = DateTimeOffset.UtcNow.AddSeconds(-RateLimitSeconds * 2);
            foreach (var key in _recentAlerts.Keys.ToList())
            {
                if (_recentAlerts.TryGetValue(key, out var ts) && ts < cutoff)
                    _recentAlerts.TryRemove(key, out _);
            }

            // Purge burst tracking
            _processBurst.Clear();

            // Keep signature cache (it's useful across the session), but cap its size
            if (_signatureCache.Count > 5000)
            {
                _signatureCache.Clear();
                _logger.LogInformation("Signature cache cleared (exceeded 5000 entries)");
            }

            _logger.LogDebug("ProcessMonitor cache cleanup complete");
        }
    }
}

/// <summary>
/// Internal struct holding process information for analysis.
/// </summary>
public class ProcessInfo
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ExecutablePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public string ParentName { get; set; } = "";
    public string Owner { get; set; } = "";
}
