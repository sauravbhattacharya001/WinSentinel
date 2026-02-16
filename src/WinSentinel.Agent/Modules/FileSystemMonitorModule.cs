using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Modules;

/// <summary>
/// Real-time file system monitoring module using FileSystemWatcher.
/// Watches critical directories for suspicious file activity including:
/// - New executables in sensitive paths (System32, Startup, Tasks)
/// - Hosts file modification (DNS hijacking)
/// - Startup folder persistence
/// - DLL sideloading attempts
/// - Suspicious script creation in temp/downloads
/// - Rapid file creation (ransomware/wiper behavior)
/// - File extension masquerading (double extensions)
/// - Mass file deletion (wiper behavior)
/// </summary>
public class FileSystemMonitorModule : IAgentModule
{
    public string Name => "FileSystemMonitor";
    public bool IsActive { get; private set; }

    private readonly ILogger<FileSystemMonitorModule> _logger;
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private readonly List<FileSystemWatcher> _watchers = new();
    private CancellationTokenSource? _cts;

    // ── Event buffering & debounce ──

    /// <summary>Pending events keyed by full path, coalesced within debounce window.</summary>
    private readonly ConcurrentDictionary<string, BufferedEvent> _pendingEvents = new();

    /// <summary>Rate-limit: recent alert keys with timestamps.</summary>
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentAlerts = new();

    /// <summary>File hash cache for change detection.</summary>
    private readonly ConcurrentDictionary<string, string> _fileHashes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Tracks rapid file creation: directory → (count, windowStart).</summary>
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> _rapidCreation = new();

    /// <summary>Tracks rapid file deletion: directory → (count, windowStart).</summary>
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> _rapidDeletion = new();

    // ── Constants ──

    private const int DebounceMs = 2000;
    private const int RateLimitSeconds = 60;
    private const int RapidCreationThreshold = 50;
    private const int RapidCreationWindowSeconds = 10;
    private const int RapidDeletionThreshold = 20;
    private const int RapidDeletionWindowSeconds = 5;
    private const int CachePurgeIntervalMinutes = 30;
    private const int EventProcessIntervalMs = 500;

    /// <summary>Executable/script extensions considered dangerous in sensitive paths.</summary>
    internal static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".com", ".pif", ".msi", ".wsf", ".hta"
    };

    /// <summary>Script extensions specifically dangerous in temp/downloads.</summary>
    internal static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta"
    };

    /// <summary>Executable extensions for double-extension masquerading detection.</summary>
    internal static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"
    };

    /// <summary>Non-executable "bait" extensions used in masquerading.</summary>
    internal static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi",
        ".zip", ".rar", ".7z", ".csv"
    };

    /// <summary>Known-safe file patterns to ignore (Windows Update, Defender, etc.).</summary>
    private static readonly string[] SafePatterns = new[]
    {
        // Windows Update
        @"\SoftwareDistribution\",
        @"\CbsTemp\",
        @"\WinSxS\Temp\",
        @"\WinSxS\Backup\",
        // Windows Defender
        @"\Windows Defender\",
        @"\Microsoft\Windows Defender\",
        @"\Definition Updates\",
        @"\MpSigStub",
        @"\MpCmdRun",
        // WinSentinel itself
        @"\WinSentinel\",
        // System restore
        @"\System Volume Information\",
        // Prefetch
        @"\Prefetch\",
        // Font cache
        @"\FontCache\",
        // .NET compilation
        @"\assembly\NativeImages",
        @"\Microsoft.NET\",
    };

    /// <summary>Known-safe process-created temp file patterns.</summary>
    private static readonly string[] SafeTempPatterns = new[]
    {
        "tmp", "~", ".tmp", ".log", ".etl", ".diagsession", ".lock"
    };

    // ── Watched directory categories ──

    private readonly List<WatchedDirectory> _watchedDirs = new();

    public FileSystemMonitorModule(
        ILogger<FileSystemMonitorModule> logger,
        ThreatLog threatLog,
        AgentConfig config)
    {
        _logger = logger;
        _threatLog = threatLog;
        _config = config;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("FileSystemMonitor starting — setting up directory watchers...");
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        BuildWatchedDirectories();

        foreach (var dir in _watchedDirs)
        {
            try
            {
                if (!Directory.Exists(dir.Path))
                {
                    _logger.LogDebug("Skipping non-existent directory: {Path}", dir.Path);
                    continue;
                }

                var watcher = new FileSystemWatcher(dir.Path)
                {
                    IncludeSubdirectories = dir.IncludeSubdirectories,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                   NotifyFilters.CreationTime | NotifyFilters.Size,
                    InternalBufferSize = 65536, // 64KB buffer to avoid overflow
                    EnableRaisingEvents = true
                };

                watcher.Created += (s, e) => OnFileEvent(e.FullPath, e.Name, FileEventType.Created, dir);
                watcher.Changed += (s, e) => OnFileEvent(e.FullPath, e.Name, FileEventType.Changed, dir);
                watcher.Deleted += (s, e) => OnFileEvent(e.FullPath, e.Name, FileEventType.Deleted, dir);
                watcher.Renamed += (s, e) => OnFileRenamed(e.OldFullPath, e.FullPath, e.Name, dir);
                watcher.Error += OnWatcherError;

                _watchers.Add(watcher);
                _logger.LogInformation("Watching: {Path} ({Category})", dir.Path, dir.Category);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to create watcher for {Path}", dir.Path);
            }
        }

        // Start the debounce event processor
        _ = Task.Run(() => EventProcessingLoopAsync(_cts.Token), _cts.Token);

        // Start cache cleanup loop
        _ = Task.Run(() => CacheCleanupLoopAsync(_cts.Token), _cts.Token);

        IsActive = true;
        _logger.LogInformation("FileSystemMonitor active with {Count} watchers", _watchers.Count);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("FileSystemMonitor stopping...");
        IsActive = false;
        _cts?.Cancel();

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error disposing watcher");
            }
        }

        _watchers.Clear();
        _pendingEvents.Clear();
        _recentAlerts.Clear();
        _fileHashes.Clear();
        _rapidCreation.Clear();
        _rapidDeletion.Clear();

        return Task.CompletedTask;
    }

    // ── Directory Setup ──

    private void BuildWatchedDirectories()
    {
        _watchedDirs.Clear();

        // System32 — DLL drops, binary replacements
        _watchedDirs.Add(new WatchedDirectory
        {
            Path = @"C:\Windows\System32",
            Category = DirectoryCategory.System32,
            IncludeSubdirectories = false // Top-level only to reduce noise
        });

        // Hosts file directory
        _watchedDirs.Add(new WatchedDirectory
        {
            Path = @"C:\Windows\System32\drivers\etc",
            Category = DirectoryCategory.HostsFile,
            IncludeSubdirectories = false
        });

        // User Startup folder
        var userStartup = Environment.ExpandEnvironmentVariables(
            @"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup");
        if (Directory.Exists(userStartup))
        {
            _watchedDirs.Add(new WatchedDirectory
            {
                Path = userStartup,
                Category = DirectoryCategory.StartupFolder,
                IncludeSubdirectories = false
            });
        }

        // All Users Startup folder
        var allUsersStartup = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";
        if (Directory.Exists(allUsersStartup))
        {
            _watchedDirs.Add(new WatchedDirectory
            {
                Path = allUsersStartup,
                Category = DirectoryCategory.StartupFolder,
                IncludeSubdirectories = false
            });
        }

        // Temp directories — malware staging
        var tempDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Environment.ExpandEnvironmentVariables(@"%TEMP%"),
            Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Temp"),
            Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)
        };
        foreach (var tempDir in tempDirs.Where(Directory.Exists))
        {
            _watchedDirs.Add(new WatchedDirectory
            {
                Path = tempDir,
                Category = DirectoryCategory.TempDirectory,
                IncludeSubdirectories = false
            });
        }

        // Downloads folder
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (Directory.Exists(downloads))
        {
            _watchedDirs.Add(new WatchedDirectory
            {
                Path = downloads,
                Category = DirectoryCategory.Downloads,
                IncludeSubdirectories = false
            });
        }

        // Scheduled Tasks directories
        _watchedDirs.Add(new WatchedDirectory
        {
            Path = @"C:\Windows\Tasks",
            Category = DirectoryCategory.ScheduledTasks,
            IncludeSubdirectories = false
        });

        _watchedDirs.Add(new WatchedDirectory
        {
            Path = @"C:\Windows\System32\Tasks",
            Category = DirectoryCategory.ScheduledTasks,
            IncludeSubdirectories = true
        });
    }

    // ── Event Handlers ──

    private void OnFileEvent(string fullPath, string? name, FileEventType eventType, WatchedDirectory dir)
    {
        try
        {
            if (string.IsNullOrEmpty(fullPath) || IsKnownSafe(fullPath))
                return;

            // Track rapid creation/deletion regardless of debounce
            var dirKey = dir.Path.ToLowerInvariant();
            if (eventType == FileEventType.Created)
                TrackRapidActivity(_rapidCreation, dirKey);
            else if (eventType == FileEventType.Deleted)
                TrackRapidActivity(_rapidDeletion, dirKey);

            // Buffer the event for debouncing
            var key = fullPath.ToLowerInvariant();
            _pendingEvents.AddOrUpdate(
                key,
                _ => new BufferedEvent
                {
                    FullPath = fullPath,
                    FileName = name ?? Path.GetFileName(fullPath),
                    EventType = eventType,
                    Directory = dir,
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow,
                    Count = 1
                },
                (_, existing) =>
                {
                    existing.LastSeen = DateTimeOffset.UtcNow;
                    existing.Count++;
                    // Upgrade event type: Created > Changed > Deleted
                    if (eventType == FileEventType.Created || existing.EventType == FileEventType.Deleted)
                        existing.EventType = eventType;
                    return existing;
                });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error buffering file event for {Path}", fullPath);
        }
    }

    private void OnFileRenamed(string oldPath, string newPath, string? name, WatchedDirectory dir)
    {
        // Treat rename as a creation at the new path (for masquerading detection)
        OnFileEvent(newPath, name, FileEventType.Created, dir);
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        var ex = e.GetException();
        _logger.LogWarning(ex, "FileSystemWatcher error — buffer may have overflowed");
    }

    // ── Debounced Event Processing ──

    private async Task EventProcessingLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(EventProcessIntervalMs, ct);
            }
            catch (OperationCanceledException) { return; }

            var now = DateTimeOffset.UtcNow;
            var readyKeys = new List<string>();

            foreach (var kvp in _pendingEvents)
            {
                if ((now - kvp.Value.LastSeen).TotalMilliseconds >= DebounceMs)
                    readyKeys.Add(kvp.Key);
            }

            foreach (var key in readyKeys)
            {
                if (_pendingEvents.TryRemove(key, out var evt))
                {
                    try
                    {
                        AnalyzeEvent(evt);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Error analyzing file event for {Path}", evt.FullPath);
                    }
                }
            }

            // Check for rapid activity bursts
            CheckRapidCreation();
            CheckRapidDeletion();
        }
    }

    // ── Analysis Engine ──

    /// <summary>
    /// Analyze a debounced file system event against all detection rules.
    /// Made internal for testability.
    /// </summary>
    internal void AnalyzeEvent(BufferedEvent evt)
    {
        var threats = new List<ThreatEvent>();

        switch (evt.Directory.Category)
        {
            case DirectoryCategory.System32:
                CheckSystem32Drop(evt, threats);
                break;

            case DirectoryCategory.HostsFile:
                CheckHostsFileModification(evt, threats);
                break;

            case DirectoryCategory.StartupFolder:
                CheckStartupPersistence(evt, threats);
                break;

            case DirectoryCategory.TempDirectory:
                CheckSuspiciousScript(evt, threats);
                CheckExtensionMasquerading(evt, threats);
                break;

            case DirectoryCategory.Downloads:
                CheckSuspiciousScript(evt, threats);
                CheckExtensionMasquerading(evt, threats);
                CheckNewExecutableInDownloads(evt, threats);
                break;

            case DirectoryCategory.ScheduledTasks:
                CheckScheduledTaskPersistence(evt, threats);
                break;
        }

        // Cross-category checks
        CheckDllSideloading(evt, threats);

        // Emit threats with rate limiting
        foreach (var threat in threats)
        {
            if (!ShouldRateLimit(threat))
            {
                _threatLog.Add(threat);
                _logger.LogWarning("[{Severity}] {Title}: {Desc}",
                    threat.Severity, threat.Title, threat.Description);
                HandleResponse(threat, evt);
            }
        }
    }

    // ── Detection Rules ──

    /// <summary>Rule: New executable/DLL dropped in System32.</summary>
    internal static void CheckSystem32Drop(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (evt.EventType != FileEventType.Created)
            return;

        var ext = Path.GetExtension(evt.FileName);
        if (!DangerousExtensions.Contains(ext))
            return;

        threats.Add(new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.Critical,
            Title = "New Executable in System32",
            Description = $"A new file '{evt.FileName}' was dropped in System32. " +
                          $"This could indicate DLL injection, binary replacement, or malware staging. " +
                          $"Path: {evt.FullPath}",
            AutoFixable = true,
            FixCommand = $"Remove-Item -Path \"{evt.FullPath}\" -Force"
        });
    }

    /// <summary>Rule: Hosts file modification (DNS hijacking).</summary>
    internal static void CheckHostsFileModification(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (!evt.FileName.Equals("hosts", StringComparison.OrdinalIgnoreCase))
            return;

        if (evt.EventType == FileEventType.Deleted)
        {
            threats.Add(new ThreatEvent
            {
                Source = "FileSystemMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Hosts File Deleted",
                Description = "The Windows hosts file was deleted. This could indicate malware tampering with DNS resolution.",
                AutoFixable = false
            });
            return;
        }

        // Created or Changed
        threats.Add(new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.High,
            Title = "Hosts File Modified",
            Description = $"The Windows hosts file was modified. This could indicate DNS hijacking or ad injection. " +
                          $"Review the file at C:\\Windows\\System32\\drivers\\etc\\hosts for suspicious entries.",
            AutoFixable = false
        });
    }

    /// <summary>Rule: New file added to startup folder (persistence).</summary>
    internal static void CheckStartupPersistence(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (evt.EventType != FileEventType.Created)
            return;

        var ext = Path.GetExtension(evt.FileName);
        var severity = DangerousExtensions.Contains(ext) ? ThreatSeverity.Critical : ThreatSeverity.High;

        threats.Add(new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = severity,
            Title = "Startup Folder Persistence",
            Description = $"A new file '{evt.FileName}' was added to a Windows Startup folder. " +
                          $"This is a common persistence mechanism used by malware. " +
                          $"Path: {evt.FullPath}",
            AutoFixable = true,
            FixCommand = $"Remove-Item -Path \"{evt.FullPath}\" -Force"
        });
    }

    /// <summary>Rule: Suspicious script creation in temp or downloads.</summary>
    internal static void CheckSuspiciousScript(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (evt.EventType != FileEventType.Created)
            return;

        var ext = Path.GetExtension(evt.FileName);
        if (!ScriptExtensions.Contains(ext))
            return;

        threats.Add(new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.Medium,
            Title = "Suspicious Script Created",
            Description = $"A script file '{evt.FileName}' was created in {evt.Directory.Category}. " +
                          $"Script files in temporary or downloads folders may indicate malware staging. " +
                          $"Path: {evt.FullPath}",
            AutoFixable = true,
            FixCommand = $"Remove-Item -Path \"{evt.FullPath}\" -Force"
        });
    }

    /// <summary>Rule: File extension masquerading — double extensions like report.pdf.exe.</summary>
    internal static void CheckExtensionMasquerading(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (evt.EventType != FileEventType.Created)
            return;

        // Check for double extensions: get the "inner" extension
        var fileName = evt.FileName;
        var outerExt = Path.GetExtension(fileName);
        if (string.IsNullOrEmpty(outerExt))
            return;

        var nameWithoutOuterExt = Path.GetFileNameWithoutExtension(fileName);
        var innerExt = Path.GetExtension(nameWithoutOuterExt);
        if (string.IsNullOrEmpty(innerExt))
            return;

        // Double extension: inner is a document type, outer is executable
        if (DocumentExtensions.Contains(innerExt) && ExecutableExtensions.Contains(outerExt))
        {
            threats.Add(new ThreatEvent
            {
                Source = "FileSystemMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "File Extension Masquerading",
                Description = $"File '{fileName}' uses a double extension ({innerExt}{outerExt}) to disguise " +
                              $"an executable as a document. This is a common social engineering technique. " +
                              $"Path: {evt.FullPath}",
                AutoFixable = true,
                FixCommand = $"Remove-Item -Path \"{evt.FullPath}\" -Force"
            });
        }
    }

    /// <summary>Rule: New DLL appearing next to a legitimate executable (DLL sideloading).</summary>
    internal void CheckDllSideloading(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (evt.EventType != FileEventType.Created)
            return;

        var ext = Path.GetExtension(evt.FileName);
        if (!ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            return;

        // Skip System32 — handled by CheckSystem32Drop
        if (evt.Directory.Category == DirectoryCategory.System32)
            return;

        // Check if there are executables in the same directory
        try
        {
            var dir = Path.GetDirectoryName(evt.FullPath);
            if (dir == null) return;

            var hasExe = Directory.EnumerateFiles(dir, "*.exe")
                .Any(f => !f.Equals(evt.FullPath, StringComparison.OrdinalIgnoreCase));

            if (hasExe)
            {
                threats.Add(new ThreatEvent
                {
                    Source = "FileSystemMonitor",
                    Severity = ThreatSeverity.High,
                    Title = "Potential DLL Sideloading",
                    Description = $"A new DLL '{evt.FileName}' appeared in a directory containing executables. " +
                                  $"This may indicate DLL sideloading/hijacking. " +
                                  $"Path: {evt.FullPath}",
                    AutoFixable = true,
                    FixCommand = $"Remove-Item -Path \"{evt.FullPath}\" -Force"
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking for DLL sideloading at {Path}", evt.FullPath);
        }
    }

    /// <summary>Rule: New executable in scheduled tasks directory.</summary>
    internal static void CheckScheduledTaskPersistence(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (evt.EventType != FileEventType.Created)
            return;

        var ext = Path.GetExtension(evt.FileName);

        // Task XML files are normal, but executables are suspicious
        if (ext.Equals(".xml", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".job", StringComparison.OrdinalIgnoreCase))
        {
            // New scheduled task file — worth monitoring
            threats.Add(new ThreatEvent
            {
                Source = "FileSystemMonitor",
                Severity = ThreatSeverity.Medium,
                Title = "New Scheduled Task Created",
                Description = $"A new scheduled task file '{evt.FileName}' was created. " +
                              $"Malware often uses scheduled tasks for persistence. " +
                              $"Path: {evt.FullPath}",
                AutoFixable = false
            });
            return;
        }

        if (DangerousExtensions.Contains(ext))
        {
            threats.Add(new ThreatEvent
            {
                Source = "FileSystemMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Executable in Tasks Directory",
                Description = $"An executable '{evt.FileName}' was dropped in a scheduled tasks directory. " +
                              $"This is a strong indicator of persistence malware. " +
                              $"Path: {evt.FullPath}",
                AutoFixable = true,
                FixCommand = $"Remove-Item -Path \"{evt.FullPath}\" -Force"
            });
        }
    }

    /// <summary>Rule: New executable downloaded.</summary>
    internal static void CheckNewExecutableInDownloads(BufferedEvent evt, List<ThreatEvent> threats)
    {
        if (evt.EventType != FileEventType.Created)
            return;

        var ext = Path.GetExtension(evt.FileName);
        if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
            !ext.Equals(".msi", StringComparison.OrdinalIgnoreCase) &&
            !ext.Equals(".scr", StringComparison.OrdinalIgnoreCase))
            return;

        // Don't duplicate if masquerading already flagged it
        threats.Add(new ThreatEvent
        {
            Source = "FileSystemMonitor",
            Severity = ThreatSeverity.Low,
            Title = "New Executable Downloaded",
            Description = $"A new executable '{evt.FileName}' appeared in the Downloads folder. " +
                          $"Verify the source before running. Path: {evt.FullPath}",
            AutoFixable = false
        });
    }

    // ── Rapid Activity Detection ──

    private void TrackRapidActivity(
        ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> tracker,
        string dirKey)
    {
        var now = DateTimeOffset.UtcNow;
        tracker.AddOrUpdate(
            dirKey,
            _ => (1, now),
            (_, existing) =>
            {
                var windowSeconds = tracker == _rapidCreation
                    ? RapidCreationWindowSeconds
                    : RapidDeletionWindowSeconds;
                if ((now - existing.WindowStart).TotalSeconds > windowSeconds)
                    return (1, now); // Reset window
                return (existing.Count + 1, existing.WindowStart);
            });
    }

    private void CheckRapidCreation()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _rapidCreation)
        {
            if (kvp.Value.Count >= RapidCreationThreshold &&
                (now - kvp.Value.WindowStart).TotalSeconds <= RapidCreationWindowSeconds)
            {
                var alertKey = $"RapidCreation|{kvp.Key}";
                if (!ShouldRateLimitByKey(alertKey))
                {
                    var threat = new ThreatEvent
                    {
                        Source = "FileSystemMonitor",
                        Severity = ThreatSeverity.Critical,
                        Title = "Rapid File Creation Detected",
                        Description = $"Over {kvp.Value.Count} files created in {RapidCreationWindowSeconds} seconds " +
                                      $"in '{kvp.Key}'. This may indicate ransomware encryption or a wiper attack.",
                        AutoFixable = false
                    };
                    _threatLog.Add(threat);
                    _logger.LogWarning("[{Severity}] {Title}: {Desc}",
                        threat.Severity, threat.Title, threat.Description);
                }

                // Reset after alerting
                _rapidCreation.TryUpdate(kvp.Key, (0, now), kvp.Value);
            }
        }
    }

    private void CheckRapidDeletion()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _rapidDeletion)
        {
            if (kvp.Value.Count >= RapidDeletionThreshold &&
                (now - kvp.Value.WindowStart).TotalSeconds <= RapidDeletionWindowSeconds)
            {
                var alertKey = $"RapidDeletion|{kvp.Key}";
                if (!ShouldRateLimitByKey(alertKey))
                {
                    var threat = new ThreatEvent
                    {
                        Source = "FileSystemMonitor",
                        Severity = ThreatSeverity.Critical,
                        Title = "Mass File Deletion Detected",
                        Description = $"Over {kvp.Value.Count} files deleted in {RapidDeletionWindowSeconds} seconds " +
                                      $"in '{kvp.Key}'. This may indicate a wiper attack or ransomware cleanup.",
                        AutoFixable = false
                    };
                    _threatLog.Add(threat);
                    _logger.LogWarning("[{Severity}] {Title}: {Desc}",
                        threat.Severity, threat.Title, threat.Description);
                }

                // Reset after alerting
                _rapidDeletion.TryUpdate(kvp.Key, (0, now), kvp.Value);
            }
        }
    }

    // ── Response Actions ──

    private void HandleResponse(ThreatEvent threat, BufferedEvent evt)
    {
        switch (_config.RiskTolerance)
        {
            case RiskTolerance.Low:
                // Aggressive: auto-quarantine critical threats
                if (threat.Severity >= ThreatSeverity.Critical && threat.AutoFixable)
                {
                    try
                    {
                        if (File.Exists(evt.FullPath))
                        {
                            var quarantineDir = Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                "WinSentinel", "Quarantine");
                            Directory.CreateDirectory(quarantineDir);

                            var quarantinePath = Path.Combine(quarantineDir,
                                $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{evt.FileName}.quarantine");

                            File.Move(evt.FullPath, quarantinePath);
                            threat.ResponseTaken = $"Auto-quarantined to {quarantinePath}";
                            _logger.LogWarning("Auto-quarantined: {Path} → {Quarantine}",
                                evt.FullPath, quarantinePath);
                        }
                        else
                        {
                            threat.ResponseTaken = "File no longer exists";
                        }
                    }
                    catch (Exception ex)
                    {
                        threat.ResponseTaken = $"Quarantine failed: {ex.Message}";
                        _logger.LogWarning(ex, "Failed to quarantine {Path}", evt.FullPath);
                    }
                }
                else
                {
                    threat.ResponseTaken = "Alert sent to UI";
                }
                break;

            case RiskTolerance.Medium:
                threat.ResponseTaken = threat.AutoFixable
                    ? "Alert sent — fix available"
                    : "Alert sent — manual review recommended";
                break;

            case RiskTolerance.High:
                threat.ResponseTaken = "Logged only (high risk tolerance)";
                break;
        }
    }

    // ── Helpers ──

    /// <summary>Check if a file path matches known-safe patterns.</summary>
    internal static bool IsKnownSafe(string fullPath)
    {
        foreach (var pattern in SafePatterns)
        {
            if (fullPath.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Safe temp file extensions (very common, very noisy)
        var ext = Path.GetExtension(fullPath);
        foreach (var safeExt in SafeTempPatterns)
        {
            if (ext.Equals(safeExt, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>Compute SHA-256 hash of a file.</summary>
    internal static string? ComputeFileHash(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return null;
            using var stream = File.OpenRead(filePath);
            var hashBytes = SHA256.HashData(stream);
            return Convert.ToHexString(hashBytes);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Check if file content actually changed (by hash).</summary>
    internal bool HasContentChanged(string filePath)
    {
        var newHash = ComputeFileHash(filePath);
        if (newHash == null) return true; // Assume changed if we can't hash

        if (_fileHashes.TryGetValue(filePath, out var oldHash))
        {
            if (oldHash == newHash) return false; // No change
        }

        _fileHashes[filePath] = newHash;
        return true;
    }

    /// <summary>Rate-limit by threat content.</summary>
    private bool ShouldRateLimit(ThreatEvent threat)
    {
        var key = $"{threat.Source}|{threat.Title}|{threat.Description?[..Math.Min(threat.Description?.Length ?? 0, 80)]}";
        return ShouldRateLimitByKey(key);
    }

    /// <summary>Rate-limit by arbitrary key.</summary>
    private bool ShouldRateLimitByKey(string key)
    {
        if (_recentAlerts.TryGetValue(key, out var lastAlert))
        {
            if ((DateTimeOffset.UtcNow - lastAlert).TotalSeconds < RateLimitSeconds)
                return true;
        }
        _recentAlerts[key] = DateTimeOffset.UtcNow;
        return false;
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

            // Purge rapid activity trackers
            _rapidCreation.Clear();
            _rapidDeletion.Clear();

            // Cap hash cache size
            if (_fileHashes.Count > 10000)
            {
                _fileHashes.Clear();
                _logger.LogInformation("File hash cache cleared (exceeded 10000 entries)");
            }

            _logger.LogDebug("FileSystemMonitor cache cleanup complete");
        }
    }
}

// ── Supporting Types ──

/// <summary>Categories of watched directories for rule selection.</summary>
public enum DirectoryCategory
{
    System32,
    HostsFile,
    StartupFolder,
    TempDirectory,
    Downloads,
    ScheduledTasks
}

/// <summary>Type of file system event.</summary>
public enum FileEventType
{
    Created,
    Changed,
    Deleted
}

/// <summary>Configuration for a watched directory.</summary>
public class WatchedDirectory
{
    public string Path { get; set; } = "";
    public DirectoryCategory Category { get; set; }
    public bool IncludeSubdirectories { get; set; }
}

/// <summary>Buffered file system event for debouncing.</summary>
public class BufferedEvent
{
    public string FullPath { get; set; } = "";
    public string FileName { get; set; } = "";
    public FileEventType EventType { get; set; }
    public WatchedDirectory Directory { get; set; } = new();
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public int Count { get; set; }
}
