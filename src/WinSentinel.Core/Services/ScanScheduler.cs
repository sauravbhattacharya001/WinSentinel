using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Background scan scheduler that runs AuditEngine on configurable intervals.
/// Uses System.Threading.Timer for background execution independent of UI thread.
/// </summary>
public class ScanScheduler : IDisposable
{
    private readonly AuditEngine _engine;
    private Timer? _timer;
    private ScheduleSettings _settings;
    private bool _isRunning;
    private bool _disposed;
    private readonly object _lock = new();
    private CancellationTokenSource? _scanCts;

    /// <summary>Raised when a scheduled scan completes.</summary>
    public event EventHandler<ScanCompletedEventArgs>? ScanCompleted;

    /// <summary>Raised when the scheduler starts or stops.</summary>
    public event EventHandler<bool>? SchedulerStateChanged;

    /// <summary>Raised when a scan is in progress (for UI updates).</summary>
    public event EventHandler<string>? ScanProgress;

    /// <summary>Whether a scan is currently running.</summary>
    public bool IsScanRunning
    {
        get { lock (_lock) return _isRunning; }
    }

    /// <summary>Whether the scheduler is actively ticking.</summary>
    public bool IsSchedulerActive => _timer != null && _settings.Enabled;

    /// <summary>Current schedule settings.</summary>
    public ScheduleSettings Settings => _settings;

    /// <summary>When the next scan is due.</summary>
    public DateTimeOffset? NextScanTime
    {
        get
        {
            if (!_settings.Enabled || !_settings.LastScanTime.HasValue) return null;
            return _settings.LastScanTime.Value + _settings.EffectiveInterval;
        }
    }

    public ScanScheduler(AuditEngine engine)
    {
        _engine = engine;
        _settings = ScheduleSettings.Load();
    }

    public ScanScheduler(AuditEngine engine, ScheduleSettings settings)
    {
        _engine = engine;
        _settings = settings;
    }

    /// <summary>Start the scheduler using current settings.</summary>
    public void Start()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ScanScheduler));

        Stop(); // Clear any existing timer

        if (!_settings.Enabled) return;

        var interval = _settings.EffectiveInterval;

        // Calculate initial delay: time until next scan is due
        TimeSpan initialDelay;
        if (_settings.LastScanTime.HasValue)
        {
            var elapsed = DateTimeOffset.UtcNow - _settings.LastScanTime.Value;
            initialDelay = elapsed >= interval ? TimeSpan.Zero : interval - elapsed;
        }
        else
        {
            // No previous scan — run soon (30 seconds from now to let app settle)
            initialDelay = TimeSpan.FromSeconds(30);
        }

        _timer = new Timer(OnTimerElapsed, null, initialDelay, interval);
        SchedulerStateChanged?.Invoke(this, true);
    }

    /// <summary>Stop the scheduler.</summary>
    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        _scanCts?.Cancel();
        SchedulerStateChanged?.Invoke(this, false);
    }

    /// <summary>Update settings and restart if needed.</summary>
    public void UpdateSettings(ScheduleSettings newSettings)
    {
        _settings = newSettings;
        _settings.Save();

        if (_settings.Enabled)
        {
            Start();
        }
        else
        {
            Stop();
        }
    }

    /// <summary>Manually trigger a scan (outside of schedule).</summary>
    public async Task<SecurityReport?> RunScanNowAsync(CancellationToken cancellationToken = default)
    {
        return await ExecuteScanAsync(isScheduled: false, cancellationToken);
    }

    private async void OnTimerElapsed(object? state)
    {
        await ExecuteScanAsync(isScheduled: true, CancellationToken.None);
    }

    private async Task<SecurityReport?> ExecuteScanAsync(bool isScheduled, CancellationToken externalToken)
    {
        lock (_lock)
        {
            if (_isRunning) return null; // Don't overlap scans
            _isRunning = true;
        }

        _scanCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);

        try
        {
            ScanProgress?.Invoke(this, "Starting security scan...");

            var progress = new Progress<(string module, int current, int total)>(p =>
            {
                ScanProgress?.Invoke(this, $"Scanning: {p.module} ({p.current}/{p.total})");
            });

            // Build a filtered engine if specific modules are selected
            AuditEngine scanEngine = _engine;
            if (_settings.IncludedModules.Count > 0)
            {
                var filteredModules = _engine.Modules
                    .Where(m => _settings.IncludedModules.Contains(m.Category, StringComparer.OrdinalIgnoreCase))
                    .ToList();

                if (filteredModules.Count > 0)
                {
                    scanEngine = new AuditEngine(filteredModules);
                }
            }

            var report = await scanEngine.RunFullAuditAsync(progress, _scanCts.Token);

            var previousScore = _settings.LastScore;
            _settings.LastScanTime = DateTimeOffset.UtcNow;
            _settings.LastScore = report.SecurityScore;
            _settings.Save();

            var args = new ScanCompletedEventArgs
            {
                Report = report,
                PreviousScore = previousScore,
                IsScheduled = isScheduled
            };

            ScanCompleted?.Invoke(this, args);
            ScanProgress?.Invoke(this, $"Scan complete — Score: {report.SecurityScore}/100");

            return report;
        }
        catch (OperationCanceledException)
        {
            ScanProgress?.Invoke(this, "Scan cancelled");
            return null;
        }
        catch (Exception ex)
        {
            ScanProgress?.Invoke(this, $"Scan error: {ex.Message}");
            return null;
        }
        finally
        {
            lock (_lock) _isRunning = false;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _scanCts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
