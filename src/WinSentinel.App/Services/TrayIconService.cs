using System.Drawing;
using System.Windows;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Forms = System.Windows.Forms;

namespace WinSentinel.App.Services;

/// <summary>
/// Manages the system tray icon (NotifyIcon), context menu, balloon notifications,
/// and minimize-to-tray behavior for WinSentinel.
/// </summary>
public sealed class TrayIconService : IDisposable
{
    private Forms.NotifyIcon? _notifyIcon;
    private readonly Window _mainWindow;
    private ScheduleSettings _settings;
    private ScanScheduler? _scheduler;
    private bool _disposed;

    /// <summary>Raised when user clicks "Run Scan Now" from tray context menu.</summary>
    public event EventHandler? ScanRequested;

    /// <summary>Raised when user clicks "Export Report" from tray context menu.</summary>
    public event EventHandler? ExportRequested;

    /// <summary>Raised when user clicks "Settings" from tray context menu.</summary>
    public event EventHandler? SettingsRequested;

    /// <summary>Raised when user clicks "View Last Score" from tray context menu.</summary>
    public event EventHandler? ViewScoreRequested;

    /// <summary>Raised when the tray balloon is clicked.</summary>
    public event EventHandler<string>? BalloonClicked;

    private string? _pendingBalloonAction;

    public TrayIconService(Window mainWindow, ScheduleSettings settings)
    {
        _mainWindow = mainWindow;
        _settings = settings;
    }

    /// <summary>
    /// Initialize the tray icon with all context menu items and event handlers.
    /// </summary>
    public void Initialize()
    {
        if (_notifyIcon != null) return;

        _notifyIcon = new Forms.NotifyIcon
        {
            Icon = CreateAppIcon(),
            Text = BuildTooltipText(),
            Visible = true
        };

        // Build context menu
        _notifyIcon.ContextMenuStrip = BuildContextMenu();

        // Double-click to open/restore main window
        _notifyIcon.DoubleClick += (_, _) => ShowMainWindow();

        // Single click updates tooltip (tooltip is set on property, shown by Windows automatically)
        _notifyIcon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left)
            {
                // Update tooltip text with current score on left click
                _notifyIcon.Text = BuildTooltipText();
            }
        };

        // Balloon click handler
        _notifyIcon.BalloonTipClicked += (_, _) =>
        {
            var action = _pendingBalloonAction;
            _pendingBalloonAction = null;

            ShowMainWindow();
            BalloonClicked?.Invoke(this, action ?? "dashboard");
        };
    }

    /// <summary>
    /// Update settings reference (e.g., after settings page saves).
    /// </summary>
    public void UpdateSettings(ScheduleSettings settings)
    {
        _settings = settings;
        if (_notifyIcon != null)
        {
            _notifyIcon.Text = BuildTooltipText();
        }
    }

    /// <summary>
    /// Set the scheduler reference for "Run Scan Now" from tray.
    /// </summary>
    public void SetScheduler(ScanScheduler scheduler)
    {
        _scheduler = scheduler;
    }

    /// <summary>
    /// Handle the main window closing event. If minimize-to-tray is enabled,
    /// hide the window instead of closing the app.
    /// Returns true if the close was intercepted (window hidden to tray).
    /// </summary>
    public bool HandleWindowClosing()
    {
        if (!_settings.MinimizeToTrayOnClose)
            return false;

        _mainWindow.Hide();

        // Show first-time balloon tip
        if (!_settings.HasShownTrayBalloon)
        {
            ShowBalloon(
                "WinSentinel",
                "WinSentinel is running in the background. Double-click the tray icon to open.",
                Forms.ToolTipIcon.Info,
                "dashboard");

            _settings.HasShownTrayBalloon = true;
            _settings.Save();
        }

        return true;
    }

    /// <summary>
    /// Show a balloon notification for scan completion.
    /// </summary>
    public void NotifyScanComplete(ScanCompletedEventArgs args)
    {
        if (!_settings.ShowTrayNotifications) return;
        if (_notifyIcon == null) return;

        var title = NotificationService.BuildTitle(args);
        var body = NotificationService.BuildBody(args);

        var icon = args.Report.TotalCritical > 0 || args.ScoreDropped
            ? Forms.ToolTipIcon.Warning
            : Forms.ToolTipIcon.Info;

        ShowBalloon(title, body, icon, "dashboard");

        // Update tooltip with latest score
        _notifyIcon.Text = BuildTooltipText();
    }

    /// <summary>
    /// Show a balloon notification for score drop.
    /// </summary>
    public void NotifyScoreDrop(int currentScore, int previousScore)
    {
        if (!_settings.ShowTrayNotifications) return;
        if (_notifyIcon == null) return;

        var delta = currentScore - previousScore;
        ShowBalloon(
            $"⚠️ Security Score Dropped",
            $"Score went from {previousScore} to {currentScore} ({delta} points)\nClick to view details.",
            Forms.ToolTipIcon.Warning,
            "dashboard");
    }

    /// <summary>
    /// Show a balloon notification for critical findings.
    /// </summary>
    public void NotifyCriticalFindings(int count)
    {
        if (!_settings.ShowTrayNotifications) return;
        if (_notifyIcon == null) return;

        ShowBalloon(
            $"🔴 {count} Critical Finding(s)",
            "New critical security issues detected. Click to review.",
            Forms.ToolTipIcon.Error,
            "dashboard");
    }

    /// <summary>
    /// Show the main window and bring it to foreground.
    /// </summary>
    public void ShowMainWindow()
    {
        _mainWindow.Show();
        _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
        _mainWindow.Topmost = true;
        _mainWindow.Topmost = false;
        _mainWindow.Focus();
    }

    /// <summary>
    /// Minimize the main window to system tray.
    /// </summary>
    public void MinimizeToTray()
    {
        _mainWindow.Hide();
    }

    /// <summary>
    /// Exit the application completely (bypasses minimize-to-tray).
    /// </summary>
    public void ExitApplication()
    {
        // Set ForceClose on the main window so OnClosing doesn't intercept
        if (_mainWindow is MainWindow mw)
        {
            mw.ForceClose = true;
        }

        _notifyIcon?.Dispose();
        _notifyIcon = null;
        System.Windows.Application.Current.Shutdown();
    }

    private Forms.ContextMenuStrip BuildContextMenu()
    {
        var menu = new Forms.ContextMenuStrip();

        // Header
        var header = new Forms.ToolStripLabel("🛡️ WinSentinel")
        {
            Font = new Font("Segoe UI", 10, System.Drawing.FontStyle.Bold)
        };
        menu.Items.Add(header);
        menu.Items.Add(new Forms.ToolStripSeparator());

        // Open WinSentinel
        var openItem = new Forms.ToolStripMenuItem("Open WinSentinel");
        openItem.Click += (_, _) => ShowMainWindow();
        openItem.Font = new Font("Segoe UI", 9, System.Drawing.FontStyle.Bold);
        menu.Items.Add(openItem);

        menu.Items.Add(new Forms.ToolStripSeparator());

        // Run Scan Now
        var scanItem = new Forms.ToolStripMenuItem("🔍 Run Scan Now");
        scanItem.Click += (_, _) =>
        {
            ShowMainWindow();
            ScanRequested?.Invoke(this, EventArgs.Empty);
        };
        menu.Items.Add(scanItem);

        // View Last Score
        var scoreItem = new Forms.ToolStripMenuItem("📊 View Last Score");
        scoreItem.Click += (_, _) =>
        {
            ShowMainWindow();
            ViewScoreRequested?.Invoke(this, EventArgs.Empty);
        };
        menu.Items.Add(scoreItem);

        // Export Report
        var exportItem = new Forms.ToolStripMenuItem("📄 Export Report");
        exportItem.Click += (_, _) =>
        {
            ShowMainWindow();
            ExportRequested?.Invoke(this, EventArgs.Empty);
        };
        menu.Items.Add(exportItem);

        menu.Items.Add(new Forms.ToolStripSeparator());

        // Minimize to Tray
        var minimizeItem = new Forms.ToolStripMenuItem("⬇️ Minimize to Tray");
        minimizeItem.Click += (_, _) => MinimizeToTray();
        menu.Items.Add(minimizeItem);

        // Settings
        var settingsItem = new Forms.ToolStripMenuItem("⚙️ Settings");
        settingsItem.Click += (_, _) =>
        {
            ShowMainWindow();
            SettingsRequested?.Invoke(this, EventArgs.Empty);
        };
        menu.Items.Add(settingsItem);

        menu.Items.Add(new Forms.ToolStripSeparator());

        // Exit
        var exitItem = new Forms.ToolStripMenuItem("❌ Exit");
        exitItem.Click += (_, _) => ExitApplication();
        menu.Items.Add(exitItem);

        return menu;
    }

    private void ShowBalloon(string title, string body, Forms.ToolTipIcon icon, string action)
    {
        if (_notifyIcon == null) return;

        _pendingBalloonAction = action;

        // Strip emoji from title for balloon (Windows doesn't render them well in balloons)
        var cleanTitle = System.Text.RegularExpressions.Regex.Replace(title, @"[\u2600-\u27BF\uD83C-\uDBFF\uDC00-\uDFFF\u200D\uFE0F]+", "").Trim();
        if (string.IsNullOrWhiteSpace(cleanTitle)) cleanTitle = title;

        _notifyIcon.ShowBalloonTip(5000, cleanTitle, body, icon);
    }

    private string BuildTooltipText()
    {
        var text = "WinSentinel Security Agent";

        if (_settings.LastScore.HasValue)
        {
            var grade = SecurityScorer.GetGrade(_settings.LastScore.Value);
            text = $"WinSentinel — Score: {_settings.LastScore}/100 ({grade})";

            if (_settings.LastScanTime.HasValue)
            {
                var local = _settings.LastScanTime.Value.ToLocalTime();
                var ago = DateTimeOffset.Now - local;
                string timeAgo;
                if (ago.TotalMinutes < 1) timeAgo = "just now";
                else if (ago.TotalHours < 1) timeAgo = $"{(int)ago.TotalMinutes}m ago";
                else if (ago.TotalDays < 1) timeAgo = $"{(int)ago.TotalHours}h ago";
                else timeAgo = $"{(int)ago.TotalDays}d ago";

                text += $"\nLast scan: {timeAgo}";
            }
        }
        else
        {
            text += "\nNo scan results yet";
        }

        // NotifyIcon.Text has a 128-char limit
        if (text.Length > 127) text = text[..127];

        return text;
    }

    /// <summary>
    /// Create the WinSentinel shield icon programmatically.
    /// </summary>
    private static Icon CreateAppIcon()
    {
        // Try to load from embedded resource or exe first
        try
        {
            var exePath = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exePath) && System.IO.File.Exists(exePath))
            {
                var exeIcon = Icon.ExtractAssociatedIcon(exePath);
                if (exeIcon != null) return exeIcon;
            }
        }
        catch { }

        // Fallback: create a simple shield icon programmatically
        var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(System.Drawing.Color.Transparent);

            // Shield shape
            var points = new PointF[]
            {
                new(16, 2),    // Top center
                new(28, 8),    // Top right
                new(26, 22),   // Bottom right
                new(16, 30),   // Bottom center
                new(6, 22),    // Bottom left
                new(4, 8),     // Top left
            };

            using var fillBrush = new SolidBrush(System.Drawing.Color.FromArgb(0, 120, 212)); // WinSentinel accent blue
            g.FillPolygon(fillBrush, points);

            using var borderPen = new Pen(System.Drawing.Color.White, 1.5f);
            g.DrawPolygon(borderPen, points);

            // Checkmark inside
            using var checkPen = new Pen(System.Drawing.Color.White, 2.5f);
            g.DrawLine(checkPen, 10, 16, 14, 22);
            g.DrawLine(checkPen, 14, 22, 22, 10);
        }

        var handle = bmp.GetHicon();
        return Icon.FromHandle(handle);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_notifyIcon != null)
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _notifyIcon = null;
        }
    }
}
