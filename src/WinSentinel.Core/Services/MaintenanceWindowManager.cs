using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Manages scheduled maintenance windows during which certain findings are
/// suppressed. Useful for planned changes, patch windows, or known-maintenance
/// periods where transient security deviations are expected.
/// Windows are stored in %LocalAppData%/WinSentinel/maintenance-windows.json.
/// </summary>
public class MaintenanceWindowManager
{
    private readonly string _filePath;
    private List<MaintenanceWindow>? _cache;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public MaintenanceWindowManager()
        : this(GetDefaultPath())
    {
    }

    public MaintenanceWindowManager(string filePath)
    {
        _filePath = filePath;
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
    }

    private static string GetDefaultPath() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSentinel", "maintenance-windows.json");

    /// <summary>
    /// Create a new maintenance window.
    /// </summary>
    public MaintenanceWindow Create(MaintenanceWindowRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Name))
            throw new ArgumentException("Window name is required.", nameof(request));
        if (request.EndUtc <= request.StartUtc)
            throw new ArgumentException("End time must be after start time.", nameof(request));

        var window = new MaintenanceWindow
        {
            Id = Guid.NewGuid().ToString("N")[..12],
            Name = request.Name.Trim(),
            Description = request.Description?.Trim(),
            StartUtc = request.StartUtc,
            EndUtc = request.EndUtc,
            SuppressedCategories = request.SuppressedCategories?.ToList() ?? new(),
            SuppressedSeverities = request.SuppressedSeverities?.ToList() ?? new(),
            SuppressedTitlePatterns = request.SuppressedTitlePatterns?.ToList() ?? new(),
            Recurring = request.Recurring,
            RecurrenceIntervalDays = request.RecurrenceIntervalDays,
            CreatedUtc = DateTimeOffset.UtcNow,
            CreatedBy = request.CreatedBy?.Trim() ?? Environment.UserName
        };

        var windows = LoadAll();
        windows.Add(window);
        Save(windows);
        return window;
    }

    /// <summary>
    /// Get all maintenance windows.
    /// </summary>
    public List<MaintenanceWindow> GetAll() => LoadAll().ToList();

    /// <summary>
    /// Get a window by ID.
    /// </summary>
    public MaintenanceWindow? GetById(string id) =>
        LoadAll().FirstOrDefault(w => w.Id == id);

    /// <summary>
    /// Delete a window by ID. Returns true if found and removed.
    /// </summary>
    public bool Delete(string id)
    {
        var windows = LoadAll();
        var removed = windows.RemoveAll(w => w.Id == id);
        if (removed > 0)
        {
            Save(windows);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Cancel an active window (sets Cancelled flag, keeps record).
    /// </summary>
    public bool Cancel(string id)
    {
        var windows = LoadAll();
        var window = windows.FirstOrDefault(w => w.Id == id);
        if (window == null) return false;
        window.Cancelled = true;
        Save(windows);
        return true;
    }

    /// <summary>
    /// Extend a window's end time.
    /// </summary>
    public bool Extend(string id, TimeSpan extension)
    {
        if (extension <= TimeSpan.Zero)
            throw new ArgumentException("Extension must be positive.", nameof(extension));

        var windows = LoadAll();
        var window = windows.FirstOrDefault(w => w.Id == id);
        if (window == null) return false;
        window.EndUtc = window.EndUtc.Add(extension);
        Save(windows);
        return true;
    }

    /// <summary>
    /// Get all currently active (non-cancelled) maintenance windows.
    /// Accounts for recurring windows.
    /// </summary>
    public List<MaintenanceWindow> GetActive(DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;
        var result = new List<MaintenanceWindow>();

        foreach (var w in LoadAll())
        {
            if (w.Cancelled) continue;
            if (IsActiveAt(w, now))
                result.Add(w);
        }
        return result;
    }

    /// <summary>
    /// Get upcoming windows (starting within the given horizon).
    /// </summary>
    public List<MaintenanceWindow> GetUpcoming(TimeSpan horizon, DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;
        var cutoff = now.Add(horizon);
        var result = new List<MaintenanceWindow>();

        foreach (var w in LoadAll())
        {
            if (w.Cancelled) continue;
            if (w.StartUtc > now && w.StartUtc <= cutoff)
                result.Add(w);
            else if (w.Recurring && w.RecurrenceIntervalDays > 0)
            {
                var next = GetNextOccurrence(w, now);
                if (next.HasValue && next.Value <= cutoff)
                    result.Add(w);
            }
        }
        return result;
    }

    /// <summary>
    /// Check if a finding should be suppressed given the currently active windows.
    /// </summary>
    public bool IsSuppressed(Finding finding, DateTimeOffset? asOf = null)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var activeWindows = GetActive(asOf);
        return activeWindows.Any(w => WindowSuppresses(w, finding));
    }

    /// <summary>
    /// Filter a list of findings, removing those suppressed by active windows.
    /// Returns a <see cref="SuppressionResult"/> with kept and suppressed findings.
    /// </summary>
    public SuppressionResult ApplyWindows(IEnumerable<Finding> findings, DateTimeOffset? asOf = null)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var activeWindows = GetActive(asOf);
        var kept = new List<Finding>();
        var suppressed = new List<SuppressedFinding>();

        foreach (var f in findings)
        {
            var matchingWindow = activeWindows.FirstOrDefault(w => WindowSuppresses(w, f));
            if (matchingWindow != null)
                suppressed.Add(new SuppressedFinding { Finding = f, WindowId = matchingWindow.Id, WindowName = matchingWindow.Name });
            else
                kept.Add(f);
        }

        return new SuppressionResult { Kept = kept, Suppressed = suppressed };
    }

    /// <summary>
    /// Purge expired (non-recurring, non-cancelled) windows older than the given age.
    /// Returns count of purged windows.
    /// </summary>
    public int PurgeExpired(TimeSpan maxAge, DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;
        var windows = LoadAll();
        var before = windows.Count;
        windows.RemoveAll(w => !w.Recurring && !w.Cancelled && w.EndUtc < now - maxAge);
        Save(windows);
        return before - windows.Count;
    }

    /// <summary>
    /// Generate a text report of all windows and their status.
    /// </summary>
    public string GenerateReport(DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;
        var windows = LoadAll();
        var lines = new List<string>
        {
            "=== Maintenance Window Report ===",
            $"Generated: {now:yyyy-MM-dd HH:mm:ss} UTC",
            $"Total windows: {windows.Count}",
            ""
        };

        foreach (var w in windows.OrderBy(w => w.StartUtc))
        {
            var status = w.Cancelled ? "CANCELLED"
                : IsActiveAt(w, now) ? "ACTIVE"
                : w.EndUtc < now ? "EXPIRED"
                : "SCHEDULED";

            lines.Add($"[{status}] {w.Name} (ID: {w.Id})");
            if (!string.IsNullOrEmpty(w.Description))
                lines.Add($"  Description: {w.Description}");
            lines.Add($"  Window: {w.StartUtc:yyyy-MM-dd HH:mm} → {w.EndUtc:yyyy-MM-dd HH:mm} UTC");
            if (w.Recurring)
                lines.Add($"  Recurring: every {w.RecurrenceIntervalDays} day(s)");
            if (w.SuppressedCategories.Count > 0)
                lines.Add($"  Categories: {string.Join(", ", w.SuppressedCategories)}");
            if (w.SuppressedSeverities.Count > 0)
                lines.Add($"  Severities: {string.Join(", ", w.SuppressedSeverities)}");
            if (w.SuppressedTitlePatterns.Count > 0)
                lines.Add($"  Title patterns: {string.Join(", ", w.SuppressedTitlePatterns)}");
            lines.Add($"  Created by: {w.CreatedBy} at {w.CreatedUtc:yyyy-MM-dd HH:mm} UTC");
            lines.Add("");
        }

        if (windows.Count == 0)
            lines.Add("No maintenance windows configured.");

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// Export windows to JSON.
    /// </summary>
    public string ExportJson() =>
        JsonSerializer.Serialize(LoadAll(), JsonOptions);

    /// <summary>
    /// Import windows from JSON, merging by ID (new IDs are added, existing are skipped).
    /// Returns count of newly imported windows.
    /// </summary>
    public int ImportJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("JSON content is required.", nameof(json));

        var imported = JsonSerializer.Deserialize<List<MaintenanceWindow>>(json, JsonOptions) ?? new();
        var existing = LoadAll();
        var existingIds = new HashSet<string>(existing.Select(w => w.Id));
        var added = 0;

        foreach (var w in imported)
        {
            if (!existingIds.Contains(w.Id))
            {
                existing.Add(w);
                existingIds.Add(w.Id);
                added++;
            }
        }

        Save(existing);
        return added;
    }

    // --- Private helpers ---

    private bool IsActiveAt(MaintenanceWindow w, DateTimeOffset time)
    {
        if (w.Cancelled) return false;

        // Direct match
        if (time >= w.StartUtc && time < w.EndUtc)
            return true;

        // Recurring match
        if (w.Recurring && w.RecurrenceIntervalDays > 0 && time >= w.StartUtc)
        {
            var duration = w.EndUtc - w.StartUtc;
            var elapsed = time - w.StartUtc;
            var intervalTicks = TimeSpan.FromDays(w.RecurrenceIntervalDays).Ticks;
            var currentCycleStart = w.StartUtc.AddTicks((elapsed.Ticks / intervalTicks) * intervalTicks);
            var currentCycleEnd = currentCycleStart.Add(duration);
            return time >= currentCycleStart && time < currentCycleEnd;
        }

        return false;
    }

    private DateTimeOffset? GetNextOccurrence(MaintenanceWindow w, DateTimeOffset after)
    {
        if (!w.Recurring || w.RecurrenceIntervalDays <= 0) return null;
        if (w.Cancelled) return null;

        var duration = w.EndUtc - w.StartUtc;
        var interval = TimeSpan.FromDays(w.RecurrenceIntervalDays);

        if (after < w.StartUtc) return w.StartUtc;

        var elapsed = after - w.StartUtc;
        var cycles = (long)(elapsed.TotalDays / w.RecurrenceIntervalDays) + 1;
        return w.StartUtc.Add(TimeSpan.FromDays(cycles * w.RecurrenceIntervalDays));
    }

    private static bool WindowSuppresses(MaintenanceWindow window, Finding finding)
    {
        // If no filters specified, suppress everything
        bool hasFilters = window.SuppressedCategories.Count > 0
            || window.SuppressedSeverities.Count > 0
            || window.SuppressedTitlePatterns.Count > 0;

        if (!hasFilters) return true;

        // Category match
        if (window.SuppressedCategories.Count > 0
            && !string.IsNullOrEmpty(finding.Category)
            && window.SuppressedCategories.Any(c =>
                string.Equals(c, finding.Category, StringComparison.OrdinalIgnoreCase)))
            return true;

        // Severity match
        if (window.SuppressedSeverities.Count > 0
            && window.SuppressedSeverities.Contains(finding.Severity))
            return true;

        // Title pattern match (case-insensitive contains)
        if (window.SuppressedTitlePatterns.Count > 0
            && window.SuppressedTitlePatterns.Any(p =>
                finding.Title.Contains(p, StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }

    private List<MaintenanceWindow> LoadAll()
    {
        if (_cache != null) return _cache;

        if (!File.Exists(_filePath))
        {
            _cache = new List<MaintenanceWindow>();
            return _cache;
        }

        try
        {
            var json = File.ReadAllText(_filePath);
            _cache = JsonSerializer.Deserialize<List<MaintenanceWindow>>(json, JsonOptions) ?? new();
        }
        catch
        {
            _cache = new List<MaintenanceWindow>();
        }
        return _cache;
    }

    private void Save(List<MaintenanceWindow> windows)
    {
        _cache = windows;
        File.WriteAllText(_filePath, JsonSerializer.Serialize(windows, JsonOptions));
    }
}

// --- Models ---

/// <summary>
/// A scheduled maintenance window during which certain findings are suppressed.
/// </summary>
public class MaintenanceWindow
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public DateTimeOffset StartUtc { get; set; }
    public DateTimeOffset EndUtc { get; set; }
    public List<string> SuppressedCategories { get; set; } = new();
    public List<Severity> SuppressedSeverities { get; set; } = new();
    public List<string> SuppressedTitlePatterns { get; set; } = new();
    public bool Recurring { get; set; }
    public int RecurrenceIntervalDays { get; set; }
    public bool Cancelled { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
}

/// <summary>
/// Request to create a maintenance window.
/// </summary>
public class MaintenanceWindowRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public DateTimeOffset StartUtc { get; set; }
    public DateTimeOffset EndUtc { get; set; }
    public List<string>? SuppressedCategories { get; set; }
    public List<Severity>? SuppressedSeverities { get; set; }
    public List<string>? SuppressedTitlePatterns { get; set; }
    public bool Recurring { get; set; }
    public int RecurrenceIntervalDays { get; set; }
    public string? CreatedBy { get; set; }
}

/// <summary>
/// Result of applying maintenance windows to a set of findings.
/// </summary>
public class SuppressionResult
{
    public List<Finding> Kept { get; set; } = new();
    public List<SuppressedFinding> Suppressed { get; set; } = new();
    public int TotalCount => Kept.Count + Suppressed.Count;
    public int SuppressedCount => Suppressed.Count;
    public double SuppressionRate => TotalCount == 0 ? 0 : (double)SuppressedCount / TotalCount;
}

/// <summary>
/// A finding that was suppressed by a maintenance window.
/// </summary>
public class SuppressedFinding
{
    public Finding Finding { get; set; } = null!;
    public string WindowId { get; set; } = string.Empty;
    public string WindowName { get; set; } = string.Empty;
}
