using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Manages investigation notes and workflow status for security findings.
/// Lets users attach notes, set statuses, assign owners, and set due dates.
/// Data persists to JSON in the user's AppData directory.
/// </summary>
public class FindingNoteService
{
    private readonly string _filePath;
    private Dictionary<string, FindingInvestigation> _investigations;

    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public FindingNoteService(string? filePath = null)
    {
        _filePath = filePath ?? GetDefaultFilePath();
        _investigations = Load();
    }

    public static string GetDefaultFilePath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(appData, "WinSentinel", "finding-notes.json");
    }

    private static string MakeKey(string title, string module)
        => $"{module.ToLowerInvariant()}::{title.ToLowerInvariant()}";

    public FindingInvestigation SetStatus(string findingTitle, string moduleName, FindingStatus status)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(findingTitle);
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleName);
        var inv = GetOrCreate(findingTitle, moduleName);
        var oldStatus = inv.Status;
        inv.Status = status;
        inv.LastUpdated = DateTimeOffset.UtcNow;
        if (oldStatus != status)
            inv.Notes.Insert(0, new FindingNote { Text = $"Status changed: {oldStatus} → {status}", Author = "system" });
        Save();
        return inv;
    }

    public FindingNote AddNote(string findingTitle, string moduleName, string noteText, string? author = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(findingTitle);
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleName);
        ArgumentException.ThrowIfNullOrWhiteSpace(noteText);
        var inv = GetOrCreate(findingTitle, moduleName);
        var note = new FindingNote { Text = noteText, Author = author ?? Environment.UserName };
        inv.Notes.Insert(0, note);
        inv.LastUpdated = DateTimeOffset.UtcNow;
        Save();
        return note;
    }

    public bool RemoveNote(string findingTitle, string moduleName, string noteId)
    {
        var key = MakeKey(findingTitle, moduleName);
        if (!_investigations.TryGetValue(key, out var inv)) return false;
        var removed = inv.Notes.RemoveAll(n => n.Id.Equals(noteId, StringComparison.OrdinalIgnoreCase));
        if (removed > 0) { inv.LastUpdated = DateTimeOffset.UtcNow; Save(); }
        return removed > 0;
    }

    public FindingInvestigation SetAssignee(string findingTitle, string moduleName, string? assignee)
    {
        var inv = GetOrCreate(findingTitle, moduleName);
        inv.Assignee = string.IsNullOrWhiteSpace(assignee) ? null : assignee;
        inv.LastUpdated = DateTimeOffset.UtcNow;
        Save();
        return inv;
    }

    public FindingInvestigation SetDueDate(string findingTitle, string moduleName, DateTimeOffset? dueDate)
    {
        var inv = GetOrCreate(findingTitle, moduleName);
        inv.DueDate = dueDate;
        inv.LastUpdated = DateTimeOffset.UtcNow;
        Save();
        return inv;
    }

    public FindingInvestigation SetPriority(string findingTitle, string moduleName, int? priority)
    {
        if (priority.HasValue && (priority.Value < 1 || priority.Value > 5))
            throw new ArgumentOutOfRangeException(nameof(priority), "Priority must be 1-5.");
        var inv = GetOrCreate(findingTitle, moduleName);
        inv.Priority = priority;
        inv.LastUpdated = DateTimeOffset.UtcNow;
        Save();
        return inv;
    }

    public FindingInvestigation? Get(string findingTitle, string moduleName)
    {
        var key = MakeKey(findingTitle, moduleName);
        return _investigations.TryGetValue(key, out var inv) ? inv : null;
    }

    public List<FindingInvestigation> GetAll()
        => _investigations.Values.OrderByDescending(i => i.LastUpdated).ToList();

    public List<FindingInvestigation> GetByStatus(FindingStatus status)
        => _investigations.Values.Where(i => i.Status == status).OrderByDescending(i => i.LastUpdated).ToList();

    public List<FindingInvestigation> GetOverdue()
        => _investigations.Values.Where(i => i.IsOverdue).OrderBy(i => i.DueDate).ToList();

    public List<FindingInvestigation> GetByAssignee(string assignee)
        => _investigations.Values
            .Where(i => i.Assignee != null && i.Assignee.Equals(assignee, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(i => i.LastUpdated).ToList();

    public List<FindingInvestigation> GetOpen()
        => _investigations.Values.Where(i => !i.IsClosed).OrderByDescending(i => i.LastUpdated).ToList();

    public InvestigationSummary GetSummary()
    {
        var all = _investigations.Values.ToList();
        return new InvestigationSummary
        {
            TotalInvestigations = all.Count,
            Open = all.Count(i => i.Status == FindingStatus.Open),
            Investigating = all.Count(i => i.Status == FindingStatus.Investigating),
            InProgress = all.Count(i => i.Status == FindingStatus.InProgress),
            AcceptedRisk = all.Count(i => i.Status == FindingStatus.AcceptedRisk),
            Resolved = all.Count(i => i.Status == FindingStatus.Resolved),
            FalsePositive = all.Count(i => i.Status == FindingStatus.FalsePositive),
            Overdue = all.Count(i => i.IsOverdue),
            WithNotes = all.Count(i => i.Notes.Count > 0),
            TotalNotes = all.Sum(i => i.Notes.Count),
        };
    }

    public bool Delete(string findingTitle, string moduleName)
    {
        var key = MakeKey(findingTitle, moduleName);
        if (_investigations.Remove(key)) { Save(); return true; }
        return false;
    }

    public int PurgeClosed()
    {
        var closedKeys = _investigations.Where(kv => kv.Value.IsClosed).Select(kv => kv.Key).ToList();
        foreach (var key in closedKeys) _investigations.Remove(key);
        if (closedKeys.Count > 0) Save();
        return closedKeys.Count;
    }

    public int ClearAll()
    {
        var count = _investigations.Count;
        _investigations.Clear();
        Save();
        return count;
    }

    public string ExportJson() => JsonSerializer.Serialize(_investigations.Values.ToList(), s_jsonOptions);

    public int ImportJson(string json)
    {
        var imported = JsonSerializer.Deserialize<List<FindingInvestigation>>(json, s_jsonOptions) ?? [];
        int count = 0;
        foreach (var inv in imported) { _investigations[MakeKey(inv.FindingTitle, inv.ModuleName)] = inv; count++; }
        Save();
        return count;
    }

    private FindingInvestigation GetOrCreate(string findingTitle, string moduleName)
    {
        var key = MakeKey(findingTitle, moduleName);
        if (!_investigations.TryGetValue(key, out var inv))
        {
            inv = new FindingInvestigation { FindingTitle = findingTitle, ModuleName = moduleName };
            _investigations[key] = inv;
        }
        return inv;
    }

    private Dictionary<string, FindingInvestigation> Load()
    {
        if (!File.Exists(_filePath))
            return new Dictionary<string, FindingInvestigation>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var json = File.ReadAllText(_filePath);
            var list = JsonSerializer.Deserialize<List<FindingInvestigation>>(json, s_jsonOptions) ?? [];
            var dict = new Dictionary<string, FindingInvestigation>(StringComparer.OrdinalIgnoreCase);
            foreach (var inv in list) dict[MakeKey(inv.FindingTitle, inv.ModuleName)] = inv;
            return dict;
        }
        catch { return new Dictionary<string, FindingInvestigation>(StringComparer.OrdinalIgnoreCase); }
    }

    private void Save()
    {
        var dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(_filePath, JsonSerializer.Serialize(_investigations.Values.ToList(), s_jsonOptions));
    }
}
