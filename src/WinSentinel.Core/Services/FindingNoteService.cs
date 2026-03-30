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

    /// <summary>
    /// Initialises a new <see cref="FindingNoteService"/>, loading any previously
    /// persisted investigations from disk.
    /// </summary>
    /// <param name="filePath">
    /// Optional path to the JSON data file. When <c>null</c>, the default
    /// AppData location is used (see <see cref="GetDefaultFilePath"/>).
    /// </param>
    public FindingNoteService(string? filePath = null)
    {
        _filePath = filePath ?? GetDefaultFilePath();
        _investigations = Load();
    }

    /// <summary>
    /// Returns the default file path for persisting investigation data
    /// (<c>%LOCALAPPDATA%\WinSentinel\finding-notes.json</c>).
    /// </summary>
    public static string GetDefaultFilePath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(appData, "WinSentinel", "finding-notes.json");
    }

    private static string MakeKey(string title, string module)
        => $"{module.ToLowerInvariant()}::{title.ToLowerInvariant()}";

    /// <summary>
    /// Sets the workflow status of a finding's investigation, creating the
    /// investigation record if it does not already exist. A system note is
    /// automatically appended when the status actually changes.
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <param name="status">The new <see cref="FindingStatus"/> to assign.</param>
    /// <returns>The updated <see cref="FindingInvestigation"/> record.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="findingTitle"/> or <paramref name="moduleName"/> is null or whitespace.</exception>
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

    /// <summary>
    /// Adds a free-text investigation note to a finding. The note is prepended
    /// to the investigation's note list (most-recent-first order).
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <param name="noteText">The note content. Must not be null or whitespace.</param>
    /// <param name="author">Optional author name; defaults to the current OS user.</param>
    /// <returns>The newly created <see cref="FindingNote"/>.</returns>
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

    /// <summary>
    /// Removes a specific note from a finding's investigation by note ID.
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <param name="noteId">The unique identifier of the note to remove.</param>
    /// <returns><c>true</c> if a note was removed; <c>false</c> if the investigation or note was not found.</returns>
    public bool RemoveNote(string findingTitle, string moduleName, string noteId)
    {
        var key = MakeKey(findingTitle, moduleName);
        if (!_investigations.TryGetValue(key, out var inv)) return false;
        var removed = inv.Notes.RemoveAll(n => n.Id.Equals(noteId, StringComparison.OrdinalIgnoreCase));
        if (removed > 0) { inv.LastUpdated = DateTimeOffset.UtcNow; Save(); }
        return removed > 0;
    }

    /// <summary>
    /// Assigns or clears the owner/assignee of a finding's investigation.
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <param name="assignee">The assignee name, or <c>null</c>/whitespace to clear the assignment.</param>
    /// <returns>The updated <see cref="FindingInvestigation"/> record.</returns>
    public FindingInvestigation SetAssignee(string findingTitle, string moduleName, string? assignee)
    {
        var inv = GetOrCreate(findingTitle, moduleName);
        inv.Assignee = string.IsNullOrWhiteSpace(assignee) ? null : assignee;
        inv.LastUpdated = DateTimeOffset.UtcNow;
        Save();
        return inv;
    }

    /// <summary>
    /// Sets or clears the due date for a finding's investigation.
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <param name="dueDate">The due date, or <c>null</c> to clear it.</param>
    /// <returns>The updated <see cref="FindingInvestigation"/> record.</returns>
    public FindingInvestigation SetDueDate(string findingTitle, string moduleName, DateTimeOffset? dueDate)
    {
        var inv = GetOrCreate(findingTitle, moduleName);
        inv.DueDate = dueDate;
        inv.LastUpdated = DateTimeOffset.UtcNow;
        Save();
        return inv;
    }

    /// <summary>
    /// Sets or clears the priority of a finding's investigation.
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <param name="priority">Priority value between 1 (highest) and 5 (lowest), or <c>null</c> to clear.</param>
    /// <returns>The updated <see cref="FindingInvestigation"/> record.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="priority"/> is outside the 1–5 range.</exception>
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

    /// <summary>
    /// Retrieves the investigation record for a specific finding, if one exists.
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <returns>The <see cref="FindingInvestigation"/> if found; otherwise <c>null</c>.</returns>
    public FindingInvestigation? Get(string findingTitle, string moduleName)
    {
        var key = MakeKey(findingTitle, moduleName);
        return _investigations.TryGetValue(key, out var inv) ? inv : null;
    }

    /// <summary>
    /// Returns all investigations, ordered by most recently updated first.
    /// </summary>
    public List<FindingInvestigation> GetAll()
        => _investigations.Values.OrderByDescending(i => i.LastUpdated).ToList();

    /// <summary>
    /// Returns all investigations with a specific workflow status, ordered by most recently updated first.
    /// </summary>
    /// <param name="status">The <see cref="FindingStatus"/> to filter by.</param>
    public List<FindingInvestigation> GetByStatus(FindingStatus status)
        => _investigations.Values.Where(i => i.Status == status).OrderByDescending(i => i.LastUpdated).ToList();

    /// <summary>
    /// Returns all investigations whose due date has passed and that are not yet closed,
    /// ordered by due date (earliest first).
    /// </summary>
    public List<FindingInvestigation> GetOverdue()
        => _investigations.Values.Where(i => i.IsOverdue).OrderBy(i => i.DueDate).ToList();

    /// <summary>
    /// Returns all investigations assigned to a specific person (case-insensitive match).
    /// </summary>
    /// <param name="assignee">The assignee name to search for.</param>
    public List<FindingInvestigation> GetByAssignee(string assignee)
        => _investigations.Values
            .Where(i => i.Assignee != null && i.Assignee.Equals(assignee, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(i => i.LastUpdated).ToList();

    /// <summary>
    /// Returns all investigations that are not in a closed state
    /// (<see cref="FindingStatus.Resolved"/> or <see cref="FindingStatus.FalsePositive"/>).
    /// </summary>
    public List<FindingInvestigation> GetOpen()
        => _investigations.Values.Where(i => !i.IsClosed).OrderByDescending(i => i.LastUpdated).ToList();

    /// <summary>
    /// Computes an aggregate summary of all current investigations, including
    /// counts by status, overdue items, and note statistics.
    /// </summary>
    /// <returns>An <see cref="InvestigationSummary"/> snapshot.</returns>
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

    /// <summary>
    /// Permanently deletes a single investigation record.
    /// </summary>
    /// <param name="findingTitle">Title of the security finding.</param>
    /// <param name="moduleName">Name of the audit module that produced the finding.</param>
    /// <returns><c>true</c> if the record was found and deleted; otherwise <c>false</c>.</returns>
    public bool Delete(string findingTitle, string moduleName)
    {
        var key = MakeKey(findingTitle, moduleName);
        if (_investigations.Remove(key)) { Save(); return true; }
        return false;
    }

    /// <summary>
    /// Removes all investigations in a closed state (Resolved or FalsePositive).
    /// </summary>
    /// <returns>The number of investigations purged.</returns>
    public int PurgeClosed()
    {
        var closedKeys = _investigations.Where(kv => kv.Value.IsClosed).Select(kv => kv.Key).ToList();
        foreach (var key in closedKeys) _investigations.Remove(key);
        if (closedKeys.Count > 0) Save();
        return closedKeys.Count;
    }

    /// <summary>
    /// Deletes all investigations, effectively resetting the service.
    /// </summary>
    /// <returns>The number of investigations that were removed.</returns>
    public int ClearAll()
    {
        var count = _investigations.Count;
        _investigations.Clear();
        Save();
        return count;
    }

    /// <summary>
    /// Serialises all current investigations to a JSON string.
    /// Useful for backup or transfer to another machine.
    /// </summary>
    public string ExportJson() => JsonSerializer.Serialize(_investigations.Values.ToList(), s_jsonOptions);

    /// <summary>
    /// Imports investigations from a JSON string, merging them into the
    /// current data set. Existing records with the same key are overwritten.
    /// </summary>
    /// <param name="json">A JSON array of <see cref="FindingInvestigation"/> objects.</param>
    /// <returns>The number of investigations imported.</returns>
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
