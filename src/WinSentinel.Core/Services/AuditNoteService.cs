using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

public class AuditNoteService
{
    private readonly string _filePath;
    private List<AuditNote>? _cache;

    public AuditNoteService() : this(GetDefaultPath()) { }
    public AuditNoteService(string filePath) { _filePath = filePath; }

    public static string GetDefaultPath()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(local, "WinSentinel", "notes.json");
    }

    public AuditNote Add(string findingPattern, string text,
        NoteCategory category = NoteCategory.Comment,
        string? module = null, string? author = null, bool pinned = false)
    {
        if (string.IsNullOrWhiteSpace(findingPattern))
            throw new ArgumentException("Finding pattern is required.", nameof(findingPattern));
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Note text is required.", nameof(text));

        var notes = Load();
        var note = new AuditNote
        {
            FindingPattern = findingPattern, Text = text, Category = category,
            Module = module, Author = author ?? Environment.UserName, Pinned = pinned
        };
        notes.Add(note);
        Save(notes);
        return note;
    }

    public List<AuditNote> GetAll() => Load();

    public AuditNote? Get(string id) =>
        Load().FirstOrDefault(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    public AuditNote? Update(string id, string? newText = null, NoteCategory? newCategory = null, bool? pinned = null)
    {
        var notes = Load();
        var note = notes.FirstOrDefault(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (note == null) return null;
        if (newText != null) note.Text = newText;
        if (newCategory.HasValue) note.Category = newCategory.Value;
        if (pinned.HasValue) note.Pinned = pinned.Value;
        note.UpdatedAt = DateTimeOffset.UtcNow;
        Save(notes);
        return note;
    }

    public bool Remove(string id)
    {
        var notes = Load();
        var removed = notes.RemoveAll(n => n.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (removed > 0) Save(notes);
        return removed > 0;
    }

    public int Clear()
    {
        var notes = Load();
        var count = notes.Count;
        if (count > 0) Save([]);
        return count;
    }

    public NoteSearchResult Search(string query)
    {
        var all = Load();
        var matched = all.Where(n =>
            n.Text.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            n.FindingPattern.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            (n.Module != null && n.Module.Contains(query, StringComparison.OrdinalIgnoreCase))
        ).ToList();
        return new NoteSearchResult { Notes = matched, Query = query, TotalNotes = all.Count };
    }

    public List<MatchedNote> Match(List<(string Title, string Module, string Severity)> findings)
    {
        var notes = Load();
        if (notes.Count == 0) return [];
        var result = new List<MatchedNote>();
        foreach (var finding in findings)
        {
            foreach (var note in notes)
            {
                if (!finding.Title.Contains(note.FindingPattern, StringComparison.OrdinalIgnoreCase)) continue;
                if (note.Module != null && !finding.Module.Contains(note.Module, StringComparison.OrdinalIgnoreCase)) continue;
                result.Add(new MatchedNote { Note = note, FindingTitle = finding.Title, FindingModule = finding.Module, FindingSeverity = finding.Severity });
            }
        }
        return result;
    }

    public NoteStats GetStats()
    {
        var notes = Load();
        var stats = new NoteStats { TotalNotes = notes.Count, PinnedNotes = notes.Count(n => n.Pinned) };
        foreach (var cat in Enum.GetValues<NoteCategory>())
        {
            var count = notes.Count(n => n.Category == cat);
            if (count > 0) stats.ByCategory[cat.ToString()] = count;
        }
        if (notes.Count > 0) { stats.OldestNote = notes.Min(n => n.CreatedAt); stats.NewestNote = notes.Max(n => n.CreatedAt); }
        return stats;
    }

    public List<AuditNote> GetByCategory(NoteCategory category) => Load().Where(n => n.Category == category).ToList();
    public List<AuditNote> GetPinned() => Load().Where(n => n.Pinned).ToList();

    private List<AuditNote> Load()
    {
        if (_cache != null) return _cache;
        if (!File.Exists(_filePath)) { _cache = []; return _cache; }
        try { var json = File.ReadAllText(_filePath); _cache = JsonSerializer.Deserialize<List<AuditNote>>(json, JsonOpts) ?? []; }
        catch { _cache = []; }
        return _cache;
    }

    private void Save(List<AuditNote> notes)
    {
        _cache = notes;
        var dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(_filePath, JsonSerializer.Serialize(notes, JsonOpts));
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
}
