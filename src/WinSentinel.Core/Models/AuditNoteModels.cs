namespace WinSentinel.Core.Models;

/// <summary>
/// A user-created annotation attached to a finding by title pattern.
/// </summary>
public class AuditNote
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string FindingPattern { get; set; } = "";
    public string Text { get; set; } = "";
    public string? Module { get; set; }
    public string? Author { get; set; }
    public NoteCategory Category { get; set; } = NoteCategory.Comment;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? UpdatedAt { get; set; }
    public bool Pinned { get; set; }
}

public enum NoteCategory
{
    Comment,
    Accepted,
    Deferred,
    InProgress,
    WontFix,
    FalsePositive
}

public class MatchedNote
{
    public AuditNote Note { get; set; } = null!;
    public string FindingTitle { get; set; } = "";
    public string? FindingModule { get; set; }
    public string? FindingSeverity { get; set; }
}

public class NoteSearchResult
{
    public List<AuditNote> Notes { get; set; } = [];
    public string Query { get; set; } = "";
    public int TotalNotes { get; set; }
}

public class NoteStats
{
    public int TotalNotes { get; set; }
    public int PinnedNotes { get; set; }
    public Dictionary<string, int> ByCategory { get; set; } = new();
    public DateTimeOffset? OldestNote { get; set; }
    public DateTimeOffset? NewestNote { get; set; }
}
