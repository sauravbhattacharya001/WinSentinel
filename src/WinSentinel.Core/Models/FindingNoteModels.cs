using System.Text.Json.Serialization;

namespace WinSentinel.Core.Models;

/// <summary>Workflow status for a security finding under investigation.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FindingStatus
{
    Open, Investigating, InProgress, AcceptedRisk, Resolved, FalsePositive,
}

/// <summary>A single investigation note attached to a finding.</summary>
public class FindingNote
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..8];
    public string Text { get; init; } = "";
    public string Author { get; init; } = Environment.UserName;
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>Investigation record for a specific finding.</summary>
public class FindingInvestigation
{
    public string FindingTitle { get; init; } = "";
    public string ModuleName { get; init; } = "";
    public FindingStatus Status { get; set; } = FindingStatus.Open;
    public string? Assignee { get; set; }
    public int? Priority { get; set; }
    public DateTimeOffset? DueDate { get; set; }
    public List<FindingNote> Notes { get; init; } = [];
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastUpdated { get; set; } = DateTimeOffset.UtcNow;
    public bool IsClosed => Status is FindingStatus.Resolved or FindingStatus.AcceptedRisk or FindingStatus.FalsePositive;
    public bool IsOverdue => DueDate.HasValue && !IsClosed && DateTimeOffset.UtcNow > DueDate.Value;
}

/// <summary>Summary statistics for all finding investigations.</summary>
public class InvestigationSummary
{
    public int TotalInvestigations { get; init; }
    public int Open { get; init; }
    public int Investigating { get; init; }
    public int InProgress { get; init; }
    public int AcceptedRisk { get; init; }
    public int Resolved { get; init; }
    public int FalsePositive { get; init; }
    public int Overdue { get; init; }
    public int WithNotes { get; init; }
    public int TotalNotes { get; init; }
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;
}
