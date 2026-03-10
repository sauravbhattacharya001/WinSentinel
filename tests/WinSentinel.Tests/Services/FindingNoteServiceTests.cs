using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class FindingNoteServiceTests : IDisposable
{
    private readonly string _tempFile;
    private readonly FindingNoteService _service;

    public FindingNoteServiceTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"winsentinel-notes-test-{Guid.NewGuid():N}.json");
        _service = new FindingNoteService(_tempFile);
    }

    public void Dispose() { try { File.Delete(_tempFile); } catch { } }

    [Fact]
    public void SetStatus_CreatesInvestigation()
    {
        var inv = _service.SetStatus("Open RDP Port", "Firewall", FindingStatus.Investigating);
        Assert.Equal("Open RDP Port", inv.FindingTitle);
        Assert.Equal(FindingStatus.Investigating, inv.Status);
    }

    [Fact]
    public void SetStatus_ChangesStatus_AddsSystemNote()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Investigating);
        var inv = _service.SetStatus("F1", "M1", FindingStatus.InProgress);
        Assert.Equal(FindingStatus.InProgress, inv.Status);
        Assert.Contains(inv.Notes, n => n.Text.Contains("Investigating → InProgress"));
    }

    [Fact]
    public void AddNote_AddsNoteToFinding()
    {
        var note = _service.AddNote("F1", "M1", "Planning fix for Q2");
        Assert.Equal("Planning fix for Q2", note.Text);
        Assert.NotEmpty(note.Id);
        Assert.Single(_service.Get("F1", "M1")!.Notes);
    }

    [Fact]
    public void AddNote_MultipleNotes_NewestFirst()
    {
        _service.AddNote("Test", "Module", "First");
        _service.AddNote("Test", "Module", "Second");
        var inv = _service.Get("Test", "Module")!;
        Assert.Equal("Second", inv.Notes[0].Text);
        Assert.Equal("First", inv.Notes[1].Text);
    }

    [Fact]
    public void RemoveNote_RemovesById()
    {
        var note = _service.AddNote("T", "M", "Remove me");
        Assert.True(_service.RemoveNote("T", "M", note.Id));
        Assert.Empty(_service.Get("T", "M")!.Notes);
    }

    [Fact]
    public void RemoveNote_NonexistentId_ReturnsFalse()
    {
        _service.AddNote("T", "M", "Keep");
        Assert.False(_service.RemoveNote("T", "M", "nope"));
    }

    [Fact]
    public void SetAssignee_SetsAndClears()
    {
        Assert.Equal("alice", _service.SetAssignee("F", "M", "alice").Assignee);
        Assert.Null(_service.SetAssignee("F", "M", null).Assignee);
    }

    [Fact]
    public void SetDueDate_SetsAndClears()
    {
        var due = DateTimeOffset.UtcNow.AddDays(7);
        Assert.Equal(due, _service.SetDueDate("F", "M", due).DueDate);
        Assert.Null(_service.SetDueDate("F", "M", null).DueDate);
    }

    [Fact]
    public void SetPriority_ValidRange()
    {
        Assert.Equal(1, _service.SetPriority("F", "M", 1).Priority);
        Assert.Equal(5, _service.SetPriority("F", "M", 5).Priority);
    }

    [Fact]
    public void SetPriority_InvalidRange_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _service.SetPriority("F", "M", 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => _service.SetPriority("F", "M", 6));
    }

    [Fact]
    public void GetByStatus_FiltersCorrectly()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Investigating);
        _service.SetStatus("F2", "M2", FindingStatus.Resolved);
        _service.SetStatus("F3", "M3", FindingStatus.Investigating);
        Assert.Equal(2, _service.GetByStatus(FindingStatus.Investigating).Count);
        Assert.Single(_service.GetByStatus(FindingStatus.Resolved));
    }

    [Fact]
    public void GetOverdue_ReturnsOnlyOverdueOpenItems()
    {
        _service.SetDueDate("F1", "M1", DateTimeOffset.UtcNow.AddDays(-1));
        _service.SetDueDate("F2", "M2", DateTimeOffset.UtcNow.AddDays(7));
        _service.SetStatus("F3", "M3", FindingStatus.Resolved);
        _service.SetDueDate("F3", "M3", DateTimeOffset.UtcNow.AddDays(-1));
        var overdue = _service.GetOverdue();
        Assert.Single(overdue);
        Assert.Equal("F1", overdue[0].FindingTitle);
    }

    [Fact]
    public void GetByAssignee_CaseInsensitive()
    {
        _service.SetAssignee("F1", "M1", "alice");
        _service.SetAssignee("F2", "M2", "bob");
        _service.SetAssignee("F3", "M3", "Alice");
        Assert.Equal(2, _service.GetByAssignee("alice").Count);
    }

    [Fact]
    public void GetOpen_ExcludesClosedStatuses()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Investigating);
        _service.SetStatus("F2", "M2", FindingStatus.Resolved);
        _service.SetStatus("F3", "M3", FindingStatus.AcceptedRisk);
        _service.SetStatus("F4", "M4", FindingStatus.FalsePositive);
        _service.SetStatus("F5", "M5", FindingStatus.InProgress);
        Assert.Equal(2, _service.GetOpen().Count);
    }

    [Fact]
    public void GetSummary_ReturnsCorrectCounts()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Investigating);
        _service.SetStatus("F2", "M2", FindingStatus.Resolved);
        _service.SetStatus("F3", "M3", FindingStatus.AcceptedRisk);
        _service.AddNote("F1", "M1", "A note");
        var summary = _service.GetSummary();
        Assert.Equal(3, summary.TotalInvestigations);
        Assert.Equal(1, summary.Investigating);
        Assert.Equal(1, summary.Resolved);
        Assert.Equal(1, summary.AcceptedRisk);
    }

    [Fact]
    public void Delete_RemovesInvestigation()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Investigating);
        Assert.True(_service.Delete("F1", "M1"));
        Assert.Null(_service.Get("F1", "M1"));
    }

    [Fact]
    public void PurgeClosed_RemovesOnlyClosed()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Investigating);
        _service.SetStatus("F2", "M2", FindingStatus.Resolved);
        _service.SetStatus("F3", "M3", FindingStatus.FalsePositive);
        Assert.Equal(2, _service.PurgeClosed());
        Assert.Single(_service.GetAll());
    }

    [Fact]
    public void ClearAll_RemovesEverything()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Open);
        _service.SetStatus("F2", "M2", FindingStatus.Open);
        Assert.Equal(2, _service.ClearAll());
        Assert.Empty(_service.GetAll());
    }

    [Fact]
    public void Persistence_SurvivesReload()
    {
        _service.SetStatus("Persist", "FW", FindingStatus.Investigating);
        _service.AddNote("Persist", "FW", "Important");
        _service.SetAssignee("Persist", "FW", "bob");

        var s2 = new FindingNoteService(_tempFile);
        var inv = s2.Get("Persist", "FW");
        Assert.NotNull(inv);
        Assert.Equal(FindingStatus.Investigating, inv!.Status);
        Assert.Equal("bob", inv.Assignee);
    }

    [Fact]
    public void ExportImportJson_RoundTrips()
    {
        _service.SetStatus("F1", "M1", FindingStatus.InProgress);
        _service.AddNote("F1", "M1", "Test");
        var json = _service.ExportJson();

        var tf2 = Path.Combine(Path.GetTempPath(), $"ws-notes-{Guid.NewGuid():N}.json");
        try
        {
            var s2 = new FindingNoteService(tf2);
            Assert.Equal(1, s2.ImportJson(json));
            Assert.Equal(FindingStatus.InProgress, s2.Get("F1", "M1")!.Status);
        }
        finally { try { File.Delete(tf2); } catch { } }
    }

    [Fact]
    public void CaseInsensitive_KeyLookup()
    {
        _service.SetStatus("Open RDP Port", "Firewall", FindingStatus.Investigating);
        Assert.NotNull(_service.Get("open rdp port", "firewall"));
    }

    [Fact]
    public void IsClosed_CorrectForEachStatus()
    {
        _service.SetStatus("F1", "M1", FindingStatus.Open);
        _service.SetStatus("F2", "M2", FindingStatus.Investigating);
        _service.SetStatus("F3", "M3", FindingStatus.InProgress);
        _service.SetStatus("F4", "M4", FindingStatus.AcceptedRisk);
        _service.SetStatus("F5", "M5", FindingStatus.Resolved);
        _service.SetStatus("F6", "M6", FindingStatus.FalsePositive);
        Assert.False(_service.Get("F1", "M1")!.IsClosed);
        Assert.False(_service.Get("F2", "M2")!.IsClosed);
        Assert.False(_service.Get("F3", "M3")!.IsClosed);
        Assert.True(_service.Get("F4", "M4")!.IsClosed);
        Assert.True(_service.Get("F5", "M5")!.IsClosed);
        Assert.True(_service.Get("F6", "M6")!.IsClosed);
    }
}
