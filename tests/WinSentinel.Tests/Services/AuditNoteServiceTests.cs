using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class AuditNoteServiceTests : IDisposable
{
    private readonly string _tempFile;
    private readonly AuditNoteService _service;

    public AuditNoteServiceTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"winsentinel-notes-test-{Guid.NewGuid():N}.json");
        _service = new AuditNoteService(_tempFile);
    }

    public void Dispose() { if (File.Exists(_tempFile)) File.Delete(_tempFile); }

    [Fact] public void Add_CreatesNote()
    {
        var note = _service.Add("Windows Firewall", "Known issue");
        Assert.Equal("Windows Firewall", note.FindingPattern);
        Assert.Equal(NoteCategory.Comment, note.Category);
        Assert.NotEmpty(note.Id);
    }

    [Fact] public void Add_WithCategory()
    { Assert.Equal(NoteCategory.Deferred, _service.Add("SMBv1", "Deferred", NoteCategory.Deferred).Category); }

    [Fact] public void Add_EmptyPattern_Throws()
    { Assert.Throws<ArgumentException>(() => _service.Add("", "text")); }

    [Fact] public void Add_EmptyText_Throws()
    { Assert.Throws<ArgumentException>(() => _service.Add("p", "")); }

    [Fact] public void GetAll_ReturnsAll()
    { _service.Add("A", "a"); _service.Add("B", "b"); Assert.Equal(2, _service.GetAll().Count); }

    [Fact] public void Get_ById()
    { var n = _service.Add("T", "t"); Assert.Equal(n.Text, _service.Get(n.Id)!.Text); }

    [Fact] public void Get_NotFound() { Assert.Null(_service.Get("x")); }

    [Fact] public void Update_Text()
    {
        var n = _service.Add("P", "old");
        var u = _service.Update(n.Id, newText: "new");
        Assert.Equal("new", u!.Text); Assert.NotNull(u.UpdatedAt);
    }

    [Fact] public void Update_Category()
    { var n = _service.Add("P", "t"); Assert.Equal(NoteCategory.Accepted, _service.Update(n.Id, newCategory: NoteCategory.Accepted)!.Category); }

    [Fact] public void Update_NotFound() { Assert.Null(_service.Update("x", newText: "y")); }

    [Fact] public void Remove_Works()
    { var n = _service.Add("T", "t"); Assert.True(_service.Remove(n.Id)); Assert.Empty(_service.GetAll()); }

    [Fact] public void Remove_NotFound() { Assert.False(_service.Remove("x")); }

    [Fact] public void Clear_All()
    { _service.Add("A", "a"); _service.Add("B", "b"); Assert.Equal(2, _service.Clear()); Assert.Empty(_service.GetAll()); }

    [Fact] public void Search_ByText()
    { _service.Add("F", "Known"); _service.Add("S", "Fix"); var r = _service.Search("known"); Assert.Single(r.Notes); Assert.Equal(2, r.TotalNotes); }

    [Fact] public void Search_ByPattern()
    { _service.Add("Firewall", "n"); Assert.Single(_service.Search("fire").Notes); }

    [Fact] public void Match_Findings()
    {
        _service.Add("Firewall", "risk"); _service.Add("SMB", "defer");
        var f = new List<(string, string, string)> { ("Windows Firewall disabled", "FW", "Critical"), ("AV outdated", "Def", "Warn") };
        var m = _service.Match(f); Assert.Single(m); Assert.Equal("Windows Firewall disabled", m[0].FindingTitle);
    }

    [Fact] public void Match_ModuleFilter()
    {
        _service.Add("Firewall", "n", module: "Network");
        var f = new List<(string, string, string)> { ("Firewall disabled", "FW", "Crit") };
        Assert.Empty(_service.Match(f));
    }

    [Fact] public void Stats()
    {
        _service.Add("A", "a"); _service.Add("B", "b", NoteCategory.Accepted, pinned: true); _service.Add("C", "c", NoteCategory.Accepted);
        var s = _service.GetStats(); Assert.Equal(3, s.TotalNotes); Assert.Equal(1, s.PinnedNotes); Assert.Equal(2, s.ByCategory["Accepted"]);
    }

    [Fact] public void GetByCategory()
    { _service.Add("A", "a"); _service.Add("B", "b", NoteCategory.Deferred); Assert.Single(_service.GetByCategory(NoteCategory.Deferred)); }

    [Fact] public void GetPinned()
    { _service.Add("A", "a", pinned: true); _service.Add("B", "b"); Assert.Single(_service.GetPinned()); }

    [Fact] public void Persistence()
    { _service.Add("T", "persisted"); var s2 = new AuditNoteService(_tempFile); Assert.Single(s2.GetAll()); Assert.Equal("persisted", s2.GetAll()[0].Text); }
}
