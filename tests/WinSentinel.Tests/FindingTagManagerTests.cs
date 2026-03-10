using Xunit;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class FindingTagManagerTests
{
    private static Finding MakeFinding(string title = "Open Port",
        string category = "Firewall", Severity severity = Severity.Warning) =>
        new() { Title = title, Description = "desc", Severity = severity, Category = category };

    // ── Tag operations ───────────────────────────────────────────

    [Fact]
    public void Tag_Creates_Entry_And_Assigns_Tags()
    {
        var mgr = new FindingTagManager();
        var result = mgr.Tag("Open RDP", "Firewall", "team-infra", "sprint-24");

        Assert.Equal(1, mgr.Count);
        Assert.Contains("team-infra", result.Tags);
        Assert.Contains("sprint-24", result.Tags);
        Assert.Equal("Open RDP", result.Title);
        Assert.Equal("Firewall", result.Category);
    }

    [Fact]
    public void Tag_Finding_Instance()
    {
        var mgr = new FindingTagManager();
        var finding = MakeFinding("Weak Cipher", "TLS");
        var result = mgr.Tag(finding, "crypto", "review");

        Assert.Contains("crypto", result.Tags);
        Assert.Equal("Weak Cipher", result.Title);
    }

    [Fact]
    public void Tag_Adds_To_Existing()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("Open RDP", "Firewall", "team-infra");
        mgr.Tag("Open RDP", "Firewall", "urgent");

        var tracked = mgr.Get("Open RDP", "Firewall");
        Assert.NotNull(tracked);
        Assert.Equal(2, tracked!.Tags.Count);
        Assert.Contains("urgent", tracked.Tags);
    }

    [Fact]
    public void Tag_Case_Insensitive()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "Urgent");
        mgr.Tag("F1", "C1", "URGENT");

        var tracked = mgr.Get("F1", "C1");
        Assert.Single(tracked!.Tags); // Same tag, different case
    }

    [Fact]
    public void Tag_Empty_Title_Throws()
    {
        var mgr = new FindingTagManager();
        Assert.Throws<ArgumentException>(() => mgr.Tag("", "Cat", "tag"));
    }

    [Fact]
    public void Tag_No_Tags_Throws()
    {
        var mgr = new FindingTagManager();
        Assert.Throws<ArgumentException>(() => mgr.Tag("F1", "C1"));
    }

    [Fact]
    public void Tag_Null_Finding_Throws()
    {
        var mgr = new FindingTagManager();
        Assert.Throws<ArgumentNullException>(() => mgr.Tag((Finding)null!, "tag"));
    }

    // ── Untag ────────────────────────────────────────────────────

    [Fact]
    public void Untag_Removes_Specific_Tags()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "a", "b", "c");

        var removed = mgr.Untag("F1", "C1", "b");

        Assert.True(removed);
        var tracked = mgr.Get("F1", "C1");
        Assert.Equal(2, tracked!.Tags.Count);
        Assert.DoesNotContain("b", tracked.Tags);
    }

    [Fact]
    public void Untag_Unknown_Finding_Returns_False()
    {
        var mgr = new FindingTagManager();
        Assert.False(mgr.Untag("Unknown", "Cat", "tag"));
    }

    [Fact]
    public void Untag_NonExistent_Tag_Returns_False()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "exists");

        Assert.False(mgr.Untag("F1", "C1", "nope"));
    }

    // ── ClearTags ────────────────────────────────────────────────

    [Fact]
    public void ClearTags_Removes_All()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "a", "b");

        Assert.True(mgr.ClearTags("F1", "C1"));

        var tracked = mgr.Get("F1", "C1");
        Assert.Empty(tracked!.Tags);
    }

    [Fact]
    public void ClearTags_Unknown_Returns_False()
    {
        var mgr = new FindingTagManager();
        Assert.False(mgr.ClearTags("Unknown", "Cat"));
    }

    // ── RenameTag ────────────────────────────────────────────────

    [Fact]
    public void RenameTag_Updates_All_Findings()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "old-name");
        mgr.Tag("F2", "C2", "old-name", "other");
        mgr.Tag("F3", "C3", "unrelated");

        var count = mgr.RenameTag("old-name", "new-name");

        Assert.Equal(2, count);
        Assert.Contains("new-name", mgr.Get("F1", "C1")!.Tags);
        Assert.Contains("new-name", mgr.Get("F2", "C2")!.Tags);
        Assert.DoesNotContain("old-name", mgr.Get("F1", "C1")!.Tags);
    }

    [Fact]
    public void RenameTag_Empty_Old_Throws()
    {
        var mgr = new FindingTagManager();
        Assert.Throws<ArgumentException>(() => mgr.RenameTag("", "new"));
    }

    // ── DeleteTag ────────────────────────────────────────────────

    [Fact]
    public void DeleteTag_Removes_From_All()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "remove-me", "keep");
        mgr.Tag("F2", "C2", "remove-me");

        var count = mgr.DeleteTag("remove-me");

        Assert.Equal(2, count);
        Assert.DoesNotContain("remove-me", mgr.Get("F1", "C1")!.Tags);
        Assert.Contains("keep", mgr.Get("F1", "C1")!.Tags);
    }

    // ── Annotations ──────────────────────────────────────────────

    [Fact]
    public void Annotate_Adds_Note()
    {
        var mgr = new FindingTagManager();
        var result = mgr.Annotate("F1", "C1", "Deferred to Q3", "admin");

        Assert.Single(result.Annotations);
        Assert.Equal("Deferred to Q3", result.Annotations[0].Text);
        Assert.Equal("admin", result.Annotations[0].Author);
    }

    [Fact]
    public void Annotate_Multiple_Notes()
    {
        var mgr = new FindingTagManager();
        mgr.Annotate("F1", "C1", "First note");
        mgr.Annotate("F1", "C1", "Second note");

        var tracked = mgr.Get("F1", "C1");
        Assert.Equal(2, tracked!.Annotations.Count);
    }

    [Fact]
    public void Annotate_Finding_Instance()
    {
        var mgr = new FindingTagManager();
        var finding = MakeFinding();
        var result = mgr.Annotate(finding, "Test note", "user");

        Assert.Single(result.Annotations);
    }

    [Fact]
    public void Annotate_Empty_Text_Throws()
    {
        var mgr = new FindingTagManager();
        Assert.Throws<ArgumentException>(() => mgr.Annotate("F1", "C1", ""));
    }

    [Fact]
    public void Annotate_Creates_Entry_If_New()
    {
        var mgr = new FindingTagManager();
        mgr.Annotate("New Finding", "Cat", "Note here");

        Assert.Equal(1, mgr.Count);
        Assert.Empty(mgr.Get("New Finding", "Cat")!.Tags);
    }

    // ── Queries ──────────────────────────────────────────────────

    [Fact]
    public void GetByTag_Returns_Matching()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "infra");
        mgr.Tag("F2", "C2", "infra", "urgent");
        mgr.Tag("F3", "C3", "dev");

        var results = mgr.GetByTag("infra");

        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void GetByAllTags_Requires_All()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "a", "b");
        mgr.Tag("F2", "C2", "a");

        var results = mgr.GetByAllTags("a", "b");

        Assert.Single(results);
        Assert.Equal("F1", results[0].Title);
    }

    [Fact]
    public void GetByAnyTag_Returns_Union()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "a");
        mgr.Tag("F2", "C2", "b");
        mgr.Tag("F3", "C3", "c");

        var results = mgr.GetByAnyTag("a", "b");

        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void GetAllTags_Returns_Unique_Set()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "alpha", "beta");
        mgr.Tag("F2", "C2", "beta", "gamma");

        var tags = mgr.GetAllTags();

        Assert.Equal(3, tags.Count);
        Assert.Contains("alpha", tags);
        Assert.Contains("gamma", tags);
    }

    [Fact]
    public void GetAnnotated_Returns_Only_Annotated()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "a");
        mgr.Annotate("F2", "C2", "Note");
        mgr.Tag("F3", "C3", "b");
        mgr.Annotate("F3", "C3", "Another note");

        var results = mgr.GetAnnotated();

        Assert.Equal(2, results.Count);
    }

    [Fact]
    public void GetByCategory_Filters()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "Network", "a");
        mgr.Tag("F2", "Firewall", "a");
        mgr.Tag("F3", "Network", "b");

        Assert.Equal(2, mgr.GetByCategory("Network").Count);
    }

    [Fact]
    public void Search_Matches_Title_Category_Tags()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("Open RDP Port", "Firewall", "infra");
        mgr.Tag("Weak Password", "Auth", "sprint-24");

        Assert.Single(mgr.Search("RDP"));
        Assert.Single(mgr.Search("Auth"));
        Assert.Single(mgr.Search("sprint"));
    }

    // ── Remove ───────────────────────────────────────────────────

    [Fact]
    public void Remove_Deletes_Entry()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "tag");

        Assert.True(mgr.Remove("F1", "C1"));
        Assert.Equal(0, mgr.Count);
    }

    [Fact]
    public void Remove_Unknown_Returns_False()
    {
        var mgr = new FindingTagManager();
        Assert.False(mgr.Remove("X", "Y"));
    }

    // ── Bulk operations ──────────────────────────────────────────

    [Fact]
    public void TagFromReport_Tags_NonPass_Findings()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "Firewall",
                    Category = "Network",
                    Findings = new List<Finding>
                    {
                        MakeFinding("Critical Issue", "Network", Severity.Critical),
                        MakeFinding("Info Issue", "Network", Severity.Info),
                        MakeFinding("Pass Check", "Network", Severity.Pass),
                    }
                }
            }
        };

        var mgr = new FindingTagManager();
        var count = mgr.TagFromReport(report, "scan-2026-03");

        Assert.Equal(2, count);  // Pass is skipped
        Assert.Equal(2, mgr.Count);
    }

    [Fact]
    public void AutoTagBySeverity_Assigns_Correct_Tags()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "Mod",
                    Category = "Cat",
                    Findings = new List<Finding>
                    {
                        MakeFinding("C1", "Cat", Severity.Critical),
                        MakeFinding("W1", "Cat", Severity.Warning),
                        MakeFinding("I1", "Cat", Severity.Info),
                        MakeFinding("P1", "Cat", Severity.Pass),
                    }
                }
            }
        };

        var mgr = new FindingTagManager();
        var count = mgr.AutoTagBySeverity(report);

        Assert.Equal(3, count);
        Assert.Contains("urgent", mgr.Get("C1", "Cat")!.Tags);
        Assert.Contains("review-needed", mgr.Get("W1", "Cat")!.Tags);
        Assert.Contains("low-priority", mgr.Get("I1", "Cat")!.Tags);
        Assert.Null(mgr.Get("P1", "Cat"));
    }

    // ── Report ───────────────────────────────────────────────────

    [Fact]
    public void GenerateReport_Counts_Correct()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "a", "b");
        mgr.Tag("F2", "C2", "a");
        mgr.Annotate("F1", "C1", "Note 1");
        mgr.Annotate("F1", "C1", "Note 2");
        mgr.Annotate("F3", "C3", "Note 3"); // No tags, just annotation

        var report = mgr.GenerateReport();

        Assert.Equal(3, report.TotalFindings);
        Assert.Equal(2, report.TotalTags);  // "a" and "b"
        Assert.Equal(3, report.TotalAnnotations);
        Assert.Equal(2, report.TagCounts["a"]);
        Assert.Equal(1, report.TagCounts["b"]);
        Assert.Equal(1, report.UntaggedCount);  // F3 has no tags
    }

    [Fact]
    public void GenerateReport_Empty_Manager()
    {
        var mgr = new FindingTagManager();
        var report = mgr.GenerateReport();

        Assert.Equal(0, report.TotalFindings);
        Assert.Equal(0, report.TotalTags);
    }

    // ── Export / Import ──────────────────────────────────────────

    [Fact]
    public void ExportJson_RoundTrips()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "alpha", "beta");
        mgr.Annotate("F1", "C1", "Important note", "admin");
        mgr.Tag("F2", "C2", "gamma");

        var json = mgr.ExportJson();

        var mgr2 = new FindingTagManager();
        var count = mgr2.ImportJson(json);

        Assert.Equal(2, count);
        Assert.Equal(2, mgr2.Count);

        var f1 = mgr2.Get("F1", "C1");
        Assert.NotNull(f1);
        Assert.Equal(2, f1!.Tags.Count);
        Assert.Single(f1.Annotations);
        Assert.Equal("Important note", f1.Annotations[0].Text);
        Assert.Equal("admin", f1.Annotations[0].Author);
    }

    [Fact]
    public void ImportJson_Merge_Combines_Tags()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "existing");

        var json = "{\"findings\":[{\"Title\":\"F1\",\"Category\":\"C1\"," +
            "\"Tags\":[\"new-tag\"],\"Annotations\":[],\"FirstTaggedAt\":\"2026-01-01T00:00:00Z\"," +
            "\"LastModifiedAt\":\"2026-01-01T00:00:00Z\"}]}";

        mgr.ImportJson(json, merge: true);

        var f = mgr.Get("F1", "C1");
        Assert.Equal(2, f!.Tags.Count);
        Assert.Contains("existing", f.Tags);
        Assert.Contains("new-tag", f.Tags);
    }

    [Fact]
    public void ImportJson_No_Findings_Throws()
    {
        var mgr = new FindingTagManager();
        Assert.Throws<ArgumentException>(() => mgr.ImportJson("{}"));
    }

    [Fact]
    public void ImportJson_Overwrite_Replaces()
    {
        var mgr = new FindingTagManager();
        mgr.Tag("F1", "C1", "old-tag");

        var json = "{\"findings\":[{\"Title\":\"F1\",\"Category\":\"C1\"," +
            "\"Tags\":[\"replaced\"],\"Annotations\":[],\"FirstTaggedAt\":\"2026-01-01T00:00:00Z\"," +
            "\"LastModifiedAt\":\"2026-01-01T00:00:00Z\"}]}";

        mgr.ImportJson(json, merge: false);

        var f = mgr.Get("F1", "C1");
        Assert.Single(f!.Tags);
        Assert.Contains("replaced", f.Tags);
    }
}
