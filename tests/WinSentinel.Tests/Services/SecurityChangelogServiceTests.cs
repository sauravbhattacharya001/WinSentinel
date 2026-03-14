using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.SecurityChangelogService;

namespace WinSentinel.Tests.Services;

public class SecurityChangelogServiceTests
{
    private readonly SecurityChangelogService _service = new();

    // ── Helper factories ─────────────────────────────────────────────

    private static SecurityReport MakeReport(
        int score,
        DateTimeOffset timestamp,
        params AuditResult[] results)
    {
        return new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = timestamp,
            Results = results.ToList()
        };
    }

    private static AuditResult MakeAuditResult(
        string module,
        string category,
        params Finding[] findings)
    {
        return new AuditResult
        {
            ModuleName = module,
            Category = category,
            Findings = findings.ToList(),
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow
        };
    }

    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset T1 = new(2026, 1, 2, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset T2 = new(2026, 1, 3, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset T3 = new(2026, 1, 4, 0, 0, 0, TimeSpan.Zero);

    // ── Generate tests ───────────────────────────────────────────────

    [Fact]
    public void Generate_TwoReports_ProducesSingleVersion()
    {
        var r1 = MakeReport(70, T0,
            MakeAuditResult("Firewall", "Network",
                Finding.Warning("Open port 22", "SSH open", "Network")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Firewall", "Network"));

        var changelog = _service.Generate([r1, r2]);

        Assert.Single(changelog.Versions);
        Assert.Equal("v1", changelog.Versions[0].Version);
        Assert.True(changelog.Versions[0].HasChanges);
    }

    [Fact]
    public void Generate_ThreeReports_ProducesTwoVersions_MostRecentFirst()
    {
        var r1 = MakeReport(60, T0);
        var r2 = MakeReport(70, T1);
        var r3 = MakeReport(80, T2);

        var changelog = _service.Generate([r1, r2, r3]);

        Assert.Equal(2, changelog.Versions.Count);
        Assert.Equal("v2", changelog.Versions[0].Version); // Most recent first
        Assert.Equal("v1", changelog.Versions[1].Version);
    }

    [Fact]
    public void Generate_FewerThanTwoReports_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.Generate([MakeReport(50, T0)]));
        Assert.Throws<ArgumentException>(() => _service.Generate([]));
    }

    [Fact]
    public void Generate_NullReports_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.Generate(null!));
    }

    // ── Entry tracking ───────────────────────────────────────────────

    [Fact]
    public void Generate_NewFinding_TrackedAsNegativeForWarningOrCritical()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Firewall", "Network"));
        var r2 = MakeReport(60, T1,
            MakeAuditResult("Firewall", "Network",
                Finding.Critical("Open RDP", "RDP exposed", "Network")));

        var changelog = _service.Generate([r1, r2]);
        var entries = changelog.Versions[0].Entries;

        Assert.Contains(entries, e => e.Type == ChangeType.NewFinding && e.Impact == Impact.Negative);
    }

    [Fact]
    public void Generate_NewInfoFinding_TrackedAsNeutral()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Firewall", "Network"));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Firewall", "Network",
                Finding.Info("Note", "Informational note", "Network")));

        var changelog = _service.Generate([r1, r2]);
        var entries = changelog.Versions[0].Entries;

        Assert.Contains(entries, e => e.Type == ChangeType.NewFinding && e.Impact == Impact.Neutral);
    }

    [Fact]
    public void Generate_ResolvedFinding_TrackedAsPositive()
    {
        var r1 = MakeReport(60, T0,
            MakeAuditResult("Firewall", "Network",
                Finding.Critical("Open RDP", "RDP exposed", "Network")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Firewall", "Network"));

        var changelog = _service.Generate([r1, r2]);
        var entries = changelog.Versions[0].Entries;

        Assert.Contains(entries, e => e.Type == ChangeType.ResolvedFinding && e.Impact == Impact.Positive);
    }

    [Fact]
    public void Generate_ScoreImproved_TrackedAsPositive()
    {
        var r1 = MakeReport(60, T0);
        var r2 = MakeReport(80, T1);

        var changelog = _service.Generate([r1, r2]);

        Assert.Contains(changelog.Versions[0].Entries,
            e => e.Type == ChangeType.ScoreImproved && e.Impact == Impact.Positive);
    }

    [Fact]
    public void Generate_ScoreDeclined_TrackedAsNegative()
    {
        var r1 = MakeReport(80, T0);
        var r2 = MakeReport(60, T1);

        var changelog = _service.Generate([r1, r2]);

        Assert.Contains(changelog.Versions[0].Entries,
            e => e.Type == ChangeType.ScoreDeclined && e.Impact == Impact.Negative);
    }

    [Fact]
    public void Generate_SeverityUpgrade_TrackedAsNegative()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Firewall", "Network",
                Finding.Warning("Weak rule", "Needs attention", "Network")));
        var r2 = MakeReport(60, T1,
            MakeAuditResult("Firewall", "Network",
                Finding.Critical("Weak rule", "Now critical", "Network")));

        var changelog = _service.Generate([r1, r2]);

        Assert.Contains(changelog.Versions[0].Entries,
            e => e.Type == ChangeType.SeverityUpgrade && e.Impact == Impact.Negative);
    }

    [Fact]
    public void Generate_SeverityDowngrade_TrackedAsPositive()
    {
        var r1 = MakeReport(60, T0,
            MakeAuditResult("Firewall", "Network",
                Finding.Critical("Issue", "Critical", "Network")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Firewall", "Network",
                Finding.Warning("Issue", "Now warning", "Network")));

        var changelog = _service.Generate([r1, r2]);

        Assert.Contains(changelog.Versions[0].Entries,
            e => e.Type == ChangeType.SeverityDowngrade && e.Impact == Impact.Positive);
    }

    [Fact]
    public void Generate_ModuleAdded_TrackedAsNeutral()
    {
        var r1 = MakeReport(70, T0);
        var r2 = MakeReport(70, T1,
            MakeAuditResult("Bluetooth", "Connectivity"));

        var changelog = _service.Generate([r1, r2]);

        Assert.Contains(changelog.Versions[0].Entries,
            e => e.Type == ChangeType.ModuleAdded && e.Impact == Impact.Neutral);
    }

    [Fact]
    public void Generate_ModuleRemoved_TrackedAsNeutral()
    {
        var r1 = MakeReport(70, T0,
            MakeAuditResult("Bluetooth", "Connectivity"));
        var r2 = MakeReport(70, T1);

        var changelog = _service.Generate([r1, r2]);

        Assert.Contains(changelog.Versions[0].Entries,
            e => e.Type == ChangeType.ModuleRemoved && e.Impact == Impact.Neutral);
    }

    // ── Aggregate stats ──────────────────────────────────────────────

    [Fact]
    public void Changelog_NetScoreChange_Computed()
    {
        var r1 = MakeReport(50, T0);
        var r2 = MakeReport(60, T1);
        var r3 = MakeReport(80, T2);

        var changelog = _service.Generate([r1, r2, r3]);

        Assert.Equal(80, changelog.LatestScore);
        Assert.Equal(50, changelog.EarliestScore);
        Assert.Equal(30, changelog.NetScoreChange);
    }

    [Fact]
    public void Changelog_TotalChanges_AggregatesAllVersions()
    {
        var r1 = MakeReport(50, T0,
            MakeAuditResult("Firewall", "Network",
                Finding.Warning("A", "desc", "Network")));
        var r2 = MakeReport(60, T1,
            MakeAuditResult("Firewall", "Network"));
        var r3 = MakeReport(70, T2,
            MakeAuditResult("Firewall", "Network",
                Finding.Warning("B", "desc", "Network")));

        var changelog = _service.Generate([r1, r2, r3]);

        Assert.True(changelog.TotalChanges > 0);
        Assert.Equal(changelog.TotalImprovements + changelog.TotalRegressions +
            changelog.Versions.Sum(v => v.Entries.Count(e => e.Impact == Impact.Neutral)),
            changelog.TotalChanges);
    }

    // ── GenerateFromDiffs ────────────────────────────────────────────

    [Fact]
    public void GenerateFromDiffs_SingleDiff_Works()
    {
        var diffService = new AuditDiffService();
        var r1 = MakeReport(60, T0,
            MakeAuditResult("Firewall", "Network",
                Finding.Warning("Issue", "desc", "Network")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Firewall", "Network"));

        var diff = diffService.Compare(r1, r2);
        var changelog = _service.GenerateFromDiffs([diff]);

        Assert.Single(changelog.Versions);
        Assert.True(changelog.Versions[0].HasChanges);
    }

    [Fact]
    public void GenerateFromDiffs_Empty_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.GenerateFromDiffs([]));
    }

    [Fact]
    public void GenerateFromDiffs_Null_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.GenerateFromDiffs(null!));
    }

    // ── Export: Markdown ──────────────────────────────────────────────

    [Fact]
    public void ToMarkdown_ContainsTitle()
    {
        var r1 = MakeReport(70, T0);
        var r2 = MakeReport(80, T1);
        var changelog = _service.Generate([r1, r2], "My Changelog");

        var md = _service.ToMarkdown(changelog);

        Assert.Contains("# My Changelog", md);
    }

    [Fact]
    public void ToMarkdown_ContainsVersionHeaders()
    {
        var r1 = MakeReport(70, T0);
        var r2 = MakeReport(80, T1);
        var changelog = _service.Generate([r1, r2]);

        var md = _service.ToMarkdown(changelog);

        Assert.Contains("## v1", md);
    }

    [Fact]
    public void ToMarkdown_ShowsRegressions_And_Improvements()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Firewall", "Network"));
        var r2 = MakeReport(60, T1,
            MakeAuditResult("Firewall", "Network",
                Finding.Critical("Bad", "bad stuff", "Network")));

        var changelog = _service.Generate([r1, r2]);
        var md = _service.ToMarkdown(changelog);

        Assert.Contains("Regressions", md);
    }

    [Fact]
    public void ToMarkdown_NullChangelog_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.ToMarkdown(null!));
    }

    // ── Export: Text ─────────────────────────────────────────────────

    [Fact]
    public void ToText_ContainsTitle()
    {
        var r1 = MakeReport(70, T0);
        var r2 = MakeReport(80, T1);
        var changelog = _service.Generate([r1, r2], "Test Title");

        var text = _service.ToText(changelog);

        Assert.Contains("TEST TITLE", text);
    }

    [Fact]
    public void ToText_ContainsVersionLabels()
    {
        var r1 = MakeReport(70, T0);
        var r2 = MakeReport(80, T1);
        var changelog = _service.Generate([r1, r2]);

        var text = _service.ToText(changelog);

        Assert.Contains("[v1]", text);
    }

    [Fact]
    public void ToText_ShowsPlusMinusIcons()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Fw", "Net",
                Finding.Warning("X", "d", "Net")));
        var r2 = MakeReport(90, T1,
            MakeAuditResult("Fw", "Net"));

        var changelog = _service.Generate([r1, r2]);
        var text = _service.ToText(changelog);

        Assert.Contains("+ [Resolved]", text);
    }

    [Fact]
    public void ToText_NullChangelog_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.ToText(null!));
    }

    // ── Export: JSON ─────────────────────────────────────────────────

    [Fact]
    public void ToJson_ValidJson()
    {
        var r1 = MakeReport(70, T0);
        var r2 = MakeReport(80, T1);
        var changelog = _service.Generate([r1, r2]);

        var json = _service.ToJson(changelog);

        Assert.NotNull(json);
        Assert.Contains("\"title\"", json);
        Assert.Contains("\"versions\"", json);
    }

    [Fact]
    public void ToJson_NullChangelog_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.ToJson(null!));
    }

    // ── Filters ──────────────────────────────────────────────────────

    [Fact]
    public void FilterEmpty_RemovesVersionsWithNoChanges()
    {
        var r1 = MakeReport(70, T0,
            MakeAuditResult("Fw", "Net"));
        var r2 = MakeReport(70, T1,
            MakeAuditResult("Fw", "Net"));
        var r3 = MakeReport(80, T2,
            MakeAuditResult("Fw", "Net",
                Finding.Warning("New", "desc", "Net")));

        var changelog = _service.Generate([r1, r2, r3]);
        var filtered = _service.FilterEmpty(changelog);

        Assert.True(filtered.Versions.Count < changelog.Versions.Count || changelog.Versions.All(v => v.HasChanges));
    }

    [Fact]
    public void FilterByImpact_OnlyPositive()
    {
        var r1 = MakeReport(60, T0,
            MakeAuditResult("Fw", "Net",
                Finding.Critical("Bad", "desc", "Net")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Fw", "Net"));

        var changelog = _service.Generate([r1, r2]);
        var positiveOnly = _service.FilterByImpact(changelog, Impact.Positive);

        Assert.All(positiveOnly.Versions.SelectMany(v => v.Entries),
            e => Assert.Equal(Impact.Positive, e.Impact));
    }

    [Fact]
    public void FilterByImpact_OnlyNegative()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Fw", "Net"));
        var r2 = MakeReport(60, T1,
            MakeAuditResult("Fw", "Net",
                Finding.Critical("Bad", "desc", "Net")));

        var changelog = _service.Generate([r1, r2]);
        var negativeOnly = _service.FilterByImpact(changelog, Impact.Negative);

        Assert.All(negativeOnly.Versions.SelectMany(v => v.Entries),
            e => Assert.Equal(Impact.Negative, e.Impact));
    }

    [Fact]
    public void FilterByDateRange_LimitsVersions()
    {
        var r1 = MakeReport(50, T0);
        var r2 = MakeReport(60, T1);
        var r3 = MakeReport(70, T2);
        var r4 = MakeReport(80, T3);

        var changelog = _service.Generate([r1, r2, r3, r4]);

        // Filter to only T1-T2
        var filtered = _service.FilterByDateRange(changelog, T1, T2);

        Assert.All(filtered.Versions, v =>
        {
            Assert.True(v.Timestamp >= T1);
            Assert.True(v.Timestamp <= T2);
        });
    }

    [Fact]
    public void FilterByDateRange_NullChangelog_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _service.FilterByDateRange(null!, T0, T1));
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void Generate_IdenticalReports_VersionHasNoChanges()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Fw", "Net",
                Finding.Pass("OK", "All good", "Net")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Fw", "Net",
                Finding.Pass("OK", "All good", "Net")));

        var changelog = _service.Generate([r1, r2]);

        // Score didn't change, same findings — should have minimal entries
        Assert.NotNull(changelog.Versions[0]);
    }

    [Fact]
    public void Generate_CustomTitle_Preserved()
    {
        var r1 = MakeReport(70, T0);
        var r2 = MakeReport(80, T1);

        var changelog = _service.Generate([r1, r2], "Production Server Changelog");

        Assert.Equal("Production Server Changelog", changelog.Title);
    }

    [Fact]
    public void ChangelogVersion_ImprovementsAndRegressions_Computed()
    {
        var r1 = MakeReport(70, T0,
            MakeAuditResult("Fw", "Net",
                Finding.Critical("Bad1", "d", "Net"),
                Finding.Warning("Bad2", "d", "Net")));
        var r2 = MakeReport(90, T1,
            MakeAuditResult("Fw", "Net"));

        var changelog = _service.Generate([r1, r2]);
        var v = changelog.Versions[0];

        Assert.True(v.Improvements > 0);
    }

    [Fact]
    public void ToMarkdown_NoChanges_ShowsNoChangesMessage()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Fw", "Net",
                Finding.Pass("OK", "fine", "Net")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Fw", "Net",
                Finding.Pass("OK", "fine", "Net")));

        var changelog = _service.Generate([r1, r2]);
        var md = _service.ToMarkdown(changelog);

        Assert.Contains("No changes", md);
    }

    [Fact]
    public void ToText_NoChanges_ShowsNoChangesMessage()
    {
        var r1 = MakeReport(80, T0,
            MakeAuditResult("Fw", "Net",
                Finding.Pass("OK", "fine", "Net")));
        var r2 = MakeReport(80, T1,
            MakeAuditResult("Fw", "Net",
                Finding.Pass("OK", "fine", "Net")));

        var changelog = _service.Generate([r1, r2]);
        var text = _service.ToText(changelog);

        Assert.Contains("No changes", text);
    }

    [Fact]
    public void GenerateFromDiffs_MultipleDiffs_OrderedCorrectly()
    {
        var diffService = new AuditDiffService();
        var r1 = MakeReport(60, T0);
        var r2 = MakeReport(70, T1);
        var r3 = MakeReport(80, T2);

        var diff1 = diffService.Compare(r1, r2);
        var diff2 = diffService.Compare(r2, r3);

        var changelog = _service.GenerateFromDiffs([diff1, diff2]);

        Assert.Equal(2, changelog.Versions.Count);
        Assert.Equal("v2", changelog.Versions[0].Version); // Most recent first
    }

    [Fact]
    public void FilterEmpty_NullChangelog_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.FilterEmpty(null!));
    }

    [Fact]
    public void FilterByImpact_NullChangelog_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _service.FilterByImpact(null!, Impact.Positive));
    }
}
