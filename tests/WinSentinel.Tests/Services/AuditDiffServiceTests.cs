using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class AuditDiffServiceTests
{
    private readonly AuditDiffService _sut = new();

    // ── Helpers ──────────────────────────────────────────────────────

    private static SecurityReport MakeReport(int score, params AuditResult[] results)
    {
        return new SecurityReport
        {
            SecurityScore = score,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = results.ToList()
        };
    }

    private static AuditResult MakeModule(string name, string category, params Finding[] findings)
    {
        return new AuditResult
        {
            ModuleName = name,
            Category = category,
            Findings = findings.ToList()
        };
    }

    // ── Null checks ─────────────────────────────────────────────────

    [Fact]
    public void Compare_NullOlder_Throws()
    {
        var report = MakeReport(100);
        Assert.Throws<ArgumentNullException>(() => _sut.Compare(null!, report));
    }

    [Fact]
    public void Compare_NullNewer_Throws()
    {
        var report = MakeReport(100);
        Assert.Throws<ArgumentNullException>(() => _sut.Compare(report, null!));
    }

    // ── Identical reports ───────────────────────────────────────────

    [Fact]
    public void Compare_IdenticalReports_IsIdentical()
    {
        var module = MakeModule("Firewall", "Network",
            Finding.Pass("Firewall On", "OK", "Network"),
            Finding.Warning("Port Open", "Port 445 is open", "Network"));
        var older = MakeReport(80, module);
        var newer = MakeReport(80, module);

        var diff = _sut.Compare(older, newer);

        Assert.True(diff.IsIdentical);
        Assert.Equal(0, diff.TotalChanges);
        Assert.Equal(0, diff.ScoreDelta);
        Assert.False(diff.GradeChanged);
        Assert.Empty(diff.NewFindings);
        Assert.Empty(diff.ResolvedFindings);
        Assert.Empty(diff.SeverityChanges);
        Assert.Empty(diff.ModuleChanges);
    }

    [Fact]
    public void Compare_EmptyReports_IsIdentical()
    {
        var older = MakeReport(100);
        var newer = MakeReport(100);

        var diff = _sut.Compare(older, newer);

        Assert.True(diff.IsIdentical);
    }

    // ── New findings ────────────────────────────────────────────────

    [Fact]
    public void Compare_NewFinding_Detected()
    {
        var older = MakeReport(95, MakeModule("Defender", "Security",
            Finding.Pass("Defender Active", "OK", "Security")));
        var newer = MakeReport(75, MakeModule("Defender", "Security",
            Finding.Pass("Defender Active", "OK", "Security"),
            Finding.Critical("Defender Disabled", "Defender is off", "Security")));

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.NewFindings);
        Assert.Equal("Defender Disabled", diff.NewFindings[0].Finding.Title);
        Assert.Equal("Defender", diff.NewFindings[0].Module);
        Assert.Empty(diff.ResolvedFindings);
        Assert.False(diff.IsIdentical);
    }

    [Fact]
    public void Compare_MultipleNewFindings_AllDetected()
    {
        var older = MakeReport(100, MakeModule("Updates", "System"));
        var newer = MakeReport(75, MakeModule("Updates", "System",
            Finding.Warning("KB Missing", "Missing update", "System"),
            Finding.Critical("Critical Update", "Critical update needed", "System")));

        var diff = _sut.Compare(older, newer);

        Assert.Equal(2, diff.NewFindings.Count);
    }

    // ── Resolved findings ───────────────────────────────────────────

    [Fact]
    public void Compare_ResolvedFinding_Detected()
    {
        var older = MakeReport(75, MakeModule("Network", "Network",
            Finding.Warning("SMB Open", "SMB port is open", "Network")));
        var newer = MakeReport(100, MakeModule("Network", "Network"));

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.ResolvedFindings);
        Assert.Equal("SMB Open", diff.ResolvedFindings[0].Finding.Title);
        Assert.Empty(diff.NewFindings);
    }

    [Fact]
    public void Compare_MultipleResolved_AllDetected()
    {
        var older = MakeReport(70, MakeModule("Net", "Network",
            Finding.Warning("A", "desc", "Network"),
            Finding.Critical("B", "desc", "Network"),
            Finding.Warning("C", "desc", "Network")));
        var newer = MakeReport(100, MakeModule("Net", "Network"));

        var diff = _sut.Compare(older, newer);

        Assert.Equal(3, diff.ResolvedFindings.Count);
    }

    // ── Severity changes ────────────────────────────────────────────

    [Fact]
    public void Compare_SeverityChange_Detected()
    {
        var older = MakeReport(95, MakeModule("Firewall", "Network",
            Finding.Warning("Port Open", "Port 445 open", "Network")));
        var newer = MakeReport(80, MakeModule("Firewall", "Network",
            Finding.Critical("Port Open", "Port 445 open — exploitable", "Network")));

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.SeverityChanges);
        var change = diff.SeverityChanges[0];
        Assert.Equal("Port Open", change.Title);
        Assert.Equal(Severity.Warning, change.OldSeverity);
        Assert.Equal(Severity.Critical, change.NewSeverity);
    }

    [Fact]
    public void Compare_SeverityDowngrade_Detected()
    {
        var older = MakeReport(80, MakeModule("M", "C",
            Finding.Critical("Issue", "desc", "C")));
        var newer = MakeReport(95, MakeModule("M", "C",
            Finding.Info("Issue", "desc", "C")));

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.SeverityChanges);
        Assert.Equal(Severity.Critical, diff.SeverityChanges[0].OldSeverity);
        Assert.Equal(Severity.Info, diff.SeverityChanges[0].NewSeverity);
    }

    [Fact]
    public void Compare_SameSeverity_NoChange()
    {
        var older = MakeReport(95, MakeModule("M", "C",
            Finding.Warning("Issue", "desc", "C")));
        var newer = MakeReport(95, MakeModule("M", "C",
            Finding.Warning("Issue", "desc updated", "C")));

        var diff = _sut.Compare(older, newer);

        Assert.Empty(diff.SeverityChanges);
    }

    // ── Module changes ──────────────────────────────────────────────

    [Fact]
    public void Compare_ModuleAdded_Detected()
    {
        var older = MakeReport(100);
        var newer = MakeReport(90, MakeModule("Encryption", "Security",
            Finding.Warning("BitLocker Off", "Not encrypted", "Security")));

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.ModuleChanges);
        Assert.Equal("Encryption", diff.ModuleChanges[0].Module);
        Assert.Equal(AuditDiffService.ChangeKind.Added, diff.ModuleChanges[0].Kind);
        // Finding from the new module should appear in NewFindings
        Assert.Single(diff.NewFindings);
    }

    [Fact]
    public void Compare_ModuleRemoved_Detected()
    {
        var older = MakeReport(90, MakeModule("Browser", "Security",
            Finding.Info("Flash detected", "Flash is installed", "Security")));
        var newer = MakeReport(100);

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.ModuleChanges);
        Assert.Equal(AuditDiffService.ChangeKind.Removed, diff.ModuleChanges[0].Kind);
        Assert.Single(diff.ResolvedFindings);
    }

    // ── Score and grade deltas ──────────────────────────────────────

    [Fact]
    public void Compare_ScoreImproved_PositiveDelta()
    {
        var older = MakeReport(60);
        var newer = MakeReport(85);

        var diff = _sut.Compare(older, newer);

        Assert.Equal(25, diff.ScoreDelta);
        Assert.Equal(60, diff.OldScore);
        Assert.Equal(85, diff.NewScore);
    }

    [Fact]
    public void Compare_ScoreDeclined_NegativeDelta()
    {
        var older = MakeReport(90);
        var newer = MakeReport(50);

        var diff = _sut.Compare(older, newer);

        Assert.Equal(-40, diff.ScoreDelta);
    }

    [Fact]
    public void Compare_GradeChanged_Flagged()
    {
        var older = MakeReport(85);
        var newer = MakeReport(60);

        var diff = _sut.Compare(older, newer);

        Assert.True(diff.GradeChanged);
        Assert.NotEqual(diff.OldGrade, diff.NewGrade);
    }

    [Fact]
    public void Compare_GradeUnchanged_NotFlagged()
    {
        // Both scores in grade "A" range (>= 90)
        var older = MakeReport(95);
        var newer = MakeReport(92);

        var diff = _sut.Compare(older, newer);

        Assert.False(diff.GradeChanged);
    }

    // ── Critical/warning deltas ─────────────────────────────────────

    [Fact]
    public void Compare_CriticalAdded_PositiveDelta()
    {
        var older = MakeReport(100, MakeModule("M", "C"));
        var newer = MakeReport(80, MakeModule("M", "C",
            Finding.Critical("X", "desc", "C")));

        var diff = _sut.Compare(older, newer);

        Assert.Equal(1, diff.CriticalDelta);
    }

    [Fact]
    public void Compare_WarningResolved_NegativeDelta()
    {
        var older = MakeReport(90, MakeModule("M", "C",
            Finding.Warning("W1", "desc", "C"),
            Finding.Warning("W2", "desc", "C")));
        var newer = MakeReport(100, MakeModule("M", "C"));

        var diff = _sut.Compare(older, newer);

        Assert.Equal(-2, diff.WarningDelta);
    }

    // ── Per-module score deltas ─────────────────────────────────────

    [Fact]
    public void Compare_ModuleScoreDeltas_Computed()
    {
        var older = MakeReport(80, MakeModule("Firewall", "Network",
            Finding.Warning("Rule Missing", "desc", "Network")));
        var newer = MakeReport(100, MakeModule("Firewall", "Network",
            Finding.Pass("All Good", "desc", "Network")));

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.ModuleDeltas);
        var md = diff.ModuleDeltas[0];
        Assert.Equal("Firewall", md.Module);
        Assert.True(md.Delta > 0); // Score should have improved
    }

    [Fact]
    public void Compare_ModuleScoreDelta_FindingCounts()
    {
        var older = MakeReport(80, MakeModule("M", "C",
            Finding.Warning("A", "desc", "C"),
            Finding.Warning("B", "desc", "C")));
        var newer = MakeReport(95, MakeModule("M", "C",
            Finding.Pass("A", "desc", "C")));

        var diff = _sut.Compare(older, newer);

        var md = diff.ModuleDeltas[0];
        Assert.Equal(2, md.OldFindingCount);
        Assert.Equal(1, md.NewFindingCount);
    }

    // ── Mixed changes ───────────────────────────────────────────────

    [Fact]
    public void Compare_MixedChanges_AllCaptured()
    {
        var older = MakeReport(70,
            MakeModule("Defender", "Security",
                Finding.Warning("Scan Outdated", "Last scan > 7d ago", "Security"),
                Finding.Pass("RTP On", "Real-time enabled", "Security")),
            MakeModule("Updates", "System",
                Finding.Critical("Missing KB", "KB5001234 missing", "System")));

        var newer = MakeReport(85,
            MakeModule("Defender", "Security",
                Finding.Pass("Scan Recent", "Scanned today", "Security"),  // severity change (Warning → resolved + new Pass)
                Finding.Pass("RTP On", "Real-time enabled", "Security"),
                Finding.Warning("Exclusion Risk", "Too many exclusions", "Security")),  // new
            MakeModule("Updates", "System"));  // Critical resolved

        var diff = _sut.Compare(older, newer);

        Assert.False(diff.IsIdentical);
        Assert.True(diff.TotalChanges > 0);
        // "Missing KB" resolved
        Assert.Contains(diff.ResolvedFindings, rf => rf.Finding.Title == "Missing KB");
        // "Exclusion Risk" is new
        Assert.Contains(diff.NewFindings, nf => nf.Finding.Title == "Exclusion Risk");
    }

    // ── Case-insensitive matching ───────────────────────────────────

    [Fact]
    public void Compare_CaseInsensitiveModuleName_Matches()
    {
        var older = MakeReport(90, MakeModule("Firewall", "Network",
            Finding.Warning("Open Port", "desc", "Network")));
        var newer = MakeReport(95, MakeModule("firewall", "Network",
            Finding.Pass("Open Port", "desc", "Network")));

        var diff = _sut.Compare(older, newer);

        // Should match as same module, not add + remove
        Assert.Empty(diff.ModuleChanges);
        Assert.Single(diff.SeverityChanges); // Warning → Pass
    }

    [Fact]
    public void Compare_CaseInsensitiveFindingTitle_Matches()
    {
        var older = MakeReport(90, MakeModule("M", "C",
            Finding.Warning("Port Open", "desc", "C")));
        var newer = MakeReport(90, MakeModule("M", "C",
            Finding.Critical("port open", "desc", "C")));

        var diff = _sut.Compare(older, newer);

        Assert.Single(diff.SeverityChanges);
        Assert.Empty(diff.NewFindings);
        Assert.Empty(diff.ResolvedFindings);
    }

    // ── Duplicate-titled findings ───────────────────────────────────

    [Fact]
    public void Compare_DuplicateTitles_CountDiffHandled()
    {
        var older = MakeReport(85, MakeModule("M", "C",
            Finding.Warning("Weak Config", "Issue 1", "C"),
            Finding.Warning("Weak Config", "Issue 2", "C")));
        var newer = MakeReport(90, MakeModule("M", "C",
            Finding.Warning("Weak Config", "Issue 1", "C")));

        var diff = _sut.Compare(older, newer);

        // One of the two duplicate findings was resolved
        Assert.Single(diff.ResolvedFindings);
        Assert.Equal("Weak Config", diff.ResolvedFindings[0].Finding.Title);
    }

    [Fact]
    public void Compare_DuplicateTitles_NewOnesDetected()
    {
        var older = MakeReport(95, MakeModule("M", "C",
            Finding.Warning("Cfg", "a", "C")));
        var newer = MakeReport(85, MakeModule("M", "C",
            Finding.Warning("Cfg", "a", "C"),
            Finding.Warning("Cfg", "b", "C"),
            Finding.Warning("Cfg", "c", "C")));

        var diff = _sut.Compare(older, newer);

        Assert.Equal(2, diff.NewFindings.Count);
    }

    // ── Timestamps ──────────────────────────────────────────────────

    [Fact]
    public void Compare_Timestamps_Preserved()
    {
        var t1 = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var t2 = new DateTimeOffset(2026, 1, 2, 12, 0, 0, TimeSpan.Zero);
        var older = new SecurityReport { GeneratedAt = t1, SecurityScore = 80 };
        var newer = new SecurityReport { GeneratedAt = t2, SecurityScore = 85 };

        var diff = _sut.Compare(older, newer);

        Assert.Equal(t1, diff.OlderTimestamp);
        Assert.Equal(t2, diff.NewerTimestamp);
        Assert.Equal(TimeSpan.FromDays(1), diff.Elapsed);
    }

    // ── Summary ─────────────────────────────────────────────────────

    [Fact]
    public void Summary_IdenticalReports_NoChangesMessage()
    {
        var r = MakeReport(100);
        var diff = _sut.Compare(r, r);
        Assert.Contains("No changes", diff.Summary());
    }

    [Fact]
    public void Summary_ScoreImproved_ShowsImproved()
    {
        var older = MakeReport(60);
        var newer = MakeReport(85);
        var diff = _sut.Compare(older, newer);
        var summary = diff.Summary();
        Assert.Contains("improved", summary);
        Assert.Contains("25", summary);
    }

    [Fact]
    public void Summary_ScoreDeclined_ShowsDeclined()
    {
        var older = MakeReport(90);
        var newer = MakeReport(50);
        var diff = _sut.Compare(older, newer);
        Assert.Contains("declined", diff.Summary());
    }

    [Fact]
    public void Summary_NewFindings_ShowsCount()
    {
        var older = MakeReport(100, MakeModule("M", "C"));
        var newer = MakeReport(80, MakeModule("M", "C",
            Finding.Warning("A", "d", "C"),
            Finding.Warning("B", "d", "C")));
        var diff = _sut.Compare(older, newer);
        Assert.Contains("+2 new finding", diff.Summary());
    }

    [Fact]
    public void Summary_ResolvedFindings_ShowsCount()
    {
        var older = MakeReport(80, MakeModule("M", "C",
            Finding.Critical("X", "d", "C")));
        var newer = MakeReport(100, MakeModule("M", "C"));
        var diff = _sut.Compare(older, newer);
        Assert.Contains("-1 resolved finding", diff.Summary());
    }

    [Fact]
    public void Summary_ModuleAdded_ShowsModule()
    {
        var older = MakeReport(100);
        var newer = MakeReport(95, MakeModule("Privacy", "Privacy"));
        var diff = _sut.Compare(older, newer);
        Assert.Contains("Added module: Privacy", diff.Summary());
    }

    // ── TotalChanges ────────────────────────────────────────────────

    [Fact]
    public void TotalChanges_SumsAllChangeTypes()
    {
        var older = MakeReport(80,
            MakeModule("A", "C1", Finding.Warning("F1", "d", "C1")),
            MakeModule("B", "C2"));
        var newer = MakeReport(75,
            MakeModule("A", "C1"),  // F1 resolved
            MakeModule("B", "C2", Finding.Critical("F2", "d", "C2")),  // F2 new
            MakeModule("C", "C3")); // Module added

        var diff = _sut.Compare(older, newer);

        // 1 resolved + 1 new + 1 module added = 3
        Assert.Equal(3, diff.TotalChanges);
    }

    // ── Multiple modules with cross-module changes ──────────────────

    [Fact]
    public void Compare_MultiModuleChanges_Tracked()
    {
        var older = MakeReport(70,
            MakeModule("Firewall", "Network",
                Finding.Warning("Port 445", "open", "Network"),
                Finding.Warning("Port 3389", "open", "Network")),
            MakeModule("Defender", "Security",
                Finding.Pass("Active", "OK", "Security")),
            MakeModule("Encryption", "Security",
                Finding.Critical("No BitLocker", "Not encrypted", "Security")));

        var newer = MakeReport(85,
            MakeModule("Firewall", "Network",
                Finding.Pass("Port 445", "closed", "Network")), // severity change + Port 3389 resolved
            MakeModule("Defender", "Security",
                Finding.Pass("Active", "OK", "Security"),
                Finding.Warning("Scan Old", "Last scan > 7d", "Security")), // new
            MakeModule("Encryption", "Security",
                Finding.Pass("BitLocker On", "Encrypted", "Security"))); // resolved old + new pass

        var diff = _sut.Compare(older, newer);

        // Port 445: Warning → Pass (severity change)
        Assert.Contains(diff.SeverityChanges, sc => sc.Title == "Port 445");
        // Port 3389: resolved
        Assert.Contains(diff.ResolvedFindings, rf => rf.Finding.Title == "Port 3389");
        // Scan Old: new
        Assert.Contains(diff.NewFindings, nf => nf.Finding.Title == "Scan Old");
        // No BitLocker: resolved
        Assert.Contains(diff.ResolvedFindings, rf => rf.Finding.Title == "No BitLocker");
        // BitLocker On: new
        Assert.Contains(diff.NewFindings, nf => nf.Finding.Title == "BitLocker On");
        // 3 module deltas
        Assert.Equal(3, diff.ModuleDeltas.Count);
    }
}
