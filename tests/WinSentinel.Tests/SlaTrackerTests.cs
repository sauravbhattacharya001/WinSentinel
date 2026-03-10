using Xunit;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class SlaTrackerTests
{
    private static readonly DateTimeOffset _baseTime =
        new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static Finding MakeFinding(Severity severity, string title = "Test Finding",
        string category = "TestModule") =>
        new() { Title = title, Description = "desc", Severity = severity, Category = category };

    // ── Policy presets ───────────────────────────────────────────

    [Fact]
    public void Enterprise_Policy_Has_Expected_Defaults()
    {
        var p = SlaTracker.SlaPolicy.Enterprise;
        Assert.Equal(TimeSpan.FromHours(24), p.CriticalDeadline);
        Assert.Equal(TimeSpan.FromDays(7), p.WarningDeadline);
        Assert.Equal(TimeSpan.FromDays(30), p.InfoDeadline);
        Assert.Equal("Enterprise", p.Name);
    }

    [Fact]
    public void Strict_Policy_Has_Shorter_Deadlines()
    {
        var p = SlaTracker.SlaPolicy.Strict;
        Assert.Equal(TimeSpan.FromHours(4), p.CriticalDeadline);
        Assert.Equal(TimeSpan.FromHours(48), p.WarningDeadline);
        Assert.Equal(TimeSpan.FromDays(14), p.InfoDeadline);
    }

    [Fact]
    public void Relaxed_Policy_Has_Longer_Deadlines()
    {
        var p = SlaTracker.SlaPolicy.Relaxed;
        Assert.Equal(TimeSpan.FromHours(72), p.CriticalDeadline);
        Assert.Equal(TimeSpan.FromDays(30), p.WarningDeadline);
        Assert.Equal(TimeSpan.FromDays(90), p.InfoDeadline);
    }

    [Fact]
    public void GetDeadline_Returns_MaxValue_For_Pass()
    {
        var p = SlaTracker.SlaPolicy.Enterprise;
        Assert.Equal(TimeSpan.MaxValue, p.GetDeadline(Severity.Pass));
    }

    // ── Track ────────────────────────────────────────────────────

    [Fact]
    public void Track_Assigns_Sequential_Ids()
    {
        var tracker = new SlaTracker();
        var f1 = tracker.Track(MakeFinding(Severity.Critical), _baseTime);
        var f2 = tracker.Track(MakeFinding(Severity.Warning), _baseTime);

        Assert.Equal("SLA-0001", f1.Id);
        Assert.Equal("SLA-0002", f2.Id);
    }

    [Fact]
    public void Track_Sets_Correct_Deadline()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        Assert.Equal(_baseTime + TimeSpan.FromHours(24), f.Deadline);
        Assert.True(f.IsOpen);
    }

    [Fact]
    public void Track_Warning_Gets_7Day_Deadline()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Warning), _baseTime);

        Assert.Equal(_baseTime + TimeSpan.FromDays(7), f.Deadline);
    }

    [Fact]
    public void Track_Pass_Gets_MaxValue_Deadline()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Pass), _baseTime);

        Assert.Equal(DateTimeOffset.MaxValue, f.Deadline);
    }

    [Fact]
    public void Track_Null_Finding_Throws()
    {
        var tracker = new SlaTracker();
        Assert.Throws<ArgumentNullException>(() => tracker.Track(null!));
    }

    // ── TrackReport ──────────────────────────────────────────────

    [Fact]
    public void TrackReport_Imports_All_NonPass_Findings()
    {
        var report = new SecurityReport
        {
            GeneratedAt = _baseTime,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "Firewall",
                    Category = "Network",
                    Findings = new List<Finding>
                    {
                        MakeFinding(Severity.Critical, "Open RDP"),
                        MakeFinding(Severity.Warning, "Weak Rule"),
                        MakeFinding(Severity.Pass, "ICMP OK"),
                    }
                }
            }
        };

        var tracker = new SlaTracker();
        var count = tracker.TrackReport(report);

        Assert.Equal(2, count);  // Pass is skipped
        Assert.Equal(2, tracker.Findings.Count);
    }

    [Fact]
    public void TrackReport_Uses_Report_Timestamp()
    {
        var report = new SecurityReport
        {
            GeneratedAt = _baseTime,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "Mod",
                    Category = "Cat",
                    Findings = new List<Finding> { MakeFinding(Severity.Warning, "Test") }
                }
            }
        };

        var tracker = new SlaTracker();
        tracker.TrackReport(report);

        Assert.Equal(_baseTime, tracker.Findings[0].DetectedAt);
    }

    // ── Resolve ──────────────────────────────────────────────────

    [Fact]
    public void Resolve_Marks_Finding_Resolved()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        var resolved = tracker.Resolve(f.Id, _baseTime + TimeSpan.FromHours(12));

        Assert.False(resolved.IsOpen);
        Assert.Equal(_baseTime + TimeSpan.FromHours(12), resolved.ResolvedAt);
    }

    [Fact]
    public void Resolve_Within_Sla_Sets_MetSla()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        tracker.Resolve(f.Id, _baseTime + TimeSpan.FromHours(12));

        Assert.True(f.MetSla);
    }

    [Fact]
    public void Resolve_After_Deadline_MissedSla()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        tracker.Resolve(f.Id, _baseTime + TimeSpan.FromHours(48));

        Assert.False(f.MetSla);
    }

    [Fact]
    public void Resolve_Unknown_Id_Throws()
    {
        var tracker = new SlaTracker();
        Assert.Throws<ArgumentException>(() => tracker.Resolve("SLA-9999"));
    }

    [Fact]
    public void Resolve_Already_Resolved_Throws()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Warning), _baseTime);
        tracker.Resolve(f.Id, _baseTime + TimeSpan.FromHours(1));

        Assert.Throws<InvalidOperationException>(() => tracker.Resolve(f.Id));
    }

    [Fact]
    public void Resolve_Stores_Notes()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Warning), _baseTime);

        tracker.Resolve(f.Id, notes: "Applied patch KB-12345");

        Assert.Equal("Applied patch KB-12345", f.ResolutionNotes);
    }

    // ── ResolveByTitle ───────────────────────────────────────────

    [Fact]
    public void ResolveByTitle_Matches_Substring()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "Open RDP Port"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "Open SSH Port"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "Weak Password"), _baseTime);

        var count = tracker.ResolveByTitle("Open", _baseTime + TimeSpan.FromHours(2));

        Assert.Equal(2, count);
        Assert.Equal(1, tracker.GetOpen().Count);
    }

    // ── Assess ───────────────────────────────────────────────────

    [Fact]
    public void Assess_OnTrack_When_Within_Window()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        var assessment = tracker.Assess(f, _baseTime + TimeSpan.FromHours(6));

        Assert.Equal(SlaTracker.SlaStatus.OnTrack, assessment.Status);
        Assert.True(assessment.TimeRemaining > TimeSpan.Zero);
    }

    [Fact]
    public void Assess_Approaching_When_Past_Threshold()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        // 75% of 24h = 18h, so at 20h it should be "approaching"
        var assessment = tracker.Assess(f, _baseTime + TimeSpan.FromHours(20));

        Assert.Equal(SlaTracker.SlaStatus.Approaching, assessment.Status);
    }

    [Fact]
    public void Assess_Overdue_When_Past_Deadline()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        var assessment = tracker.Assess(f, _baseTime + TimeSpan.FromHours(30));

        Assert.Equal(SlaTracker.SlaStatus.Overdue, assessment.Status);
        Assert.True(assessment.TimeRemaining < TimeSpan.Zero);
    }

    [Fact]
    public void Assess_Resolved_Finding()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Warning), _baseTime);
        tracker.Resolve(f.Id, _baseTime + TimeSpan.FromDays(3));

        var assessment = tracker.Assess(f, _baseTime + TimeSpan.FromDays(10));

        Assert.Equal(SlaTracker.SlaStatus.Resolved, assessment.Status);
        Assert.Contains("within SLA", assessment.UrgencyLabel);
    }

    [Fact]
    public void Assess_Resolved_After_Sla()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);
        tracker.Resolve(f.Id, _baseTime + TimeSpan.FromHours(48));

        var assessment = tracker.Assess(f);

        Assert.Contains("AFTER SLA", assessment.UrgencyLabel);
    }

    [Fact]
    public void Assess_Pass_Finding_Is_Exempt()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Pass), _baseTime);

        var assessment = tracker.Assess(f);

        Assert.Equal(SlaTracker.SlaStatus.Exempt, assessment.Status);
    }

    // ── GenerateReport ───────────────────────────────────────────

    [Fact]
    public void GenerateReport_Empty_Tracker()
    {
        var tracker = new SlaTracker();
        var report = tracker.GenerateReport();

        Assert.Equal(0, report.TotalTracked);
        Assert.Equal(100.0, report.CompliancePercent);
    }

    [Fact]
    public void GenerateReport_Counts_Correct()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "F1"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "F2"), _baseTime);
        var f3 = tracker.Track(MakeFinding(Severity.Warning, "F3"), _baseTime);
        tracker.Resolve(f3.Id, _baseTime + TimeSpan.FromDays(2));

        var report = tracker.GenerateReport(_baseTime + TimeSpan.FromDays(3));

        Assert.Equal(3, report.TotalTracked);
        Assert.Equal(2, report.OpenCount);
        Assert.Equal(1, report.ResolvedCount);
    }

    [Fact]
    public void GenerateReport_Compliance_100_When_All_Met()
    {
        var tracker = new SlaTracker();
        var f1 = tracker.Track(MakeFinding(Severity.Critical, "F1"), _baseTime);
        var f2 = tracker.Track(MakeFinding(Severity.Warning, "F2"), _baseTime);
        tracker.Resolve(f1.Id, _baseTime + TimeSpan.FromHours(12));  // within 24h
        tracker.Resolve(f2.Id, _baseTime + TimeSpan.FromDays(3));    // within 7d

        var report = tracker.GenerateReport();

        Assert.Equal(100.0, report.CompliancePercent);
    }

    [Fact]
    public void GenerateReport_Compliance_50_When_Half_Missed()
    {
        var tracker = new SlaTracker();
        var f1 = tracker.Track(MakeFinding(Severity.Critical, "F1"), _baseTime);
        var f2 = tracker.Track(MakeFinding(Severity.Critical, "F2"), _baseTime);
        tracker.Resolve(f1.Id, _baseTime + TimeSpan.FromHours(12));  // within SLA
        tracker.Resolve(f2.Id, _baseTime + TimeSpan.FromHours(48));  // missed SLA

        var report = tracker.GenerateReport();

        Assert.Equal(50.0, report.CompliancePercent);
    }

    [Fact]
    public void GenerateReport_MTTR_Calculated()
    {
        var tracker = new SlaTracker();
        var f1 = tracker.Track(MakeFinding(Severity.Warning, "F1"), _baseTime);
        var f2 = tracker.Track(MakeFinding(Severity.Warning, "F2"), _baseTime);
        tracker.Resolve(f1.Id, _baseTime + TimeSpan.FromHours(10));
        tracker.Resolve(f2.Id, _baseTime + TimeSpan.FromHours(20));

        var report = tracker.GenerateReport();

        Assert.NotNull(report.MeanTimeToRemediate);
        Assert.Equal(15.0, report.MeanTimeToRemediate.Value.TotalHours, 1);
    }

    [Fact]
    public void GenerateReport_BySeverity_Breakdown()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "C1"), _baseTime);
        tracker.Track(MakeFinding(Severity.Critical, "C2"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "W1"), _baseTime);

        var report = tracker.GenerateReport(_baseTime + TimeSpan.FromHours(1));

        Assert.Equal(2, report.BySeverity[Severity.Critical].Total);
        Assert.Equal(1, report.BySeverity[Severity.Warning].Total);
    }

    [Fact]
    public void GenerateReport_Overdue_List()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "Overdue1"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "OnTrack1"), _baseTime);

        // 48h later: critical is overdue (24h SLA), warning is still on track (7d SLA)
        var report = tracker.GenerateReport(_baseTime + TimeSpan.FromHours(48));

        Assert.Single(report.TopOverdue);
        Assert.Equal("Overdue1", report.TopOverdue[0].Finding.Title);
    }

    [Fact]
    public void GenerateReport_Assessments_Ordered_By_Urgency()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Info, "Info1"), _baseTime);
        tracker.Track(MakeFinding(Severity.Critical, "Crit1"), _baseTime);

        // Check at 30h: critical is overdue, info is on track
        var report = tracker.GenerateReport(_baseTime + TimeSpan.FromHours(30));

        // Overdue findings should come first
        Assert.Equal(SlaTracker.SlaStatus.Overdue, report.Assessments[0].Status);
    }

    // ── Query helpers ────────────────────────────────────────────

    [Fact]
    public void GetOpen_Returns_Only_Open()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "F1"), _baseTime);
        var f2 = tracker.Track(MakeFinding(Severity.Warning, "F2"), _baseTime);
        tracker.Resolve(f2.Id);

        Assert.Single(tracker.GetOpen());
        Assert.Equal("F1", tracker.GetOpen()[0].Title);
    }

    [Fact]
    public void GetOverdue_Returns_Past_Deadline()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "F1"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "F2"), _baseTime);

        var overdue = tracker.GetOverdue(_baseTime + TimeSpan.FromHours(48));

        Assert.Single(overdue);  // Only critical is overdue at 48h
        Assert.Equal("F1", overdue[0].Title);
    }

    [Fact]
    public void GetApproaching_Returns_Near_Deadline()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "F1"), _baseTime);

        // At 20h into 24h deadline (83%), past 75% threshold
        var approaching = tracker.GetApproaching(_baseTime + TimeSpan.FromHours(20));

        Assert.Single(approaching);
    }

    [Fact]
    public void GetById_Returns_Correct_Finding()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Warning, "Specific"), _baseTime);

        Assert.Equal("Specific", tracker.GetById(f.Id)?.Title);
        Assert.Null(tracker.GetById("SLA-9999"));
    }

    [Fact]
    public void GetByCategory_Filters_Correctly()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Warning, "F1", "Network"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "F2", "Firewall"), _baseTime);
        tracker.Track(MakeFinding(Severity.Critical, "F3", "Network"), _baseTime);

        Assert.Equal(2, tracker.GetByCategory("Network").Count);
        Assert.Single(tracker.GetByCategory("Firewall"));
    }

    [Fact]
    public void GetBySeverity_Filters_Correctly()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "C1"), _baseTime);
        tracker.Track(MakeFinding(Severity.Critical, "C2"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "W1"), _baseTime);

        Assert.Equal(2, tracker.GetBySeverity(Severity.Critical).Count);
        Assert.Single(tracker.GetBySeverity(Severity.Warning));
    }

    // ── Export / Import ──────────────────────────────────────────

    [Fact]
    public void ExportJson_RoundTrips()
    {
        var tracker = new SlaTracker();
        var f1 = tracker.Track(MakeFinding(Severity.Critical, "Crit1", "Network"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "Warn1", "Firewall"), _baseTime);
        tracker.Resolve(f1.Id, _baseTime + TimeSpan.FromHours(12), "Patched");

        var json = tracker.ExportJson();

        var tracker2 = new SlaTracker();
        var count = tracker2.ImportJson(json);

        Assert.Equal(2, count);
        Assert.Equal(2, tracker2.Findings.Count);
        Assert.Equal("Crit1", tracker2.Findings[0].Title);
        Assert.False(tracker2.Findings[0].IsOpen);
        Assert.Equal("Patched", tracker2.Findings[0].ResolutionNotes);
    }

    [Fact]
    public void ImportJson_Continues_Id_Sequence()
    {
        var tracker = new SlaTracker();
        tracker.ImportJson("{\"findings\":[{\"Id\":\"SLA-0005\",\"Title\":\"T\",\"Category\":\"C\"," +
            "\"Severity\":\"Warning\",\"DetectedAt\":\"2026-01-01T00:00:00Z\"," +
            "\"Deadline\":\"2026-01-08T00:00:00Z\"}]}");

        var f = tracker.Track(MakeFinding(Severity.Info, "New"), _baseTime);
        Assert.Equal("SLA-0006", f.Id);
    }

    [Fact]
    public void ImportJson_Invalid_Throws()
    {
        var tracker = new SlaTracker();
        Assert.Throws<ArgumentException>(() => tracker.ImportJson("{}"));
    }

    // ── Custom policy ────────────────────────────────────────────

    [Fact]
    public void Custom_Policy_Applied()
    {
        var policy = new SlaTracker.SlaPolicy
        {
            Name = "Custom",
            CriticalDeadline = TimeSpan.FromHours(2),
            WarningDeadline = TimeSpan.FromHours(12),
            InfoDeadline = TimeSpan.FromDays(3),
        };

        var tracker = new SlaTracker(policy);
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        Assert.Equal(_baseTime + TimeSpan.FromHours(2), f.Deadline);
    }

    [Fact]
    public void Strict_Policy_Flags_Approaching_Earlier()
    {
        var tracker = new SlaTracker(SlaTracker.SlaPolicy.Strict);
        // Strict: Critical = 4h, ApproachingThreshold = 0.5
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        // At 3h into 4h deadline (75%), past 50% threshold
        var assessment = tracker.Assess(f, _baseTime + TimeSpan.FromHours(3));

        Assert.Equal(SlaTracker.SlaStatus.Approaching, assessment.Status);
    }

    // ── Text report ──────────────────────────────────────────────

    [Fact]
    public void GenerateTextReport_Contains_Key_Sections()
    {
        var tracker = new SlaTracker();
        tracker.Track(MakeFinding(Severity.Critical, "Open Port"), _baseTime);
        tracker.Track(MakeFinding(Severity.Warning, "Weak Cipher"), _baseTime);
        var f = tracker.Track(MakeFinding(Severity.Info, "Old Software"), _baseTime);
        tracker.Resolve(f.Id, _baseTime + TimeSpan.FromDays(5));

        var text = tracker.GenerateTextReport(_baseTime + TimeSpan.FromHours(30));

        Assert.Contains("SLA Compliance Report", text);
        Assert.Contains("Total Tracked:", text);
        Assert.Contains("OVERDUE", text);
        Assert.Contains("Open Port", text);
        Assert.Contains("By Severity", text);
    }

    [Fact]
    public void GenerateTextReport_Empty_Tracker()
    {
        var tracker = new SlaTracker();
        var text = tracker.GenerateTextReport();

        Assert.Contains("SLA Compliance Report", text);
        Assert.Contains("Total Tracked:    0", text);
    }

    // ── WindowConsumed ───────────────────────────────────────────

    [Fact]
    public void WindowConsumed_Is_Correct_Fraction()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        // 12h into 24h deadline = 0.5
        var assessment = tracker.Assess(f, _baseTime + TimeSpan.FromHours(12));

        Assert.Equal(0.5, assessment.WindowConsumed, 2);
    }

    [Fact]
    public void WindowConsumed_Exceeds_1_When_Overdue()
    {
        var tracker = new SlaTracker();
        var f = tracker.Track(MakeFinding(Severity.Critical), _baseTime);

        var assessment = tracker.Assess(f, _baseTime + TimeSpan.FromHours(48));

        Assert.True(assessment.WindowConsumed > 1.0);
    }
}
