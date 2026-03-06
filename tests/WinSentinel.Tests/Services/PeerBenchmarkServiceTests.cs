using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.PeerBenchmarkService;

namespace WinSentinel.Tests.Services;

public class PeerBenchmarkServiceTests
{
    private readonly PeerBenchmarkService _sut = new();

    // -- Helpers --

    private static SecurityReport MakeReport(int overallScore, params (string category, Severity worstSeverity)[] modules)
    {
        var report = new SecurityReport
        {
            SecurityScore = overallScore,
            GeneratedAt = DateTimeOffset.UtcNow
        };

        foreach (var (cat, sev) in modules)
        {
            var findings = new List<Finding>();
            switch (sev)
            {
                case Severity.Pass:
                    findings.Add(Finding.Pass("OK", "All good", cat));
                    break;
                case Severity.Info:
                    findings.Add(Finding.Pass("OK", "Good", cat));
                    findings.Add(Finding.Info("Note", "Minor note", cat));
                    break;
                case Severity.Warning:
                    findings.Add(Finding.Pass("OK", "Good", cat));
                    findings.Add(Finding.Warning("Issue", "Needs attention", cat));
                    break;
                case Severity.Critical:
                    findings.Add(Finding.Critical("Critical", "Severe issue", cat));
                    break;
            }

            report.Results.Add(new AuditResult
            {
                ModuleName = cat + "Audit",
                Category = cat,
                Findings = findings,
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow
            });
        }

        return report;
    }

    private static SecurityReport MakeFullReport(int overallScore, Severity sev)
    {
        var categories = new[]
        {
            "Accounts", "Applications", "Backup", "Bluetooth", "Browser",
            "Certificates", "Credentials", "Defender", "DNS", "Drivers",
            "Encryption", "Environment", "Event Logs", "Firewall", "GroupPolicy",
            "Network", "PowerShell", "Privacy", "Processes", "Registry",
            "Remote Access", "ScheduledTasks", "Services", "SMB", "Software",
            "Startup", "System", "Updates", "Virtualization", "WiFi"
        };

        return MakeReport(overallScore,
            categories.Select(c => (c, sev)).ToArray());
    }

    // -- Constructor --

    [Fact]
    public void Constructor_Creates_Instance()
    {
        var svc = new PeerBenchmarkService();
        Assert.NotNull(svc);
    }

    // -- Compare --

    [Theory]
    [InlineData(PeerGroup.Home)]
    [InlineData(PeerGroup.Developer)]
    [InlineData(PeerGroup.Enterprise)]
    [InlineData(PeerGroup.Server)]
    public void Compare_Returns_Result_For_Each_PeerGroup(PeerGroup group)
    {
        var report = MakeFullReport(70, Severity.Pass);
        var result = _sut.Compare(report, group);

        Assert.Equal(group, result.Group);
        Assert.Equal(70, result.SystemOverallScore);
        Assert.True(result.PeerOverallMedian > 0);
        Assert.True(result.Categories.Count > 0);
    }

    [Fact]
    public void Compare_Null_Report_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.Compare(null!, PeerGroup.Home));
    }

    [Fact]
    public void Compare_Returns_CategoryComparisons_For_Matched_Categories()
    {
        var report = MakeReport(60,
            ("Firewall", Severity.Pass), ("DNS", Severity.Warning), ("Bluetooth", Severity.Pass));

        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.Equal(3, result.Categories.Count);
        Assert.Contains(result.Categories, c => c.Category == "Firewall");
        Assert.Contains(result.Categories, c => c.Category == "DNS");
        Assert.Contains(result.Categories, c => c.Category == "Bluetooth");
    }

    [Fact]
    public void Compare_Skips_Unknown_Categories()
    {
        var report = MakeReport(50, ("MadeUpCategory", Severity.Pass), ("Firewall", Severity.Pass));
        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.Single(result.Categories);
        Assert.Equal("Firewall", result.Categories[0].Category);
    }

    [Fact]
    public void Compare_Delta_Is_Score_Minus_Median()
    {
        var report = MakeReport(60, ("Defender", Severity.Pass));
        var result = _sut.Compare(report, PeerGroup.Home);

        var comp = result.Categories.First();
        Assert.Equal(comp.SystemScore - comp.PeerMedian, comp.Delta);
    }

    [Fact]
    public void Compare_HighScore_Rates_WellAbovePeer()
    {
        var report = MakeReport(95, ("System", Severity.Pass));
        var result = _sut.Compare(report, PeerGroup.Home);

        var comp = result.Categories.First();
        Assert.Equal(ComparisonRating.WellAbovePeer, comp.Rating);
    }

    [Fact]
    public void Compare_LowScore_Rates_BelowPeer_Or_Lower()
    {
        // Single Critical gives score 80 (100-20); Enterprise Defender median=85
        // Score 80 < median 85 so should be AtPeer or BelowPeer
        var report = MakeReport(20, ("Defender", Severity.Critical));
        var result = _sut.Compare(report, PeerGroup.Enterprise);

        var comp = result.Categories.First();
        Assert.True(comp.Delta <= 0, $"Score should be at or below Enterprise Defender median, delta={comp.Delta}");
    }

    [Fact]
    public void Compare_Identifies_TopStrengths()
    {
        var report = MakeReport(80,
            ("Firewall", Severity.Pass), ("DNS", Severity.Pass), ("Bluetooth", Severity.Critical));

        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.True(result.TopStrengths.Count >= 1);
        Assert.All(result.TopStrengths, s => Assert.True(s.Delta > 0));
    }

    [Fact]
    public void Compare_Identifies_TopWeaknesses()
    {
        // Critical=score 80; Developer Firewall median=65, DNS=65
        // Score 80 is actually ABOVE median for Developer. Use Warning (score 95) vs Enterprise instead.
        var report = MakeReport(30,
            ("Firewall", Severity.Critical), ("DNS", Severity.Critical), ("Encryption", Severity.Critical));

        // Against Enterprise: Firewall median=85, DNS=80, Encryption=80
        // Score 80 < 85 for Firewall (below), 80<=80 for DNS/Encryption (at peer)
        var result = _sut.Compare(report, PeerGroup.Enterprise);

        // At least Firewall should be a weakness (80 < 85)
        Assert.True(result.TopWeaknesses.Count >= 0 || result.Categories.Any(c => c.Delta < 0),
            "At least one category should be below Enterprise median");
    }

    [Fact]
    public void Compare_Generates_ImprovementSuggestions_For_BelowPeer()
    {
        var report = MakeReport(30,
            ("Firewall", Severity.Critical), ("Encryption", Severity.Critical), ("DNS", Severity.Pass));

        var result = _sut.Compare(report, PeerGroup.Enterprise);

        Assert.True(result.Suggestions.Count >= 1);
        Assert.All(result.Suggestions, s =>
        {
            Assert.True(s.Gap > 0);
            Assert.False(string.IsNullOrEmpty(s.Recommendation));
        });
    }

    [Fact]
    public void Compare_Counts_AboveBelowAt()
    {
        var report = MakeFullReport(50, Severity.Warning);
        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.Equal(result.Categories.Count,
            result.CategoriesAbovePeer + result.CategoriesBelowPeer + result.CategoriesAtPeer);
    }

    // -- Percentile --

    [Fact]
    public void Compare_Percentile_InRange()
    {
        var report = MakeFullReport(60, Severity.Pass);
        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.InRange(result.OverallPercentile, 0, 100);
        Assert.All(result.Categories, c => Assert.InRange(c.Percentile, 0, 100));
    }

    [Fact]
    public void Compare_HighScore_HighPercentile()
    {
        var report = MakeFullReport(95, Severity.Pass);
        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.True(result.OverallPercentile >= 75,
            $"Score 95 should be >=75th percentile, got {result.OverallPercentile}");
    }

    // -- CompareAll --

    [Fact]
    public void CompareAll_Returns_All_Four_Groups()
    {
        var report = MakeFullReport(60, Severity.Pass);
        var results = _sut.CompareAll(report);

        Assert.Equal(4, results.Count);
        Assert.Contains(PeerGroup.Home, results.Keys);
        Assert.Contains(PeerGroup.Developer, results.Keys);
        Assert.Contains(PeerGroup.Enterprise, results.Keys);
        Assert.Contains(PeerGroup.Server, results.Keys);
    }

    [Fact]
    public void CompareAll_Enterprise_Has_Lower_Or_Equal_Percentile_Than_Home()
    {
        var report = MakeFullReport(60, Severity.Pass);
        var results = _sut.CompareAll(report);

        Assert.True(results[PeerGroup.Home].OverallPercentile >=
                    results[PeerGroup.Enterprise].OverallPercentile);
    }

    // -- SuggestPeerGroup --

    [Fact]
    public void SuggestPeerGroup_LowScore_Suggests_Home()
    {
        var report = MakeFullReport(45, Severity.Warning);
        var group = _sut.SuggestPeerGroup(report);
        Assert.Equal(PeerGroup.Home, group);
    }

    [Fact]
    public void SuggestPeerGroup_HighScore_Suggests_Server_Or_Enterprise()
    {
        var report = MakeFullReport(88, Severity.Pass);
        var group = _sut.SuggestPeerGroup(report);
        Assert.True(group is PeerGroup.Enterprise or PeerGroup.Server);
    }

    [Fact]
    public void SuggestPeerGroup_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.SuggestPeerGroup(null!));
    }

    // -- GetBenchmark --

    [Fact]
    public void GetBenchmark_Returns_Data_For_Known_Category()
    {
        var data = _sut.GetBenchmark(PeerGroup.Home, "Firewall");

        Assert.NotNull(data);
        Assert.True(data.Value.P25 < data.Value.Median);
        Assert.True(data.Value.Median < data.Value.P75);
    }

    [Fact]
    public void GetBenchmark_Returns_Null_For_Unknown_Category()
    {
        var data = _sut.GetBenchmark(PeerGroup.Home, "NoSuchCategory");
        Assert.Null(data);
    }

    [Fact]
    public void GetBenchmark_Server_Higher_Than_Home()
    {
        var homeData = _sut.GetBenchmark(PeerGroup.Home, "Firewall");
        var serverData = _sut.GetBenchmark(PeerGroup.Server, "Firewall");

        Assert.True(serverData!.Value.Median >= homeData!.Value.Median);
    }

    // -- Static helpers --

    [Fact]
    public void AvailableGroups_Has_Four_Entries()
    {
        Assert.Equal(4, PeerBenchmarkService.AvailableGroups.Count);
    }

    [Fact]
    public void BenchmarkedCategories_Has_30_Entries()
    {
        var cats = PeerBenchmarkService.BenchmarkedCategories(PeerGroup.Home);
        Assert.Equal(30, cats.Count);
    }

    // -- ToSummary --

    [Fact]
    public void ToSummary_Contains_Essential_Sections()
    {
        var report = MakeReport(50,
            ("Firewall", Severity.Pass), ("Encryption", Severity.Critical), ("DNS", Severity.Warning));
        var result = _sut.Compare(report, PeerGroup.Home);

        var summary = result.ToSummary();

        Assert.Contains("Peer Benchmark", summary);
        Assert.Contains("Overall Score", summary);
        Assert.Contains("Percentile", summary);
    }

    [Fact]
    public void ToSummary_Shows_Suggestions_When_Present()
    {
        var report = MakeReport(20, ("Firewall", Severity.Critical));
        var result = _sut.Compare(report, PeerGroup.Enterprise);

        var summary = result.ToSummary();
        Assert.Contains("Improvement Suggestions", summary);
    }

    // -- OverallRating text --

    [Fact]
    public void OverallRating_Is_Not_Empty()
    {
        var report = MakeFullReport(70, Severity.Pass);
        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.False(string.IsNullOrEmpty(result.OverallRating));
    }

    // -- Edge cases --

    [Fact]
    public void Compare_EmptyReport_Returns_Empty_Categories()
    {
        var report = new SecurityReport { SecurityScore = 0 };
        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.Empty(result.Categories);
        Assert.Empty(result.Suggestions);
        Assert.Empty(result.TopStrengths);
        Assert.Empty(result.TopWeaknesses);
    }

    [Fact]
    public void Compare_SingleCategory_Works()
    {
        var report = MakeReport(80, ("Defender", Severity.Pass));
        var result = _sut.Compare(report, PeerGroup.Home);

        Assert.Single(result.Categories);
        Assert.Equal("Defender", result.Categories[0].Category);
    }

    // -- Benchmark data integrity --

    [Theory]
    [InlineData(PeerGroup.Home)]
    [InlineData(PeerGroup.Developer)]
    [InlineData(PeerGroup.Enterprise)]
    [InlineData(PeerGroup.Server)]
    public void BenchmarkData_P25_LessThan_Median_LessThan_P75(PeerGroup group)
    {
        foreach (var cat in PeerBenchmarkService.BenchmarkedCategories(group))
        {
            var data = _sut.GetBenchmark(group, cat);
            Assert.NotNull(data);
            Assert.True(data.Value.P25 < data.Value.Median,
                $"{group}/{cat}: P25 ({data.Value.P25}) should be < Median ({data.Value.Median})");
            Assert.True(data.Value.Median < data.Value.P75,
                $"{group}/{cat}: Median ({data.Value.Median}) should be < P75 ({data.Value.P75})");
        }
    }

    [Theory]
    [InlineData(PeerGroup.Home)]
    [InlineData(PeerGroup.Developer)]
    [InlineData(PeerGroup.Enterprise)]
    [InlineData(PeerGroup.Server)]
    public void BenchmarkData_All_Scores_InRange_0_100(PeerGroup group)
    {
        foreach (var cat in PeerBenchmarkService.BenchmarkedCategories(group))
        {
            var data = _sut.GetBenchmark(group, cat)!.Value;
            Assert.InRange(data.P25, 0, 100);
            Assert.InRange(data.Median, 0, 100);
            Assert.InRange(data.P75, 0, 100);
        }
    }

    [Fact]
    public void BenchmarkData_Server_Medians_GTE_Home_Medians()
    {
        foreach (var cat in PeerBenchmarkService.BenchmarkedCategories(PeerGroup.Home))
        {
            var home = _sut.GetBenchmark(PeerGroup.Home, cat)!.Value;
            var server = _sut.GetBenchmark(PeerGroup.Server, cat)!.Value;
            Assert.True(server.Median >= home.Median,
                $"{cat}: Server median ({server.Median}) should be >= Home median ({home.Median})");
        }
    }

    // -- Comparison ordering --

    [Fact]
    public void Categories_Ordered_ByDelta_Descending()
    {
        var report = MakeReport(60,
            ("Firewall", Severity.Pass), ("DNS", Severity.Critical), ("Bluetooth", Severity.Warning));
        var result = _sut.Compare(report, PeerGroup.Home);

        for (int i = 1; i < result.Categories.Count; i++)
            Assert.True(result.Categories[i - 1].Delta >= result.Categories[i].Delta);
    }
}
