using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class FindingHeatmapServiceTests
{
    private readonly FindingHeatmapService _svc = new();

    private static Finding MakeFinding(Severity sev, DayOfWeek dow, int hour, string category = "Network")
    {
        var baseDate = new DateTimeOffset(2026, 3, 2, hour, 0, 0, TimeSpan.Zero); // Monday
        int diff = ((int)dow - (int)DayOfWeek.Monday + 7) % 7;
        return new Finding { Title = $"Test-{sev}", Description = "desc", Severity = sev, Category = category, Timestamp = baseDate.AddDays(diff) };
    }

    [Fact] public void Build_Empty_ZeroCounts() { var r = _svc.Build(Array.Empty<Finding>()); Assert.Equal(0, r.Summary.TotalFindings); Assert.Equal(168, r.Cells.Count); Assert.Empty(r.Hotspots); }
    [Fact] public void Build_Single_CorrectCell() { var r = _svc.Build(new[] { MakeFinding(Severity.Warning, DayOfWeek.Wednesday, 14) }); Assert.Equal(1, r.Summary.TotalFindings); var c = r.Cells.First(c => c.DayOfWeek == DayOfWeek.Wednesday && c.Hour == 14); Assert.Equal(1, c.Count); Assert.Equal(3.0, c.WeightedScore); }
    [Fact] public void Build_SeverityWeighting() { var r = _svc.Build(new[] { MakeFinding(Severity.Info, DayOfWeek.Monday, 10), MakeFinding(Severity.Critical, DayOfWeek.Monday, 10) }); var c = r.Cells.First(c => c.DayOfWeek == DayOfWeek.Monday && c.Hour == 10); Assert.Equal(11.0, c.WeightedScore); }
    [Fact] public void Build_Pass_ZeroWeight() { var r = _svc.Build(new[] { MakeFinding(Severity.Pass, DayOfWeek.Friday, 8) }); Assert.Equal(0.0, r.Cells.First(c => c.DayOfWeek == DayOfWeek.Friday && c.Hour == 8).WeightedScore); }
    [Fact] public void Build_MinSeverityFilter() { var r = _svc.Build(new[] { MakeFinding(Severity.Info, DayOfWeek.Monday, 10), MakeFinding(Severity.Critical, DayOfWeek.Monday, 10) }, new HeatmapOptions { MinSeverity = Severity.Warning }); Assert.Equal(1, r.Summary.TotalFindings); }
    [Fact] public void Build_CategoryFilter() { var r = _svc.Build(new[] { MakeFinding(Severity.Warning, DayOfWeek.Monday, 10, "Network"), MakeFinding(Severity.Warning, DayOfWeek.Monday, 10, "Firewall") }, new HeatmapOptions { CategoryFilter = "Firewall" }); Assert.Equal(1, r.Summary.TotalFindings); }
    [Fact] public void Build_CategoryFilter_CaseInsensitive() { var r = _svc.Build(new[] { MakeFinding(Severity.Warning, DayOfWeek.Monday, 10, "Network") }, new HeatmapOptions { CategoryFilter = "network" }); Assert.Equal(1, r.Summary.TotalFindings); }
    [Fact] public void Build_Intensity_Normalized() { var r = _svc.Build(new[] { MakeFinding(Severity.Critical, DayOfWeek.Monday, 10), MakeFinding(Severity.Critical, DayOfWeek.Monday, 10), MakeFinding(Severity.Info, DayOfWeek.Tuesday, 15) }); Assert.Equal(10.0, r.Cells.First(c => c.DayOfWeek == DayOfWeek.Monday && c.Hour == 10).Intensity); Assert.True(r.Cells.First(c => c.DayOfWeek == DayOfWeek.Tuesday && c.Hour == 15).Intensity is > 0 and < 10); }
    [Fact] public void Build_Hotspots_Ordered() { var r = _svc.Build(new[] { MakeFinding(Severity.Critical, DayOfWeek.Monday, 2), MakeFinding(Severity.Info, DayOfWeek.Wednesday, 14) }); Assert.True(r.Hotspots[0].WeightedScore >= r.Hotspots[1].WeightedScore); }
    [Fact] public void Build_TopHotspotsLimit() { var r = _svc.Build(Enumerable.Range(0, 10).Select(i => MakeFinding(Severity.Warning, DayOfWeek.Monday, i)).ToList(), new HeatmapOptions { TopHotspots = 3 }); Assert.Equal(3, r.Hotspots.Count); }
    [Fact] public void Build_SeverityCounts() { var r = _svc.Build(new[] { MakeFinding(Severity.Warning, DayOfWeek.Friday, 12), MakeFinding(Severity.Warning, DayOfWeek.Friday, 12), MakeFinding(Severity.Critical, DayOfWeek.Friday, 12) }); var c = r.Cells.First(c => c.DayOfWeek == DayOfWeek.Friday && c.Hour == 12); Assert.Equal(2, c.SeverityCounts[Severity.Warning]); Assert.Equal(1, c.SeverityCounts[Severity.Critical]); }
    [Fact] public void Build_Categories() { var r = _svc.Build(new[] { MakeFinding(Severity.Info, DayOfWeek.Monday, 8, "Network"), MakeFinding(Severity.Info, DayOfWeek.Monday, 8, "Firewall"), MakeFinding(Severity.Info, DayOfWeek.Monday, 8, "Network") }); Assert.Equal(2, r.Cells.First(c => c.DayOfWeek == DayOfWeek.Monday && c.Hour == 8).Categories.Count); }
    [Fact] public void Build_PeakDay() { var r = _svc.Build(new[] { MakeFinding(Severity.Critical, DayOfWeek.Thursday, 10), MakeFinding(Severity.Critical, DayOfWeek.Thursday, 11), MakeFinding(Severity.Info, DayOfWeek.Monday, 10) }); Assert.Equal(DayOfWeek.Thursday, r.Summary.PeakDay); }
    [Fact] public void Build_PeakHour() { var r = _svc.Build(new[] { MakeFinding(Severity.Critical, DayOfWeek.Monday, 3), MakeFinding(Severity.Critical, DayOfWeek.Tuesday, 3), MakeFinding(Severity.Info, DayOfWeek.Wednesday, 15) }); Assert.Equal(3, r.Summary.PeakHour); }
    [Fact] public void Build_BusinessHoursPercent() { var r = _svc.Build(new[] { MakeFinding(Severity.Warning, DayOfWeek.Monday, 10), MakeFinding(Severity.Warning, DayOfWeek.Monday, 14), MakeFinding(Severity.Warning, DayOfWeek.Monday, 22) }); Assert.True(r.Summary.BusinessHoursPercent > 60); Assert.True(r.Summary.OffHoursPercent > 30); }
    [Fact] public void Build_WeekdayPercent() { var r = _svc.Build(new[] { MakeFinding(Severity.Warning, DayOfWeek.Monday, 10), MakeFinding(Severity.Warning, DayOfWeek.Saturday, 10) }); Assert.Equal(50.0, r.Summary.WeekdayPercent); }
    [Fact] public void Pattern_OffHours() { var r = _svc.Build(Enumerable.Range(0, 20).Select(_ => MakeFinding(Severity.Critical, DayOfWeek.Monday, 2)).ToList()); Assert.Contains(r.Patterns, p => p.Type == PatternType.OffHoursActivity); }
    [Fact] public void Pattern_Weekend() { var f = new List<Finding>(); for (int i = 0; i < 30; i++) { f.Add(MakeFinding(Severity.Critical, DayOfWeek.Saturday, 10)); f.Add(MakeFinding(Severity.Critical, DayOfWeek.Sunday, 14)); } f.Add(MakeFinding(Severity.Info, DayOfWeek.Monday, 10)); Assert.Contains(_svc.Build(f).Patterns, p => p.Type == PatternType.WeekendSpike); }
    [Fact] public void Pattern_LateNight() { var f = new List<Finding>(); for (int i = 0; i < 10; i++) f.Add(MakeFinding(Severity.Critical, DayOfWeek.Tuesday, 2)); f.Add(MakeFinding(Severity.Info, DayOfWeek.Wednesday, 12)); Assert.Contains(_svc.Build(f).Patterns, p => p.Type == PatternType.LateNightConcentration); }
    [Fact] public void Pattern_SingleDay() { var f = new List<Finding>(); for (int i = 0; i < 20; i++) f.Add(MakeFinding(Severity.Critical, DayOfWeek.Friday, 10 + (i % 8))); f.Add(MakeFinding(Severity.Info, DayOfWeek.Monday, 10)); Assert.Contains(_svc.Build(f).Patterns, p => p.Type == PatternType.SingleDayDominance); }
    [Fact] public void Pattern_Burst() { Assert.Contains(_svc.Build(Enumerable.Range(0, 5).Select(_ => MakeFinding(Severity.Critical, DayOfWeek.Wednesday, 3)).ToList()).Patterns, p => p.Type == PatternType.BurstPattern); }
    [Fact] public void Pattern_NoFalsePositives_EvenSpread() { var f = new List<Finding>(); for (int d = 0; d < 7; d++) for (int h = 9; h < 17; h++) f.Add(MakeFinding(Severity.Warning, (DayOfWeek)((d + 1) % 7), h)); var r = _svc.Build(f); Assert.DoesNotContain(r.Patterns, p => p.Type == PatternType.OffHoursActivity); Assert.DoesNotContain(r.Patterns, p => p.Type == PatternType.LateNightConcentration); }
    [Fact] public void TextReport_Sections() { var r = _svc.Build(new[] { MakeFinding(Severity.Critical, DayOfWeek.Monday, 10), MakeFinding(Severity.Warning, DayOfWeek.Friday, 22) }); var t = _svc.ToTextReport(r); Assert.Contains("FINDING TEMPORAL HEATMAP REPORT", t); Assert.Contains("Mon", t); Assert.Contains("Sun", t); Assert.Contains("Top Hotspots", t); }
    [Fact] public void TextReport_Empty_NoHotspots() { Assert.DoesNotContain("Top Hotspots", _svc.ToTextReport(_svc.Build(Array.Empty<Finding>()))); }
    [Fact] public void Json_Valid() { var r = _svc.Build(new[] { MakeFinding(Severity.Warning, DayOfWeek.Tuesday, 8), MakeFinding(Severity.Critical, DayOfWeek.Tuesday, 8) }); var j = _svc.ToJson(r); Assert.Contains("\"TotalFindings\": 2", j); Assert.Contains("\"Tuesday\"", j); Assert.NotNull(System.Text.Json.JsonDocument.Parse(j)); }
    [Fact] public void Build_Null_Throws() { Assert.Throws<ArgumentNullException>(() => _svc.Build(null!)); }
    [Fact] public void TextReport_Null_Throws() { Assert.Throws<ArgumentNullException>(() => _svc.ToTextReport(null!)); }
    [Fact] public void Json_Null_Throws() { Assert.Throws<ArgumentNullException>(() => _svc.ToJson(null!)); }
    [Fact] public void Build_Grid_7x24() { var r = _svc.Build(Array.Empty<Finding>()); Assert.Equal(7, r.Grid.GetLength(0)); Assert.Equal(24, r.Grid.GetLength(1)); }
    [Fact] public void Build_AllDaysHours() { var r = _svc.Build(Array.Empty<Finding>()); Assert.Equal(7, r.Cells.Select(c => c.DayOfWeek).Distinct().Count()); Assert.Equal(24, r.Cells.Select(c => c.Hour).Distinct().Count()); }
    [Fact] public void Build_Default5Hotspots() { var r = _svc.Build(Enumerable.Range(0, 10).Select(i => MakeFinding(Severity.Warning, DayOfWeek.Monday, i)).ToList()); Assert.Equal(5, r.Hotspots.Count); }
    [Fact] public void Build_LargeDataset() { var rng = new Random(42); var f = Enumerable.Range(0, 1000).Select(_ => MakeFinding((Severity)rng.Next(0, 4), (DayOfWeek)rng.Next(0, 7), rng.Next(0, 24), rng.Next(2) == 0 ? "Net" : "Acct")).ToList(); var r = _svc.Build(f); Assert.Equal(1000, r.Summary.TotalFindings); }
    [Fact] public void Build_OnlyPass_ZeroScore() { var r = _svc.Build(Enumerable.Range(0, 5).Select(_ => MakeFinding(Severity.Pass, DayOfWeek.Monday, 10)).ToList()); Assert.Equal(0, r.Summary.TotalWeightedScore); }
    [Fact] public void Build_IntensityRange() { var r = _svc.Build(new[] { MakeFinding(Severity.Critical, DayOfWeek.Monday, 10), MakeFinding(Severity.Info, DayOfWeek.Friday, 20) }); foreach (var c in r.Cells) Assert.InRange(c.Intensity, 0, 10); }
}
