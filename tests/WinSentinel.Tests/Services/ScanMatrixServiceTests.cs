using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class ScanMatrixServiceTests
{
    private static AuditRunRecord MakeRun(long id, int overallScore, DateTimeOffset timestamp,
        params (string module, string category, int score, int findings, int critical, int warnings)[] modules)
    {
        var run = new AuditRunRecord
        {
            Id = id,
            OverallScore = overallScore,
            Grade = overallScore >= 80 ? "A" : overallScore >= 60 ? "B" : "C",
            Timestamp = timestamp,
            TotalFindings = modules.Sum(m => m.findings),
            CriticalCount = modules.Sum(m => m.critical),
            WarningCount = modules.Sum(m => m.warnings),
        };
        foreach (var (module, category, score, findings, critical, warnings) in modules)
        {
            run.ModuleScores.Add(new ModuleScoreRecord
            {
                RunId = id,
                ModuleName = module,
                Category = category,
                Score = score,
                FindingCount = findings,
                CriticalCount = critical,
                WarningCount = warnings,
            });
        }
        return run;
    }

    [Fact]
    public void Build_EmptyRuns_ReturnsEmptyMatrix()
    {
        var svc = new ScanMatrixService();
        var result = svc.Build([]);

        Assert.Empty(result.Columns);
        Assert.Empty(result.Rows);
        Assert.Equal(0, result.Summary.TotalScans);
    }

    [Fact]
    public void Build_TwoRuns_BuildsCorrectMatrix()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        // Runs provided newest-first
        var runs = new List<AuditRunRecord>
        {
            MakeRun(2, 85, now,
                ("Firewall", "Firewall", 90, 1, 0, 1),
                ("Network", "Network", 80, 2, 0, 2)),
            MakeRun(1, 70, now.AddDays(-7),
                ("Firewall", "Firewall", 70, 3, 1, 2),
                ("Network", "Network", 70, 4, 1, 3)),
        };

        var result = svc.Build(runs);

        Assert.Equal(2, result.Columns.Count);
        // Columns should be chronological (oldest first)
        Assert.Equal(1, result.Columns[0].RunId);
        Assert.Equal(2, result.Columns[1].RunId);

        Assert.Equal(2, result.Rows.Count);
        Assert.Equal(2, result.Summary.TotalScans);
        Assert.Equal(2, result.Summary.TotalModules);
    }

    [Fact]
    public void Build_DetectsImprovingAndDecliningModules()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        var runs = new List<AuditRunRecord>
        {
            MakeRun(2, 80, now,
                ("Firewall", "Firewall", 90, 1, 0, 1),   // improved from 60
                ("Network", "Network", 50, 5, 2, 3)),     // declined from 80
            MakeRun(1, 70, now.AddDays(-7),
                ("Firewall", "Firewall", 60, 4, 2, 2),
                ("Network", "Network", 80, 2, 0, 2)),
        };

        var result = svc.Build(runs);

        var firewall = result.Rows.First(r => r.ModuleName == "Firewall");
        var network = result.Rows.First(r => r.ModuleName == "Network");

        Assert.Equal(30, firewall.NetChange);
        Assert.Equal("Improving", firewall.Trend);

        Assert.Equal(-30, network.NetChange);
        Assert.Equal("Declining", network.Trend);

        // Default sort: worst regressions first
        Assert.Equal("Network", result.Rows[0].ModuleName);
        Assert.Equal("Firewall", result.Rows[1].ModuleName);

        Assert.Equal(1, result.Summary.ImprovingModules);
        Assert.Equal(1, result.Summary.DecliningModules);
    }

    [Fact]
    public void Build_SortByName_SortsAlphabetically()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        var runs = new List<AuditRunRecord>
        {
            MakeRun(2, 80, now,
                ("Firewall", "Firewall", 90, 1, 0, 1),
                ("Accounts", "Accounts", 70, 2, 0, 2)),
            MakeRun(1, 70, now.AddDays(-7),
                ("Firewall", "Firewall", 60, 4, 2, 2),
                ("Accounts", "Accounts", 70, 2, 0, 2)),
        };

        var result = svc.Build(runs, new ScanMatrixService.MatrixOptions { SortByName = true });

        Assert.Equal("Accounts", result.Rows[0].ModuleName);
        Assert.Equal("Firewall", result.Rows[1].ModuleName);
    }

    [Fact]
    public void Build_ModuleFilter_FiltersCorrectly()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        var runs = new List<AuditRunRecord>
        {
            MakeRun(2, 80, now,
                ("Firewall", "Firewall", 90, 1, 0, 1),
                ("Network", "Network", 80, 2, 0, 2)),
            MakeRun(1, 70, now.AddDays(-7),
                ("Firewall", "Firewall", 60, 4, 2, 2),
                ("Network", "Network", 70, 4, 1, 3)),
        };

        var result = svc.Build(runs, new ScanMatrixService.MatrixOptions { ModuleFilter = "fire" });

        Assert.Single(result.Rows);
        Assert.Equal("Firewall", result.Rows[0].ModuleName);
    }

    [Fact]
    public void Build_MissingModule_ShowsNullCell()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        var runs = new List<AuditRunRecord>
        {
            MakeRun(2, 80, now,
                ("Firewall", "Firewall", 90, 1, 0, 1),
                ("NewModule", "NewModule", 75, 2, 0, 2)),
            MakeRun(1, 70, now.AddDays(-7),
                ("Firewall", "Firewall", 60, 4, 2, 2)),
        };

        var result = svc.Build(runs);

        var newMod = result.Rows.First(r => r.ModuleName == "NewModule");
        // First column (old run) should be null, second should have score
        Assert.Null(newMod.Cells[0]);
        Assert.NotNull(newMod.Cells[1]);
        Assert.Equal(75, newMod.Cells[1]!.Score);
    }

    [Fact]
    public void Build_MaxScans_LimitsColumns()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        var runs = new List<AuditRunRecord>();
        for (int i = 0; i < 10; i++)
        {
            runs.Add(MakeRun(10 - i, 70 + i, now.AddDays(-i),
                ("Firewall", "Firewall", 70 + i, 1, 0, 1)));
        }

        var result = svc.Build(runs, new ScanMatrixService.MatrixOptions { MaxScans = 3 });

        Assert.Equal(3, result.Columns.Count);
        Assert.Equal(3, result.Summary.TotalScans);
    }

    [Fact]
    public void Build_StableModule_DetectedCorrectly()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        var runs = new List<AuditRunRecord>
        {
            MakeRun(2, 80, now,
                ("Firewall", "Firewall", 80, 1, 0, 1)),
            MakeRun(1, 80, now.AddDays(-7),
                ("Firewall", "Firewall", 80, 1, 0, 1)),
        };

        var result = svc.Build(runs);

        Assert.Equal("Stable", result.Rows[0].Trend);
        Assert.Equal(0, result.Rows[0].NetChange);
        Assert.Equal(1, result.Summary.StableModules);
    }

    [Fact]
    public void Build_RunsWithoutModuleScores_AreSkipped()
    {
        var svc = new ScanMatrixService();
        var now = DateTimeOffset.UtcNow;

        var runs = new List<AuditRunRecord>
        {
            new() { Id = 2, OverallScore = 80, Timestamp = now, Grade = "A" },  // no module scores
            MakeRun(1, 70, now.AddDays(-7),
                ("Firewall", "Firewall", 70, 3, 1, 2)),
        };

        var result = svc.Build(runs);

        // Only one run has module scores, so only 1 column
        Assert.Single(result.Columns);
    }
}
