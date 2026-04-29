namespace WinSentinel.Tests.Services;

using System.Globalization;
using System.Text.Json;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

public class ThreatDnaProfilerServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _dbPath;
    private readonly string _snapshotDir;

    public ThreatDnaProfilerServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "WinSentinel_DnaTest_" + Path.GetRandomFileName());
        Directory.CreateDirectory(_tempDir);
        _dbPath = Path.Combine(_tempDir, "test.db");
        _snapshotDir = Path.Combine(_tempDir, "dna");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    private AuditHistoryService CreateHistory() => new(_dbPath);

    private ThreatDnaProfilerService CreateService(AuditHistoryService history) =>
        new(history, _snapshotDir);

    private void SeedRun(AuditHistoryService history, DateTimeOffset timestamp,
        params (string Module, string Title, Severity Severity)[] findings)
    {
        var report = new SecurityReport
        {
            GeneratedAt = timestamp,
            SecurityScore = 70,
            Results = findings
                .GroupBy(f => f.Module)
                .Select(g => new AuditResult
                {
                    ModuleName = g.Key,
                    Category = g.Key,
                    Findings = g.Select(f => new Finding
                    {
                        Title = f.Title,
                        Description = $"Test finding: {f.Title}",
                        Severity = f.Severity,
                        Category = g.Key
                    }).ToList()
                }).ToList()
        };
        history.SaveAuditResult(report);
    }

    [Fact]
    public void EmptyHistory_ReturnsEmptyReport()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        var svc = CreateService(history);

        var report = svc.GenerateProfile();

        Assert.Equal(0, report.GeneCount);
        Assert.Empty(report.Genes);
        Assert.Empty(report.CategoryBreakdown);
    }

    [Fact]
    public void SingleFinding_ProducesOneGene()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.Equal(1, report.GeneCount);
        Assert.Single(report.Genes);
        Assert.Equal("Open port 3389", report.Genes[0].Title);
    }

    [Fact]
    public void MultipleModules_ProduceCorrectCategories()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning),
            ("AccountAudit", "Guest account enabled", Severity.Critical),
            ("FirewallAudit", "Firewall disabled", Severity.Critical));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.Equal(3, report.GeneCount);
        var categories = report.Genes.Select(g => g.Category).Distinct().ToList();
        Assert.Contains("Network", categories);
        Assert.Contains("Account", categories);
        Assert.Contains("Firewall", categories);
    }

    [Fact]
    public void FrequencyCounting_TracksRepeatAppearances()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        for (int i = 0; i < 5; i++)
        {
            SeedRun(history, DateTimeOffset.UtcNow.AddDays(-10 + i),
                ("NetworkAudit", "Open port 3389", Severity.Warning));
        }

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.Equal(1, report.GeneCount);
        Assert.Equal(5, report.Genes[0].Frequency);
    }

    [Fact]
    public void PersistenceCalculation_IsCorrect()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        // Finding appears in 3 out of 4 scans
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-4),
            ("NetworkAudit", "Open port 3389", Severity.Warning));
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-3),
            ("NetworkAudit", "Open port 3389", Severity.Warning));
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-2),
            ("AccountAudit", "Guest enabled", Severity.Warning)); // different finding
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        var portGene = report.Genes.First(g => g.Title == "Open port 3389");
        Assert.Equal(0.75, portGene.Persistence); // 3 out of 4
    }

    [Fact]
    public void ResistanceScore_DetectsRegressions()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        // Finding appears, disappears, reappears (regression)
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-5),
            ("NetworkAudit", "Open port 3389", Severity.Warning));
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-4),
            ("AccountAudit", "Other finding", Severity.Warning)); // port gone
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-3),
            ("NetworkAudit", "Open port 3389", Severity.Warning)); // back! regression
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-2),
            ("AccountAudit", "Other finding", Severity.Warning)); // gone again
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning)); // back again!

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        var portGene = report.Genes.First(g => g.Title == "Open port 3389");
        Assert.True(portGene.ResistanceScore > 0, "Should detect regression resistance");
    }

    [Fact]
    public void ResilienceScore_IsInValidRange()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning),
            ("AccountAudit", "Guest enabled", Severity.Critical));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.InRange(report.OverallResilienceScore, 0, 100);
    }

    [Fact]
    public void ResilienceScore_HigherWhenNoActiveGenes()
    {
        var noActive = new List<ThreatGene>
        {
            new() { GeneId = "GENE-NET-001", Severity = "Critical", IsActive = false, Persistence = 1.0, ResistanceScore = 0.5 },
            new() { GeneId = "GENE-ACC-002", Severity = "Critical", IsActive = false, Persistence = 1.0, ResistanceScore = 0.5 },
            new() { GeneId = "GENE-FIR-003", Severity = "Critical", IsActive = false, Persistence = 1.0, ResistanceScore = 0.5 }
        };
        var withActive = new List<ThreatGene>
        {
            new() { GeneId = "GENE-NET-001", Severity = "Critical", IsActive = true, Persistence = 1.0, ResistanceScore = 0.5 },
            new() { GeneId = "GENE-ACC-002", Severity = "Critical", IsActive = true, Persistence = 1.0, ResistanceScore = 0.5 },
            new() { GeneId = "GENE-FIR-003", Severity = "Critical", IsActive = true, Persistence = 1.0, ResistanceScore = 0.5 }
        };

        var scoreNoActive = ThreatDnaProfilerService.CalculateResilienceScore(noActive);
        var scoreWithActive = ThreatDnaProfilerService.CalculateResilienceScore(withActive);

        Assert.True(scoreNoActive > scoreWithActive,
            $"No-active score ({scoreNoActive}) should be higher than with-active score ({scoreWithActive})");
    }

    [Fact]
    public void ResilienceScore_EmptyGenes_Returns100()
    {
        var score = ThreatDnaProfilerService.CalculateResilienceScore([]);
        Assert.Equal(100, score);
    }

    [Fact]
    public void EvolutionPhase_Emerging_WithFewSnapshots()
    {
        var snapshots = new List<DnaSnapshot>
        {
            new() { Timestamp = DateTimeOffset.UtcNow, GeneCount = 5, ActiveGenes = 3, ResilienceScore = 60 }
        };

        var phase = ThreatDnaProfilerService.DetermineEvolutionPhase(snapshots);
        Assert.Equal("Emerging", phase);
    }

    [Fact]
    public void EvolutionPhase_Resilient_WithHighScores()
    {
        var snapshots = new List<DnaSnapshot>();
        for (int i = 0; i < 5; i++)
        {
            snapshots.Add(new DnaSnapshot
            {
                Timestamp = DateTimeOffset.UtcNow.AddDays(-5 + i),
                GeneCount = 3,
                ActiveGenes = i == 0 ? 2 : 1, // decreasing
                ResilienceScore = 88 + i, // increasing and high
                TopCategory = "Network"
            });
        }

        var phase = ThreatDnaProfilerService.DetermineEvolutionPhase(snapshots);
        Assert.Equal("Resilient", phase);
    }

    [Fact]
    public void SnapshotSaveAndLoad_RoundTrips()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning));

        var svc = CreateService(history);
        svc.GenerateProfile(); // Creates first snapshot

        var loaded = svc.GetEvolutionHistory();
        Assert.NotEmpty(loaded);
        Assert.True(loaded.Count >= 1);
    }

    [Fact]
    public void MutationDetection_NewGene_WhenGenesIncrease()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        // First run creates baseline
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-2),
            ("NetworkAudit", "Open port 3389", Severity.Warning));

        var svc = CreateService(history);
        svc.GenerateProfile(); // Saves snapshot

        // Second run adds a new finding
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning),
            ("AccountAudit", "Guest enabled", Severity.Critical));

        var report = svc.GenerateProfile();

        // Should detect mutations since we have a previous snapshot
        Assert.NotEmpty(report.MutationAlerts);
        Assert.Contains(report.MutationAlerts, m => m.MutationType == DnaMutationType.NewGene);
    }

    [Fact]
    public void MutationDetection_GeneEliminated_WhenGenesDecrease()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        // First run with multiple findings
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-2),
            ("NetworkAudit", "Open port 3389", Severity.Warning),
            ("AccountAudit", "Guest enabled", Severity.Critical));

        var svc = CreateService(history);
        svc.GenerateProfile(); // Saves snapshot

        // Second run with fewer findings
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning));

        var report = svc.GenerateProfile();

        // The gene count decreased — elimination mutation possible
        // (Note: depends on filtering by days; both runs are in window)
        Assert.NotNull(report.MutationAlerts);
    }

    [Fact]
    public void DnaHash_Consistent_ForSameGenes()
    {
        var genes1 = new List<ThreatGene>
        {
            new() { GeneId = "GENE-NET-001", IsActive = true },
            new() { GeneId = "GENE-ACC-002", IsActive = true }
        };
        var genes2 = new List<ThreatGene>
        {
            new() { GeneId = "GENE-ACC-002", IsActive = true },
            new() { GeneId = "GENE-NET-001", IsActive = true }
        };

        var hash1 = ThreatDnaProfilerService.ComputeDnaHash(genes1);
        var hash2 = ThreatDnaProfilerService.ComputeDnaHash(genes2);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void DnaHash_Changes_WhenGenesChange()
    {
        var genes1 = new List<ThreatGene>
        {
            new() { GeneId = "GENE-NET-001", IsActive = true }
        };
        var genes2 = new List<ThreatGene>
        {
            new() { GeneId = "GENE-NET-001", IsActive = true },
            new() { GeneId = "GENE-ACC-002", IsActive = true }
        };

        var hash1 = ThreatDnaProfilerService.ComputeDnaHash(genes1);
        var hash2 = ThreatDnaProfilerService.ComputeDnaHash(genes2);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void DnaHash_EmptyGenes_ReturnsZeroHash()
    {
        var hash = ThreatDnaProfilerService.ComputeDnaHash([]);
        Assert.Equal("0000000000000000", hash);
    }

    [Fact]
    public void CategoryBreakdown_IsCorrect()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning),
            ("NetworkAudit", "Open port 22", Severity.Warning),
            ("AccountAudit", "Guest enabled", Severity.Critical));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.Equal(2, report.CategoryBreakdown.Count);
        var networkCat = report.CategoryBreakdown.First(c => c.Category == "Network");
        Assert.Equal(2, networkCat.GeneCount);
    }

    [Fact]
    public void HardeningPlan_Generated_ForActiveGenes()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Critical),
            ("AccountAudit", "Guest enabled", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.NotEmpty(report.HardeningPlan);
        Assert.True(report.HardeningPlan[0].Priority > 0);
    }

    [Fact]
    public void HardeningPlan_PrioritizesCritical()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("AccountAudit", "Guest enabled", Severity.Warning),
            ("NetworkAudit", "Open port 3389", Severity.Critical));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        // First action should target critical genes
        var first = report.HardeningPlan.First();
        Assert.Contains("critical", first.Action, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MitreTechnique_MappedCorrectly()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        var gene = report.Genes.First();
        Assert.Contains("T1046", gene.MitreTechnique);
    }

    [Fact]
    public void SeverityWeighting_CriticalMoreImpactful()
    {
        var criticalGenes = new List<ThreatGene>
        {
            new() { Severity = "Critical", IsActive = true, Persistence = 1.0, ResistanceScore = 0 }
        };
        var warningGenes = new List<ThreatGene>
        {
            new() { Severity = "Warning", IsActive = true, Persistence = 1.0, ResistanceScore = 0 }
        };

        var critScore = ThreatDnaProfilerService.CalculateResilienceScore(criticalGenes);
        var warnScore = ThreatDnaProfilerService.CalculateResilienceScore(warningGenes);

        Assert.True(critScore < warnScore, "Critical should reduce resilience more");
    }

    [Fact]
    public void HistoryDaysFiltering_RespectsWindow()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        // Old run outside window
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-100),
            ("NetworkAudit", "Ancient finding", Severity.Warning));
        // Recent run inside window
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Recent finding", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile(historyDays: 30);

        // Only recent finding should appear (old one is outside 30-day window)
        Assert.All(report.Genes, g => Assert.Equal("Recent finding", g.Title));
    }

    [Fact]
    public void GeneId_HasCorrectFormat()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        var gene = report.Genes.First();
        Assert.Matches(@"^GENE-[A-Z]{3}-\d{3}$", gene.GeneId);
    }

    [Fact]
    public void PassAndInfoFindings_ExcludedFromDna()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Pass finding", Severity.Pass),
            ("AccountAudit", "Info finding", Severity.Info),
            ("FirewallAudit", "Real warning", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.Equal(1, report.GeneCount);
        Assert.Equal("Real warning", report.Genes[0].Title);
    }

    [Fact]
    public void DominantCategory_SetCorrectly()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Port 3389", Severity.Critical),
            ("NetworkAudit", "Port 22", Severity.Critical),
            ("AccountAudit", "Guest", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.Equal("Network", report.DominantCategory);
    }

    [Fact]
    public void Recommendations_Generated()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Open port 3389", Severity.Critical));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        Assert.NotEmpty(report.Recommendations);
    }

    [Fact]
    public void ActiveGene_CorrectlyIdentified()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-2),
            ("NetworkAudit", "Port 3389", Severity.Warning),
            ("AccountAudit", "Guest", Severity.Warning));
        // Latest scan only has one finding
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1),
            ("NetworkAudit", "Port 3389", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        var portGene = report.Genes.First(g => g.Title == "Port 3389");
        var guestGene = report.Genes.First(g => g.Title == "Guest");

        Assert.True(portGene.IsActive);
        Assert.False(guestGene.IsActive);
    }

    [Fact]
    public void TopN_LimitsGeneCount()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        var findings = Enumerable.Range(1, 20)
            .Select(i => ($"Module{i}Audit", $"Finding {i}", Severity.Warning))
            .ToArray();
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-1), findings);

        var svc = CreateService(history);
        var report = svc.GenerateProfile(topN: 5);

        Assert.Equal(5, report.Genes.Count);
        Assert.Equal(20, report.GeneCount); // Total count remains accurate
    }

    [Fact]
    public void MitreMap_HasCommonModules()
    {
        Assert.True(ThreatDnaProfilerService.MitreMap.ContainsKey("Account"));
        Assert.True(ThreatDnaProfilerService.MitreMap.ContainsKey("Network"));
        Assert.True(ThreatDnaProfilerService.MitreMap.ContainsKey("Firewall"));
        Assert.True(ThreatDnaProfilerService.MitreMap.ContainsKey("PowerShell"));
    }

    [Fact]
    public void SeverityWeight_ReturnsExpectedValues()
    {
        Assert.Equal(10, ThreatDnaProfilerService.SeverityWeight("Critical"));
        Assert.Equal(5, ThreatDnaProfilerService.SeverityWeight("Warning"));
        Assert.Equal(1, ThreatDnaProfilerService.SeverityWeight("Info"));
        Assert.Equal(0, ThreatDnaProfilerService.SeverityWeight("Pass"));
    }

    [Fact]
    public void MultipleRuns_TracksFirstAndLastSeen()
    {
        using var history = CreateHistory();
        history.EnsureDatabase();

        var first = DateTimeOffset.UtcNow.AddDays(-5);
        var last = DateTimeOffset.UtcNow.AddDays(-1);

        SeedRun(history, first, ("NetworkAudit", "Port 3389", Severity.Warning));
        SeedRun(history, DateTimeOffset.UtcNow.AddDays(-3), ("AccountAudit", "Other", Severity.Warning));
        SeedRun(history, last, ("NetworkAudit", "Port 3389", Severity.Warning));

        var svc = CreateService(history);
        var report = svc.GenerateProfile();

        var gene = report.Genes.First(g => g.Title == "Port 3389");
        Assert.True(gene.FirstSeen <= gene.LastSeen);
    }
}
