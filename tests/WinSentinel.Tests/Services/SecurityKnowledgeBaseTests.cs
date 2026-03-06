using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>
/// Tests for SecurityKnowledgeBase — CWE/ATT&amp;CK mapping, finding enrichment,
/// report enrichment, search, and text report generation.
/// </summary>
public class SecurityKnowledgeBaseTests
{
    private readonly SecurityKnowledgeBase _kb = new();

    // ─── Initialization ──────────────────────────────────────────

    [Fact]
    public void Constructor_LoadsBuiltInEntries()
    {
        Assert.NotEmpty(_kb.Entries);
        Assert.True(_kb.Entries.Count >= 20, "Should have at least 20 built-in entries");
    }

    [Fact]
    public void Constructor_IndexesCweIds()
    {
        var cweIds = _kb.GetAllCweIds();
        Assert.NotEmpty(cweIds);
        Assert.Contains("CWE-284", cweIds);
        Assert.Contains("CWE-311", cweIds);
    }

    [Fact]
    public void Constructor_IndexesAttackIds()
    {
        var attackIds = _kb.GetAllAttackIds();
        Assert.NotEmpty(attackIds);
        Assert.Contains("T1562.004", attackIds);
        Assert.Contains("T1210", attackIds);
    }

    // ─── CWE Lookup ──────────────────────────────────────────────

    [Theory]
    [InlineData("CWE-284")]
    [InlineData("cwe-284")]
    [InlineData("284")]
    public void LookupByCwe_VariousFormats_FindsEntry(string cweId)
    {
        var entry = _kb.LookupByCwe(cweId);
        Assert.NotNull(entry);
        Assert.Equal("CWE-284", entry!.CweId);
    }

    [Fact]
    public void LookupByCwe_NonExistent_ReturnsNull()
    {
        Assert.Null(_kb.LookupByCwe("CWE-99999"));
    }

    [Fact]
    public void LookupByCwe_FirewallDisabled_ReturnsCorrectEntry()
    {
        // CWE-284 is shared by multiple entries (Firewall Disabled, Bluetooth Discoverable);
        // last registered wins in the index. Verify we get a valid entry.
        var entry = _kb.LookupByCwe("CWE-284");
        Assert.NotNull(entry);
        Assert.Equal("CWE-284", entry!.CweId);
        Assert.NotEqual(ImpactRating.Unknown, entry.ImpactRating);
        Assert.NotNull(entry.Explanation);
        Assert.NotEmpty(entry.BestPractices);
        Assert.NotEmpty(entry.References);
    }

    // ─── ATT&CK Lookup ──────────────────────────────────────────

    [Fact]
    public void LookupByAttackId_Existing_FindsEntry()
    {
        var entry = _kb.LookupByAttackId("T1562.004");
        Assert.NotNull(entry);
        Assert.Equal("Impair Defenses: Disable or Modify System Firewall", entry!.AttackTechniqueName);
    }

    [Fact]
    public void LookupByAttackId_NonExistent_ReturnsNull()
    {
        Assert.Null(_kb.LookupByAttackId("T9999.999"));
    }

    [Theory]
    [InlineData("T1210", "Exploitation of Remote Services")]
    [InlineData("T1005", "Data from Local System")]
    [InlineData("T1078.001", "Valid Accounts: Default Accounts")]
    [InlineData("T1110", "Brute Force")]
    public void LookupByAttackId_KnownTechniques_CorrectNames(string id, string expectedName)
    {
        var entry = _kb.LookupByAttackId(id);
        Assert.NotNull(entry);
        Assert.Equal(expectedName, entry!.AttackTechniqueName);
    }

    // ─── Category Lookup ─────────────────────────────────────────

    [Fact]
    public void GetByCategory_Firewall_ReturnsMultiple()
    {
        var results = _kb.GetByCategory("Firewall");
        Assert.True(results.Count >= 2);
        Assert.Contains(results, e => e.Title == "Firewall Disabled");
        Assert.Contains(results, e => e.Title == "Overly Permissive Firewall Rule");
    }

    [Fact]
    public void GetByCategory_CaseInsensitive()
    {
        var lower = _kb.GetByCategory("firewall");
        var upper = _kb.GetByCategory("FIREWALL");
        Assert.Equal(lower.Count, upper.Count);
    }

    [Fact]
    public void GetByCategory_NonExistent_ReturnsEmpty()
    {
        var results = _kb.GetByCategory("NonExistentCategory");
        Assert.Empty(results);
    }

    // ─── Finding Matching ────────────────────────────────────────

    [Fact]
    public void MatchFinding_ExactTitleMatch()
    {
        var finding = new Finding
        {
            Title = "Firewall Disabled",
            Description = "Windows Firewall is not enabled",
            Severity = Severity.Critical,
            Category = "Firewall"
        };

        var entry = _kb.MatchFinding(finding);
        Assert.NotNull(entry);
        Assert.Equal("Firewall Disabled", entry!.Title);
    }

    [Fact]
    public void MatchFinding_SubstringMatch()
    {
        var finding = new Finding
        {
            Title = "SMBv1 protocol is enabled on this system",
            Description = "Legacy SMB protocol detected",
            Severity = Severity.Critical,
            Category = "SMB"
        };

        var entry = _kb.MatchFinding(finding);
        Assert.NotNull(entry);
        Assert.Equal("SMBv1 Enabled", entry!.Title);
    }

    [Fact]
    public void MatchFinding_KeywordMatch()
    {
        var finding = new Finding
        {
            Title = "System lacks proper disk encryption configuration",
            Description = "BitLocker full-disk encryption is not active on drive C:",
            Severity = Severity.Warning,
            Category = "Encryption"
        };

        var entry = _kb.MatchFinding(finding);
        Assert.NotNull(entry);
        Assert.Equal("BitLocker Not Enabled", entry!.Title);
    }

    [Fact]
    public void MatchFinding_NoMatch_ReturnsNull()
    {
        var finding = new Finding
        {
            Title = "Completely unrelated issue XYZ123",
            Description = "Nothing matches here at all",
            Severity = Severity.Info,
            Category = "Unknown"
        };

        Assert.Null(_kb.MatchFinding(finding));
    }

    // ─── Enrichment ──────────────────────────────────────────────

    [Fact]
    public void Enrich_MatchedFinding_PopulatesAllFields()
    {
        var finding = new Finding
        {
            Title = "Windows Defender Disabled",
            Description = "Real-time protection is off",
            Severity = Severity.Critical,
            Category = "Defender"
        };

        var enriched = _kb.Enrich(finding);

        Assert.Same(finding, enriched.Finding);
        Assert.NotNull(enriched.KnowledgeEntry);
        Assert.Equal("CWE-693", enriched.CweId);
        Assert.Equal("T1562.001", enriched.AttackTechniqueId);
        Assert.Equal(ImpactRating.Critical, enriched.ImpactRating);
        Assert.NotNull(enriched.Explanation);
        Assert.NotEmpty(enriched.BestPractices);
        Assert.NotEmpty(enriched.References);
    }

    [Fact]
    public void Enrich_UnmatchedFinding_ReturnsUnknownImpact()
    {
        var finding = new Finding
        {
            Title = "Some unknown issue 12345",
            Description = "No match",
            Severity = Severity.Info,
            Category = "Other"
        };

        var enriched = _kb.Enrich(finding);

        Assert.Same(finding, enriched.Finding);
        Assert.Null(enriched.KnowledgeEntry);
        Assert.Null(enriched.CweId);
        Assert.Equal(ImpactRating.Unknown, enriched.ImpactRating);
    }

    // ─── Report Enrichment ───────────────────────────────────────

    [Fact]
    public void EnrichReport_EmptyReport_ReturnsCleanStats()
    {
        var report = new SecurityReport();
        var result = _kb.EnrichReport(report);

        Assert.Empty(result.EnrichedFindings);
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(100.0, result.CoveragePercent);
    }

    [Fact]
    public void EnrichReport_MixedFindings_CorrectCounts()
    {
        var report = CreateTestReport();
        var result = _kb.EnrichReport(report);

        Assert.Equal(3, result.TotalFindings);
        Assert.True(result.MatchedCount >= 2, "At least 2 of 3 test findings should match");
        Assert.Equal(result.TotalFindings - result.MatchedCount, result.UnmatchedCount);
    }

    [Fact]
    public void EnrichReport_CweDistribution_Populated()
    {
        var report = CreateTestReport();
        var result = _kb.EnrichReport(report);

        Assert.NotEmpty(result.CweDistribution);
    }

    [Fact]
    public void EnrichReport_TopCwes_OrderedByFrequency()
    {
        var report = CreateReportWithDuplicateCategories();
        var result = _kb.EnrichReport(report);

        if (result.TopCwes.Count >= 2)
        {
            Assert.True(result.TopCwes[0].Count >= result.TopCwes[1].Count);
        }
    }

    [Fact]
    public void EnrichReport_ImpactDistribution_Populated()
    {
        var report = CreateTestReport();
        var result = _kb.EnrichReport(report);

        Assert.NotEmpty(result.ImpactDistribution);
    }

    [Fact]
    public void EnrichReport_CoveragePercent_Calculated()
    {
        var report = CreateTestReport();
        var result = _kb.EnrichReport(report);

        Assert.True(result.CoveragePercent >= 0 && result.CoveragePercent <= 100);
    }

    // ─── Search ──────────────────────────────────────────────────

    [Theory]
    [InlineData("firewall", 2)]
    [InlineData("SMBv1", 1)]
    [InlineData("password", 1)]
    public void Search_ByKeyword_FindsExpectedMinimum(string query, int minExpected)
    {
        var results = _kb.Search(query);
        Assert.True(results.Count >= minExpected,
            $"Expected at least {minExpected} results for '{query}', got {results.Count}");
    }

    [Fact]
    public void Search_ByCweId_FindsEntry()
    {
        var results = _kb.Search("CWE-311");
        Assert.NotEmpty(results);
        Assert.Contains(results, e => e.CweId == "CWE-311");
    }

    [Fact]
    public void Search_ByAttackId_FindsEntry()
    {
        var results = _kb.Search("T1210");
        Assert.NotEmpty(results);
    }

    [Fact]
    public void Search_EmptyQuery_ReturnsEmpty()
    {
        Assert.Empty(_kb.Search(""));
        Assert.Empty(_kb.Search("   "));
    }

    [Fact]
    public void Search_NoMatch_ReturnsEmpty()
    {
        Assert.Empty(_kb.Search("xyzzy_no_match_12345"));
    }

    // ─── Custom Registration ─────────────────────────────────────

    [Fact]
    public void Register_CustomEntry_Findable()
    {
        var kb = new SecurityKnowledgeBase();
        kb.Register(new KnowledgeEntry
        {
            Title = "Custom Security Issue",
            CweId = "CWE-999",
            AttackTechniqueId = "T9999",
            AttackTechniqueName = "Custom Technique",
            ImpactRating = ImpactRating.Medium,
            Categories = new[] { "CustomCategory" },
            TitlePatterns = new[] { "Custom Security Issue" },
            Keywords = new[] { "custom" }
        });

        Assert.NotNull(kb.LookupByCwe("CWE-999"));
        Assert.NotNull(kb.LookupByAttackId("T9999"));
        Assert.NotEmpty(kb.GetByCategory("CustomCategory"));
    }

    // ─── Text Report ─────────────────────────────────────────────

    [Fact]
    public void GenerateTextReport_ContainsHeader()
    {
        var report = CreateTestReport();
        var result = _kb.EnrichReport(report);
        var text = _kb.GenerateTextReport(result);

        Assert.Contains("Security Knowledge Base Report", text);
        Assert.Contains("Total Findings:", text);
        Assert.Contains("KB Matched:", text);
        Assert.Contains("Coverage:", text);
    }

    [Fact]
    public void GenerateTextReport_IncludesTopCwes_WhenPresent()
    {
        var report = CreateTestReport();
        var result = _kb.EnrichReport(report);
        var text = _kb.GenerateTextReport(result);

        if (result.TopCwes.Count > 0)
        {
            Assert.Contains("Top CWE Weaknesses:", text);
            Assert.Contains(result.TopCwes[0].CweId, text);
        }
    }

    [Fact]
    public void GenerateTextReport_EmptyReport_NoErrors()
    {
        var report = new SecurityReport();
        var result = _kb.EnrichReport(report);
        var text = _kb.GenerateTextReport(result);

        Assert.Contains("Total Findings:      0", text);
    }

    // ─── GetAll Methods ──────────────────────────────────────────

    [Fact]
    public void GetAllCweIds_Sorted()
    {
        var ids = _kb.GetAllCweIds();
        for (int i = 1; i < ids.Count; i++)
        {
            Assert.True(string.CompareOrdinal(ids[i - 1], ids[i]) <= 0,
                $"CWE IDs not sorted: {ids[i - 1]} > {ids[i]}");
        }
    }

    [Fact]
    public void GetAllAttackIds_Sorted()
    {
        var ids = _kb.GetAllAttackIds();
        for (int i = 1; i < ids.Count; i++)
        {
            Assert.True(string.CompareOrdinal(ids[i - 1], ids[i]) <= 0,
                $"ATT&CK IDs not sorted: {ids[i - 1]} > {ids[i]}");
        }
    }

    // ─── Impact Rating Enum ──────────────────────────────────────

    [Fact]
    public void ImpactRating_HasAllLevels()
    {
        Assert.True(Enum.IsDefined(typeof(ImpactRating), ImpactRating.Unknown));
        Assert.True(Enum.IsDefined(typeof(ImpactRating), ImpactRating.Low));
        Assert.True(Enum.IsDefined(typeof(ImpactRating), ImpactRating.Medium));
        Assert.True(Enum.IsDefined(typeof(ImpactRating), ImpactRating.High));
        Assert.True(Enum.IsDefined(typeof(ImpactRating), ImpactRating.Critical));
    }

    // ─── Entry Data Integrity ────────────────────────────────────

    [Fact]
    public void AllEntries_HaveRequiredFields()
    {
        foreach (var entry in _kb.Entries)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.Title),
                "Every entry must have a title");
            Assert.NotEqual(ImpactRating.Unknown, entry.ImpactRating);
            Assert.NotEmpty(entry.Categories);
        }
    }

    [Fact]
    public void AllEntries_HaveExplanations()
    {
        foreach (var entry in _kb.Entries)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.Explanation),
                $"Entry '{entry.Title}' should have an explanation");
        }
    }

    [Fact]
    public void AllEntries_HaveBestPractices()
    {
        foreach (var entry in _kb.Entries)
        {
            Assert.NotEmpty(entry.BestPractices);
        }
    }

    [Fact]
    public void CriticalEntries_HaveReferences()
    {
        var critical = _kb.Entries.Where(e => e.ImpactRating == ImpactRating.Critical);
        foreach (var entry in critical)
        {
            Assert.NotEmpty(entry.References);
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────

    private static SecurityReport CreateTestReport()
    {
        var report = new SecurityReport();
        report.Results.Add(new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall",
            Findings = new List<Finding>
            {
                new Finding
                {
                    Title = "Firewall Disabled",
                    Description = "Windows Firewall is not active",
                    Severity = Severity.Critical,
                    Category = "Firewall"
                },
                new Finding
                {
                    Title = "Overly Permissive Firewall Rule",
                    Description = "Rule allows all inbound on public profile",
                    Severity = Severity.Warning,
                    Category = "Firewall"
                }
            }
        });
        report.Results.Add(new AuditResult
        {
            ModuleName = "OtherAudit",
            Category = "Other",
            Findings = new List<Finding>
            {
                new Finding
                {
                    Title = "Unrecognized issue XYZ",
                    Description = "Won't match anything",
                    Severity = Severity.Info,
                    Category = "Other"
                }
            }
        });
        return report;
    }

    private static SecurityReport CreateReportWithDuplicateCategories()
    {
        var report = new SecurityReport();
        report.Results.Add(new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall",
            Findings = new List<Finding>
            {
                new Finding { Title = "Firewall Disabled", Description = "Off", Severity = Severity.Critical, Category = "Firewall" },
                new Finding { Title = "Overly Permissive Firewall Rule", Description = "Wide open", Severity = Severity.Warning, Category = "Firewall" },
            }
        });
        report.Results.Add(new AuditResult
        {
            ModuleName = "EncryptionAudit",
            Category = "Encryption",
            Findings = new List<Finding>
            {
                new Finding { Title = "BitLocker Not Enabled", Description = "No disk encryption", Severity = Severity.Warning, Category = "Encryption" },
            }
        });
        report.Results.Add(new AuditResult
        {
            ModuleName = "AccountAudit",
            Category = "Accounts",
            Findings = new List<Finding>
            {
                new Finding { Title = "Guest Account Enabled", Description = "Guest active", Severity = Severity.Warning, Category = "Accounts" },
                new Finding { Title = "Weak Password Policy", Description = "Min length 4", Severity = Severity.Warning, Category = "Accounts" },
            }
        });
        return report;
    }
}
