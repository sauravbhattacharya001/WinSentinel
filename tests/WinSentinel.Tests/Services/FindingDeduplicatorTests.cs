using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class FindingDeduplicatorTests
{
    private readonly FindingDeduplicator _sut = new();

    // ── Constructor Validation ──────────────────────────────────

    [Fact]
    public void Constructor_DefaultThresholdAndNgramSize()
    {
        var dedup = new FindingDeduplicator();
        // Should not throw
        var result = dedup.Deduplicate(new List<Finding>());
        Assert.Equal(0, result.OriginalCount);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    public void Constructor_InvalidThreshold_Throws(double threshold)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new FindingDeduplicator(threshold));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(11)]
    public void Constructor_InvalidNgramSize_Throws(int ngramSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new FindingDeduplicator(ngramSize: ngramSize));
    }

    [Fact]
    public void Constructor_ValidBoundaryValues()
    {
        _ = new FindingDeduplicator(0.0, 2);
        _ = new FindingDeduplicator(1.0, 10);
    }

    // ── Null / Empty / Single ───────────────────────────────────

    [Fact]
    public void Deduplicate_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.Deduplicate(null!));
    }

    [Fact]
    public void Deduplicate_Empty_ReturnsEmpty()
    {
        var result = _sut.Deduplicate(Array.Empty<Finding>());
        Assert.Empty(result.Deduplicated);
        Assert.Empty(result.Groups);
        Assert.Equal(0, result.OriginalCount);
        Assert.Equal(0, result.DuplicatesRemoved);
        Assert.Equal(0.0, result.ReductionPercent);
    }

    [Fact]
    public void Deduplicate_SingleFinding_ReturnsSame()
    {
        var finding = Finding.Warning("Test", "Desc", "Cat");
        var result = _sut.Deduplicate(new[] { finding });
        Assert.Single(result.Deduplicated);
        Assert.Same(finding, result.Deduplicated[0]);
        Assert.Empty(result.Groups);
        Assert.Equal(0, result.DuplicatesRemoved);
    }

    // ── Exact Duplicate Detection ───────────────────────────────

    [Fact]
    public void Deduplicate_ExactDuplicateTitles_MergesIntoOne()
    {
        var findings = new[]
        {
            Finding.Warning("RDP is enabled", "Remote Desktop is active", "Network"),
            Finding.Warning("RDP is enabled", "Remote Desktop is active", "Network"),
        };
        var result = _sut.Deduplicate(findings);

        Assert.Equal(2, result.OriginalCount);
        Assert.Equal(1, result.DeduplicatedCount);
        Assert.Equal(1, result.DuplicatesRemoved);
        Assert.Equal(50.0, result.ReductionPercent);
        Assert.Single(result.Groups);
    }

    [Fact]
    public void Deduplicate_ExactDuplicates_KeepsHighestSeverity()
    {
        var findings = new[]
        {
            Finding.Info("SMBv1 Enabled", "SMBv1 is legacy", "Network"),
            Finding.Critical("SMBv1 Enabled", "SMBv1 is legacy", "Network"),
            Finding.Warning("SMBv1 Enabled", "SMBv1 is legacy", "Network"),
        };
        var result = _sut.Deduplicate(findings);

        Assert.Single(result.Deduplicated);
        Assert.Equal(Severity.Critical, result.Deduplicated[0].Severity);
        Assert.Equal(2, result.DuplicatesRemoved);
    }

    // ── Near-Duplicate (Fuzzy) Detection ────────────────────────

    [Fact]
    public void Deduplicate_SimilarTitles_MergesAboveThreshold()
    {
        var findings = new[]
        {
            Finding.Warning("Windows Firewall is disabled on all profiles", "Firewall off", "Firewall",
                fixCommand: "netsh advfirewall set allprofiles state on"),
            Finding.Warning("Windows Firewall is disabled on the domain profile", "Firewall off on domain", "Firewall",
                fixCommand: "netsh advfirewall set domainprofile state on"),
        };
        // Very similar titles + same category + similar fix commands — should merge
        var result = _sut.Deduplicate(findings);

        Assert.Equal(1, result.DeduplicatedCount);
        Assert.Single(result.Groups);
    }

    [Fact]
    public void Deduplicate_DifferentFindings_NoMerge()
    {
        var findings = new[]
        {
            Finding.Warning("RDP is enabled", "Remote Desktop active", "Network"),
            Finding.Warning("SMBv1 is enabled", "Server Message Block v1", "Network"),
        };
        var result = _sut.Deduplicate(findings);

        Assert.Equal(2, result.DeduplicatedCount);
        Assert.Empty(result.Groups);
        Assert.Equal(0, result.DuplicatesRemoved);
    }

    [Fact]
    public void Deduplicate_SameFixCommand_BoostsSimilarity()
    {
        // Two findings with different titles but identical fix commands.
        // The shared fix command + category + severity should push above threshold.
        var findings = new[]
        {
            Finding.Warning("UAC policy is disabled on this system", "EnableLUA registry key is set to 0", "Registry",
                fixCommand: "Set-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA -Value 1"),
            Finding.Warning("UAC policy is not enabled on this system", "User Account Control is turned off", "Registry",
                fixCommand: "Set-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA -Value 1"),
        };
        var result = _sut.Deduplicate(findings);

        Assert.Equal(1, result.DeduplicatedCount);
    }

    // ── Threshold Behavior ──────────────────────────────────────

    [Fact]
    public void Deduplicate_HighThreshold_FewMerges()
    {
        var strict = new FindingDeduplicator(threshold: 0.95);
        var findings = new[]
        {
            Finding.Warning("Windows Firewall disabled", "FW off", "Firewall"),
            Finding.Warning("Windows Firewall is currently disabled", "FW is off", "Firewall"),
        };
        var result = strict.Deduplicate(findings);
        // At 0.95, slight title difference should prevent merge
        Assert.Equal(2, result.DeduplicatedCount);
    }

    [Fact]
    public void Deduplicate_LowThreshold_MoreMerges()
    {
        var loose = new FindingDeduplicator(threshold: 0.3);
        var findings = new[]
        {
            Finding.Warning("Firewall protection is off", "Network protection disabled", "Firewall"),
            Finding.Warning("Network firewall protection disabled", "Not active", "Firewall"),
        };
        var result = loose.Deduplicate(findings);
        // At 0.3, same category + some shared title n-grams should merge
        Assert.Equal(1, result.DeduplicatedCount);
    }

    // ── Cross-Module Deduplication ───────────────────────────────

    [Fact]
    public void DeduplicateAcrossModules_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.DeduplicateAcrossModules(null!));
    }

    [Fact]
    public void DeduplicateAcrossModules_SkipsPassFindings()
    {
        var results = new[]
        {
            new AuditResult
            {
                ModuleName = "Module1",
                Category = "Test",
                Findings = new List<Finding>
                {
                    Finding.Pass("All good", "Everything fine", "Test"),
                    Finding.Warning("Issue A", "Problem detected", "Test"),
                },
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow,
                Success = true
            },
            new AuditResult
            {
                ModuleName = "Module2",
                Category = "Test",
                Findings = new List<Finding>
                {
                    Finding.Pass("All good", "Everything fine", "Test"),
                    Finding.Warning("Issue A", "Problem detected", "Test"),
                },
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow,
                Success = true
            }
        };

        var result = _sut.DeduplicateAcrossModules(results);
        // Pass findings excluded; two Warning "Issue A" should merge to 1
        Assert.Equal(1, result.DeduplicatedCount);
        Assert.Equal(Severity.Warning, result.Deduplicated[0].Severity);
    }

    [Fact]
    public void DeduplicateAcrossModules_DifferentModules_SameFinding()
    {
        var results = new[]
        {
            new AuditResult
            {
                ModuleName = "RegistryAudit",
                Category = "Registry",
                Findings = new List<Finding>
                {
                    Finding.Critical("UAC is disabled", "EnableLUA = 0", "Registry",
                        fixCommand: "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f"),
                },
                StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow, Success = true
            },
            new AuditResult
            {
                ModuleName = "GroupPolicyAudit",
                Category = "Registry",
                Findings = new List<Finding>
                {
                    Finding.Warning("UAC is disabled", "User Account Control not enabled", "Registry",
                        fixCommand: "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f"),
                },
                StartTime = DateTimeOffset.UtcNow, EndTime = DateTimeOffset.UtcNow, Success = true
            },
        };

        var result = _sut.DeduplicateAcrossModules(results);
        Assert.Equal(1, result.DeduplicatedCount);
        // Should keep Critical (higher severity)
        Assert.Equal(Severity.Critical, result.Deduplicated[0].Severity);
    }

    // ── NgramSimilarity ─────────────────────────────────────────

    [Fact]
    public void NgramSimilarity_IdenticalStrings_Returns1()
    {
        Assert.Equal(1.0, _sut.NgramSimilarity("hello world", "hello world"));
    }

    [Fact]
    public void NgramSimilarity_EmptyString_Returns0()
    {
        Assert.Equal(0.0, _sut.NgramSimilarity("", "hello"));
        Assert.Equal(0.0, _sut.NgramSimilarity("hello", ""));
        Assert.Equal(0.0, _sut.NgramSimilarity("", ""));
    }

    [Fact]
    public void NgramSimilarity_NullString_Returns0()
    {
        Assert.Equal(0.0, _sut.NgramSimilarity(null!, "hello"));
        Assert.Equal(0.0, _sut.NgramSimilarity("hello", null!));
    }

    [Fact]
    public void NgramSimilarity_SimilarStrings_HighScore()
    {
        double sim = _sut.NgramSimilarity("windows firewall disabled", "windows firewall is disabled");
        Assert.True(sim > 0.6, $"Expected > 0.6, got {sim}");
    }

    [Fact]
    public void NgramSimilarity_DifferentStrings_LowScore()
    {
        double sim = _sut.NgramSimilarity("rdp enabled", "antivirus update");
        Assert.True(sim < 0.3, $"Expected < 0.3, got {sim}");
    }

    [Fact]
    public void NgramSimilarity_ShortStrings_BelowNgramSize()
    {
        // Strings shorter than n-gram size still match if identical
        // (identity check runs before n-gram extraction)
        Assert.Equal(1.0, _sut.NgramSimilarity("ab", "ab"));
        // Different short strings produce 0 n-grams → similarity 0
        Assert.Equal(0.0, _sut.NgramSimilarity("ab", "cd"));
    }

    // ── ComputeSimilarity ───────────────────────────────────────

    [Fact]
    public void ComputeSimilarity_IdenticalFindings_MaxScore()
    {
        var a = Finding.Warning("Firewall disabled", "Windows Firewall is off", "Firewall",
            fixCommand: "netsh advfirewall set allprofiles state on");
        var b = Finding.Warning("Firewall disabled", "Windows Firewall is off", "Firewall",
            fixCommand: "netsh advfirewall set allprofiles state on");

        var (score, reason) = _sut.ComputeSimilarity(a, b);
        Assert.True(score >= 0.95, $"Expected >= 0.95 for identical findings, got {score}");
        Assert.Contains("exact title", reason);
    }

    [Fact]
    public void ComputeSimilarity_CompletelyDifferent_LowScore()
    {
        var a = Finding.Warning("RDP enabled", "Remote Desktop on", "Network");
        var b = Finding.Critical("Antivirus outdated", "AV definitions expired", "Malware");

        var (score, _) = _sut.ComputeSimilarity(a, b);
        Assert.True(score < 0.3, $"Expected < 0.3 for different findings, got {score}");
    }

    [Fact]
    public void ComputeSimilarity_SameCategoryBoosts()
    {
        var a = Finding.Warning("Issue X", "Description A", "Network");
        var b = Finding.Warning("Issue Y", "Description B", "Network");

        var (withCat, _) = _sut.ComputeSimilarity(a, b);

        var c = Finding.Warning("Issue Y", "Description B", "Firewall");
        var (withoutCat, _) = _sut.ComputeSimilarity(a, c);

        Assert.True(withCat > withoutCat, "Same category should boost similarity");
    }

    // ── Multiple Groups ─────────────────────────────────────────

    [Fact]
    public void Deduplicate_MultipleGroups_CorrectGrouping()
    {
        var findings = new[]
        {
            // Group 1: Firewall (exact title match)
            Finding.Warning("Windows Firewall is disabled on all profiles", "FW off", "Firewall"),
            Finding.Critical("Windows Firewall is disabled on all profiles", "FW not active", "Firewall"),
            // Group 2: SMB (exact title match)
            Finding.Warning("SMBv1 protocol is enabled on this system", "Legacy protocol", "Network"),
            Finding.Warning("SMBv1 protocol is enabled on this system", "Old SMB version", "Network"),
            // Unique
            Finding.Info("New USB storage device detected and connected", "New USB", "Hardware"),
        };

        var result = _sut.Deduplicate(findings);

        Assert.Equal(3, result.DeduplicatedCount); // 2 groups + 1 unique
        Assert.Equal(2, result.Groups.Count);
        Assert.Equal(2, result.DuplicatesRemoved);
    }

    [Fact]
    public void Deduplicate_TripleDuplicate_SingleGroup()
    {
        var findings = new[]
        {
            Finding.Info("Remote Desktop Protocol is enabled", "RDP is active on this machine", "Network"),
            Finding.Warning("Remote Desktop Protocol is enabled", "RDP service is running and accepting connections", "Network"),
            Finding.Critical("Remote Desktop Protocol is enabled", "RDP is exposed and accepting connections", "Network"),
        };

        var result = _sut.Deduplicate(findings);

        Assert.Single(result.Deduplicated);
        Assert.Equal(Severity.Critical, result.Deduplicated[0].Severity);
        Assert.Single(result.Groups);
        Assert.Equal(2, result.Groups[0].Duplicates.Count);
    }

    // ── Reduction Stats ─────────────────────────────────────────

    [Fact]
    public void Deduplicate_ReductionPercent_Correct()
    {
        var findings = new[]
        {
            Finding.Warning("A", "Desc", "Cat"),
            Finding.Warning("A", "Desc", "Cat"),
            Finding.Warning("A", "Desc", "Cat"),
            Finding.Warning("A", "Desc", "Cat"),
        };

        var result = _sut.Deduplicate(findings);

        Assert.Equal(4, result.OriginalCount);
        Assert.Equal(1, result.DeduplicatedCount);
        Assert.Equal(3, result.DuplicatesRemoved);
        Assert.Equal(75.0, result.ReductionPercent);
    }

    // ── Edge Cases ──────────────────────────────────────────────

    [Fact]
    public void Deduplicate_CaseInsensitiveMatching()
    {
        var findings = new[]
        {
            Finding.Warning("FIREWALL DISABLED", "fw off", "Firewall"),
            Finding.Warning("firewall disabled", "FW OFF", "firewall"),
        };

        var result = _sut.Deduplicate(findings);
        Assert.Equal(1, result.DeduplicatedCount);
    }

    [Fact]
    public void Deduplicate_NullDescriptionsHandled()
    {
        var a = new Finding { Title = "Windows Firewall disabled", Description = null!, Severity = Severity.Warning, Category = "Firewall" };
        var b = new Finding { Title = "Windows Firewall disabled", Description = null!, Severity = Severity.Warning, Category = "Firewall" };

        var result = _sut.Deduplicate(new[] { a, b });
        Assert.Equal(1, result.DeduplicatedCount);
    }

    [Fact]
    public void Deduplicate_EmptyFixCommands_NoBoost()
    {
        var a = Finding.Warning("Issue", "Desc", "Cat");
        var b = Finding.Warning("Issue", "Desc", "Cat");
        // Both have null FixCommand — should still merge on title+desc+category

        var result = _sut.Deduplicate(new[] { a, b });
        Assert.Equal(1, result.DeduplicatedCount);
    }

    [Fact]
    public void Deduplicate_AllUnique_NoGroupsNoReduction()
    {
        var findings = new[]
        {
            Finding.Warning("Firewall issue", "Off", "Firewall"),
            Finding.Critical("RDP problem", "Exposed", "Network"),
            Finding.Info("USB detected", "New device", "Hardware"),
        };

        var result = _sut.Deduplicate(findings);

        Assert.Equal(3, result.DeduplicatedCount);
        Assert.Empty(result.Groups);
        Assert.Equal(0, result.DuplicatesRemoved);
        Assert.Equal(0.0, result.ReductionPercent);
    }

    [Fact]
    public void DuplicateGroup_AverageSimilarity_ReasonableValue()
    {
        var findings = new[]
        {
            Finding.Warning("Firewall disabled", "Not active", "Firewall"),
            Finding.Warning("Firewall disabled", "Not active", "Firewall"),
        };

        var result = _sut.Deduplicate(findings);
        Assert.Single(result.Groups);
        Assert.True(result.Groups[0].AverageSimilarity > 0.8);
    }

    [Fact]
    public void ComputeSimilarity_FuzzyMatch_ReasonShowsCorrectPercentage()
    {
        // Two findings with similar but not identical titles —
        // the similarity reason should show a human-readable percentage (e.g. "73%"), not "1%"
        var a = Finding.Warning("Windows Defender real-time disabled", "Desc A", "Security");
        var b = Finding.Warning("Windows Defender protection disabled", "Desc B", "Security");

        var (score, reason) = _sut.ComputeSimilarity(a, b);

        // Titles are similar enough that fuzzy match should fire
        Assert.True(score > 0.3, $"Score {score} should be > 0.3 for similar titles");

        // If a fuzzy title reason is present, the percentage should be > 10
        // (not "~0%" or "~1%" which would happen if the 0.0-1.0 value wasn't multiplied by 100)
        if (reason.Contains("title ~"))
        {
            // Extract the number from "title ~73%"
            var match = System.Text.RegularExpressions.Regex.Match(reason, @"title ~(\d+)%");
            Assert.True(match.Success, $"Reason '{reason}' should contain 'title ~NN%'");
            var pct = int.Parse(match.Groups[1].Value);
            Assert.True(pct > 10, $"Percentage {pct} should be > 10 for similar titles (was the 0-1 value displayed instead of 0-100?)");
        }
    }

    [Fact]
    public void ComputeSimilarity_FuzzyDescription_ReasonShowsCorrectPercentage()
    {
        // Same title, similar descriptions — description reason should show correct %
        var a = Finding.Warning("Firewall issue", "Windows Firewall is not properly configured for the domain profile", "Firewall");
        var b = Finding.Warning("Firewall issue", "Windows Firewall is not properly configured for the public profile", "Firewall");

        var (_, reason) = _sut.ComputeSimilarity(a, b);

        if (reason.Contains("desc ~"))
        {
            var match = System.Text.RegularExpressions.Regex.Match(reason, @"desc ~(\d+)%");
            Assert.True(match.Success, $"Reason '{reason}' should contain 'desc ~NN%'");
            var pct = int.Parse(match.Groups[1].Value);
            Assert.True(pct > 10, $"Description percentage {pct} should be > 10 for similar descriptions");
        }
    }
}
