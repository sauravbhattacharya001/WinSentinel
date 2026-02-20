using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class IgnoreRuleServiceTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _rulesPath;
    private readonly IgnoreRuleService _service;

    public IgnoreRuleServiceTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "WinSentinel_IgnoreTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_testDir);
        _rulesPath = Path.Combine(_testDir, "ignore-rules.json");
        _service = new IgnoreRuleService(_rulesPath);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDir))
                Directory.Delete(_testDir, true);
        }
        catch { }
    }

    private static SecurityReport CreateTestReport()
    {
        var firewallResult = new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall",
            Findings = new List<Finding>
            {
                Finding.Critical("Firewall Disabled", "Windows Firewall is turned off", "Firewall",
                    "Enable Windows Firewall", "Set-NetFirewallProfile -All -Enabled True"),
                Finding.Warning("Inbound Rules Too Permissive", "Too many open ports", "Firewall",
                    "Review inbound firewall rules"),
                Finding.Pass("Outbound Filtering", "Outbound traffic is filtered", "Firewall"),
            },
            StartTime = DateTimeOffset.UtcNow.AddSeconds(-2),
            EndTime = DateTimeOffset.UtcNow,
            Success = true
        };

        var networkResult = new AuditResult
        {
            ModuleName = "NetworkAudit",
            Category = "Network",
            Findings = new List<Finding>
            {
                Finding.Critical("SMB v1 Enabled", "Legacy SMB protocol is enabled", "Network",
                    "Disable SMB v1"),
                Finding.Warning("LLMNR Enabled", "Link-Local Multicast Name Resolution is active", "Network",
                    "Disable LLMNR"),
                Finding.Warning("Remote Desktop Enabled", "RDP is accessible", "Network",
                    "Disable if not needed"),
                Finding.Info("IPv6 Enabled", "IPv6 is enabled on all adapters", "Network"),
            },
            StartTime = DateTimeOffset.UtcNow.AddSeconds(-2),
            EndTime = DateTimeOffset.UtcNow,
            Success = true
        };

        var encryptionResult = new AuditResult
        {
            ModuleName = "EncryptionAudit",
            Category = "Encryption",
            Findings = new List<Finding>
            {
                Finding.Warning("BitLocker Not Enabled", "System drive is not encrypted", "Encryption",
                    "Enable BitLocker"),
                Finding.Pass("TLS Configuration", "TLS settings are secure", "Encryption"),
            },
            StartTime = DateTimeOffset.UtcNow.AddSeconds(-2),
            EndTime = DateTimeOffset.UtcNow,
            Success = true
        };

        var report = new SecurityReport
        {
            Results = [firewallResult, networkResult, encryptionResult],
            GeneratedAt = DateTimeOffset.UtcNow
        };
        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    // ── AddRule Tests ──

    [Fact]
    public void AddRule_BasicPattern_CreatesRule()
    {
        var rule = _service.AddRule("SMB");
        Assert.NotNull(rule);
        Assert.Equal("SMB", rule.Pattern);
        Assert.Equal(IgnoreMatchMode.Contains, rule.MatchMode);
        Assert.True(rule.Enabled);
        Assert.True(rule.IsActive);
        Assert.False(rule.IsExpired);
        Assert.NotEmpty(rule.Id);
    }

    [Fact]
    public void AddRule_WithAllOptions_SetsAllProperties()
    {
        var expires = DateTimeOffset.UtcNow.AddDays(30);
        var rule = _service.AddRule("^BitLocker.*",
            matchMode: IgnoreMatchMode.Regex,
            module: "Encryption",
            severity: Severity.Warning,
            reason: "Accepted risk on dev machines",
            expiresAt: expires);

        Assert.Equal("^BitLocker.*", rule.Pattern);
        Assert.Equal(IgnoreMatchMode.Regex, rule.MatchMode);
        Assert.Equal("Encryption", rule.Module);
        Assert.Equal(Severity.Warning, rule.Severity);
        Assert.Equal("Accepted risk on dev machines", rule.Reason);
        Assert.NotNull(rule.ExpiresAt);
        Assert.True(rule.IsActive);
    }

    [Fact]
    public void AddRule_EmptyPattern_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => _service.AddRule(""));
        Assert.Throws<ArgumentException>(() => _service.AddRule("   "));
    }

    [Fact]
    public void AddRule_InvalidRegex_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => _service.AddRule("[invalid", IgnoreMatchMode.Regex));
    }

    [Fact]
    public void AddRule_PersistsToFile()
    {
        _service.AddRule("Test Pattern");

        // Create a new service instance to verify persistence
        var service2 = new IgnoreRuleService(_rulesPath);
        var rules = service2.GetAllRules();
        Assert.Single(rules);
        Assert.Equal("Test Pattern", rules[0].Pattern);
    }

    [Fact]
    public void AddRule_MultipleRules_AllPersisted()
    {
        _service.AddRule("Pattern 1");
        _service.AddRule("Pattern 2");
        _service.AddRule("Pattern 3");

        var rules = _service.GetAllRules();
        Assert.Equal(3, rules.Count);
    }

    // ── GetRule Tests ──

    [Fact]
    public void GetRule_ExistingId_ReturnsRule()
    {
        var added = _service.AddRule("Test");
        var found = _service.GetRule(added.Id);
        Assert.NotNull(found);
        Assert.Equal(added.Id, found.Id);
        Assert.Equal("Test", found.Pattern);
    }

    [Fact]
    public void GetRule_NonExistentId_ReturnsNull()
    {
        var found = _service.GetRule("nonexistent");
        Assert.Null(found);
    }

    [Fact]
    public void GetRule_CaseInsensitiveId()
    {
        var added = _service.AddRule("Test");
        var found = _service.GetRule(added.Id.ToUpperInvariant());
        Assert.NotNull(found);
    }

    // ── GetActiveRules Tests ──

    [Fact]
    public void GetActiveRules_ExcludesDisabled()
    {
        _service.AddRule("Active Rule");
        var disabled = _service.AddRule("Disabled Rule");
        _service.ToggleRule(disabled.Id, false);

        var active = _service.GetActiveRules();
        Assert.Single(active);
        Assert.Equal("Active Rule", active[0].Pattern);
    }

    [Fact]
    public void GetActiveRules_ExcludesExpired()
    {
        _service.AddRule("Active Rule");
        _service.AddRule("Expired Rule", expiresAt: DateTimeOffset.UtcNow.AddDays(-1));

        var active = _service.GetActiveRules();
        Assert.Single(active);
        Assert.Equal("Active Rule", active[0].Pattern);
    }

    // ── RemoveRule Tests ──

    [Fact]
    public void RemoveRule_ExistingId_ReturnsTrue()
    {
        var rule = _service.AddRule("Remove Me");
        Assert.True(_service.RemoveRule(rule.Id));
        Assert.Empty(_service.GetAllRules());
    }

    [Fact]
    public void RemoveRule_NonExistentId_ReturnsFalse()
    {
        Assert.False(_service.RemoveRule("nonexistent"));
    }

    // ── ToggleRule Tests ──

    [Fact]
    public void ToggleRule_DisableAndEnable()
    {
        var rule = _service.AddRule("Toggle Me");

        Assert.True(_service.ToggleRule(rule.Id, false));
        var disabled = _service.GetRule(rule.Id);
        Assert.NotNull(disabled);
        Assert.False(disabled.Enabled);

        Assert.True(_service.ToggleRule(rule.Id, true));
        var enabled = _service.GetRule(rule.Id);
        Assert.NotNull(enabled);
        Assert.True(enabled.Enabled);
    }

    [Fact]
    public void ToggleRule_NonExistentId_ReturnsFalse()
    {
        Assert.False(_service.ToggleRule("nonexistent", false));
    }

    // ── ClearAllRules Tests ──

    [Fact]
    public void ClearAllRules_RemovesAll()
    {
        _service.AddRule("Rule 1");
        _service.AddRule("Rule 2");
        _service.AddRule("Rule 3");

        var count = _service.ClearAllRules();
        Assert.Equal(3, count);
        Assert.Empty(_service.GetAllRules());
    }

    [Fact]
    public void ClearAllRules_EmptyList_ReturnsZero()
    {
        Assert.Equal(0, _service.ClearAllRules());
    }

    // ── PurgeExpiredRules Tests ──

    [Fact]
    public void PurgeExpiredRules_RemovesOnlyExpired()
    {
        _service.AddRule("Active Rule");
        _service.AddRule("Expired Rule", expiresAt: DateTimeOffset.UtcNow.AddDays(-1));

        var purged = _service.PurgeExpiredRules();
        Assert.Equal(1, purged);
        var remaining = _service.GetAllRules();
        Assert.Single(remaining);
        Assert.Equal("Active Rule", remaining[0].Pattern);
    }

    [Fact]
    public void PurgeExpiredRules_NoExpired_ReturnsZero()
    {
        _service.AddRule("Active Rule");
        Assert.Equal(0, _service.PurgeExpiredRules());
    }

    // ── Pattern Matching Tests ──

    [Fact]
    public void MatchesFinding_ContainsMode_CaseInsensitive()
    {
        var rule = new IgnoreRule { Pattern = "smb", MatchMode = IgnoreMatchMode.Contains };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_ContainsMode_NoMatch()
    {
        var rule = new IgnoreRule { Pattern = "BitLocker", MatchMode = IgnoreMatchMode.Contains };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_ExactMode_MatchesExactly()
    {
        var rule = new IgnoreRule { Pattern = "SMB v1 Enabled", MatchMode = IgnoreMatchMode.Exact };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_ExactMode_CaseInsensitive()
    {
        var rule = new IgnoreRule { Pattern = "smb v1 enabled", MatchMode = IgnoreMatchMode.Exact };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_ExactMode_PartialDoesNotMatch()
    {
        var rule = new IgnoreRule { Pattern = "SMB", MatchMode = IgnoreMatchMode.Exact };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_RegexMode_Matches()
    {
        var rule = new IgnoreRule { Pattern = "^SMB.*Enabled$", MatchMode = IgnoreMatchMode.Regex };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_RegexMode_NoMatch()
    {
        var rule = new IgnoreRule { Pattern = "^BitLocker", MatchMode = IgnoreMatchMode.Regex };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_RegexMode_InvalidRegex_ReturnsFalse()
    {
        var rule = new IgnoreRule { Pattern = "[invalid", MatchMode = IgnoreMatchMode.Regex };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_SeverityFilter_Matches()
    {
        var rule = new IgnoreRule { Pattern = "SMB", Severity = Severity.Critical };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_SeverityFilter_WrongSeverity()
    {
        var rule = new IgnoreRule { Pattern = "SMB", Severity = Severity.Warning };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.MatchesFinding(rule, finding));
    }

    [Fact]
    public void MatchesFinding_ModuleFilter_Matches()
    {
        var rule = new IgnoreRule { Pattern = "SMB", Module = "Network" };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.MatchesFinding(rule, finding, "Network"));
    }

    [Fact]
    public void MatchesFinding_ModuleFilter_WrongModule()
    {
        var rule = new IgnoreRule { Pattern = "SMB", Module = "Firewall" };
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.MatchesFinding(rule, finding, "Network"));
    }

    [Fact]
    public void MatchesFinding_ModuleFilter_ContainsMatch()
    {
        var rule = new IgnoreRule { Pattern = "test", Module = "fire" };
        var finding = Finding.Warning("test finding", "desc", "Firewall");
        Assert.True(_service.MatchesFinding(rule, finding, "Firewall"));
    }

    [Fact]
    public void MatchesFinding_CombinedFilters()
    {
        var rule = new IgnoreRule
        {
            Pattern = "SMB",
            MatchMode = IgnoreMatchMode.Contains,
            Module = "Network",
            Severity = Severity.Critical
        };

        // Match: correct pattern + module + severity
        var match = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.MatchesFinding(rule, match, "Network"));

        // No match: wrong severity
        var wrongSev = Finding.Warning("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.MatchesFinding(rule, wrongSev, "Network"));

        // No match: wrong module
        var wrongMod = Finding.Critical("SMB v1 Enabled", "desc", "Firewall");
        Assert.False(_service.MatchesFinding(rule, wrongMod, "Firewall"));
    }

    // ── ApplyRules Tests ──

    [Fact]
    public void ApplyRules_NoRules_AllFindingsActive()
    {
        var findings = new List<Finding>
        {
            Finding.Critical("A", "desc", "Cat"),
            Finding.Warning("B", "desc", "Cat"),
        };

        var result = _service.ApplyRules(findings);
        Assert.Equal(2, result.ActiveFindings.Count);
        Assert.Empty(result.IgnoredFindings);
        Assert.Equal(2, result.TotalFindings);
        Assert.Equal(0, result.SuppressedCount);
    }

    [Fact]
    public void ApplyRules_MatchingRule_SuppressesFinding()
    {
        _service.AddRule("SMB");

        var findings = new List<Finding>
        {
            Finding.Critical("SMB v1 Enabled", "desc", "Network"),
            Finding.Warning("LLMNR Enabled", "desc", "Network"),
        };

        var result = _service.ApplyRules(findings);
        Assert.Single(result.ActiveFindings);
        Assert.Single(result.IgnoredFindings);
        Assert.Equal("LLMNR Enabled", result.ActiveFindings[0].Title);
        Assert.Equal("SMB v1 Enabled", result.IgnoredFindings[0].Finding.Title);
    }

    // ── ApplyRulesToReport Tests ──

    [Fact]
    public void ApplyRulesToReport_NoRules_ReturnsOriginal()
    {
        var report = CreateTestReport();
        var originalScore = report.SecurityScore;

        var filtered = _service.ApplyRulesToReport(report, out var ignored);
        Assert.Equal(originalScore, filtered.SecurityScore);
        Assert.Empty(ignored);
    }

    [Fact]
    public void ApplyRulesToReport_SuppressesMatchingFindings()
    {
        _service.AddRule("SMB");

        var report = CreateTestReport();
        var filtered = _service.ApplyRulesToReport(report, out var ignored);

        Assert.Single(ignored);
        Assert.Equal("SMB v1 Enabled", ignored[0].Finding.Title);

        // The filtered report should have a higher score (removed a critical finding)
        Assert.True(filtered.SecurityScore > report.SecurityScore);
    }

    [Fact]
    public void ApplyRulesToReport_MultipleRules_SuppressesAll()
    {
        _service.AddRule("SMB");
        _service.AddRule("LLMNR");
        _service.AddRule("Remote Desktop");

        var report = CreateTestReport();
        var filtered = _service.ApplyRulesToReport(report, out var ignored);

        Assert.Equal(3, ignored.Count);
        var ignoredTitles = ignored.Select(i => i.Finding.Title).OrderBy(t => t).ToList();
        Assert.Contains("LLMNR Enabled", ignoredTitles);
        Assert.Contains("Remote Desktop Enabled", ignoredTitles);
        Assert.Contains("SMB v1 Enabled", ignoredTitles);
    }

    [Fact]
    public void ApplyRulesToReport_ModuleScopedRule()
    {
        // Only suppress SMB findings in Network module
        _service.AddRule("Disabled", module: "Firewall");

        var report = CreateTestReport();
        var filtered = _service.ApplyRulesToReport(report, out var ignored);

        // Should match "Firewall Disabled" in Firewall, not other modules
        Assert.Single(ignored);
        Assert.Equal("Firewall Disabled", ignored[0].Finding.Title);
    }

    [Fact]
    public void ApplyRulesToReport_SeverityScopedRule()
    {
        // Only suppress Warning-level findings matching "Enabled"
        _service.AddRule("Enabled", severity: Severity.Warning);

        var report = CreateTestReport();
        var filtered = _service.ApplyRulesToReport(report, out var ignored);

        // Should match LLMNR Enabled (warning), Remote Desktop Enabled (warning), and BitLocker Not Enabled (warning)
        // but NOT SMB v1 Enabled (critical) or Firewall Disabled (critical)
        Assert.Equal(3, ignored.Count);
        Assert.DoesNotContain(ignored, i => i.Finding.Title == "SMB v1 Enabled");
        Assert.Contains(ignored, i => i.Finding.Title == "LLMNR Enabled");
        Assert.Contains(ignored, i => i.Finding.Title == "Remote Desktop Enabled");
        Assert.Contains(ignored, i => i.Finding.Title == "BitLocker Not Enabled");
    }

    [Fact]
    public void ApplyRulesToReport_RecalculatesScore()
    {
        var report = CreateTestReport();
        var originalScore = report.SecurityScore;

        // Suppress all critical findings
        _service.AddRule("Firewall Disabled", IgnoreMatchMode.Exact);
        _service.AddRule("SMB v1 Enabled", IgnoreMatchMode.Exact);

        var filtered = _service.ApplyRulesToReport(report, out _);

        // Score should be higher since we removed 2 critical findings (each -20 points)
        Assert.True(filtered.SecurityScore > originalScore);
    }

    [Fact]
    public void ApplyRulesToReport_DisabledRule_NotApplied()
    {
        var rule = _service.AddRule("SMB");
        _service.ToggleRule(rule.Id, false);

        var report = CreateTestReport();
        var filtered = _service.ApplyRulesToReport(report, out var ignored);

        Assert.Empty(ignored);
    }

    [Fact]
    public void ApplyRulesToReport_ExpiredRule_NotApplied()
    {
        _service.AddRule("SMB", expiresAt: DateTimeOffset.UtcNow.AddDays(-1));

        var report = CreateTestReport();
        var filtered = _service.ApplyRulesToReport(report, out var ignored);

        Assert.Empty(ignored);
    }

    // ── IsIgnored Tests ──

    [Fact]
    public void IsIgnored_MatchingRule_ReturnsTrue()
    {
        _service.AddRule("SMB");
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.True(_service.IsIgnored(finding));
    }

    [Fact]
    public void IsIgnored_NoMatchingRule_ReturnsFalse()
    {
        _service.AddRule("BitLocker");
        var finding = Finding.Critical("SMB v1 Enabled", "desc", "Network");
        Assert.False(_service.IsIgnored(finding));
    }

    // ── GetRuleMatchCounts Tests ──

    [Fact]
    public void GetRuleMatchCounts_CountsCorrectly()
    {
        var rule1 = _service.AddRule("Enabled");  // Matches many findings
        var rule2 = _service.AddRule("BitLocker"); // Matches one

        var report = CreateTestReport();
        var counts = _service.GetRuleMatchCounts(report);

        Assert.True(counts[rule1.Id] >= 3); // Multiple "...Enabled" findings
        Assert.Equal(1, counts[rule2.Id]);   // Just "BitLocker Not Enabled"
    }

    // ── IgnoreRule Model Tests ──

    [Fact]
    public void IgnoreRule_IsExpired_FutureDate_ReturnsFalse()
    {
        var rule = new IgnoreRule { ExpiresAt = DateTimeOffset.UtcNow.AddDays(30) };
        Assert.False(rule.IsExpired);
    }

    [Fact]
    public void IgnoreRule_IsExpired_PastDate_ReturnsTrue()
    {
        var rule = new IgnoreRule { ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1) };
        Assert.True(rule.IsExpired);
    }

    [Fact]
    public void IgnoreRule_IsExpired_NoExpiry_ReturnsFalse()
    {
        var rule = new IgnoreRule();
        Assert.False(rule.IsExpired);
    }

    [Fact]
    public void IgnoreRule_IsActive_EnabledAndNotExpired()
    {
        var rule = new IgnoreRule { Enabled = true, ExpiresAt = DateTimeOffset.UtcNow.AddDays(30) };
        Assert.True(rule.IsActive);
    }

    [Fact]
    public void IgnoreRule_IsActive_DisabledButNotExpired()
    {
        var rule = new IgnoreRule { Enabled = false, ExpiresAt = DateTimeOffset.UtcNow.AddDays(30) };
        Assert.False(rule.IsActive);
    }

    [Fact]
    public void IgnoreRule_IsActive_EnabledButExpired()
    {
        var rule = new IgnoreRule { Enabled = true, ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1) };
        Assert.False(rule.IsActive);
    }

    // ── IgnoreFilterResult Tests ──

    [Fact]
    public void IgnoreFilterResult_TotalFindings_Correct()
    {
        var result = new IgnoreFilterResult
        {
            ActiveFindings = [Finding.Warning("A", "d", "C")],
            IgnoredFindings = [new IgnoredFinding
            {
                Finding = Finding.Critical("B", "d", "C"),
                MatchedRule = new IgnoreRule { Pattern = "B" }
            }]
        };

        Assert.Equal(2, result.TotalFindings);
        Assert.Equal(1, result.SuppressedCount);
    }

    // ── Edge Cases ──

    [Fact]
    public void ApplyRules_EmptyFindings_ReturnsEmptyResult()
    {
        _service.AddRule("anything");
        var result = _service.ApplyRules(new List<Finding>());
        Assert.Empty(result.ActiveFindings);
        Assert.Empty(result.IgnoredFindings);
    }

    [Fact]
    public void AddRule_ExactMode_CreatesCorrectly()
    {
        var rule = _service.AddRule("Exact Title Match", IgnoreMatchMode.Exact);
        Assert.Equal(IgnoreMatchMode.Exact, rule.MatchMode);
    }

    [Fact]
    public void AddRule_RegexMode_ValidPattern()
    {
        var rule = _service.AddRule("^(SMB|LLMNR).*", IgnoreMatchMode.Regex);
        Assert.Equal(IgnoreMatchMode.Regex, rule.MatchMode);
    }

    [Fact]
    public void ApplyRulesToReport_PreservesAuditResultMetadata()
    {
        _service.AddRule("SMB");
        var report = CreateTestReport();

        var filtered = _service.ApplyRulesToReport(report, out _);

        // Verify audit result metadata is preserved
        foreach (var result in filtered.Results)
        {
            Assert.NotEmpty(result.ModuleName);
            Assert.NotEmpty(result.Category);
            Assert.True(result.Success);
        }
    }

    [Fact]
    public void AddRule_MultipleThenRemoveOne_RestPersist()
    {
        var r1 = _service.AddRule("Rule 1");
        var r2 = _service.AddRule("Rule 2");
        var r3 = _service.AddRule("Rule 3");

        _service.RemoveRule(r2.Id);

        var remaining = _service.GetAllRules();
        Assert.Equal(2, remaining.Count);
        Assert.Contains(remaining, r => r.Id == r1.Id);
        Assert.Contains(remaining, r => r.Id == r3.Id);
    }

    [Fact]
    public void MatchesFinding_ModuleFilter_FallsBackToFindingCategory()
    {
        var rule = new IgnoreRule { Pattern = "test", Module = "Network" };
        var finding = Finding.Warning("test finding", "desc", "Network");
        // When moduleCategory is null, should fall back to finding.Category
        Assert.True(_service.MatchesFinding(rule, finding, null));
    }
}
