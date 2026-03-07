using Xunit;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;


public class PolicyManagerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _rulesPath;
    private readonly IgnoreRuleService _ignoreService;
    private readonly ComplianceProfileService _complianceService;
    private readonly PolicyManager _manager;

    public PolicyManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "winsentinel-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _rulesPath = Path.Combine(_tempDir, "ignore-rules.json");
        _ignoreService = new IgnoreRuleService(_rulesPath);
        _complianceService = new ComplianceProfileService();
        _manager = new PolicyManager(_ignoreService, _complianceService);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    // ── Export ────────────────────────────────────────────────────

    [Fact]
    public void Export_ReturnsPolicy_WithCorrectVersion()
    {
        var policy = _manager.Export();
        Assert.Equal(1, policy.Version);
    }

    [Fact]
    public void Export_IncludesIgnoreRules()
    {
        _ignoreService.AddRule("test-pattern", reason: "test reason");
        var policy = _manager.Export();
        Assert.Equal(1, policy.IgnoreRules.Count);
        Assert.Equal("test-pattern", policy.IgnoreRules[0].Pattern);
    }

    [Fact]
    public void Export_IncludesDefaultAlertRules()
    {
        var policy = _manager.Export();
        Assert.True(policy.AlertRules.Count > 0, "Should include default alert rules");
    }

    [Fact]
    public void Export_SetsNameAndAuthor()
    {
        var policy = _manager.Export("My Policy", "Test description");
        Assert.Equal("My Policy", policy.Name);
        Assert.Equal("Test description", policy.Description);
        Assert.False(string.IsNullOrEmpty(policy.Author));
    }

    [Fact]
    public void Export_DefaultName_UsesMachineName()
    {
        var policy = _manager.Export();
        Assert.True(policy.Name.Contains("Policy"));
    }

    // ── Export/Load roundtrip ────────────────────────────────────

    [Fact]
    public void ExportToFile_CreatesValidFile()
    {
        var filePath = Path.Combine(_tempDir, "test-policy.json");
        _manager.ExportToFile(filePath);
        Assert.True(File.Exists(filePath));
    }

    [Fact]
    public void ExportThenLoad_Roundtrips()
    {
        _ignoreService.AddRule("test-rule", reason: "roundtrip test");
        var filePath = Path.Combine(_tempDir, "roundtrip.json");
        _manager.ExportToFile(filePath);

        var loaded = PolicyManager.LoadFromFile(filePath);
        Assert.Equal(1, loaded.Version);
        Assert.Equal(1, loaded.IgnoreRules.Count);
        Assert.Equal("test-rule", loaded.IgnoreRules[0].Pattern);
    }

    [Fact]
    
    public void LoadFromFile_ThrowsIfNotFound()
    {
        Assert.Throws<FileNotFoundException>(() =>
            PolicyManager.LoadFromFile(Path.Combine(_tempDir, "nonexistent.json")));
    }

    // ── Validate ─────────────────────────────────────────────────

    [Fact]
    public void Validate_ValidPolicy_ReturnsNoErrors()
    {
        var policy = new SecurityPolicy
        {
            Name = "Test Policy",
            ComplianceProfile = "home"
        };
        var result = _manager.Validate(policy);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidVersion_ReturnsError()
    {
        var policy = new SecurityPolicy { Version = 0 };
        var result = _manager.Validate(policy);
        Assert.False(result.IsValid);
        Assert.True(result.Errors.Any(e => e.Contains("version")));
    }

    [Fact]
    public void Validate_FutureVersion_ReturnsWarning()
    {
        var policy = new SecurityPolicy { Version = 99, Name = "Future" };
        var result = _manager.Validate(policy);
        Assert.True(result.IsValid); // warning, not error
        Assert.True(result.Warnings.Any(w => w.Contains("newer")));
    }

    [Fact]
    public void Validate_UnknownProfile_ReturnsError()
    {
        var policy = new SecurityPolicy
        {
            Name = "Bad Profile",
            ComplianceProfile = "nonexistent-profile-xyz"
        };
        var result = _manager.Validate(policy);
        Assert.False(result.IsValid);
        Assert.True(result.Errors.Any(e => e.Contains("Unknown compliance profile")));
    }

    [Fact]
    public void Validate_KnownProfile_IsValid()
    {
        var policy = new SecurityPolicy
        {
            Name = "Valid",
            ComplianceProfile = "enterprise"
        };
        var result = _manager.Validate(policy);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidMinScore_ReturnsError()
    {
        var policy = new SecurityPolicy
        {
            Name = "Bad Score",
            MinimumScore = 150
        };
        var result = _manager.Validate(policy);
        Assert.False(result.IsValid);
        Assert.True(result.Errors.Any(e => e.Contains("MinimumScore")));
    }

    [Fact]
    public void Validate_EmptyIgnorePattern_ReturnsError()
    {
        var policy = new SecurityPolicy
        {
            Name = "Empty Pattern",
            IgnoreRules = [new IgnoreRule { Pattern = "" }]
        };
        var result = _manager.Validate(policy);
        Assert.False(result.IsValid);
        Assert.True(result.Errors.Any(e => e.Contains("empty pattern")));
    }

    [Fact]
    public void Validate_InvalidRegex_ReturnsError()
    {
        var policy = new SecurityPolicy
        {
            Name = "Bad Regex",
            IgnoreRules = [new IgnoreRule
            {
                Pattern = "[invalid(",
                MatchMode = IgnoreMatchMode.Regex
            }]
        };
        var result = _manager.Validate(policy);
        Assert.False(result.IsValid);
        Assert.True(result.Errors.Any(e => e.Contains("invalid regex")));
    }

    [Fact]
    public void Validate_ExpiredRule_ReturnsWarning()
    {
        var policy = new SecurityPolicy
        {
            Name = "Expired",
            IgnoreRules = [new IgnoreRule
            {
                Pattern = "old-finding",
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(-30)
            }]
        };
        var result = _manager.Validate(policy);
        Assert.True(result.IsValid); // warning, not error
        Assert.True(result.Warnings.Any(w => w.Contains("expired")));
    }

    [Fact]
    public void Validate_NoName_ReturnsWarning()
    {
        var policy = new SecurityPolicy { Name = "" };
        var result = _manager.Validate(policy);
        Assert.True(result.IsValid);
        Assert.True(result.Warnings.Any(w => w.Contains("no name")));
    }

    // ── Diff ─────────────────────────────────────────────────────

    [Fact]
    public void Diff_IdenticalConfigs_NoChanges()
    {
        var policy = _manager.Export();
        var diff = _manager.Diff(policy);
        Assert.False(diff.HasChanges);
    }

    [Fact]
    public void Diff_AdditionalIgnoreRule_DetectsAdded()
    {
        var policy = _manager.Export();
        policy.IgnoreRules.Add(new IgnoreRule { Pattern = "new-rule" });
        var diff = _manager.Diff(policy);
        Assert.True(diff.HasChanges);
        Assert.Equal(1, diff.IgnoreRulesAdded);
    }

    [Fact]
    public void Diff_RemovedIgnoreRule_DetectsRemoved()
    {
        _ignoreService.AddRule("existing-rule");
        var incoming = _manager.Export(); // start from current export to match alerts
        incoming.IgnoreRules.Clear(); // remove the ignore rule
        var diff = _manager.Diff(incoming);
        Assert.True(diff.HasChanges);
        Assert.Equal(1, diff.IgnoreRulesRemoved);
    }

    [Fact]
    public void Diff_ProfileChange_Detected()
    {
        var policy = _manager.Export();
        policy.ComplianceProfile = "enterprise";
        var diff = _manager.Diff(policy);
        Assert.True(diff.ComplianceProfileChanged);
        Assert.Equal("enterprise", diff.IncomingProfile);
    }

    [Fact]
    public void Diff_MinScoreChange_Detected()
    {
        var policy = _manager.Export();
        policy.MinimumScore = 85;
        var diff = _manager.Diff(policy);
        Assert.True(diff.MinimumScoreChanged);
        Assert.Equal(85, diff.IncomingMinScore);
    }

    [Fact]
    public void Diff_SkippedModuleChange_Detected()
    {
        var policy = _manager.Export();
        policy.SkippedModules.Add("Event Log");
        var diff = _manager.Diff(policy);
        Assert.True(diff.HasChanges);
        Assert.Equal(1, diff.SkippedModulesAdded);
    }

    [Fact]
    public void Diff_Details_ContainHumanReadable()
    {
        var policy = _manager.Export();
        policy.IgnoreRules.Add(new IgnoreRule { Pattern = "firewall-disabled" });
        policy.ComplianceProfile = "server";
        var diff = _manager.Diff(policy);
        Assert.True(diff.Details.Any(d => d.Contains("firewall-disabled")));
    }

    // ── Import ───────────────────────────────────────────────────

    [Fact]
    public void Import_ValidPolicy_Success()
    {
        var policy = new SecurityPolicy
        {
            Name = "Import Test",
            IgnoreRules = [
                new IgnoreRule { Pattern = "imported-rule-1", Reason = "test" },
                new IgnoreRule { Pattern = "imported-rule-2", Reason = "test" }
            ]
        };
        var result = _manager.Import(policy);
        Assert.True(result.Success);
        Assert.Equal(2, result.IgnoreRulesImported);

        // Verify rules were actually persisted
        var rules = _ignoreService.GetAllRules();
        Assert.Equal(2, rules.Count);
    }

    [Fact]
    public void Import_ClearsExistingRules()
    {
        _ignoreService.AddRule("old-rule", reason: "should be removed");
        Assert.Equal(1, _ignoreService.GetAllRules().Count);

        var policy = new SecurityPolicy
        {
            Name = "Replace",
            IgnoreRules = [new IgnoreRule { Pattern = "new-rule" }]
        };
        var result = _manager.Import(policy);
        Assert.True(result.Success);

        var rules = _ignoreService.GetAllRules();
        Assert.Equal(1, rules.Count);
        Assert.Equal("new-rule", rules[0].Pattern);
    }

    [Fact]
    public void Import_SkipsExpiredRules()
    {
        var policy = new SecurityPolicy
        {
            Name = "Expired Rules",
            IgnoreRules = [
                new IgnoreRule { Pattern = "active", Reason = "keep" },
                new IgnoreRule
                {
                    Pattern = "expired",
                    Reason = "should skip",
                    ExpiresAt = DateTimeOffset.UtcNow.AddDays(-10)
                }
            ]
        };
        var result = _manager.Import(policy);
        Assert.True(result.Success);
        Assert.Equal(1, result.IgnoreRulesImported); // only the active one
    }

    [Fact]
    public void Import_InvalidPolicy_FailsWithoutForce()
    {
        var policy = new SecurityPolicy
        {
            Name = "Invalid",
            ComplianceProfile = "nonexistent-xyz"
        };
        var result = _manager.Import(policy, force: false);
        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.True(result.Error.Contains("Validation failed"));
    }

    [Fact]
    public void Import_InvalidPolicy_SucceedsWithForce()
    {
        var policy = new SecurityPolicy
        {
            Name = "Force Import",
            ComplianceProfile = "nonexistent-xyz",
            IgnoreRules = [new IgnoreRule { Pattern = "forced" }]
        };
        var result = _manager.Import(policy, force: true);
        Assert.True(result.Success);
        Assert.Equal(1, result.IgnoreRulesImported);
    }

    // ── End-to-end roundtrip ─────────────────────────────────────

    [Fact]
    public void FullRoundtrip_ExportImportPreservesConfig()
    {
        // Set up some config
        _ignoreService.AddRule("rule-one", IgnoreMatchMode.Contains, reason: "first");
        _ignoreService.AddRule("rule-two", IgnoreMatchMode.Exact, reason: "second");

        // Export
        var filePath = Path.Combine(_tempDir, "full-roundtrip.json");
        _manager.ExportToFile(filePath, "Roundtrip Test", "End-to-end test");

        // Create fresh services
        var newRulesPath = Path.Combine(_tempDir, "new-rules.json");
        var newIgnoreService = new IgnoreRuleService(newRulesPath);
        var newManager = new PolicyManager(newIgnoreService, _complianceService);

        // Import
        var policy = PolicyManager.LoadFromFile(filePath);
        var result = newManager.Import(policy);

        Assert.True(result.Success);
        Assert.Equal(2, result.IgnoreRulesImported);

        // Verify
        var importedRules = newIgnoreService.GetAllRules();
        Assert.Equal(2, importedRules.Count);
        Assert.True(importedRules.Any(r => r.Pattern == "rule-one"));
        Assert.True(importedRules.Any(r => r.Pattern == "rule-two"));
    }

    [Fact]
    public void Serialize_ProducesValidJson()
    {
        var policy = _manager.Export("JSON Test");
        var json = PolicyManager.Serialize(policy);
        Assert.True(json.Contains("JSON Test"));
        Assert.True(json.Contains("version"));
        Assert.True(json.Contains("ignoreRules"));
    }

    // ── Policy model ─────────────────────────────────────────────

    [Fact]
    public void SecurityPolicy_DefaultsAreCorrect()
    {
        var policy = new SecurityPolicy();
        Assert.Equal(1, policy.Version);
        Assert.Equal("", policy.Name);
        Assert.Null(policy.ComplianceProfile);
        Assert.Null(policy.MinimumScore);
        Assert.Equal(0, policy.IgnoreRules.Count);
        Assert.Equal(0, policy.AlertRules.Count);
        Assert.Equal(0, policy.SkippedModules.Count);
        Assert.Equal(0, policy.Tags.Count);
    }

    [Fact]
    public void PolicyDiffResult_HasChanges_FalseWhenEmpty()
    {
        var diff = new PolicyDiffResult();
        Assert.False(diff.HasChanges);
    }

    [Fact]
    public void PolicyValidationResult_IsValid_TrueWhenNoErrors()
    {
        var result = new PolicyValidationResult();
        Assert.True(result.IsValid);
        result.Warnings.Add("just a warning");
        Assert.True(result.IsValid); // warnings don't affect validity
    }

    [Fact]
    public void PolicyValidationResult_IsValid_FalseWithErrors()
    {
        var result = new PolicyValidationResult();
        result.Errors.Add("something wrong");
        Assert.False(result.IsValid);
    }
}

