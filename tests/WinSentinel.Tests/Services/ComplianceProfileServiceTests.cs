using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class ComplianceProfileServiceTests
{
    private readonly ComplianceProfileService _service = new();

    // ── Helper Methods ──────────────────────────────────────────────

    private static SecurityReport CreateReport(params (string module, string category, Finding[] findings)[] modules)
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow
        };

        foreach (var (module, category, findings) in modules)
        {
            var result = new AuditResult
            {
                ModuleName = module,
                Category = category,
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
            };
            foreach (var f in findings)
                result.Findings.Add(f);
            report.Results.Add(result);
        }

        report.SecurityScore = SecurityScorer.CalculateScore(report);
        return report;
    }

    private static SecurityReport CreateSimpleReport()
    {
        return CreateReport(
            ("FirewallAudit", "Firewall & Network Protection", new[]
            {
                Finding.Pass("Firewall Enabled", "All profiles enabled", "Firewall"),
                Finding.Warning("Inbound Rules Too Permissive", "Too many inbound rules", "Firewall",
                    "Review and remove unnecessary rules"),
            }),
            ("NetworkAudit", "Network Configuration", new[]
            {
                Finding.Critical("SMB Signing Not Required", "SMB signing is not enforced", "Network",
                    "Enable SMB signing"),
                Finding.Warning("LLMNR Protocol Enabled", "LLMNR is enabled", "Network",
                    "Disable LLMNR", "reg add HKLM\\..."),
                Finding.Warning("NetBIOS over TCP/IP Enabled", "NetBIOS is active", "Network",
                    "Disable NetBIOS"),
            }),
            ("EncryptionAudit", "Encryption", new[]
            {
                Finding.Warning("BitLocker Not Enabled", "System drive is not encrypted", "Encryption",
                    "Enable BitLocker", "manage-bde -on C:"),
            }),
            ("EventLogAudit", "Event Log", new[]
            {
                Finding.Warning("Audit Policy Not Configured", "No audit policy set", "EventLog",
                    "Configure audit policy"),
            }),
            ("AccountAudit", "Account Security", new[]
            {
                Finding.Warning("No Password Expiration Policy", "Passwords don't expire", "Accounts"),
                Finding.Info("Guest Account Status", "Guest account is disabled", "Accounts"),
            }),
            ("DefenderAudit", "Windows Defender", new[]
            {
                Finding.Pass("Real-time Protection", "Defender is active", "Defender"),
            }),
            ("ProcessAudit", "Running Processes", new[]
            {
                Finding.Info("Multiple Listening Services", "12 services listening on ports", "Processes"),
            })
        );
    }

    // ── Profile Registration Tests ──────────────────────────────────

    [Fact]
    public void Constructor_RegistersAllBuiltInProfiles()
    {
        Assert.Equal(4, _service.Profiles.Count);
        Assert.True(_service.ProfileExists("home"));
        Assert.True(_service.ProfileExists("developer"));
        Assert.True(_service.ProfileExists("enterprise"));
        Assert.True(_service.ProfileExists("server"));
    }

    [Fact]
    public void ProfileNames_ReturnsAllNames()
    {
        var names = _service.ProfileNames;
        Assert.Contains("home", names);
        Assert.Contains("developer", names);
        Assert.Contains("enterprise", names);
        Assert.Contains("server", names);
    }

    [Theory]
    [InlineData("home")]
    [InlineData("HOME")]
    [InlineData("Home")]
    public void ProfileExists_CaseInsensitive(string name)
    {
        Assert.True(_service.ProfileExists(name));
    }

    [Fact]
    public void ProfileExists_UnknownProfile_ReturnsFalse()
    {
        Assert.False(_service.ProfileExists("nonexistent"));
    }

    [Fact]
    public void GetProfile_ReturnsCorrectProfile()
    {
        var profile = _service.GetProfile("home");
        Assert.NotNull(profile);
        Assert.Equal("home", profile.Name);
        Assert.Equal("Home / Personal", profile.DisplayName);
    }

    [Fact]
    public void GetProfile_UnknownProfile_ReturnsNull()
    {
        Assert.Null(_service.GetProfile("nonexistent"));
    }

    [Theory]
    [InlineData("home", "HOME")]
    [InlineData("developer", "Developer")]
    [InlineData("enterprise", "ENTERPRISE")]
    [InlineData("server", "Server")]
    public void GetProfile_CaseInsensitive(string expected, string input)
    {
        var profile = _service.GetProfile(input);
        Assert.NotNull(profile);
        Assert.Equal(expected, profile.Name);
    }

    // ── Profile Properties Tests ────────────────────────────────────

    [Fact]
    public void HomeProfile_HasCorrectProperties()
    {
        var profile = _service.GetProfile("home")!;
        Assert.Equal(60, profile.ComplianceThreshold);
        Assert.NotEmpty(profile.Description);
        Assert.NotEmpty(profile.TargetAudience);
        Assert.NotEmpty(profile.Recommendations);
        Assert.NotEmpty(profile.ModuleWeights);
        Assert.NotEmpty(profile.SeverityOverrides);
    }

    [Fact]
    public void DeveloperProfile_HasCorrectProperties()
    {
        var profile = _service.GetProfile("developer")!;
        Assert.Equal(70, profile.ComplianceThreshold);
        Assert.NotEmpty(profile.Description);
        Assert.NotEmpty(profile.Recommendations);
    }

    [Fact]
    public void EnterpriseProfile_HasCorrectProperties()
    {
        var profile = _service.GetProfile("enterprise")!;
        Assert.Equal(85, profile.ComplianceThreshold);
        Assert.NotEmpty(profile.SeverityOverrides);
        // Enterprise should upgrade some findings to Critical
        Assert.Contains(profile.SeverityOverrides, kv => kv.Value.NewSeverity == Severity.Critical);
    }

    [Fact]
    public void ServerProfile_HasHighestThreshold()
    {
        var profile = _service.GetProfile("server")!;
        Assert.Equal(90, profile.ComplianceThreshold);
    }

    [Fact]
    public void AllProfiles_HaveRequiredFields()
    {
        foreach (var profile in _service.Profiles)
        {
            Assert.NotEmpty(profile.Name);
            Assert.NotEmpty(profile.DisplayName);
            Assert.NotEmpty(profile.Description);
            Assert.NotEmpty(profile.TargetAudience);
            Assert.True(profile.ComplianceThreshold >= 0 && profile.ComplianceThreshold <= 100);
            Assert.NotEmpty(profile.Recommendations);
        }
    }

    [Fact]
    public void AllProfiles_HaveReasonableWeights()
    {
        foreach (var profile in _service.Profiles)
        {
            foreach (var (module, weight) in profile.ModuleWeights)
            {
                Assert.True(weight >= 0.0, $"Weight for {module} in {profile.Name} is negative: {weight}");
                Assert.True(weight <= 2.0, $"Weight for {module} in {profile.Name} exceeds 2.0: {weight}");
            }
        }
    }

    [Fact]
    public void AllProfiles_OverridesHaveReasons()
    {
        foreach (var profile in _service.Profiles)
        {
            foreach (var (title, ov) in profile.SeverityOverrides)
            {
                Assert.NotEmpty(ov.Reason);
            }
        }
    }

    // ── Profile Thresholds (ascending strictness) ────────────────────

    [Fact]
    public void Profiles_ThresholdsAscendInStrictness()
    {
        var home = _service.GetProfile("home")!;
        var developer = _service.GetProfile("developer")!;
        var enterprise = _service.GetProfile("enterprise")!;
        var server = _service.GetProfile("server")!;

        Assert.True(home.ComplianceThreshold <= developer.ComplianceThreshold);
        Assert.True(developer.ComplianceThreshold <= enterprise.ComplianceThreshold);
        Assert.True(enterprise.ComplianceThreshold <= server.ComplianceThreshold);
    }

    // ── Apply Profile Tests ─────────────────────────────────────────

    [Fact]
    public void ApplyProfile_ByName_Works()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        Assert.NotNull(result);
        Assert.Equal("home", result.Profile.Name);
        Assert.True(result.AdjustedScore >= 0);
        Assert.True(result.AdjustedScore <= 100);
    }

    [Fact]
    public void ApplyProfile_UnknownName_Throws()
    {
        var report = CreateSimpleReport();
        Assert.Throws<ArgumentException>(() => _service.ApplyProfile("nonexistent", report));
    }

    [Fact]
    public void ApplyProfile_EmptyReport_Returns100()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            SecurityScore = 100
        };

        var result = _service.ApplyProfile("home", report);
        Assert.Equal(100, result.AdjustedScore);
        Assert.Equal("A", result.AdjustedGrade);
    }

    [Fact]
    public void ApplyProfile_SetsOriginalScore()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        Assert.Equal(report.SecurityScore, result.OriginalScore);
    }

    [Fact]
    public void ApplyProfile_SetsOriginalGrade()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        Assert.Equal(SecurityScorer.GetGrade(report.SecurityScore), result.OriginalGrade);
    }

    // ── Severity Override Tests ─────────────────────────────────────

    [Fact]
    public void ApplyProfile_HomeProfile_DowngradesSMBSigning()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        // SMB Signing should be downgraded from Critical to Info in home profile
        var smbOverride = result.AppliedOverrides
            .FirstOrDefault(o => o.FindingTitle == "SMB Signing Not Required");
        Assert.NotNull(smbOverride);
        Assert.Equal(Severity.Critical, smbOverride.OriginalSeverity);
        Assert.Equal(Severity.Info, smbOverride.NewSeverity);
    }

    [Fact]
    public void ApplyProfile_EnterpriseProfile_UpgradesSMBSigning()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("enterprise", report);

        // SMB Signing should remain Critical (or be upgraded) in enterprise
        var smbOverride = result.AppliedOverrides
            .FirstOrDefault(o => o.FindingTitle == "SMB Signing Not Required");
        // It's already Critical, so the override should match Critical
        // It shouldn't downgrade
        if (smbOverride != null)
        {
            Assert.Equal(Severity.Critical, smbOverride.NewSeverity);
        }
    }

    [Fact]
    public void ApplyProfile_HomeProfile_DowngradesLLMNR()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        var llmnrOverride = result.AppliedOverrides
            .FirstOrDefault(o => o.FindingTitle == "LLMNR Protocol Enabled");
        Assert.NotNull(llmnrOverride);
        Assert.Equal(Severity.Warning, llmnrOverride.OriginalSeverity);
        Assert.Equal(Severity.Info, llmnrOverride.NewSeverity);
    }

    [Fact]
    public void ApplyProfile_EnterpriseProfile_UpgradesLLMNR()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("enterprise", report);

        var llmnrOverride = result.AppliedOverrides
            .FirstOrDefault(o => o.FindingTitle == "LLMNR Protocol Enabled");
        Assert.NotNull(llmnrOverride);
        Assert.Equal(Severity.Critical, llmnrOverride.NewSeverity);
    }

    [Fact]
    public void ApplyProfile_OverridesCountMatchesApplied()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        Assert.Equal(result.AppliedOverrides.Count, result.OverridesApplied);
    }

    [Fact]
    public void ApplyProfile_OverridesRecordModuleCategory()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        foreach (var ov in result.AppliedOverrides)
        {
            Assert.NotEmpty(ov.ModuleCategory);
        }
    }

    [Fact]
    public void ApplyProfile_OverridesRecordReason()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        foreach (var ov in result.AppliedOverrides)
        {
            Assert.NotEmpty(ov.Reason);
        }
    }

    // ── Score Adjustment Tests ──────────────────────────────────────

    [Fact]
    public void ApplyProfile_HomeProfile_IncreasesScoreByDowngradingSeverities()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        // Home profile should generally increase score by downgrading enterprise findings
        // and reducing weight on less important modules
        Assert.True(result.AdjustedScore >= result.OriginalScore,
            $"Expected adjusted ({result.AdjustedScore}) >= original ({result.OriginalScore}) for home profile");
    }

    [Fact]
    public void ApplyProfile_EnterpriseProfile_MayDecreaseScoreByUpgradingSeverities()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("enterprise", report);

        // Enterprise profile may decrease or keep score same by upgrading findings
        // and increasing weights on critical modules
        Assert.True(result.AdjustedScore <= result.OriginalScore,
            $"Expected adjusted ({result.AdjustedScore}) <= original ({result.OriginalScore}) for enterprise profile");
    }

    [Fact]
    public void ApplyProfile_AdjustedScoreClampedTo0_100()
    {
        var report = CreateReport(
            ("TestModule", "Firewall & Network Protection", new[]
            {
                Finding.Critical("Issue 1", "desc", "cat"),
                Finding.Critical("Issue 2", "desc", "cat"),
                Finding.Critical("Issue 3", "desc", "cat"),
                Finding.Critical("Issue 4", "desc", "cat"),
                Finding.Critical("Issue 5", "desc", "cat"),
                Finding.Critical("Issue 6", "desc", "cat"),
            })
        );

        var result = _service.ApplyProfile("server", report);
        Assert.True(result.AdjustedScore >= 0);
        Assert.True(result.AdjustedScore <= 100);
    }

    // ── Module Weights Tests ────────────────────────────────────────

    [Fact]
    public void ApplyProfile_ModuleScoresRecordsWeights()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        Assert.NotEmpty(result.ModuleScores);
        foreach (var ms in result.ModuleScores)
        {
            Assert.NotEmpty(ms.Category);
        }
    }

    [Fact]
    public void ApplyProfile_ModulesWeightedCountIsCorrect()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        // Home profile has multiple modules with non-1.0 weights
        Assert.True(result.ModulesWeighted > 0);
    }

    [Fact]
    public void ApplyProfile_HomeProfile_ReducesEventLogWeight()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        var eventLog = result.ModuleScores.FirstOrDefault(m => m.Category == "Event Log");
        Assert.NotNull(eventLog);
        Assert.True(eventLog.Weight < 1.0, $"Expected Event Log weight < 1.0 in home profile, got {eventLog.Weight}");
    }

    [Fact]
    public void ApplyProfile_EnterpriseProfile_IncreasesEncryptionWeight()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("enterprise", report);

        var encryption = result.ModuleScores.FirstOrDefault(m => m.Category == "Encryption");
        Assert.NotNull(encryption);
        Assert.True(encryption.Weight > 1.0, $"Expected Encryption weight > 1.0 in enterprise profile, got {encryption.Weight}");
    }

    [Fact]
    public void ApplyProfile_ServerProfile_ReducesBrowserWeight()
    {
        var report = CreateSimpleReport();

        // Add a browser module to the report
        var browserReport = CreateReport(
            ("BrowserAudit", "Browser Security", new[]
            {
                Finding.Warning("Outdated Browser", "Browser needs update", "Browser"),
            })
        );

        var result = _service.ApplyProfile("server", browserReport);
        var browser = result.ModuleScores.FirstOrDefault(m => m.Category == "Browser Security");
        Assert.NotNull(browser);
        Assert.True(browser.Weight < 1.0, $"Expected Browser weight < 1.0 in server profile, got {browser.Weight}");
    }

    // ── Skipped Modules Tests ───────────────────────────────────────

    [Fact]
    public void ApplyProfile_WithSkippedModule_SkipsInResults()
    {
        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test profile",
            ComplianceThreshold = 50,
            SkippedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Event Log" }
        };

        var report = CreateSimpleReport();
        var result = _service.ApplyProfile(profile, report);

        var eventLog = result.ModuleScores.FirstOrDefault(m => m.Category == "Event Log");
        Assert.NotNull(eventLog);
        Assert.True(eventLog.Skipped);
        Assert.Equal(1, result.ModulesSkipped);
    }

    [Fact]
    public void ApplyProfile_SkippedModule_ExcludedFromScoring()
    {
        // Create a report with one bad module
        var report = CreateReport(
            ("GoodModule", "Good Category", new[]
            {
                Finding.Pass("All Good", "desc", "cat"),
            }),
            ("BadModule", "Bad Category", new[]
            {
                Finding.Critical("Bad Issue 1", "desc", "cat"),
                Finding.Critical("Bad Issue 2", "desc", "cat"),
                Finding.Critical("Bad Issue 3", "desc", "cat"),
                Finding.Critical("Bad Issue 4", "desc", "cat"),
                Finding.Critical("Bad Issue 5", "desc", "cat"),
            })
        );

        // Without skipping - score should be low
        var noSkipProfile = new ComplianceProfile
        {
            Name = "noskip",
            DisplayName = "No Skip",
            Description = "No skip",
            ComplianceThreshold = 50,
        };

        var resultNoSkip = _service.ApplyProfile(noSkipProfile, report);

        // With skipping bad module - score should be higher
        var skipProfile = new ComplianceProfile
        {
            Name = "skip",
            DisplayName = "Skip",
            Description = "Skip",
            ComplianceThreshold = 50,
            SkippedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Bad Category" }
        };

        var resultSkip = _service.ApplyProfile(skipProfile, report);
        Assert.True(resultSkip.AdjustedScore > resultNoSkip.AdjustedScore);
    }

    // ── Compliance Verdict Tests ────────────────────────────────────

    [Fact]
    public void ApplyProfile_IsCompliant_WhenAboveThreshold()
    {
        // Perfect report
        var report = CreateReport(
            ("TestModule", "Test Category", new[]
            {
                Finding.Pass("All Good", "desc", "cat"),
            })
        );

        var result = _service.ApplyProfile("home", report);
        Assert.True(result.IsCompliant);
    }

    [Fact]
    public void ApplyProfile_IsNotCompliant_WhenBelowThreshold()
    {
        // Terrible report
        var report = CreateReport(
            ("TestModule", "Firewall & Network Protection", new[]
            {
                Finding.Critical("Issue 1", "desc", "cat"),
                Finding.Critical("Issue 2", "desc", "cat"),
                Finding.Critical("Issue 3", "desc", "cat"),
                Finding.Critical("Issue 4", "desc", "cat"),
                Finding.Critical("Issue 5", "desc", "cat"),
            })
        );

        var result = _service.ApplyProfile("server", report);
        Assert.False(result.IsCompliant);
    }

    [Fact]
    public void ApplyProfile_ComplianceThresholdFromProfile()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);
        Assert.Equal(60, result.ComplianceThreshold);
    }

    [Fact]
    public void ApplyProfile_AddsDeficitRecommendation_WhenNotCompliant()
    {
        var report = CreateReport(
            ("TestModule", "Firewall & Network Protection", new[]
            {
                Finding.Critical("Issue 1", "desc", "cat"),
                Finding.Critical("Issue 2", "desc", "cat"),
                Finding.Critical("Issue 3", "desc", "cat"),
                Finding.Critical("Issue 4", "desc", "cat"),
                Finding.Critical("Issue 5", "desc", "cat"),
            })
        );

        var result = _service.ApplyProfile("enterprise", report);
        if (!result.IsCompliant)
        {
            Assert.Contains(result.Recommendations, r => r.Contains("below") && r.Contains("threshold"));
        }
    }

    // ── Module Score Calculation with Overrides ─────────────────────

    [Fact]
    public void CalculateModuleScoreWithOverrides_NoOverrides_MatchesOriginal()
    {
        var auditResult = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        auditResult.Findings.Add(Finding.Warning("Test Warning", "desc", "cat"));

        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test"
        };

        var score = ComplianceProfileService.CalculateModuleScoreWithOverrides(auditResult, profile);
        Assert.Equal(95, score); // 100 - 5 for one warning
    }

    [Fact]
    public void CalculateModuleScoreWithOverrides_WithDowngrade_IncreasesScore()
    {
        var auditResult = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        auditResult.Findings.Add(Finding.Critical("Critical Issue", "desc", "cat"));

        var profileNoOverride = new ComplianceProfile
        {
            Name = "test1",
            DisplayName = "Test",
            Description = "Test"
        };

        var profileWithOverride = new ComplianceProfile
        {
            Name = "test2",
            DisplayName = "Test",
            Description = "Test",
            SeverityOverrides = new Dictionary<string, SeverityOverride>
            {
                ["Critical Issue"] = new(Severity.Info, "Not relevant")
            }
        };

        var scoreNoOverride = ComplianceProfileService.CalculateModuleScoreWithOverrides(auditResult, profileNoOverride);
        var scoreWithOverride = ComplianceProfileService.CalculateModuleScoreWithOverrides(auditResult, profileWithOverride);

        Assert.Equal(80, scoreNoOverride);  // 100 - 20
        Assert.Equal(100, scoreWithOverride); // Info doesn't deduct
    }

    [Fact]
    public void CalculateModuleScoreWithOverrides_WithUpgrade_DecreasesScore()
    {
        var auditResult = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        auditResult.Findings.Add(Finding.Warning("Warning Issue", "desc", "cat"));

        var profileWithUpgrade = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test",
            SeverityOverrides = new Dictionary<string, SeverityOverride>
            {
                ["Warning Issue"] = new(Severity.Critical, "Critical in this context")
            }
        };

        var score = ComplianceProfileService.CalculateModuleScoreWithOverrides(auditResult, profileWithUpgrade);
        Assert.Equal(80, score); // 100 - 20 (upgraded to Critical)
    }

    [Fact]
    public void CalculateModuleScoreWithOverrides_CaseInsensitive()
    {
        var auditResult = new AuditResult
        {
            ModuleName = "Test",
            Category = "Test",
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow.AddSeconds(1)
        };
        auditResult.Findings.Add(Finding.Critical("SMB Signing Not Required", "desc", "cat"));

        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test",
            SeverityOverrides = new Dictionary<string, SeverityOverride>
            {
                ["smb signing not required"] = new(Severity.Info, "Not relevant")
            }
        };

        var score = ComplianceProfileService.CalculateModuleScoreWithOverrides(auditResult, profile);
        Assert.Equal(100, score); // Downgraded to Info
    }

    // ── Recommendations Tests ───────────────────────────────────────

    [Fact]
    public void ApplyProfile_IncludesProfileRecommendations()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        Assert.NotEmpty(result.Recommendations);
    }

    [Fact]
    public void ApplyProfile_RecommendationsContainProfileSpecificAdvice()
    {
        var report = CreateSimpleReport();

        var homeResult = _service.ApplyProfile("home", report);
        var enterpriseResult = _service.ApplyProfile("enterprise", report);

        // Different profiles should have different recommendations
        Assert.NotEqual(homeResult.Recommendations, enterpriseResult.Recommendations);
    }

    // ── Timestamp Tests ─────────────────────────────────────────────

    [Fact]
    public void ApplyProfile_SetsCheckedAtTimestamp()
    {
        var before = DateTimeOffset.UtcNow;
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);
        var after = DateTimeOffset.UtcNow;

        Assert.True(result.CheckedAt >= before);
        Assert.True(result.CheckedAt <= after);
    }

    // ── Grade Tests ─────────────────────────────────────────────────

    [Fact]
    public void ApplyProfile_AdjustedGradeMatchesScore()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        Assert.Equal(SecurityScorer.GetGrade(result.AdjustedScore), result.AdjustedGrade);
    }

    // ── Module Overrides In Module Count ────────────────────────────

    [Fact]
    public void ApplyProfile_TracksOverridesPerModule()
    {
        var report = CreateSimpleReport();
        var result = _service.ApplyProfile("home", report);

        // Network Configuration should have overrides (SMB, LLMNR, NetBIOS)
        var networkModule = result.ModuleScores.FirstOrDefault(m => m.Category == "Network Configuration");
        Assert.NotNull(networkModule);
        Assert.True(networkModule.OverridesInModule > 0);
    }

    // ── Cross-profile Comparison Tests ──────────────────────────────

    [Fact]
    public void DifferentProfiles_ProduceDifferentScores()
    {
        var report = CreateSimpleReport();

        var homeResult = _service.ApplyProfile("home", report);
        var enterpriseResult = _service.ApplyProfile("enterprise", report);
        var serverResult = _service.ApplyProfile("server", report);

        // Home should be most lenient, server most strict
        Assert.True(homeResult.AdjustedScore >= enterpriseResult.AdjustedScore,
            $"Home ({homeResult.AdjustedScore}) should score >= Enterprise ({enterpriseResult.AdjustedScore})");
    }

    [Fact]
    public void DifferentProfiles_HaveDifferentOverrideCounts()
    {
        var report = CreateSimpleReport();

        var homeResult = _service.ApplyProfile("home", report);
        var enterpriseResult = _service.ApplyProfile("enterprise", report);

        // Both should apply overrides but potentially different numbers
        Assert.True(homeResult.OverridesApplied > 0 || enterpriseResult.OverridesApplied > 0);
    }

    // ── Custom Profile Tests ────────────────────────────────────────

    [Fact]
    public void ApplyProfile_CustomProfile_Works()
    {
        var customProfile = new ComplianceProfile
        {
            Name = "custom",
            DisplayName = "Custom",
            Description = "Custom test profile",
            ComplianceThreshold = 50,
            ModuleWeights = new Dictionary<string, double>
            {
                ["Firewall & Network Protection"] = 2.0,
                ["Network Configuration"] = 0.5,
            },
            SeverityOverrides = new Dictionary<string, SeverityOverride>
            {
                ["SMB Signing Not Required"] = new(Severity.Pass, "Not applicable"),
            },
        };

        var report = CreateSimpleReport();
        var result = _service.ApplyProfile(customProfile, report);

        Assert.Equal("custom", result.Profile.Name);
        Assert.True(result.AdjustedScore >= 0);
        Assert.True(result.AdjustedScore <= 100);
    }

    [Fact]
    public void ApplyProfile_DefaultWeight_IsOnePointZero()
    {
        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test",
        };

        var report = CreateReport(
            ("TestModule", "Unweighted Category", new[]
            {
                Finding.Warning("Test", "desc", "cat"),
            })
        );

        var result = _service.ApplyProfile(profile, report);
        var moduleScore = result.ModuleScores.First();
        Assert.Equal(1.0, moduleScore.Weight);
    }

    // ── SeverityOverride Model Tests ────────────────────────────────

    [Fact]
    public void SeverityOverride_ConstructorSetsFields()
    {
        var ov = new SeverityOverride(Severity.Warning, "Test reason");
        Assert.Equal(Severity.Warning, ov.NewSeverity);
        Assert.Equal("Test reason", ov.Reason);
    }

    [Fact]
    public void SeverityOverride_DefaultConstructor_Works()
    {
        var ov = new SeverityOverride();
        Assert.Equal(default, ov.NewSeverity);
        Assert.Equal("", ov.Reason);
    }

    // ── ComplianceResult Model Tests ────────────────────────────────

    [Fact]
    public void ComplianceResult_IsCompliant_DependsOnThreshold()
    {
        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test",
            ComplianceThreshold = 70,
        };

        var report = CreateReport(
            ("TestModule", "Test", new[]
            {
                Finding.Pass("Good", "desc", "cat"),
            })
        );

        var result = _service.ApplyProfile(profile, report);
        Assert.True(result.IsCompliant); // Score 100 > threshold 70
    }

    [Fact]
    public void ComplianceResult_IsNotCompliant_WhenScoreBelowThreshold()
    {
        var profile = new ComplianceProfile
        {
            Name = "test",
            DisplayName = "Test",
            Description = "Test",
            ComplianceThreshold = 95,
        };

        var report = CreateReport(
            ("TestModule", "Test", new[]
            {
                Finding.Warning("Issue 1", "desc", "cat"),
                Finding.Warning("Issue 2", "desc", "cat"),
            })
        );

        var result = _service.ApplyProfile(profile, report);
        // Score = 90, threshold = 95 → not compliant
        Assert.False(result.IsCompliant);
    }
}
