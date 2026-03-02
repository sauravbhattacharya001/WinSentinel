using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

/// <summary>Stub audit module for testing profile-based module selection.</summary>
file class StubModule : IAuditModule
{
    public string Name { get; }
    public string Category { get; }
    public string Description => $"Stub module: {Name}";

    public StubModule(string name, string category = "Test")
    {
        Name = name;
        Category = category;
    }

    public Task<AuditResult> RunAuditAsync(CancellationToken ct = default)
        => Task.FromResult(new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow,
            EndTime = DateTimeOffset.UtcNow,
            Findings = new()
        });
}

public class ScanProfileManagerTests
{
    private static List<IAuditModule> CreateTestModules() => new()
    {
        new StubModule("Firewall", "Network"),
        new StubModule("Defender", "Antivirus"),
        new StubModule("Updates", "System"),
        new StubModule("Account Security", "Identity"),
        new StubModule("Network", "Network"),
        new StubModule("Privacy", "Privacy"),
        new StubModule("Browser Security", "Privacy"),
        new StubModule("App Security", "Applications"),
        new StubModule("Process Audit", "System"),
        new StubModule("Startup Items", "System"),
        new StubModule("System Info", "System"),
        new StubModule("Encryption", "Security"),
        new StubModule("Event Log", "Monitoring"),
    };

    private static SecurityReport CreateTestReport()
    {
        return new SecurityReport
        {
            SecurityScore = 75,
            GeneratedAt = DateTimeOffset.UtcNow,
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "Firewall",
                    Category = "Network",
                    Findings = new()
                    {
                        new Finding { Title = "Firewall disabled", Description = "Windows Firewall is turned off", Severity = Severity.Critical },
                        new Finding { Title = "Inbound rule too broad", Description = "An inbound rule allows all traffic", Severity = Severity.Warning },
                        new Finding { Title = "Firewall logging off", Description = "Firewall logging is not enabled", Severity = Severity.Info },
                        new Finding { Title = "Default rules present", Description = "Default firewall rules are configured", Severity = Severity.Pass },
                    }
                },
                new()
                {
                    ModuleName = "Privacy",
                    Category = "Privacy",
                    Findings = new()
                    {
                        new Finding { Title = "Telemetry enabled", Description = "Windows telemetry is sending data", Severity = Severity.Warning },
                        new Finding { Title = "Location tracking on", Description = "Location services are enabled", Severity = Severity.Info },
                    }
                },
                new()
                {
                    ModuleName = "Defender",
                    Category = "Antivirus",
                    Findings = new()
                    {
                        new Finding { Title = "Definitions outdated", Description = "Virus definitions are more than 7 days old", Severity = Severity.Critical },
                    }
                }
            }
        };
    }

    // ── Constructor & Built-in Profiles ─────────────────────

    [Fact]
    public void Constructor_RegistersBuiltInProfiles()
    {
        var mgr = new ScanProfileManager();
        Assert.True(mgr.Count >= 5);
        Assert.True(mgr.HasProfile("Quick"));
        Assert.True(mgr.HasProfile("Full"));
        Assert.True(mgr.HasProfile("Privacy"));
        Assert.True(mgr.HasProfile("Network"));
        Assert.True(mgr.HasProfile("CriticalOnly"));
    }

    [Fact]
    public void BuiltInProfiles_AreMarkedBuiltIn()
    {
        var mgr = new ScanProfileManager();
        var builtIns = mgr.GetBuiltInProfiles();
        Assert.True(builtIns.Count >= 5);
        Assert.All(builtIns, p => Assert.True(p.IsBuiltIn));
    }

    [Fact]
    public void BuiltInProfiles_HaveNonEmptyDescriptions()
    {
        var mgr = new ScanProfileManager();
        var builtIns = mgr.GetBuiltInProfiles();
        Assert.All(builtIns, p => Assert.False(string.IsNullOrWhiteSpace(p.Description)));
    }

    [Fact]
    public void BuiltInProfiles_HaveTags()
    {
        var mgr = new ScanProfileManager();
        var builtIns = mgr.GetBuiltInProfiles();
        Assert.All(builtIns, p => Assert.NotEmpty(p.Tags));
    }

    // ── Profile CRUD ─────────────────────────────────────────

    [Fact]
    public void AddProfile_CustomProfile_Succeeds()
    {
        var mgr = new ScanProfileManager();
        var profile = new ScanProfile
        {
            Name = "MyCustom",
            Description = "A custom test profile",
            IncludeModules = { "Firewall", "Network" },
            Tags = { "custom" }
        };

        var result = mgr.AddProfile(profile);
        Assert.Same(mgr, result); // fluent
        Assert.True(mgr.HasProfile("MyCustom"));
        Assert.False(mgr.GetProfile("MyCustom")!.IsBuiltIn);
    }

    [Fact]
    public void AddProfile_CaseInsensitive()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile { Name = "TestProfile" });
        Assert.True(mgr.HasProfile("testprofile"));
        Assert.True(mgr.HasProfile("TESTPROFILE"));
    }

    [Fact]
    public void AddProfile_Duplicate_Throws()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile { Name = "Test" });
        Assert.Throws<InvalidOperationException>(
            () => mgr.AddProfile(new ScanProfile { Name = "Test" }));
    }

    [Fact]
    public void AddProfile_BuiltInNameCollision_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<InvalidOperationException>(
            () => mgr.AddProfile(new ScanProfile { Name = "Quick" }));
    }

    [Fact]
    public void AddProfile_EmptyName_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<ArgumentException>(
            () => mgr.AddProfile(new ScanProfile { Name = "" }));
    }

    [Fact]
    public void AddProfile_TooLongName_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<ArgumentException>(
            () => mgr.AddProfile(new ScanProfile { Name = new string('x', 100) }));
    }

    [Fact]
    public void AddProfile_Null_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<ArgumentNullException>(() => mgr.AddProfile(null!));
    }

    [Fact]
    public void AddProfile_TooManyTags_Throws()
    {
        var mgr = new ScanProfileManager();
        var profile = new ScanProfile
        {
            Name = "TooManyTags",
            Tags = Enumerable.Range(0, 25).Select(i => $"tag{i}").ToList()
        };
        Assert.Throws<ArgumentException>(() => mgr.AddProfile(profile));
    }

    [Fact]
    public void UpdateProfile_CustomProfile_Succeeds()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile
        {
            Name = "MyProfile",
            Description = "Original"
        });

        mgr.UpdateProfile(new ScanProfile
        {
            Name = "MyProfile",
            Description = "Updated"
        });

        var updated = mgr.GetProfile("MyProfile");
        Assert.Equal("Updated", updated!.Description);
        Assert.NotNull(updated.ModifiedAt);
    }

    [Fact]
    public void UpdateProfile_BuiltIn_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<InvalidOperationException>(() =>
            mgr.UpdateProfile(new ScanProfile { Name = "Quick", Description = "modified" }));
    }

    [Fact]
    public void UpdateProfile_NotFound_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<KeyNotFoundException>(() =>
            mgr.UpdateProfile(new ScanProfile { Name = "nonexistent" }));
    }

    [Fact]
    public void RemoveProfile_CustomProfile_Succeeds()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile { Name = "ToRemove" });
        Assert.True(mgr.RemoveProfile("ToRemove"));
        Assert.False(mgr.HasProfile("ToRemove"));
    }

    [Fact]
    public void RemoveProfile_BuiltIn_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<InvalidOperationException>(
            () => mgr.RemoveProfile("Quick"));
    }

    [Fact]
    public void RemoveProfile_NotFound_ReturnsFalse()
    {
        var mgr = new ScanProfileManager();
        Assert.False(mgr.RemoveProfile("nonexistent"));
    }

    // ── Profile Queries ──────────────────────────────────────

    [Fact]
    public void GetProfiles_NoFilter_ReturnsAll()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile { Name = "Custom1" });
        var all = mgr.GetProfiles();
        Assert.True(all.Count >= 6); // 5 built-in + 1 custom
    }

    [Fact]
    public void GetProfiles_FilterByTag()
    {
        var mgr = new ScanProfileManager();
        var privacy = mgr.GetProfiles("privacy");
        Assert.Contains(privacy, p => p.Name == "Privacy");
    }

    [Fact]
    public void GetCustomProfiles_ExcludesBuiltIn()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile { Name = "Custom1" });
        var customs = mgr.GetCustomProfiles();
        Assert.Single(customs);
        Assert.Equal("Custom1", customs[0].Name);
    }

    [Fact]
    public void ProfileNames_ContainsAllProfiles()
    {
        var mgr = new ScanProfileManager();
        var names = mgr.ProfileNames;
        Assert.Contains("Quick", names);
        Assert.Contains("Full", names);
    }

    // ── Module Selection ─────────────────────────────────────

    [Fact]
    public void SelectModules_QuickProfile_SelectsCriticalModules()
    {
        var mgr = new ScanProfileManager();
        var modules = CreateTestModules();
        var selected = mgr.SelectModules("Quick", modules);

        var names = selected.Select(m => m.Name).ToList();
        Assert.Contains("Firewall", names);
        Assert.Contains("Defender", names);
        Assert.DoesNotContain("Privacy", names);
        Assert.DoesNotContain("Browser Security", names);
    }

    [Fact]
    public void SelectModules_FullProfile_SelectsAll()
    {
        var mgr = new ScanProfileManager();
        var modules = CreateTestModules();
        var selected = mgr.SelectModules("Full", modules);
        Assert.Equal(modules.Count, selected.Count);
    }

    [Fact]
    public void SelectModules_PrivacyProfile_SelectsPrivacyModules()
    {
        var mgr = new ScanProfileManager();
        var modules = CreateTestModules();
        var selected = mgr.SelectModules("Privacy", modules);

        var names = selected.Select(m => m.Name).ToList();
        Assert.Contains("Privacy", names);
        Assert.Contains("Browser Security", names);
        Assert.Contains("App Security", names);
        Assert.DoesNotContain("Firewall", names);
    }

    [Fact]
    public void SelectModules_NetworkProfile_SelectsNetworkModules()
    {
        var mgr = new ScanProfileManager();
        var modules = CreateTestModules();
        var selected = mgr.SelectModules("Network", modules);

        var names = selected.Select(m => m.Name).ToList();
        Assert.Contains("Firewall", names);
        Assert.Contains("Network", names);
        Assert.Equal(2, selected.Count);
    }

    [Fact]
    public void SelectModules_CustomWithExclude_ExcludesCorrectly()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile
        {
            Name = "NoPrivacy",
            ExcludeModules = { "Privacy", "Browser Security" }
        });

        var modules = CreateTestModules();
        var selected = mgr.SelectModules("NoPrivacy", modules);

        var names = selected.Select(m => m.Name).ToList();
        Assert.DoesNotContain("Privacy", names);
        Assert.DoesNotContain("Browser Security", names);
        Assert.Equal(modules.Count - 2, selected.Count);
    }

    [Fact]
    public void SelectModules_IncludeAndExclude_ExcludeWins()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile
        {
            Name = "IncExc",
            IncludeModules = { "Firewall", "Network", "Privacy" },
            ExcludeModules = { "Privacy" }
        });

        var modules = CreateTestModules();
        var selected = mgr.SelectModules("IncExc", modules);

        var names = selected.Select(m => m.Name).ToList();
        Assert.Contains("Firewall", names);
        Assert.Contains("Network", names);
        Assert.DoesNotContain("Privacy", names);
        Assert.Equal(2, selected.Count);
    }

    [Fact]
    public void SelectModules_CaseInsensitiveModuleNames()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile
        {
            Name = "CaseTest",
            IncludeModules = { "firewall", "NETWORK" }
        });

        var modules = CreateTestModules();
        var selected = mgr.SelectModules("CaseTest", modules);
        Assert.Equal(2, selected.Count);
    }

    [Fact]
    public void SelectModules_UnknownProfile_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<KeyNotFoundException>(
            () => mgr.SelectModules("nonexistent", CreateTestModules()));
    }

    [Fact]
    public void SelectModules_EmptyModuleList_ReturnsEmpty()
    {
        var mgr = new ScanProfileManager();
        var selected = mgr.SelectModules("Quick", new List<IAuditModule>());
        Assert.Empty(selected);
    }

    // ── Finding Filtering ────────────────────────────────────

    [Fact]
    public void FilterReport_MinSeverityWarning_FiltersLower()
    {
        var mgr = new ScanProfileManager();
        var report = CreateTestReport();

        // Quick profile has MinimumSeverity = Warning
        var filtered = mgr.FilterReport("Quick", report);

        // Firewall: Critical + Warning survive (Info + Pass filtered)
        var fw = filtered.Results.First(r => r.ModuleName == "Firewall");
        Assert.Equal(2, fw.Findings.Count);
        Assert.All(fw.Findings, f => Assert.True(f.Severity >= Severity.Warning));

        // Privacy: Warning survives, Info filtered
        var priv = filtered.Results.First(r => r.ModuleName == "Privacy");
        Assert.Single(priv.Findings);
    }

    [Fact]
    public void FilterReport_MinSeverityCritical_OnlyCritical()
    {
        var mgr = new ScanProfileManager();
        var report = CreateTestReport();

        var filtered = mgr.FilterReport("CriticalOnly", report);

        var allFindings = filtered.Results.SelectMany(r => r.Findings).ToList();
        Assert.Equal(2, allFindings.Count); // 2 Critical findings total
        Assert.All(allFindings, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void FilterReport_MinSeverityPass_NoFiltering()
    {
        var mgr = new ScanProfileManager();
        var report = CreateTestReport();

        var filtered = mgr.FilterReport("Full", report);

        Assert.Equal(
            report.Results.Sum(r => r.Findings.Count),
            filtered.Results.Sum(r => r.Findings.Count));
    }

    [Fact]
    public void FilterReport_PreservesReportMetadata()
    {
        var mgr = new ScanProfileManager();
        var report = CreateTestReport();

        var filtered = mgr.FilterReport("CriticalOnly", report);

        Assert.Equal(report.GeneratedAt, filtered.GeneratedAt);
        Assert.Equal(report.SecurityScore, filtered.SecurityScore);
        Assert.Equal(report.Results.Count, filtered.Results.Count);
    }

    // ── ApplyProfile ─────────────────────────────────────────

    [Fact]
    public void ApplyProfile_ReturnsProfiledScanResult()
    {
        var mgr = new ScanProfileManager();
        var modules = CreateTestModules();
        var report = CreateTestReport();

        var quick = mgr.GetProfile("Quick")!;
        var result = mgr.ApplyProfile(quick, modules, report);

        Assert.Equal("Quick", result.ProfileName);
        Assert.True(result.SelectedModules.Count < modules.Count);
        Assert.True(result.ExcludedModules.Count > 0);
        Assert.Equal(modules.Count, result.TotalAvailableModules);
        Assert.True(result.FilteredFindingsCount >= 0);
    }

    [Fact]
    public void ApplyProfile_Full_NoExclusions()
    {
        var mgr = new ScanProfileManager();
        var modules = CreateTestModules();
        var report = CreateTestReport();

        var full = mgr.GetProfile("Full")!;
        var result = mgr.ApplyProfile(full, modules, report);

        Assert.Empty(result.ExcludedModules);
        Assert.Equal(modules.Count, result.SelectedModules.Count);
        Assert.Equal(0, result.FilteredFindingsCount);
    }

    [Fact]
    public void ApplyProfile_CriticalOnly_FiltersNonCritical()
    {
        var mgr = new ScanProfileManager();
        var modules = CreateTestModules();
        var report = CreateTestReport();

        var critical = mgr.GetProfile("CriticalOnly")!;
        var result = mgr.ApplyProfile(critical, modules, report);

        // Original has 7 findings, 2 are Critical → 5 filtered
        Assert.Equal(5, result.FilteredFindingsCount);
    }

    // ── Serialization ────────────────────────────────────────

    [Fact]
    public void ExportCustomProfiles_OnlyIncludesCustom()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile
        {
            Name = "Export1",
            Description = "Test export",
            Tags = { "test" }
        });

        var json = mgr.ExportCustomProfiles();
        Assert.Contains("Export1", json);
        Assert.DoesNotContain("Quick", json); // Built-in excluded
    }

    [Fact]
    public void ExportCustomProfiles_NoCustom_EmptyArray()
    {
        var mgr = new ScanProfileManager();
        var json = mgr.ExportCustomProfiles();
        Assert.Equal("[]", json);
    }

    [Fact]
    public void ImportCustomProfiles_RoundTrip()
    {
        var mgr1 = new ScanProfileManager();
        mgr1.AddProfile(new ScanProfile
        {
            Name = "Custom1",
            Description = "Test profile",
            IncludeModules = { "Firewall", "Network" },
            MinimumSeverity = Severity.Warning,
            Tags = { "test" }
        });

        var json = mgr1.ExportCustomProfiles();

        var mgr2 = new ScanProfileManager();
        int imported = mgr2.ImportCustomProfiles(json);

        Assert.Equal(1, imported);
        var profile = mgr2.GetProfile("Custom1");
        Assert.NotNull(profile);
        Assert.Equal("Test profile", profile!.Description);
        Assert.Equal(Severity.Warning, profile.MinimumSeverity);
        Assert.Contains("Firewall", profile.IncludeModules);
    }

    [Fact]
    public void ImportCustomProfiles_SkipsBuiltInNames()
    {
        var mgr = new ScanProfileManager();
        string json = """[{"Name":"Quick","Description":"Fake Quick"}]""";
        int imported = mgr.ImportCustomProfiles(json);
        Assert.Equal(0, imported);

        // Original Quick profile unchanged
        var quick = mgr.GetProfile("Quick");
        Assert.True(quick!.IsBuiltIn);
    }

    [Fact]
    public void ImportCustomProfiles_NullJson_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.Throws<ArgumentException>(() => mgr.ImportCustomProfiles(null!));
    }

    [Fact]
    public void ImportCustomProfiles_InvalidJson_Throws()
    {
        var mgr = new ScanProfileManager();
        Assert.ThrowsAny<Exception>(() => mgr.ImportCustomProfiles("{invalid}"));
    }

    [Fact]
    public void ImportCustomProfiles_OverwritesExisting()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile
        {
            Name = "Overwrite",
            Description = "Original"
        });

        string json = """[{"Name":"Overwrite","Description":"Imported"}]""";
        mgr.ImportCustomProfiles(json);

        Assert.Equal("Imported", mgr.GetProfile("Overwrite")!.Description);
    }

    // ── Edge Cases ───────────────────────────────────────────

    [Fact]
    public void SelectModules_ProfileObject_Directly()
    {
        var mgr = new ScanProfileManager();
        var profile = new ScanProfile
        {
            Name = "Direct",
            IncludeModules = { "Firewall" }
        };

        var modules = CreateTestModules();
        var selected = mgr.SelectModules(profile, modules);
        Assert.Single(selected);
        Assert.Equal("Firewall", selected[0].Name);
    }

    [Fact]
    public void FilterReport_ProfileObject_Directly()
    {
        var mgr = new ScanProfileManager();
        var profile = new ScanProfile
        {
            Name = "Direct",
            MinimumSeverity = Severity.Critical
        };

        var report = CreateTestReport();
        var filtered = mgr.FilterReport(profile, report);
        var allFindings = filtered.Results.SelectMany(r => r.Findings).ToList();
        Assert.All(allFindings, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void AddProfile_MaxProfileLimit()
    {
        var mgr = new ScanProfileManager();
        // Built-in profiles take 5 slots, add up to limit
        int toAdd = ScanProfileManager.MaxProfiles - mgr.Count;
        for (int i = 0; i < toAdd; i++)
            mgr.AddProfile(new ScanProfile { Name = $"P{i}" });

        Assert.Throws<InvalidOperationException>(
            () => mgr.AddProfile(new ScanProfile { Name = "overflow" }));
    }

    [Fact]
    public void AddProfile_SetsCreatedAt()
    {
        var mgr = new ScanProfileManager();
        var before = DateTimeOffset.UtcNow;
        mgr.AddProfile(new ScanProfile { Name = "Timed" });
        var after = DateTimeOffset.UtcNow;

        var profile = mgr.GetProfile("Timed");
        Assert.InRange(profile!.CreatedAt, before, after);
    }

    [Fact]
    public void UpdateProfile_PreservesCreatedAt()
    {
        var mgr = new ScanProfileManager();
        mgr.AddProfile(new ScanProfile { Name = "Preserve" });
        var original = mgr.GetProfile("Preserve")!.CreatedAt;

        mgr.UpdateProfile(new ScanProfile
        {
            Name = "Preserve",
            Description = "Updated"
        });

        Assert.Equal(original, mgr.GetProfile("Preserve")!.CreatedAt);
    }

    [Fact]
    public void GetProfile_NotFound_ReturnsNull()
    {
        var mgr = new ScanProfileManager();
        Assert.Null(mgr.GetProfile("nonexistent"));
    }
}
