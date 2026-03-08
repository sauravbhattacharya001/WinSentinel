using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class MitreAttackMapperTests
{
    private readonly MitreAttackMapper _mapper = new();

    private static SecurityReport CreateReport(params Finding[] findings)
    {
        return new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "TestModule",
                    Category = "Test",
                    Findings = findings.ToList()
                }
            }
        };
    }

    private static SecurityReport CreateReportWithCategories(
        params (string category, Finding[] findings)[] modules)
    {
        return new SecurityReport
        {
            Results = modules.Select(m => new AuditResult
            {
                ModuleName = m.category + "Module",
                Category = m.category,
                Findings = m.findings.ToList()
            }).ToList()
        };
    }

    #region Constructor & Basics

    [Fact]
    public void Constructor_InitializesTechniques()
    {
        Assert.NotEmpty(_mapper.TechniqueIds);
        Assert.True(_mapper.TechniqueIds.Count >= 40);
    }

    [Fact]
    public void Constructor_InitializesTactics()
    {
        Assert.NotEmpty(_mapper.Tactics);
        Assert.Equal(14, _mapper.Tactics.Count);
    }

    [Fact]
    public void GetTechnique_KnownId_ReturnsTechnique()
    {
        var tech = _mapper.GetTechnique("T1059");
        Assert.NotNull(tech);
        Assert.Equal("Command and Scripting Interpreter", tech.Name);
        Assert.Equal(AttackTactic.Execution, tech.Tactic);
    }

    [Fact]
    public void GetTechnique_UnknownId_ReturnsNull()
    {
        Assert.Null(_mapper.GetTechnique("T9999"));
    }

    [Fact]
    public void GetTechnique_CaseInsensitive()
    {
        Assert.NotNull(_mapper.GetTechnique("t1059"));
    }

    [Fact]
    public void GetTacticName_AllTactics_ReturnReadableNames()
    {
        foreach (var tactic in _mapper.Tactics)
        {
            var name = MitreAttackMapper.GetTacticName(tactic);
            Assert.NotEmpty(name);
            Assert.DoesNotContain("_", name);
        }
    }

    [Fact]
    public void MitreUrl_Format()
    {
        var tech = _mapper.GetTechnique("T1059.001");
        Assert.NotNull(tech);
        Assert.Equal("https://attack.mitre.org/techniques/T1059/001", tech.MitreUrl);
    }

    #endregion

    #region GetTechniquesForTactic

    [Fact]
    public void GetTechniquesForTactic_ReturnsCorrectTechniques()
    {
        var execTechs = _mapper.GetTechniquesForTactic(AttackTactic.Execution);
        Assert.NotEmpty(execTechs);
        Assert.All(execTechs, t => Assert.Equal(AttackTactic.Execution, t.Tactic));
    }

    [Fact]
    public void GetTechniquesForTactic_OrderedById()
    {
        var techs = _mapper.GetTechniquesForTactic(AttackTactic.InitialAccess);
        var ids = techs.Select(t => t.Id).ToList();
        Assert.Equal(ids.OrderBy(x => x).ToList(), ids);
    }

    #endregion

    #region MapFinding

    [Fact]
    public void MapFinding_PowerShellCategory_MapsToExecution()
    {
        var finding = Finding.Warning("Unrestricted execution policy",
            "PowerShell execution policy is unrestricted", "PowerShell");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1059.001", techniques);
    }

    [Fact]
    public void MapFinding_RDPCategory_MapsToMultiple()
    {
        var finding = Finding.Warning("RDP enabled",
            "Remote Desktop Protocol is enabled", "RDP");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1133", techniques);  // Initial Access
        Assert.Contains("T1021.001", techniques);  // Lateral Movement
    }

    [Fact]
    public void MapFinding_PassSeverity_StillMaps()
    {
        // MapFinding works on any severity; Analyze filters
        var finding = Finding.Pass("Firewall OK", "Firewall is properly configured", "Firewall");
        var techniques = _mapper.MapFinding(finding);
        // Should still find matches based on category
        Assert.NotNull(techniques);
    }

    [Fact]
    public void MapFinding_NoMatch_ReturnsEmpty()
    {
        var finding = Finding.Warning("Unknown issue", "Something unrelated", "UnknownCategory");
        var techniques = _mapper.MapFinding(finding);
        Assert.Empty(techniques);
    }

    [Fact]
    public void MapFinding_ScheduledTasks_MapsToPersistence()
    {
        var finding = Finding.Critical("Suspicious scheduled task",
            "Unrecognized scheduled task found", "ScheduledTasks");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1053", techniques);
    }

    [Fact]
    public void MapFinding_USBCategory_MapsToExfiltration()
    {
        var finding = Finding.Warning("USB storage enabled",
            "USB removable storage is enabled", "USB");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1052", techniques);
    }

    [Fact]
    public void MapFinding_ClipboardCategory_MapsToCollection()
    {
        var finding = Finding.Warning("Clipboard history enabled",
            "Clipboard history is enabled", "Clipboard");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1115", techniques);
    }

    [Fact]
    public void MapFinding_AccountsWithPasswordTitle_MapsToCredentialAccess()
    {
        var finding = Finding.Warning("Weak password policy",
            "Password minimum length is too short", "Accounts");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1110", techniques);
    }

    [Fact]
    public void MapFinding_BackupCategory_MapsToImpact()
    {
        var finding = Finding.Warning("No recovery points",
            "System restore point backup is disabled", "Backup");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1490", techniques);
    }

    [Fact]
    public void MapFinding_SMBCategory_MapsToLateralAndDiscovery()
    {
        var finding = Finding.Warning("SMB v1 enabled",
            "SMBv1 share protocol is enabled", "SMB");
        var techniques = _mapper.MapFinding(finding);
        Assert.Contains("T1021.002", techniques);
        Assert.Contains("T1135", techniques);
    }

    #endregion

    #region Analyze

    [Fact]
    public void Analyze_EmptyReport_ReturnsCleanResult()
    {
        var report = CreateReport();
        var result = _mapper.Analyze(report);
        Assert.Equal(0, result.TotalFindings);
        Assert.Equal(0, result.MappedFindings);
        Assert.Equal(0, result.TechniquesExposed);
        Assert.Equal(0, result.TacticsExposed);
        Assert.Equal("None", result.OverallExposureLevel);
        Assert.Equal(100, result.CoveragePercent);
    }

    [Fact]
    public void Analyze_OnlyPassFindings_ReturnsNoExposure()
    {
        var report = CreateReport(
            Finding.Pass("Firewall OK", "All good", "Firewall"),
            Finding.Pass("RDP disabled", "Good", "RDP")
        );
        var result = _mapper.Analyze(report);
        Assert.Equal(2, result.TotalFindings);
        Assert.Equal(0, result.MappedFindings);
        Assert.Equal(0, result.TechniquesExposed);
    }

    [Fact]
    public void Analyze_OnlyInfoFindings_ReturnsNoExposure()
    {
        var report = CreateReport(
            Finding.Info("System info", "Windows 11", "System")
        );
        var result = _mapper.Analyze(report);
        Assert.Equal(0, result.MappedFindings);
    }

    [Fact]
    public void Analyze_WarningFindings_CreatesExposure()
    {
        var report = CreateReportWithCategories(
            ("PowerShell", new[] { Finding.Warning("Unrestricted", "Bad policy", "PowerShell") }),
            ("RDP", new[] { Finding.Warning("RDP open", "RDP is on", "RDP") })
        );
        var result = _mapper.Analyze(report);
        Assert.True(result.MappedFindings > 0);
        Assert.True(result.TacticsExposed > 0);
        Assert.True(result.TechniquesExposed > 0);
    }

    [Fact]
    public void Analyze_CriticalFindings_HigherExposure()
    {
        var reportWarn = CreateReportWithCategories(
            ("PowerShell", new[] { Finding.Warning("Unrestricted", "Bad", "PowerShell") })
        );
        var reportCrit = CreateReportWithCategories(
            ("PowerShell", new[] { Finding.Critical("Unrestricted", "Bad", "PowerShell") })
        );
        var warnResult = _mapper.Analyze(reportWarn);
        var critResult = _mapper.Analyze(reportCrit);
        Assert.True(critResult.OverallExposureScore >= warnResult.OverallExposureScore);
    }

    [Fact]
    public void Analyze_MultipleTactics_AllRepresented()
    {
        var report = CreateReportWithCategories(
            ("PowerShell", new[] { Finding.Warning("Script execution", "Bad", "PowerShell") }),
            ("RDP", new[] { Finding.Warning("RDP open", "Bad", "RDP") }),
            ("Accounts", new[] { Finding.Warning("Weak password policy", "Bad", "Accounts") }),
            ("Startup", new[] { Finding.Warning("Suspicious startup item", "Bad", "Startup") })
        );
        var result = _mapper.Analyze(report);
        Assert.True(result.TacticsExposed >= 3);
    }

    [Fact]
    public void Analyze_KillChainHeatmap_AllTacticsPresent()
    {
        var report = CreateReport(
            Finding.Warning("Test", "Test", "PowerShell")
        );
        var result = _mapper.Analyze(report);
        Assert.Equal(14, result.KillChainHeatmap.Count);
        Assert.All(result.KillChainHeatmap.Values, v =>
            Assert.Contains(v, new[] { "None", "Low", "Medium", "High", "Critical" }));
    }

    [Fact]
    public void Analyze_TopTechniques_LimitedTo10()
    {
        var findings = new List<Finding>();
        // Create many findings across different categories
        foreach (var cat in new[] { "PowerShell", "RDP", "SMB", "Accounts", "Firewall",
            "USB", "Clipboard", "Startup", "Registry", "Backup", "Updates", "Encryption" })
        {
            findings.Add(Finding.Critical($"Issue in {cat}", $"Problem in {cat}", cat));
        }
        var report = CreateReportWithCategories(
            findings.Select(f => (f.Category, new[] { f })).ToArray());
        var result = _mapper.Analyze(report);
        Assert.True(result.TopTechniques.Count <= 10);
    }

    [Fact]
    public void Analyze_Recommendations_NotEmpty_WhenExposureExists()
    {
        var report = CreateReportWithCategories(
            ("RDP", new[] { Finding.Critical("RDP open", "Bad", "RDP") }),
            ("Accounts", new[] { Finding.Critical("Weak passwords", "Bad", "Accounts") })
        );
        var result = _mapper.Analyze(report);
        Assert.NotEmpty(result.Recommendations);
    }

    [Fact]
    public void Analyze_Recommendations_NoExposure_ReturnsMinimalAdvice()
    {
        var report = CreateReport();
        var result = _mapper.Analyze(report);
        Assert.Single(result.Recommendations);
        Assert.Contains("minimal", result.Recommendations[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_CoveragePercent_Calculated()
    {
        var report = CreateReportWithCategories(
            ("PowerShell", new[] { Finding.Warning("Script", "Bad", "PowerShell") }),
            ("UnknownCat", new[] { Finding.Warning("Random", "Unknown", "UnknownCat") })
        );
        var result = _mapper.Analyze(report);
        Assert.True(result.CoveragePercent > 0);
        Assert.True(result.CoveragePercent <= 100);
        Assert.True(result.UnmappedFindings > 0);
    }

    [Fact]
    public void Analyze_ExposureLevel_MatchesScore()
    {
        // Create a high-exposure scenario
        var findings = new[] { "PowerShell", "RDP", "SMB", "Accounts", "Firewall", "USB", "Startup" }
            .SelectMany(cat => Enumerable.Range(0, 3).Select(i =>
                Finding.Critical($"Issue {i} in {cat}", $"Critical problem", cat)))
            .ToArray();
        var report = CreateReportWithCategories(
            findings.Select(f => (f.Category, new[] { f })).ToArray());
        var result = _mapper.Analyze(report);

        // Verify level matches score
        if (result.OverallExposureScore >= 75) Assert.Equal("Critical", result.OverallExposureLevel);
        else if (result.OverallExposureScore >= 50) Assert.Equal("High", result.OverallExposureLevel);
        else if (result.OverallExposureScore >= 25) Assert.Equal("Medium", result.OverallExposureLevel);
        else if (result.OverallExposureScore > 0) Assert.Equal("Low", result.OverallExposureLevel);
        else Assert.Equal("None", result.OverallExposureLevel);
    }

    [Fact]
    public void Analyze_TacticExposure_SortedByTacticOrder()
    {
        var report = CreateReportWithCategories(
            ("Startup", new[] { Finding.Warning("Startup item", "Bad", "Startup") }),
            ("PowerShell", new[] { Finding.Warning("Script", "Bad", "PowerShell") })
        );
        var result = _mapper.Analyze(report);
        if (result.TacticExposures.Count >= 2)
        {
            for (int i = 1; i < result.TacticExposures.Count; i++)
            {
                Assert.True(result.TacticExposures[i].Tactic >= result.TacticExposures[i - 1].Tactic);
            }
        }
    }

    [Fact]
    public void Analyze_TechniqueSummary_OrderedBySeverityThenCount()
    {
        var report = CreateReportWithCategories(
            ("RDP", new[]
            {
                Finding.Critical("RDP critical", "Bad", "RDP"),
                Finding.Warning("RDP warning 1", "Bad", "RDP"),
                Finding.Warning("RDP warning 2", "Bad", "RDP")
            })
        );
        var result = _mapper.Analyze(report);
        foreach (var tactic in result.TacticExposures)
        {
            if (tactic.Techniques.Count >= 2)
            {
                Assert.True(tactic.Techniques[0].HighestSeverity >= tactic.Techniques[1].HighestSeverity);
            }
        }
    }

    #endregion

    #region Recommendations

    [Fact]
    public void Analyze_InitialAccessExposure_RecommendsHardening()
    {
        var report = CreateReportWithCategories(
            ("RDP", new[]
            {
                Finding.Critical("RDP enabled", "RDP is on", "RDP"),
                Finding.Critical("RDP no NLA", "NLA disabled", "RDP"),
                Finding.Critical("RDP exposed", "RDP on internet", "RDP")
            })
        );
        var result = _mapper.Analyze(report);
        Assert.Contains(result.Recommendations,
            r => r.Contains("initial access", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_CredentialExposure_RecommendsPasswordPolicy()
    {
        var report = CreateReportWithCategories(
            ("Accounts", new[]
            {
                Finding.Critical("Weak password policy", "Bad", "Accounts"),
                Finding.Critical("No lockout", "No account lockout", "Accounts"),
                Finding.Critical("Password too short", "Bad", "Accounts")
            })
        );
        var result = _mapper.Analyze(report);
        Assert.Contains(result.Recommendations,
            r => r.Contains("credential", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_LateralMovementExposure_RecommendsSegmentation()
    {
        var report = CreateReportWithCategories(
            ("SMB", new[]
            {
                Finding.Critical("SMBv1 enabled", "SMBv1 share on", "SMB"),
                Finding.Critical("Admin shares", "Admin share exposed", "SMB"),
                Finding.Critical("SMB open", "SMB accessible", "SMB")
            })
        );
        var result = _mapper.Analyze(report);
        Assert.Contains(result.Recommendations,
            r => r.Contains("lateral movement", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_CriticalTactics_UrgentRecommendation()
    {
        // Many critical findings to push exposure to Critical level
        var findings = Enumerable.Range(0, 5)
            .Select(i => Finding.Critical($"Critical RDP {i}", "Bad", "RDP"))
            .ToArray();
        var report = CreateReportWithCategories(("RDP", findings));
        var result = _mapper.Analyze(report);
        if (result.TacticExposures.Any(t => t.ExposureLevel == "Critical"))
        {
            Assert.Contains(result.Recommendations,
                r => r.Contains("URGENT", StringComparison.OrdinalIgnoreCase));
        }
    }

    #endregion

    #region FormatReport

    [Fact]
    public void FormatReport_EmptyReport_ReturnsValidText()
    {
        var report = CreateReport();
        var result = _mapper.Analyze(report);
        var text = _mapper.FormatReport(result);
        Assert.Contains("MITRE ATT&CK", text);
        Assert.Contains("Kill Chain Heatmap", text);
        Assert.Contains("None", text);
    }

    [Fact]
    public void FormatReport_WithFindings_IncludesTechniqueIds()
    {
        var report = CreateReportWithCategories(
            ("PowerShell", new[] { Finding.Warning("Script", "Bad", "PowerShell") })
        );
        var result = _mapper.Analyze(report);
        var text = _mapper.FormatReport(result);
        Assert.Contains("T1059", text);
    }

    [Fact]
    public void FormatReport_CriticalExposure_ShowsDoubleExclamation()
    {
        var report = CreateReportWithCategories(
            ("PowerShell", new[] { Finding.Critical("Script", "Bad", "PowerShell") })
        );
        var result = _mapper.Analyze(report);
        var text = _mapper.FormatReport(result);
        Assert.Contains("!!", text);
    }

    [Fact]
    public void FormatReport_IncludesRecommendations()
    {
        var report = CreateReportWithCategories(
            ("RDP", new[] { Finding.Critical("RDP", "Bad", "RDP") })
        );
        var result = _mapper.Analyze(report);
        var text = _mapper.FormatReport(result);
        Assert.Contains("Recommendations", text);
        Assert.Contains("→", text);
    }

    [Fact]
    public void FormatReport_HeatmapShowsAllTactics()
    {
        var report = CreateReport();
        var result = _mapper.Analyze(report);
        var text = _mapper.FormatReport(result);
        Assert.Contains("Initial Access", text);
        Assert.Contains("Lateral Movement", text);
        Assert.Contains("Exfiltration", text);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void Analyze_DuplicateFindings_NotDoubleCounted()
    {
        var finding = Finding.Warning("RDP open", "RDP is on", "RDP");
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new() { ModuleName = "Module1", Category = "RDP", Findings = new() { finding } },
                new() { ModuleName = "Module2", Category = "Network", Findings = new() { finding } }
            }
        };
        var result = _mapper.Analyze(report);
        // The same Finding object instance should be counted once
        Assert.Equal(1, result.MappedFindings);
    }

    [Fact]
    public void Analyze_MixedSeverities_OnlyActionableMapped()
    {
        var report = CreateReportWithCategories(
            ("PowerShell", new[]
            {
                Finding.Pass("PS OK", "Good", "PowerShell"),
                Finding.Info("PS info", "Info", "PowerShell"),
                Finding.Warning("PS warn", "Bad", "PowerShell"),
                Finding.Critical("PS crit", "Bad", "PowerShell")
            })
        );
        var result = _mapper.Analyze(report);
        Assert.Equal(4, result.TotalFindings);
        Assert.Equal(2, result.MappedFindings);
    }

    [Fact]
    public void Analyze_GeneratedAtTimestamp_Set()
    {
        var report = CreateReport();
        var before = DateTimeOffset.UtcNow;
        var result = _mapper.Analyze(report);
        Assert.True(result.GeneratedAt >= before.AddSeconds(-1));
    }

    #endregion
}
