using WinSentinel.Cli;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// Tests for ConsoleFormatter — covers output content, color logic,
/// and edge cases. Uses Console.Out redirection to capture output.
/// </summary>
public class ConsoleFormatterTests : IDisposable
{
    private readonly StringWriter _writer;
    private readonly StringWriter _errorWriter;
    private readonly TextWriter _originalOut;
    private readonly TextWriter _originalError;
    private readonly ConsoleColor _originalColor;

    public ConsoleFormatterTests()
    {
        _writer = new StringWriter();
        _errorWriter = new StringWriter();
        _originalOut = Console.Out;
        _originalError = Console.Error;
        _originalColor = Console.ForegroundColor;
        Console.SetOut(_writer);
        Console.SetError(_errorWriter);
    }

    public void Dispose()
    {
        Console.SetOut(_originalOut);
        Console.SetError(_originalError);
        Console.ForegroundColor = _originalColor;
        _writer.Dispose();
        _errorWriter.Dispose();
    }

    private string GetOutput() => _writer.ToString();
    private string GetErrorOutput() => _errorWriter.ToString();
    private string GetAllOutput() => _writer.ToString() + _errorWriter.ToString();

    // ── Helper factories ────────────────────────────────────────────

    private static SecurityReport CreateReport(int criticals = 1, int warnings = 2, int infos = 1, int passes = 3)
    {
        var report = new SecurityReport
        {
            GeneratedAt = new DateTimeOffset(2026, 2, 15, 12, 0, 0, TimeSpan.Zero)
        };

        var result = new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall",
            StartTime = report.GeneratedAt,
            EndTime = report.GeneratedAt.AddSeconds(2)
        };

        for (int i = 0; i < criticals; i++)
            result.Findings.Add(Finding.Critical($"Critical {i + 1}", $"Desc {i + 1}", "Firewall", $"Fix {i + 1}"));
        for (int i = 0; i < warnings; i++)
            result.Findings.Add(Finding.Warning($"Warning {i + 1}", $"Desc {i + 1}", "Firewall", $"Fix {i + 1}"));
        for (int i = 0; i < infos; i++)
            result.Findings.Add(Finding.Info($"Info {i + 1}", $"Desc {i + 1}", "Firewall"));
        for (int i = 0; i < passes; i++)
            result.Findings.Add(Finding.Pass($"Pass {i + 1}", $"Desc {i + 1}", "Firewall"));

        report.Results.Add(result);
        return report;
    }

    private static SecurityReport CreateMultiModuleReport()
    {
        var report = new SecurityReport
        {
            GeneratedAt = new DateTimeOffset(2026, 2, 15, 12, 0, 0, TimeSpan.Zero)
        };

        var fw = new AuditResult { ModuleName = "FirewallAudit", Category = "Firewall" };
        fw.Findings.Add(Finding.Critical("FW Critical", "Desc", "Firewall", "Fix it"));
        fw.Findings.Add(Finding.Pass("FW Pass", "OK", "Firewall"));

        var net = new AuditResult { ModuleName = "NetworkAudit", Category = "Network" };
        net.Findings.Add(Finding.Warning("Net Warning", "Desc", "Network", "Fix it"));
        net.Findings.Add(Finding.Info("Net Info", "Desc", "Network"));
        net.Findings.Add(Finding.Pass("Net Pass 1", "OK", "Network"));
        net.Findings.Add(Finding.Pass("Net Pass 2", "OK", "Network"));

        report.Results.Add(fw);
        report.Results.Add(net);
        return report;
    }

    private static AuditRunRecord CreateRunRecord(long id = 1, int score = 85, int criticals = 1, int warnings = 3)
    {
        return new AuditRunRecord
        {
            Id = id,
            Timestamp = new DateTimeOffset(2026, 2, 15, 12, 0, 0, TimeSpan.Zero),
            OverallScore = score,
            Grade = SecurityScorer.GetGrade(score),
            TotalFindings = criticals + warnings + 4,
            CriticalCount = criticals,
            WarningCount = warnings,
            InfoCount = 2,
            PassCount = 2,
            IsScheduled = false
        };
    }

    // ── GetScoreConsoleColor ────────────────────────────────────────

    [Theory]
    [InlineData(100, ConsoleColor.Green)]
    [InlineData(95, ConsoleColor.Green)]
    [InlineData(80, ConsoleColor.Green)]
    [InlineData(79, ConsoleColor.Yellow)]
    [InlineData(60, ConsoleColor.Yellow)]
    [InlineData(59, ConsoleColor.DarkYellow)]
    [InlineData(40, ConsoleColor.DarkYellow)]
    [InlineData(39, ConsoleColor.Red)]
    [InlineData(0, ConsoleColor.Red)]
    public void GetScoreConsoleColor_ReturnsCorrectColor(int score, ConsoleColor expected)
    {
        Assert.Equal(expected, ConsoleFormatter.GetScoreConsoleColor(score));
    }

    // ── PrintBanner ─────────────────────────────────────────────────

    [Fact]
    public void PrintBanner_ContainsAppName()
    {
        ConsoleFormatter.PrintBanner();
        Assert.Contains("WinSentinel", GetOutput());
    }

    [Fact]
    public void PrintBanner_ContainsBoxDrawing()
    {
        ConsoleFormatter.PrintBanner();
        var output = GetOutput();
        Assert.Contains("╔", output);
        Assert.Contains("╚", output);
    }

    [Fact]
    public void PrintBanner_RestoresColor()
    {
        var before = Console.ForegroundColor;
        ConsoleFormatter.PrintBanner();
        Assert.Equal(before, Console.ForegroundColor);
    }

    // ── PrintProgress ───────────────────────────────────────────────

    [Fact]
    public void PrintProgress_ShowsModuleName()
    {
        ConsoleFormatter.PrintProgress("FirewallAudit", 1, 5);
        Assert.Contains("FirewallAudit", GetOutput());
    }

    [Fact]
    public void PrintProgress_ShowsCounters()
    {
        ConsoleFormatter.PrintProgress("Test", 3, 10);
        Assert.Contains("3/10", GetOutput());
    }

    [Fact]
    public void PrintProgress_ShowsScanningLabel()
    {
        ConsoleFormatter.PrintProgress("Defender", 1, 1);
        Assert.Contains("Scanning", GetOutput());
    }

    // ── PrintProgressDone ───────────────────────────────────────────

    [Fact]
    public void PrintProgressDone_ShowsModuleCount()
    {
        ConsoleFormatter.PrintProgressDone(13, TimeSpan.FromSeconds(2.5));
        Assert.Contains("13 modules", GetOutput());
    }

    [Fact]
    public void PrintProgressDone_ShowsElapsedTime()
    {
        ConsoleFormatter.PrintProgressDone(5, TimeSpan.FromSeconds(1.234));
        Assert.Contains("1.2s", GetOutput());
    }

    [Fact]
    public void PrintProgressDone_ShowsCheckmark()
    {
        ConsoleFormatter.PrintProgressDone(1, TimeSpan.FromSeconds(0.5));
        Assert.Contains("✓", GetOutput());
    }

    // ── PrintScore ──────────────────────────────────────────────────

    [Fact]
    public void PrintScore_ShowsScoreOutOf100()
    {
        ConsoleFormatter.PrintScore(85);
        Assert.Contains("85/100", GetOutput());
    }

    [Fact]
    public void PrintScore_ShowsGrade()
    {
        ConsoleFormatter.PrintScore(85);
        Assert.Contains(SecurityScorer.GetGrade(85), GetOutput());
    }

    [Fact]
    public void PrintScore_Quiet_ShowsCompactOutput()
    {
        ConsoleFormatter.PrintScore(72, quiet: true);
        Assert.Contains("72/100", GetOutput());
    }

    [Fact]
    public void PrintScore_ShowsScoreBar()
    {
        ConsoleFormatter.PrintScore(50);
        Assert.Contains("█", GetOutput());
    }

    [Fact]
    public void PrintScore_ZeroScore()
    {
        ConsoleFormatter.PrintScore(0);
        Assert.Contains("0/100", GetOutput());
    }

    [Fact]
    public void PrintScore_PerfectScore()
    {
        ConsoleFormatter.PrintScore(100);
        Assert.Contains("100/100", GetOutput());
    }

    [Fact]
    public void PrintScore_RestoresColor()
    {
        var before = Console.ForegroundColor;
        ConsoleFormatter.PrintScore(75);
        Assert.Equal(before, Console.ForegroundColor);
    }

    // ── PrintSummary ────────────────────────────────────────────────

    [Fact]
    public void PrintSummary_ShowsCriticalCount()
    {
        ConsoleFormatter.PrintSummary(CreateReport(criticals: 3));
        Assert.Contains("3 critical", GetOutput());
    }

    [Fact]
    public void PrintSummary_ShowsWarningCount()
    {
        ConsoleFormatter.PrintSummary(CreateReport(warnings: 5));
        Assert.Contains("5 warnings", GetOutput());
    }

    [Fact]
    public void PrintSummary_ShowsInfoCount()
    {
        ConsoleFormatter.PrintSummary(CreateReport(infos: 2));
        Assert.Contains("2 info", GetOutput());
    }

    [Fact]
    public void PrintSummary_ShowsPassCount()
    {
        ConsoleFormatter.PrintSummary(CreateReport(passes: 4));
        Assert.Contains("4 pass", GetOutput());
    }

    [Fact]
    public void PrintSummary_ShowsTotalCount()
    {
        ConsoleFormatter.PrintSummary(CreateReport(criticals: 1, warnings: 2, infos: 1, passes: 3));
        Assert.Contains("7 total", GetOutput());
    }

    [Fact]
    public void PrintSummary_ZeroFindings()
    {
        ConsoleFormatter.PrintSummary(CreateReport(0, 0, 0, 0));
        var output = GetOutput();
        Assert.Contains("0 critical", output);
        Assert.Contains("0 total", output);
    }

    [Fact]
    public void PrintSummary_RestoresColor()
    {
        var before = Console.ForegroundColor;
        ConsoleFormatter.PrintSummary(CreateReport());
        Assert.Equal(before, Console.ForegroundColor);
    }

    // ── PrintModuleTable ────────────────────────────────────────────

    [Fact]
    public void PrintModuleTable_ShowsHeader()
    {
        var output = RunAndCapture(() => ConsoleFormatter.PrintModuleTable(CreateReport()));
        Assert.Contains("Module", output);
        Assert.Contains("Score", output);
        Assert.Contains("Grade", output);
    }

    [Fact]
    public void PrintModuleTable_ShowsModuleName()
    {
        ConsoleFormatter.PrintModuleTable(CreateReport());
        Assert.Contains("Firewall", GetOutput());
    }

    [Fact]
    public void PrintModuleTable_MultipleModules()
    {
        ConsoleFormatter.PrintModuleTable(CreateMultiModuleReport());
        var output = GetOutput();
        Assert.Contains("Firewall", output);
        Assert.Contains("Network", output);
    }

    [Fact]
    public void PrintModuleTable_ShowsSeparatorLine()
    {
        ConsoleFormatter.PrintModuleTable(CreateReport());
        Assert.Contains("─", GetOutput());
    }

    [Fact]
    public void PrintModuleTable_RestoresColor()
    {
        var before = Console.ForegroundColor;
        ConsoleFormatter.PrintModuleTable(CreateReport());
        Assert.Equal(before, Console.ForegroundColor);
    }

    // ── PrintFindings ───────────────────────────────────────────────

    [Fact]
    public void PrintFindings_ShowsCriticalFindings()
    {
        ConsoleFormatter.PrintFindings(CreateReport(criticals: 2, warnings: 0));
        var output = GetOutput();
        Assert.Contains("Critical 1", output);
        Assert.Contains("Critical 2", output);
    }

    [Fact]
    public void PrintFindings_ShowsWarningFindings()
    {
        ConsoleFormatter.PrintFindings(CreateReport(criticals: 0, warnings: 1));
        Assert.Contains("Warning 1", GetOutput());
    }

    [Fact]
    public void PrintFindings_NoActionableFindings()
    {
        ConsoleFormatter.PrintFindings(CreateReport(criticals: 0, warnings: 0, infos: 2, passes: 3));
        // Should not crash
        Assert.NotNull(GetOutput());
    }

    // ── PrintHelp ───────────────────────────────────────────────────

    [Fact]
    public void PrintHelp_ShowsUsage()
    {
        ConsoleFormatter.PrintHelp();
        Assert.Contains("USAGE", GetOutput());
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("history")]
    [InlineData("fix")]
    [InlineData("baseline")]
    [InlineData("compliance")]
    [InlineData("ignore")]
    [InlineData("age")]
    [InlineData("trend")]
    public void PrintHelp_ShowsCommand(string command)
    {
        ConsoleFormatter.PrintHelp();
        Assert.Contains(command, GetOutput().ToLower());
    }

    // ── PrintVersion ────────────────────────────────────────────────

    [Fact]
    public void PrintVersion_ShowsProductName()
    {
        ConsoleFormatter.PrintVersion();
        Assert.Contains("WinSentinel", GetOutput());
    }

    // ── PrintError / PrintWarning ───────────────────────────────────

    [Fact]
    public void PrintError_ShowsMessage()
    {
        ConsoleFormatter.PrintError("Something went wrong");
        Assert.Contains("Something went wrong", GetErrorOutput());
    }

    [Fact]
    public void PrintError_ShowsErrorPrefix()
    {
        ConsoleFormatter.PrintError("test");
        Assert.Contains("Error", GetErrorOutput());
    }

    [Fact]
    public void PrintError_RestoresColor()
    {
        var before = Console.ForegroundColor;
        ConsoleFormatter.PrintError("test");
        Assert.Equal(before, Console.ForegroundColor);
    }

    [Fact]
    public void PrintWarning_ShowsMessage()
    {
        ConsoleFormatter.PrintWarning("Watch out");
        Assert.Contains("Watch out", GetOutput());
    }

    [Fact]
    public void PrintWarning_RestoresColor()
    {
        var before = Console.ForegroundColor;
        ConsoleFormatter.PrintWarning("test");
        Assert.Equal(before, Console.ForegroundColor);
    }

    // ── PrintHistoryBanner ──────────────────────────────────────────

    [Fact]
    public void PrintHistoryBanner_ShowsRunCount()
    {
        ConsoleFormatter.PrintHistoryBanner(42, 30);
        Assert.Contains("42", GetOutput());
    }

    [Fact]
    public void PrintHistoryBanner_ShowsDays()
    {
        ConsoleFormatter.PrintHistoryBanner(10, 7);
        Assert.Contains("7", GetOutput());
    }

    // ── PrintHistoryTable ───────────────────────────────────────────

    [Fact]
    public void PrintHistoryTable_ShowsRunScore()
    {
        var runs = new List<AuditRunRecord> { CreateRunRecord(score: 85) };
        ConsoleFormatter.PrintHistoryTable(runs);
        Assert.Contains("85", GetOutput());
    }

    [Fact]
    public void PrintHistoryTable_ShowsGrade()
    {
        var runs = new List<AuditRunRecord> { CreateRunRecord(score: 90) };
        ConsoleFormatter.PrintHistoryTable(runs);
        Assert.Contains(SecurityScorer.GetGrade(90), GetOutput());
    }

    [Fact]
    public void PrintHistoryTable_Empty_DoesNotThrow()
    {
        ConsoleFormatter.PrintHistoryTable(new List<AuditRunRecord>());
        Assert.NotNull(GetOutput());
    }

    [Fact]
    public void PrintHistoryTable_Quiet_ProducesOutput()
    {
        var runs = new List<AuditRunRecord> { CreateRunRecord(score: 90) };
        ConsoleFormatter.PrintHistoryTable(runs, quiet: true);
        Assert.Contains("90", GetOutput());
    }

    [Fact]
    public void PrintHistoryTable_ShowsTableHeader()
    {
        var runs = new List<AuditRunRecord> { CreateRunRecord() };
        ConsoleFormatter.PrintHistoryTable(runs);
        var output = GetOutput();
        Assert.Contains("#", output);
        Assert.Contains("Date", output);
    }

    [Fact]
    public void PrintHistoryTable_MultipleRuns()
    {
        var runs = new List<AuditRunRecord>
        {
            CreateRunRecord(id: 1, score: 85),
            CreateRunRecord(id: 2, score: 70)
        };
        ConsoleFormatter.PrintHistoryTable(runs);
        var output = GetOutput();
        Assert.Contains("85", output);
        Assert.Contains("70", output);
    }

    // ── PrintFixResults ─────────────────────────────────────────────

    [Fact]
    public void PrintFixResults_ShowsFindingTitle()
    {
        var results = new List<(Finding finding, FixResult result)>
        {
            (Finding.Critical("Test Finding", "Desc", "Module", "Fix it"),
             new FixResult { Success = true, Output = "Fixed OK", FindingTitle = "Test Finding" })
        };
        ConsoleFormatter.PrintFixResults(results);
        Assert.Contains("Test Finding", GetOutput());
    }

    [Fact]
    public void PrintFixResults_ShowsFailedFix()
    {
        var results = new List<(Finding finding, FixResult result)>
        {
            (Finding.Warning("Warn Finding", "Desc", "Module", "Fix"),
             new FixResult { Success = false, Error = "Permission denied", FindingTitle = "Warn Finding" })
        };
        ConsoleFormatter.PrintFixResults(results);
        Assert.Contains("Warn Finding", GetOutput());
    }

    [Fact]
    public void PrintFixResults_Empty_DoesNotThrow()
    {
        ConsoleFormatter.PrintFixResults(new List<(Finding, FixResult)>());
        Assert.NotNull(GetOutput());
    }

    // ── PrintBaselineSaved ──────────────────────────────────────────

    [Fact]
    public void PrintBaselineSaved_ShowsBaselineInfo()
    {
        var baseline = new SecurityBaseline
        {
            Name = "TestBaseline",
            OverallScore = 85,
            Grade = "A",
            CreatedAt = DateTimeOffset.UtcNow,
            TotalFindings = 5,
            CriticalCount = 1,
            WarningCount = 2,
            InfoCount = 1,
            PassCount = 1
        };
        ConsoleFormatter.PrintBaselineSaved(baseline);
        var output = GetOutput();
        Assert.Contains("TestBaseline", output);
        Assert.Contains("85", output);
    }

    // ── PrintBaselineList ───────────────────────────────────────────

    [Fact]
    public void PrintBaselineList_ShowsBaselines()
    {
        var baselines = new List<BaselineSummary>
        {
            new BaselineSummary
            {
                Name = "prod-baseline",
                OverallScore = 90,
                Grade = "A+",
                TotalFindings = 5,
                CriticalCount = 0,
                WarningCount = 1,
                CreatedAt = DateTimeOffset.UtcNow,
                MachineName = "TEST-PC"
            }
        };
        ConsoleFormatter.PrintBaselineList(baselines);
        Assert.Contains("prod-baseline", GetOutput());
    }

    [Fact]
    public void PrintBaselineList_Empty_ProducesOutput()
    {
        ConsoleFormatter.PrintBaselineList(new List<BaselineSummary>());
        Assert.True(GetOutput().Length > 0);
    }

    [Fact]
    public void PrintBaselineList_Quiet_ShowsCompactOutput()
    {
        var baselines = new List<BaselineSummary>
        {
            new BaselineSummary
            {
                Name = "quick",
                OverallScore = 75,
                Grade = "B",
                TotalFindings = 3,
                CriticalCount = 0,
                WarningCount = 1,
                CreatedAt = DateTimeOffset.UtcNow,
                MachineName = "TEST-PC"
            }
        };
        ConsoleFormatter.PrintBaselineList(baselines, quiet: true);
        Assert.Contains("quick", GetOutput());
    }

    // ── PrintIgnoredSummary ─────────────────────────────────────────

    [Fact]
    public void PrintIgnoredSummary_ShowsCount()
    {
        ConsoleFormatter.PrintIgnoredSummary(5);
        Assert.Contains("5", GetOutput());
    }

    [Fact]
    public void PrintIgnoredSummary_ZeroCount()
    {
        ConsoleFormatter.PrintIgnoredSummary(0);
        Assert.Contains("0", GetOutput());
    }

    // ── PrintIgnoredFindings ────────────────────────────────────────

    [Fact]
    public void PrintIgnoredFindings_ShowsFindingTitles()
    {
        var rule = new IgnoreRule { Pattern = "test*", Reason = "Testing" };
        var ignored = new List<IgnoredFinding>
        {
            new IgnoredFinding
            {
                Finding = Finding.Warning("Ignored Issue 1", "Desc", "Firewall", "Fix"),
                MatchedRule = rule
            },
            new IgnoredFinding
            {
                Finding = Finding.Info("Ignored Issue 2", "Desc", "Network"),
                MatchedRule = rule
            }
        };
        ConsoleFormatter.PrintIgnoredFindings(ignored);
        var output = GetOutput();
        Assert.Contains("Ignored Issue 1", output);
        Assert.Contains("Ignored Issue 2", output);
    }

    [Fact]
    public void PrintIgnoredFindings_Empty_DoesNotThrow()
    {
        ConsoleFormatter.PrintIgnoredFindings(new List<IgnoredFinding>());
        Assert.NotNull(GetOutput());
    }

    // ── PrintIgnoreRuleAdded ────────────────────────────────────────

    [Fact]
    public void PrintIgnoreRuleAdded_ShowsRuleId()
    {
        var rule = new IgnoreRule
        {
            Id = "testrule1",
            Pattern = "Test Pattern*",
            Reason = "Not applicable",
            CreatedAt = DateTimeOffset.UtcNow
        };
        ConsoleFormatter.PrintIgnoreRuleAdded(rule);
        Assert.Contains("testrule1", GetOutput());
    }

    // ── PrintIgnoreRuleList ─────────────────────────────────────────

    [Fact]
    public void PrintIgnoreRuleList_ShowsRules()
    {
        var rules = new List<IgnoreRule>
        {
            new IgnoreRule
            {
                Id = "rule-abc",
                Pattern = "FW*",
                Reason = "Expected config",
                CreatedAt = DateTimeOffset.UtcNow
            }
        };
        ConsoleFormatter.PrintIgnoreRuleList(rules);
        Assert.Contains("rule-abc", GetOutput());
    }

    [Fact]
    public void PrintIgnoreRuleList_Empty_ProducesOutput()
    {
        ConsoleFormatter.PrintIgnoreRuleList(new List<IgnoreRule>());
        Assert.True(GetOutput().Length > 0);
    }

    [Fact]
    public void PrintIgnoreRuleList_Quiet_ShowsCompact()
    {
        var rules = new List<IgnoreRule>
        {
            new IgnoreRule { Id = "q-rule", Pattern = "Net*", Reason = "Test" }
        };
        ConsoleFormatter.PrintIgnoreRuleList(rules, quiet: true);
        Assert.Contains("q-rule", GetOutput());
    }

    // ── PrintProfileList ────────────────────────────────────────────

    [Fact]
    public void PrintProfileList_ShowsProfiles()
    {
        var svc = new ComplianceProfileService();
        ConsoleFormatter.PrintProfileList(svc.Profiles);
        Assert.True(GetOutput().Length > 0);
    }

    [Fact]
    public void PrintProfileList_Quiet_ShowsCompact()
    {
        var svc = new ComplianceProfileService();
        ConsoleFormatter.PrintProfileList(svc.Profiles, quiet: true);
        Assert.True(GetOutput().Length > 0);
    }

    // ── PrintChecklist ──────────────────────────────────────────────

    [Fact]
    public void PrintChecklist_ShowsItems()
    {
        var plan = new RemediationPlan
        {
            CurrentScore = 65,
            CurrentGrade = "C",
            ProjectedScore = 85,
            ProjectedGrade = "A",
            QuickWins = new List<RemediationItem>
            {
                new RemediationItem
                {
                    StepNumber = 1,
                    Title = "Enable Firewall",
                    Description = "Turn on the firewall",
                    Severity = Severity.Critical,
                    Category = "Firewall",
                    Impact = 10,
                    Effort = "Quick",
                    EstimatedTime = "5 minutes",
                    Remediation = "Enable it",
                    FixCommand = "Set-NetFirewallProfile -Enabled True"
                }
            }
        };
        ConsoleFormatter.PrintChecklist(plan);
        Assert.Contains("Enable Firewall", GetOutput());
    }

    [Fact]
    public void PrintChecklist_EmptyPlan_ShowsAllClear()
    {
        var plan = new RemediationPlan
        {
            CurrentScore = 100,
            CurrentGrade = "A+",
            ProjectedScore = 100,
            ProjectedGrade = "A+"
        };
        ConsoleFormatter.PrintChecklist(plan);
        Assert.Contains("✅", GetOutput());
    }

    [Fact]
    public void PrintChecklist_Quiet_ShowsCompact()
    {
        var plan = new RemediationPlan
        {
            CurrentScore = 70,
            CurrentGrade = "B",
            ProjectedScore = 90,
            ProjectedGrade = "A",
            QuickWins = new List<RemediationItem>
            {
                new RemediationItem
                {
                    StepNumber = 1,
                    Title = "Quick Fix",
                    Description = "Do it",
                    Severity = Severity.Warning,
                    Category = "Defender",
                    Impact = 5,
                    Effort = "Quick",
                    EstimatedTime = "2 minutes"
                }
            }
        };
        ConsoleFormatter.PrintChecklist(plan, quiet: true);
        Assert.Contains("Quick Fix", GetOutput());
    }

    // ── PrintComplianceResult ───────────────────────────────────────

    [Fact]
    public void PrintComplianceResult_ShowsProfileName()
    {
        var svc = new ComplianceProfileService();
        var profile = svc.Profiles[0];
        var result = new ComplianceResult
        {
            Profile = profile,
            OriginalScore = 85,
            AdjustedScore = 92,
            OriginalGrade = "A",
            AdjustedGrade = "A+"
        };
        ConsoleFormatter.PrintComplianceResult(result);
        Assert.Contains(profile.DisplayName, GetOutput());
    }

    [Fact]
    public void PrintComplianceResult_Quiet_ShowsCompact()
    {
        var svc = new ComplianceProfileService();
        var profile = svc.Profiles[0];
        var result = new ComplianceResult
        {
            Profile = profile,
            OriginalScore = 88,
            AdjustedScore = 88,
            OriginalGrade = "A",
            AdjustedGrade = "A"
        };
        ConsoleFormatter.PrintComplianceResult(result, quiet: true);
        Assert.Contains("88", GetOutput());
    }

    // ── Console color restoration ───────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(45)]
    [InlineData(65)]
    [InlineData(85)]
    [InlineData(100)]
    public void PrintScore_AllRanges_RestoreColor(int score)
    {
        var before = Console.ForegroundColor;
        ConsoleFormatter.PrintScore(score);
        Assert.Equal(before, Console.ForegroundColor);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    [Fact]
    public void PrintHistoryTable_ScheduledRun_ShowsType()
    {
        var run = CreateRunRecord();
        run.IsScheduled = true;
        ConsoleFormatter.PrintHistoryTable(new List<AuditRunRecord> { run });
        Assert.Contains("Scheduled", GetOutput());
    }

    [Fact]
    public void PrintHistoryTable_ManualRun_ShowsType()
    {
        var run = CreateRunRecord();
        run.IsScheduled = false;
        ConsoleFormatter.PrintHistoryTable(new List<AuditRunRecord> { run });
        Assert.Contains("Manual", GetOutput());
    }

    [Fact]
    public void PrintModuleTable_FailedModule_ShowsErrorStatus()
    {
        var report = new SecurityReport
        {
            GeneratedAt = DateTimeOffset.UtcNow
        };
        var result = new AuditResult
        {
            ModuleName = "FailedModule",
            Category = "Failing",
            Success = false
        };
        report.Results.Add(result);
        ConsoleFormatter.PrintModuleTable(report);
        Assert.Contains("ERROR", GetOutput());
    }

    // ── Helper to capture output cleanly ────────────────────────────

    private string RunAndCapture(Action action)
    {
        action();
        return GetOutput();
    }
}
