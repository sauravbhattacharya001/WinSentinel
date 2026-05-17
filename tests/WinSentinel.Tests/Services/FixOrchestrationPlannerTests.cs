using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class FixOrchestrationPlannerTests
{
    private readonly FixOrchestrationPlanner _planner = new();

    private static Finding F(string title, string category, Severity sev,
        string? fix = null, string? rem = null) => new()
    {
        Title = title,
        Description = title,
        Category = category,
        Severity = sev,
        FixCommand = fix,
        Remediation = rem,
    };

    private static SecurityReport Report(params Finding[] findings)
    {
        var r = new SecurityReport
        {
            GeneratedAt = new DateTimeOffset(2026, 5, 16, 19, 0, 0, TimeSpan.Zero),
            SecurityScore = 70,
        };
        var ar = new AuditResult
        {
            ModuleName = "Composite",
            Category = "Composite",
            StartTime = r.GeneratedAt,
            EndTime = r.GeneratedAt.AddSeconds(1),
        };
        ar.Findings.AddRange(findings);
        r.Results.Add(ar);
        return r;
    }

    // ── Smoke ────────────────────────────────────────────────────────

    [Fact]
    public void Plan_EmptyFindings_ReturnsEmptyPlan()
    {
        var plan = _planner.Plan(Array.Empty<Finding>(), new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Equal(0, plan.TotalSteps);
        Assert.Empty(plan.Steps);
        Assert.Empty(plan.RebootBatches);
    }

    [Fact]
    public void Plan_SingleFinding_AssignsOrderAndPhase()
    {
        var plan = _planner.Plan(new[]
        {
            F("Firewall disabled", "Firewall", Severity.Critical, "Set-NetFirewallProfile -All -Enabled True"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Single(plan.Steps);
        var s = plan.Steps[0];
        Assert.Equal(1, s.Order);
        Assert.Equal(FixOrchestrationPlanner.Phase.Foundation, s.Phase);
        Assert.True(s.HasAutoFix);
    }

    [Fact]
    public void Plan_PassFindings_AreSkipped()
    {
        var plan = _planner.Plan(new[]
        {
            F("All good", "Firewall", Severity.Pass),
            F("BitLocker off", "Encryption", Severity.Critical),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Single(plan.Steps);
        Assert.Equal("BitLocker off", plan.Steps[0].Title);
    }

    [Fact]
    public void Plan_FromSecurityReport_IncludesOnlyActionable()
    {
        var report = Report(
            F("Defender real-time protection disabled", "Defender", Severity.Critical),
            F("OK", "System", Severity.Pass)
        );

        var plan = _planner.Plan(report, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Single(plan.Steps);
        Assert.Equal("Defender real-time protection disabled", plan.Steps[0].Title);
    }

    // ── Phase classification ─────────────────────────────────────────

    [Fact]
    public void Classify_FoundationKeywords_GoToFoundation()
    {
        var plan = _planner.Plan(new[]
        {
            F("Defender disabled", "Defender", Severity.Critical),
            F("Firewall disabled", "Firewall", Severity.Critical),
            F("UAC set too low", "System", Severity.Warning),
        }, new FixOrchestrationPlanner.PlanOptions { IncludeRestorePoint = false, IncludeVerification = false });

        Assert.All(plan.Steps, s => Assert.Equal(FixOrchestrationPlanner.Phase.Foundation, s.Phase));
    }

    [Fact]
    public void Classify_ContainmentKeywords_GoToContainment()
    {
        var plan = _planner.Plan(new[]
        {
            F("Block IP 1.2.3.4", "Network", Severity.Critical,
                rem: "block ip address that is exfiltrating"),
            F("Kill process malware.exe", "Processes", Severity.Critical,
                rem: "kill process tree"),
            F("Disable account hacker", "User Accounts", Severity.Critical,
                rem: "disable account immediately"),
        }, new FixOrchestrationPlanner.PlanOptions { IncludeRestorePoint = false, IncludeVerification = false });

        Assert.All(plan.Steps, s => Assert.Equal(FixOrchestrationPlanner.Phase.Containment, s.Phase));
        Assert.All(plan.Steps, s => Assert.True(s.DisruptsUsers));
    }

    [Fact]
    public void Classify_CleanupKeywords_GoToCleanup()
    {
        var plan = _planner.Plan(new[]
        {
            F("Outdated software: Foo 1.0", "Software Inventory", Severity.Warning,
                rem: "uninstall outdated software"),
            F("Remove startup entry XYZ", "Startup", Severity.Warning,
                rem: "remove startup entry"),
        }, new FixOrchestrationPlanner.PlanOptions { IncludeRestorePoint = false, IncludeVerification = false });

        Assert.All(plan.Steps, s => Assert.Equal(FixOrchestrationPlanner.Phase.Cleanup, s.Phase));
    }

    [Fact]
    public void Classify_RegistryAndPolicy_GoToHardening()
    {
        var plan = _planner.Plan(new[]
        {
            F("Audit policy missing", "Event Log", Severity.Warning,
                rem: "enable audit policy"),
            F("SMB1 enabled", "Network", Severity.Warning,
                rem: "disable smb1 via registry"),
        }, new FixOrchestrationPlanner.PlanOptions { IncludeRestorePoint = false, IncludeVerification = false });

        Assert.All(plan.Steps, s => Assert.Equal(FixOrchestrationPlanner.Phase.Hardening, s.Phase));
    }

    // ── Phase order ──────────────────────────────────────────────────

    [Fact]
    public void Plan_StepsOrdered_PreconditionsThenFoundationThenHardeningThenContainmentThenCleanupThenVerification()
    {
        var plan = _planner.Plan(new[]
        {
            F("Outdated app", "Software Inventory", Severity.Warning, rem: "uninstall outdated app"),
            F("Block IP 9.9.9.9", "Network", Severity.Critical, rem: "block ip outbound"),
            F("Firewall disabled", "Firewall", Severity.Critical),
            F("SMB1 enabled", "Network", Severity.Warning, rem: "disable smb1 registry"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = true,
            IncludeVerification = true,
        });

        var phases = plan.Steps.Select(s => (int)s.Phase).ToList();
        var sorted = phases.OrderBy(p => p).ToList();
        Assert.Equal(sorted, phases);

        // First step is preconditions, last step is verification
        Assert.Equal(FixOrchestrationPlanner.Phase.Preconditions, plan.Steps.First().Phase);
        Assert.Equal(FixOrchestrationPlanner.Phase.Verification, plan.Steps.Last().Phase);
    }

    [Fact]
    public void Plan_RestorePoint_IsFirstWhenEnabled()
    {
        var plan = _planner.Plan(new[]
        {
            F("Firewall disabled", "Firewall", Severity.Critical),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = true,
            IncludeVerification = false,
        });

        Assert.Equal(FixOrchestrationPlanner.Phase.Preconditions, plan.Steps[0].Phase);
        Assert.Contains("Restore", plan.Steps[0].Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Plan_Verification_OneStepPerImpactedCategory()
    {
        var plan = _planner.Plan(new[]
        {
            F("Firewall disabled", "Firewall", Severity.Critical),
            F("BitLocker off", "Encryption", Severity.Critical),
            F("BitLocker recovery key missing", "Encryption", Severity.Warning),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = true,
        });

        var verif = plan.Steps.Where(s => s.Phase == FixOrchestrationPlanner.Phase.Verification).ToList();
        Assert.Equal(2, verif.Count);
        Assert.Contains(verif, s => s.Category == "Firewall");
        Assert.Contains(verif, s => s.Category == "Encryption");
    }

    // ── Reboot batching ──────────────────────────────────────────────

    [Fact]
    public void RebootBatch_GroupsRebootStepsInSamePhase()
    {
        var plan = _planner.Plan(new[]
        {
            F("Driver out of date", "Drivers", Severity.Warning,
                rem: "install new driver, reboot required"),
            F("Pending Windows Update install", "Windows Update", Severity.Critical,
                rem: "windows update install pending; reboot required"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.True(plan.RebootBatchCount >= 1);
        Assert.All(plan.Steps.Where(s => s.RequiresReboot), s => Assert.True(s.RebootBatch > 0));
    }

    [Fact]
    public void RebootBatch_NoRebootSteps_NoBatches()
    {
        var plan = _planner.Plan(new[]
        {
            F("Registry policy tweak", "Registry", Severity.Warning,
                rem: "set registry value"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Empty(plan.RebootBatches);
        Assert.Equal(0, plan.RebootBatchCount);
    }

    // ── Risk profile ─────────────────────────────────────────────────

    [Fact]
    public void DestructiveSteps_AreFlagged()
    {
        var plan = _planner.Plan(new[]
        {
            F("Uninstall outdated app FooBar", "Software Inventory", Severity.Warning,
                rem: "uninstall the program"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Single(plan.Steps);
        Assert.True(plan.Steps[0].DestructiveOrIrreversible);
        Assert.True(plan.DestructiveSteps >= 1);
    }

    [Fact]
    public void BlastRadius_HigherForNetworkContainment()
    {
        var plan = _planner.Plan(new[]
        {
            F("Block IP 9.9.9.9", "Network", Severity.Critical, rem: "block ip address outbound"),
            F("Registry policy tweak", "Registry", Severity.Info, rem: "registry value tweak"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        var net = plan.Steps.First(s => s.Title.StartsWith("Block IP"));
        var reg = plan.Steps.First(s => s.Title.StartsWith("Registry"));
        Assert.True(net.BlastRadius > reg.BlastRadius);
    }

    // ── MaxSteps ─────────────────────────────────────────────────────

    [Fact]
    public void MaxSteps_LimitsToTopNBySeverity()
    {
        var plan = _planner.Plan(new[]
        {
            F("Info A", "X", Severity.Info),
            F("Warn B", "X", Severity.Warning),
            F("Crit C", "X", Severity.Critical),
            F("Info D", "X", Severity.Info),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            MaxSteps = 2,
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Equal(2, plan.TotalSteps);
        Assert.Contains(plan.Steps, s => s.Title == "Crit C");
        Assert.Contains(plan.Steps, s => s.Title == "Warn B");
    }

    // ── Risk warnings ────────────────────────────────────────────────

    [Fact]
    public void RiskWindowWarnings_EmittedForDisruptiveSteps()
    {
        var plan = _planner.Plan(new[]
        {
            F("Disable account hacker", "User Accounts", Severity.Critical,
                rem: "disable account immediately"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            RespectBusinessHours = true,
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.NotEmpty(plan.RiskWindowWarnings);
        Assert.Contains(plan.RiskWindowWarnings, w => w.Contains("business hours", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RiskWindowWarnings_Empty_WhenBusinessHoursIgnored()
    {
        var plan = _planner.Plan(new[]
        {
            F("Disable account hacker", "User Accounts", Severity.Critical,
                rem: "disable account"),
        }, new FixOrchestrationPlanner.PlanOptions
        {
            RespectBusinessHours = false,
            IncludeRestorePoint = false,
            IncludeVerification = false,
        });

        Assert.Empty(plan.RiskWindowWarnings);
    }

    // ── Formatters ───────────────────────────────────────────────────

    [Fact]
    public void RenderText_ContainsPhaseHeadersAndCounts()
    {
        var plan = _planner.Plan(new[]
        {
            F("Firewall disabled", "Firewall", Severity.Critical, "Set-NetFirewallProfile -All -Enabled True"),
        });

        var text = FixOrchestrationPlanner.RenderText(plan);
        Assert.Contains("Fix Orchestration Plan", text);
        Assert.Contains("PHASE: FOUNDATION", text);
        Assert.Contains("Firewall disabled", text);
    }

    [Fact]
    public void RenderMarkdown_ContainsTablesAndPhases()
    {
        var plan = _planner.Plan(new[]
        {
            F("Firewall disabled", "Firewall", Severity.Critical),
        });

        var md = FixOrchestrationPlanner.RenderMarkdown(plan);
        Assert.Contains("# 🛠 Fix Orchestration Plan", md);
        Assert.Contains("## Phase: Foundation", md);
        Assert.Contains("| # | Severity | Title", md);
    }

    [Fact]
    public void RenderJson_ParsesAndContainsSteps()
    {
        var plan = _planner.Plan(new[]
        {
            F("Firewall disabled", "Firewall", Severity.Critical),
        });

        var json = FixOrchestrationPlanner.RenderJson(plan);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("TotalSteps").GetInt32() >= 1);
        Assert.True(root.GetProperty("Steps").GetArrayLength() >= 1);
        var firstPhase = root.GetProperty("Steps")[0].GetProperty("Phase").GetString();
        Assert.False(string.IsNullOrEmpty(firstPhase));
    }

    [Fact]
    public void Plan_NullFindings_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _planner.Plan((IEnumerable<Finding>)null!));
    }

    [Fact]
    public void Plan_NullReport_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _planner.Plan((SecurityReport)null!));
    }
}
