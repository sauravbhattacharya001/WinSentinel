using System.Text.Json;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.ServiceTamperingAdvisor;

namespace WinSentinel.Tests;

public class ServiceTamperingAdvisorTests
{
    private static readonly DateTime Now = new DateTime(2026, 5, 22, 17, 0, 0, DateTimeKind.Utc);

    private static AdvisorContext Ctx(
        RiskAppetite risk = RiskAppetite.Balanced,
        int hours = 72) =>
        new AdvisorContext { Risk = risk, NowOverride = Now, RecentChangeHours = hours };

    private static WindowsServiceSnapshot Make(
        string name,
        ServiceCategory category = ServiceCategory.Other,
        bool critical = false,
        bool tamperproof = false,
        ServiceState expectedState = ServiceState.Running,
        ServiceState currentState = ServiceState.Running,
        ServiceStartupType expectedStartup = ServiceStartupType.Auto,
        ServiceStartupType currentStartup = ServiceStartupType.Auto,
        string? binaryPath = @"C:\Windows\System32\svc.exe",
        bool hashKnown = true,
        int recovery = 3,
        bool aclWeakened = false,
        DateTime? lastChange = null,
        string? changedBy = "NT AUTHORITY\\SYSTEM")
    {
        return new WindowsServiceSnapshot(
            ServiceName: name,
            DisplayName: name,
            Category: category,
            CriticalAsset: critical,
            Tamperproof: tamperproof,
            ExpectedState: expectedState,
            CurrentState: currentState,
            ExpectedStartupType: expectedStartup,
            CurrentStartupType: currentStartup,
            BinaryPath: binaryPath,
            BinaryPathHashKnown: hashKnown,
            RecoveryActionsCount: recovery,
            AclWeakened: aclWeakened,
            LastChangeAt: lastChange,
            ChangedBy: changedBy);
    }

    [Fact]
    public void Empty_input_returns_healthy_grade_A_with_fallback_action()
    {
        var advisor = new ServiceTamperingAdvisor();
        var r = advisor.Analyze(Array.Empty<WindowsServiceSnapshot>(), Ctx());

        Assert.Equal(0, r.TotalServices);
        Assert.Equal("A", r.Grade);
        Assert.Equal("NO_DATA", r.Verdict);
        Assert.Single(r.Playbook);
        Assert.Equal("ALL_SERVICES_HEALTHY", r.Playbook[0].Id);
        Assert.Equal(ActionPriority.P3, r.Playbook[0].Priority);
    }

    [Fact]
    public void Tamperproof_drift_forces_F_and_priority_zero_action()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make(
            "WinDefend",
            category: ServiceCategory.Antivirus,
            critical: true,
            tamperproof: true,
            currentState: ServiceState.Stopped,
            currentStartup: ServiceStartupType.Disabled);

        var r = advisor.Analyze(new[] { svc }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Equal("ACTIVE_TAMPERING_SUSPECTED", r.Verdict);
        Assert.Equal(1, r.QuarantineCount);
        var a = Assert.Single(r.Assessments);
        Assert.Equal(ServiceVerdict.QuarantineAndRestore, a.Verdict);
        Assert.Equal(ActionPriority.P0, a.Priority);
        Assert.Contains("SECURITY_SERVICE_TAMPERED", a.Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "RESTORE_SECURITY_SERVICE_INTEGRITY" && p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Suspicious_binary_path_forces_F()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("RogueSvc",
            binaryPath: @"C:\Users\Public\AppData\Local\Temp\evil.exe");

        var r = advisor.Analyze(new[] { svc }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Contains(r.Assessments[0].Reasons, x => x == "BINARY_PATH_SUSPICIOUS");
        Assert.Contains(r.Playbook, p => p.Id == "QUARANTINE_SUSPICIOUS_BINARY");
    }

    [Fact]
    public void Critical_service_disabled_forces_F_and_re_enable_action()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("MpsSvc",
            category: ServiceCategory.Firewall,
            critical: true,
            currentState: ServiceState.Stopped,
            currentStartup: ServiceStartupType.Disabled);

        var r = advisor.Analyze(new[] { svc }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Contains(r.Playbook, p => p.Id == "RE_ENABLE_DISABLED_CRITICAL");
        Assert.Contains(r.Assessments[0].Reasons, x => x == "CRITICAL_SERVICE_DISABLED");
    }

    [Fact]
    public void Healthy_service_yields_grade_A()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("HealthySvc", critical: false);
        var r = advisor.Analyze(new[] { svc }, Ctx());
        Assert.Equal("A", r.Grade);
        Assert.Equal("HEALTHY", r.Verdict);
        Assert.Equal(ServiceVerdict.Healthy, r.Assessments[0].Verdict);
        Assert.Contains(r.Playbook, p => p.Id == "ALL_SERVICES_HEALTHY");
    }

    [Fact]
    public void Stopped_critical_service_triggers_restart_playbook()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("EventLog",
            category: ServiceCategory.EventLog,
            critical: true,
            currentState: ServiceState.Stopped);

        var r = advisor.Analyze(new[] { svc }, Ctx());

        Assert.Contains(r.Playbook, p => p.Id == "RESTART_CRITICAL_SERVICES");
        Assert.Contains(r.Assessments[0].Reasons, x => x == "CRITICAL_SERVICE_STOPPED");
    }

    [Fact]
    public void Unknown_binary_hash_flags_revalidate()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X", critical: true, hashKnown: false);
        var r = advisor.Analyze(new[] { svc }, Ctx());
        Assert.Contains(r.Playbook, p => p.Id == "REVALIDATE_BINARY_PATH");
    }

    [Fact]
    public void Acl_weakened_yields_p1_restore_acl()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X", aclWeakened: true);
        var r = advisor.Analyze(new[] { svc }, Ctx());
        Assert.Contains(r.Playbook, p => p.Id == "RESTORE_ACL_DEFAULTS" && p.Priority == ActionPriority.P1);
    }

    [Fact]
    public void Recent_unauthorized_change_flags_investigation()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X",
            lastChange: Now.AddHours(-5),
            changedBy: "EVIL-DOMAIN\\attacker");

        var r = advisor.Analyze(new[] { svc }, Ctx());
        Assert.Contains(r.Assessments[0].Reasons, x => x == "RECENT_UNAUTHORIZED_CHANGE");
        Assert.Contains(r.Playbook, p => p.Id == "INVESTIGATE_UNAUTHORIZED_CHANGE");
    }

    [Fact]
    public void Trusted_changer_not_flagged()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X",
            lastChange: Now.AddHours(-2),
            changedBy: "NT AUTHORITY\\SYSTEM");

        var r = advisor.Analyze(new[] { svc }, Ctx());
        Assert.DoesNotContain(r.Assessments[0].Reasons, x => x == "RECENT_UNAUTHORIZED_CHANGE");
    }

    [Fact]
    public void Startup_downgrade_auto_to_manual_flagged()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X",
            expectedStartup: ServiceStartupType.Auto,
            currentStartup: ServiceStartupType.Manual);

        var r = advisor.Analyze(new[] { svc }, Ctx());
        Assert.Contains(r.Assessments[0].Reasons, x => x == "STARTUP_TYPE_DOWNGRADED");
        Assert.Contains(r.Playbook, p => p.Id == "RESTORE_AUTOSTART");
    }

    [Fact]
    public void Missing_recovery_actions_for_critical_flags_p2()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X", critical: true, recovery: 0);
        var r = advisor.Analyze(new[] { svc }, Ctx());
        Assert.Contains(r.Assessments[0].Reasons, x => x == "RECOVERY_ACTIONS_REMOVED");
        Assert.Contains(r.Playbook, p => p.Id == "RESTORE_RECOVERY_ACTIONS");
    }

    [Fact]
    public void Aggressive_appetite_trims_low_severity_p2_actions()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svcs = new[]
        {
            Make("Crit",
                critical: true,
                tamperproof: true,
                currentState: ServiceState.Stopped),
            Make("Other",
                expectedStartup: ServiceStartupType.Auto,
                currentStartup: ServiceStartupType.Manual),
        };

        var r = advisor.Analyze(svcs, Ctx(RiskAppetite.Aggressive));

        // Tamper P0 should always be present.
        Assert.Contains(r.Playbook, p => p.Priority == ActionPriority.P0);
        // RESTORE_RECOVERY_ACTIONS is whitelisted; other P2 actions should be trimmed.
        Assert.DoesNotContain(r.Playbook,
            p => p.Priority == ActionPriority.P2 && p.Id != "RESTORE_RECOVERY_ACTIONS");
    }

    [Fact]
    public void Cautious_appetite_adds_schedule_audit_when_grade_degraded()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X", aclWeakened: true, critical: true); // generates P1, not enough to F
        var r = advisor.Analyze(new[] { svc }, Ctx(RiskAppetite.Cautious));
        // Should land in C/D/F band — cautious adds a follow-up audit.
        Assert.Contains(new[] { "C", "D", "F" }, g => g == r.Grade);
        Assert.Contains(r.Playbook, p => p.Id == "SCHEDULE_SERVICE_AUDIT");
    }

    [Fact]
    public void Multiple_stopped_critical_services_emit_outage_cluster_insight()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svcs = new[]
        {
            Make("A", critical: true, currentState: ServiceState.Stopped),
            Make("B", critical: true, currentState: ServiceState.Stopped),
        };
        var r = advisor.Analyze(svcs, Ctx());
        Assert.Contains(r.Insights, i => i.StartsWith("CRITICAL_SERVICE_OUTAGE_CLUSTER:"));
    }

    [Fact]
    public void Markdown_renderer_contains_all_sections()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X", critical: true, currentState: ServiceState.Stopped);
        var r = advisor.Analyze(new[] { svc }, Ctx());
        var md = advisor.ToMarkdown(r);
        Assert.Contains("# Windows Service Tampering Report", md);
        Assert.Contains("## Services", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
    }

    [Fact]
    public void Json_renderer_is_valid_json()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X", critical: true, currentState: ServiceState.Stopped);
        var r = advisor.Analyze(new[] { svc }, Ctx());
        var json = advisor.ToJson(r);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("F", doc.RootElement.GetProperty("Grade").GetString() ?? doc.RootElement.GetProperty("grade").GetString());
    }

    [Fact]
    public void Assessments_sorted_p0_first_then_risk_desc()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svcs = new[]
        {
            Make("Z_healthy"),
            Make("A_critical_tamper",
                critical: true,
                tamperproof: true,
                currentState: ServiceState.Stopped),
            Make("M_aged_acl", aclWeakened: true, critical: true),
        };
        var r = advisor.Analyze(svcs, Ctx());
        Assert.Equal("A_critical_tamper", r.Assessments[0].ServiceName);
        // Healthy ones come last.
        Assert.Equal("Z_healthy", r.Assessments[^1].ServiceName);
    }

    [Fact]
    public void Does_not_mutate_input_list()
    {
        var advisor = new ServiceTamperingAdvisor();
        var svc = Make("X", critical: true, currentState: ServiceState.Stopped);
        var input = new List<WindowsServiceSnapshot> { svc };
        var copy = new List<WindowsServiceSnapshot>(input);
        advisor.Analyze(input, Ctx());
        Assert.Equal(copy.Count, input.Count);
        Assert.Same(copy[0], input[0]);
    }
}
