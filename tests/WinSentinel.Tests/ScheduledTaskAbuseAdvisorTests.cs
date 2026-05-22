using System.Text.Json;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.ScheduledTaskAbuseAdvisor;

namespace WinSentinel.Tests;

public class ScheduledTaskAbuseAdvisorTests
{
    private static readonly DateTime Now = new DateTime(2026, 5, 22, 17, 0, 0, DateTimeKind.Utc);

    private static AdvisorContext Ctx(
        RiskAppetite risk = RiskAppetite.Balanced,
        int recentHours = 72,
        int staleDays = 180) =>
        new AdvisorContext
        {
            Risk = risk,
            NowOverride = Now,
            RecentRegistrationHours = recentHours,
            StaleDays = staleDays,
        };

    private static ScheduledTaskSnapshot Make(
        string name,
        string? path = null,
        TaskPrincipal principal = TaskPrincipal.User,
        bool hidden = false,
        bool enabled = true,
        IReadOnlyList<TaskTrigger>? triggers = null,
        string? action = @"C:\Windows\System32\notepad.exe",
        IReadOnlyList<string>? args = null,
        bool hashKnown = true,
        bool signatureValid = true,
        bool aclWeakened = false,
        bool builtIn = false,
        DateTime? registeredAt = null,
        DateTime? lastRunAt = null,
        string? registeredBy = "NT AUTHORITY\\SYSTEM")
    {
        return new ScheduledTaskSnapshot(
            TaskName: name,
            TaskPath: path ?? ("\\" + name),
            Principal: principal,
            Hidden: hidden,
            Enabled: enabled,
            Triggers: triggers ?? new[] { TaskTrigger.OnSchedule },
            ActionCommand: action,
            ActionArguments: args,
            BinaryHashKnown: hashKnown,
            BinarySignatureValid: signatureValid,
            AclWeakened: aclWeakened,
            BuiltInTask: builtIn,
            RegisteredAt: registeredAt,
            LastRunAt: lastRunAt,
            RegisteredBy: registeredBy);
    }

    [Fact]
    public void Empty_input_returns_grade_A_with_p3_fallback()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var r = a.Analyze(Array.Empty<ScheduledTaskSnapshot>(), Ctx());

        Assert.Equal(0, r.TotalTasks);
        Assert.Equal("A", r.Grade);
        Assert.Equal("NO_DATA", r.Verdict);
        Assert.Single(r.Playbook);
        Assert.Equal("ALL_TASKS_HEALTHY", r.Playbook[0].Id);
        Assert.Equal(ActionPriority.P3, r.Playbook[0].Priority);
    }

    [Fact]
    public void Suspicious_binary_path_forces_F_and_quarantine_action()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("RogueTask", principal: TaskPrincipal.System,
            action: @"C:\Users\Public\AppData\Local\Temp\evil.exe");

        var r = a.Analyze(new[] { t }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Equal("PERSISTENCE_ABUSE_SUSPECTED", r.Verdict);
        Assert.Equal(1, r.QuarantineCount);
        var assess = Assert.Single(r.Assessments);
        Assert.Equal(TaskVerdict.QuarantineAndDelete, assess.Verdict);
        Assert.Contains("SUSPICIOUS_BINARY_PATH", assess.Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "QUARANTINE_SUSPICIOUS_TASK_BINARY" && p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Lolbin_powershell_with_encoded_command_forces_F()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("Updater",
            principal: TaskPrincipal.System,
            action: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            args: new[] { "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", "SQBFAFgAIA==" });

        var r = a.Analyze(new[] { t }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Contains("LOLBIN_LAUNCHER", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "DISABLE_LOLBIN_PERSISTENCE" && p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Hidden_privileged_task_triggers_p0_investigation()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("ShadyAdminTask",
            principal: TaskPrincipal.Administrators,
            hidden: true,
            enabled: true,
            triggers: new[] { TaskTrigger.OnSchedule });

        var r = a.Analyze(new[] { t }, Ctx());

        Assert.Contains("HIDDEN_TASK_PRIVILEGED", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "INVESTIGATE_HIDDEN_PRIVILEGED_TASKS" && p.Priority == ActionPriority.P0);
        Assert.Contains(r.Insights, i => i.StartsWith("HIDDEN_PRIVILEGED_TASKS:"));
    }

    [Fact]
    public void Builtin_hidden_task_is_ignored()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("Microsoft\\Windows\\Defender",
            principal: TaskPrincipal.System,
            hidden: true,
            builtIn: true);

        var r = a.Analyze(new[] { t }, Ctx());

        Assert.DoesNotContain("HIDDEN_TASK_PRIVILEGED", r.Assessments[0].Reasons);
        Assert.Equal("A", r.Grade);
    }

    [Fact]
    public void Persistence_trigger_on_unsigned_user_task_flags_both_reasons()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("LogonHelper",
            principal: TaskPrincipal.User,
            triggers: new[] { TaskTrigger.AtLogon },
            signatureValid: false,
            registeredBy: "NT AUTHORITY\\SYSTEM");

        var r = a.Analyze(new[] { t }, Ctx());

        Assert.Contains("PERSISTENCE_TRIGGER", r.Assessments[0].Reasons);
        Assert.Contains("UNSIGNED_BINARY", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "RESTRICT_PERSISTENCE_TRIGGERS");
        Assert.Contains(r.Playbook, p => p.Id == "REQUIRE_SIGNED_TASK_BINARIES");
    }

    [Fact]
    public void Recent_unauthorized_registration_flags_and_clusters()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var ts = Now.AddHours(-1);
        var t1 = Make("WeirdTask1", principal: TaskPrincipal.Administrators,
            registeredAt: ts, registeredBy: "WORKSTATION\\bob");
        var t2 = Make("WeirdTask2", principal: TaskPrincipal.Administrators,
            registeredAt: ts, registeredBy: "WORKSTATION\\bob");

        var r = a.Analyze(new[] { t1, t2 }, Ctx());

        Assert.All(r.Assessments, x => Assert.Contains("RECENT_UNAUTHORIZED_REGISTRATION", x.Reasons));
        Assert.Contains(r.Playbook, p => p.Id == "REVIEW_RECENT_UNAUTHORIZED_REGISTRATIONS");
        Assert.Contains(r.Insights, i => i.StartsWith("UNAUTHORIZED_REGISTRATION_CLUSTER:"));
    }

    [Fact]
    public void Trusted_principal_recent_registration_is_not_unauthorized()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("MaintTask",
            principal: TaskPrincipal.System,
            registeredAt: Now.AddHours(-1),
            registeredBy: "NT SERVICE\\TrustedInstaller");

        var r = a.Analyze(new[] { t }, Ctx());
        Assert.DoesNotContain("RECENT_UNAUTHORIZED_REGISTRATION", r.Assessments[0].Reasons);
    }

    [Fact]
    public void Unknown_registrar_flagged_when_recent()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("MysteryTask",
            registeredAt: Now.AddHours(-2),
            registeredBy: null);

        var r = a.Analyze(new[] { t }, Ctx());
        Assert.Contains("UNKNOWN_REGISTRAR", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "ATTRIBUTE_UNKNOWN_REGISTRATIONS");
    }

    [Fact]
    public void Stale_high_privilege_task_flagged()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("OldOpsTask",
            principal: TaskPrincipal.Administrators,
            lastRunAt: Now.AddDays(-365));

        var r = a.Analyze(new[] { t }, Ctx(staleDays: 180));
        Assert.Contains("STALE_HIGH_PRIVILEGE", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "RETIRE_STALE_PRIVILEGED_TASKS");
    }

    [Fact]
    public void Disabled_but_persistent_dormant_pattern_flagged()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("DormantAttacker",
            principal: TaskPrincipal.User,
            enabled: false,
            triggers: new[] { TaskTrigger.AtLogon },
            signatureValid: false);

        var r = a.Analyze(new[] { t }, Ctx());
        Assert.Contains("DISABLED_BUT_PERSISTENT", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "AUDIT_DORMANT_PERSISTENCE");
    }

    [Fact]
    public void Acl_weakened_flagged_with_p1_action()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("SoftAcl", principal: TaskPrincipal.System, aclWeakened: true);
        var r = a.Analyze(new[] { t }, Ctx());
        Assert.Contains("ACL_WEAKENED", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "RESTORE_TASK_ACLS");
    }

    [Fact]
    public void Unknown_binary_yields_p2_hash_action()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("MaybeOk", action: @"C:\Apps\foo.exe", hashKnown: false);
        var r = a.Analyze(new[] { t }, Ctx());
        Assert.Contains("UNKNOWN_BINARY", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "HASH_AND_VERIFY_UNKNOWN_BINARIES");
    }

    [Fact]
    public void Healthy_task_yields_grade_A_and_p3()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("CleanOne", builtIn: true);
        var r = a.Analyze(new[] { t }, Ctx());
        Assert.Equal("A", r.Grade);
        Assert.Contains("HEALTHY", r.Assessments[0].Reasons);
        Assert.Single(r.Playbook);
        Assert.Equal("ALL_TASKS_HEALTHY", r.Playbook[0].Id);
    }

    [Fact]
    public void Cautious_appetite_appends_inventory_audit_when_grade_is_poor()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("Susp",
            principal: TaskPrincipal.System,
            action: @"C:\Users\Public\Downloads\thing.exe");
        var r = a.Analyze(new[] { t }, Ctx(risk: RiskAppetite.Cautious));
        Assert.Equal("F", r.Grade);
        Assert.Contains(r.Playbook, p => p.Id == "SCHEDULE_TASK_INVENTORY_AUDIT");
    }

    [Fact]
    public void Aggressive_appetite_trims_p3_when_other_actions_present()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t1 = Make("Susp",
            principal: TaskPrincipal.System,
            action: @"C:\Users\Public\Downloads\thing.exe");
        var t2 = Make("Calm", builtIn: true);
        var r = a.Analyze(new[] { t1, t2 }, Ctx(risk: RiskAppetite.Aggressive));
        Assert.DoesNotContain(r.Playbook, p => p.Priority == ActionPriority.P3);
    }

    [Fact]
    public void Assessments_sorted_by_priority_then_risk_then_path()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t1 = Make("LowRisk", path: "\\Z_Low", builtIn: true);
        var t2 = Make("HighRisk", path: "\\A_High",
            principal: TaskPrincipal.System,
            action: @"C:\Users\Public\Downloads\evil.exe");
        var t3 = Make("MidRisk", path: "\\M_Mid",
            principal: TaskPrincipal.Administrators,
            triggers: new[] { TaskTrigger.AtLogon },
            signatureValid: false);
        var r = a.Analyze(new[] { t1, t2, t3 }, Ctx());
        // P0 first
        Assert.Equal(ActionPriority.P0, r.Assessments[0].Priority);
        Assert.Equal("\\A_High", r.Assessments[0].TaskPath);
    }

    [Fact]
    public void Markdown_renders_all_sections()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("Susp",
            principal: TaskPrincipal.System,
            action: @"C:\Users\Public\Downloads\thing.exe");
        var r = a.Analyze(new[] { t }, Ctx());
        var md = a.ToMarkdown(r);
        Assert.Contains("# Scheduled Task Abuse Report", md);
        Assert.Contains("## Tasks", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
        Assert.Contains("PERSISTENCE_ABUSE_SUSPECTED", md);
    }

    [Fact]
    public void Json_round_trips()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("Susp",
            principal: TaskPrincipal.System,
            action: @"C:\Users\Public\Downloads\thing.exe");
        var r = a.Analyze(new[] { t }, Ctx());
        var json = a.ToJson(r);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("F", doc.RootElement.GetProperty("Grade").GetString());
        Assert.Equal("PERSISTENCE_ABUSE_SUSPECTED", doc.RootElement.GetProperty("Verdict").GetString());
    }

    [Fact]
    public void Inputs_are_not_mutated()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var triggers = new List<TaskTrigger> { TaskTrigger.AtLogon };
        var args = new List<string> { "-EncodedCommand", "SQBFAFgAIA==" };
        var t = Make("Susp",
            principal: TaskPrincipal.System,
            action: @"C:\Windows\System32\powershell.exe",
            args: args,
            triggers: triggers);
        var pre = JsonSerializer.Serialize(t);
        a.Analyze(new[] { t }, Ctx());
        var post = JsonSerializer.Serialize(t);
        Assert.Equal(pre, post);
        Assert.Single(triggers);
        Assert.Equal(2, args.Count);
    }

    [Fact]
    public void Lolbin_with_no_payload_args_is_not_flagged()
    {
        var a = new ScheduledTaskAbuseAdvisor();
        var t = Make("PlainPwsh",
            principal: TaskPrincipal.System,
            action: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            args: null);
        var r = a.Analyze(new[] { t }, Ctx());
        Assert.DoesNotContain("LOLBIN_LAUNCHER", r.Assessments[0].Reasons);
    }
}
