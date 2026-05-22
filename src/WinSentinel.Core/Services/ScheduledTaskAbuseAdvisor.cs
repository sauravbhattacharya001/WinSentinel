using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic Windows scheduled-task abuse advisor.
/// <para>
/// Scores per-task snapshots for signs of persistence abuse and tampering:
/// SYSTEM-level tasks created from suspicious paths, hidden tasks, unsigned
/// or LOLBin-launched payloads, At-logon / At-startup triggers on
/// user-writable binaries, recently registered tasks by unknown principals,
/// and stale tasks with weakened ACLs.
/// </para>
/// <para>
/// Eighth sibling in the agentic services suite alongside
/// <see cref="ServiceTamperingAdvisor"/> — focusing on the *scheduled task*
/// persistence surface rather than Windows services. Answers
/// <em>which scheduled tasks look abused, and what should we do first?</em>
/// </para>
/// <para>
/// Pure / deterministic — no I/O, no schtasks queries. Caller passes
/// task snapshots gathered by their own collector. Inject time via
/// <see cref="AdvisorContext.NowOverride"/> for reproducible tests.
/// Never mutates inputs.
/// </para>
/// </summary>
public class ScheduledTaskAbuseAdvisor
{
    // ── Public model ─────────────────────────────────────────────

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TaskTrigger
    {
        AtLogon,
        AtStartup,
        OnSchedule,
        OnEvent,
        OnIdle,
        OnDemand,
        Unknown,
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TaskPrincipal
    {
        System,
        LocalService,
        NetworkService,
        Administrators,
        User,
        Unknown,
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TaskVerdict
    {
        QuarantineAndDelete,
        RestrictAndReview,
        MonitorAndReview,
        Healthy,
    }

    /// <summary>A snapshot of one scheduled task collected from the host.</summary>
    public record ScheduledTaskSnapshot(
        string TaskName,
        string TaskPath,
        TaskPrincipal Principal,
        bool Hidden,
        bool Enabled,
        IReadOnlyList<TaskTrigger> Triggers,
        string? ActionCommand,
        IReadOnlyList<string>? ActionArguments,
        bool BinaryHashKnown,
        bool BinarySignatureValid,
        bool AclWeakened,
        bool BuiltInTask,
        DateTime? RegisteredAt,
        DateTime? LastRunAt,
        string? RegisteredBy);

    public class AdvisorContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;
        public DateTime? NowOverride { get; set; }

        /// <summary>Window (hours) within which a recent registration is considered fresh.</summary>
        public int RecentRegistrationHours { get; set; } = 72;

        /// <summary>Tasks not run within this many days are considered stale (and noteworthy if also weak).</summary>
        public int StaleDays { get; set; } = 180;
    }

    public record TaskAssessment(
        string TaskName,
        string TaskPath,
        TaskPrincipal Principal,
        int RiskScore,
        TaskVerdict Verdict,
        ActionPriority Priority,
        IReadOnlyList<string> Reasons);

    public record PlaybookAction(
        string Id,
        ActionPriority Priority,
        string Label,
        string Owner,
        int BlastRadius,
        string Reversibility,
        string Reason,
        IReadOnlyList<string> RelatedTaskPaths);

    public record ScheduledTaskAbuseReport(
        DateTime GeneratedAt,
        int TotalTasks,
        int QuarantineCount,
        int RestrictCount,
        int MonitorCount,
        double MeanRiskScore,
        double MaxRiskScore,
        string Verdict,
        string Grade,
        IReadOnlyList<TaskAssessment> Assessments,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights);

    // ── Public API ───────────────────────────────────────────────

    public ScheduledTaskAbuseReport Analyze(
        IEnumerable<ScheduledTaskSnapshot> tasks,
        AdvisorContext? ctx = null)
    {
        if (tasks is null) throw new ArgumentNullException(nameof(tasks));
        ctx ??= new AdvisorContext();
        var list = tasks.ToList();
        var now = ctx.NowOverride ?? DateTime.UtcNow;
        double sevMult = ctx.Risk switch
        {
            RiskAppetite.Cautious => 1.15,
            RiskAppetite.Aggressive => 0.85,
            _ => 1.0,
        };
        int recentWindow = Math.Max(1, ctx.RecentRegistrationHours);
        int staleDays = Math.Max(1, ctx.StaleDays);

        var assessments = new List<TaskAssessment>();

        // Cross-portfolio buckets used to drive the playbook.
        var suspiciousBinaries = new List<string>();
        var lolbinLaunches = new List<string>();
        var unsignedBinaries = new List<string>();
        var unknownBinaries = new List<string>();
        var hiddenSystemTasks = new List<string>();
        var persistenceTriggers = new List<string>();
        var aclWeakened = new List<string>();
        var unauthorizedRegistrations = new List<string>();
        var unknownRegistrar = new List<string>();
        var staleHighPriv = new List<string>();
        var disabledLooksDormant = new List<string>();

        bool forceF = false;

        foreach (var t in list)
        {
            var reasons = new List<string>();
            var sevHits = new List<int>();

            bool isHighPriv = t.Principal == TaskPrincipal.System
                              || t.Principal == TaskPrincipal.Administrators
                              || t.Principal == TaskPrincipal.LocalService
                              || t.Principal == TaskPrincipal.NetworkService;

            // SUSPICIOUS_BINARY_PATH — task points at user-writable area.
            if (IsSuspiciousPath(t.ActionCommand))
            {
                sevHits.Add(isHighPriv ? 95 : 70);
                reasons.Add("SUSPICIOUS_BINARY_PATH");
                suspiciousBinaries.Add(t.TaskPath);
                forceF = true;
            }

            // LOLBIN_LAUNCHER — task launches a known living-off-the-land binary
            // with a payload argument (powershell -enc, cmd /c <script>, mshta, regsvr32, rundll32, wmic).
            if (IsLolbinLauncher(t.ActionCommand, t.ActionArguments))
            {
                sevHits.Add(isHighPriv ? 85 : 60);
                reasons.Add("LOLBIN_LAUNCHER");
                lolbinLaunches.Add(t.TaskPath);
                forceF = true;
            }

            // UNKNOWN_BINARY — hash isn't in our trust database.
            if (!t.BinaryHashKnown && !string.IsNullOrWhiteSpace(t.ActionCommand))
            {
                sevHits.Add(isHighPriv ? 55 : 30);
                reasons.Add("UNKNOWN_BINARY");
                unknownBinaries.Add(t.TaskPath);
            }

            // UNSIGNED_BINARY — task action is a real binary with an invalid/missing signature.
            if (!t.BinarySignatureValid && !string.IsNullOrWhiteSpace(t.ActionCommand))
            {
                sevHits.Add(isHighPriv ? 60 : 35);
                reasons.Add("UNSIGNED_BINARY");
                unsignedBinaries.Add(t.TaskPath);
            }

            // HIDDEN_TASK_PRIVILEGED — hidden, enabled, high-privilege, non-built-in.
            if (t.Hidden && t.Enabled && isHighPriv && !t.BuiltInTask)
            {
                sevHits.Add(70);
                reasons.Add("HIDDEN_TASK_PRIVILEGED");
                hiddenSystemTasks.Add(t.TaskPath);
            }

            // PERSISTENCE_TRIGGER — AtLogon / AtStartup is a classic persistence vector.
            // High-severity if the task is also high-privilege, non-built-in, and not signed.
            bool hasPersistenceTrigger = t.Triggers != null
                && t.Triggers.Any(tr => tr == TaskTrigger.AtLogon || tr == TaskTrigger.AtStartup);
            if (hasPersistenceTrigger && !t.BuiltInTask)
            {
                int baseSev = isHighPriv ? 50 : 25;
                if (!t.BinarySignatureValid) baseSev += 15;
                sevHits.Add(baseSev);
                reasons.Add("PERSISTENCE_TRIGGER");
                persistenceTriggers.Add(t.TaskPath);
            }

            // ACL_WEAKENED
            if (t.AclWeakened)
            {
                sevHits.Add(isHighPriv ? 60 : 35);
                reasons.Add("ACL_WEAKENED");
                aclWeakened.Add(t.TaskPath);
            }

            // RECENT_UNAUTHORIZED_REGISTRATION
            bool registeredRecently = t.RegisteredAt.HasValue
                && (now - t.RegisteredAt.Value).TotalHours <= recentWindow
                && (now - t.RegisteredAt.Value).TotalHours >= 0;
            if (registeredRecently && IsUnauthorizedPrincipal(t.RegisteredBy))
            {
                sevHits.Add(isHighPriv ? 65 : 45);
                reasons.Add("RECENT_UNAUTHORIZED_REGISTRATION");
                unauthorizedRegistrations.Add(t.TaskPath);
            }

            // UNKNOWN_REGISTRAR (recent registration, no attribution)
            if (registeredRecently && string.IsNullOrWhiteSpace(t.RegisteredBy))
            {
                sevHits.Add(25);
                if (!reasons.Contains("RECENT_UNAUTHORIZED_REGISTRATION"))
                    reasons.Add("UNKNOWN_REGISTRAR");
                unknownRegistrar.Add(t.TaskPath);
            }

            // STALE_HIGH_PRIVILEGE — high-privilege, non-built-in, hasn't run in StaleDays.
            // Surprisingly common for stale operator scripts that linger as a foothold.
            bool isStale = t.LastRunAt.HasValue
                && (now - t.LastRunAt.Value).TotalDays >= staleDays;
            if (isStale && isHighPriv && !t.BuiltInTask)
            {
                sevHits.Add(30);
                reasons.Add("STALE_HIGH_PRIVILEGE");
                staleHighPriv.Add(t.TaskPath);
            }

            // DISABLED_BUT_PERSISTENT — task disabled but still bound to a persistence trigger
            // and a suspicious or unsigned binary; attackers commonly stage a "dormant" task
            // they re-enable later. We flag low-severity but worth a sweep.
            if (!t.Enabled && hasPersistenceTrigger
                && (!t.BinarySignatureValid || IsSuspiciousPath(t.ActionCommand)))
            {
                sevHits.Add(40);
                reasons.Add("DISABLED_BUT_PERSISTENT");
                disabledLooksDormant.Add(t.TaskPath);
            }

            int risk;
            if (sevHits.Count == 0)
            {
                risk = 0;
                reasons.Add("HEALTHY");
            }
            else
            {
                sevHits.Sort((a, b) => b.CompareTo(a));
                int top = sevHits[0];
                int rest = sevHits.Skip(1).Sum();
                int restCapped = Math.Min(rest, 60);
                double raw = (top + 0.4 * restCapped) * sevMult;
                risk = (int)Math.Round(Math.Clamp(raw, 0, 100));
            }

            TaskVerdict verdict;
            ActionPriority priority;
            if (risk >= 75)
            {
                verdict = TaskVerdict.QuarantineAndDelete;
                priority = ActionPriority.P0;
            }
            else if (risk >= 50)
            {
                verdict = TaskVerdict.RestrictAndReview;
                priority = ActionPriority.P1;
            }
            else if (risk >= 25)
            {
                verdict = TaskVerdict.MonitorAndReview;
                priority = ActionPriority.P2;
            }
            else
            {
                verdict = TaskVerdict.Healthy;
                priority = ActionPriority.P3;
            }

            assessments.Add(new TaskAssessment(
                t.TaskName,
                t.TaskPath,
                t.Principal,
                risk,
                verdict,
                priority,
                reasons));
        }

        // Deterministic sort: priority asc (P0 first), then risk desc, then path asc.
        assessments.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            int r = b.RiskScore.CompareTo(a.RiskScore);
            if (r != 0) return r;
            return string.CompareOrdinal(a.TaskPath, b.TaskPath);
        });

        int total = list.Count;
        int qCount = assessments.Count(a => a.Verdict == TaskVerdict.QuarantineAndDelete);
        int rCount = assessments.Count(a => a.Verdict == TaskVerdict.RestrictAndReview);
        int mCount = assessments.Count(a => a.Verdict == TaskVerdict.MonitorAndReview);
        double meanRisk = assessments.Count == 0 ? 0 : assessments.Average(a => a.RiskScore);
        double maxRisk = assessments.Count == 0 ? 0 : assessments.Max(a => a.RiskScore);

        string verdictStr;
        string grade;
        if (total == 0)
        {
            verdictStr = "NO_DATA";
            grade = "A";
        }
        else if (qCount > 0 || forceF)
        {
            verdictStr = "PERSISTENCE_ABUSE_SUSPECTED";
            grade = "F";
        }
        else if (rCount > 0 || maxRisk >= 50)
        {
            verdictStr = "DEGRADED_POSTURE";
            grade = maxRisk >= 65 ? "D" : "C";
        }
        else if (mCount > 0 || maxRisk >= 25)
        {
            verdictStr = "MINOR_DRIFT";
            grade = "B";
        }
        else
        {
            verdictStr = "HEALTHY";
            grade = "A";
        }

        var playbook = BuildPlaybook(
            ctx.Risk,
            grade,
            suspiciousBinaries,
            lolbinLaunches,
            unsignedBinaries,
            unknownBinaries,
            hiddenSystemTasks,
            persistenceTriggers,
            aclWeakened,
            unauthorizedRegistrations,
            unknownRegistrar,
            staleHighPriv,
            disabledLooksDormant,
            total);

        var insights = new List<string>();
        if (suspiciousBinaries.Count > 0)
            insights.Add($"USER_WRITABLE_PAYLOAD_LOCATIONS:{suspiciousBinaries.Count}");
        if (lolbinLaunches.Count > 0)
            insights.Add($"LOLBIN_PERSISTENCE_VECTOR:{lolbinLaunches.Count}");
        if (hiddenSystemTasks.Count >= 1)
            insights.Add($"HIDDEN_PRIVILEGED_TASKS:{hiddenSystemTasks.Count}");
        if (unauthorizedRegistrations.Count >= 2)
            insights.Add($"UNAUTHORIZED_REGISTRATION_CLUSTER:{unauthorizedRegistrations.Count}");
        if (persistenceTriggers.Count >= 3)
            insights.Add($"WIDESPREAD_PERSISTENCE_FOOTPRINT:{persistenceTriggers.Count}");
        if (aclWeakened.Count >= 2)
            insights.Add($"WIDESPREAD_ACL_WEAKENING:{aclWeakened.Count}");
        if (staleHighPriv.Count >= 3)
            insights.Add($"STALE_HIGH_PRIVILEGE_BACKLOG:{staleHighPriv.Count}");
        if (total > 0 && qCount == 0 && rCount == 0 && mCount == 0)
            insights.Add("ALL_TASKS_HEALTHY");

        return new ScheduledTaskAbuseReport(
            GeneratedAt: now,
            TotalTasks: total,
            QuarantineCount: qCount,
            RestrictCount: rCount,
            MonitorCount: mCount,
            MeanRiskScore: Math.Round(meanRisk, 2),
            MaxRiskScore: Math.Round(maxRisk, 2),
            Verdict: verdictStr,
            Grade: grade,
            Assessments: assessments,
            Playbook: playbook,
            Insights: insights);
    }

    public string ToMarkdown(ScheduledTaskAbuseReport report)
    {
        if (report is null) throw new ArgumentNullException(nameof(report));
        var sb = new StringBuilder();
        sb.AppendLine("# Scheduled Task Abuse Report");
        sb.AppendLine();
        sb.AppendLine($"- Generated: {report.GeneratedAt:O}");
        sb.AppendLine($"- Total tasks: {report.TotalTasks}");
        sb.AppendLine($"- Quarantine: {report.QuarantineCount} | Restrict: {report.RestrictCount} | Monitor: {report.MonitorCount}");
        sb.AppendLine($"- Mean risk: {report.MeanRiskScore:F2} | Max risk: {report.MaxRiskScore:F2}");
        sb.AppendLine($"- Verdict: **{report.Verdict}** | Grade: **{report.Grade}**");
        sb.AppendLine();

        sb.AppendLine("## Tasks");
        if (report.Assessments.Count == 0)
        {
            sb.AppendLine("_(no tasks analyzed)_");
        }
        else
        {
            sb.AppendLine("| Task | Principal | Risk | Verdict | Priority | Reasons |");
            sb.AppendLine("|---|---|---:|---|---|---|");
            foreach (var a in report.Assessments)
            {
                sb.AppendLine($"| {a.TaskPath} | {a.Principal} | {a.RiskScore} | {a.Verdict} | {a.Priority} | {string.Join(", ", a.Reasons)} |");
            }
        }
        sb.AppendLine();

        sb.AppendLine("## Playbook");
        if (report.Playbook.Count == 0)
        {
            sb.AppendLine("_(no actions)_");
        }
        else
        {
            sb.AppendLine("| Priority | Action | Owner | Blast | Reversibility | Tasks |");
            sb.AppendLine("|---|---|---|---:|---|---|");
            foreach (var p in report.Playbook)
            {
                sb.AppendLine($"| {p.Priority} | {p.Label} ({p.Id}) | {p.Owner} | {p.BlastRadius} | {p.Reversibility} | {string.Join(", ", p.RelatedTaskPaths)} |");
            }
        }
        sb.AppendLine();

        sb.AppendLine("## Insights");
        if (report.Insights.Count == 0)
        {
            sb.AppendLine("- (none)");
        }
        else
        {
            foreach (var i in report.Insights) sb.AppendLine($"- {i}");
        }
        return sb.ToString();
    }

    public string ToJson(ScheduledTaskAbuseReport report)
    {
        if (report is null) throw new ArgumentNullException(nameof(report));
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        };
        return JsonSerializer.Serialize(report, opts);
    }

    // ── Internals ────────────────────────────────────────────────

    private static bool IsSuspiciousPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.ToLowerInvariant().Trim();
        if (p.StartsWith("\""))
        {
            int end = p.IndexOf('"', 1);
            if (end > 0) p = p.Substring(1, end - 1);
        }
        string[] needles =
        {
            @"\temp\",
            @"\tmp\",
            @"\appdata\local\temp",
            @"\appdata\roaming\",
            @"\users\public\",
            @"\programdata\public\",
            @"\downloads\",
            @"\$recycle.bin\",
            @"\windows\tasks\",
        };
        return needles.Any(p.Contains);
    }

    private static readonly string[] LolbinNames =
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "wscript.exe",
        "cscript.exe",
        "wmic.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msbuild.exe",
        "installutil.exe",
    };

    private static bool IsLolbinLauncher(string? command, IReadOnlyList<string>? args)
    {
        if (string.IsNullOrWhiteSpace(command)) return false;
        var c = command.ToLowerInvariant().Trim();
        // Strip surrounding quotes
        if (c.StartsWith("\""))
        {
            int end = c.IndexOf('"', 1);
            if (end > 0) c = c.Substring(1, end - 1);
        }
        // Match by trailing executable name, not full path.
        bool isLolbin = LolbinNames.Any(n => c.EndsWith("\\" + n) || c == n || c.EndsWith("/" + n));
        if (!isLolbin) return false;

        // Lone LOLBin with no arguments is much less interesting (e.g. a built-in maintenance task);
        // require *some* arguments to flag as a launcher.
        if (args is null || args.Count == 0) return false;

        // Strong-signal flags that usually mean "I'm launching a payload".
        string[] payloadHints =
        {
            "-enc",
            "-encodedcommand",
            "-nop",
            "-noprofile",
            "-windowstyle",
            "-w hidden",
            "/c",
            "iex",
            "invoke-expression",
            "downloadstring",
            "downloadfile",
            "frombase64string",
            ".ps1",
            ".vbs",
            ".js",
            ".hta",
            "http://",
            "https://",
            "\\\\",
            "javascript:",
        };
        string joined = string.Join(" ", args).ToLowerInvariant();
        return payloadHints.Any(joined.Contains);
    }

    private static bool IsUnauthorizedPrincipal(string? changedBy)
    {
        if (string.IsNullOrWhiteSpace(changedBy)) return false;
        var c = changedBy.ToLowerInvariant();
        // Trusted: well-known SYSTEM / TrustedInstaller / Administrators.
        string[] trusted =
        {
            "nt authority\\system",
            "nt service\\trustedinstaller",
            "builtin\\administrators",
            "nt authority\\local service",
            "nt authority\\network service",
        };
        if (trusted.Any(t => c.Contains(t))) return false;
        // Anything else that registered a privileged task in a small recent window
        // (the caller already gated by recency) is suspicious by default.
        return true;
    }

    private static List<PlaybookAction> BuildPlaybook(
        RiskAppetite risk,
        string grade,
        List<string> suspiciousBinaries,
        List<string> lolbinLaunches,
        List<string> unsignedBinaries,
        List<string> unknownBinaries,
        List<string> hiddenSystemTasks,
        List<string> persistenceTriggers,
        List<string> aclWeakened,
        List<string> unauthorizedRegistrations,
        List<string> unknownRegistrar,
        List<string> staleHighPriv,
        List<string> disabledLooksDormant,
        int total)
    {
        var actions = new List<PlaybookAction>();

        if (suspiciousBinaries.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "QUARANTINE_SUSPICIOUS_TASK_BINARY",
                ActionPriority.P0,
                "Quarantine suspicious task binaries from user-writable paths",
                "incident_response",
                BlastRadius: 4,
                Reversibility: "low",
                Reason: "Scheduled tasks pointing at user-writable directories are a classic persistence pattern.",
                RelatedTaskPaths: suspiciousBinaries.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (lolbinLaunches.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "DISABLE_LOLBIN_PERSISTENCE",
                ActionPriority.P0,
                "Disable and dump LOLBin-launching scheduled tasks",
                "incident_response",
                BlastRadius: 4,
                Reversibility: "medium",
                Reason: "Tasks that launch powershell/mshta/regsvr32/etc with payload arguments are a known persistence vector.",
                RelatedTaskPaths: lolbinLaunches.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (hiddenSystemTasks.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "INVESTIGATE_HIDDEN_PRIVILEGED_TASKS",
                ActionPriority.P0,
                "Investigate hidden privileged scheduled tasks",
                "incident_response",
                BlastRadius: 3,
                Reversibility: "medium",
                Reason: "Non-built-in privileged tasks marked Hidden are unusual and frequently used to evade defenders.",
                RelatedTaskPaths: hiddenSystemTasks.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unauthorizedRegistrations.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "REVIEW_RECENT_UNAUTHORIZED_REGISTRATIONS",
                ActionPriority.P0,
                "Review recent scheduled-task registrations by non-trusted principals",
                "incident_response",
                BlastRadius: 3,
                Reversibility: "medium",
                Reason: "Recent task registrations not attributed to SYSTEM / TrustedInstaller / Administrators warrant review.",
                RelatedTaskPaths: unauthorizedRegistrations.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (persistenceTriggers.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "RESTRICT_PERSISTENCE_TRIGGERS",
                ActionPriority.P1,
                "Restrict AtLogon/AtStartup triggers on non-built-in tasks",
                "platform_admin",
                BlastRadius: 3,
                Reversibility: "high",
                Reason: "Logon/startup triggers on unsigned or non-built-in tasks reduce visibility into what runs at boot.",
                RelatedTaskPaths: persistenceTriggers.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unsignedBinaries.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "REQUIRE_SIGNED_TASK_BINARIES",
                ActionPriority.P1,
                "Replace unsigned task binaries with signed builds",
                "platform_admin",
                BlastRadius: 3,
                Reversibility: "high",
                Reason: "Unsigned task payloads cannot be attested and bypass code-signing posture checks.",
                RelatedTaskPaths: unsignedBinaries.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (aclWeakened.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "RESTORE_TASK_ACLS",
                ActionPriority.P1,
                "Restore weakened scheduled-task ACLs to baseline",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Weakened ACLs let lower-privilege users modify task definitions and pivot to SYSTEM.",
                RelatedTaskPaths: aclWeakened.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (disabledLooksDormant.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "AUDIT_DORMANT_PERSISTENCE",
                ActionPriority.P1,
                "Audit disabled tasks that still carry persistence triggers and suspicious binaries",
                "incident_response",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Attackers stage disabled tasks they can re-enable later; treat as a foothold.",
                RelatedTaskPaths: disabledLooksDormant.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unknownBinaries.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "HASH_AND_VERIFY_UNKNOWN_BINARIES",
                ActionPriority.P2,
                "Hash and verify scheduled-task binaries missing from the trust database",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Unknown payloads should be hashed and either added to the allow-list or removed.",
                RelatedTaskPaths: unknownBinaries.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unknownRegistrar.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "ATTRIBUTE_UNKNOWN_REGISTRATIONS",
                ActionPriority.P2,
                "Attribute recent task registrations missing a creator principal",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: "Recent registrations with no creator attribution are a telemetry gap worth closing.",
                RelatedTaskPaths: unknownRegistrar.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (staleHighPriv.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "RETIRE_STALE_PRIVILEGED_TASKS",
                ActionPriority.P2,
                "Retire stale privileged scheduled tasks that haven't run in a long time",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Stale privileged tasks expand the persistence surface area with no operational benefit.",
                RelatedTaskPaths: staleHighPriv.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        // Cautious adds a calibration sweep when grade is poor.
        if (risk == RiskAppetite.Cautious && (grade == "C" || grade == "D" || grade == "F"))
        {
            actions.Add(new PlaybookAction(
                "SCHEDULE_TASK_INVENTORY_AUDIT",
                ActionPriority.P2,
                "Schedule a full scheduled-task inventory audit",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: "Grade indicates posture drift; a planned sweep catches what we missed.",
                RelatedTaskPaths: new List<string>()));
        }

        // P3 fallback so callers always have something to do.
        if (actions.Count == 0)
        {
            actions.Add(new PlaybookAction(
                "ALL_TASKS_HEALTHY",
                ActionPriority.P3,
                "Maintain scheduled-task monitoring",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: total == 0
                    ? "No tasks were provided; keep the collector running."
                    : "No abuse indicators detected; continue routine monitoring.",
                RelatedTaskPaths: new List<string>()));
        }

        // Aggressive trims P3 fallbacks when actionable items already exist
        // (caller asked for less noise, not more).
        if (risk == RiskAppetite.Aggressive && actions.Count > 1)
        {
            actions = actions.Where(a => a.Priority != ActionPriority.P3).ToList();
        }

        // Deterministic order: priority asc, id asc.
        actions.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            return string.CompareOrdinal(a.Id, b.Id);
        });
        return actions;
    }
}
