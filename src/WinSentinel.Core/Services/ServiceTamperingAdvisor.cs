using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic Windows-service tampering advisor.
/// <para>
/// Scores per-service snapshots for signs of tampering with security-critical
/// Windows services (Defender, Firewall, EventLog, Update, Backup, etc.):
/// stopped/disabled critical services, weakened ACLs, suspicious binary paths,
/// missing recovery actions, unauthorized recent changes — then emits a
/// portfolio verdict + P0-first remediation playbook.
/// </para>
/// <para>
/// Seventh sibling in the agentic services suite alongside
/// <see cref="FixOrchestrationPlanner"/>, <see cref="AlertRoutingAdvisor"/>,
/// <see cref="AttackerProfileSynthesizer"/>, <see cref="PostureRegressionExplainer"/>,
/// <see cref="PolicyExceptionRiskAdvisor"/>, and
/// <see cref="ThreatHorizonForecastAdvisor"/>. It answers
/// <em>which Windows services look tampered with, and what should we do first?</em>
/// </para>
/// <para>
/// Pure / deterministic — no I/O, no process queries. Caller passes service
/// snapshots gathered by their own collector. Inject time via
/// <see cref="AdvisorContext.NowOverride"/> for reproducible tests.
/// Never mutates inputs.
/// </para>
/// </summary>
public class ServiceTamperingAdvisor
{
    // ── Public model ─────────────────────────────────────────────

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ServiceState { Running, Stopped, Paused, Unknown }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ServiceStartupType { Auto, AutoDelayed, Manual, Disabled, Unknown }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ServiceCategory { Antivirus, Firewall, EventLog, Update, Backup, RemoteAccess, Other }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ServiceVerdict
    {
        QuarantineAndRestore,
        RestoreAndHarden,
        MonitorAndReview,
        Healthy,
    }

    /// <summary>A snapshot of one Windows service collected from the host.</summary>
    public record WindowsServiceSnapshot(
        string ServiceName,
        string DisplayName,
        ServiceCategory Category,
        bool CriticalAsset,
        bool Tamperproof,
        ServiceState ExpectedState,
        ServiceState CurrentState,
        ServiceStartupType ExpectedStartupType,
        ServiceStartupType CurrentStartupType,
        string? BinaryPath,
        bool BinaryPathHashKnown,
        int RecoveryActionsCount,
        bool AclWeakened,
        DateTime? LastChangeAt,
        string? ChangedBy);

    public class AdvisorContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;
        public DateTime? NowOverride { get; set; }
        /// <summary>Window (hours) within which a recent change is considered fresh and noteworthy.</summary>
        public int RecentChangeHours { get; set; } = 72;
    }

    public record ServiceAssessment(
        string ServiceName,
        string DisplayName,
        ServiceCategory Category,
        int RiskScore,
        ServiceVerdict Verdict,
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
        IReadOnlyList<string> RelatedServiceNames);

    public record ServiceTamperingReport(
        DateTime GeneratedAt,
        int TotalServices,
        int QuarantineCount,
        int RestoreCount,
        int MonitorCount,
        double MeanRiskScore,
        double MaxRiskScore,
        string Verdict,
        string Grade,
        IReadOnlyList<ServiceAssessment> Assessments,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights);

    // ── Public API ───────────────────────────────────────────────

    public ServiceTamperingReport Analyze(
        IEnumerable<WindowsServiceSnapshot> services,
        AdvisorContext? ctx = null)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        ctx ??= new AdvisorContext();
        var list = services.ToList();
        var now = ctx.NowOverride ?? DateTime.UtcNow;
        double sevMult = ctx.Risk switch
        {
            RiskAppetite.Cautious => 1.15,
            RiskAppetite.Aggressive => 0.85,
            _ => 1.0,
        };
        int recentWindow = Math.Max(1, ctx.RecentChangeHours);

        var assessments = new List<ServiceAssessment>();
        // Cross-portfolio buckets for playbook generation
        var stoppedCritical = new List<string>();
        var disabledCritical = new List<string>();
        var tamperproofViolations = new List<string>();
        var suspiciousBinaries = new List<string>();
        var unknownBinaries = new List<string>();
        var aclWeakened = new List<string>();
        var startupDowngraded = new List<string>();
        var unauthorizedChanges = new List<string>();
        var unknownChanger = new List<string>();
        var recoveryRemoved = new List<string>();

        bool forceF = false;

        foreach (var s in list)
        {
            var reasons = new List<string>();
            var sevHits = new List<int>();

            bool isCritical = s.CriticalAsset || s.Tamperproof;

            // CRITICAL_SERVICE_STOPPED
            if (s.CriticalAsset
                && s.ExpectedState == ServiceState.Running
                && (s.CurrentState == ServiceState.Stopped || s.CurrentState == ServiceState.Paused))
            {
                sevHits.Add(80);
                reasons.Add("CRITICAL_SERVICE_STOPPED");
                stoppedCritical.Add(s.ServiceName);
            }

            // CRITICAL_SERVICE_DISABLED
            if (s.CriticalAsset
                && s.CurrentStartupType == ServiceStartupType.Disabled
                && s.ExpectedStartupType != ServiceStartupType.Disabled)
            {
                sevHits.Add(90);
                reasons.Add("CRITICAL_SERVICE_DISABLED");
                disabledCritical.Add(s.ServiceName);
                forceF = true;
            }

            // SECURITY_SERVICE_TAMPERED (tamperproof service drifted)
            if (s.Tamperproof
                && (s.CurrentState != s.ExpectedState
                    || s.CurrentStartupType != s.ExpectedStartupType
                    || s.AclWeakened))
            {
                sevHits.Add(95);
                reasons.Add("SECURITY_SERVICE_TAMPERED");
                tamperproofViolations.Add(s.ServiceName);
                forceF = true;
            }

            // BINARY_PATH_UNKNOWN
            if (!s.BinaryPathHashKnown)
            {
                sevHits.Add(isCritical ? 70 : 40);
                reasons.Add("BINARY_PATH_UNKNOWN");
                unknownBinaries.Add(s.ServiceName);
            }

            // BINARY_PATH_SUSPICIOUS (executable lives in user-writable area)
            if (IsSuspiciousPath(s.BinaryPath))
            {
                sevHits.Add(80);
                reasons.Add("BINARY_PATH_SUSPICIOUS");
                suspiciousBinaries.Add(s.ServiceName);
                forceF = true;
            }

            // ACL_WEAKENED
            if (s.AclWeakened)
            {
                sevHits.Add(isCritical ? 60 : 35);
                reasons.Add("ACL_WEAKENED");
                aclWeakened.Add(s.ServiceName);
            }

            // RECOVERY_ACTIONS_REMOVED
            if (s.CriticalAsset && s.RecoveryActionsCount == 0)
            {
                sevHits.Add(35);
                reasons.Add("RECOVERY_ACTIONS_REMOVED");
                recoveryRemoved.Add(s.ServiceName);
            }

            // STARTUP_TYPE_DOWNGRADED (Auto -> Manual etc, but not Disabled which is handled above)
            if (IsStartupDowngrade(s.ExpectedStartupType, s.CurrentStartupType))
            {
                sevHits.Add(30);
                reasons.Add("STARTUP_TYPE_DOWNGRADED");
                startupDowngraded.Add(s.ServiceName);
            }

            // RECENT_UNAUTHORIZED_CHANGE
            bool changeRecent = s.LastChangeAt.HasValue
                && (now - s.LastChangeAt.Value).TotalHours <= recentWindow
                && (now - s.LastChangeAt.Value).TotalHours >= 0;
            if (changeRecent && IsUnauthorizedChanger(s.ChangedBy))
            {
                sevHits.Add(55);
                reasons.Add("RECENT_UNAUTHORIZED_CHANGE");
                unauthorizedChanges.Add(s.ServiceName);
            }

            // UNKNOWN_CHANGER (had a recent change but no attribution)
            if (changeRecent && string.IsNullOrWhiteSpace(s.ChangedBy))
            {
                sevHits.Add(25);
                if (!reasons.Contains("RECENT_UNAUTHORIZED_CHANGE"))
                    reasons.Add("UNKNOWN_CHANGER");
                unknownChanger.Add(s.ServiceName);
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

            ServiceVerdict verdict;
            ActionPriority priority;
            if (risk >= 75)
            {
                verdict = ServiceVerdict.QuarantineAndRestore;
                priority = ActionPriority.P0;
            }
            else if (risk >= 50)
            {
                verdict = ServiceVerdict.RestoreAndHarden;
                priority = ActionPriority.P1;
            }
            else if (risk >= 25)
            {
                verdict = ServiceVerdict.MonitorAndReview;
                priority = ActionPriority.P2;
            }
            else
            {
                verdict = ServiceVerdict.Healthy;
                priority = ActionPriority.P3;
            }

            assessments.Add(new ServiceAssessment(
                s.ServiceName,
                s.DisplayName,
                s.Category,
                risk,
                verdict,
                priority,
                reasons));
        }

        // Sort assessments deterministically: priority asc (P0 first), then risk desc, then name asc.
        assessments.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            int r = b.RiskScore.CompareTo(a.RiskScore);
            if (r != 0) return r;
            return string.CompareOrdinal(a.ServiceName, b.ServiceName);
        });

        int total = list.Count;
        int qCount = assessments.Count(a => a.Verdict == ServiceVerdict.QuarantineAndRestore);
        int rCount = assessments.Count(a => a.Verdict == ServiceVerdict.RestoreAndHarden);
        int mCount = assessments.Count(a => a.Verdict == ServiceVerdict.MonitorAndReview);
        double meanRisk = assessments.Count == 0 ? 0 : assessments.Average(a => a.RiskScore);
        double maxRisk = assessments.Count == 0 ? 0 : assessments.Max(a => a.RiskScore);

        // Portfolio verdict + grade
        string verdictStr;
        string grade;
        if (total == 0)
        {
            verdictStr = "NO_DATA";
            grade = "A";
        }
        else if (qCount > 0 || forceF)
        {
            verdictStr = "ACTIVE_TAMPERING_SUSPECTED";
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

        // Playbook
        var playbook = BuildPlaybook(
            ctx.Risk,
            grade,
            stoppedCritical,
            disabledCritical,
            tamperproofViolations,
            suspiciousBinaries,
            unknownBinaries,
            aclWeakened,
            startupDowngraded,
            unauthorizedChanges,
            unknownChanger,
            recoveryRemoved,
            total);

        // Insights
        var insights = new List<string>();
        if (tamperproofViolations.Count > 0)
            insights.Add($"TAMPERPROOF_SERVICE_TAMPERED:{tamperproofViolations.Count}");
        if (disabledCritical.Count > 0)
            insights.Add($"CRITICAL_SERVICE_DISABLED:{disabledCritical.Count}");
        if (suspiciousBinaries.Count > 0)
            insights.Add($"SUSPICIOUS_BINARY_LOCATIONS:{suspiciousBinaries.Count}");
        if (stoppedCritical.Count >= 2)
            insights.Add($"CRITICAL_SERVICE_OUTAGE_CLUSTER:{stoppedCritical.Count}");
        if (unauthorizedChanges.Count >= 2)
            insights.Add($"UNAUTHORIZED_CHANGE_CLUSTER:{unauthorizedChanges.Count}");
        if (aclWeakened.Count >= 2)
            insights.Add($"WIDESPREAD_ACL_WEAKENING:{aclWeakened.Count}");
        if (total > 0 && qCount == 0 && rCount == 0 && mCount == 0)
            insights.Add("ALL_SERVICES_HEALTHY");

        return new ServiceTamperingReport(
            GeneratedAt: now,
            TotalServices: total,
            QuarantineCount: qCount,
            RestoreCount: rCount,
            MonitorCount: mCount,
            MeanRiskScore: Math.Round(meanRisk, 2),
            MaxRiskScore: Math.Round(maxRisk, 2),
            Verdict: verdictStr,
            Grade: grade,
            Assessments: assessments,
            Playbook: playbook,
            Insights: insights);
    }

    public string ToMarkdown(ServiceTamperingReport report)
    {
        if (report is null) throw new ArgumentNullException(nameof(report));
        var sb = new StringBuilder();
        sb.AppendLine("# Windows Service Tampering Report");
        sb.AppendLine();
        sb.AppendLine($"- Generated: {report.GeneratedAt:O}");
        sb.AppendLine($"- Total services: {report.TotalServices}");
        sb.AppendLine($"- Quarantine: {report.QuarantineCount} | Restore: {report.RestoreCount} | Monitor: {report.MonitorCount}");
        sb.AppendLine($"- Mean risk: {report.MeanRiskScore:F2} | Max risk: {report.MaxRiskScore:F2}");
        sb.AppendLine($"- Verdict: **{report.Verdict}** | Grade: **{report.Grade}**");
        sb.AppendLine();

        sb.AppendLine("## Services");
        if (report.Assessments.Count == 0)
        {
            sb.AppendLine("_(no services analyzed)_");
        }
        else
        {
            sb.AppendLine("| Service | Category | Risk | Verdict | Priority | Reasons |");
            sb.AppendLine("|---|---|---:|---|---|---|");
            foreach (var a in report.Assessments)
            {
                sb.AppendLine($"| {a.ServiceName} | {a.Category} | {a.RiskScore} | {a.Verdict} | {a.Priority} | {string.Join(", ", a.Reasons)} |");
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
            sb.AppendLine("| Priority | Action | Owner | Blast | Reversibility | Services |");
            sb.AppendLine("|---|---|---|---:|---|---|");
            foreach (var p in report.Playbook)
            {
                sb.AppendLine($"| {p.Priority} | {p.Label} ({p.Id}) | {p.Owner} | {p.BlastRadius} | {p.Reversibility} | {string.Join(", ", p.RelatedServiceNames)} |");
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

    public string ToJson(ServiceTamperingReport report)
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
        var p = path.ToLowerInvariant();
        // Strip surrounding quotes and any trailing arguments.
        if (p.StartsWith("\"") && p.IndexOf('"', 1) is int end && end > 0)
        {
            p = p.Substring(1, end - 1);
        }
        string[] needles =
        {
            @"\temp\",
            @"\tmp\",
            @"\appdata\local\temp",
            @"\users\public\",
            @"\programdata\public\",
            @"\downloads\",
            @"\$recycle.bin\",
            @"\windows\temp\",
        };
        foreach (var n in needles)
        {
            if (p.Contains(n)) return true;
        }
        return false;
    }

    private static bool IsStartupDowngrade(ServiceStartupType expected, ServiceStartupType current)
    {
        if (current == ServiceStartupType.Disabled) return false; // handled separately
        // Auto/AutoDelayed -> Manual is a downgrade.
        bool expectedAuto = expected == ServiceStartupType.Auto || expected == ServiceStartupType.AutoDelayed;
        return expectedAuto && current == ServiceStartupType.Manual;
    }

    private static readonly HashSet<string> KnownTrustedChangers = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM",
        "NT AUTHORITY\\SYSTEM",
        "TrustedInstaller",
        "NT SERVICE\\TrustedInstaller",
        "Administrator",
        "BUILTIN\\Administrators",
    };

    private static bool IsUnauthorizedChanger(string? changedBy)
    {
        if (string.IsNullOrWhiteSpace(changedBy)) return false;
        if (KnownTrustedChangers.Contains(changedBy)) return false;
        // Anyone else (including unknown user accounts) is treated as unauthorized.
        return true;
    }

    private List<PlaybookAction> BuildPlaybook(
        RiskAppetite risk,
        string grade,
        List<string> stoppedCritical,
        List<string> disabledCritical,
        List<string> tamperproofViolations,
        List<string> suspiciousBinaries,
        List<string> unknownBinaries,
        List<string> aclWeakened,
        List<string> startupDowngraded,
        List<string> unauthorizedChanges,
        List<string> unknownChanger,
        List<string> recoveryRemoved,
        int total)
    {
        var actions = new List<PlaybookAction>();

        // P0 actions
        if (tamperproofViolations.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "RESTORE_SECURITY_SERVICE_INTEGRITY",
                Priority: ActionPriority.P0,
                Label: "Restore tamperproof security service to expected state",
                Owner: "incident_response",
                BlastRadius: 5,
                Reversibility: "low",
                Reason: "A tamperproof security-critical service (e.g., AV / EDR) has drifted from its expected configuration — treat as active intrusion until proven otherwise.",
                RelatedServiceNames: tamperproofViolations.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }
        if (suspiciousBinaries.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "QUARANTINE_SUSPICIOUS_BINARY",
                Priority: ActionPriority.P0,
                Label: "Quarantine service binaries running from user-writable paths",
                Owner: "incident_response",
                BlastRadius: 4,
                Reversibility: "medium",
                Reason: "Service binary lives under a user-writable location (Temp / AppData / Public). Classic persistence pattern; isolate the host and forensically capture the binary before deletion.",
                RelatedServiceNames: suspiciousBinaries.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }
        if (disabledCritical.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "RE_ENABLE_DISABLED_CRITICAL",
                Priority: ActionPriority.P0,
                Label: "Re-enable disabled critical services and start them",
                Owner: "security_ops",
                BlastRadius: 3,
                Reversibility: "high",
                Reason: "Critical Windows services are set to Disabled. Restore expected startup type and start the service.",
                RelatedServiceNames: disabledCritical.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }
        if (stoppedCritical.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "RESTART_CRITICAL_SERVICES",
                Priority: ActionPriority.P0,
                Label: "Restart stopped critical services",
                Owner: "security_ops",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Critical services are stopped though expected to be running. Restart and confirm no auto-stop loop is in effect.",
                RelatedServiceNames: stoppedCritical.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }
        if (unknownBinaries.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "REVALIDATE_BINARY_PATH",
                Priority: ActionPriority.P0,
                Label: "Re-validate service binary hash against known-good baseline",
                Owner: "security_ops",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Service binary hash is unknown / not in baseline. Re-baseline if the binary is legitimate, otherwise treat as tampering.",
                RelatedServiceNames: unknownBinaries.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        // P1 actions
        if (aclWeakened.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "RESTORE_ACL_DEFAULTS",
                Priority: ActionPriority.P1,
                Label: "Restore default ACLs on tampered service entries",
                Owner: "security_ops",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Service ACL was weakened — non-admins may be able to reconfigure or restart the service. Reset to default SDDL.",
                RelatedServiceNames: aclWeakened.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }
        if (unauthorizedChanges.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "INVESTIGATE_UNAUTHORIZED_CHANGE",
                Priority: ActionPriority.P1,
                Label: "Investigate recent unauthorized service configuration changes",
                Owner: "incident_response",
                BlastRadius: 3,
                Reversibility: "medium",
                Reason: "Recent service changes were made by an account outside the trusted-changer set. Audit the account, recent process tree, and login history.",
                RelatedServiceNames: unauthorizedChanges.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }
        if (startupDowngraded.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "RESTORE_AUTOSTART",
                Priority: ActionPriority.P1,
                Label: "Restore Auto startup type on downgraded services",
                Owner: "security_ops",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Services expected to be Auto-start are now Manual; they may silently fail to launch after reboot.",
                RelatedServiceNames: startupDowngraded.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        // P2 actions
        if (recoveryRemoved.Count > 0)
        {
            actions.Add(new PlaybookAction(
                Id: "RESTORE_RECOVERY_ACTIONS",
                Priority: ActionPriority.P2,
                Label: "Re-add recovery actions for critical services",
                Owner: "security_ops",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: "Critical service has zero recovery actions configured — failures won't auto-restart. Add Restart on first/second failure.",
                RelatedServiceNames: recoveryRemoved.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }
        if (unknownChanger.Count >= 2)
        {
            actions.Add(new PlaybookAction(
                Id: "AUDIT_RECENT_CHANGES",
                Priority: ActionPriority.P2,
                Label: "Audit recent service changes with unknown attribution",
                Owner: "security_ops",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: "Multiple recent service changes have no recorded actor. Enable Service Control Manager auditing (Event ID 7040/4697).",
                RelatedServiceNames: unknownChanger.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        // Cautious appends a scheduled audit when grade is C or worse.
        if (risk == RiskAppetite.Cautious && (grade == "C" || grade == "D" || grade == "F"))
        {
            if (!actions.Any(a => a.Id == "SCHEDULE_SERVICE_AUDIT"))
            {
                actions.Add(new PlaybookAction(
                    Id: "SCHEDULE_SERVICE_AUDIT",
                    Priority: ActionPriority.P2,
                    Label: "Schedule a full service-control audit",
                    Owner: "security_lead",
                    BlastRadius: 1,
                    Reversibility: "high",
                    Reason: "Cautious risk appetite + degraded grade — schedule a follow-up audit to make sure nothing regressed.",
                    RelatedServiceNames: Array.Empty<string>()));
            }
        }

        // P3 fallback
        if (actions.Count == 0)
        {
            actions.Add(new PlaybookAction(
                Id: "ALL_SERVICES_HEALTHY",
                Priority: ActionPriority.P3,
                Label: "All monitored services look healthy",
                Owner: "security_ops",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: total == 0
                    ? "No services were supplied to analyze."
                    : "No tampering signals detected across the supplied service snapshots.",
                RelatedServiceNames: Array.Empty<string>()));
        }

        // Aggressive trims the healthy fallback when other actions exist (it does nothing here)
        // and trims lone P2 actions when P0/P1 exist.
        if (risk == RiskAppetite.Aggressive)
        {
            bool anyP0P1 = actions.Any(a => a.Priority == ActionPriority.P0 || a.Priority == ActionPriority.P1);
            if (anyP0P1)
            {
                actions = actions.Where(a => a.Priority != ActionPriority.P2 || a.Id == "RESTORE_RECOVERY_ACTIONS")
                                 .ToList();
            }
        }

        // Deterministic order: priority asc, then id asc.
        actions.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            return string.CompareOrdinal(a.Id, b.Id);
        });

        return actions;
    }
}
