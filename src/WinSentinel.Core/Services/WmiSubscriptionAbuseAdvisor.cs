using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic Windows WMI Event Subscription abuse advisor.
/// <para>
/// Scores per-subscription snapshots (event filter + consumer + binding triple)
/// for signs of persistence abuse — the classic MITRE ATT&amp;CK T1546.003 vector.
/// Detects ActiveScript / CommandLine consumers, LOLBin payloads, encoded
/// PowerShell, suspicious WQL polling intervals, non-default namespaces,
/// recently registered bindings by non-trusted principals, weak ACLs, and
/// stale high-privilege subscriptions.
/// </para>
/// <para>
/// Ninth sibling in the agentic services suite alongside
/// <see cref="ScheduledTaskAbuseAdvisor"/> and <see cref="ServiceTamperingAdvisor"/>
/// — focusing on the WMI persistence surface rather than scheduled tasks or
/// Windows services. Answers <em>which WMI event subscriptions look abused,
/// and what should we do first?</em>
/// </para>
/// <para>
/// Pure / deterministic — no I/O, no WMI queries. Caller passes subscription
/// snapshots gathered by their own collector (Get-WmiObject -Namespace
/// root\subscription, autoruns, or similar). Inject time via
/// <see cref="AdvisorContext.NowOverride"/> for reproducible tests. Never
/// mutates inputs.
/// </para>
/// </summary>
public class WmiSubscriptionAbuseAdvisor
{
    // ── Public model ─────────────────────────────────────────────

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ConsumerType
    {
        ActiveScript,
        CommandLine,
        LogFile,
        Smtp,
        NtEventLog,
        Unknown,
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum SubscriptionPrincipal
    {
        System,
        LocalService,
        NetworkService,
        Administrators,
        User,
        Unknown,
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum SubscriptionVerdict
    {
        QuarantineAndDelete,
        RestrictAndReview,
        MonitorAndReview,
        Healthy,
    }

    /// <summary>A snapshot of one WMI permanent event subscription (filter + consumer + binding).</summary>
    public record WmiSubscriptionSnapshot(
        string FilterName,
        string ConsumerName,
        ConsumerType ConsumerKind,
        SubscriptionPrincipal Principal,
        string Namespace,
        string? QueryLanguage,
        string? Query,
        string? ConsumerCommandLine,
        string? ConsumerScriptText,
        bool BinaryHashKnown,
        bool BinarySignatureValid,
        bool AclWeakened,
        bool BuiltInSubscription,
        bool Enabled,
        DateTime? RegisteredAt,
        DateTime? LastTriggeredAt,
        string? RegisteredBy);

    public class AdvisorContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;
        public DateTime? NowOverride { get; set; }

        /// <summary>Window (hours) within which a recent registration is considered fresh.</summary>
        public int RecentRegistrationHours { get; set; } = 72;

        /// <summary>Subscriptions not triggered within this many days are stale.</summary>
        public int StaleDays { get; set; } = 180;

        /// <summary>WQL WITHIN interval (seconds) below which polling looks unusually tight.</summary>
        public int TightPollingThresholdSeconds { get; set; } = 60;
    }

    public record SubscriptionAssessment(
        string FilterName,
        string ConsumerName,
        ConsumerType ConsumerKind,
        SubscriptionPrincipal Principal,
        int RiskScore,
        SubscriptionVerdict Verdict,
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
        IReadOnlyList<string> RelatedSubscriptionIds);

    public record WmiSubscriptionAbuseReport(
        DateTime GeneratedAt,
        int TotalSubscriptions,
        int QuarantineCount,
        int RestrictCount,
        int MonitorCount,
        double MeanRiskScore,
        double MaxRiskScore,
        string Verdict,
        string Grade,
        IReadOnlyList<SubscriptionAssessment> Assessments,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights);

    // ── Public API ───────────────────────────────────────────────

    public WmiSubscriptionAbuseReport Analyze(
        IEnumerable<WmiSubscriptionSnapshot> subscriptions,
        AdvisorContext? ctx = null)
    {
        if (subscriptions is null) throw new ArgumentNullException(nameof(subscriptions));
        ctx ??= new AdvisorContext();
        var list = subscriptions.ToList();
        var now = ctx.NowOverride ?? DateTime.UtcNow;
        double sevMult = ctx.Risk switch
        {
            RiskAppetite.Cautious => 1.15,
            RiskAppetite.Aggressive => 0.85,
            _ => 1.0,
        };
        int recentWindow = Math.Max(1, ctx.RecentRegistrationHours);
        int staleDays = Math.Max(1, ctx.StaleDays);
        int tightPollSecs = Math.Max(1, ctx.TightPollingThresholdSeconds);

        var assessments = new List<SubscriptionAssessment>();

        var scriptConsumers = new List<string>();
        var lolbinConsumers = new List<string>();
        var suspiciousScripts = new List<string>();
        var unsignedBinaries = new List<string>();
        var unknownBinaries = new List<string>();
        var tightPolling = new List<string>();
        var nonDefaultNamespace = new List<string>();
        var aclWeakened = new List<string>();
        var unauthorizedRegistrations = new List<string>();
        var unknownRegistrar = new List<string>();
        var staleHighPriv = new List<string>();

        bool forceF = false;

        foreach (var s in list)
        {
            var reasons = new List<string>();
            var sevHits = new List<int>();
            string subId = $"{s.Namespace}::{s.FilterName}->{s.ConsumerName}";

            bool isHighPriv = s.Principal == SubscriptionPrincipal.System
                              || s.Principal == SubscriptionPrincipal.Administrators
                              || s.Principal == SubscriptionPrincipal.LocalService
                              || s.Principal == SubscriptionPrincipal.NetworkService;

            // ACTIVE_SCRIPT_CONSUMER — ActiveScriptEventConsumer is the textbook
            // WMI-persistence vector (Stuxnet, APT29). Treat as P0.
            if (s.ConsumerKind == ConsumerType.ActiveScript && !s.BuiltInSubscription)
            {
                sevHits.Add(isHighPriv ? 90 : 70);
                reasons.Add("ACTIVE_SCRIPT_CONSUMER");
                scriptConsumers.Add(subId);
                forceF = true;
            }

            // LOLBIN_CONSUMER — CommandLineEventConsumer that launches a LOLBin
            // with payload arguments.
            if (s.ConsumerKind == ConsumerType.CommandLine
                && IsLolbinLauncher(s.ConsumerCommandLine))
            {
                sevHits.Add(isHighPriv ? 85 : 60);
                reasons.Add("LOLBIN_CONSUMER");
                lolbinConsumers.Add(subId);
                forceF = true;
            }

            // SUSPICIOUS_SCRIPT_CONTENT — ActiveScript / inline script with
            // base64, http, downloadstring, iex, frombase64string indicators.
            if (!string.IsNullOrWhiteSpace(s.ConsumerScriptText)
                && IsSuspiciousScript(s.ConsumerScriptText))
            {
                sevHits.Add(isHighPriv ? 80 : 55);
                reasons.Add("SUSPICIOUS_SCRIPT_CONTENT");
                suspiciousScripts.Add(subId);
                forceF = true;
            }

            // UNKNOWN_BINARY — hash isn't in our trust database.
            if (!s.BinaryHashKnown && !string.IsNullOrWhiteSpace(s.ConsumerCommandLine))
            {
                sevHits.Add(isHighPriv ? 50 : 30);
                reasons.Add("UNKNOWN_BINARY");
                unknownBinaries.Add(subId);
            }

            // UNSIGNED_BINARY
            if (!s.BinarySignatureValid && !string.IsNullOrWhiteSpace(s.ConsumerCommandLine))
            {
                sevHits.Add(isHighPriv ? 55 : 35);
                reasons.Add("UNSIGNED_BINARY");
                unsignedBinaries.Add(subId);
            }

            // TIGHT_POLLING_INTERVAL — WQL WITHIN N where N is very small means
            // the subscription is firing constantly; classic for fast attacker
            // foothold or telemetry beacons.
            if (TryExtractWithinSeconds(s.Query, out int withinSecs)
                && withinSecs > 0 && withinSecs < tightPollSecs)
            {
                sevHits.Add(35);
                reasons.Add("TIGHT_POLLING_INTERVAL");
                tightPolling.Add(subId);
            }

            // NON_DEFAULT_NAMESPACE — WMI subscriptions outside the well-known
            // root\subscription and root\default namespaces are unusual.
            if (!IsDefaultNamespace(s.Namespace) && !s.BuiltInSubscription)
            {
                sevHits.Add(40);
                reasons.Add("NON_DEFAULT_NAMESPACE");
                nonDefaultNamespace.Add(subId);
            }

            // ACL_WEAKENED
            if (s.AclWeakened)
            {
                sevHits.Add(isHighPriv ? 55 : 35);
                reasons.Add("ACL_WEAKENED");
                aclWeakened.Add(subId);
            }

            // RECENT_UNAUTHORIZED_REGISTRATION
            bool registeredRecently = s.RegisteredAt.HasValue
                && (now - s.RegisteredAt.Value).TotalHours <= recentWindow
                && (now - s.RegisteredAt.Value).TotalHours >= 0;
            if (registeredRecently && IsUnauthorizedPrincipal(s.RegisteredBy))
            {
                sevHits.Add(isHighPriv ? 65 : 45);
                reasons.Add("RECENT_UNAUTHORIZED_REGISTRATION");
                unauthorizedRegistrations.Add(subId);
            }

            // UNKNOWN_REGISTRAR
            if (registeredRecently && string.IsNullOrWhiteSpace(s.RegisteredBy))
            {
                sevHits.Add(25);
                if (!reasons.Contains("RECENT_UNAUTHORIZED_REGISTRATION"))
                    reasons.Add("UNKNOWN_REGISTRAR");
                unknownRegistrar.Add(subId);
            }

            // STALE_HIGH_PRIVILEGE
            bool isStale = s.LastTriggeredAt.HasValue
                && (now - s.LastTriggeredAt.Value).TotalDays >= staleDays;
            if (isStale && isHighPriv && !s.BuiltInSubscription)
            {
                sevHits.Add(30);
                reasons.Add("STALE_HIGH_PRIVILEGE");
                staleHighPriv.Add(subId);
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

            SubscriptionVerdict verdict;
            ActionPriority priority;
            if (risk >= 75)
            {
                verdict = SubscriptionVerdict.QuarantineAndDelete;
                priority = ActionPriority.P0;
            }
            else if (risk >= 50)
            {
                verdict = SubscriptionVerdict.RestrictAndReview;
                priority = ActionPriority.P1;
            }
            else if (risk >= 25)
            {
                verdict = SubscriptionVerdict.MonitorAndReview;
                priority = ActionPriority.P2;
            }
            else
            {
                verdict = SubscriptionVerdict.Healthy;
                priority = ActionPriority.P3;
            }

            assessments.Add(new SubscriptionAssessment(
                s.FilterName,
                s.ConsumerName,
                s.ConsumerKind,
                s.Principal,
                risk,
                verdict,
                priority,
                reasons));
        }

        assessments.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            int r = b.RiskScore.CompareTo(a.RiskScore);
            if (r != 0) return r;
            return string.CompareOrdinal(a.FilterName + "->" + a.ConsumerName,
                                          b.FilterName + "->" + b.ConsumerName);
        });

        int total = list.Count;
        int qCount = assessments.Count(a => a.Verdict == SubscriptionVerdict.QuarantineAndDelete);
        int rCount = assessments.Count(a => a.Verdict == SubscriptionVerdict.RestrictAndReview);
        int mCount = assessments.Count(a => a.Verdict == SubscriptionVerdict.MonitorAndReview);
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
            verdictStr = "WMI_PERSISTENCE_ABUSE_SUSPECTED";
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
            scriptConsumers,
            lolbinConsumers,
            suspiciousScripts,
            unsignedBinaries,
            unknownBinaries,
            tightPolling,
            nonDefaultNamespace,
            aclWeakened,
            unauthorizedRegistrations,
            unknownRegistrar,
            staleHighPriv,
            total);

        var insights = new List<string>();
        if (scriptConsumers.Count > 0)
            insights.Add($"ACTIVE_SCRIPT_CONSUMERS:{scriptConsumers.Count}");
        if (lolbinConsumers.Count > 0)
            insights.Add($"LOLBIN_PERSISTENCE_VECTOR:{lolbinConsumers.Count}");
        if (suspiciousScripts.Count > 0)
            insights.Add($"OBFUSCATED_SCRIPT_PAYLOADS:{suspiciousScripts.Count}");
        if (nonDefaultNamespace.Count >= 1)
            insights.Add($"UNUSUAL_NAMESPACE_SUBSCRIPTIONS:{nonDefaultNamespace.Count}");
        if (unauthorizedRegistrations.Count >= 2)
            insights.Add($"UNAUTHORIZED_REGISTRATION_CLUSTER:{unauthorizedRegistrations.Count}");
        if (tightPolling.Count >= 2)
            insights.Add($"TIGHT_POLLING_CLUSTER:{tightPolling.Count}");
        if (aclWeakened.Count >= 2)
            insights.Add($"WIDESPREAD_ACL_WEAKENING:{aclWeakened.Count}");
        if (staleHighPriv.Count >= 3)
            insights.Add($"STALE_HIGH_PRIVILEGE_BACKLOG:{staleHighPriv.Count}");
        if (total > 0 && qCount == 0 && rCount == 0 && mCount == 0)
            insights.Add("ALL_SUBSCRIPTIONS_HEALTHY");

        return new WmiSubscriptionAbuseReport(
            GeneratedAt: now,
            TotalSubscriptions: total,
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

    public string ToMarkdown(WmiSubscriptionAbuseReport report)
    {
        if (report is null) throw new ArgumentNullException(nameof(report));
        var sb = new StringBuilder();
        sb.AppendLine("# WMI Event Subscription Abuse Report");
        sb.AppendLine();
        sb.AppendLine($"- Generated: {report.GeneratedAt:O}");
        sb.AppendLine($"- Total subscriptions: {report.TotalSubscriptions}");
        sb.AppendLine($"- Quarantine: {report.QuarantineCount} | Restrict: {report.RestrictCount} | Monitor: {report.MonitorCount}");
        sb.AppendLine($"- Mean risk: {report.MeanRiskScore:F2} | Max risk: {report.MaxRiskScore:F2}");
        sb.AppendLine($"- Verdict: **{report.Verdict}** | Grade: **{report.Grade}**");
        sb.AppendLine();

        sb.AppendLine("## Subscriptions");
        if (report.Assessments.Count == 0)
        {
            sb.AppendLine("_(no subscriptions analyzed)_");
        }
        else
        {
            sb.AppendLine("| Filter | Consumer | Kind | Principal | Risk | Verdict | Priority | Reasons |");
            sb.AppendLine("|---|---|---|---|---:|---|---|---|");
            foreach (var a in report.Assessments)
            {
                sb.AppendLine($"| {a.FilterName} | {a.ConsumerName} | {a.ConsumerKind} | {a.Principal} | {a.RiskScore} | {a.Verdict} | {a.Priority} | {string.Join(", ", a.Reasons)} |");
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
            sb.AppendLine("| Priority | Action | Owner | Blast | Reversibility | Subscriptions |");
            sb.AppendLine("|---|---|---|---:|---|---|");
            foreach (var p in report.Playbook)
            {
                sb.AppendLine($"| {p.Priority} | {p.Label} ({p.Id}) | {p.Owner} | {p.BlastRadius} | {p.Reversibility} | {string.Join(", ", p.RelatedSubscriptionIds)} |");
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

    public string ToJson(WmiSubscriptionAbuseReport report)
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

    private static bool IsLolbinLauncher(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        var c = commandLine.ToLowerInvariant().Trim();
        bool hasLolbin = LolbinNames.Any(n => c.Contains("\\" + n) || c.StartsWith(n + " ") || c == n || c.Contains("/" + n));
        if (!hasLolbin) return false;
        string[] payloadHints =
        {
            "-enc",
            "-encodedcommand",
            "-nop",
            "-noprofile",
            "-windowstyle",
            "-w hidden",
            "/c ",
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
        return payloadHints.Any(c.Contains);
    }

    private static bool IsSuspiciousScript(string scriptText)
    {
        var s = scriptText.ToLowerInvariant();
        string[] needles =
        {
            "frombase64string",
            "downloadstring",
            "downloadfile",
            "invoke-expression",
            "iex(",
            "iex (",
            "http://",
            "https://",
            "wscript.shell",
            "shell.application",
            "winmgmts:",
            "createobject(\"wscript",
            "createobject(\"scripting",
            "-encodedcommand",
            "-enc ",
            "powershell.exe",
        };
        return needles.Any(s.Contains);
    }

    private static bool TryExtractWithinSeconds(string? wql, out int seconds)
    {
        seconds = 0;
        if (string.IsNullOrWhiteSpace(wql)) return false;
        // Match: ... WITHIN <number> ... (case-insensitive)
        var lower = wql.ToLowerInvariant();
        int idx = lower.IndexOf("within", StringComparison.Ordinal);
        if (idx < 0) return false;
        int i = idx + "within".Length;
        while (i < lower.Length && char.IsWhiteSpace(lower[i])) i++;
        int start = i;
        while (i < lower.Length && (char.IsDigit(lower[i]) || lower[i] == '.')) i++;
        if (i == start) return false;
        var num = lower.Substring(start, i - start);
        if (!double.TryParse(num, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out double v))
            return false;
        seconds = (int)Math.Round(v);
        return true;
    }

    private static bool IsDefaultNamespace(string? ns)
    {
        if (string.IsNullOrWhiteSpace(ns)) return true; // be conservative; only flag if caller explicitly set non-default
        var n = ns.Trim().ToLowerInvariant().Replace('/', '\\');
        return n == "root\\subscription" || n == "root\\default" || n == "root\\cimv2";
    }

    private static bool IsUnauthorizedPrincipal(string? changedBy)
    {
        if (string.IsNullOrWhiteSpace(changedBy)) return false;
        var c = changedBy.ToLowerInvariant();
        string[] trusted =
        {
            "nt authority\\system",
            "nt service\\trustedinstaller",
            "builtin\\administrators",
            "nt authority\\local service",
            "nt authority\\network service",
        };
        if (trusted.Any(t => c.Contains(t))) return false;
        return true;
    }

    private static List<PlaybookAction> BuildPlaybook(
        RiskAppetite risk,
        string grade,
        List<string> scriptConsumers,
        List<string> lolbinConsumers,
        List<string> suspiciousScripts,
        List<string> unsignedBinaries,
        List<string> unknownBinaries,
        List<string> tightPolling,
        List<string> nonDefaultNamespace,
        List<string> aclWeakened,
        List<string> unauthorizedRegistrations,
        List<string> unknownRegistrar,
        List<string> staleHighPriv,
        int total)
    {
        var actions = new List<PlaybookAction>();

        if (scriptConsumers.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "QUARANTINE_ACTIVE_SCRIPT_CONSUMERS",
                ActionPriority.P0,
                "Quarantine ActiveScriptEventConsumer subscriptions",
                "incident_response",
                BlastRadius: 5,
                Reversibility: "low",
                Reason: "ActiveScriptEventConsumer is the textbook WMI persistence vector (MITRE T1546.003). Treat as compromise until proven benign.",
                RelatedSubscriptionIds: scriptConsumers.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (lolbinConsumers.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "DISABLE_LOLBIN_CONSUMERS",
                ActionPriority.P0,
                "Disable and dump LOLBin-launching CommandLineEventConsumer subscriptions",
                "incident_response",
                BlastRadius: 4,
                Reversibility: "medium",
                Reason: "CommandLineEventConsumers running powershell/mshta/regsvr32 with payload arguments are a known persistence vector.",
                RelatedSubscriptionIds: lolbinConsumers.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (suspiciousScripts.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "EXTRACT_AND_REVERSE_SCRIPT_PAYLOADS",
                ActionPriority.P0,
                "Extract and reverse obfuscated WMI consumer script payloads",
                "incident_response",
                BlastRadius: 3,
                Reversibility: "medium",
                Reason: "Inline scripts referencing base64 / DownloadString / IEX / FromBase64String are almost always staging payloads.",
                RelatedSubscriptionIds: suspiciousScripts.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unauthorizedRegistrations.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "REVIEW_RECENT_UNAUTHORIZED_REGISTRATIONS",
                ActionPriority.P0,
                "Review recent WMI subscription registrations by non-trusted principals",
                "incident_response",
                BlastRadius: 3,
                Reversibility: "medium",
                Reason: "Recent subscription registrations not attributed to SYSTEM / TrustedInstaller / Administrators warrant review.",
                RelatedSubscriptionIds: unauthorizedRegistrations.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (nonDefaultNamespace.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "INVESTIGATE_UNUSUAL_NAMESPACES",
                ActionPriority.P1,
                "Investigate WMI subscriptions outside default namespaces",
                "incident_response",
                BlastRadius: 3,
                Reversibility: "medium",
                Reason: "Subscriptions outside root\\subscription / root\\default / root\\cimv2 are unusual and used to hide from defenders.",
                RelatedSubscriptionIds: nonDefaultNamespace.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unsignedBinaries.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "REQUIRE_SIGNED_CONSUMER_BINARIES",
                ActionPriority.P1,
                "Replace unsigned consumer binaries with signed builds",
                "platform_admin",
                BlastRadius: 3,
                Reversibility: "high",
                Reason: "Unsigned consumer payloads cannot be attested and bypass code-signing posture checks.",
                RelatedSubscriptionIds: unsignedBinaries.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (aclWeakened.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "RESTORE_SUBSCRIPTION_ACLS",
                ActionPriority.P1,
                "Restore weakened WMI namespace / subscription ACLs to baseline",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Weakened ACLs let lower-privilege users register new subscriptions and pivot to SYSTEM.",
                RelatedSubscriptionIds: aclWeakened.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (tightPolling.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "TUNE_TIGHT_POLLING",
                ActionPriority.P2,
                "Investigate or relax tight WQL polling intervals",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Sub-minute WITHIN intervals burn CPU and are characteristic of beacon-style subscriptions.",
                RelatedSubscriptionIds: tightPolling.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unknownBinaries.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "HASH_AND_VERIFY_UNKNOWN_BINARIES",
                ActionPriority.P2,
                "Hash and verify WMI consumer binaries missing from the trust database",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Unknown payloads should be hashed and either added to the allow-list or removed.",
                RelatedSubscriptionIds: unknownBinaries.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (unknownRegistrar.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "ATTRIBUTE_UNKNOWN_REGISTRATIONS",
                ActionPriority.P2,
                "Attribute recent subscription registrations missing a creator principal",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: "Recent registrations with no creator attribution are a telemetry gap worth closing.",
                RelatedSubscriptionIds: unknownRegistrar.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        if (staleHighPriv.Count > 0)
        {
            actions.Add(new PlaybookAction(
                "RETIRE_STALE_PRIVILEGED_SUBSCRIPTIONS",
                ActionPriority.P2,
                "Retire stale privileged WMI subscriptions that haven't triggered in a long time",
                "platform_admin",
                BlastRadius: 2,
                Reversibility: "high",
                Reason: "Stale privileged subscriptions expand the persistence surface area with no operational benefit.",
                RelatedSubscriptionIds: staleHighPriv.OrderBy(x => x, StringComparer.Ordinal).ToList()));
        }

        // Cautious adds a calibration sweep when grade is poor.
        if (risk == RiskAppetite.Cautious && (grade == "C" || grade == "D" || grade == "F"))
        {
            actions.Add(new PlaybookAction(
                "SCHEDULE_WMI_SUBSCRIPTION_AUDIT",
                ActionPriority.P2,
                "Schedule a full WMI subscription inventory audit",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: "Grade indicates posture drift; a planned sweep catches what we missed.",
                RelatedSubscriptionIds: new List<string>()));
        }

        if (actions.Count == 0)
        {
            actions.Add(new PlaybookAction(
                "ALL_SUBSCRIPTIONS_HEALTHY",
                ActionPriority.P3,
                "Maintain WMI subscription monitoring",
                "platform_admin",
                BlastRadius: 1,
                Reversibility: "high",
                Reason: total == 0
                    ? "No subscriptions were provided; keep the collector running."
                    : "No abuse indicators detected; continue routine monitoring.",
                RelatedSubscriptionIds: new List<string>()));
        }

        if (risk == RiskAppetite.Aggressive && actions.Count > 1)
        {
            actions = actions.Where(a => a.Priority != ActionPriority.P3).ToList();
        }

        actions.Sort((a, b) =>
        {
            int p = ((int)a.Priority).CompareTo((int)b.Priority);
            if (p != 0) return p;
            return string.CompareOrdinal(a.Id, b.Id);
        });
        return actions;
    }
}
