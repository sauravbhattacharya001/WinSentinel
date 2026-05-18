using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic posture regression explainer.
/// <para>
/// Compares two <see cref="PostureSnapshot"/>s (previous + current) and a
/// <see cref="RegressionContext"/> of recent config changes + fix rollbacks,
/// then emits a ranked, structured <see cref="PostureRegressionReport"/>:
/// per-signal classification with severity / priority / owner / reversibility,
/// a deduped P0-first remediation playbook, cross-category insights, an
/// overall verdict band (IMPROVING / STABLE / REGRESSING / DEGRADED /
/// COLLAPSING) and an A-F grade.
/// </para>
/// <para>
/// Sibling to <see cref="FixOrchestrationPlanner"/> (sequences fixes),
/// <see cref="AlertRoutingAdvisor"/> (routes alerts) and
/// <see cref="AttackerProfileSynthesizer"/> (identifies attackers). This
/// advisor answers <em>why did our security posture get worse since last
/// scan and what should we hunt first?</em>
/// </para>
/// <para>Pure / deterministic - no I/O. Time can be pinned via
/// <see cref="RegressionContext.NowOverride"/> for reproducible tests.
/// Never mutates input snapshots.</para>
/// </summary>
public class PostureRegressionExplainer
{
    // ── Public model ─────────────────────────────────────────────

    /// <summary>Severity of an individual finding.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum FindingSeverity { Low, Medium, High, Critical }

    /// <summary>Overall trend verdict.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RegressionVerdict { Improving, Stable, Regressing, Degraded, Collapsing }

    /// <summary>How aggressively the advisor recommends action.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    /// <summary>Signal / action priority bucket.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    /// <summary>Minimal projection of a finding used for delta analysis.</summary>
    public record FindingSummary(
        string Id,
        string Category,
        FindingSeverity Severity,
        string Title,
        bool IsNew = false,
        bool IsResolved = false,
        bool IsPersistent = false);

    /// <summary>Snapshot of posture at a point in time.</summary>
    public record PostureSnapshot(
        DateTime Timestamp,
        int OverallScore,
        IReadOnlyDictionary<string, int> CategoryScores,
        IReadOnlyList<FindingSummary> Findings);

    /// <summary>A configuration change event from the change log.</summary>
    public record ConfigChange(DateTime Time, string Component, string Description);

    /// <summary>A fix rollback / revert event.</summary>
    public record FixRollback(DateTime Time, string FixId, string Description);

    /// <summary>Caller-supplied context for the explainer.</summary>
    public class RegressionContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;
        public DateTime? NowOverride { get; set; }
        public List<ConfigChange> RecentConfigChanges { get; set; } = new();
        public List<FixRollback> RecentFixRollbacks { get; set; } = new();
    }

    /// <summary>A classified regression signal.</summary>
    public record RegressionSignal(
        string Code,
        int Severity,
        ActionPriority Priority,
        string Headline,
        string Reason,
        string Owner,
        int BlastRadius,
        string Reversibility,
        IReadOnlyList<string> EvidenceFindingIds,
        string? RootCauseHint);

    /// <summary>A playbook action recommendation.</summary>
    public record PlaybookAction(
        string Id,
        ActionPriority Priority,
        string Label,
        string Owner,
        int BlastRadius,
        string Reversibility,
        string Reason,
        IReadOnlyList<string> RelatedSignalCodes);

    /// <summary>Full report returned to the caller.</summary>
    public record PostureRegressionReport(
        DateTime GeneratedAt,
        int PreviousScore,
        int CurrentScore,
        int TotalDelta,
        IReadOnlyDictionary<string, int> CategoryDeltas,
        RegressionVerdict Verdict,
        string Grade,
        IReadOnlyList<RegressionSignal> Signals,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights);

    // ── Public API ───────────────────────────────────────────────

    public PostureRegressionReport Explain(
        PostureSnapshot previous,
        PostureSnapshot current,
        RegressionContext? ctx = null)
    {
        if (previous is null) throw new ArgumentNullException(nameof(previous));
        if (current is null) throw new ArgumentNullException(nameof(current));
        ctx ??= new RegressionContext();
        var now = ctx.NowOverride ?? current.Timestamp;

        // Defensive snapshot copies so we never mutate inputs.
        var prevFindings = previous.Findings.ToList();
        var curFindings = current.Findings.ToList();
        var prevCats = new Dictionary<string, int>(previous.CategoryScores);
        var curCats = new Dictionary<string, int>(current.CategoryScores);

        int totalDelta = current.OverallScore - previous.OverallScore;
        var categoryDeltas = new SortedDictionary<string, int>();
        foreach (var k in prevCats.Keys.Union(curCats.Keys))
            categoryDeltas[k] = curCats.GetValueOrDefault(k) - prevCats.GetValueOrDefault(k);

        int sevShift = ctx.Risk switch
        {
            RiskAppetite.Cautious => +5,
            RiskAppetite.Aggressive => -5,
            _ => 0,
        };

        var signals = new List<RegressionSignal>();

        // NEW_CRITICAL_FINDING
        var newCrit = curFindings.Where(f => f.IsNew &&
            (f.Severity == FindingSeverity.Critical || f.Severity == FindingSeverity.High)).ToList();
        if (newCrit.Count > 0)
        {
            int sev = Clamp(70 + 5 * newCrit.Count + sevShift);
            var hint = MatchHint(ctx, now, newCrit.Select(n => n.Title).Concat(newCrit.Select(n => n.Id)));
            signals.Add(new RegressionSignal(
                "NEW_CRITICAL_FINDING", sev, BucketP(sev),
                $"{newCrit.Count} new high/critical finding(s)",
                $"New high-severity findings appeared since last snapshot ({string.Join(", ", newCrit.Take(3).Select(f => f.Title))}).",
                "security_eng", 4, "medium",
                newCrit.Select(f => f.Id).ToList(), hint));
        }

        // FIX_ROLLBACK_SUSPECTED
        var rollbacks = ctx.RecentFixRollbacks
            .Where(r => (now - r.Time).TotalDays <= 7 && r.Time <= now)
            .ToList();
        if (rollbacks.Count > 0 && (totalDelta < 0 || newCrit.Count > 0))
        {
            // Try to bind rollback to a finding whose id/title mentions the fix id
            var bound = curFindings.Where(f => f.IsNew && rollbacks.Any(r =>
                f.Title.Contains(r.FixId, StringComparison.OrdinalIgnoreCase) ||
                f.Id.Contains(r.FixId, StringComparison.OrdinalIgnoreCase) ||
                r.Description.Contains(f.Category, StringComparison.OrdinalIgnoreCase))).ToList();
            int sev = Clamp(80 + sevShift);
            var hint = $"Rollback of {rollbacks[0].FixId} at {rollbacks[0].Time:O} (\"{rollbacks[0].Description}\")";
            signals.Add(new RegressionSignal(
                "FIX_ROLLBACK_SUSPECTED", sev, ActionPriority.P0,
                "Recent fix rollback likely caused regression",
                $"{rollbacks.Count} rollback(s) within 7d; posture moved by {totalDelta}.",
                "security_eng", 3, "medium",
                bound.Select(f => f.Id).ToList(), hint));
        }

        // CONTROL_DECAY (per category dropped >=10) - emit one consolidated signal
        var decayCats = categoryDeltas.Where(kv => kv.Value <= -10).ToList();
        if (decayCats.Count > 0)
        {
            int worst = -decayCats.Min(kv => kv.Value);
            int sev = Clamp(45 + Math.Min(worst, 50) + sevShift);
            signals.Add(new RegressionSignal(
                "CONTROL_DECAY", sev, BucketP(sev),
                $"Control decay in {decayCats.Count} category(ies)",
                $"Largest drop: {decayCats.OrderBy(kv => kv.Value).First().Key} ({decayCats.Min(kv => kv.Value)} pts).",
                "automation", 3, "high",
                Array.Empty<string>(), null));
        }

        // NEW_ATTACK_SURFACE
        var newSurface = curFindings.Where(f => f.IsNew &&
            f.Category.Equals("AttackSurface", StringComparison.OrdinalIgnoreCase)).ToList();
        if (newSurface.Count > 0)
        {
            int sev = Clamp(55 + 5 * newSurface.Count + sevShift);
            signals.Add(new RegressionSignal(
                "NEW_ATTACK_SURFACE", sev, BucketP(sev),
                $"{newSurface.Count} new attack-surface finding(s)",
                "New exposed services or open ports detected since last snapshot.",
                "security_eng", 4, "medium",
                newSurface.Select(f => f.Id).ToList(), null));
        }

        // CONFIG_DRIFT_SPIKE
        int driftDelta = categoryDeltas.GetValueOrDefault("ConfigDrift");
        int newDrift = curFindings.Count(f => f.IsNew &&
            f.Category.Equals("ConfigDrift", StringComparison.OrdinalIgnoreCase));
        if (driftDelta <= -15 || newDrift >= 3)
        {
            int sev = Clamp(50 + Math.Abs(Math.Min(driftDelta, 0)) + sevShift);
            var hint = MatchHint(ctx, now, new[] { "ConfigDrift" });
            signals.Add(new RegressionSignal(
                "CONFIG_DRIFT_SPIKE", sev, BucketP(sev),
                "Configuration drift spike",
                $"ConfigDrift score moved {driftDelta} pts; {newDrift} new drift finding(s).",
                "sre", 3, "high",
                Array.Empty<string>(), hint));
        }

        // MONITORING_BLINDSPOT
        int monDelta = categoryDeltas.GetValueOrDefault("Monitoring");
        if (monDelta <= -10)
        {
            int sev = Clamp(45 + Math.Abs(monDelta) + sevShift);
            signals.Add(new RegressionSignal(
                "MONITORING_BLINDSPOT", sev, BucketP(sev),
                "Monitoring coverage dropped",
                $"Monitoring score moved {monDelta} pts — telemetry gap likely.",
                "soc", 3, "high",
                Array.Empty<string>(), null));
        }

        // PERSISTENT_HIGH_SEVERITY
        var persistent = curFindings.Where(f => f.IsPersistent &&
            (f.Severity == FindingSeverity.High || f.Severity == FindingSeverity.Critical)).ToList();
        if (persistent.Count >= 3)
        {
            int sev = Clamp(40 + 3 * persistent.Count + sevShift);
            signals.Add(new RegressionSignal(
                "PERSISTENT_HIGH_SEVERITY", sev, BucketP(sev),
                $"{persistent.Count} persistent high/critical finding(s)",
                "These findings have survived multiple snapshots — backlog risk.",
                "soc", 2, "high",
                persistent.Select(f => f.Id).Take(8).ToList(), null));
        }

        // RESOLVED_PROGRESS (positive)
        int resolved = curFindings.Count(f => f.IsResolved);
        if (resolved >= 5 && totalDelta >= 0)
        {
            signals.Add(new RegressionSignal(
                "RESOLVED_PROGRESS", 5, ActionPriority.P3,
                $"{resolved} findings resolved",
                $"Posture held or improved (Δ={totalDelta}) while resolving {resolved} finding(s).",
                "security_eng", 1, "high",
                Array.Empty<string>(), null));
        }

        // Cautious risk-appetite promotion: monitoring/config -> P0
        if (ctx.Risk == RiskAppetite.Cautious)
        {
            for (int i = 0; i < signals.Count; i++)
            {
                if ((signals[i].Code == "MONITORING_BLINDSPOT" || signals[i].Code == "CONFIG_DRIFT_SPIKE") &&
                    signals[i].Priority != ActionPriority.P0)
                {
                    signals[i] = signals[i] with { Priority = ActionPriority.P0 };
                }
            }
        }

        // ── Verdict ──
        int p0Count = signals.Count(s => s.Priority == ActionPriority.P0);
        bool collapsing = totalDelta < -30 ||
            (p0Count >= 1 && signals.Any(s => s.Code == "NEW_CRITICAL_FINDING"));
        RegressionVerdict verdict;
        if (collapsing) verdict = RegressionVerdict.Collapsing;
        else if (totalDelta <= -30) verdict = RegressionVerdict.Degraded;
        else if (totalDelta <= -15) verdict = RegressionVerdict.Degraded;
        else if (totalDelta <= -5) verdict = RegressionVerdict.Regressing;
        else if (totalDelta >= 5) verdict = RegressionVerdict.Improving;
        else verdict = RegressionVerdict.Stable;

        string grade = verdict switch
        {
            RegressionVerdict.Improving => "A",
            RegressionVerdict.Stable => "B",
            RegressionVerdict.Regressing => "C",
            RegressionVerdict.Degraded => "D",
            RegressionVerdict.Collapsing => "F",
            _ => "C",
        };
        if (p0Count >= 2) grade = "F";

        // ── Playbook ──
        var playbook = new List<PlaybookAction>();
        void Add(string id, ActionPriority p, string label, string owner, int blast, string rev, string reason, params string[] codes)
        {
            if (playbook.Any(a => a.Id == id)) return;
            playbook.Add(new PlaybookAction(id, p, label, owner, blast, rev, reason, codes.ToList()));
        }

        if (verdict == RegressionVerdict.Collapsing)
            Add("EMERGENCY_TRIAGE", ActionPriority.P0,
                "Open incident: posture collapsing",
                "incident_commander", 5, "low",
                "Overall score collapsed; convene war room and freeze risky deploys.",
                signals.Select(s => s.Code).ToArray());

        foreach (var s in signals)
        {
            switch (s.Code)
            {
                case "FIX_ROLLBACK_SUSPECTED":
                    Add("INVESTIGATE_ROLLBACK", ActionPriority.P0,
                        "Investigate recent fix rollback",
                        "security_eng", 3, "medium",
                        s.RootCauseHint ?? "Rollback within 7d correlated to regression.",
                        s.Code);
                    break;
                case "CONTROL_DECAY":
                    Add("REAPPLY_HARDENING",
                        s.Priority == ActionPriority.P0 ? ActionPriority.P0 : ActionPriority.P1,
                        "Reapply hardening baseline to decayed controls",
                        "automation", 3, "high",
                        s.Reason, s.Code);
                    break;
                case "CONFIG_DRIFT_SPIKE":
                    Add("AUDIT_CONFIG_CHANGES",
                        s.Priority == ActionPriority.P0 ? ActionPriority.P0 : ActionPriority.P1,
                        "Audit recent config changes",
                        "sre", 3, "high",
                        s.Reason, s.Code);
                    break;
                case "MONITORING_BLINDSPOT":
                    Add("CLOSE_MONITORING_GAP",
                        s.Priority == ActionPriority.P0 ? ActionPriority.P0 : ActionPriority.P1,
                        "Restore monitoring / telemetry coverage",
                        "soc", 3, "high",
                        s.Reason, s.Code);
                    break;
                case "NEW_ATTACK_SURFACE":
                    Add("ATTACK_SURFACE_REVIEW", ActionPriority.P1,
                        "Review new attack-surface findings",
                        "security_eng", 4, "medium",
                        s.Reason, s.Code);
                    break;
                case "PERSISTENT_HIGH_SEVERITY":
                    Add("ESCALATE_PERSISTENT", ActionPriority.P2,
                        "Escalate persistent high/critical backlog",
                        "soc", 2, "high",
                        s.Reason, s.Code);
                    break;
            }
        }

        // Celebrate progress only when it's the *only* signal in the list.
        if (signals.Count == 1 && signals[0].Code == "RESOLVED_PROGRESS")
            Add("CELEBRATE_PROGRESS", ActionPriority.P3,
                "Acknowledge remediation progress",
                "team_lead", 1, "high",
                "Recognise sustained remediation work to maintain morale.",
                "RESOLVED_PROGRESS");

        if (ctx.Risk == RiskAppetite.Aggressive)
            playbook.RemoveAll(a => a.Priority == ActionPriority.P2 || a.Priority == ActionPriority.P3);

        playbook = playbook.OrderBy(a => (int)a.Priority).ThenBy(a => a.Id, StringComparer.Ordinal).ToList();

        // ── Insights ──
        var insights = new List<string>();
        int newCount = curFindings.Count(f => f.IsNew);
        if (newCount >= 5) insights.Add($"NEW_FINDING_BURST: {newCount} new findings since last snapshot");
        var worstCat = categoryDeltas.OrderBy(kv => kv.Value).FirstOrDefault();
        if (worstCat.Value <= -25)
            insights.Add($"CATEGORY_COLLAPSE: {worstCat.Key} dropped {worstCat.Value} pts");
        if (signals.Any(s => s.RootCauseHint != null))
            insights.Add("ROOT_CAUSE_LIKELY: change-log hint matched at least one signal");
        int droppedCats = categoryDeltas.Count(kv => kv.Value <= -5);
        if (droppedCats >= 3)
            insights.Add($"CROSS_CATEGORY_DEGRADATION: {droppedCats} categories regressed");
        int chronicCount = curFindings.Count(f => f.IsPersistent);
        if (chronicCount >= 5) insights.Add($"CHRONIC_PERSISTENCE: {chronicCount} persistent findings");

        var signalsOut = signals
            .OrderBy(s => (int)s.Priority)
            .ThenByDescending(s => s.Severity)
            .ThenBy(s => s.Code, StringComparer.Ordinal)
            .ToList();

        return new PostureRegressionReport(
            now,
            previous.OverallScore,
            current.OverallScore,
            totalDelta,
            categoryDeltas,
            verdict,
            grade,
            signalsOut,
            playbook,
            insights);
    }

    // ── Renderers ─────────────────────────────────────────────────

    public static string Render(PostureRegressionReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Posture regression report  generated {r.GeneratedAt:O}");
        sb.AppendLine($"Verdict: {r.Verdict}  Grade: {r.Grade}");
        sb.AppendLine($"Score: {r.PreviousScore} -> {r.CurrentScore}  (delta {r.TotalDelta:+#;-#;0})");
        sb.AppendLine();
        sb.AppendLine("Category deltas:");
        foreach (var kv in r.CategoryDeltas)
            sb.AppendLine($"  - {kv.Key}: {kv.Value:+#;-#;0}");
        sb.AppendLine();
        sb.AppendLine($"Signals ({r.Signals.Count}):");
        foreach (var s in r.Signals)
            sb.AppendLine($"  [{s.Priority}] {s.Code} sev={s.Severity} owner={s.Owner} blast={s.BlastRadius} :: {s.Headline}");
        sb.AppendLine();
        sb.AppendLine($"Playbook ({r.Playbook.Count}):");
        foreach (var a in r.Playbook)
            sb.AppendLine($"  [{a.Priority}] {a.Id} -> {a.Label} (owner={a.Owner}, blast={a.BlastRadius}, rev={a.Reversibility})");
        sb.AppendLine();
        sb.AppendLine($"Insights ({r.Insights.Count}):");
        foreach (var i in r.Insights) sb.AppendLine($"  - {i}");
        return sb.ToString();
    }

    public static string RenderMarkdown(PostureRegressionReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- Verdict: **{r.Verdict}**  (grade **{r.Grade}**)");
        sb.AppendLine($"- Score: {r.PreviousScore} → {r.CurrentScore} (Δ {r.TotalDelta:+#;-#;0})");
        sb.AppendLine($"- Generated: {r.GeneratedAt:O}");
        sb.AppendLine();
        sb.AppendLine("## Signals");
        sb.AppendLine();
        sb.AppendLine("| Priority | Code | Severity | Owner | Headline |");
        sb.AppendLine("|----------|------|----------|-------|----------|");
        foreach (var s in r.Signals)
            sb.AppendLine($"| {s.Priority} | {s.Code} | {s.Severity} | {s.Owner} | {s.Headline} |");
        sb.AppendLine();
        sb.AppendLine("## Playbook");
        sb.AppendLine();
        foreach (var a in r.Playbook)
            sb.AppendLine($"- **[{a.Priority}] {a.Id}** — {a.Label} _(owner {a.Owner}, blast {a.BlastRadius}, reversibility {a.Reversibility})_  ");
        sb.AppendLine();
        sb.AppendLine("## Insights");
        sb.AppendLine();
        if (r.Insights.Count == 0) sb.AppendLine("- _none_");
        else foreach (var i in r.Insights) sb.AppendLine($"- {i}");
        return sb.ToString();
    }

    public static string RenderJson(PostureRegressionReport r)
    {
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        };
        return JsonSerializer.Serialize(r, opts);
    }

    // ── Internals ─────────────────────────────────────────────────

    private static int Clamp(int v) => Math.Max(0, Math.Min(100, v));

    private static ActionPriority BucketP(int sev) =>
        sev >= 80 ? ActionPriority.P0 :
        sev >= 60 ? ActionPriority.P1 :
        sev >= 30 ? ActionPriority.P2 :
        ActionPriority.P3;

    private static string? MatchHint(RegressionContext ctx, DateTime now, IEnumerable<string> needles)
    {
        var window = TimeSpan.FromDays(7);
        foreach (var n in needles)
        {
            var hit = ctx.RecentConfigChanges.FirstOrDefault(c =>
                c.Time <= now && (now - c.Time) <= window &&
                (c.Description.Contains(n, StringComparison.OrdinalIgnoreCase) ||
                 c.Component.Contains(n, StringComparison.OrdinalIgnoreCase)));
            if (hit != null)
                return $"Config change to {hit.Component} at {hit.Time:O}: {hit.Description}";
        }
        var fallback = ctx.RecentConfigChanges.FirstOrDefault(c =>
            c.Time <= now && (now - c.Time) <= window);
        return fallback == null ? null
            : $"Config change to {fallback.Component} at {fallback.Time:O}: {fallback.Description}";
    }
}
