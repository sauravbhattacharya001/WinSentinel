using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic forward-looking threat-horizon forecaster.
/// <para>
/// Looks at recent low-confidence attacker signals (reconnaissance, brute force,
/// IOC matches, phishing, rogue DNS, dark-web mentions) together with current
/// posture context (open critical findings, attack-surface size, recent
/// regressions, recently-revoked exceptions) and projects a 7-day forward
/// "threat pressure" score, per-day forecast curve, verdict ladder, and a
/// hardening playbook.
/// </para>
/// <para>
/// Sixth sibling in the agentic services suite alongside
/// <see cref="FixOrchestrationPlanner"/>, <see cref="AlertRoutingAdvisor"/>,
/// <see cref="AttackerProfileSynthesizer"/>, <see cref="PostureRegressionExplainer"/>
/// and <see cref="PolicyExceptionRiskAdvisor"/>. Distinct from
/// <c>AttackerProfileSynthesizer</c> (which classifies an <em>active</em>
/// attacker from finished detector hits) and
/// <c>PostureRegressionExplainer</c> (which explains <em>past</em> degradation):
/// this advisor forecasts pressure on the <em>next</em> 1..N days.
/// </para>
/// <para>
/// Pure / deterministic — no I/O. Inject time via
/// <see cref="ForecastContext.NowOverride"/> for reproducible tests.
/// Never mutates inputs.
/// </para>
/// </summary>
public class ThreatHorizonForecastAdvisor
{
    // ── Public model ─────────────────────────────────────────────

    /// <summary>How aggressively the advisor recommends action.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    /// <summary>Action / forecast priority bucket.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    /// <summary>Recon signal type.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ReconSignalType
    {
        PortScan,
        BruteForce,
        CredentialStuffing,
        PhishingLanding,
        IocMatch,
        RogueDns,
        DarkWebMention,
        AnomalousOutbound,
    }

    /// <summary>Horizon verdict ladder (ordered from quietest to loudest).</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum HorizonVerdict
    {
        Calm,
        Elevated,
        Imminent,
        UnderPressure,
    }

    /// <summary>A single recon / attacker-side signal observation.</summary>
    public record ReconSignal(
        string Id,
        ReconSignalType Type,
        DateTime ObservedAt,
        string Source,
        double Confidence,
        string Detail);

    /// <summary>Current posture context — defender side.</summary>
    public record PostureContext(
        int OpenCriticalFindings,
        int OpenHighFindings,
        int AttackSurfaceSize,
        int ExposedAssetCount,
        int DaysSinceLastRegression,
        int RecentlyRevokedExceptionCount);

    /// <summary>Caller-supplied forecast context.</summary>
    public class ForecastContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;
        public DateTime? NowOverride { get; set; }
        /// <summary>Forecast horizon in days (default 7, min 1, max 30).</summary>
        public int HorizonDays { get; set; } = 7;
        /// <summary>How many days back to consider recon signals (default 14).</summary>
        public int LookbackDays { get; set; } = 14;
    }

    /// <summary>A weighted contribution from one signal class.</summary>
    public record SignalContribution(
        string Code,
        int Weight,
        int Count,
        string Detail);

    /// <summary>Per-day forecast point.</summary>
    public record DailyForecast(
        int Day,
        DateTime Date,
        int Pressure,
        HorizonVerdict Verdict);

    /// <summary>Single playbook action.</summary>
    public record PlaybookAction(
        string Id,
        ActionPriority Priority,
        string Label,
        string Owner,
        int BlastRadius,
        string Reversibility,
        string Reason);

    /// <summary>Full report returned to the caller.</summary>
    public record ThreatHorizonReport(
        DateTime GeneratedAt,
        int HorizonDays,
        int PressureScore,
        HorizonVerdict Verdict,
        string Grade,
        IReadOnlyList<SignalContribution> Contributions,
        IReadOnlyList<DailyForecast> Forecast,
        IReadOnlyList<PlaybookAction> Playbook,
        IReadOnlyList<string> Insights);

    // ── Public API ───────────────────────────────────────────────

    /// <summary>Forecast threat horizon.</summary>
    public ThreatHorizonReport Analyze(
        IEnumerable<ReconSignal> signals,
        PostureContext posture,
        ForecastContext? ctx = null)
    {
        if (signals is null) throw new ArgumentNullException(nameof(signals));
        if (posture is null) throw new ArgumentNullException(nameof(posture));
        ctx ??= new ForecastContext();
        var now = ctx.NowOverride ?? DateTime.UtcNow;
        int horizon = Math.Clamp(ctx.HorizonDays, 1, 30);
        int lookback = Math.Max(1, ctx.LookbackDays);

        var fresh = signals
            .Where(s => s is not null && (now - s.ObservedAt).TotalDays <= lookback && s.ObservedAt <= now)
            .ToList();

        var contributions = new List<SignalContribution>();
        int totalAttacker = 0;
        int totalDefender = 0;

        // ── Attacker-side signal weights ─────────────────────────

        int bruteCount = fresh.Count(s =>
            (s.Type == ReconSignalType.BruteForce || s.Type == ReconSignalType.CredentialStuffing) &&
            (now - s.ObservedAt).TotalDays <= 1.0);
        if (bruteCount > 0)
        {
            int w = bruteCount switch { < 3 => 10, < 10 => 25, _ => 40 };
            contributions.Add(new("BRUTE_FORCE_VELOCITY", w, bruteCount,
                $"{bruteCount} brute-force / credential-stuffing event(s) in the last 24h"));
            totalAttacker += w;
        }

        var portScanSources = fresh
            .Where(s => s.Type == ReconSignalType.PortScan)
            .Select(s => s.Source)
            .Where(src => !string.IsNullOrWhiteSpace(src))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        if (portScanSources > 0)
        {
            int w = portScanSources switch { < 3 => 5, < 8 => 15, _ => 25 };
            contributions.Add(new("PORT_SCAN_BURST", w, portScanSources,
                $"{portScanSources} distinct port-scan source(s) in the last {lookback}d"));
            totalAttacker += w;
        }

        var iocMatches = fresh.Where(s => s.Type == ReconSignalType.IocMatch).ToList();
        if (iocMatches.Count > 0)
        {
            bool highConf = iocMatches.Any(s => s.Confidence >= 0.8);
            int w = highConf ? 60 : 30;
            contributions.Add(new("IOC_MATCH_FRESH", w, iocMatches.Count,
                highConf
                    ? $"{iocMatches.Count} fresh IOC match(es) including a high-confidence hit"
                    : $"{iocMatches.Count} fresh IOC match(es)"));
            totalAttacker += w;
        }

        int phishCount = fresh.Count(s => s.Type == ReconSignalType.PhishingLanding);
        if (phishCount > 0)
        {
            int w = phishCount switch { < 3 => 5, < 8 => 12, _ => 20 };
            contributions.Add(new("PHISHING_LANDING_HITS", w, phishCount,
                $"{phishCount} phishing-landing hit(s) in the last {lookback}d"));
            totalAttacker += w;
        }

        int rogueDnsCount = fresh.Count(s => s.Type == ReconSignalType.RogueDns);
        if (rogueDnsCount > 0)
        {
            int w = rogueDnsCount switch { < 5 => 10, _ => 20 };
            contributions.Add(new("ROGUE_DNS_QUERIES", w, rogueDnsCount,
                $"{rogueDnsCount} rogue-DNS query event(s) in the last {lookback}d"));
            totalAttacker += w;
        }

        int darkWebCount = fresh.Count(s => s.Type == ReconSignalType.DarkWebMention);
        if (darkWebCount > 0)
        {
            contributions.Add(new("DARK_WEB_MENTION", 25, darkWebCount,
                $"{darkWebCount} dark-web mention(s) in the last {lookback}d"));
            totalAttacker += 25;
        }

        int anomOutboundCount = fresh.Count(s => s.Type == ReconSignalType.AnomalousOutbound);
        if (anomOutboundCount > 0)
        {
            int w = anomOutboundCount switch { < 3 => 8, _ => 18 };
            contributions.Add(new("ANOMALOUS_OUTBOUND", w, anomOutboundCount,
                $"{anomOutboundCount} anomalous outbound traffic event(s) in the last {lookback}d"));
            totalAttacker += w;
        }

        // ── Defender-side / overhang weights ─────────────────────

        if (posture.OpenCriticalFindings > 0)
        {
            int w = Math.Min(25, 5 * posture.OpenCriticalFindings);
            contributions.Add(new("OPEN_CRITICAL_OVERHANG", w, posture.OpenCriticalFindings,
                $"{posture.OpenCriticalFindings} open critical finding(s) on the defender side"));
            totalDefender += w;
        }

        if (posture.AttackSurfaceSize >= 50)
        {
            int w = posture.AttackSurfaceSize >= 200 ? 20 :
                    posture.AttackSurfaceSize >= 100 ? 15 : 10;
            contributions.Add(new("LARGE_ATTACK_SURFACE", w, posture.AttackSurfaceSize,
                $"Attack-surface size {posture.AttackSurfaceSize} (large)"));
            totalDefender += w;
        }

        if (posture.DaysSinceLastRegression >= 0 && posture.DaysSinceLastRegression < 14)
        {
            contributions.Add(new("RECENT_REGRESSION", 10, posture.DaysSinceLastRegression,
                $"Posture regression observed {posture.DaysSinceLastRegression}d ago"));
            totalDefender += 10;
        }

        if (posture.RecentlyRevokedExceptionCount >= 1)
        {
            int w = posture.RecentlyRevokedExceptionCount switch { < 3 => 5, _ => 15 };
            contributions.Add(new("EXCEPTION_THAW", w, posture.RecentlyRevokedExceptionCount,
                $"{posture.RecentlyRevokedExceptionCount} recently revoked exception(s) — net-new exposure"));
            totalDefender += w;
        }

        if (posture.ExposedAssetCount >= 5)
        {
            int w = posture.ExposedAssetCount >= 25 ? 15 :
                    posture.ExposedAssetCount >= 10 ? 10 : 5;
            contributions.Add(new("EXPOSED_ASSETS", w, posture.ExposedAssetCount,
                $"{posture.ExposedAssetCount} exposed asset(s)"));
            totalDefender += w;
        }

        // ── Risk-appetite shift ──────────────────────────────────

        int shift = ctx.Risk switch
        {
            RiskAppetite.Cautious => +5,
            RiskAppetite.Aggressive => -5,
            _ => 0,
        };

        int raw = totalAttacker + totalDefender + shift;
        int pressure = Math.Clamp(raw, 0, 100);

        HorizonVerdict verdict =
            pressure < 25 ? HorizonVerdict.Calm :
            pressure < 50 ? HorizonVerdict.Elevated :
            pressure < 75 ? HorizonVerdict.Imminent :
            HorizonVerdict.UnderPressure;

        string grade =
            pressure < 15 ? "A" :
            pressure < 35 ? "B" :
            pressure < 55 ? "C" :
            pressure < 75 ? "D" :
            "F";

        // ── Per-day forecast curve ───────────────────────────────
        // Attacker pressure decays slowly over the horizon if no fresh
        // signals; defender overhang stays roughly flat. We approximate
        // the curve with a linear blend so behavior is deterministic and
        // easy to reason about.

        var forecast = new List<DailyForecast>(horizon);
        for (int d = 1; d <= horizon; d++)
        {
            // Attacker side decays ~5% per day; defender stays flat.
            double decay = Math.Max(0.0, 1.0 - 0.05 * (d - 1));
            int projected = (int)Math.Round(totalAttacker * decay) + totalDefender + shift;
            int p = Math.Clamp(projected, 0, 100);
            HorizonVerdict v =
                p < 25 ? HorizonVerdict.Calm :
                p < 50 ? HorizonVerdict.Elevated :
                p < 75 ? HorizonVerdict.Imminent :
                HorizonVerdict.UnderPressure;
            forecast.Add(new DailyForecast(d, now.AddDays(d).Date, p, v));
        }

        // ── Playbook ─────────────────────────────────────────────

        var playbook = new List<PlaybookAction>();
        bool Has(string code) => contributions.Any(c => c.Code == code);
        void Add(string id, ActionPriority p, string label, string owner, int blast, string rev, string reason)
        {
            if (playbook.Any(a => a.Id == id)) return;
            playbook.Add(new PlaybookAction(id, p, label, owner, blast, rev, reason));
        }

        if (verdict == HorizonVerdict.UnderPressure)
            Add("ACTIVATE_HIGH_ALERT", ActionPriority.P0,
                "Activate high-alert posture",
                "soc_lead", 5, "high",
                $"Pressure score {pressure} ≥ 75 — convene war-room and elevate detection sensitivity.");

        if (Has("IOC_MATCH_FRESH"))
            Add("BLOCK_KNOWN_IOCS", ActionPriority.P0,
                "Block fresh IOCs at perimeter",
                "network_eng", 4, "high",
                "Fresh IOC matches observed — push to firewall / EDR block lists immediately.");

        if (Has("BRUTE_FORCE_VELOCITY"))
        {
            var brute = contributions.First(c => c.Code == "BRUTE_FORCE_VELOCITY");
            var pri = brute.Weight >= 25 ? ActionPriority.P0 : ActionPriority.P1;
            Add("RATE_LIMIT_AUTH", pri,
                "Tighten auth rate-limiting / enable lockouts",
                "iam_eng", 3, "high",
                $"{brute.Count} brute / credential-stuffing event(s) in last 24h — enforce per-source rate limits and step-up MFA.");
        }

        if (Has("PORT_SCAN_BURST") && Has("LARGE_ATTACK_SURFACE"))
            Add("HARDEN_PERIMETER", ActionPriority.P0,
                "Harden the network perimeter",
                "network_eng", 4, "medium",
                "Port-scan activity combined with a large attack surface — close unused ports and audit edge ACLs.");
        else if (Has("PORT_SCAN_BURST"))
            Add("AUDIT_EXPOSED_PORTS", ActionPriority.P1,
                "Audit exposed ports",
                "network_eng", 2, "high",
                "Port-scan activity observed — verify intentional exposure.");

        if (Has("PHISHING_LANDING_HITS"))
            Add("DEPLOY_PHISH_AWARENESS", ActionPriority.P1,
                "Deploy phishing-awareness reminder",
                "security_comms", 2, "high",
                "Phishing-landing activity in the lookback window — push a short awareness blurb to all users.");

        if (Has("OPEN_CRITICAL_OVERHANG"))
            Add("PATCH_CRITICAL_OVERHANG", ActionPriority.P1,
                "Patch critical finding overhang",
                "remediation", 3, "medium",
                "Open critical findings amplify the risk of incoming attacks landing — prioritize this sprint.");

        if (Has("DARK_WEB_MENTION"))
            Add("THREAT_INTEL_DEEP_DIVE", ActionPriority.P1,
                "Dark-web mention deep-dive",
                "threat_intel", 2, "high",
                "Dark-web mention(s) detected — investigate context and dispatch credential / data-leak hunts.");

        if (Has("ROGUE_DNS_QUERIES"))
            Add("FORCE_DNS_REVIEW", ActionPriority.P2,
                "Review DNS egress",
                "network_eng", 2, "high",
                "Rogue DNS query events — verify resolver configuration and force trusted DNS.");

        if (Has("ANOMALOUS_OUTBOUND"))
            Add("INVESTIGATE_EGRESS", ActionPriority.P1,
                "Investigate anomalous outbound traffic",
                "soc_analyst", 3, "high",
                "Anomalous outbound traffic events — verify against known baselines, suspect C2 / data exfil.");

        if (Has("EXCEPTION_THAW"))
            Add("REVALIDATE_THAWED_CONTROLS", ActionPriority.P2,
                "Revalidate recently un-waived controls",
                "security_eng", 2, "high",
                "Recently revoked exceptions expose new controls — re-test that mitigations behave as intended.");

        // Compound condition: 2+ P0 actions ⇒ also convene a war room.
        int p0Count = playbook.Count(a => a.Priority == ActionPriority.P0);
        if (p0Count >= 2)
            Add("CONVENE_THREAT_WAR_ROOM", ActionPriority.P0,
                "Convene threat war-room",
                "ciso_office", 5, "high",
                $"{p0Count} P0 conditions detected — bring leads from SOC / network / IAM / IR to a single channel.");

        if (playbook.Count == 0)
            Add("WATCH_AND_WAIT", ActionPriority.P3,
                "Maintain current detection rhythm",
                "soc_analyst", 1, "high",
                "No P0/P1/P2 conditions detected — keep telemetry on, no escalation needed.");

        // Aggressive: drop P3 and standalone P2 when P0/P1 present.
        if (ctx.Risk == RiskAppetite.Aggressive)
        {
            bool hasP0OrP1 = playbook.Any(a => a.Priority == ActionPriority.P0 || a.Priority == ActionPriority.P1);
            if (hasP0OrP1)
            {
                playbook.RemoveAll(a => a.Priority == ActionPriority.P3);
                playbook.RemoveAll(a => a.Priority == ActionPriority.P2);
            }
        }

        playbook = playbook
            .OrderBy(a => (int)a.Priority)
            .ThenBy(a => a.Id, StringComparer.Ordinal)
            .ToList();

        // ── Insights ─────────────────────────────────────────────

        var insights = new List<string>();
        int networkHeat = (Has("PORT_SCAN_BURST") ? 1 : 0) +
                          (Has("ROGUE_DNS_QUERIES") ? 1 : 0) +
                          (Has("ANOMALOUS_OUTBOUND") ? 1 : 0);
        int authHeat = (Has("BRUTE_FORCE_VELOCITY") ? 1 : 0);
        int userHeat = (Has("PHISHING_LANDING_HITS") ? 1 : 0) +
                       (Has("DARK_WEB_MENTION") ? 1 : 0);

        if (networkHeat >= 2 && networkHeat > authHeat && networkHeat > userHeat)
            insights.Add("HEAT_CONCENTRATED_NETWORK");
        if (userHeat >= 2 && userHeat > networkHeat && userHeat > authHeat)
            insights.Add("HEAT_CONCENTRATED_USER");
        if (authHeat >= 1 && Has("BRUTE_FORCE_VELOCITY") &&
            contributions.First(c => c.Code == "BRUTE_FORCE_VELOCITY").Weight >= 25)
            insights.Add("HEAT_CONCENTRATED_AUTH");
        if (totalAttacker > 0 && totalDefender > 0)
            insights.Add("COMPOUND_PRESSURE_INTERNAL_AND_EXTERNAL");
        if (contributions.Count == 0)
            insights.Add("LOW_SIGNAL_ENVIRONMENT");
        if (verdict == HorizonVerdict.UnderPressure && forecast.All(f => f.Verdict >= HorizonVerdict.Imminent))
            insights.Add("SUSTAINED_PRESSURE_FORECAST");

        contributions = contributions
            .OrderByDescending(c => c.Weight)
            .ThenBy(c => c.Code, StringComparer.Ordinal)
            .ToList();

        return new ThreatHorizonReport(
            now,
            horizon,
            pressure,
            verdict,
            grade,
            contributions,
            forecast,
            playbook,
            insights);
    }

    // ── Renderers ─────────────────────────────────────────────────

    /// <summary>Plain-text renderer.</summary>
    public static string Render(ThreatHorizonReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Threat horizon forecast  generated {r.GeneratedAt:O}  horizon {r.HorizonDays}d");
        sb.AppendLine($"Verdict: {r.Verdict}  Grade: {r.Grade}  Pressure: {r.PressureScore}/100");
        sb.AppendLine();
        sb.AppendLine($"Contributions ({r.Contributions.Count}):");
        foreach (var c in r.Contributions)
            sb.AppendLine($"  [+{c.Weight}] {c.Code} x{c.Count} — {c.Detail}");
        sb.AppendLine();
        sb.AppendLine($"Daily forecast:");
        foreach (var f in r.Forecast)
            sb.AppendLine($"  +{f.Day}d ({f.Date:yyyy-MM-dd}) pressure={f.Pressure} verdict={f.Verdict}");
        sb.AppendLine();
        sb.AppendLine($"Playbook ({r.Playbook.Count}):");
        foreach (var p in r.Playbook)
            sb.AppendLine($"  [{p.Priority}] {p.Id} -> {p.Label} (owner={p.Owner}, blast={p.BlastRadius}, rev={p.Reversibility})");
        sb.AppendLine();
        sb.AppendLine($"Insights ({r.Insights.Count}):");
        foreach (var i in r.Insights) sb.AppendLine($"  - {i}");
        return sb.ToString();
    }

    /// <summary>Markdown renderer.</summary>
    public static string RenderMarkdown(ThreatHorizonReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- Verdict: **{r.Verdict}**  (grade **{r.Grade}**)");
        sb.AppendLine($"- Pressure: **{r.PressureScore}/100**  (horizon {r.HorizonDays}d)");
        sb.AppendLine($"- Generated: {r.GeneratedAt:O}");
        sb.AppendLine();
        sb.AppendLine("## Contributions");
        sb.AppendLine();
        if (r.Contributions.Count == 0)
        {
            sb.AppendLine("- _none_");
        }
        else
        {
            sb.AppendLine("| Code | Weight | Count | Detail |");
            sb.AppendLine("|------|-------:|------:|--------|");
            foreach (var c in r.Contributions)
                sb.AppendLine($"| {c.Code} | {c.Weight} | {c.Count} | {c.Detail} |");
        }
        sb.AppendLine();
        sb.AppendLine("## Daily forecast");
        sb.AppendLine();
        sb.AppendLine("| Day | Date | Pressure | Verdict |");
        sb.AppendLine("|----:|------|---------:|---------|");
        foreach (var f in r.Forecast)
            sb.AppendLine($"| +{f.Day}d | {f.Date:yyyy-MM-dd} | {f.Pressure} | {f.Verdict} |");
        sb.AppendLine();
        sb.AppendLine("## Playbook");
        sb.AppendLine();
        if (r.Playbook.Count == 0) sb.AppendLine("- _none_");
        else foreach (var p in r.Playbook)
            sb.AppendLine($"- **[{p.Priority}] {p.Id}** — {p.Label} _(owner {p.Owner}, blast {p.BlastRadius}, reversibility {p.Reversibility})_  ");
        sb.AppendLine();
        sb.AppendLine("## Insights");
        sb.AppendLine();
        if (r.Insights.Count == 0) sb.AppendLine("- _none_");
        else foreach (var i in r.Insights) sb.AppendLine($"- {i}");
        return sb.ToString();
    }

    /// <summary>Deterministic JSON renderer.</summary>
    public static string RenderJson(ThreatHorizonReport r)
    {
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        };
        return JsonSerializer.Serialize(r, opts);
    }
}
