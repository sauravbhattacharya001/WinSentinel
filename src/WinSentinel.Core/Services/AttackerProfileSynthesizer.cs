using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Core.Services;

/// <summary>
/// Agentic attacker-profile synthesizer.
/// <para>
/// Cross-module classifier: given a batch of <see cref="AttackerSignal"/>
/// records (one per observed TTP, harvested from any detector — InitialAccess,
/// Execution, Persistence, PrivilegeEscalation, DefenseEvasion,
/// CredentialAccess, Discovery, LateralMovement, Collection, C2,
/// Exfiltration, Impact, plus tag hints like <c>encryption</c>,
/// <c>mining</c>, <c>scanner</c>) it picks the most likely attacker
/// <see cref="AttackerArchetype"/>, emits secondary candidates ranked by
/// weighted softmax confidence, computes kill-chain progression %, and
/// produces a ranked <see cref="HuntFocus"/> + <see cref="ContainmentAction"/>
/// playbook tailored to the inferred archetype.
/// </para>
/// <para>
/// Complements <see cref="AlertRoutingAdvisor"/> (which decides *where*
/// alerts go) and <see cref="FixOrchestrationPlanner"/> (which sequences
/// fixes): this advisor decides *who* is attacking and *what to hunt next*.
/// </para>
/// <para>
/// Pure / deterministic — no I/O. Time can be pinned via
/// <see cref="ProfileContext.NowOverride"/> for reproducible tests.
/// </para>
/// </summary>
public class AttackerProfileSynthesizer
{
    // ── Public model ────────────────────────────────────────────

    /// <summary>MITRE-ATT&amp;CK style tactic.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum Tactic
    {
        Reconnaissance,
        InitialAccess,
        Execution,
        Persistence,
        PrivilegeEscalation,
        DefenseEvasion,
        CredentialAccess,
        Discovery,
        LateralMovement,
        Collection,
        CommandAndControl,
        Exfiltration,
        Impact,
        Other,
    }

    /// <summary>Best-guess attacker archetype.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum AttackerArchetype
    {
        CommodityMalware,
        RansomwareOperator,
        AptNationState,
        InsiderThreat,
        RedTeam,
        AutomatedScanner,
        CryptoMiner,
        ScriptKiddie,
        Unknown,
    }

    /// <summary>Per-archetype confidence band.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ConfidenceBand { Low, Moderate, High, VeryHigh }

    /// <summary>How aggressively the synthesizer recommends containment.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RiskAppetite { Cautious, Balanced, Aggressive }

    /// <summary>Hunt / containment action priority bucket.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ActionPriority { P0, P1, P2, P3 }

    /// <summary>Single observed TTP signal from any detector.</summary>
    public record AttackerSignal(
        string TtpId,
        Tactic Tactic,
        string Source,
        int SeverityScore = 50,
        int Confidence = 75,
        DateTimeOffset? ObservedAt = null,
        IReadOnlyList<string>? Tags = null);

    /// <summary>Caller-supplied scoring context.</summary>
    public class ProfileContext
    {
        public RiskAppetite Risk { get; set; } = RiskAppetite.Balanced;

        /// <summary>Set true if any host on the network holds sensitive data — bumps insider/ransom severity.</summary>
        public bool ContainsSensitiveData { get; set; }

        /// <summary>Set true if there is an active known red-team / pen-test window.</summary>
        public bool ActiveRedTeamWindow { get; set; }

        /// <summary>Pin "now" for deterministic testing.</summary>
        public DateTimeOffset? NowOverride { get; set; }
    }

    /// <summary>Ranked archetype candidate.</summary>
    public record ArchetypeCandidate(
        AttackerArchetype Archetype,
        int Score,           // 0..100 (softmax % of total)
        double RawScore,     // pre-softmax cumulative
        ConfidenceBand Band,
        IReadOnlyList<string> SupportingTactics);

    /// <summary>Targeted hunt query suggestion.</summary>
    public record HuntFocus(
        string Code,
        string Question,
        ActionPriority Priority,
        IReadOnlyList<string> Tactics,
        string ExpectedSignal);

    /// <summary>Immediate containment action.</summary>
    public record ContainmentAction(
        string Code,
        string Headline,
        ActionPriority Priority,
        string Owner,        // soc / it / leadership / hr
        int BlastRadius,     // 1 (low) .. 5 (very disruptive)
        string Reversibility,// low / medium / high
        string Reason);

    /// <summary>Single-line portfolio observation.</summary>
    public record ProfileInsight(string Code, string Headline, ActionPriority Severity);

    /// <summary>Full synthesised profile.</summary>
    public class AttackerProfile
    {
        public AttackerArchetype PrimaryArchetype { get; set; }
        public int PrimaryConfidence { get; set; }
        public ConfidenceBand PrimaryBand { get; set; }
        public List<ArchetypeCandidate> Candidates { get; set; } = new();
        public List<HuntFocus> Hunts { get; set; } = new();
        public List<ContainmentAction> Containments { get; set; } = new();
        public List<ProfileInsight> Insights { get; set; } = new();
        public int KillChainProgressionPct { get; set; }
        public int TempoSignalsPerHour { get; set; }
        public string Headline { get; set; } = "";
        public string Grade { get; set; } = "C";
        public DateTimeOffset GeneratedAt { get; set; }
    }

    // ── Public API ─────────────────────────────────────────────

    /// <summary>Synthesise an attacker profile from a batch of signals.</summary>
    public AttackerProfile Synthesize(
        IEnumerable<AttackerSignal> signals,
        ProfileContext? context = null)
    {
        ArgumentNullException.ThrowIfNull(signals);
        context ??= new ProfileContext();
        var now = context.NowOverride ?? DateTimeOffset.UtcNow;
        var batch = signals.ToList();

        if (batch.Count == 0)
        {
            return new AttackerProfile
            {
                PrimaryArchetype = AttackerArchetype.Unknown,
                PrimaryConfidence = 0,
                PrimaryBand = ConfidenceBand.Low,
                Headline = "No attacker signals observed.",
                Grade = "A",
                GeneratedAt = now,
            };
        }

        // 1) Tactic weight per archetype (dot-product style scoring).
        var candidates = ScoreCandidates(batch, context);

        var primary = candidates[0];
        var killChainPct = ComputeKillChainPct(batch);
        var tempo = ComputeTempo(batch, now);

        var hunts = BuildHunts(primary.Archetype, batch, context);
        var containments = BuildContainments(primary, batch, context);
        var insights = BuildInsights(primary, batch, killChainPct, tempo, context);

        var grade = ComputeGrade(primary, killChainPct, batch);
        var headline = $"{Pretty(primary.Archetype)} suspected ({primary.Score}% confidence, {primary.Band}); " +
                       $"kill-chain {killChainPct}% advanced; tempo {tempo}/hr; grade {grade}.";

        return new AttackerProfile
        {
            PrimaryArchetype = primary.Archetype,
            PrimaryConfidence = primary.Score,
            PrimaryBand = primary.Band,
            Candidates = candidates,
            Hunts = hunts,
            Containments = containments,
            Insights = insights,
            KillChainProgressionPct = killChainPct,
            TempoSignalsPerHour = tempo,
            Headline = headline,
            Grade = grade,
            GeneratedAt = now,
        };
    }

    // ── Scoring ─────────────────────────────────────────────────

    // Per-archetype tactic weights (0..10). Tuned by hand; the synthesiser
    // takes a dot product with per-tactic observed signal-weight.
    private static readonly Dictionary<AttackerArchetype, Dictionary<Tactic, double>> ArchetypeProfiles =
        new()
        {
            [AttackerArchetype.CommodityMalware] = new()
            {
                [Tactic.InitialAccess] = 6,
                [Tactic.Execution] = 7,
                [Tactic.Persistence] = 8,
                [Tactic.DefenseEvasion] = 5,
                [Tactic.CommandAndControl] = 7,
                [Tactic.Impact] = 3,
            },
            [AttackerArchetype.RansomwareOperator] = new()
            {
                [Tactic.InitialAccess] = 5,
                [Tactic.Discovery] = 6,
                [Tactic.CredentialAccess] = 7,
                [Tactic.LateralMovement] = 8,
                [Tactic.DefenseEvasion] = 5,
                [Tactic.Collection] = 4,
                [Tactic.Exfiltration] = 5,
                [Tactic.Impact] = 10,
            },
            [AttackerArchetype.AptNationState] = new()
            {
                [Tactic.Reconnaissance] = 5,
                [Tactic.InitialAccess] = 4,
                [Tactic.Persistence] = 8,
                [Tactic.PrivilegeEscalation] = 7,
                [Tactic.DefenseEvasion] = 9,
                [Tactic.CredentialAccess] = 7,
                [Tactic.Discovery] = 6,
                [Tactic.LateralMovement] = 7,
                [Tactic.Collection] = 6,
                [Tactic.CommandAndControl] = 6,
                [Tactic.Exfiltration] = 7,
            },
            [AttackerArchetype.InsiderThreat] = new()
            {
                [Tactic.Discovery] = 5,
                [Tactic.Collection] = 9,
                [Tactic.Exfiltration] = 9,
                [Tactic.CredentialAccess] = 3,
            },
            [AttackerArchetype.RedTeam] = new()
            {
                [Tactic.Reconnaissance] = 6,
                [Tactic.InitialAccess] = 6,
                [Tactic.Execution] = 6,
                [Tactic.Persistence] = 5,
                [Tactic.PrivilegeEscalation] = 6,
                [Tactic.DefenseEvasion] = 6,
                [Tactic.CredentialAccess] = 6,
                [Tactic.Discovery] = 6,
                [Tactic.LateralMovement] = 6,
                [Tactic.CommandAndControl] = 5,
            },
            [AttackerArchetype.AutomatedScanner] = new()
            {
                [Tactic.Reconnaissance] = 9,
                [Tactic.InitialAccess] = 7,
                [Tactic.Discovery] = 3,
            },
            [AttackerArchetype.CryptoMiner] = new()
            {
                [Tactic.Execution] = 8,
                [Tactic.Persistence] = 7,
                [Tactic.DefenseEvasion] = 4,
                [Tactic.CommandAndControl] = 4,
                [Tactic.Impact] = 5,
            },
            [AttackerArchetype.ScriptKiddie] = new()
            {
                [Tactic.InitialAccess] = 7,
                [Tactic.Execution] = 5,
                [Tactic.Discovery] = 4,
            },
        };

    private static List<ArchetypeCandidate> ScoreCandidates(
        List<AttackerSignal> batch,
        ProfileContext ctx)
    {
        // Per-tactic aggregated signal-weight (severity * confidence / 1e4).
        var tacticWeight = new Dictionary<Tactic, double>();
        var tacticSeen = new Dictionary<Tactic, List<string>>();
        foreach (var s in batch)
        {
            double w = Math.Clamp(s.SeverityScore, 0, 100)
                       * Math.Clamp(s.Confidence, 0, 100) / 10000.0;
            tacticWeight[s.Tactic] = tacticWeight.GetValueOrDefault(s.Tactic) + w;
            if (!tacticSeen.TryGetValue(s.Tactic, out var list))
                tacticSeen[s.Tactic] = list = new List<string>();
            if (!list.Contains(s.TtpId)) list.Add(s.TtpId);
        }

        // Tag-driven nudges (case-insensitive).
        var tags = batch.SelectMany(s => s.Tags ?? Array.Empty<string>())
            .Select(t => t.ToLowerInvariant()).ToHashSet();

        var raw = new Dictionary<AttackerArchetype, double>();
        foreach (var (arch, weights) in ArchetypeProfiles)
        {
            double sum = 0;
            foreach (var (t, w) in tacticWeight)
            {
                if (weights.TryGetValue(t, out var aw)) sum += aw * w;
            }
            raw[arch] = sum;
        }

        // Tag boosters.
        if (tags.Contains("ransom") || tags.Contains("encryption") || tags.Contains("encrypted_files"))
            raw[AttackerArchetype.RansomwareOperator] += 4;
        if (tags.Contains("mining") || tags.Contains("xmr") || tags.Contains("xmrig") || tags.Contains("coinminer"))
            raw[AttackerArchetype.CryptoMiner] += 5;
        if (tags.Contains("scanner") || tags.Contains("portscan") || tags.Contains("masscan") || tags.Contains("nmap"))
            raw[AttackerArchetype.AutomatedScanner] += 5;
        if (tags.Contains("insider") || tags.Contains("legit_credentials"))
            raw[AttackerArchetype.InsiderThreat] += 5;
        if (tags.Contains("nation_state") || tags.Contains("apt") || tags.Contains("low_and_slow"))
            raw[AttackerArchetype.AptNationState] += 5;
        if (ctx.ActiveRedTeamWindow)
            raw[AttackerArchetype.RedTeam] += 6;
        if (ctx.ContainsSensitiveData)
        {
            raw[AttackerArchetype.InsiderThreat] += 2;
            raw[AttackerArchetype.RansomwareOperator] += 2;
            raw[AttackerArchetype.AptNationState] += 2;
        }

        // Risk-appetite shifts the noise floor for low-impact archetypes.
        if (ctx.Risk == RiskAppetite.Cautious)
        {
            raw[AttackerArchetype.RansomwareOperator] *= 1.10;
            raw[AttackerArchetype.AptNationState] *= 1.10;
            raw[AttackerArchetype.InsiderThreat] *= 1.10;
        }
        else if (ctx.Risk == RiskAppetite.Aggressive)
        {
            raw[AttackerArchetype.ScriptKiddie] *= 1.10;
            raw[AttackerArchetype.AutomatedScanner] *= 1.10;
        }

        var total = raw.Values.Sum();
        var candidates = new List<ArchetypeCandidate>();
        foreach (var (arch, score) in raw.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key.ToString()))
        {
            if (score <= 0) continue;
            int pct = total > 0 ? (int)Math.Round(score / total * 100.0) : 0;
            var supporting = ArchetypeProfiles[arch].Keys
                .Where(tacticSeen.ContainsKey)
                .OrderByDescending(t => tacticWeight[t])
                .Select(t => t.ToString())
                .Take(5)
                .ToList();
            candidates.Add(new ArchetypeCandidate(
                arch,
                pct,
                Math.Round(score, 3),
                BandFor(pct),
                supporting));
        }

        if (candidates.Count == 0)
        {
            candidates.Add(new ArchetypeCandidate(
                AttackerArchetype.Unknown, 0, 0, ConfidenceBand.Low, Array.Empty<string>()));
        }

        return candidates;
    }

    private static ConfidenceBand BandFor(int pct) => pct switch
    {
        >= 70 => ConfidenceBand.VeryHigh,
        >= 50 => ConfidenceBand.High,
        >= 30 => ConfidenceBand.Moderate,
        _ => ConfidenceBand.Low,
    };

    // ── Kill-chain progression / tempo ──────────────────────────

    // Ordered "depth" of each tactic in a generic kill chain.
    private static readonly Tactic[] KillChainOrder =
    {
        Tactic.Reconnaissance,
        Tactic.InitialAccess,
        Tactic.Execution,
        Tactic.Persistence,
        Tactic.PrivilegeEscalation,
        Tactic.DefenseEvasion,
        Tactic.CredentialAccess,
        Tactic.Discovery,
        Tactic.LateralMovement,
        Tactic.Collection,
        Tactic.CommandAndControl,
        Tactic.Exfiltration,
        Tactic.Impact,
    };

    private static int ComputeKillChainPct(List<AttackerSignal> batch)
    {
        var seen = batch.Select(s => s.Tactic).ToHashSet();
        int deepest = -1;
        for (int i = 0; i < KillChainOrder.Length; i++)
        {
            if (seen.Contains(KillChainOrder[i])) deepest = i;
        }
        if (deepest < 0) return 0;
        return (int)Math.Round((deepest + 1) * 100.0 / KillChainOrder.Length);
    }

    private static int ComputeTempo(List<AttackerSignal> batch, DateTimeOffset now)
    {
        var window = TimeSpan.FromHours(1);
        var cutoff = now - window;
        int recent = batch.Count(s => (s.ObservedAt ?? now) >= cutoff);
        return recent;
    }

    // ── Hunts ───────────────────────────────────────────────────

    private static List<HuntFocus> BuildHunts(
        AttackerArchetype primary,
        List<AttackerSignal> batch,
        ProfileContext ctx)
    {
        var hunts = new List<HuntFocus>();
        var seen = batch.Select(s => s.Tactic).ToHashSet();

        void Add(string code, string q, ActionPriority p, Tactic[] tactics, string expected) =>
            hunts.Add(new HuntFocus(code, q, p, tactics.Select(t => t.ToString()).ToList(), expected));

        switch (primary)
        {
            case AttackerArchetype.RansomwareOperator:
                Add("HUNT_VSS_DELETION",
                    "Search last 24h for vssadmin/wbadmin shadow-copy deletions on any host.",
                    ActionPriority.P0,
                    new[] { Tactic.Impact, Tactic.DefenseEvasion },
                    "Process creation of vssadmin.exe with 'delete shadows'.");
                Add("HUNT_LATERAL_SMB",
                    "List SMB writes between workstations in last 6h sorted by file count.",
                    ActionPriority.P0,
                    new[] { Tactic.LateralMovement },
                    "Burst of unsigned-host SMB writes to ADMIN$/C$.");
                Add("HUNT_RANSOM_NOTE",
                    "File-create events for *README*ransom*, *_HOW_TO_DECRYPT*, .txt next to mass-renamed files.",
                    ActionPriority.P1,
                    new[] { Tactic.Impact },
                    "Note files created next to recently-modified user docs.");
                break;
            case AttackerArchetype.AptNationState:
                Add("HUNT_BEACON_INTERVAL",
                    "Outbound connections with jittered, near-periodic timing (low-variance interval).",
                    ActionPriority.P0,
                    new[] { Tactic.CommandAndControl },
                    "Repeating beacons to a single rare destination.");
                Add("HUNT_LIVING_OFF_LAND",
                    "Recent use of certutil / bitsadmin / mshta / rundll32 with web URLs.",
                    ActionPriority.P0,
                    new[] { Tactic.DefenseEvasion, Tactic.Execution },
                    "LOLBin downloaders.");
                Add("HUNT_DPAPI",
                    "Access to DPAPI master keys or LSASS handles by non-system processes.",
                    ActionPriority.P1,
                    new[] { Tactic.CredentialAccess },
                    "Credential theft attempts.");
                break;
            case AttackerArchetype.InsiderThreat:
                Add("HUNT_DATA_EGRESS",
                    "Top users by outbound byte volume in last 7 days, ranked vs personal baseline.",
                    ActionPriority.P0,
                    new[] { Tactic.Exfiltration },
                    "Outliers > 3x personal baseline.");
                Add("HUNT_USB_WRITES",
                    "Removable-device writes by users not on the allowlist.",
                    ActionPriority.P0,
                    new[] { Tactic.Collection, Tactic.Exfiltration },
                    "Bulk file copies to USB.");
                Add("HUNT_CLOUD_UPLOAD",
                    "Personal cloud uploads (Dropbox/GDrive/iCloud) > 100MB.",
                    ActionPriority.P1,
                    new[] { Tactic.Exfiltration },
                    "Personal-account exfil paths.");
                break;
            case AttackerArchetype.CommodityMalware:
                Add("HUNT_AUTORUN",
                    "New Run-key / scheduled-task entries created in last 24h not signed by trusted vendor.",
                    ActionPriority.P0,
                    new[] { Tactic.Persistence },
                    "Unsigned autostart entries.");
                Add("HUNT_C2",
                    "Outbound HTTPS to low-reputation destinations classified as C2 / RAT panels.",
                    ActionPriority.P1,
                    new[] { Tactic.CommandAndControl },
                    "RAT family hits in TI feed.");
                break;
            case AttackerArchetype.CryptoMiner:
                Add("HUNT_HIGH_CPU",
                    "Processes sustaining > 80% CPU for > 10 minutes off-hours.",
                    ActionPriority.P0,
                    new[] { Tactic.Impact, Tactic.Execution },
                    "Miner workloads.");
                Add("HUNT_STRATUM",
                    "Outbound connections to stratum+tcp / mining pool ports (3333/5555/7777/14444).",
                    ActionPriority.P0,
                    new[] { Tactic.CommandAndControl },
                    "Stratum protocol fingerprint.");
                break;
            case AttackerArchetype.AutomatedScanner:
                Add("HUNT_PORT_SWEEP",
                    "Single source IP touching > 50 unique destination ports / 10 minutes.",
                    ActionPriority.P0,
                    new[] { Tactic.Reconnaissance },
                    "Port-sweep pattern.");
                Add("HUNT_AUTH_FAILS",
                    "Login failures grouped by source IP for last 24h, ranked by unique-user count.",
                    ActionPriority.P1,
                    new[] { Tactic.InitialAccess },
                    "Credential stuffing fingerprint.");
                break;
            case AttackerArchetype.RedTeam:
                Add("HUNT_REDTEAM_TAGS",
                    "Confirm engagement window, scope, and authorised operator handles.",
                    ActionPriority.P1,
                    new[] { Tactic.Other },
                    "Engagement letter.");
                Add("HUNT_OUT_OF_SCOPE",
                    "Any TTPs touching hosts outside red-team scope - those are real incidents.",
                    ActionPriority.P0,
                    new[] { Tactic.LateralMovement, Tactic.Collection },
                    "Out-of-scope movement = treat as real.");
                break;
            case AttackerArchetype.ScriptKiddie:
                Add("HUNT_PUBLIC_EXPLOIT",
                    "Look for use of recent public PoC payloads against externally-facing services.",
                    ActionPriority.P1,
                    new[] { Tactic.InitialAccess },
                    "PoC fingerprints in WAF / EDR.");
                break;
        }

        // Generic hunts based on gaps.
        if (seen.Contains(Tactic.CredentialAccess) && !seen.Contains(Tactic.LateralMovement))
        {
            Add("HUNT_PRE_LATERAL",
                "Watch for first lateral move - cred theft often precedes it within hours.",
                ActionPriority.P1,
                new[] { Tactic.LateralMovement },
                "First east-west auth attempt by the compromised account.");
        }
        if (seen.Contains(Tactic.Collection) && !seen.Contains(Tactic.Exfiltration))
        {
            Add("HUNT_PRE_EXFIL",
                "Collection observed without exfil - hunt for staging archives (rar/7z/zip > 50MB) in temp dirs.",
                ActionPriority.P0,
                new[] { Tactic.Exfiltration },
                "Recently-created large archives.");
        }

        // Risk-appetite tightening.
        if (ctx.Risk == RiskAppetite.Aggressive)
        {
            hunts = hunts.Where(h => h.Priority != ActionPriority.P2 && h.Priority != ActionPriority.P3).ToList();
        }

        return hunts;
    }

    // ── Containments ────────────────────────────────────────────

    private static List<ContainmentAction> BuildContainments(
        ArchetypeCandidate primary,
        List<AttackerSignal> batch,
        ProfileContext ctx)
    {
        var actions = new List<ContainmentAction>();
        void Add(string code, string headline, ActionPriority p, string owner, int blast, string rev, string reason) =>
            actions.Add(new ContainmentAction(code, headline, p, owner, blast, rev, reason));

        switch (primary.Archetype)
        {
            case AttackerArchetype.RansomwareOperator:
                Add("ISOLATE_AFFECTED_HOSTS",
                    "Network-isolate hosts with Impact-stage signals immediately.",
                    ActionPriority.P0, "soc", 4, "medium",
                    "Stop encryption from spreading laterally.");
                Add("DISABLE_SMB_LATERAL",
                    "Block SMB workstation-to-workstation in firewall, leave servers-only.",
                    ActionPriority.P0, "it", 3, "high",
                    "Cut the most common ransomware lateral path.");
                Add("FREEZE_BACKUPS",
                    "Pause backup write-window and verify last clean offsite snapshot.",
                    ActionPriority.P0, "it", 2, "high",
                    "Protect restore points from being encrypted.");
                Add("NOTIFY_LEADERSHIP",
                    "Open executive incident bridge; engage legal + comms.",
                    ActionPriority.P1, "leadership", 2, "high",
                    "Ransom is a business-level event.");
                break;
            case AttackerArchetype.AptNationState:
                Add("COLLECT_FORENSICS_FIRST",
                    "Do NOT reimage yet - snapshot memory + disk on suspect hosts first.",
                    ActionPriority.P0, "soc", 2, "high",
                    "APTs leave volatile artifacts; reimage loses attribution.");
                Add("ROTATE_PRIV_CREDS",
                    "Rotate domain admin + service-account credentials with staged kerb-tgt reset.",
                    ActionPriority.P0, "it", 4, "low",
                    "APTs persist via stolen creds; rotation evicts.");
                Add("SEGMENT_CROWN_JEWELS",
                    "Tighten ACLs around sensitive data stores and require step-up auth.",
                    ActionPriority.P1, "it", 3, "high",
                    "Limit blast radius while hunt continues.");
                break;
            case AttackerArchetype.InsiderThreat:
                Add("DLP_HOLD",
                    "Place subject user on DLP hold; queue outbound to manual review.",
                    ActionPriority.P0, "soc", 2, "high",
                    "Stop further exfil without tipping subject off.");
                Add("HR_LEGAL_LOOP",
                    "Loop HR + legal before any access change - chain-of-custody matters.",
                    ActionPriority.P0, "hr", 2, "high",
                    "Insider cases live or die on evidence handling.");
                Add("PRESERVE_ENDPOINT",
                    "Image subject endpoint; preserve sent items / browser history.",
                    ActionPriority.P1, "soc", 1, "high",
                    "Evidence preservation for HR / legal.");
                break;
            case AttackerArchetype.CommodityMalware:
                Add("QUARANTINE_HOST",
                    "EDR quarantine affected host; run full AV sweep after.",
                    ActionPriority.P0, "soc", 3, "high",
                    "Stop further C2 + persistence growth.");
                Add("REMOVE_PERSISTENCE",
                    "Clean autostart entries + scheduled tasks created in last 7 days.",
                    ActionPriority.P1, "soc", 2, "high",
                    "Standard commodity malware persistence cleanup.");
                break;
            case AttackerArchetype.CryptoMiner:
                Add("KILL_MINER_PROCESS",
                    "Terminate offending process and block its hashes / parent binaries.",
                    ActionPriority.P0, "soc", 2, "high",
                    "Stop CPU drain immediately.");
                Add("BLOCK_STRATUM_EGRESS",
                    "Egress-block known stratum ports for non-server VLANs.",
                    ActionPriority.P1, "it", 2, "high",
                    "Prevent re-infection.");
                break;
            case AttackerArchetype.AutomatedScanner:
                Add("RATE_LIMIT_INGRESS",
                    "Apply per-source rate-limit on external services; geo-block if relevant.",
                    ActionPriority.P1, "it", 2, "high",
                    "Noisy automation: rate-limit suffices for most.");
                Add("PATCH_EXPOSED",
                    "Audit & patch any service the scanner targeted that is internet-facing.",
                    ActionPriority.P1, "it", 2, "high",
                    "Scanner findings often precede targeted exploit.");
                break;
            case AttackerArchetype.RedTeam:
                Add("CONFIRM_SCOPE",
                    "Verify engagement-letter scope before acting on signals.",
                    ActionPriority.P1, "leadership", 1, "high",
                    "Don't burn red-team budget with premature containment.");
                Add("LET_DETECTIONS_FIRE",
                    "Keep alerting on; capture full TTPs for blue-team retro.",
                    ActionPriority.P2, "soc", 1, "high",
                    "Red-team value lives in the after-action review.");
                break;
            case AttackerArchetype.ScriptKiddie:
                Add("BLOCK_SOURCE",
                    "Block source IP at edge; rotate public-facing creds touched.",
                    ActionPriority.P1, "it", 1, "high",
                    "Low-skill actor - perimeter hardening usually suffices.");
                break;
        }

        // Sensitive-data presence promotes ContainsSensitiveData scenarios.
        if (ctx.ContainsSensitiveData &&
            (primary.Archetype == AttackerArchetype.RansomwareOperator ||
             primary.Archetype == AttackerArchetype.InsiderThreat ||
             primary.Archetype == AttackerArchetype.AptNationState))
        {
            Add("ENGAGE_DATA_OWNER",
                "Notify data-classification owner so impact assessment can start in parallel.",
                ActionPriority.P0, "leadership", 1, "high",
                "Sensitive data implicated - regulatory clock may have started.");
        }

        // Active red-team window suppresses destructive containment.
        if (ctx.ActiveRedTeamWindow && primary.Archetype != AttackerArchetype.RedTeam)
        {
            actions = actions.Where(a => a.BlastRadius <= 2 || a.Owner == "leadership").ToList();
        }

        // Risk-appetite tweaks.
        if (ctx.Risk == RiskAppetite.Cautious)
        {
            // Promote any P1 isolation-style action to P0.
            actions = actions.Select(a =>
                a.Priority == ActionPriority.P1 && a.Code.Contains("ISOLATE", StringComparison.OrdinalIgnoreCase)
                    ? a with { Priority = ActionPriority.P0 } : a).ToList();
        }
        else if (ctx.Risk == RiskAppetite.Aggressive)
        {
            actions = actions.Where(a => a.Priority != ActionPriority.P2 && a.Priority != ActionPriority.P3).ToList();
        }

        // Dedup by Code; preserve first occurrence priority.
        var seenCodes = new HashSet<string>();
        var ordered = new List<ContainmentAction>();
        foreach (var a in actions
                     .OrderBy(a => (int)a.Priority)
                     .ThenBy(a => a.Code, StringComparer.Ordinal))
        {
            if (seenCodes.Add(a.Code)) ordered.Add(a);
        }

        return ordered;
    }

    // ── Insights & grade ────────────────────────────────────────

    private static List<ProfileInsight> BuildInsights(
        ArchetypeCandidate primary,
        List<AttackerSignal> batch,
        int killChainPct,
        int tempo,
        ProfileContext ctx)
    {
        var insights = new List<ProfileInsight>();

        if (killChainPct >= 80)
            insights.Add(new ProfileInsight(
                "DEEP_KILL_CHAIN",
                $"Attacker has progressed to {killChainPct}% of the kill chain (Impact / Exfil).",
                ActionPriority.P0));
        else if (killChainPct >= 50)
            insights.Add(new ProfileInsight(
                "MID_KILL_CHAIN",
                $"Attacker is at {killChainPct}% of kill chain - past discovery, moving toward objective.",
                ActionPriority.P1));

        if (tempo >= 10)
            insights.Add(new ProfileInsight(
                "HIGH_TEMPO",
                $"High signal tempo: {tempo} TTPs/hour - likely hands-on-keyboard.",
                ActionPriority.P0));

        var sourceFan = batch.Select(s => s.Source).Distinct().Count();
        if (sourceFan >= 4)
            insights.Add(new ProfileInsight(
                "MULTI_DETECTOR_FAN",
                $"Activity surfaced by {sourceFan} different detectors - high cross-corroboration.",
                ActionPriority.P1));

        if (primary.Band == ConfidenceBand.Low)
            insights.Add(new ProfileInsight(
                "AMBIGUOUS_PROFILE",
                "Top archetype confidence is low - treat playbook as exploratory and gather more signal.",
                ActionPriority.P2));

        if (ctx.ContainsSensitiveData &&
            primary.Archetype is AttackerArchetype.RansomwareOperator
                or AttackerArchetype.InsiderThreat
                or AttackerArchetype.AptNationState)
            insights.Add(new ProfileInsight(
                "REGULATORY_CLOCK",
                "Sensitive data is in scope - regulatory notification deadlines may apply.",
                ActionPriority.P0));

        if (ctx.ActiveRedTeamWindow && primary.Archetype != AttackerArchetype.RedTeam)
            insights.Add(new ProfileInsight(
                "REDTEAM_WINDOW_MISMATCH",
                "Red-team window is active but profile is not RedTeam - validate scope before containment.",
                ActionPriority.P1));

        return insights;
    }

    private static string ComputeGrade(
        ArchetypeCandidate primary,
        int killChainPct,
        List<AttackerSignal> batch)
    {
        // Grade reflects defender posture risk implied by the profile.
        if (primary.Archetype == AttackerArchetype.Unknown) return "A";
        if (killChainPct >= 90 || primary.Archetype == AttackerArchetype.RansomwareOperator && killChainPct >= 60)
            return "F";
        if (killChainPct >= 70) return "D";
        if (killChainPct >= 50) return "C";
        if (batch.Count >= 10) return "C";
        if (killChainPct >= 30) return "B";
        return "A";
    }

    // ── Formatters ─────────────────────────────────────────────

    private static string Pretty(AttackerArchetype a) => a switch
    {
        AttackerArchetype.CommodityMalware => "Commodity malware",
        AttackerArchetype.RansomwareOperator => "Ransomware operator",
        AttackerArchetype.AptNationState => "APT / nation-state",
        AttackerArchetype.InsiderThreat => "Insider threat",
        AttackerArchetype.RedTeam => "Red team",
        AttackerArchetype.AutomatedScanner => "Automated scanner",
        AttackerArchetype.CryptoMiner => "Crypto miner",
        AttackerArchetype.ScriptKiddie => "Script kiddie",
        _ => "Unknown",
    };

    /// <summary>Plain-text rendering of the profile.</summary>
    public string FormatText(AttackerProfile p)
    {
        ArgumentNullException.ThrowIfNull(p);
        var sb = new StringBuilder();
        sb.AppendLine($"ATTACKER PROFILE - Grade {p.Grade}");
        sb.AppendLine(p.Headline);
        sb.AppendLine($"Generated: {p.GeneratedAt:u}");
        sb.AppendLine(new string('-', 60));
        sb.AppendLine($"Primary: {Pretty(p.PrimaryArchetype)}  ({p.PrimaryConfidence}%, {p.PrimaryBand})");
        sb.AppendLine($"Kill-chain progression: {p.KillChainProgressionPct}%   Tempo: {p.TempoSignalsPerHour}/hr");
        sb.AppendLine();
        sb.AppendLine("Candidates:");
        foreach (var c in p.Candidates)
        {
            sb.AppendLine($"  - {Pretty(c.Archetype),-22} {c.Score,3}% ({c.Band})");
            if (c.SupportingTactics.Count > 0)
                sb.AppendLine($"      tactics: {string.Join(", ", c.SupportingTactics)}");
        }
        if (p.Hunts.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Hunts:");
            foreach (var h in p.Hunts)
            {
                sb.AppendLine($"  [{h.Priority}] {h.Code}: {h.Question}");
                sb.AppendLine($"        expect: {h.ExpectedSignal}");
            }
        }
        if (p.Containments.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Containment:");
            foreach (var a in p.Containments)
            {
                sb.AppendLine($"  [{a.Priority}] {a.Code} (owner={a.Owner}, blast={a.BlastRadius}, rev={a.Reversibility})");
                sb.AppendLine($"        {a.Headline}");
                sb.AppendLine($"        why: {a.Reason}");
            }
        }
        if (p.Insights.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Insights:");
            foreach (var i in p.Insights)
                sb.AppendLine($"  * [{i.Severity}] {i.Code}: {i.Headline}");
        }
        return sb.ToString();
    }

    /// <summary>Markdown rendering of the profile.</summary>
    public string FormatMarkdown(AttackerProfile p)
    {
        ArgumentNullException.ThrowIfNull(p);
        var sb = new StringBuilder();
        sb.AppendLine("# Attacker Profile");
        sb.AppendLine();
        sb.AppendLine($"**Grade:** {p.Grade}  ");
        sb.AppendLine($"**Headline:** {p.Headline}  ");
        sb.AppendLine($"**Primary:** {Pretty(p.PrimaryArchetype)} ({p.PrimaryConfidence}%, {p.PrimaryBand})  ");
        sb.AppendLine($"**Kill-chain:** {p.KillChainProgressionPct}%  &nbsp; **Tempo:** {p.TempoSignalsPerHour}/hr  ");
        sb.AppendLine($"**Generated:** {p.GeneratedAt:u}");
        sb.AppendLine();
        sb.AppendLine("## Candidates");
        sb.AppendLine();
        sb.AppendLine("| Archetype | Confidence | Band | Supporting tactics |");
        sb.AppendLine("|-----------|-----------:|------|--------------------|");
        foreach (var c in p.Candidates)
            sb.AppendLine($"| {Pretty(c.Archetype)} | {c.Score}% | {c.Band} | {string.Join(", ", c.SupportingTactics)} |");

        if (p.Hunts.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Hunts");
            sb.AppendLine();
            foreach (var h in p.Hunts)
                sb.AppendLine($"- **[{h.Priority}] {h.Code}** — {h.Question} _Expect:_ {h.ExpectedSignal}");
        }
        if (p.Containments.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Containment");
            sb.AppendLine();
            sb.AppendLine("| Priority | Code | Owner | Blast | Reversibility | Action |");
            sb.AppendLine("|----------|------|-------|------:|--------------:|--------|");
            foreach (var a in p.Containments)
                sb.AppendLine($"| {a.Priority} | {a.Code} | {a.Owner} | {a.BlastRadius} | {a.Reversibility} | {a.Headline} |");
        }
        if (p.Insights.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("## Insights");
            sb.AppendLine();
            foreach (var i in p.Insights)
                sb.AppendLine($"- **[{i.Severity}] {i.Code}** — {i.Headline}");
        }
        return sb.ToString();
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>JSON rendering of the profile (deterministic with fixed NowOverride).</summary>
    public string FormatJson(AttackerProfile p)
    {
        ArgumentNullException.ThrowIfNull(p);
        return JsonSerializer.Serialize(p, JsonOpts);
    }
}
