using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Chains audit findings into multi-step attack paths that model how an
/// attacker could traverse the MITRE ATT&amp;CK kill chain on this system.
///
/// <para>Where <see cref="MitreAttackMapper"/> maps individual findings to
/// ATT&amp;CK techniques, this analyzer connects those techniques into
/// realistic attack <em>paths</em> — ordered sequences of stages an
/// adversary would follow (Initial Access → Execution → Persistence →
/// Privilege Escalation → Lateral Movement → Exfiltration).</para>
///
/// <para>Each path is scored by likelihood and impact, and the analyzer
/// identifies <strong>chokepoint findings</strong> — the findings whose
/// remediation would break the most attack paths.</para>
///
/// <h3>Usage:</h3>
/// <code>
/// var mapper = new MitreAttackMapper();
/// var attackReport = mapper.Analyze(securityReport);
/// var pathAnalyzer = new AttackPathAnalyzer();
/// var result = pathAnalyzer.Analyze(securityReport, attackReport);
/// Console.WriteLine(result.Summary);
/// </code>
/// </summary>
public class AttackPathAnalyzer
{
    // ── Attack stage definitions ─────────────────────────────────

    /// <summary>
    /// Canonical stages of a kill chain attack path, ordered by progression.
    /// </summary>
    public enum AttackStage
    {
        InitialAccess = 0,
        Execution = 1,
        Persistence = 2,
        PrivilegeEscalation = 3,
        LateralMovement = 4,
        Exfiltration = 5
    }

    /// <summary>
    /// Maps MITRE ATT&amp;CK tactics to canonical attack stages.
    /// Multiple tactics may map to the same stage.
    /// </summary>
    private static readonly Dictionary<AttackTactic, AttackStage> TacticToStage = new()
    {
        [AttackTactic.InitialAccess] = AttackStage.InitialAccess,
        [AttackTactic.Reconnaissance] = AttackStage.InitialAccess,
        [AttackTactic.Execution] = AttackStage.Execution,
        [AttackTactic.CommandAndControl] = AttackStage.Execution,
        [AttackTactic.Persistence] = AttackStage.Persistence,
        [AttackTactic.DefenseEvasion] = AttackStage.Persistence,
        [AttackTactic.PrivilegeEscalation] = AttackStage.PrivilegeEscalation,
        [AttackTactic.CredentialAccess] = AttackStage.PrivilegeEscalation,
        [AttackTactic.Discovery] = AttackStage.LateralMovement,
        [AttackTactic.LateralMovement] = AttackStage.LateralMovement,
        [AttackTactic.Collection] = AttackStage.Exfiltration,
        [AttackTactic.Exfiltration] = AttackStage.Exfiltration,
        [AttackTactic.Impact] = AttackStage.Exfiltration,
    };

    /// <summary>Stage display names.</summary>
    private static readonly Dictionary<AttackStage, string> StageNames = new()
    {
        [AttackStage.InitialAccess] = "Initial Access",
        [AttackStage.Execution] = "Execution",
        [AttackStage.Persistence] = "Persistence",
        [AttackStage.PrivilegeEscalation] = "Privilege Escalation",
        [AttackStage.LateralMovement] = "Lateral Movement",
        [AttackStage.Exfiltration] = "Exfiltration",
    };

    // ── Category → stage mapping (finding-level, no MITRE needed) ──

    /// <summary>
    /// Maps finding categories to attack stages for findings that may not
    /// have a MITRE mapping. This catches common audit categories.
    /// </summary>
    private static readonly Dictionary<string, AttackStage> CategoryStageMap =
        new(StringComparer.OrdinalIgnoreCase)
    {
        // Initial Access
        ["Firewall"] = AttackStage.InitialAccess,
        ["Network"] = AttackStage.InitialAccess,
        ["WiFi"] = AttackStage.InitialAccess,
        ["RemoteAccess"] = AttackStage.InitialAccess,
        ["RDP"] = AttackStage.InitialAccess,
        ["Bluetooth"] = AttackStage.InitialAccess,
        ["SMB"] = AttackStage.InitialAccess,
        // Execution
        ["PowerShell"] = AttackStage.Execution,
        ["Application"] = AttackStage.Execution,
        ["Browser"] = AttackStage.Execution,
        ["Drivers"] = AttackStage.Execution,
        // Persistence
        ["Startup"] = AttackStage.Persistence,
        ["ScheduledTasks"] = AttackStage.Persistence,
        ["Services"] = AttackStage.Persistence,
        ["Registry"] = AttackStage.Persistence,
        // Privilege Escalation
        ["Accounts"] = AttackStage.PrivilegeEscalation,
        ["Credentials"] = AttackStage.PrivilegeEscalation,
        ["Certificate"] = AttackStage.PrivilegeEscalation,
        ["GroupPolicy"] = AttackStage.PrivilegeEscalation,
        // Lateral Movement
        ["DNS"] = AttackStage.LateralMovement,
        ["WinRM"] = AttackStage.LateralMovement,
        // Exfiltration
        ["Privacy"] = AttackStage.Exfiltration,
        ["Encryption"] = AttackStage.Exfiltration,
        ["Backup"] = AttackStage.Exfiltration,
    };

    // ── Result models ────────────────────────────────────────────

    /// <summary>
    /// A single step in an attack path, backed by a real finding.
    /// </summary>
    public class AttackStep
    {
        /// <summary>Attack stage this step belongs to.</summary>
        public required AttackStage Stage { get; init; }

        /// <summary>Human-readable stage name.</summary>
        public string StageName => StageNames.GetValueOrDefault(Stage, Stage.ToString());

        /// <summary>The finding that enables this step.</summary>
        public required Finding Finding { get; init; }

        /// <summary>MITRE technique ID (if mapped).</summary>
        public string? TechniqueId { get; init; }

        /// <summary>MITRE technique name (if mapped).</summary>
        public string? TechniqueName { get; init; }

        /// <summary>Source audit module.</summary>
        public required string Module { get; init; }
    }

    /// <summary>
    /// A complete multi-step attack path from initial access to objective.
    /// </summary>
    public class AttackPath
    {
        /// <summary>Ordered steps in this path.</summary>
        public List<AttackStep> Steps { get; init; } = new();

        /// <summary>Path name describing the scenario.</summary>
        public required string Name { get; init; }

        /// <summary>Brief description of the attack scenario.</summary>
        public required string Description { get; init; }

        /// <summary>Number of distinct stages covered.</summary>
        public int StagesCovered => Steps.Select(s => s.Stage).Distinct().Count();

        /// <summary>
        /// Exploitability score (0–100). Longer paths that span more stages
        /// with higher-severity findings score higher.
        /// </summary>
        public double ExploitabilityScore { get; set; }

        /// <summary>Risk level derived from exploitability score.</summary>
        public string RiskLevel => ExploitabilityScore switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 40 => "Medium",
            >= 20 => "Low",
            _ => "Minimal"
        };

        /// <summary>Highest severity among all steps.</summary>
        public Severity HighestSeverity =>
            Steps.Count > 0 ? Steps.Max(s => s.Finding.Severity) : Severity.Pass;
    }

    /// <summary>
    /// A finding that appears in multiple attack paths — a remediation
    /// chokepoint. Fixing it breaks the most paths.
    /// </summary>
    public class Chokepoint
    {
        /// <summary>The finding.</summary>
        public required Finding Finding { get; init; }

        /// <summary>Source module.</summary>
        public required string Module { get; init; }

        /// <summary>How many attack paths this finding appears in.</summary>
        public int PathCount { get; set; }

        /// <summary>Sum of exploitability scores of paths it appears in.</summary>
        public double TotalRiskReduced { get; set; }

        /// <summary>Priority rank (1 = fix first).</summary>
        public int Priority { get; set; }
    }

    /// <summary>
    /// Full attack path analysis result.
    /// </summary>
    public class AttackPathReport
    {
        public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

        /// <summary>All discovered attack paths, sorted by exploitability (descending).</summary>
        public List<AttackPath> Paths { get; init; } = new();

        /// <summary>Top chokepoints — fix these to break the most paths.</summary>
        public List<Chokepoint> Chokepoints { get; init; } = new();

        /// <summary>Per-stage finding counts.</summary>
        public Dictionary<string, int> StageBreakdown { get; init; } = new();

        /// <summary>Total findings analysed.</summary>
        public int TotalFindings { get; set; }

        /// <summary>Total findings that contributed to at least one path.</summary>
        public int FindingsInPaths { get; set; }

        /// <summary>Highest exploitability score across all paths.</summary>
        public double MaxExploitability =>
            Paths.Count > 0 ? Paths.Max(p => p.ExploitabilityScore) : 0;

        /// <summary>Overall risk level.</summary>
        public string OverallRisk => MaxExploitability switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 40 => "Medium",
            >= 20 => "Low",
            _ => "Minimal"
        };

        /// <summary>Human-readable summary.</summary>
        public string Summary
        {
            get
            {
                if (Paths.Count == 0)
                    return "No multi-stage attack paths detected. Your security posture blocks kill chain progression.";

                var critical = Paths.Count(p => p.RiskLevel == "Critical");
                var high = Paths.Count(p => p.RiskLevel == "High");
                return $"Detected {Paths.Count} attack path(s) ({critical} critical, {high} high risk). " +
                       $"Top chokepoint: \"{Chokepoints.FirstOrDefault()?.Finding.Title ?? "none"}\" " +
                       $"(appears in {Chokepoints.FirstOrDefault()?.PathCount ?? 0} path(s)). " +
                       $"Overall risk: {OverallRisk}.";
            }
        }
    }

    // ── Analysis ─────────────────────────────────────────────────

    /// <summary>
    /// Analyse a security report and its MITRE mapping to discover attack paths.
    /// </summary>
    /// <param name="report">The security audit report.</param>
    /// <param name="attackReport">
    /// Optional MITRE ATT&amp;CK mapping report. If null, findings are
    /// classified by category alone.
    /// </param>
    /// <returns>Attack path analysis report.</returns>
    public AttackPathReport Analyze(SecurityReport report, AttackReport? attackReport = null)
    {
        // 1. Classify all actionable findings into attack stages
        var stageFindings = ClassifyFindings(report, attackReport);

        // 2. Build attack paths by chaining stages
        var paths = BuildPaths(stageFindings);

        // 3. Score each path
        foreach (var path in paths) ScorePath(path);
        paths.Sort((a, b) => b.ExploitabilityScore.CompareTo(a.ExploitabilityScore));

        // 4. Identify chokepoints
        var chokepoints = FindChokepoints(paths);

        // 5. Stage breakdown
        var breakdown = new Dictionary<string, int>();
        foreach (var stage in Enum.GetValues<AttackStage>())
        {
            var name = StageNames.GetValueOrDefault(stage, stage.ToString());
            breakdown[name] = stageFindings.GetValueOrDefault(stage)?.Count ?? 0;
        }

        var findingsInPaths = paths
            .SelectMany(p => p.Steps)
            .Select(s => s.Finding.Title)
            .Distinct()
            .Count();

        return new AttackPathReport
        {
            Paths = paths,
            Chokepoints = chokepoints,
            StageBreakdown = breakdown,
            TotalFindings = report.TotalFindings,
            FindingsInPaths = findingsInPaths,
        };
    }

    // ── Stage classification ─────────────────────────────────────

    private Dictionary<AttackStage, List<AttackStep>> ClassifyFindings(
        SecurityReport report, AttackReport? attackReport)
    {
        var result = new Dictionary<AttackStage, List<AttackStep>>();

        // Build a lookup from finding title → technique for MITRE-mapped findings
        var mitreLookup = new Dictionary<string, (string Id, string Name, AttackTactic Tactic)>(
            StringComparer.OrdinalIgnoreCase);

        if (attackReport != null)
        {
            foreach (var tactic in attackReport.TacticExposures)
            foreach (var tech in tactic.Techniques)
            {
                // The technique summary doesn't carry individual finding titles,
                // so we rely on tactic-level mapping as a hint.
                // We'll match by tactic when a finding's category matches.
            }
        }

        foreach (var auditResult in report.Results)
        foreach (var finding in auditResult.Findings)
        {
            // Skip passed/info findings — they're not exploitable
            if (finding.Severity < Severity.Warning) continue;

            AttackStage? stage = null;
            string? techId = null;
            string? techName = null;

            // Try MITRE tactic → stage mapping if attack report is available
            if (attackReport != null)
            {
                foreach (var tacticExposure in attackReport.TacticExposures)
                {
                    if (TacticToStage.TryGetValue(tacticExposure.Tactic, out var mappedStage))
                    {
                        // Check if this finding's category matches any technique in this tactic
                        foreach (var tech in tacticExposure.Techniques)
                        {
                            if (CategoryMatchesTechnique(auditResult.Category, finding, tech))
                            {
                                stage = mappedStage;
                                techId = tech.TechniqueId;
                                techName = tech.TechniqueName;
                                break;
                            }
                        }
                    }
                    if (stage.HasValue) break;
                }
            }

            // Fallback: category → stage mapping
            if (!stage.HasValue && CategoryStageMap.TryGetValue(auditResult.Category, out var catStage))
            {
                stage = catStage;
            }

            // Also try finding's own category field
            if (!stage.HasValue && !string.IsNullOrEmpty(finding.Category) &&
                CategoryStageMap.TryGetValue(finding.Category, out var findCatStage))
            {
                stage = findCatStage;
            }

            if (!stage.HasValue) continue; // Can't classify — skip

            if (!result.ContainsKey(stage.Value))
                result[stage.Value] = new List<AttackStep>();

            result[stage.Value].Add(new AttackStep
            {
                Stage = stage.Value,
                Finding = finding,
                TechniqueId = techId,
                TechniqueName = techName,
                Module = auditResult.ModuleName,
            });
        }

        return result;
    }

    private static bool CategoryMatchesTechnique(string category, Finding finding, TechniqueSummary tech)
    {
        // Match by category or finding title containing part of technique name
        var techLower = tech.TechniqueName.ToLowerInvariant();
        var catLower = category.ToLowerInvariant();
        var titleLower = finding.Title.ToLowerInvariant();

        // Direct substring matches
        if (techLower.Contains(catLower) || catLower.Contains(techLower)) return true;

        // Split technique name into words and check if any appear in the title
        var techWords = techLower.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int matches = techWords.Count(w => w.Length > 3 && titleLower.Contains(w));
        return matches >= 2; // At least 2 significant words match
    }

    // ── Path building ────────────────────────────────────────────

    /// <summary>
    /// Builds attack paths by combining findings across consecutive stages.
    /// A valid path needs at least 2 stages. Paths are built greedily:
    /// for each initial-access finding, extend through subsequent stages.
    /// </summary>
    private static List<AttackPath> BuildPaths(Dictionary<AttackStage, List<AttackStep>> stageFindings)
    {
        var paths = new List<AttackPath>();
        var stages = Enum.GetValues<AttackStage>().OrderBy(s => (int)s).ToArray();

        // Find the earliest populated stage
        int startIdx = -1;
        for (int i = 0; i < stages.Length; i++)
        {
            if (stageFindings.ContainsKey(stages[i]) && stageFindings[stages[i]].Count > 0)
            {
                startIdx = i;
                break;
            }
        }

        if (startIdx < 0) return paths;

        var entrySteps = stageFindings[stages[startIdx]];

        // For each entry point, try to build the longest path
        foreach (var entry in entrySteps)
        {
            var pathSteps = new List<AttackStep> { entry };

            // Greedily extend to subsequent stages
            for (int i = startIdx + 1; i < stages.Length; i++)
            {
                if (!stageFindings.TryGetValue(stages[i], out var candidates) ||
                    candidates.Count == 0)
                    continue;

                // Pick the highest-severity finding at this stage
                var best = candidates
                    .OrderByDescending(s => s.Finding.Severity)
                    .ThenByDescending(s => s.TechniqueId != null ? 1 : 0)
                    .First();

                pathSteps.Add(best);
            }

            // Only keep paths with ≥ 2 distinct stages
            if (pathSteps.Select(s => s.Stage).Distinct().Count() < 2) continue;

            var (name, desc) = GeneratePathNarrative(pathSteps);

            paths.Add(new AttackPath
            {
                Name = name,
                Description = desc,
                Steps = pathSteps,
            });
        }

        // Deduplicate paths with identical step titles
        var seen = new HashSet<string>();
        var deduped = new List<AttackPath>();
        foreach (var path in paths)
        {
            var key = string.Join("|", path.Steps.Select(s => s.Finding.Title));
            if (seen.Add(key)) deduped.Add(path);
        }

        return deduped;
    }

    private static (string Name, string Description) GeneratePathNarrative(List<AttackStep> steps)
    {
        var entry = steps[0];
        var final = steps[^1];

        var name = $"{entry.StageName} via {Shorten(entry.Finding.Title)} → {final.StageName}";

        var stageNames = steps.Select(s => s.StageName).Distinct();
        var desc = $"Attacker chains {steps.Count} step(s) across {string.Join(" → ", stageNames)}. " +
                   $"Entry: {entry.Finding.Title}. " +
                   $"Objective: {final.Finding.Title}.";

        return (name, desc);
    }

    private static string Shorten(string text) =>
        text.Length <= 40 ? text : text[..37] + "...";

    // ── Scoring ──────────────────────────────────────────────────

    private static void ScorePath(AttackPath path)
    {
        if (path.Steps.Count == 0) { path.ExploitabilityScore = 0; return; }

        // Factors:
        // 1. Stage coverage (more stages = more dangerous) — 40% weight
        double stageCoverage = path.StagesCovered / 6.0;

        // 2. Average severity of steps — 35% weight
        double avgSeverity = path.Steps.Average(s => (int)s.Finding.Severity) / 3.0;

        // 3. Has critical findings — 15% weight
        double hasCritical = path.Steps.Any(s => s.Finding.Severity == Severity.Critical) ? 1.0 : 0.0;

        // 4. Path length bonus (longer paths = more complete attack) — 10% weight
        double lengthBonus = Math.Min(path.Steps.Count / 6.0, 1.0);

        path.ExploitabilityScore = Math.Round(
            (stageCoverage * 0.40 + avgSeverity * 0.35 + hasCritical * 0.15 + lengthBonus * 0.10) * 100,
            1);
    }

    // ── Chokepoint analysis ──────────────────────────────────────

    private static List<Chokepoint> FindChokepoints(List<AttackPath> paths)
    {
        // Count how many paths each finding appears in
        var findingPaths = new Dictionary<string, (Finding Finding, string Module, double TotalRisk, int Count)>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var path in paths)
        foreach (var step in path.Steps)
        {
            var key = step.Finding.Title;
            if (findingPaths.TryGetValue(key, out var existing))
            {
                findingPaths[key] = (existing.Finding, existing.Module,
                    existing.TotalRisk + path.ExploitabilityScore, existing.Count + 1);
            }
            else
            {
                findingPaths[key] = (step.Finding, step.Module, path.ExploitabilityScore, 1);
            }
        }

        var chokepoints = findingPaths.Values
            .Where(f => f.Count >= 1)
            .OrderByDescending(f => f.TotalRisk)
            .ThenByDescending(f => f.Count)
            .Select((f, i) => new Chokepoint
            {
                Finding = f.Finding,
                Module = f.Module,
                PathCount = f.Count,
                TotalRiskReduced = Math.Round(f.TotalRisk, 1),
                Priority = i + 1,
            })
            .Take(10)
            .ToList();

        return chokepoints;
    }
}
