using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Core.Services;

/// <summary>
/// Swarm Intelligence: multiple autonomous analyst agents collaborate
/// on a collective security assessment, each examining data from a
/// different perspective, then voting on consensus recommendations.
/// </summary>
public class SecuritySwarmIntelligence
{
    // ── Result types ─────────────────────────────────────────────────

    public record SwarmAgent(string Name, string Role, string Emoji);

    public record AgentInsight(string Finding, string Severity, double Confidence);

    public record AgentAnalysis(
        SwarmAgent Agent,
        List<AgentInsight> Insights,
        string Summary,
        double OverallConfidence);

    public record ConsensusItem(
        string Recommendation,
        double AgreementLevel,
        List<string> SupportingAgents,
        string Priority);

    public class SwarmReport
    {
        public List<AgentAnalysis> AgentAnalyses { get; init; } = [];
        public List<ConsensusItem> Consensus { get; init; } = [];
        public double CollectiveConfidence { get; init; }
        public string CollectiveVerdict { get; init; } = "";
        public List<string> Dissents { get; init; } = [];
        public Dictionary<string, int> VotingRecord { get; init; } = new();
    }

    // ── Agents ───────────────────────────────────────────────────────

    private static readonly SwarmAgent Sentinel = new("Sentinel", "Threat Hunter", "🛡️");
    private static readonly SwarmAgent Strategist = new("Strategist", "Pattern Analyst", "♟️");
    private static readonly SwarmAgent Historian = new("Historian", "Trend Analyst", "📜");
    private static readonly SwarmAgent Economist = new("Economist", "Cost Analyst", "💰");
    private static readonly SwarmAgent Contrarian = new("Contrarian", "Devil's Advocate", "🔥");
    private static readonly SwarmAgent Synthesizer = new("Synthesizer", "Consensus Builder", "🧠");

    private readonly AuditHistoryService _history;

    public SecuritySwarmIntelligence(AuditHistoryService historyService)
    {
        _history = historyService;
    }

    // ── Public API ───────────────────────────────────────────────────

    public SwarmReport Analyze(SecurityReport report, int historyDays = 30)
    {
        var history = _history.GetHistory(historyDays);
        var allFindings = report.Results.SelectMany(r => r.Findings).ToList();

        // Run each agent
        var sentinelAnalysis = RunSentinel(report, allFindings);
        var strategistAnalysis = RunStrategist(report, allFindings);
        var historianAnalysis = RunHistorian(report, allFindings, history);
        var economistAnalysis = RunEconomist(report, allFindings);
        var contrarianAnalysis = RunContrarian(report, allFindings);

        var allAgentResults = new List<AgentAnalysis>
        {
            sentinelAnalysis, strategistAnalysis, historianAnalysis,
            economistAnalysis, contrarianAnalysis
        };

        // Synthesizer combines everyone
        var synthesizerAnalysis = RunSynthesizer(allAgentResults, report);
        allAgentResults.Add(synthesizerAnalysis);

        // Build consensus
        var (consensus, votes, dissents) = BuildConsensus(allAgentResults);

        var collectiveConfidence = allAgentResults.Average(a => a.OverallConfidence);
        var verdict = collectiveConfidence >= 80 ? "LOW RISK — Swarm is confident in current posture"
            : collectiveConfidence >= 60 ? "MODERATE RISK — Swarm recommends targeted improvements"
            : collectiveConfidence >= 40 ? "HIGH RISK — Swarm urges prioritized remediation"
            : "CRITICAL RISK — Swarm demands immediate action";

        return new SwarmReport
        {
            AgentAnalyses = allAgentResults,
            Consensus = consensus,
            CollectiveConfidence = Math.Round(collectiveConfidence, 1),
            CollectiveVerdict = verdict,
            Dissents = dissents,
            VotingRecord = votes
        };
    }

    // ── Agent Implementations ────────────────────────────────────────

    private AgentAnalysis RunSentinel(SecurityReport report, List<Finding> findings)
    {
        var insights = new List<AgentInsight>();
        var criticals = findings.Where(f => f.Severity == Severity.Critical).ToList();
        var warnings = findings.Where(f => f.Severity == Severity.Warning).ToList();

        if (criticals.Count > 0)
        {
            insights.Add(new AgentInsight(
                $"{criticals.Count} critical finding(s) require immediate attention",
                "CRITICAL", 0.95));

            // Group criticals by category
            foreach (var group in criticals.GroupBy(f => f.Category).OrderByDescending(g => g.Count()))
            {
                insights.Add(new AgentInsight(
                    $"{group.Key}: {group.Count()} critical issue(s) — {group.First().Title}",
                    "CRITICAL", 0.9));
            }
        }

        if (warnings.Count > 0)
        {
            insights.Add(new AgentInsight(
                $"{warnings.Count} warning(s) across {warnings.Select(f => f.Category).Distinct().Count()} categories",
                "WARNING", 0.8));
        }

        // Module severity density
        foreach (var result in report.Results.OrderByDescending(r => r.CriticalCount).Take(3))
        {
            if (result.CriticalCount > 0)
                insights.Add(new AgentInsight(
                    $"{result.ModuleName} has highest severity density ({result.CriticalCount}C/{result.WarningCount}W)",
                    "HIGH", 0.85));
        }

        var urgencyScore = Math.Min(100, criticals.Count * 25 + warnings.Count * 5);
        var confidence = criticals.Count > 0 ? 90.0 : warnings.Count > 0 ? 70.0 : 95.0;
        var summary = criticals.Count > 0
            ? $"Urgent: {criticals.Count} critical threats detected. Immediate remediation required."
            : warnings.Count > 0
                ? $"Moderate threat level: {warnings.Count} warnings need attention."
                : "No active threats detected. Perimeter is secure.";

        return new AgentAnalysis(Sentinel, insights, summary, confidence);
    }

    private AgentAnalysis RunStrategist(SecurityReport report, List<Finding> findings)
    {
        var insights = new List<AgentInsight>();
        var nonPass = findings.Where(f => f.Severity != Severity.Pass).ToList();

        // Cross-module pattern analysis
        var categoryGroups = nonPass.GroupBy(f => f.Category).OrderByDescending(g => g.Count()).ToList();
        if (categoryGroups.Count > 0)
        {
            var topCategory = categoryGroups.First();
            insights.Add(new AgentInsight(
                $"Dominant weakness category: \"{topCategory.Key}\" ({topCategory.Count()} findings across modules)",
                "HIGH", 0.85));
        }

        // Find modules that share similar finding titles (pattern clusters)
        var titleWords = nonPass
            .SelectMany(f => f.Title.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(w => w.Length > 4)
            .GroupBy(w => w.ToLowerInvariant())
            .Where(g => g.Count() >= 3)
            .OrderByDescending(g => g.Count())
            .Take(3);

        foreach (var word in titleWords)
        {
            insights.Add(new AgentInsight(
                $"Recurring theme \"{word.Key}\" appears in {word.Count()} findings — systemic pattern",
                "MEDIUM", 0.7));
        }

        // Module coupling: modules with same categories of issues
        var moduleCats = report.Results
            .Select(r => (r.ModuleName, Cats: r.Findings.Where(f => f.Severity != Severity.Pass).Select(f => f.Category).Distinct().ToHashSet()))
            .Where(mc => mc.Cats.Count > 0)
            .ToList();

        for (int i = 0; i < moduleCats.Count; i++)
        {
            for (int j = i + 1; j < moduleCats.Count; j++)
            {
                var overlap = moduleCats[i].Cats.Intersect(moduleCats[j].Cats).ToList();
                if (overlap.Count >= 2)
                {
                    insights.Add(new AgentInsight(
                        $"{moduleCats[i].ModuleName} & {moduleCats[j].ModuleName} share {overlap.Count} weakness categories — coordinated fix recommended",
                        "MEDIUM", 0.75));
                }
            }
        }

        var confidence = nonPass.Count > 0 ? 75.0 : 90.0;
        var summary = categoryGroups.Count > 1
            ? $"Identified {categoryGroups.Count} distinct weakness patterns. Systemic configuration drift likely."
            : "Limited pattern data. More modules needed for strategic analysis.";

        return new AgentAnalysis(Strategist, insights, summary, confidence);
    }

    private AgentAnalysis RunHistorian(SecurityReport report, List<Finding> findings, List<AuditRunRecord> history)
    {
        var insights = new List<AgentInsight>();

        if (history.Count < 2)
        {
            insights.Add(new AgentInsight(
                "Insufficient history for trend analysis — run more audits to enable temporal insights",
                "INFO", 0.5));
            return new AgentAnalysis(Historian, insights, "Need more audit history for meaningful analysis.", 50.0);
        }

        // Score trend
        var recent = history.Take(5).ToList();
        var older = history.Skip(5).Take(5).ToList();
        if (older.Count > 0)
        {
            var recentAvg = recent.Average(r => r.OverallScore);
            var olderAvg = older.Average(r => r.OverallScore);
            var delta = recentAvg - olderAvg;
            if (Math.Abs(delta) > 2)
            {
                var direction = delta > 0 ? "improving" : "degrading";
                var sev = delta > 0 ? "INFO" : "WARNING";
                insights.Add(new AgentInsight(
                    $"Score trend is {direction}: {olderAvg:F0} → {recentAvg:F0} ({delta:+0.0;-0.0} points)",
                    sev, 0.85));
            }
        }

        // Recurring findings (appear in multiple runs)
        var findingFreq = history
            .SelectMany(r => r.Findings)
            .GroupBy(f => f.Title)
            .Where(g => g.Count() >= 3)
            .OrderByDescending(g => g.Count())
            .Take(5);

        foreach (var group in findingFreq)
        {
            insights.Add(new AgentInsight(
                $"\"{group.Key}\" recurred in {group.Count()}/{history.Count} runs — persistent issue",
                "WARNING", 0.8));
        }

        // Regression detection
        var latest = history.FirstOrDefault();
        var previous = history.Skip(1).FirstOrDefault();
        if (latest != null && previous != null && latest.CriticalCount > previous.CriticalCount)
        {
            insights.Add(new AgentInsight(
                $"Regression: criticals increased {previous.CriticalCount} → {latest.CriticalCount}",
                "CRITICAL", 0.9));
        }

        var confidence = history.Count >= 5 ? 80.0 : 60.0;
        var summary = insights.Any(i => i.Severity == "CRITICAL")
            ? "Regression detected! Previously resolved issues are returning."
            : insights.Any(i => i.Severity == "WARNING")
                ? "Persistent issues found that resist remediation. Root-cause investigation needed."
                : "Stable trend with no major regressions.";

        return new AgentAnalysis(Historian, insights, summary, confidence);
    }

    private AgentAnalysis RunEconomist(SecurityReport report, List<Finding> findings)
    {
        var insights = new List<AgentInsight>();
        var actionable = findings.Where(f => f.Severity is Severity.Critical or Severity.Warning).ToList();

        // Estimate effort: criticals ~2h, warnings ~1h, info ~0.25h
        var totalHours = actionable.Sum(f => f.Severity == Severity.Critical ? 2.0 : 1.0);
        var fixableCount = actionable.Count(f => f.FixCommand != null);

        insights.Add(new AgentInsight(
            $"Estimated remediation effort: {totalHours:F0} hours for {actionable.Count} actionable findings",
            "INFO", 0.7));

        if (fixableCount > 0)
        {
            var autoPercent = (fixableCount * 100.0) / Math.Max(1, actionable.Count);
            insights.Add(new AgentInsight(
                $"{fixableCount}/{actionable.Count} ({autoPercent:F0}%) findings are auto-fixable — high ROI",
                "INFO", 0.85));
        }

        // ROI by module: most findings per module = best bang for buck
        var moduleEfficiency = report.Results
            .Where(r => r.CriticalCount + r.WarningCount > 0)
            .OrderByDescending(r => r.CriticalCount * 3 + r.WarningCount)
            .Take(3);

        foreach (var m in moduleEfficiency)
        {
            insights.Add(new AgentInsight(
                $"Fix {m.ModuleName} first: {m.CriticalCount}C + {m.WarningCount}W findings — best cost-effectiveness",
                "HIGH", 0.8));
        }

        // Quick wins
        var quickWins = actionable.Where(f => f.FixCommand != null && f.Severity == Severity.Critical).Take(3);
        foreach (var qw in quickWins)
        {
            insights.Add(new AgentInsight(
                $"Quick win: \"{qw.Title}\" is critical AND auto-fixable",
                "HIGH", 0.9));
        }

        var confidence = actionable.Count > 0 ? 75.0 : 90.0;
        var summary = fixableCount > actionable.Count / 2
            ? $"Good news: {fixableCount} of {actionable.Count} issues are auto-fixable. Start there for maximum ROI."
            : $"{totalHours:F0}h estimated effort. Focus on {report.Results.OrderByDescending(r => r.CriticalCount).FirstOrDefault()?.ModuleName ?? "top module"} first.";

        return new AgentAnalysis(Economist, insights, summary, confidence);
    }

    private AgentAnalysis RunContrarian(SecurityReport report, List<Finding> findings)
    {
        var insights = new List<AgentInsight>();

        // Challenge: info/low severity could escalate
        var infoFindings = findings.Where(f => f.Severity == Severity.Info).ToList();
        if (infoFindings.Count > 5)
        {
            insights.Add(new AgentInsight(
                $"{infoFindings.Count} informational findings are being overlooked — some could escalate",
                "WARNING", 0.65));
        }

        // False sense of security from pass count
        var passCount = findings.Count(f => f.Severity == Severity.Pass);
        var totalChecks = findings.Count;
        if (passCount > 0 && totalChecks > 0)
        {
            var passRate = (passCount * 100.0) / totalChecks;
            if (passRate > 80)
            {
                insights.Add(new AgentInsight(
                    $"High pass rate ({passRate:F0}%) may create false confidence — {totalChecks - passCount} issues still exist",
                    "WARNING", 0.7));
            }
        }

        // Modules with zero findings might not be checking enough
        var emptyModules = report.Results.Where(r => r.Findings.Count == 0).ToList();
        if (emptyModules.Count > 0)
        {
            insights.Add(new AgentInsight(
                $"{emptyModules.Count} module(s) reported zero findings — possibly insufficient coverage, not perfection",
                "MEDIUM", 0.6));
        }

        // Challenge: are we fixing symptoms not causes?
        var categories = findings.Where(f => f.Severity != Severity.Pass)
            .GroupBy(f => f.Category)
            .Where(g => g.Count() >= 3);

        foreach (var cat in categories)
        {
            insights.Add(new AgentInsight(
                $"\"{cat.Key}\" has {cat.Count()} findings — are we treating symptoms or root cause?",
                "MEDIUM", 0.65));
        }

        // No critical doesn't mean safe
        if (findings.All(f => f.Severity != Severity.Critical))
        {
            insights.Add(new AgentInsight(
                "No criticals today, but absence of evidence ≠ evidence of absence. Consider expanding scan scope.",
                "INFO", 0.55));
        }

        var confidence = 60.0; // Contrarian is always somewhat uncertain — that's the point
        var summary = "Don't get complacent. I see blind spots that the team consensus might miss.";

        return new AgentAnalysis(Contrarian, insights, summary, confidence);
    }

    private AgentAnalysis RunSynthesizer(List<AgentAnalysis> otherAgents, SecurityReport report)
    {
        var insights = new List<AgentInsight>();

        // Agreement analysis
        var allInsightTexts = otherAgents.SelectMany(a => a.Insights).ToList();
        var criticalInsights = allInsightTexts.Where(i => i.Severity is "CRITICAL" or "HIGH").ToList();
        var agentsWithCritical = otherAgents.Count(a => a.Insights.Any(i => i.Severity is "CRITICAL" or "HIGH"));

        insights.Add(new AgentInsight(
            $"{agentsWithCritical}/{otherAgents.Count} agents flagged high-severity concerns — {(agentsWithCritical >= 3 ? "strong" : "moderate")} consensus",
            agentsWithCritical >= 3 ? "HIGH" : "MEDIUM", 0.85));

        // Average confidence
        var avgConf = otherAgents.Average(a => a.OverallConfidence);
        insights.Add(new AgentInsight(
            $"Swarm confidence: {avgConf:F0}% average ({otherAgents.Min(a => a.OverallConfidence):F0}% min, {otherAgents.Max(a => a.OverallConfidence):F0}% max)",
            "INFO", 0.9));

        // Contrarian vs majority
        var contrarianAgent = otherAgents.FirstOrDefault(a => a.Agent.Name == "Contrarian");
        if (contrarianAgent != null && contrarianAgent.Insights.Count > 0)
        {
            insights.Add(new AgentInsight(
                $"Contrarian raised {contrarianAgent.Insights.Count} concerns — review dissenting views below",
                "MEDIUM", 0.75));
        }

        var confidence = avgConf;
        var summary = $"Swarm analysis complete. {agentsWithCritical} agents see urgent issues. Overall posture: {(avgConf >= 70 ? "manageable" : "needs attention")}.";

        return new AgentAnalysis(Synthesizer, insights, summary, confidence);
    }

    // ── Consensus Building ───────────────────────────────────────────

    private (List<ConsensusItem> consensus, Dictionary<string, int> votes, List<string> dissents)
        BuildConsensus(List<AgentAnalysis> analyses)
    {
        var recommendations = new Dictionary<string, List<string>>();
        var dissents = new List<string>();

        // Each agent's top insight becomes a recommendation "vote"
        foreach (var analysis in analyses)
        {
            var topInsights = analysis.Insights
                .Where(i => i.Severity is "CRITICAL" or "HIGH" or "WARNING")
                .OrderByDescending(i => i.Confidence)
                .Take(2);

            foreach (var insight in topInsights)
            {
                // Normalize to a recommendation key
                var key = NormalizeRecommendation(insight.Finding);
                if (!recommendations.ContainsKey(key))
                    recommendations[key] = [];
                if (!recommendations[key].Contains(analysis.Agent.Name))
                    recommendations[key].Add(analysis.Agent.Name);
            }
        }

        // Track contrarian dissents
        var contrarianAgent = analyses.FirstOrDefault(a => a.Agent.Name == "Contrarian");
        if (contrarianAgent != null)
        {
            foreach (var insight in contrarianAgent.Insights.Take(3))
            {
                dissents.Add($"{contrarianAgent.Agent.Emoji} {contrarianAgent.Agent.Name}: \"{insight.Finding}\"");
            }
        }

        // Build consensus items sorted by agreement
        var totalAgents = analyses.Count;
        var consensusItems = recommendations
            .OrderByDescending(kv => kv.Value.Count)
            .ThenByDescending(kv => kv.Key.Contains("critical", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
            .Take(8)
            .Select(kv => new ConsensusItem(
                kv.Key,
                Math.Round((kv.Value.Count * 100.0) / totalAgents, 0),
                kv.Value,
                kv.Value.Count >= 4 ? "URGENT" : kv.Value.Count >= 2 ? "HIGH" : "MEDIUM"))
            .ToList();

        // Voting record
        var votes = recommendations
            .OrderByDescending(kv => kv.Value.Count)
            .Take(10)
            .ToDictionary(kv => TruncateKey(kv.Key, 50), kv => kv.Value.Count);

        return (consensusItems, votes, dissents);
    }

    private static string NormalizeRecommendation(string finding)
    {
        // Simplify to a recommendation-style phrase
        if (finding.Length > 80)
            return finding[..80] + "...";
        return finding;
    }

    private static string TruncateKey(string key, int maxLen)
    {
        return key.Length <= maxLen ? key : key[..maxLen] + "...";
    }
}
