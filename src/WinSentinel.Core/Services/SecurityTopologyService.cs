namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Security Topology — maps interconnections between security modules, identifies keystone
/// modules whose improvement cascades benefits, detects vulnerability chains, and scores
/// structural resilience of the overall security posture.
/// </summary>
public class SecurityTopologyService
{
    private readonly AuditHistoryService _history;

    public SecurityTopologyService(AuditHistoryService history)
    {
        _history = history;
    }

    public TopologyResult Analyze(int days = 30)
    {
        var runs = _history.GetHistory(days);
        if (runs.Count < 3)
            return new TopologyResult
            {
                AnalyzedAt = DateTimeOffset.UtcNow,
                StructuralHealth = "insufficient-data",
                Recommendations = new List<string> { "Need at least 3 audit runs to build topology." }
            };

        // Collect all module names
        var allModules = runs
            .SelectMany(r => r.ModuleScores.Select(ms => ms.ModuleName))
            .Distinct()
            .OrderBy(m => m)
            .ToList();

        if (allModules.Count < 2)
            return new TopologyResult
            {
                AnalyzedAt = DateTimeOffset.UtcNow,
                ModuleCount = allModules.Count,
                StructuralHealth = "insufficient-modules",
                Recommendations = new List<string> { "Need at least 2 modules for topology analysis." }
            };

        // Build score time-series per module
        var timeSeries = new Dictionary<string, List<double>>();
        foreach (var mod in allModules)
            timeSeries[mod] = new List<double>();

        foreach (var run in runs)
        {
            var scoreMap = run.ModuleScores.ToDictionary(ms => ms.ModuleName, ms => (double)ms.Score);
            foreach (var mod in allModules)
                timeSeries[mod].Add(scoreMap.GetValueOrDefault(mod, -1));
        }

        // Calculate Pearson correlation for each pair
        var edges = new List<TopologyEdge>();
        for (int i = 0; i < allModules.Count; i++)
        {
            for (int j = i + 1; j < allModules.Count; j++)
            {
                double corr = PearsonCorrelation(timeSeries[allModules[i]], timeSeries[allModules[j]]);
                if (double.IsNaN(corr)) continue;
                if (Math.Abs(corr) < 0.3) continue;

                string relationship = corr > 0.6 ? "amplifies"
                    : corr < -0.3 ? "compensates"
                    : "coupled";

                edges.Add(new TopologyEdge
                {
                    Source = allModules[i],
                    Target = allModules[j],
                    Correlation = Math.Round(corr, 3),
                    Relationship = relationship
                });
            }
        }

        // Build adjacency
        var adjacency = new Dictionary<string, HashSet<string>>();
        foreach (var mod in allModules)
            adjacency[mod] = new HashSet<string>();
        foreach (var e in edges)
        {
            adjacency[e.Source].Add(e.Target);
            adjacency[e.Target].Add(e.Source);
        }

        // Latest scores
        var latestScores = runs[0].ModuleScores.ToDictionary(ms => ms.ModuleName, ms => ms.Score);

        // Build nodes with centrality
        int maxPossible = allModules.Count - 1;
        var nodes = allModules.Select(mod => new TopologyNode
        {
            Module = mod,
            Score = latestScores.GetValueOrDefault(mod, 0),
            Connections = adjacency[mod].Count,
            Centrality = maxPossible > 0 ? Math.Round((double)adjacency[mod].Count / maxPossible, 3) : 0,
            Role = ClassifyRole(adjacency[mod].Count, maxPossible, latestScores.GetValueOrDefault(mod, 0))
        }).OrderByDescending(n => n.Centrality).ToList();

        // Keystone modules: top 3 by centrality
        var keystones = nodes.Where(n => n.Connections > 0).Take(3).ToList();

        // Vulnerability chains: connected components of low-scoring modules via positive correlations
        var lowModules = new HashSet<string>(nodes.Where(n => n.Score < 70).Select(n => n.Module));
        var positiveAdj = new Dictionary<string, HashSet<string>>();
        foreach (var mod in allModules)
            positiveAdj[mod] = new HashSet<string>();
        foreach (var e in edges.Where(e => e.Correlation > 0.3))
        {
            positiveAdj[e.Source].Add(e.Target);
            positiveAdj[e.Target].Add(e.Source);
        }

        var chains = FindVulnerabilityChains(lowModules, positiveAdj, latestScores);

        // Cascade impact: for each low-scoring module, estimate improvement potential
        var cascadeImpacts = new List<TopologyCascadeImpact>();
        foreach (var mod in allModules.Where(m => latestScores.GetValueOrDefault(m, 0) < 80))
        {
            double cascadeGain = 0;
            var affected = new List<string>();
            foreach (var e in edges.Where(e => (e.Source == mod || e.Target == mod) && e.Correlation > 0))
            {
                var other = e.Source == mod ? e.Target : e.Source;
                double potential = e.Correlation * (100 - latestScores.GetValueOrDefault(other, 0)) * 0.1;
                cascadeGain += potential;
                affected.Add(other);
            }

            if (cascadeGain > 0)
            {
                cascadeImpacts.Add(new TopologyCascadeImpact
                {
                    Module = mod,
                    CurrentScore = latestScores.GetValueOrDefault(mod, 0),
                    PotentialCascadeGain = Math.Round(cascadeGain, 1),
                    AffectedModules = affected,
                    Priority = cascadeGain > 10 ? "high" : cascadeGain > 5 ? "medium" : "low"
                });
            }
        }
        cascadeImpacts = cascadeImpacts.OrderByDescending(c => c.PotentialCascadeGain).ToList();

        // Graph metrics
        int maxEdges = allModules.Count * (allModules.Count - 1) / 2;
        double density = maxEdges > 0 ? Math.Round((double)edges.Count / maxEdges, 3) : 0;

        // Resilience score
        double avgScore = nodes.Count > 0 ? nodes.Average(n => n.Score) : 0;
        double avgCentrality = nodes.Count > 0 ? nodes.Average(n => n.Centrality) : 0;
        int isolatedCount = nodes.Count(n => n.Connections == 0);
        double isolatedPenalty = nodes.Count > 0 ? (double)isolatedCount / nodes.Count * 20 : 0;
        double chainPenalty = Math.Min(30, chains.Count * 10);
        double resilience = Math.Max(0, Math.Min(100,
            avgScore * 0.5 + (1 - density) * 20 + avgCentrality * 10 - isolatedPenalty - chainPenalty));
        resilience = Math.Round(resilience, 1);

        string structuralHealth = resilience >= 80 ? "robust"
            : resilience >= 60 ? "moderate"
            : resilience >= 40 ? "fragile"
            : "critical";

        // Recommendations
        var recommendations = GenerateRecommendations(nodes, edges, chains, cascadeImpacts, keystones, density, structuralHealth);

        return new TopologyResult
        {
            AnalyzedAt = DateTimeOffset.UtcNow,
            ModuleCount = allModules.Count,
            EdgeCount = edges.Count,
            GraphDensity = density,
            Nodes = nodes,
            Edges = edges,
            KeystoneModules = keystones,
            VulnerabilityChains = chains,
            CascadeImpacts = cascadeImpacts,
            Recommendations = recommendations,
            StructuralHealth = structuralHealth,
            ResilienceScore = resilience
        };
    }

    private static double PearsonCorrelation(List<double> x, List<double> y)
    {
        // Filter out entries where either is -1 (missing)
        var pairs = x.Zip(y).Where(p => p.First >= 0 && p.Second >= 0).ToList();
        if (pairs.Count < 3) return double.NaN;

        double n = pairs.Count;
        double sumX = pairs.Sum(p => p.First);
        double sumY = pairs.Sum(p => p.Second);
        double sumXY = pairs.Sum(p => p.First * p.Second);
        double sumX2 = pairs.Sum(p => p.First * p.First);
        double sumY2 = pairs.Sum(p => p.Second * p.Second);

        double denom = Math.Sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));
        if (denom == 0) return 0;
        return (n * sumXY - sumX * sumY) / denom;
    }

    private static string ClassifyRole(int connections, int maxPossible, int score)
    {
        double centrality = maxPossible > 0 ? (double)connections / maxPossible : 0;
        if (connections == 0) return "isolated";
        if (centrality >= 0.6) return "keystone";
        if (centrality >= 0.3) return "bridge";
        return "leaf";
    }

    private static List<VulnerabilityChain> FindVulnerabilityChains(
        HashSet<string> lowModules, Dictionary<string, HashSet<string>> adj,
        Dictionary<string, int> scores)
    {
        var visited = new HashSet<string>();
        var chains = new List<VulnerabilityChain>();

        foreach (var mod in lowModules)
        {
            if (visited.Contains(mod)) continue;
            var component = new List<string>();
            var queue = new Queue<string>();
            queue.Enqueue(mod);
            visited.Add(mod);
            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                component.Add(current);
                foreach (var neighbor in adj[current])
                {
                    if (!visited.Contains(neighbor) && lowModules.Contains(neighbor))
                    {
                        visited.Add(neighbor);
                        queue.Enqueue(neighbor);
                    }
                }
            }

            if (component.Count >= 2)
            {
                double avgScore = component.Average(m => scores.GetValueOrDefault(m, 0));
                double chainRisk = Math.Round((100 - avgScore) * component.Count * 0.1, 1);
                chains.Add(new VulnerabilityChain
                {
                    Modules = component.OrderBy(m => scores.GetValueOrDefault(m, 0)).ToList(),
                    ChainRisk = chainRisk,
                    Description = $"{component.Count} correlated weak modules (avg score {avgScore:F0}) — failures may cascade"
                });
            }
        }

        return chains.OrderByDescending(c => c.ChainRisk).ToList();
    }

    private static List<string> GenerateRecommendations(
        List<TopologyNode> nodes, List<TopologyEdge> edges,
        List<VulnerabilityChain> chains, List<TopologyCascadeImpact> cascades,
        List<TopologyNode> keystones, double density, string health)
    {
        var recs = new List<string>();

        if (chains.Count > 0)
            recs.Add($"⚠ {chains.Count} vulnerability chain(s) detected — correlated weak modules risk cascading failures.");

        if (cascades.Count > 0)
        {
            var top = cascades[0];
            recs.Add($"🎯 Prioritize improving {top.Module} (score {top.CurrentScore}) — highest cascade potential ({top.PotentialCascadeGain:F1} pts across {top.AffectedModules.Count} modules).");
        }

        var isolated = nodes.Where(n => n.Role == "isolated").ToList();
        if (isolated.Count > 0)
            recs.Add($"🔌 {isolated.Count} isolated module(s) ({string.Join(", ", isolated.Select(n => n.Module))}) — no correlation detected, may need independent monitoring.");

        if (keystones.Count > 0 && keystones.Any(k => k.Score < 70))
        {
            var weakKeystones = keystones.Where(k => k.Score < 70).ToList();
            recs.Add($"🏛 Keystone module(s) at risk: {string.Join(", ", weakKeystones.Select(k => $"{k.Module} ({k.Score})"))} — weaknesses here affect many connected modules.");
        }

        var compensating = edges.Where(e => e.Relationship == "compensates").ToList();
        if (compensating.Count > 0)
            recs.Add($"⚖ {compensating.Count} compensating relationship(s) found — some modules offset each other's weaknesses.");

        if (density > 0.7)
            recs.Add("🕸 High graph density — modules are tightly coupled. Changes in one area likely affect many others.");
        else if (density < 0.2)
            recs.Add("🏝 Low graph density — modules are largely independent. Focus improvements individually.");

        if (health == "critical")
            recs.Add("🚨 Structural health is CRITICAL — multiple cascading risks and weak keystones detected.");
        else if (health == "robust")
            recs.Add("✅ Structural health is robust — module interconnections are well-balanced.");

        return recs;
    }
}

// ── Result Models ──────────────────────────────────────────────

public class TopologyResult
{
    public DateTimeOffset AnalyzedAt { get; set; }
    public int ModuleCount { get; set; }
    public int EdgeCount { get; set; }
    public double GraphDensity { get; set; }
    public List<TopologyNode> Nodes { get; set; } = new();
    public List<TopologyEdge> Edges { get; set; } = new();
    public List<TopologyNode> KeystoneModules { get; set; } = new();
    public List<VulnerabilityChain> VulnerabilityChains { get; set; } = new();
    public List<TopologyCascadeImpact> CascadeImpacts { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
    public string StructuralHealth { get; set; } = "unknown";
    public double ResilienceScore { get; set; }
}

public class TopologyNode
{
    public string Module { get; set; } = "";
    public int Score { get; set; }
    public int Connections { get; set; }
    public double Centrality { get; set; }
    public string Role { get; set; } = "";
}

public class TopologyEdge
{
    public string Source { get; set; } = "";
    public string Target { get; set; } = "";
    public double Correlation { get; set; }
    public string Relationship { get; set; } = "";
}

public class VulnerabilityChain
{
    public List<string> Modules { get; set; } = new();
    public double ChainRisk { get; set; }
    public string Description { get; set; } = "";
}

public class TopologyCascadeImpact
{
    public string Module { get; set; } = "";
    public int CurrentScore { get; set; }
    public double PotentialCascadeGain { get; set; }
    public List<string> AffectedModules { get; set; } = new();
    public string Priority { get; set; } = "";
}
