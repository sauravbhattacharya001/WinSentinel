namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Renders Security Topology — module interconnection map with keystones, vulnerability chains,
    /// cascade impacts, and structural resilience.
    /// </summary>
    public static void PrintTopology(TopologyResult result, CliOptions options)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🔗  Security Topology                 ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        if (result.Nodes.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No module data found. Run --audit first.");
            Console.ResetColor();
            return;
        }

        // ── Overview ──
        Console.WriteLine();
        Console.Write("  Modules: ");
        WriteColored($"{result.ModuleCount}", ConsoleColor.White);
        Console.Write("  Edges: ");
        WriteColored($"{result.EdgeCount}", ConsoleColor.White);
        Console.Write("  Density: ");
        var densityColor = result.GraphDensity > 0.7 ? ConsoleColor.Red
            : result.GraphDensity > 0.4 ? ConsoleColor.Yellow
            : ConsoleColor.Green;
        WriteColored($"{result.GraphDensity:F2}", densityColor);
        Console.WriteLine();

        Console.Write("  Resilience: ");
        WriteColored($"{result.ResilienceScore:F1}/100", ScoreColor((int)result.ResilienceScore));
        Console.Write("  Health: ");
        var healthColor = result.StructuralHealth switch
        {
            "robust" => ConsoleColor.Green,
            "moderate" => ConsoleColor.Yellow,
            "fragile" => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };
        WriteColored(result.StructuralHealth.ToUpperInvariant(), healthColor);
        Console.WriteLine();

        // ── Module Topology Table ──
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ── Module Nodes ──────────────────────────────────");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Module",-22} {"Score",6} {"Links",6} {"Centrality",11} {"Role",10}");
        Console.ResetColor();

        foreach (var node in result.Nodes)
        {
            Console.Write($"  {node.Module,-22}");
            WriteColored($"{node.Score,6}", ScoreColor(node.Score));
            Console.Write($"{node.Connections,6}");
            Console.Write($"{node.Centrality,11:F3}");
            var roleColor = node.Role switch
            {
                "keystone" => ConsoleColor.Magenta,
                "bridge" => ConsoleColor.Cyan,
                "leaf" => ConsoleColor.DarkGray,
                "isolated" => ConsoleColor.DarkRed,
                _ => ConsoleColor.Gray
            };
            WriteColored($"{node.Role,10}", roleColor);
            Console.WriteLine();
        }

        // ── Adjacency Grid ──
        if (result.Edges.Count > 0 && result.Nodes.Count <= 12)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Connection Matrix ─────────────────────────────");
            Console.ResetColor();

            var modules = result.Nodes.Select(n => n.Module).ToList();
            var edgeMap = new Dictionary<string, double>();
            foreach (var e in result.Edges)
            {
                edgeMap[$"{e.Source}|{e.Target}"] = e.Correlation;
                edgeMap[$"{e.Target}|{e.Source}"] = e.Correlation;
            }

            // Abbreviated labels
            var labels = modules.Select(m => m.Length > 6 ? m[..6] : m).ToList();

            Console.Write("  {0,8}", "");
            foreach (var lbl in labels)
                Console.Write($" {lbl,6}");
            Console.WriteLine();

            for (int i = 0; i < modules.Count; i++)
            {
                Console.Write($"  {labels[i],8}");
                for (int j = 0; j < modules.Count; j++)
                {
                    if (i == j)
                    {
                        Console.Write("      ·");
                        continue;
                    }
                    var key = $"{modules[i]}|{modules[j]}";
                    if (edgeMap.TryGetValue(key, out var corr))
                    {
                        var corrColor = corr > 0.6 ? ConsoleColor.Green
                            : corr > 0 ? ConsoleColor.Yellow
                            : ConsoleColor.Red;
                        var sym = corr > 0.6 ? "██" : corr > 0.3 ? "▓▓" : corr > 0 ? "░░" : "××";
                        Console.Write("   ");
                        Console.ForegroundColor = corrColor;
                        Console.Write($"{sym,4}");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.Write("      ·");
                    }
                }
                Console.WriteLine();
            }

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ██ strong positive  ▓▓ moderate positive  ×× negative");
            Console.ResetColor();
        }

        // ── Keystone Modules ──
        if (result.KeystoneModules.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Keystone Modules (highest centrality) ─────────");
            Console.ResetColor();

            foreach (var ks in result.KeystoneModules)
            {
                Console.Write("  🏛 ");
                WriteColored(ks.Module, ConsoleColor.Magenta);
                Console.Write($"  score=");
                WriteColored($"{ks.Score}", ScoreColor(ks.Score));
                Console.Write($"  links={ks.Connections}  centrality={ks.Centrality:F3}");
                Console.WriteLine();
            }
        }

        // ── Vulnerability Chains ──
        if (result.VulnerabilityChains.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Vulnerability Chains ──────────────────────────");
            Console.ResetColor();

            foreach (var chain in result.VulnerabilityChains)
            {
                Console.Write("  ⛓ ");
                var riskColor = chain.ChainRisk > 20 ? ConsoleColor.Red
                    : chain.ChainRisk > 10 ? ConsoleColor.Yellow
                    : ConsoleColor.DarkYellow;
                WriteColored($"Risk {chain.ChainRisk:F1}", riskColor);
                Console.Write("  ");
                Console.Write(string.Join(" → ", chain.Modules));
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"    {chain.Description}");
                Console.ResetColor();
            }
        }

        // ── Cascade Impact ──
        if (result.CascadeImpacts.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Cascade Impact (improve these first) ──────────");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"Module",-22} {"Score",6} {"Cascade",8} {"Priority",9}  Affects");
            Console.ResetColor();

            foreach (var ci in result.CascadeImpacts.Take(10))
            {
                Console.Write($"  {ci.Module,-22}");
                WriteColored($"{ci.CurrentScore,6}", ScoreColor(ci.CurrentScore));
                Console.Write($"{ci.PotentialCascadeGain,8:F1}");
                var priColor = ci.Priority switch
                {
                    "high" => ConsoleColor.Red,
                    "medium" => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };
                WriteColored($"{ci.Priority,9}", priColor);
                Console.Write($"  {Truncate(string.Join(", ", ci.AffectedModules), 40)}");
                Console.WriteLine();
            }
        }

        // ── Recommendations ──
        if (result.Recommendations.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Proactive Recommendations ─────────────────────");
            Console.ResetColor();

            foreach (var rec in result.Recommendations)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"  {rec}");
                Console.ResetColor();
            }
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Analyzed at {result.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        Console.ResetColor();
        Console.WriteLine();
    }
}
