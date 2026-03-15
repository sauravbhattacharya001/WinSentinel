using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>Print attack path analysis report.</summary>
    public static void PrintAttackPaths(AttackPathAnalyzer.AttackPathReport report)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       ⚔️  Attack Path Analysis               ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Summary strip
        var riskColor = report.OverallRisk switch
        {
            "Critical" => ConsoleColor.Red,
            "High" => ConsoleColor.DarkYellow,
            "Medium" => ConsoleColor.Yellow,
            "Low" => ConsoleColor.Green,
            _ => ConsoleColor.DarkGray
        };
        WriteColored("  Overall Risk: ", ConsoleColor.White);
        WriteColored($"{report.OverallRisk}", riskColor);
        WriteColored("  │  Paths: ", ConsoleColor.White);
        WriteColored($"{report.Paths.Count}", ConsoleColor.Yellow);
        WriteColored("  │  Findings in Paths: ", ConsoleColor.White);
        WriteColored($"{report.FindingsInPaths}/{report.TotalFindings}", ConsoleColor.DarkGray);
        Console.WriteLine();
        Console.WriteLine();

        // Stage Breakdown
        WriteLineColored("  ── Kill Chain Stage Breakdown ──", ConsoleColor.DarkGray);
        Console.WriteLine();

        foreach (var (stage, count) in report.StageBreakdown)
        {
            var icon = stage switch
            {
                "Initial Access" => "🚪",
                "Execution" => "⚙️",
                "Persistence" => "📌",
                "Privilege Escalation" => "⬆️",
                "Lateral Movement" => "↔️",
                "Exfiltration" => "📤",
                _ => "•"
            };

            WriteColored($"    {icon} {stage,-24}", ConsoleColor.White);

            if (count > 0)
            {
                var barLen = Math.Min(count * 2, 30);
                WriteColored(new string('█', barLen), count > 3 ? ConsoleColor.Red : ConsoleColor.Yellow);
                WriteLineColored($" {count} finding(s)", ConsoleColor.DarkGray);
            }
            else
            {
                WriteLineColored("  ✓ No exposures", ConsoleColor.Green);
            }
        }
        Console.WriteLine();

        // Attack Paths (top 10)
        if (report.Paths.Count > 0)
        {
            WriteLineColored("  ── Attack Paths ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            var displayCount = Math.Min(report.Paths.Count, 10);
            for (int i = 0; i < displayCount; i++)
            {
                var path = report.Paths[i];
                var pathRiskColor = path.RiskLevel switch
                {
                    "Critical" => ConsoleColor.Red,
                    "High" => ConsoleColor.DarkYellow,
                    "Medium" => ConsoleColor.Yellow,
                    "Low" => ConsoleColor.Green,
                    _ => ConsoleColor.DarkGray
                };

                WriteColored($"  [{i + 1}] ", ConsoleColor.DarkGray);
                WriteColored($"{path.Name}", ConsoleColor.White);
                Console.WriteLine();

                WriteColored("      Risk: ", ConsoleColor.DarkGray);
                WriteColored($"{path.ExploitabilityScore:F0}/100 ({path.RiskLevel})", pathRiskColor);
                WriteColored("  │  Stages: ", ConsoleColor.DarkGray);
                WriteColored($"{path.StagesCovered}", ConsoleColor.Yellow);
                WriteColored("  │  Steps: ", ConsoleColor.DarkGray);
                WriteLineColored($"{path.Steps.Count}", ConsoleColor.DarkGray);

                // Show chain
                WriteColored("      ", ConsoleColor.DarkGray);
                for (int j = 0; j < path.Steps.Count; j++)
                {
                    var step = path.Steps[j];
                    var stepColor = step.Finding.Severity switch
                    {
                        Severity.Critical => ConsoleColor.Red,
                        Severity.Warning => ConsoleColor.Yellow,
                        _ => ConsoleColor.DarkGray
                    };

                    if (j > 0) WriteColored(" → ", ConsoleColor.DarkGray);
                    WriteColored($"{step.StageName}", stepColor);
                }
                Console.WriteLine();

                // Show step details
                foreach (var step in path.Steps)
                {
                    var sevColor = step.Finding.Severity switch
                    {
                        Severity.Critical => ConsoleColor.Red,
                        Severity.Warning => ConsoleColor.Yellow,
                        _ => ConsoleColor.DarkGray
                    };
                    var sevLabel = step.Finding.Severity switch
                    {
                        Severity.Critical => "CRIT",
                        Severity.Warning => "WARN",
                        _ => "INFO"
                    };

                    WriteColored($"        [{sevLabel}] ", sevColor);
                    WriteColored($"{step.StageName}: ", ConsoleColor.DarkGray);

                    var title = step.Finding.Title.Length > 55
                        ? step.Finding.Title[..52] + "..."
                        : step.Finding.Title;
                    WriteLineColored(title, ConsoleColor.White);

                    if (step.TechniqueId != null)
                    {
                        WriteColored("               ", ConsoleColor.DarkGray);
                        WriteLineColored($"MITRE: {step.TechniqueId} ({step.TechniqueName})", ConsoleColor.DarkCyan);
                    }
                }
                Console.WriteLine();
            }

            if (report.Paths.Count > 10)
            {
                WriteLineColored($"    ... and {report.Paths.Count - 10} more path(s). Use --json for full output.", ConsoleColor.DarkGray);
                Console.WriteLine();
            }
        }
        else
        {
            WriteLineColored("  ✅ No multi-stage attack paths detected!", ConsoleColor.Green);
            WriteLineColored("     Your security posture blocks kill chain progression.", ConsoleColor.DarkGray);
            Console.WriteLine();
        }

        // Chokepoints
        if (report.Chokepoints.Count > 0)
        {
            WriteLineColored("  ── Remediation Chokepoints (fix these first) ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            foreach (var cp in report.Chokepoints)
            {
                var sevColor = cp.Finding.Severity switch
                {
                    Severity.Critical => ConsoleColor.Red,
                    Severity.Warning => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkGray
                };

                WriteColored($"  #{cp.Priority} ", ConsoleColor.White);
                var title = cp.Finding.Title.Length > 50
                    ? cp.Finding.Title[..47] + "..."
                    : cp.Finding.Title;
                WriteColored(title, sevColor);
                Console.WriteLine();

                WriteColored("     ", ConsoleColor.DarkGray);
                WriteColored($"Appears in {cp.PathCount} path(s)", ConsoleColor.DarkGray);
                WriteColored("  │  Risk reduced: ", ConsoleColor.DarkGray);
                WriteColored($"{cp.TotalRiskReduced:F0}", ConsoleColor.Yellow);
                WriteColored("  │  Module: ", ConsoleColor.DarkGray);
                WriteLineColored(cp.Module, ConsoleColor.DarkGray);

                if (cp.Finding.Remediation != null)
                {
                    WriteColored("     Fix: ", ConsoleColor.DarkGray);
                    var rem = cp.Finding.Remediation.Length > 70
                        ? cp.Finding.Remediation[..67] + "..."
                        : cp.Finding.Remediation;
                    WriteLineColored(rem, ConsoleColor.Cyan);
                }
            }
            Console.WriteLine();
        }

        // Summary
        WriteLineColored("  ── Summary ──", ConsoleColor.DarkGray);
        Console.WriteLine();
        WriteColored("  ", ConsoleColor.DarkGray);
        WriteLineColored(report.Summary, ConsoleColor.White);
        Console.WriteLine();
    }
}
