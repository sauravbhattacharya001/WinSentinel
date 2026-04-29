namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintRegression(RegressionReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🔄 REGRESSION PREDICTOR — Fix Stability Analysis      ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Regression Score Gauge
        Console.Write("  Regression Score: ");
        var scoreColor = report.RegressionScore switch
        {
            < 25 => ConsoleColor.Green,
            < 50 => ConsoleColor.Yellow,
            < 75 => ConsoleColor.Red,
            _ => ConsoleColor.DarkRed
        };
        Console.ForegroundColor = scoreColor;
        var filled = report.RegressionScore / 5;
        var empty = 20 - filled;
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.RegressionScore}/100");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Risk Level
        Console.Write("  Risk Level: ");
        Console.ForegroundColor = report.RiskLevel switch
        {
            "Critical" => ConsoleColor.DarkRed,
            "High" => ConsoleColor.Red,
            "Medium" => ConsoleColor.Yellow,
            _ => ConsoleColor.Green
        };
        var riskEmoji = report.RiskLevel switch
        {
            "Critical" => "🚨",
            "High" => "🔴",
            "Medium" => "🟡",
            _ => "🟢"
        };
        Console.WriteLine($"{riskEmoji}  {report.RiskLevel}");
        Console.ForegroundColor = original;

        // Stats line
        Console.Write("  Analyzed: ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"{report.AnalyzedRuns} runs  |  Regressions: {report.TotalRegressionsFound}  |  Rate: {report.OverallRegressionRate:P1}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Yo-Yo Findings
        if (report.YoYoFindings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ── 🔄 Yo-Yo Findings (Keep Coming Back) ──────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Finding                                  Module          Sev       Regs  Rate    Pattern    Root Cause Hint");
            Console.WriteLine("  ────────────────────────────────────────  ──────────────  ────────  ────  ──────  ─────────  ────────────────────────────────────────");
            Console.ForegroundColor = original;

            foreach (var f in report.YoYoFindings)
            {
                var title = f.Title.Length > 40 ? f.Title[..37] + "..." : f.Title;
                var module = f.Module.Length > 14 ? f.Module[..11] + "..." : f.Module;
                var hint = f.RootCauseHint.Length > 40 ? f.RootCauseHint[..37] + "..." : f.RootCauseHint;

                Console.Write($"  {title,-42}{module,-16}");
                Console.ForegroundColor = SeverityColor(f.Severity);
                Console.Write($"{f.Severity,-10}");
                Console.ForegroundColor = original;
                Console.Write($"{f.RegressionCount,-6}{f.RegressionRate:P0}".PadRight(8));
                Console.ForegroundColor = f.Pattern == "Chronic" ? ConsoleColor.Red :
                    f.Pattern == "Periodic" ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
                Console.Write($"{f.Pattern,-11}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(hint);
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        // At-Risk Fixes
        if (report.AtRiskFixes.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ── ⚠️ At-Risk Fixes (Likely to Regress) ──────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Finding                                  Module          Sev       Prob    Conf    Since  Action");
            Console.WriteLine("  ────────────────────────────────────────  ──────────────  ────────  ──────  ──────  ─────  ──────────────────────────────────────────");
            Console.ForegroundColor = original;

            foreach (var p in report.AtRiskFixes)
            {
                var title = p.Title.Length > 40 ? p.Title[..37] + "..." : p.Title;
                var module = p.Module.Length > 14 ? p.Module[..11] + "..." : p.Module;
                var action = p.RecommendedAction.Length > 42 ? p.RecommendedAction[..39] + "..." : p.RecommendedAction;

                Console.Write($"  {title,-42}{module,-16}");
                Console.ForegroundColor = SeverityColor(p.Severity);
                Console.Write($"{p.Severity,-10}");
                Console.ForegroundColor = p.RegressionProbability >= 0.5 ? ConsoleColor.Red :
                    p.RegressionProbability >= 0.3 ? ConsoleColor.Yellow : ConsoleColor.Green;
                Console.Write($"{p.RegressionProbability:P0}".PadRight(8));
                Console.ForegroundColor = original;
                Console.Write($"{p.Confidence,-8}{p.RunsSinceFix,-7}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(action);
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        // Module Stability
        if (report.ModuleProfiles.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  ── 🏗️ Module Stability ──────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Module                Findings  Regs  Rate    Stability  Top Offender");
            Console.WriteLine("  ────────────────────  ────────  ────  ──────  ─────────  ──────────────────────────────────────");
            Console.ForegroundColor = original;

            foreach (var m in report.ModuleProfiles)
            {
                var moduleName = m.ModuleName.Length > 20 ? m.ModuleName[..17] + "..." : m.ModuleName;
                var topOffender = m.TopYoYoFinding.Length > 38 ? m.TopYoYoFinding[..35] + "..." : m.TopYoYoFinding;

                Console.Write($"  {moduleName,-22}{m.TotalFindings,-10}{m.RegressionCount,-6}{m.RegressionRate:P0}".PadRight(50));
                Console.ForegroundColor = m.Stability switch
                {
                    "Volatile" => ConsoleColor.Red,
                    "Shaky" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Green
                };
                Console.Write($"{m.Stability,-11}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(topOffender);
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── 💡 Recommendations ────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var rec in report.Recommendations)
            {
                Console.Write("  ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(rec);
                Console.ForegroundColor = original;
            }
            Console.WriteLine();
        }

        if (report.YoYoFindings.Count == 0 && report.AtRiskFixes.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✅ No regressions detected — your fixes are holding strong!");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }
    }

    private static ConsoleColor SeverityColor(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => ConsoleColor.DarkRed,
        "high" => ConsoleColor.Red,
        "warning" => ConsoleColor.Yellow,
        "info" => ConsoleColor.DarkGray,
        _ => ConsoleColor.Gray
    };
}
