using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>Print full STRIDE threat model report.</summary>
    public static void PrintThreatModel(ThreatModelService.ThreatModel model)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       🛡️  STRIDE Threat Model                ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Summary strip
        var riskColor = GetSeverityColor(model.OverallRisk);
        WriteColored("  Overall Risk: ", ConsoleColor.White);
        WriteColored($"{model.OverallRisk}", riskColor);
        WriteColored("  │  Threats: ", ConsoleColor.White);
        WriteColored($"{model.TotalThreats}", ConsoleColor.Yellow);
        WriteColored("  │  Attack Paths: ", ConsoleColor.White);
        WriteColored($"{model.TotalAttackPaths}", ConsoleColor.Yellow);
        WriteColored("  │  STRIDE Coverage: ", ConsoleColor.White);
        WriteLineColored($"{model.StrideCoveragePercent}%", ConsoleColor.DarkGray);
        Console.WriteLine();

        // STRIDE Category Summary
        WriteLineColored("  ── STRIDE Category Breakdown ──", ConsoleColor.DarkGray);
        Console.WriteLine();

        foreach (var cat in model.CategorySummaries)
        {
            var icon = cat.Category switch
            {
                ThreatModelService.StrideCategory.Spoofing => "🎭",
                ThreatModelService.StrideCategory.Tampering => "🔧",
                ThreatModelService.StrideCategory.Repudiation => "📝",
                ThreatModelService.StrideCategory.InformationDisclosure => "👁️",
                ThreatModelService.StrideCategory.DenialOfService => "⛔",
                ThreatModelService.StrideCategory.ElevationOfPrivilege => "⬆️",
                _ => "•"
            };

            var sevColor = GetSeverityColor(cat.WorstSeverity);
            WriteColored($"  {icon} {cat.Category,-25}", ConsoleColor.White);
            if (cat.ThreatCount == 0)
            {
                WriteLineColored(" ✓ No threats", ConsoleColor.Green);
            }
            else
            {
                WriteColored($" {cat.ThreatCount} threat(s)", sevColor);
                if (cat.CriticalCount > 0)
                    WriteColored($"  {cat.CriticalCount} critical", ConsoleColor.Red);
                if (cat.WarningCount > 0)
                    WriteColored($"  {cat.WarningCount} warning", ConsoleColor.Yellow);
                Console.WriteLine();
            }
        }

        Console.WriteLine();

        // Threats detail
        if (model.Threats.Count > 0)
        {
            WriteLineColored("  ── Identified Threats ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            for (int i = 0; i < model.Threats.Count; i++)
            {
                var t = model.Threats[i];
                var sevColor = GetSeverityColor(t.RiskLevel);

                WriteColored($"  {i + 1}. ", ConsoleColor.White);
                WriteColored($"[{t.RiskLevel}] ", sevColor);
                WriteColored($"[{t.Category}] ", ConsoleColor.DarkCyan);
                WriteLineColored(t.Title, ConsoleColor.White);

                WriteColored("     ", ConsoleColor.White);
                WriteLineColored(t.Description, ConsoleColor.DarkGray);

                WriteColored("     Evidence: ", ConsoleColor.White);
                WriteLineColored($"{t.EvidenceCount} finding(s)", ConsoleColor.Yellow);

                WriteColored("     Mitigation: ", ConsoleColor.White);
                WriteLineColored(t.Mitigation, ConsoleColor.Green);

                if (t.MitigationCommand != null)
                {
                    WriteColored("     Command: ", ConsoleColor.White);
                    WriteLineColored(t.MitigationCommand, ConsoleColor.DarkYellow);
                }

                Console.WriteLine();
            }
        }

        // Attack Paths
        if (model.AttackPaths.Count > 0)
        {
            WriteLineColored("  ── Attack Paths ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            foreach (var path in model.AttackPaths)
            {
                var pathColor = GetSeverityColor(path.OverallRisk);

                WriteColored("  ⚔️  ", ConsoleColor.White);
                WriteColored(path.Name, pathColor);
                WriteColored($" ({path.StepCount} steps, risk score: {path.CombinedRiskScore})", ConsoleColor.DarkGray);
                Console.WriteLine();

                WriteColored("     ", ConsoleColor.White);
                WriteLineColored(path.Narrative, ConsoleColor.DarkGray);

                for (int s = 0; s < path.Steps.Count; s++)
                {
                    var step = path.Steps[s];
                    var arrow = s == 0 ? "►" : "→";
                    WriteColored($"     {arrow} Step {step.Order}: ", ConsoleColor.White);
                    WriteLineColored(step.Action, GetSeverityColor(step.Threat.RiskLevel));
                }

                Console.WriteLine();
            }
        }

        // Priority Actions
        if (model.PriorityActions.Count > 0)
        {
            WriteLineColored("  ── Priority Actions ──", ConsoleColor.DarkGray);
            Console.WriteLine();

            for (int i = 0; i < model.PriorityActions.Count; i++)
            {
                WriteColored($"  {i + 1}. ", ConsoleColor.White);
                WriteLineColored(model.PriorityActions[i], ConsoleColor.Green);
            }

            Console.WriteLine();
        }

        if (model.TotalThreats == 0)
        {
            WriteLineColored("  ✓ No STRIDE threats identified — current security posture looks strong!", ConsoleColor.Green);
        }
    }
}
