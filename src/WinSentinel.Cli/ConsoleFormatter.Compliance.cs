using System.Text;
using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print a single-framework compliance report with control-level details.
    /// </summary>
    public static void PrintComplianceReport(ComplianceReport report)
    {
        Console.WriteLine();
        WriteLineColored($"  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored($"  ║       📋  Compliance Report                 ║", ConsoleColor.Cyan);
        WriteLineColored($"  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        // Framework info
        WriteColored("  Framework: ", ConsoleColor.DarkGray);
        WriteLineColored(report.FrameworkName, ConsoleColor.White);
        WriteColored("  Version:   ", ConsoleColor.DarkGray);
        WriteLineColored(report.FrameworkVersion, ConsoleColor.White);
        Console.WriteLine();

        // Verdict
        var verdictColor = report.Summary.OverallVerdict switch
        {
            ComplianceVerdict.Compliant => ConsoleColor.Green,
            ComplianceVerdict.PartiallyCompliant => ConsoleColor.Yellow,
            ComplianceVerdict.NonCompliant => ConsoleColor.Red,
            _ => ConsoleColor.DarkGray
        };
        var verdictIcon = report.Summary.OverallVerdict switch
        {
            ComplianceVerdict.Compliant => "✅",
            ComplianceVerdict.PartiallyCompliant => "⚠️",
            ComplianceVerdict.NonCompliant => "❌",
            _ => "❓"
        };
        WriteColored("  Verdict: ", ConsoleColor.DarkGray);
        WriteLineColored($"{verdictIcon} {report.Summary.OverallVerdict}", verdictColor);

        WriteColored("  Compliance: ", ConsoleColor.DarkGray);
        var pctColor = report.Summary.CompliancePercentage >= 80 ? ConsoleColor.Green
            : report.Summary.CompliancePercentage >= 50 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        WriteLineColored($"{report.Summary.CompliancePercentage:F1}%", pctColor);
        Console.WriteLine();

        // Summary bar
        WriteLineColored("  Summary", ConsoleColor.White);
        WriteLineColored("  ───────────────────────────────────────", ConsoleColor.DarkGray);
        WriteColored("    Pass:         ", ConsoleColor.DarkGray);
        WriteLineColored($"{report.Summary.PassCount}", ConsoleColor.Green);
        WriteColored("    Fail:         ", ConsoleColor.DarkGray);
        WriteLineColored($"{report.Summary.FailCount}", ConsoleColor.Red);
        WriteColored("    Partial:      ", ConsoleColor.DarkGray);
        WriteLineColored($"{report.Summary.PartialCount}", ConsoleColor.Yellow);
        WriteColored("    Not Assessed: ", ConsoleColor.DarkGray);
        WriteLineColored($"{report.Summary.NotAssessedCount}", ConsoleColor.DarkGray);
        Console.WriteLine();

        // Control details
        WriteLineColored("  Controls", ConsoleColor.White);
        WriteLineColored("  ───────────────────────────────────────", ConsoleColor.DarkGray);

        foreach (var control in report.Controls)
        {
            var (icon, color) = control.Status switch
            {
                ControlStatus.Pass => ("✅", ConsoleColor.Green),
                ControlStatus.Fail => ("❌", ConsoleColor.Red),
                ControlStatus.Partial => ("⚠️", ConsoleColor.Yellow),
                _ => ("─ ", ConsoleColor.DarkGray)
            };

            WriteColored($"    {icon} ", color);
            WriteColored($"[{control.ControlId}] ", ConsoleColor.DarkCyan);
            WriteLineColored(control.ControlTitle, ConsoleColor.White);

            if (control.Status == ControlStatus.Fail || control.Status == ControlStatus.Partial)
            {
                // Show related findings
                foreach (var finding in control.RelatedFindings)
                {
                    if (finding.Severity == Core.Models.Severity.Pass) continue;
                    var sevColor = finding.Severity == Core.Models.Severity.Critical
                        ? ConsoleColor.Red : ConsoleColor.Yellow;
                    WriteColored($"         ", ConsoleColor.DarkGray);
                    WriteColored($"[{finding.Severity}] ", sevColor);
                    WriteLineColored(finding.Title, ConsoleColor.DarkGray);
                }

                // Show remediation hints
                if (control.Remediation.Count > 0)
                {
                    WriteColored("         💡 ", ConsoleColor.DarkGray);
                    WriteLineColored(control.Remediation[0], ConsoleColor.DarkYellow);
                }
            }
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Print a cross-framework compliance comparison.
    /// </summary>
    public static void PrintCrossFrameworkCompliance(CrossFrameworkSummary summary)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║       📊  Cross-Framework Compliance        ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        WriteColored("  Security Score: ", ConsoleColor.DarkGray);
        var scoreColor = summary.SecurityScore >= 80 ? ConsoleColor.Green
            : summary.SecurityScore >= 60 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        WriteLineColored($"{summary.SecurityScore}/100", scoreColor);
        Console.WriteLine();

        // Framework comparison table
        WriteLineColored("  Framework                          Compliance   Verdict          Pass  Fail  Partial", ConsoleColor.White);
        WriteLineColored("  ────────────────────────────────── ────────── ──────────────── ───── ───── ───────", ConsoleColor.DarkGray);

        foreach (var fw in summary.FrameworkResults)
        {
            var pctColor = fw.CompliancePercentage >= 80 ? ConsoleColor.Green
                : fw.CompliancePercentage >= 50 ? ConsoleColor.Yellow
                : ConsoleColor.Red;
            var verdictColor = fw.Verdict switch
            {
                ComplianceVerdict.Compliant => ConsoleColor.Green,
                ComplianceVerdict.PartiallyCompliant => ConsoleColor.Yellow,
                ComplianceVerdict.NonCompliant => ConsoleColor.Red,
                _ => ConsoleColor.DarkGray
            };

            WriteColored($"  {fw.FrameworkName,-36} ", ConsoleColor.White);
            WriteColored($"{fw.CompliancePercentage,8:F1}%  ", pctColor);
            WriteColored($"{fw.Verdict,-16} ", verdictColor);
            WriteColored($"{fw.PassCount,5} ", ConsoleColor.Green);
            WriteColored($"{fw.FailCount,5} ", ConsoleColor.Red);
            WriteLineColored($"{fw.PartialCount,7}", ConsoleColor.Yellow);
        }

        Console.WriteLine();

        // Critical gaps across frameworks
        var allGaps = summary.FrameworkResults
            .Where(fw => fw.CriticalGaps.Count > 0)
            .ToList();

        if (allGaps.Count > 0)
        {
            WriteLineColored("  Critical Gaps", ConsoleColor.White);
            WriteLineColored("  ───────────────────────────────────────", ConsoleColor.DarkGray);

            foreach (var fw in allGaps)
            {
                WriteLineColored($"    {fw.FrameworkName}:", ConsoleColor.DarkCyan);
                foreach (var gap in fw.CriticalGaps.Take(5))
                {
                    WriteColored("      ❌ ", ConsoleColor.Red);
                    WriteLineColored(gap, ConsoleColor.DarkGray);
                }
                if (fw.CriticalGaps.Count > 5)
                {
                    WriteLineColored($"      ... and {fw.CriticalGaps.Count - 5} more", ConsoleColor.DarkGray);
                }
            }
            Console.WriteLine();
        }

        // High-impact fix recommendations (findings that affect multiple frameworks)
        var findingFrameworkCounts = new Dictionary<string, List<string>>();
        foreach (var fw in summary.FrameworkResults)
        {
            foreach (var gap in fw.CriticalGaps)
            {
                // Extract the control title after ": "
                var colonIdx = gap.IndexOf(": ");
                var title = colonIdx >= 0 ? gap[(colonIdx + 2)..] : gap;
                if (!findingFrameworkCounts.ContainsKey(title))
                    findingFrameworkCounts[title] = new List<string>();
                findingFrameworkCounts[title].Add(fw.FrameworkId);
            }
        }

        var multiFrameworkGaps = findingFrameworkCounts
            .Where(kv => kv.Value.Count > 1)
            .OrderByDescending(kv => kv.Value.Count)
            .Take(5)
            .ToList();

        if (multiFrameworkGaps.Count > 0)
        {
            WriteLineColored("  🎯 High-Impact Fixes (affect multiple frameworks)", ConsoleColor.White);
            WriteLineColored("  ───────────────────────────────────────", ConsoleColor.DarkGray);

            foreach (var gap in multiFrameworkGaps)
            {
                WriteColored($"    [{gap.Value.Count} frameworks] ", ConsoleColor.Magenta);
                WriteLineColored(gap.Key, ConsoleColor.White);
                WriteColored("      Frameworks: ", ConsoleColor.DarkGray);
                WriteLineColored(string.Join(", ", gap.Value), ConsoleColor.DarkCyan);
            }
            Console.WriteLine();
        }
    }

    /// <summary>
    /// Render a single-framework compliance report as CSV.
    /// </summary>
    public static string RenderComplianceCsv(ComplianceReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ControlId,ControlTitle,Status,FindingCount,Remediation");
        foreach (var control in report.Controls)
        {
            var remediation = control.Remediation.Count > 0
                ? control.Remediation[0].Replace("\"", "\"\"")
                : "";
            var findingCount = control.RelatedFindings.Count(f =>
                f.Severity != Core.Models.Severity.Pass);
            sb.AppendLine($"\"{control.ControlId}\",\"{control.ControlTitle}\",\"{control.Status}\",{findingCount},\"{remediation}\"");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Render a cross-framework summary as CSV.
    /// </summary>
    public static string RenderComplianceCrossFrameworkCsv(CrossFrameworkSummary summary)
    {
        var sb = new StringBuilder();
        sb.AppendLine("FrameworkId,FrameworkName,CompliancePercentage,Verdict,Pass,Fail,Partial,NotAssessed,CriticalGapCount");
        foreach (var fw in summary.FrameworkResults)
        {
            sb.AppendLine($"\"{fw.FrameworkId}\",\"{fw.FrameworkName}\",{fw.CompliancePercentage:F1},\"{fw.Verdict}\",{fw.PassCount},{fw.FailCount},{fw.PartialCount},{fw.NotAssessedCount},{fw.CriticalGaps.Count}");
        }
        return sb.ToString();
    }
}
