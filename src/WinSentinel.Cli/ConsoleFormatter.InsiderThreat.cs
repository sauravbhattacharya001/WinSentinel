namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintInsiderThreat(InsiderThreatReport report)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║      🕵️ INSIDER THREAT — Behavioral Profiler                ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // ── Overview ─────────────────────────────────────────────
        var tierColor = report.RiskTier switch
        {
            "Critical" => ConsoleColor.Red,
            "High" => ConsoleColor.Red,
            "Elevated" => ConsoleColor.Yellow,
            "Moderate" => ConsoleColor.Yellow,
            _ => ConsoleColor.Green
        };

        Console.Write("  Posture Score: ");
        Console.ForegroundColor = tierColor;
        Console.Write($"{report.PostureScore}/100");
        Console.ForegroundColor = original;
        Console.Write("  │  Risk Tier: ");
        Console.ForegroundColor = tierColor;
        Console.Write(report.RiskTier);
        Console.ForegroundColor = original;
        Console.Write("  │  Users: ");
        Console.Write($"{report.UsersProfiled}");
        Console.Write("  │  Events: ");
        Console.WriteLine($"{report.EventsProcessed}");
        Console.WriteLine($"  History: {report.DaysAnalyzed} days analyzed");
        Console.WriteLine();

        // ── Risk Distribution ────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ─── Risk Distribution ───────────────────────────────────────");
        Console.ForegroundColor = original;
        if (report.Stats.HighRiskUsers > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ■ Critical/High: {report.Stats.HighRiskUsers}");
            Console.ForegroundColor = original;
        }
        if (report.Stats.MediumRiskUsers > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  ■ Medium: {report.Stats.MediumRiskUsers}");
            Console.ForegroundColor = original;
        }
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ■ Low: {report.Stats.LowRiskUsers}");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // ── User Risk Profiles ───────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ─── User Risk Profiles ──────────────────────────────────────");
        Console.ForegroundColor = original;
        var topProfiles = report.Profiles.Take(10).ToList();
        if (topProfiles.Count == 0)
        {
            Console.WriteLine("  No user profiles detected.");
        }
        else
        {
            Console.WriteLine("  {0,-25} {1,-8} {2,-12} {3,-15} {4}",
                "Username", "Score", "Level", "Trend", "Patterns");
            Console.WriteLine("  " + new string('─', 75));

            foreach (var profile in topProfiles)
            {
                var color = profile.RiskLevel switch
                {
                    InsiderRiskLevel.Critical => ConsoleColor.Red,
                    InsiderRiskLevel.High => ConsoleColor.Red,
                    InsiderRiskLevel.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.Gray
                };

                var name = profile.Username.Length > 24
                    ? profile.Username[..21] + "..."
                    : profile.Username;
                Console.Write($"  {name,-25} ");
                Console.ForegroundColor = color;
                Console.Write($"{profile.RiskScore,-8}");
                Console.Write($"{profile.RiskLevel,-12}");
                Console.ForegroundColor = original;
                Console.Write($"{profile.ActivityTrend,-15} ");
                Console.WriteLine($"{profile.ThreatPatterns.Count} pattern(s)");

                // Show deviations for high-risk users
                if (profile.RiskLevel >= InsiderRiskLevel.High)
                {
                    foreach (var dev in profile.Deviations.Take(3))
                    {
                        Console.Write("    └─ ");
                        Console.ForegroundColor = dev.Severity == Severity.Critical
                            ? ConsoleColor.Red : ConsoleColor.Yellow;
                        Console.Write($"[{dev.Type}]");
                        Console.ForegroundColor = original;
                        Console.WriteLine($" {dev.Description}");
                    }
                }
            }
        }
        Console.WriteLine();

        // ── Threat Indicators ────────────────────────────────────
        if (report.Indicators.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  ─── Threat Indicators ({report.Indicators.Count}) ─────────────────────────────────");
            Console.ForegroundColor = original;
            foreach (var indicator in report.Indicators.Take(8))
            {
                Console.Write("  ");
                Console.ForegroundColor = indicator.Severity == Severity.Critical
                    ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write($"[{indicator.Category}]");
                Console.ForegroundColor = original;
                Console.Write($" {indicator.Username}: ");
                Console.WriteLine(indicator.Description);
                Console.WriteLine($"    Confidence: {indicator.Confidence}%  " +
                    (indicator.MitreTechnique != null ? $"MITRE: {indicator.MitreTechnique}" : ""));
                if (indicator.Evidence.Count > 0)
                {
                    Console.WriteLine($"    Evidence: {indicator.Evidence.First()}");
                }
                Console.WriteLine();
            }
        }

        // ── Anomaly Timeline ─────────────────────────────────────
        if (report.AnomalyTimeline.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  ─── Anomaly Timeline (recent {Math.Min(8, report.AnomalyTimeline.Count)}) ──────────────────────");
            Console.ForegroundColor = original;
            foreach (var anomaly in report.AnomalyTimeline.Take(8))
            {
                var impactColor = anomaly.ImpactScore >= 8 ? ConsoleColor.Red :
                                  anomaly.ImpactScore >= 5 ? ConsoleColor.Yellow :
                                  ConsoleColor.Gray;
                Console.Write($"  {anomaly.Timestamp:yyyy-MM-dd HH:mm} ");
                Console.ForegroundColor = impactColor;
                Console.Write($"[Impact:{anomaly.ImpactScore}]");
                Console.ForegroundColor = original;
                Console.WriteLine($" {anomaly.Username} — {anomaly.AnomalyType}: {anomaly.Description}");
            }
            Console.WriteLine();
        }

        // ── Stats Summary ────────────────────────────────────────
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ─── Signal Summary ──────────────────────────────────────────");
        Console.ForegroundColor = original;
        Console.WriteLine($"  Off-hours deviations:     {report.Stats.OffHoursEvents}");
        Console.WriteLine($"  Exfiltration indicators:  {report.Stats.ExfiltrationIndicators}");
        Console.WriteLine($"  Privilege abuse signals:  {report.Stats.PrivilegeAbuseIndicators}");
        Console.WriteLine($"  Account anomalies:        {report.Stats.AccountAnomalies}");
        Console.WriteLine($"  Pre-departure signals:    {report.Stats.PreDepartureUsers} user(s)");
        Console.WriteLine();

        // ── Recommendations ──────────────────────────────────────
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Autonomous Recommendations ─────────────────────────────");
            Console.ForegroundColor = original;
            foreach (var rec in report.Recommendations)
            {
                var color = rec.Priority <= 2 ? ConsoleColor.Red :
                            rec.Priority <= 4 ? ConsoleColor.Yellow : ConsoleColor.Cyan;
                Console.Write($"  {rec.Priority}. ");
                Console.ForegroundColor = color;
                Console.WriteLine(rec.Action);
                Console.ForegroundColor = original;
                Console.WriteLine($"     Target: {rec.Target}");
                Console.WriteLine($"     Rationale: {rec.Rationale}");
                Console.WriteLine($"     Impact: {rec.ExpectedImpact}");
                Console.WriteLine();
            }
        }

        Console.ForegroundColor = original;
    }
}
