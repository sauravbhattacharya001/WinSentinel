namespace WinSentinel.Cli;

using WinSentinel.Core.Models;

public static partial class ConsoleFormatter
{
    public static void PrintBeacon(BeaconDetectionReport report, CliOptions options)
    {
        var original = Console.ForegroundColor;

        // Header
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║     📡 BEACON DETECTOR — C2 Communication Analysis      ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
        Console.ForegroundColor = original;
        Console.WriteLine();

        // Risk Score Gauge
        Console.Write("  Overall Risk: ");
        var scoreColor = report.OverallRiskScore switch
        {
            >= 80 => ConsoleColor.DarkRed,
            >= 60 => ConsoleColor.Red,
            >= 40 => ConsoleColor.Yellow,
            >= 20 => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Green
        };
        Console.ForegroundColor = scoreColor;
        var filled = (int)(report.OverallRiskScore / 5);
        var empty = 20 - filled;
        Console.Write($"[{new string('█', filled)}{new string('░', empty)}] {report.OverallRiskScore}/100");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Summary Stats
        Console.Write("  Connections Analyzed: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{report.ConnectionsAnalyzed}");
        Console.ForegroundColor = original;

        Console.Write("  │  Beacons Found: ");
        Console.ForegroundColor = report.BeaconsDetected > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"{report.BeaconsDetected}");
        Console.ForegroundColor = original;

        Console.Write("  │  High/Critical: ");
        Console.ForegroundColor = report.HighConfidenceBeacons > 0 ? ConsoleColor.DarkRed : ConsoleColor.Green;
        Console.Write($"{report.HighConfidenceBeacons}");
        Console.ForegroundColor = original;
        Console.WriteLine();
        Console.WriteLine();

        // Beacon Candidates
        if (report.Candidates.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Detected Beacons ───────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var candidate in report.Candidates)
            {
                var levelColor = candidate.ConfidenceLevel switch
                {
                    BeaconConfidence.Critical => ConsoleColor.DarkRed,
                    BeaconConfidence.High => ConsoleColor.Red,
                    BeaconConfidence.Medium => ConsoleColor.Yellow,
                    _ => ConsoleColor.DarkYellow
                };

                var levelIcon = candidate.ConfidenceLevel switch
                {
                    BeaconConfidence.Critical => "🔴",
                    BeaconConfidence.High => "🟠",
                    BeaconConfidence.Medium => "🟡",
                    _ => "🟢"
                };

                Console.Write($"  {levelIcon} ");
                Console.ForegroundColor = levelColor;
                Console.Write($"[{candidate.ConfidenceLevel}]");
                Console.ForegroundColor = original;
                Console.Write($" {candidate.RemoteIp}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($":{string.Join(",", candidate.RemotePorts)}");
                Console.ForegroundColor = original;

                if (candidate.ProcessName != null)
                {
                    Console.Write($" via ");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write(candidate.ProcessName);
                    Console.ForegroundColor = original;
                }

                Console.WriteLine();

                // Details
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("     ");
                Console.ForegroundColor = original;
                Console.Write($"Interval: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{candidate.IntervalSeconds}s");
                Console.ForegroundColor = original;
                Console.Write($"  Jitter: ");
                Console.ForegroundColor = candidate.JitterPercent < 10 ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write($"{candidate.JitterPercent}%");
                Console.ForegroundColor = original;
                Console.Write($"  Callbacks: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{candidate.CallbackCount}");
                Console.ForegroundColor = original;
                Console.Write($"  Risk: ");
                Console.ForegroundColor = candidate.RiskScore >= 70 ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write($"{candidate.RiskScore}");
                Console.ForegroundColor = original;
                Console.WriteLine();

                if (candidate.MatchedProfile != null)
                {
                    Console.Write("     ⚠️  Profile Match: ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(candidate.MatchedProfile);
                    Console.ForegroundColor = original;
                }

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"     {candidate.Assessment}");
                Console.ForegroundColor = original;

                Console.Write("     MITRE: ");
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine(candidate.MitreTechnique);
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✅ No beaconing patterns detected in current analysis window.");
            Console.ForegroundColor = original;
            Console.WriteLine();
        }

        // Statistics
        if (report.Stats.TotalUniqueEndpoints > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Statistics ─────────────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();
            Console.WriteLine($"  Unique Endpoints: {report.Stats.TotalUniqueEndpoints}    Regular Patterns: {report.Stats.EndpointsWithRegularIntervals}");
            if (report.Stats.EndpointsWithRegularIntervals > 0)
            {
                Console.WriteLine($"  Mean Interval: {report.Stats.MeanInterval:F1}s    Median: {report.Stats.MedianInterval:F1}s");
                Console.WriteLine($"  Fast (<60s): {report.Stats.ShortBeacons}    Medium (60-300s): {report.Stats.MediumBeacons}    Slow (>300s): {report.Stats.LongBeacons}");
                Console.WriteLine($"  Profile Matches: {report.Stats.ProfileMatches}");
            }
            Console.WriteLine();
        }

        // Recommendations
        if (report.Recommendations.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  ─── Recommendations ───────────────────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var rec in report.Recommendations.OrderBy(r => r.Priority))
            {
                var priorityColor = rec.Priority switch
                {
                    1 => ConsoleColor.Red,
                    2 => ConsoleColor.Yellow,
                    _ => ConsoleColor.White
                };

                Console.Write($"  [{rec.Priority}] ");
                Console.ForegroundColor = priorityColor;
                Console.WriteLine(rec.Action);
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"      {rec.Rationale}");
                if (rec.Command != null)
                {
                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine($"      $ {rec.Command}");
                }
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
        }

        // Known Profiles Reference
        if (!options.Quiet)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─── Known C2 Profiles (reference) ─────────────────────────");
            Console.ForegroundColor = original;
            Console.WriteLine();

            foreach (var profile in WinSentinel.Core.Services.BeaconDetectionService.KnownProfiles.Take(5))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"    • {profile.Name,-28}");
                Console.Write($" interval={profile.TypicalIntervalSeconds}s");
                Console.Write($"  jitter={profile.TypicalJitterPercent}%");
                Console.ForegroundColor = original;
                Console.WriteLine();
            }
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"    ... and {WinSentinel.Core.Services.BeaconDetectionService.KnownProfiles.Count - 5} more profiles");
            Console.ForegroundColor = original;
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Analysis completed at {report.AnalysisTimestamp:yyyy-MM-dd HH:mm:ss} UTC");
        Console.ForegroundColor = original;
        Console.WriteLine();
    }
}
