namespace WinSentinel.Cli;

using WinSentinel.Core.Services;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Renders a Security Compass with ASCII compass rose, headings, waypoints, and trajectory.
    /// </summary>
    public static void PrintCompass(CompassResult result, CliOptions options)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🧭  Security Compass                  ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        if (result.Headings.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No module data found. Run --audit first.");
            Console.ResetColor();
            return;
        }

        // ── Position Info ──
        Console.WriteLine();
        Console.Write("  Position: ");
        WriteColored($"{Math.Abs(result.CurrentPosition.Latitude):F1}°{(result.CurrentPosition.Latitude >= 0 ? "N" : "S")}", ConsoleColor.White);
        Console.Write(", ");
        WriteColored($"{Math.Abs(result.CurrentPosition.Longitude):F1}°{(result.CurrentPosition.Longitude >= 0 ? "E" : "W")}", ConsoleColor.White);
        Console.Write("  (");
        WriteColored(result.CurrentPosition.Label, ConsoleColor.Cyan);
        Console.WriteLine(")");

        Console.Write("  Ideal:    ");
        WriteColored($"{result.IdealPosition.Latitude:F1}°N", ConsoleColor.Green);
        Console.Write(", ");
        WriteColored($" {result.IdealPosition.Longitude:F1}°E", ConsoleColor.Green);
        Console.Write("  (");
        WriteColored(result.IdealPosition.Label, ConsoleColor.Green);
        Console.WriteLine(")");

        Console.Write("  Deviation: ");
        var devColor = result.DeviationDegrees < 30 ? ConsoleColor.Green
            : result.DeviationDegrees < 60 ? ConsoleColor.Yellow
            : result.DeviationDegrees < 90 ? ConsoleColor.DarkYellow
            : ConsoleColor.Red;
        WriteColored($"{result.DeviationDegrees:F1}° off-course", devColor);
        Console.WriteLine();

        // ── ASCII Compass Rose ──
        Console.WriteLine();
        PrintCompassRose(result);

        // ── Trajectory ──
        Console.WriteLine();
        Console.Write("  Trajectory: ");
        var trajColor = result.Trajectory.Direction switch
        {
            "approaching" => ConsoleColor.Green,
            "drifting" => ConsoleColor.Red,
            _ => ConsoleColor.Yellow
        };
        var trajArrow = result.Trajectory.Direction switch
        {
            "approaching" => "↗",
            "drifting" => "↘",
            _ => "→"
        };
        WriteColored($"{result.Trajectory.Direction} {trajArrow}", trajColor);
        Console.Write("  ");
        Console.WriteLine(result.Trajectory.Narrative);

        // ── Headings Table ──
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ── Heading by Module ──────────────────────────────");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"Module",-20} {"Score",6} {"Target",7} {"Bearing",8} {"Dir",5} {"Gap",5}  Guidance");
        Console.ResetColor();

        foreach (var h in result.Headings)
        {
            Console.Write($"  {h.Module,-20}");
            WriteColored($"{h.CurrentScore,6}", ScoreColor(h.CurrentScore));
            Console.Write($"{h.TargetScore,7}");
            Console.Write($"{h.BearingDegrees,8:F0}°");
            var dirArrow = h.Direction switch
            {
                "N" => "↑", "NE" => "↗", "E" => "→", "SE" => "↘",
                "S" => "↓", "SW" => "↙", "W" => "←", "NW" => "↖",
                _ => "•"
            };
            WriteColored($" {dirArrow,-4}", h.Distance > 25 ? ConsoleColor.Red : h.Distance > 10 ? ConsoleColor.Yellow : ConsoleColor.Green);
            Console.Write($"{h.Distance,5:F0}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  {Truncate(h.Guidance, 50)}");
            Console.ResetColor();
            Console.WriteLine();
        }

        // ── Course Correction ──
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ── Course Correction ──────────────────────────────");
        Console.ResetColor();
        Console.Write("  Primary: ");
        WriteColored(result.CourseCorrection, ConsoleColor.White);
        Console.WriteLine();

        // ── Waypoints ──
        if (result.Waypoints.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ── Waypoints ─────────────────────────────────────");
            Console.ResetColor();

            foreach (var wp in result.Waypoints.Take(10))
            {
                Console.Write($"  {wp.Order,2}. 🏁 ");
                WriteColored($"{wp.Module,-18}", ConsoleColor.White);
                Console.Write(" → ");
                WriteColored($"+{wp.ExpectedGain} pts", ConsoleColor.Green);
                Console.Write($"  ({wp.CumulativeProgress:F0}% toward ideal)");
                Console.WriteLine();
            }

            if (result.Waypoints.Count > 10)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ... and {result.Waypoints.Count - 10} more waypoints");
                Console.ResetColor();
            }
        }

        Console.WriteLine();
    }

    private static void PrintCompassRose(CompassResult result)
    {
        // Simple ASCII compass rose showing current position vs ideal
        // Map position to a 15x15 grid
        int size = 7;
        int cx = size, cy = size;

        // Map ideal to center-top, current to relative position
        // Y axis: latitude (N=top, S=bottom), X axis: longitude (W=left, E=right)
        double latRange = 180.0; // -90 to 90
        double lonRange = 360.0; // -180 to 180

        int idealY = 1; // Near top
        int idealX = cx; // Center

        // Current position relative
        double latNorm = (90.0 - result.CurrentPosition.Latitude) / latRange; // 0=N, 1=S
        double lonNorm = (result.CurrentPosition.Longitude + 180.0) / lonRange; // 0=W, 1=E
        int curY = Math.Clamp((int)(latNorm * (size * 2)), 0, size * 2);
        int curX = Math.Clamp((int)(lonNorm * (size * 2)), 0, size * 2);

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("                N (Secure)");
        Console.WriteLine("                │");

        for (int y = 0; y <= size * 2; y++)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            if (y == size)
                Console.Write("    W ──────────┼──────────> E");
            else
            {
                Console.Write("                │");
                // Check if ideal or current is on this row
                bool hasIdeal = y == idealY && idealX == cx;
                bool hasCurrent = y == curY;

                if (hasIdeal && hasCurrent && curX == idealX)
                {
                    // Same position
                    Console.ResetColor();
                    // Position the marker
                    Console.CursorLeft = 16 + (curX - cx);
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write("⊕");
                }
                else
                {
                    if (hasIdeal)
                    {
                        Console.CursorLeft = 18;
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write("★ ideal");
                    }
                    if (hasCurrent)
                    {
                        Console.CursorLeft = 16 + Math.Max(0, curX - cx + 2);
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write("● you");
                    }
                }
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("                │");
        Console.WriteLine("                S (Critical)");
        Console.ResetColor();

        // Legend
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("    ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("★");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("=ideal  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("●");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("=current position");
        Console.ResetColor();
    }

}
