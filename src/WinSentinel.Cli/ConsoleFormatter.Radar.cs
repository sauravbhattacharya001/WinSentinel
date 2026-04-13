namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Renders an ASCII radar/spider chart showing per-module security scores
    /// with optional historical comparison overlay.
    /// </summary>
    public static void PrintRadar(
        List<(string name, int score)> modules,
        List<int?> previousScores,
        int overallScore,
        DateTimeOffset fromDate,
        DateTimeOffset toDate,
        int auditRuns,
        int radius = 14)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       📡  Security Radar                    ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        if (modules.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No module data found.");
            Console.ResetColor();
            return;
        }

        Console.WriteLine();
        Console.Write("  Period: ");
        WriteColored($"{fromDate:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write(" → ");
        WriteColored($"{toDate:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write("  |  Audits: ");
        WriteColored($"{auditRuns}", ConsoleColor.White);
        Console.Write("  |  Overall: ");
        WriteColored($"{overallScore}/100", ScoreColor(overallScore));
        Console.WriteLine();

        // === ASCII Radar Chart ===
        int n = modules.Count;
        int size = radius;
        int diameter = size * 2 + 1;
        int cx = size;
        int cy = size;

        // Grid for drawing
        char[,] grid = new char[diameter, diameter];
        ConsoleColor[,] colors = new ConsoleColor[diameter, diameter];
        for (int y = 0; y < diameter; y++)
            for (int x = 0; x < diameter; x++)
            {
                grid[y, x] = ' ';
                colors[y, x] = ConsoleColor.DarkGray;
            }

        // Draw reference circles at 25%, 50%, 75%, 100%
        foreach (var pct in new[] { 25, 50, 75, 100 })
        {
            double r = size * pct / 100.0;
            int steps = Math.Max(60, (int)(r * 12));
            for (int s = 0; s < steps; s++)
            {
                double angle = 2 * Math.PI * s / steps;
                int px = cx + (int)Math.Round(r * Math.Cos(angle));
                int py = cy + (int)Math.Round(r * Math.Sin(angle) * 0.5); // 0.5 for aspect ratio
                if (px >= 0 && px < diameter && py >= 0 && py < diameter && grid[py, px] == ' ')
                {
                    grid[py, px] = '·';
                    colors[py, px] = ConsoleColor.DarkGray;
                }
            }
        }

        // Draw axis lines from center to each module
        double[] angles = new double[n];
        for (int i = 0; i < n; i++)
        {
            angles[i] = -Math.PI / 2 + 2 * Math.PI * i / n; // Start from top
            for (int step = 0; step <= size; step++)
            {
                int px = cx + (int)Math.Round(step * Math.Cos(angles[i]));
                int py = cy + (int)Math.Round(step * Math.Sin(angles[i]) * 0.5);
                if (px >= 0 && px < diameter && py >= 0 && py < diameter && grid[py, px] == ' ')
                {
                    grid[py, px] = '·';
                    colors[py, px] = ConsoleColor.DarkGray;
                }
            }
        }

        // Plot previous scores (if available) as 'o'
        bool hasPrevious = previousScores.Any(s => s.HasValue);
        if (hasPrevious)
        {
            PlotPolygon(grid, colors, cx, cy, size, n, angles,
                previousScores.Select(s => s ?? 0).ToArray(), 'o', ConsoleColor.DarkYellow);
        }

        // Plot current scores as '●'
        PlotPolygon(grid, colors, cx, cy, size, n, angles,
            modules.Select(m => m.score).ToArray(), '●', ConsoleColor.Green);

        // Place module labels (indices) at axis endpoints
        for (int i = 0; i < n; i++)
        {
            double labelR = size + 2;
            int lx = cx + (int)Math.Round(labelR * Math.Cos(angles[i]));
            int ly = cy + (int)Math.Round(labelR * Math.Sin(angles[i]) * 0.5);
            char label = (char)('A' + (i < 26 ? i : i - 26));
            if (lx >= 0 && lx < diameter && ly >= 0 && ly < diameter)
            {
                grid[ly, lx] = label;
                colors[ly, lx] = ConsoleColor.White;
            }
        }

        // Render grid
        Console.WriteLine();
        for (int y = 0; y < diameter; y++)
        {
            Console.Write("    ");
            for (int x = 0; x < diameter; x++)
            {
                Console.ForegroundColor = colors[y, x];
                Console.Write(grid[y, x]);
            }
            Console.WriteLine();
        }
        Console.ResetColor();

        // Legend
        Console.WriteLine();
        Console.Write("    ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("● Current");
        Console.ResetColor();
        if (hasPrevious)
        {
            Console.Write("  ");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Write("o Previous");
            Console.ResetColor();
        }
        Console.Write("  ");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("· Grid (25/50/75/100%)");
        Console.ResetColor();
        Console.WriteLine();

        // === Module Breakdown Table ===
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ┌────┬────────────────────────────┬───────┬──────────┬───────┬───────────┐");
        Console.WriteLine("  │ ID │ Module                     │ Score │ Previous │ Delta │ Trend     │");
        Console.WriteLine("  ├────┼────────────────────────────┼───────┼──────────┼───────┼───────────┤");
        Console.ResetColor();

        for (int i = 0; i < modules.Count; i++)
        {
            var (name, score) = modules[i];
            var prev = previousScores[i];
            char id = (char)('A' + (i < 26 ? i : i - 26));

            string shortName = name.Length > 26 ? name[..26] : name;
            string scoreStr = score.ToString().PadLeft(3);
            string prevStr = prev.HasValue ? prev.Value.ToString().PadLeft(5) : "  N/A";
            int delta = prev.HasValue ? score - prev.Value : 0;
            string deltaStr = prev.HasValue
                ? (delta > 0 ? $"+{delta}" : delta.ToString()).PadLeft(4)
                : " N/A";
            string trend = prev.HasValue
                ? (delta > 5 ? "▲▲ Great" : delta > 0 ? "▲ Better" : delta == 0 ? "● Stable" : delta >= -5 ? "▼ Worse" : "▼▼ Alert")
                : "— New";

            Console.Write($"  │ {id}  │ {shortName,-26} │ ");
            Console.ForegroundColor = ScoreColor(score);
            Console.Write(scoreStr);
            Console.ResetColor();
            Console.Write($"   │ {prevStr}    │ ");

            if (prev.HasValue)
            {
                Console.ForegroundColor = delta > 0 ? ConsoleColor.Green : delta < 0 ? ConsoleColor.Red : ConsoleColor.Gray;
                Console.Write(deltaStr);
                Console.ResetColor();
            }
            else
            {
                Console.Write(deltaStr);
            }

            Console.Write($"  │ ");
            Console.ForegroundColor = delta > 5 ? ConsoleColor.Green :
                                       delta > 0 ? ConsoleColor.DarkGreen :
                                       delta == 0 ? ConsoleColor.Gray :
                                       delta >= -5 ? ConsoleColor.Yellow : ConsoleColor.Red;
            Console.Write($"{trend,-9}");
            Console.ResetColor();
            Console.WriteLine(" │");
        }

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  └────┴────────────────────────────┴───────┴──────────┴───────┴───────────┘");
        Console.ResetColor();

        // === Posture Summary ===
        Console.WriteLine();
        var improving = modules.Select((m, i) => (m, i))
            .Where(x => previousScores[x.i].HasValue && x.m.score > previousScores[x.i]!.Value)
            .Select(x => x.m.name).ToList();
        var regressing = modules.Select((m, i) => (m, i))
            .Where(x => previousScores[x.i].HasValue && x.m.score < previousScores[x.i]!.Value)
            .Select(x => x.m.name).ToList();
        var weakest = modules.OrderBy(m => m.score).Take(3).ToList();
        var strongest = modules.OrderByDescending(m => m.score).Take(3).ToList();

        // Symmetry score (how balanced is the posture?)
        var avg = modules.Average(m => (double)m.score);
        var variance = modules.Sum(m => Math.Pow(m.score - avg, 2)) / modules.Count;
        var symmetry = Math.Max(0, 100 - (int)Math.Sqrt(variance));

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  ── Posture Insights ──────────────────────────────");
        Console.ResetColor();

        Console.Write("  Symmetry Score: ");
        WriteColored($"{symmetry}/100", ScoreColor(symmetry));
        Console.Write(" (");
        Console.Write(symmetry >= 90 ? "well-balanced" :
                      symmetry >= 70 ? "minor imbalances" :
                      symmetry >= 50 ? "notable gaps" : "severely uneven");
        Console.WriteLine(")");

        Console.Write("  Strongest:  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(string.Join(", ", strongest.Select(s => $"{s.name} ({s.score})")));
        Console.ResetColor();

        Console.Write("  Weakest:    ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(string.Join(", ", weakest.Select(s => $"{s.name} ({s.score})")));
        Console.ResetColor();

        if (improving.Count > 0)
        {
            Console.Write("  Improving:  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(string.Join(", ", improving));
            Console.ResetColor();
        }

        if (regressing.Count > 0)
        {
            Console.Write("  Regressing: ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(string.Join(", ", regressing));
            Console.ResetColor();
        }

        // Proactive recommendation
        if (weakest.Count > 0 && weakest[0].score < 50)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("  ⚠ Recommendation: ");
            Console.ResetColor();
            Console.WriteLine($"Focus remediation on \"{weakest[0].name}\" (score: {weakest[0].score}). ");
            Console.WriteLine($"    Use --harden --modules {weakest[0].name} to auto-fix available issues.");
        }
        else if (symmetry < 70)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("  ⚠ Recommendation: ");
            Console.ResetColor();
            Console.WriteLine("Posture is uneven. Address low-scoring modules to improve balance.");
        }

        Console.WriteLine();
        return;
    }

    private static void PlotPolygon(char[,] grid, ConsoleColor[,] colors,
        int cx, int cy, int size, int n, double[] angles, int[] scores,
        char marker, ConsoleColor color)
    {
        // Draw edges between consecutive score points
        var points = new (int x, int y)[n];
        for (int i = 0; i < n; i++)
        {
            double r = size * scores[i] / 100.0;
            points[i] = (
                cx + (int)Math.Round(r * Math.Cos(angles[i])),
                cy + (int)Math.Round(r * Math.Sin(angles[i]) * 0.5)
            );
        }

        // Draw lines between consecutive points
        for (int i = 0; i < n; i++)
        {
            int next = (i + 1) % n;
            DrawLine(grid, colors, points[i].x, points[i].y, points[next].x, points[next].y, '·', color);
        }

        // Place markers at vertices
        for (int i = 0; i < n; i++)
        {
            var (px, py) = points[i];
            if (px >= 0 && px < grid.GetLength(1) && py >= 0 && py < grid.GetLength(0))
            {
                grid[py, px] = marker;
                colors[py, px] = color;
            }
        }
    }

    private static void DrawLine(char[,] grid, ConsoleColor[,] colors,
        int x0, int y0, int x1, int y1, char ch, ConsoleColor color)
    {
        int dx = Math.Abs(x1 - x0), sx = x0 < x1 ? 1 : -1;
        int dy = -Math.Abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
        int err = dx + dy;

        int h = grid.GetLength(0), w = grid.GetLength(1);

        while (true)
        {
            if (x0 >= 0 && x0 < w && y0 >= 0 && y0 < h &&
                grid[y0, x0] != '●' && grid[y0, x0] != 'o')
            {
                // Don't overwrite existing markers
                if (grid[y0, x0] == ' ' || grid[y0, x0] == '·')
                {
                    grid[y0, x0] = ch;
                    colors[y0, x0] = color;
                }
            }

            if (x0 == x1 && y0 == y1) break;
            int e2 = 2 * err;
            if (e2 >= dy) { err += dy; x0 += sx; }
            if (e2 <= dx) { err += dx; y0 += sy; }
        }
    }
}
