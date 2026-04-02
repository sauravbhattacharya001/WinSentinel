namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintPulse(
        List<(DateTimeOffset date, int score, int total, int critical, int high, int medium, int low)> dataPoints,
        int chartWidth,
        int alertBelow,
        bool showFindings)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       💓  Security Pulse                    ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        if (dataPoints.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No audit data found.");
            Console.ResetColor();
            return;
        }

        var first = dataPoints[0];
        var last = dataPoints[^1];
        var scores = dataPoints.Select(p => p.score).ToList();
        var avg = scores.Average();
        var min = scores.Min();
        var max = scores.Max();
        var current = last.score;
        var delta = current - first.score;
        var alertCount = scores.Count(s => s < alertBelow);

        // Volatility (standard deviation)
        var variance = scores.Select(s => Math.Pow(s - avg, 2)).Average();
        var stdDev = Math.Sqrt(variance);

        // Streak detection
        int streak = 0;
        bool streakUp = true;
        if (dataPoints.Count >= 2)
        {
            streakUp = dataPoints[^1].score >= dataPoints[^2].score;
            streak = 1;
            for (int i = dataPoints.Count - 2; i >= 1; i--)
            {
                bool thisUp = dataPoints[i].score >= dataPoints[i - 1].score;
                if (thisUp == streakUp) streak++;
                else break;
            }
        }

        // Header stats
        Console.WriteLine();
        Console.Write("  Period: ");
        WriteColored($"{first.date:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write(" → ");
        WriteColored($"{last.date:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write($"  ({dataPoints.Count} audits)");
        Console.WriteLine();
        Console.WriteLine();

        // Current score
        Console.Write("  Current: ");
        WriteColored($"{current}", ScoreColor(current));
        Console.Write("  │  Avg: ");
        WriteColored($"{avg:F1}", ScoreColor((int)avg));
        Console.Write("  │  Min: ");
        WriteColored($"{min}", ScoreColor(min));
        Console.Write("  │  Max: ");
        WriteColored($"{max}", ScoreColor(max));
        Console.WriteLine();

        Console.Write("  Change: ");
        var deltaStr = delta >= 0 ? $"+{delta}" : $"{delta}";
        WriteColored(deltaStr, delta >= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.Write("  │  Volatility: ");
        var volColor = stdDev < 5 ? ConsoleColor.Green : stdDev < 15 ? ConsoleColor.Yellow : ConsoleColor.Red;
        WriteColored($"σ={stdDev:F1}", volColor);
        Console.Write("  │  Streak: ");
        var streakIcon = streakUp ? "▲" : "▼";
        WriteColored($"{streak}{streakIcon}", streakUp ? ConsoleColor.Green : ConsoleColor.Red);
        Console.WriteLine();

        if (alertCount > 0)
        {
            Console.Write("  ⚠ Alerts: ");
            WriteColored($"{alertCount} runs below {alertBelow}", ConsoleColor.Red);
            Console.WriteLine();
        }

        // Health assessment
        Console.Write("  Vitals: ");
        var healthLabel = current >= 80 ? "HEALTHY" : current >= 60 ? "ELEVATED" : current >= 40 ? "CONCERNING" : "CRITICAL";
        var healthColor = current >= 80 ? ConsoleColor.Green : current >= 60 ? ConsoleColor.Yellow : current >= 40 ? ConsoleColor.DarkYellow : ConsoleColor.Red;
        var healthIcon = current >= 80 ? "💚" : current >= 60 ? "💛" : current >= 40 ? "🧡" : "❤️";
        Console.Write($"{healthIcon} ");
        WriteColored(healthLabel, healthColor);
        Console.WriteLine();

        // ASCII EKG chart
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ─── Score Pulse ───────────────────────────────────────");
        Console.ResetColor();

        var chartHeight = 12;
        var minScore = Math.Max(0, min - 5);
        var maxScore = Math.Min(100, max + 5);
        var range = Math.Max(maxScore - minScore, 1);

        // Resample to chart width
        var resampled = ResampleScores(scores, chartWidth);

        for (int row = chartHeight; row >= 0; row--)
        {
            var rowScore = minScore + (range * row / chartHeight);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  {rowScore,3} │");

            for (int col = 0; col < resampled.Count; col++)
            {
                var val = resampled[col];
                var normalizedRow = (int)Math.Round((val - minScore) * chartHeight / (double)range);

                if (normalizedRow == row)
                {
                    var color = ScoreColor((int)val);
                    if (val < alertBelow) color = ConsoleColor.Red;
                    Console.ForegroundColor = color;

                    // EKG-style character selection
                    char ch;
                    if (col > 0)
                    {
                        var prevNorm = (int)Math.Round((resampled[col - 1] - minScore) * chartHeight / (double)range);
                        if (normalizedRow > prevNorm) ch = '╱';
                        else if (normalizedRow < prevNorm) ch = '╲';
                        else ch = '━';
                    }
                    else ch = '●';

                    Console.Write(ch);
                }
                else if (row == 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write('─');
                }
                else
                {
                    // Draw vertical connector if between current and previous point
                    bool inBetween = false;
                    if (col > 0)
                    {
                        var curNorm = (int)Math.Round((resampled[col] - minScore) * chartHeight / (double)range);
                        var prevNorm = (int)Math.Round((resampled[col - 1] - minScore) * chartHeight / (double)range);
                        var lo = Math.Min(curNorm, prevNorm);
                        var hi = Math.Max(curNorm, prevNorm);
                        if (row > lo && row < hi) inBetween = true;
                    }

                    if (inBetween)
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write('│');
                    }
                    else
                    {
                        Console.Write(' ');
                    }
                }
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        // X-axis
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("      └");
        Console.Write(new string('─', resampled.Count));
        Console.ResetColor();
        Console.WriteLine();

        // Date labels
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("       ");
        Console.Write($"{first.date:MM/dd}");
        var gap = resampled.Count - 10;
        if (gap > 0) Console.Write(new string(' ', gap));
        Console.Write($"{last.date:MM/dd}");
        Console.ResetColor();
        Console.WriteLine();

        // Alert threshold line label
        if (alertBelow > minScore && alertBelow < maxScore)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"  Alert threshold: score < {alertBelow}");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Findings summary
        if (showFindings)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─── Finding Trends ────────────────────────────────────");
            Console.ResetColor();

            var recentHalf = dataPoints.Skip(dataPoints.Count / 2).ToList();
            var olderHalf = dataPoints.Take(dataPoints.Count / 2).ToList();

            void PrintFindingTrend(string label, Func<(DateTimeOffset date, int score, int total, int critical, int high, int medium, int low), int> selector, ConsoleColor color)
            {
                var recentAvg = recentHalf.Count > 0 ? recentHalf.Average(p => selector(p)) : 0;
                var olderAvg = olderHalf.Count > 0 ? olderHalf.Average(p => selector(p)) : 0;
                var trend = recentAvg - olderAvg;
                var trendStr = trend >= 0.5 ? "▲" : trend <= -0.5 ? "▼" : "─";
                var trendColor = trend <= -0.5 ? ConsoleColor.Green : trend >= 0.5 ? ConsoleColor.Red : ConsoleColor.DarkGray;

                Console.Write("  ");
                Console.ForegroundColor = color;
                Console.Write($"  {label,-10}");
                Console.ResetColor();
                Console.Write($" latest: ");
                WriteColored($"{selector(dataPoints[^1]),3}", color);
                Console.Write($"  avg: {recentAvg:F1}");
                Console.Write("  trend: ");
                WriteColored(trendStr, trendColor);
                Console.WriteLine();
            }

            PrintFindingTrend("Critical", p => p.critical, ConsoleColor.Red);
            PrintFindingTrend("High", p => p.high, ConsoleColor.DarkYellow);
            PrintFindingTrend("Medium", p => p.medium, ConsoleColor.Yellow);
            PrintFindingTrend("Low", p => p.low, ConsoleColor.DarkGray);
        }

        // Recommendations
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ─── Recommendations ──────────────────────────────────");
        Console.ResetColor();

        if (current < alertBelow)
        {
            Console.Write("  ");
            WriteColored("  🚨 Score is below alert threshold!", ConsoleColor.Red);
            Console.WriteLine(" Run --audit --fix to remediate critical findings.");
        }

        if (stdDev > 15)
        {
            Console.Write("  ");
            WriteColored("  ⚡ High volatility detected.", ConsoleColor.Yellow);
            Console.WriteLine(" Scores are swinging wildly — investigate root causes.");
        }

        if (!streakUp && streak >= 3)
        {
            Console.Write("  ");
            WriteColored($"  📉 {streak}-run downward streak.", ConsoleColor.Red);
            Console.WriteLine(" Security posture is degrading — take action.");
        }

        if (streakUp && streak >= 3)
        {
            Console.Write("  ");
            WriteColored($"  📈 {streak}-run upward streak!", ConsoleColor.Green);
            Console.WriteLine(" Great progress — keep it up.");
        }

        if (current >= 80 && stdDev < 5)
        {
            Console.Write("  ");
            WriteColored("  ✅ Stable and healthy.", ConsoleColor.Green);
            Console.WriteLine(" Security posture is solid.");
        }

        Console.WriteLine();

        return;

        static ConsoleColor ScoreColor(int score) =>
            score >= 80 ? ConsoleColor.Green :
            score >= 60 ? ConsoleColor.Yellow :
            score >= 40 ? ConsoleColor.DarkYellow :
            ConsoleColor.Red;

        static List<double> ResampleScores(List<int> scores, int targetWidth)
        {
            if (scores.Count <= targetWidth) return scores.Select(s => (double)s).ToList();

            var result = new List<double>();
            var step = (double)(scores.Count - 1) / (targetWidth - 1);
            for (int i = 0; i < targetWidth; i++)
            {
                var idx = i * step;
                var lo = (int)Math.Floor(idx);
                var hi = Math.Min(lo + 1, scores.Count - 1);
                var frac = idx - lo;
                result.Add(scores[lo] * (1 - frac) + scores[hi] * frac);
            }
            return result;
        }
    }
}
