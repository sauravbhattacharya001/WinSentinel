namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintBurndown(
        int historyDays,
        List<(DateTimeOffset date, int total, int critical, int high, int medium, int low)> dataPoints,
        int chartWidth,
        string? severityFilter,
        DateTimeOffset? projectedZeroDate,
        double burnRate)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       📉  Findings Burndown                 ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        if (dataPoints.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No audit data found.");
            Console.ResetColor();
            return;
        }

        // Summary stats
        var first = dataPoints[0];
        var last = dataPoints[^1];
        var startCount = GetFilteredCount(first, severityFilter);
        var endCount = GetFilteredCount(last, severityFilter);
        var delta = endCount - startCount;

        Console.WriteLine();
        Console.Write("  Period: ");
        WriteColored($"{first.date:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write(" → ");
        WriteColored($"{last.date:yyyy-MM-dd}", ConsoleColor.Cyan);
        Console.Write($"  ({historyDays} days, {dataPoints.Count} audits)");
        Console.WriteLine();

        var label = severityFilter?.ToUpperInvariant() ?? "ALL";
        Console.Write($"  Tracking: ");
        WriteColored(label, ConsoleColor.White);
        Console.WriteLine(" findings");
        Console.WriteLine();

        Console.Write("  Start: ");
        WriteColored($"{startCount}", ConsoleColor.White);
        Console.Write("  →  Current: ");
        var endColor = endCount <= startCount ? ConsoleColor.Green : ConsoleColor.Red;
        WriteColored($"{endCount}", endColor);
        Console.Write("  (");
        var deltaStr = delta >= 0 ? $"+{delta}" : $"{delta}";
        WriteColored(deltaStr, delta <= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.WriteLine(")");

        Console.Write("  Burn rate: ");
        var rateColor = burnRate <= 0 ? ConsoleColor.Green : ConsoleColor.Red;
        WriteColored($"{burnRate:+0.00;-0.00;0.00}/day", rateColor);
        Console.WriteLine();

        if (projectedZeroDate.HasValue && burnRate < 0)
        {
            var daysToZero = (int)(projectedZeroDate.Value - DateTimeOffset.UtcNow).TotalDays;
            Console.Write("  Zero target: ");
            WriteColored($"{projectedZeroDate.Value:yyyy-MM-dd}", ConsoleColor.Green);
            Console.Write($" (~{daysToZero} days)");
            Console.WriteLine();
        }
        else if (burnRate >= 0 && endCount > 0)
        {
            Console.Write("  Zero target: ");
            WriteColored("NOT CONVERGING", ConsoleColor.Red);
            Console.Write(" — findings are not decreasing");
            Console.WriteLine();
        }

        // ASCII chart
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("  ── BURNDOWN CHART ──");
        Console.ResetColor();

        var counts = dataPoints.Select(p => GetFilteredCount(p, severityFilter)).ToList();
        var maxCount = counts.Max();
        if (maxCount == 0) maxCount = 1;

        // Determine chart rows (height)
        var chartHeight = 15;
        var step = (double)maxCount / chartHeight;

        // Y-axis labels width
        var yLabelWidth = maxCount.ToString().Length + 1;

        for (int row = chartHeight; row >= 0; row--)
        {
            var threshold = (int)(row * step);
            var label2 = row == chartHeight ? $"{maxCount}" :
                         row == 0 ? "0" :
                         row == chartHeight / 2 ? $"{maxCount / 2}" : "";

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  {label2.PadLeft(yLabelWidth)} │");
            Console.ResetColor();

            // Sample data points to fit chart width
            var sampleCount = Math.Min(chartWidth, dataPoints.Count);
            for (int col = 0; col < sampleCount; col++)
            {
                var idx = (int)((double)col / sampleCount * dataPoints.Count);
                var val = counts[idx];
                var barThreshold = (int)(row * step);

                if (val >= barThreshold && barThreshold > 0)
                {
                    // Color based on severity level at this point
                    var pct = (double)val / maxCount;
                    Console.ForegroundColor = pct > 0.7 ? ConsoleColor.Red :
                                              pct > 0.3 ? ConsoleColor.Yellow :
                                              ConsoleColor.Green;
                    Console.Write("█");
                }
                else
                {
                    Console.Write(" ");
                }
            }

            Console.ResetColor();
            Console.WriteLine();
        }

        // X-axis
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  {"".PadLeft(yLabelWidth)} └");
        Console.Write(new string('─', Math.Min(chartWidth, dataPoints.Count)));
        Console.ResetColor();
        Console.WriteLine();

        // X-axis labels
        var startLabel = first.date.ToString("MM/dd");
        var endLabel = last.date.ToString("MM/dd");
        var axisWidth = Math.Min(chartWidth, dataPoints.Count);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  {"".PadLeft(yLabelWidth + 1)}{startLabel}");
        Console.Write(new string(' ', Math.Max(0, axisWidth - startLabel.Length - endLabel.Length)));
        Console.Write(endLabel);
        Console.ResetColor();
        Console.WriteLine();

        // Breakdown table
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("  ── SEVERITY BREAKDOWN (current) ──");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌──────────┬───────┬────────────────────────────────┐");
        Console.WriteLine("  │ Severity │ Count │ Bar                            │");
        Console.WriteLine("  ├──────────┼───────┼────────────────────────────────┤");
        Console.ResetColor();

        var maxBar = 30;
        var severities = new[] {
            ("Critical", last.critical, ConsoleColor.Red),
            ("High", last.high, ConsoleColor.DarkRed),
            ("Medium", last.medium, ConsoleColor.Yellow),
            ("Low", last.low, ConsoleColor.Green)
        };

        var maxSev = severities.Max(s => s.Item2);
        if (maxSev == 0) maxSev = 1;

        foreach (var (name, count, color) in severities)
        {
            var barLen = (int)((double)count / maxSev * maxBar);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");
            Console.ForegroundColor = color;
            Console.Write($"{name,-8}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ResetColor();
            Console.Write($"{count,5}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ForegroundColor = color;
            Console.Write(new string('█', barLen));
            Console.Write(new string(' ', maxBar - barLen));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(" │");
            Console.ResetColor();
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └──────────┴───────┴────────────────────────────────┘");
        Console.ResetColor();

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ℹ Burndown shows finding count trend over time.");
        Console.WriteLine("    Zero target uses linear projection from current burn rate.");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static int GetFilteredCount(
        (DateTimeOffset date, int total, int critical, int high, int medium, int low) point,
        string? severityFilter)
    {
        return severityFilter switch
        {
            "critical" => point.critical,
            "high" => point.high,
            "medium" => point.medium,
            "low" => point.low,
            _ => point.total
        };
    }
}
