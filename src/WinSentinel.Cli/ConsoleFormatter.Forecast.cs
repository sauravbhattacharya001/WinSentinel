namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintForecast(
        int dataPoints,
        int historyDays,
        int forecastDays,
        double currentScore,
        double projectedScore,
        string trend,
        double r2,
        double scoreSlopePerDay,
        double findingsSlopePerDay,
        double criticalSlopePerDay,
        List<(int day, double score, double findings, double critical)> forecasts)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🔮  Security Forecast                 ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════╝");
        Console.ResetColor();

        // Summary
        var trendEmoji = trend switch
        {
            "improving" => "📈",
            "declining" => "📉",
            _ => "➡️"
        };

        var trendColor = trend switch
        {
            "improving" => ConsoleColor.Green,
            "declining" => ConsoleColor.Red,
            _ => ConsoleColor.Yellow
        };

        Console.WriteLine();
        Console.Write("  Analysis based on ");
        WriteColored($"{dataPoints} audit runs", ConsoleColor.Cyan);
        Console.WriteLine($" over the last {historyDays} days");
        Console.WriteLine();

        // Current vs projected
        Console.Write("  Current Score:   ");
        WriteScoreColored(currentScore);
        Console.WriteLine();
        Console.Write("  Projected Score: ");
        WriteScoreColored(projectedScore);
        Console.Write($"  (in {forecastDays} days)");
        Console.WriteLine();

        Console.Write("  Trend:           ");
        WriteColored($"{trendEmoji} {trend.ToUpperInvariant()}", trendColor);
        Console.WriteLine();

        // Confidence
        Console.Write("  Confidence (R²): ");
        var confColor = r2 > 0.7 ? ConsoleColor.Green : r2 > 0.4 ? ConsoleColor.Yellow : ConsoleColor.Red;
        var confLabel = r2 > 0.7 ? "High" : r2 > 0.4 ? "Medium" : "Low";
        WriteColored($"{r2:P1} ({confLabel})", confColor);
        Console.WriteLine();

        // Rates of change
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("  ── RATES OF CHANGE (per day) ──");
        Console.ResetColor();
        Console.Write("  Score:    ");
        WriteColored($"{scoreSlopePerDay:+0.000;-0.000;0.000}", scoreSlopePerDay >= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.Write("  │  Findings: ");
        WriteColored($"{findingsSlopePerDay:+0.000;-0.000;0.000}", findingsSlopePerDay <= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.Write("  │  Critical: ");
        WriteColored($"{criticalSlopePerDay:+0.000;-0.000;0.000}", criticalSlopePerDay <= 0 ? ConsoleColor.Green : ConsoleColor.Red);
        Console.WriteLine();

        // Projection table
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("  ── PROJECTIONS ──");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌──────────┬────────────┬───────┬──────────┬──────────┐");
        Console.WriteLine("  │   Day    │    Date    │ Score │ Findings │ Critical │");
        Console.WriteLine("  ├──────────┼────────────┼───────┼──────────┼──────────┤");
        Console.ResetColor();

        foreach (var (day, score, findings, critical) in forecasts)
        {
            var date = DateTimeOffset.UtcNow.AddDays(day).ToString("yyyy-MM-dd");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  │ ");
            Console.ResetColor();
            Console.Write($"+{day,4}d   ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("│ ");
            Console.ResetColor();
            Console.Write($"{date} ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("│ ");
            WriteScoreColored(score, padded: true);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ResetColor();
            Console.Write($"{(int)Math.Round(findings),8}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" │ ");
            Console.ResetColor();
            Console.Write($"{(int)Math.Round(critical),8}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(" │");
            Console.ResetColor();
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └──────────┴────────────┴───────┴──────────┴──────────┘");
        Console.ResetColor();

        // Disclaimer
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ℹ Projections use linear regression on historical audit data.");
        Console.WriteLine("    Actual results depend on remediation effort and new threats.");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void WriteScoreColored(double score, bool padded = false)
    {
        var color = score >= 80 ? ConsoleColor.Green
            : score >= 60 ? ConsoleColor.Yellow
            : ConsoleColor.Red;
        Console.ForegroundColor = color;
        Console.Write(padded ? $"{score,5:F1}" : $"{score:F1}");
        Console.ResetColor();
    }
}
