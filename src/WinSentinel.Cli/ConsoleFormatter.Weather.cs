namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static string GetWeatherCondition(int score) => score switch
    {
        >= 90 => "Sunny",
        >= 75 => "Partly Cloudy",
        >= 60 => "Cloudy",
        >= 40 => "Rainy",
        >= 20 => "Stormy",
        _ => "Severe"
    };

    static string GetWeatherEmoji(int score) => score switch
    {
        >= 90 => "☀️",
        >= 75 => "🌤️",
        >= 60 => "☁️",
        >= 40 => "🌧️",
        >= 20 => "⛈️",
        _ => "🌪️"
    };

    static string GetWindDesc(double findingsPerDay) => findingsPerDay switch
    {
        < 1 => "Calm",
        < 3 => "Breeze",
        < 6 => "Gusty",
        < 10 => "Gale",
        _ => "Hurricane"
    };

    static string GetUvDesc(int critical) => critical switch
    {
        0 => "None",
        1 => "Low",
        <= 3 => "Moderate",
        <= 5 => "High",
        _ => "Extreme"
    };

    static string GetVisibilityDesc(int coveragePct) => coveragePct switch
    {
        >= 90 => "Excellent",
        >= 75 => "Good",
        >= 50 => "Fair",
        >= 25 => "Poor",
        _ => "Fog"
    };

    static ConsoleColor GetWeatherColor(int score) => score switch
    {
        >= 90 => ConsoleColor.Green,
        >= 75 => ConsoleColor.Cyan,
        >= 60 => ConsoleColor.Yellow,
        >= 40 => ConsoleColor.DarkYellow,
        >= 20 => ConsoleColor.Red,
        _ => ConsoleColor.DarkRed
    };

    public static void PrintWeather(
        List<(DateTimeOffset date, int score, int total, int critical, int high, int medium, int low)> dataPoints,
        int coveragePct,
        int humidityPct,
        bool extended)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🌤️  Security Weather Report                          ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ResetColor();

        if (dataPoints.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No audit data found.");
            Console.ResetColor();
            return;
        }

        var current = dataPoints[^1];
        var scores = dataPoints.Select(p => p.score).ToList();
        var condition = GetWeatherCondition(current.score);
        var emoji = GetWeatherEmoji(current.score);
        var color = GetWeatherColor(current.score);

        // Wind: findings per day
        var daySpan = (dataPoints[^1].date - dataPoints[0].date).TotalDays;
        var findingsPerDay = daySpan > 0 ? dataPoints.Sum(p => p.total) / daySpan : 0.0;
        var windDesc = GetWindDesc(findingsPerDay);

        // Pressure: trend over last 7 data points
        var recentPoints = dataPoints.TakeLast(Math.Min(7, dataPoints.Count)).ToList();
        var pressureDelta = recentPoints.Count >= 2 ? recentPoints[^1].score - recentPoints[0].score : 0;
        var pressureDir = pressureDelta > 2 ? "Rising ↑" : pressureDelta < -2 ? "Falling ↓" : "Steady →";

        // Current conditions box
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ┌─────────────────────────────────────────────────┐");
        Console.ResetColor();

        Console.Write("  │     ");
        Console.ForegroundColor = color;
        Console.Write($"{emoji}  {condition.ToUpper(),-38}");
        Console.ResetColor();
        Console.WriteLine("│");

        Console.Write("  │     Temperature: ");
        Console.ForegroundColor = color;
        Console.Write($"{current.score}°S");
        Console.ResetColor();
        Console.WriteLine($"{"",30}│");

        Console.Write("  │     Wind:        ");
        WriteColored($"{windDesc} ({findingsPerDay:F1} findings/day)", ConsoleColor.White);
        var windPad = 29 - $"{windDesc} ({findingsPerDay:F1} findings/day)".Length;
        if (windPad < 0) windPad = 0;
        Console.WriteLine($"{new string(' ', windPad)}│");

        Console.Write("  │     Humidity:    ");
        var humColor = humidityPct > 60 ? ConsoleColor.Red : humidityPct > 30 ? ConsoleColor.Yellow : ConsoleColor.Green;
        WriteColored($"{humidityPct}%", humColor);
        Console.Write(" (recurring findings)");
        var humText = $"{humidityPct}% (recurring findings)";
        var humPad = 29 - humText.Length;
        if (humPad < 0) humPad = 0;
        Console.WriteLine($"{new string(' ', humPad)}│");

        Console.Write("  │     Visibility:  ");
        var visDesc = GetVisibilityDesc(coveragePct);
        WriteColored($"{visDesc} ({coveragePct}% coverage)", ConsoleColor.White);
        var visPad = 29 - $"{visDesc} ({coveragePct}% coverage)".Length;
        if (visPad < 0) visPad = 0;
        Console.WriteLine($"{new string(' ', visPad)}│");

        Console.Write("  │     Pressure:    ");
        var pressColor = pressureDelta > 2 ? ConsoleColor.Green : pressureDelta < -2 ? ConsoleColor.Red : ConsoleColor.White;
        var pressText = $"{pressureDir} ({(pressureDelta >= 0 ? "+" : "")}{pressureDelta} over {recentPoints.Count} runs)";
        WriteColored(pressText, pressColor);
        var pressPad = 29 - pressText.Length;
        if (pressPad < 0) pressPad = 0;
        Console.WriteLine($"{new string(' ', pressPad)}│");

        Console.Write("  │     UV Index:    ");
        var uvDesc = GetUvDesc(current.critical);
        var uvColor = current.critical == 0 ? ConsoleColor.Green : current.critical <= 3 ? ConsoleColor.Yellow : ConsoleColor.Red;
        var uvText = $"{uvDesc} ({current.critical} critical)";
        WriteColored(uvText, uvColor);
        var uvPad = 29 - uvText.Length;
        if (uvPad < 0) uvPad = 0;
        Console.WriteLine($"{new string(' ', uvPad)}│");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └─────────────────────────────────────────────────┘");
        Console.ResetColor();

        // 7-Day Forecast using linear regression
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  📊 7-Day Forecast");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ─────────────────────────────────────────────────");
        Console.ResetColor();

        // Simple linear regression on scores
        var n = scores.Count;
        var sumX = 0.0;
        var sumY = 0.0;
        var sumXY = 0.0;
        var sumX2 = 0.0;
        for (int i = 0; i < n; i++)
        {
            sumX += i;
            sumY += scores[i];
            sumXY += i * scores[i];
            sumX2 += i * i;
        }
        var slope = n > 1 ? (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX) : 0;
        var intercept = (sumY - slope * sumX) / n;

        var today = DateTimeOffset.Now;
        Console.Write("  ");
        for (int d = 0; d < 7; d++)
        {
            var day = today.AddDays(d);
            var label = d == 0 ? "Today" : day.ToString("ddd");
            Console.Write($"{label,-8}");
        }
        Console.WriteLine();

        Console.Write("  ");
        for (int d = 0; d < 7; d++)
        {
            var projected = Math.Clamp((int)(intercept + slope * (n + d)), 0, 100);
            var fEmoji = GetWeatherEmoji(projected);
            var fColor = GetWeatherColor(projected);
            Console.ForegroundColor = fColor;
            Console.Write($"{fEmoji}{projected,-6}");
            Console.ResetColor();
        }
        Console.WriteLine();

        // Outlook
        var day7Score = Math.Clamp((int)(intercept + slope * (n + 6)), 0, 100);
        Console.WriteLine();
        Console.Write("  Outlook: ");
        if (slope > 0.5)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Conditions improving. Expect {GetWeatherCondition(day7Score).ToLower()} by {today.AddDays(6):ddd}.");
        }
        else if (slope < -0.5)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Conditions degrading. Expect {GetWeatherCondition(day7Score).ToLower()} by {today.AddDays(6):ddd}.");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"Stable conditions. Expect continued {GetWeatherCondition(day7Score).ToLower()}.");
        }
        Console.ResetColor();

        // Weather Advisories
        var advisories = new List<string>();
        if (findingsPerDay > 3)
            advisories.Add($"Wind Advisory: Finding rate is {findingsPerDay:F1}/day — above normal");
        if (humidityPct > 50)
            advisories.Add($"Humidity Warning: {humidityPct}% of findings are recurring — stale issues detected");
        if (current.critical > 0)
            advisories.Add($"UV Alert: {current.critical} critical finding{(current.critical > 1 ? "s" : "")} require immediate attention");
        if (pressureDelta < -5)
            advisories.Add($"Pressure Drop: Score dropped {Math.Abs(pressureDelta)} points over recent runs");
        if (coveragePct < 50)
            advisories.Add($"Fog Advisory: Only {coveragePct}% scan coverage — blind spots likely");

        if (advisories.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ⚠️  Weather Advisories");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();
            foreach (var a in advisories)
            {
                Console.Write("  • ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(a);
                Console.ResetColor();
            }
        }

        // Proactive Recommendations
        var recs = new List<string>();
        if (current.score < 90 && current.high > 0)
            recs.Add($"Address {current.high} high-severity finding{(current.high > 1 ? "s" : "")} to improve conditions");
        if (humidityPct > 30)
            recs.Add("Clear recurring findings to reduce humidity below 30%");
        if (coveragePct < 80)
            recs.Add("Enable more audit modules to improve visibility above 80%");
        if (current.critical > 0)
            recs.Add("Resolve critical findings to eliminate UV exposure");
        if (slope < 0)
            recs.Add("Score is trending down — investigate recent changes");

        if (recs.Count > 0)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  💡 Proactive Recommendations");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();
            foreach (var r in recs)
            {
                Console.Write("  • ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(r);
                Console.ResetColor();
            }
        }

        // Extended forecast
        if (extended)
        {
            // Historical weather pattern
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  📅 Historical Weather Pattern");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();
            Console.Write("  ");
            foreach (var dp in dataPoints.TakeLast(30))
            {
                Console.ForegroundColor = GetWeatherColor(dp.score);
                Console.Write(GetWeatherEmoji(dp.score));
            }
            Console.ResetColor();
            Console.WriteLine();
            Console.Write("  ");
            foreach (var dp in dataPoints.TakeLast(30))
            {
                Console.ForegroundColor = GetWeatherColor(dp.score);
                Console.Write($"{dp.score,-3}");
            }
            Console.ResetColor();
            Console.WriteLine();

            // Storm tracker: drops > 10 points
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ⛈️  Storm Tracker (score drops > 10 points)");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();

            var storms = new List<(DateTimeOffset date, int from, int to)>();
            for (int i = 1; i < dataPoints.Count; i++)
            {
                var drop = dataPoints[i - 1].score - dataPoints[i].score;
                if (drop > 10)
                    storms.Add((dataPoints[i].date, dataPoints[i - 1].score, dataPoints[i].score));
            }

            if (storms.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  No significant storms detected. Smooth sailing! ⛵");
                Console.ResetColor();
            }
            else
            {
                foreach (var s in storms.TakeLast(10))
                {
                    Console.Write($"  {s.date:yyyy-MM-dd}  ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write($"{s.from}°S → {s.to}°S");
                    Console.ResetColor();
                    Console.Write($"  (dropped {s.from - s.to} points)");
                    Console.WriteLine();
                }
            }

            // Best/worst scores
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  📈 Seasonal Analysis");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  ─────────────────────────────────────────────────");
            Console.ResetColor();
            var best = dataPoints.MaxBy(p => p.score);
            var worst = dataPoints.MinBy(p => p.score);
            Console.Write("  Best:  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"{GetWeatherEmoji(best.score)} {best.score}°S");
            Console.ResetColor();
            Console.WriteLine($" on {best.date:yyyy-MM-dd}");
            Console.Write("  Worst: ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"{GetWeatherEmoji(worst.score)} {worst.score}°S");
            Console.ResetColor();
            Console.WriteLine($" on {worst.date:yyyy-MM-dd}");
            var avg = scores.Average();
            Console.Write("  Avg:   ");
            Console.ForegroundColor = GetWeatherColor((int)avg);
            Console.Write($"{GetWeatherEmoji((int)avg)} {avg:F0}°S");
            Console.ResetColor();
            Console.WriteLine();
        }

        Console.WriteLine();
        return;
    }
}
