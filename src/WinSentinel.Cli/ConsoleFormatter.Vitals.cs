using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    public static void PrintVitals(VitalSignsResult result)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║       🏥  Security Vital Signs                              ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        // Heartbeat
        PrintVitalRow("💓", "HEARTBEAT", "Scan Frequency",
            $"{result.Heartbeat.Bpm} BPM", result.Heartbeat.Status, true,
            new[]
            {
                $"Last scan: {FormatHoursAgo(result.Heartbeat.LastScanHoursAgo)} | Avg interval: {result.Heartbeat.AvgIntervalHours:F1}h",
                BuildHeartbeatWave(result.Heartbeat.Bpm)
            });

        // Blood Pressure
        PrintVitalRow("🩸", "BLOOD PRESSURE", "Score Stability",
            $"{result.BloodPressure.Systolic}/{result.BloodPressure.Diastolic}", result.BloodPressure.Status, false,
            new[]
            {
                $"Current: {result.BloodPressure.Systolic}/100 | Baseline: {result.BloodPressure.Diastolic}/100",
                $"Trend: {result.BloodPressure.Trend} | Volatility: {(result.BloodPressure.Volatility < 5 ? "Low" : result.BloodPressure.Volatility < 12 ? "Moderate" : "High")}"
            });

        // Temperature
        PrintVitalRow("🌡️", "TEMPERATURE", "Threat Activity",
            $"{result.Temperature.TemperatureF:F1}°F", result.Temperature.Status, false,
            new[]
            {
                $"Active threats: {result.Temperature.ActiveThreats} | New (24h): {result.Temperature.New24h} | Resolved (24h): {result.Temperature.Resolved24h}",
                $"Fever threshold: >10 active threats (103°F+)"
            });

        // Respiration
        PrintVitalRow("🫁", "RESPIRATION", "Remediation Rate",
            $"{result.Respiration.Rpm} RPM", result.Respiration.Status, false,
            new[]
            {
                $"Fixed (recent): {result.Respiration.FixedRecent} | New (recent): {result.Respiration.NewRecent} | Net: {(result.Respiration.FixedRecent >= result.Respiration.NewRecent ? "+" : "")}{result.Respiration.FixedRecent - result.Respiration.NewRecent}",
                $"Breathing: {result.Respiration.Quality}"
            });

        // Oxygen
        PrintVitalRow("💉", "OXYGEN", "Coverage",
            $"{result.Oxygen.SpO2Percent:F0}% SpO2", result.Oxygen.Status, false,
            new[]
            {
                $"Passing: {result.Oxygen.ActiveModules}/{result.Oxygen.TotalModules} checks",
                $"Saturation trend: {result.Oxygen.Trend}"
            });

        // Consciousness
        PrintVitalRow("🧠", "CONSCIOUSNESS", "Posture Awareness",
            result.Consciousness.Level, result.Consciousness.Status, false,
            new[]
            {
                $"Ignored findings: {result.Consciousness.IgnoredFindings} | Stale exemptions: {result.Consciousness.StaleExemptions}",
                $"Awareness score: {result.Consciousness.AwarenessScore:F0}/100"
            });

        Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");

        // Diagnosis
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("  📋 DIAGNOSIS");
        Console.ResetColor();
        Console.WriteLine("  ┌─────────────────────────────────────────────────────────────┐");

        Console.Write("  │  Overall Status: ");
        var triageColor = result.TriageLevel switch
        {
            "GREEN" => ConsoleColor.Green,
            "YELLOW" => ConsoleColor.Yellow,
            "RED" => ConsoleColor.Red,
            "BLACK" => ConsoleColor.DarkRed,
            _ => ConsoleColor.White
        };
        WriteColored($"{result.OverallStatus}", triageColor);
        var triageIcon = result.TriageLevel switch
        {
            "GREEN" => " ✅",
            "YELLOW" => " ⚠️",
            "RED" => " 🔴",
            "BLACK" => " 💀",
            _ => ""
        };
        Console.WriteLine(triageIcon);

        Console.Write("  │  Triage Level: ");
        WriteColored(result.TriageLevel, triageColor);
        Console.WriteLine();
        Console.WriteLine("  │");

        if (result.Concerns.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(result.Concerns.Count > 2 ? "  │  🚨 Serious Concerns:" : "  │  ⚠️  Mild Concerns:");
            Console.ResetColor();
            foreach (var c in result.Concerns)
                Console.WriteLine($"  │  • {c}");
            Console.WriteLine("  │");
        }

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  │  💊 Prescriptions:");
        Console.ResetColor();
        for (int i = 0; i < result.Prescriptions.Count; i++)
            Console.WriteLine($"  │  {i + 1}. {result.Prescriptions[i]}");

        Console.WriteLine("  └─────────────────────────────────────────────────────────────┘");
        Console.WriteLine();
    }

    private static void PrintVitalRow(string emoji, string name, string subtitle,
        string value, VitalStatus status, bool isFirst, string[] details)
    {
        var sep = isFirst ? "┌" : "├";
        Console.WriteLine($"  {sep}─────────────────────────────────────────────────────────────┐");

        var statusColor = status switch
        {
            VitalStatus.Normal => ConsoleColor.Green,
            VitalStatus.Elevated => ConsoleColor.Yellow,
            VitalStatus.Critical => ConsoleColor.Red,
            _ => ConsoleColor.White
        };
        var statusLabel = status switch
        {
            VitalStatus.Normal => "[Normal]",
            VitalStatus.Elevated => "[Elevated]",
            VitalStatus.Critical => "[CRITICAL]",
            _ => "[Unknown]"
        };

        Console.Write($"  │  {emoji} ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{name}");
        Console.ResetColor();
        Console.Write($" ({subtitle})");

        // Right-align value + status
        int leftLen = 5 + emoji.Length + 1 + name.Length + 2 + subtitle.Length + 1;
        string rightPart = $"{value}  {statusLabel}";
        int pad = Math.Max(1, 62 - leftLen - rightPart.Length);
        Console.Write(new string(' ', pad));
        WriteColored(value, ConsoleColor.White);
        Console.Write("  ");
        WriteColored(statusLabel, statusColor);
        Console.WriteLine();

        foreach (var detail in details)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  │  {detail}");
            Console.ResetColor();
        }
    }

    private static string FormatHoursAgo(double? hours)
    {
        if (hours == null) return "never";
        if (hours < 1) return $"{(int)(hours.Value * 60)}m ago";
        if (hours < 48) return $"{hours:F0}h ago";
        return $"{hours / 24:F0}d ago";
    }

    private static string BuildHeartbeatWave(int bpm)
    {
        // Build a simple ASCII EKG wave
        if (bpm <= 0) return "░░░░░░░░░░  FLATLINE  ░░░░░░░░░░";
        int peakInterval = Math.Max(3, 40 / Math.Max(bpm / 10, 1));
        var wave = new char[50];
        for (int i = 0; i < 50; i++)
        {
            if (i % peakInterval == 0) wave[i] = '█';
            else if (i % peakInterval == 1) wave[i] = '▓';
            else wave[i] = '░';
        }
        return new string(wave);
    }
}
