using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Maps security audit metrics to medical vital signs for intuitive health assessment.
/// </summary>
public class VitalSignsService : IDisposable
{
    private readonly AuditHistoryService _history;
    private readonly bool _ownsHistory;

    public VitalSignsService() : this(new AuditHistoryService()) { _ownsHistory = true; }
    public VitalSignsService(AuditHistoryService history) { _history = history; }

    public VitalSignsResult Assess(int historyDays = 30)
    {
        var runs = _history.GetHistory(historyDays);
        runs = runs.OrderBy(r => r.Timestamp).ToList();

        var heartbeat = AssessHeartbeat(runs);
        var bp = AssessBloodPressure(runs);
        var temp = AssessTemperature(runs);
        var resp = AssessRespiration(runs);
        var oxygen = AssessOxygen(runs);
        var consciousness = AssessConsciousness(runs);

        var vitals = new[] { heartbeat.Status, bp.Status, temp.Status, resp.Status, oxygen.Status, consciousness.Status };
        int critCount = vitals.Count(v => v == VitalStatus.Critical);
        int warnCount = vitals.Count(v => v == VitalStatus.Elevated);

        var (overall, triage) = (critCount, warnCount) switch
        {
            ( >= 3, _) => ("CRITICAL", "BLACK"),
            ( >= 1, _) => ("SERIOUS", "RED"),
            (0, >= 2) => ("GUARDED", "YELLOW"),
            _ => ("STABLE", "GREEN")
        };

        var concerns = new List<string>();
        var prescriptions = new List<string>();

        if (heartbeat.Status != VitalStatus.Normal)
        {
            concerns.Add($"Heartbeat {(heartbeat.Status == VitalStatus.Critical ? "critically" : "slightly")} abnormal — scans are {(heartbeat.Bpm < 60 ? "too infrequent" : "erratic")}");
            prescriptions.Add("Schedule regular audits (--schedule-optimize) to maintain healthy scan rhythm");
        }
        if (bp.Status != VitalStatus.Normal)
        {
            concerns.Add($"Blood pressure {(bp.Status == VitalStatus.Critical ? "dangerously high" : "slightly elevated")} — score dropped {bp.Systolic - bp.Diastolic} points from baseline");
            prescriptions.Add("Run --fixall to address auto-fixable findings and stabilize score");
        }
        if (temp.Status != VitalStatus.Normal)
        {
            concerns.Add($"Temperature elevated at {temp.TemperatureF:F1}°F — {temp.ActiveThreats} active threats detected");
            prescriptions.Add("Review active threats (--threats) and triage with --triage");
        }
        if (resp.Status != VitalStatus.Normal)
        {
            concerns.Add($"Respiration {(resp.Status == VitalStatus.Critical ? "critically" : "slightly")} weak — remediation rate declining");
            prescriptions.Add("Address oldest findings first (--finding-age --sort oldest) to improve remediation flow");
        }
        if (oxygen.Status != VitalStatus.Normal)
        {
            concerns.Add($"Oxygen saturation low at {oxygen.SpO2Percent:F0}% — module coverage gaps detected");
            prescriptions.Add("Run a full audit (--audit) to restore module coverage");
        }
        if (consciousness.Status != VitalStatus.Normal)
        {
            concerns.Add($"Consciousness {consciousness.Level} — {consciousness.StaleExemptions} stale exemptions reducing awareness");
            prescriptions.Add("Audit exemptions (--exemptions --audit) and review ignored findings (--show-ignored)");
        }

        if (prescriptions.Count == 0)
            prescriptions.Add("All vitals nominal — maintain current security hygiene");

        return new VitalSignsResult(heartbeat, bp, temp, resp, oxygen, consciousness, overall, triage, concerns, prescriptions);
    }

    private static HeartbeatVital AssessHeartbeat(List<AuditRunRecord> runs)
    {
        if (runs.Count < 2)
            return new HeartbeatVital(0, 0, null, VitalStatus.Critical);

        var intervals = new List<double>();
        for (int i = 1; i < runs.Count; i++)
            intervals.Add((runs[i].Timestamp - runs[i - 1].Timestamp).TotalHours);

        var avgInterval = intervals.Average();
        var lastScanAgo = (DateTimeOffset.UtcNow - runs[^1].Timestamp).TotalHours;

        // Map interval to BPM: 1h interval = 100 BPM, 6h = 72, 12h = 55, 24h+ = 40
        int bpm = Math.Clamp((int)(120 - avgInterval * 8), 30, 120);

        var status = (bpm, lastScanAgo) switch
        {
            (< 40, _) => VitalStatus.Critical,
            (< 55, _) => VitalStatus.Elevated,
            (_, > 48) => VitalStatus.Critical,
            (_, > 24) => VitalStatus.Elevated,
            _ => VitalStatus.Normal
        };

        return new HeartbeatVital(bpm, avgInterval, lastScanAgo, status);
    }

    private static BloodPressureVital AssessBloodPressure(List<AuditRunRecord> runs)
    {
        if (runs.Count == 0)
            return new BloodPressureVital(0, 0, 0, "Unknown", VitalStatus.Critical);

        int current = runs[^1].OverallScore;
        int baseline = (int)runs.Average(r => r.OverallScore);
        var scores = runs.Select(r => (double)r.OverallScore).ToList();
        double variance = scores.Count > 1 ? scores.Select(s => Math.Pow(s - scores.Average(), 2)).Average() : 0;
        double volatility = Math.Sqrt(variance);
        string trend = runs.Count >= 3
            ? (runs[^1].OverallScore > runs[^3].OverallScore ? "Improving ↗" : runs[^1].OverallScore < runs[^3].OverallScore ? "Declining ↘" : "Stable ──")
            : "Insufficient data";

        var status = (current, volatility) switch
        {
            (< 50, _) => VitalStatus.Critical,
            (< 70, _) => VitalStatus.Elevated,
            (_, > 15) => VitalStatus.Elevated,
            _ => VitalStatus.Normal
        };

        return new BloodPressureVital(current, baseline, volatility, trend, status);
    }

    private static TemperatureVital AssessTemperature(List<AuditRunRecord> runs)
    {
        if (runs.Count == 0)
            return new TemperatureVital(98.6, 0, 0, 0, VitalStatus.Normal);

        var latest = runs[^1];
        int activeThreats = latest.CriticalCount + latest.WarningCount;
        int recent24h = runs.Where(r => r.Timestamp > DateTimeOffset.UtcNow.AddHours(-24)).Sum(r => r.CriticalCount + r.WarningCount);
        int resolvedEstimate = runs.Count >= 2 ? Math.Max(0, runs[^2].TotalFindings - latest.TotalFindings) : 0;

        // Map: 0 threats = 97°F, each threat adds ~0.3°F
        double tempF = 97.0 + activeThreats * 0.3;
        tempF = Math.Min(tempF, 106.0);

        var status = tempF switch
        {
            > 103.0 => VitalStatus.Critical,
            > 100.4 => VitalStatus.Elevated,
            _ => VitalStatus.Normal
        };

        return new TemperatureVital(tempF, activeThreats, recent24h, resolvedEstimate, status);
    }

    private static RespirationVital AssessRespiration(List<AuditRunRecord> runs)
    {
        if (runs.Count < 2)
            return new RespirationVital(0, 0, 0, "Unknown", VitalStatus.Elevated);

        // Compare recent findings vs older — net reduction = good respiration
        var recentRuns = runs.TakeLast(Math.Min(runs.Count, 7)).ToList();
        int recentTotal = recentRuns[^1].TotalFindings;
        int olderTotal = recentRuns[0].TotalFindings;
        int netChange = olderTotal - recentTotal; // positive = improvement
        int fixedEstimate = Math.Max(0, netChange);
        int newEstimate = Math.Max(0, -netChange);

        // Map net improvement to RPM: big improvement = deep breathing
        int rpm = Math.Clamp(12 + netChange, 4, 30);
        string quality = rpm switch
        {
            >= 18 => "Deep and steady",
            >= 12 => "Normal rhythm",
            >= 8 => "Shallow breathing",
            _ => "Labored"
        };

        var status = rpm switch
        {
            < 8 => VitalStatus.Critical,
            < 12 => VitalStatus.Elevated,
            _ => VitalStatus.Normal
        };

        return new RespirationVital(rpm, fixedEstimate, newEstimate, quality, status);
    }

    private static OxygenVital AssessOxygen(List<AuditRunRecord> runs)
    {
        if (runs.Count == 0)
            return new OxygenVital(0, 0, 0, "Unknown", VitalStatus.Critical);

        var latest = runs[^1];
        // Use pass count vs total to estimate coverage
        int total = latest.TotalFindings + latest.PassCount;
        double coverage = total > 0 ? (double)latest.PassCount / total * 100 : 100;
        coverage = Math.Clamp(coverage, 0, 100);

        // Trend
        string trend = "Stable ──";
        if (runs.Count >= 3)
        {
            var older = runs[^3];
            int olderTotal = older.TotalFindings + older.PassCount;
            double olderCov = olderTotal > 0 ? (double)older.PassCount / olderTotal * 100 : 100;
            trend = coverage > olderCov + 2 ? "Improving ↗" : coverage < olderCov - 2 ? "Declining ↘" : "Stable ──";
        }

        var status = coverage switch
        {
            < 85 => VitalStatus.Critical,
            < 93 => VitalStatus.Elevated,
            _ => VitalStatus.Normal
        };

        return new OxygenVital(coverage, latest.PassCount, latest.TotalFindings + latest.PassCount, trend, status);
    }

    private static ConsciousnessVital AssessConsciousness(List<AuditRunRecord> runs)
    {
        if (runs.Count == 0)
            return new ConsciousnessVital("Unconscious", 0, 0, 0, VitalStatus.Critical);

        var latest = runs[^1];
        // Info-level findings often represent ignored/acknowledged items
        int ignoredEstimate = latest.InfoCount;
        int staleEstimate = Math.Max(0, ignoredEstimate / 3); // rough estimate
        int total = latest.TotalFindings + latest.PassCount;
        double awarenessScore = total > 0 ? Math.Max(0, 100 - (ignoredEstimate * 2.0) - (staleEstimate * 5.0)) : 100;
        awarenessScore = Math.Clamp(awarenessScore, 0, 100);

        string level = awarenessScore switch
        {
            >= 80 => "Alert",
            >= 50 => "Drowsy",
            _ => "Unconscious"
        };

        var status = level switch
        {
            "Alert" => VitalStatus.Normal,
            "Drowsy" => VitalStatus.Elevated,
            _ => VitalStatus.Critical
        };

        return new ConsciousnessVital(level, ignoredEstimate, staleEstimate, awarenessScore, status);
    }

    public void Dispose()
    {
        if (_ownsHistory) _history.Dispose();
        GC.SuppressFinalize(this);
    }
}

// --- Models ---

public enum VitalStatus { Normal, Elevated, Critical }

public record HeartbeatVital(int Bpm, double AvgIntervalHours, double? LastScanHoursAgo, VitalStatus Status);
public record BloodPressureVital(int Systolic, int Diastolic, double Volatility, string Trend, VitalStatus Status);
public record TemperatureVital(double TemperatureF, int ActiveThreats, int New24h, int Resolved24h, VitalStatus Status);
public record RespirationVital(int Rpm, int FixedRecent, int NewRecent, string Quality, VitalStatus Status);
public record OxygenVital(double SpO2Percent, int ActiveModules, int TotalModules, string Trend, VitalStatus Status);
public record ConsciousnessVital(string Level, int IgnoredFindings, int StaleExemptions, double AwarenessScore, VitalStatus Status);

public record VitalSignsResult(
    HeartbeatVital Heartbeat,
    BloodPressureVital BloodPressure,
    TemperatureVital Temperature,
    RespirationVital Respiration,
    OxygenVital Oxygen,
    ConsciousnessVital Consciousness,
    string OverallStatus,
    string TriageLevel,
    List<string> Concerns,
    List<string> Prescriptions);
