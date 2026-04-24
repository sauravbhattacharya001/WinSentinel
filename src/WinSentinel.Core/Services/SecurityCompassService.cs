namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Security Compass — directional gap analysis showing current position relative to ideal,
/// with heading guidance toward biggest improvement areas.
/// </summary>
public class SecurityCompassService
{
    private readonly AuditHistoryService _history;

    public SecurityCompassService(AuditHistoryService history)
    {
        _history = history;
    }

    public CompassResult Analyze(int days = 30)
    {
        var runs = _history.GetHistory(days);
        if (runs.Count == 0)
            return new CompassResult
            {
                AnalyzedAt = DateTimeOffset.UtcNow,
                Headings = new List<CompassHeading>(),
                Waypoints = new List<CompassWaypoint>(),
                Trajectory = new CompassTrend
                {
                    Direction = "unknown",
                    Narrative = "No audit data available."
                }
            };

        var latest = runs[0];
        var overallScore = (double)latest.OverallScore;

        // Module scores from latest run (use ModuleScores if available, else derive from findings)
        var moduleScores = latest.ModuleScores.Count > 0
            ? latest.ModuleScores
                .Select(ms => new { Module = ms.ModuleName, Score = ms.Score })
                .OrderBy(m => m.Score)
                .ToList()
            : latest.Findings
                .GroupBy(f => f.ModuleName)
                .Select(g => new
                {
                    Module = g.Key,
                    Score = Math.Max(0, 100 - g.Sum(f => SeverityWeight(f.Severity)))
                })
                .OrderBy(m => m.Score)
                .ToList();

        if (moduleScores.Count == 0)
        {
            // Perfect score, no findings
            moduleScores.Add(new { Module = "Overall", Score = (int)overallScore });
        }

        // Calculate position
        // Latitude: score mapped to -90..90 (0 score = -90, 100 = 90)
        double latitude = (overallScore / 100.0) * 180.0 - 90.0;
        // Longitude: balance = stddev of module scores mapped to -180..180
        var scores = moduleScores.Select(m => (double)m.Score).ToList();
        double mean = scores.Average();
        double stddev = scores.Count > 1
            ? Math.Sqrt(scores.Sum(s => (s - mean) * (s - mean)) / scores.Count)
            : 0;
        double longitude = -(stddev / 50.0) * 180.0; // Higher imbalance = more west

        var currentPos = new CompassPosition
        {
            Latitude = Math.Round(latitude, 1),
            Longitude = Math.Round(longitude, 1),
            Label = $"Score {overallScore:F0}/100"
        };

        var idealPos = new CompassPosition
        {
            Latitude = 90.0,
            Longitude = 0.0,
            Label = "Score 100/100"
        };

        // Deviation: angular distance between current and ideal
        double deviationDeg = Math.Round(
            Math.Sqrt(Math.Pow(90.0 - latitude, 2) + Math.Pow(0.0 - longitude, 2)) / Math.Sqrt(180.0 * 180.0 + 180.0 * 180.0) * 180.0,
            1);

        // Headings per module
        var headings = new List<CompassHeading>();
        foreach (var m in moduleScores)
        {
            int target = 95; // ideal target
            double gap = Math.Max(0, target - m.Score);
            double bearing = (1.0 - m.Score / 100.0) * 180.0; // 0=N(perfect), 180=S(critical)

            // Check trend for this module
            bool declining = false;
            if (runs.Count >= 2)
            {
                var prevRun = runs[Math.Min(1, runs.Count - 1)];
                var prevModEntry = prevRun.ModuleScores.FirstOrDefault(ms => ms.ModuleName == m.Module);
                if (prevModEntry != null)
                    declining = m.Score < prevModEntry.Score;
            }

            // Adjust bearing for decline (push toward W)
            if (declining) bearing = Math.Min(360, bearing + 90);

            string direction = BearingToDirection(bearing);

            headings.Add(new CompassHeading
            {
                Module = m.Module,
                CurrentScore = m.Score,
                TargetScore = target,
                BearingDegrees = Math.Round(bearing, 1),
                Distance = gap,
                Direction = direction,
                Guidance = GenerateGuidance(m.Module, m.Score, target, declining)
            });
        }

        // Waypoints: ordered by gap descending
        var waypoints = new List<CompassWaypoint>();
        double totalGap = headings.Sum(h => h.Distance);
        double cumulative = 0;
        int order = 1;
        foreach (var h in headings.OrderByDescending(h => h.Distance))
        {
            if (h.Distance <= 0) continue;
            cumulative += h.Distance;
            waypoints.Add(new CompassWaypoint
            {
                Order = order++,
                Module = h.Module,
                Action = h.Guidance,
                ExpectedGain = (int)h.Distance,
                CumulativeProgress = totalGap > 0 ? Math.Round(cumulative / totalGap * 100, 1) : 100
            });
        }

        // Trajectory from score history
        var trajectory = CalculateTrajectory(runs, overallScore);

        // Course correction
        string courseCorrection = waypoints.Count > 0
            ? $"Focus on {waypoints[0].Module} ({headings.First(h => h.Module == waypoints[0].Module).CurrentScore}→{headings.First(h => h.Module == waypoints[0].Module).TargetScore}, biggest gap)"
            : "On course — maintain current heading.";

        return new CompassResult
        {
            CurrentPosition = currentPos,
            IdealPosition = idealPos,
            Headings = headings,
            DeviationDegrees = deviationDeg,
            CourseCorrection = courseCorrection,
            Waypoints = waypoints,
            Trajectory = trajectory,
            AnalyzedAt = DateTimeOffset.UtcNow
        };
    }

    private CompassTrend CalculateTrajectory(List<AuditRunRecord> runs, double currentScore)
    {
        if (runs.Count < 2)
            return new CompassTrend
            {
                Direction = "holding",
                VelocityPerDay = 0,
                EstimatedDaysToTarget = -1,
                Narrative = "Not enough data for trajectory analysis."
            };

        // Linear regression over scores
        var points = runs.Select((r, i) => new { Day = (runs[0].Timestamp - r.Timestamp).TotalDays, Score = (double)r.OverallScore }).ToList();
        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
        int n = points.Count;
        foreach (var p in points)
        {
            sumX += p.Day;
            sumY += p.Score;
            sumXY += p.Day * p.Score;
            sumX2 += p.Day * p.Day;
        }
        double denom = n * sumX2 - sumX * sumX;
        double slope = denom != 0 ? (n * sumXY - sumX * sumY) / denom : 0;
        // slope is score change per day (negative day = past, so negate)
        double velocity = -slope;

        string direction;
        if (velocity > 0.1) direction = "approaching";
        else if (velocity < -0.1) direction = "drifting";
        else direction = "holding";

        int eta = velocity > 0.1 ? (int)Math.Ceiling((100 - currentScore) / velocity) : -1;

        string narrative = direction switch
        {
            "approaching" => $"Heading toward ideal at +{velocity:F1}/day. ETA ~{eta} days.",
            "drifting" => $"Drifting away from ideal at {velocity:F1}/day. Course correction needed.",
            _ => "Holding steady. Push improvements to gain momentum."
        };

        return new CompassTrend
        {
            Direction = direction,
            VelocityPerDay = Math.Round(velocity, 2),
            EstimatedDaysToTarget = eta,
            Narrative = narrative
        };
    }

    private static int SeverityWeight(string severity) => severity?.ToLowerInvariant() switch
    {
        "critical" => 20,
        "high" => 12,
        "medium" => 6,
        "low" => 3,
        "info" or "informational" => 1,
        _ => 2
    };

    private static string BearingToDirection(double bearing)
    {
        bearing = ((bearing % 360) + 360) % 360;
        return bearing switch
        {
            < 22.5 => "N",
            < 67.5 => "NE",
            < 112.5 => "E",
            < 157.5 => "SE",
            < 202.5 => "S",
            < 247.5 => "SW",
            < 292.5 => "W",
            < 337.5 => "NW",
            _ => "N"
        };
    }

    private static string DirectionArrow(string dir) => dir switch
    {
        "N" => "↑",
        "NE" => "↗",
        "E" => "→",
        "SE" => "↘",
        "S" => "↓",
        "SW" => "↙",
        "W" => "←",
        "NW" => "↖",
        _ => "•"
    };

    private static string GenerateGuidance(string module, int current, int target, bool declining)
    {
        if (declining)
            return $"⚠ {module} is declining — investigate recent changes and stabilize.";
        if (current >= target)
            return $"✓ {module} is on target — maintain current practices.";
        int gap = target - current;
        if (gap > 50)
            return $"Critical gap in {module} — prioritize immediate remediation.";
        if (gap > 25)
            return $"Significant gap in {module} — schedule focused improvement sprint.";
        if (gap > 10)
            return $"Moderate gap in {module} — address in next maintenance window.";
        return $"Minor gap in {module} — include in routine hardening.";
    }
}

// ── Result Models ──────────────────────────────────────────────

public class CompassResult
{
    public CompassPosition CurrentPosition { get; set; } = new();
    public CompassPosition IdealPosition { get; set; } = new();
    public List<CompassHeading> Headings { get; set; } = new();
    public double DeviationDegrees { get; set; }
    public string CourseCorrection { get; set; } = "";
    public List<CompassWaypoint> Waypoints { get; set; } = new();
    public CompassTrend Trajectory { get; set; } = new();
    public DateTimeOffset AnalyzedAt { get; set; }
}

public class CompassPosition
{
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public string Label { get; set; } = "";
}

public class CompassHeading
{
    public string Module { get; set; } = "";
    public int CurrentScore { get; set; }
    public int TargetScore { get; set; }
    public double BearingDegrees { get; set; }
    public double Distance { get; set; }
    public string Direction { get; set; } = "";
    public string Guidance { get; set; } = "";
}

public class CompassWaypoint
{
    public int Order { get; set; }
    public string Module { get; set; } = "";
    public string Action { get; set; } = "";
    public int ExpectedGain { get; set; }
    public double CumulativeProgress { get; set; }
}

public class CompassTrend
{
    public string Direction { get; set; } = "";
    public double VelocityPerDay { get; set; }
    public int EstimatedDaysToTarget { get; set; }
    public string Narrative { get; set; } = "";
}
