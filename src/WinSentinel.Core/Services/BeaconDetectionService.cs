namespace WinSentinel.Core.Services;

using System.Text.Json;
using WinSentinel.Core.Models;

/// <summary>
/// Autonomous Beacon Detection Service — analyzes network connection logs
/// to identify C2 beaconing patterns through statistical timing analysis.
///
/// Detection methodology:
/// 1. Collects connection timestamps per unique remote endpoint
/// 2. Computes inter-arrival times between consecutive connections
/// 3. Calculates interval regularity (standard deviation / mean = jitter)
/// 4. Low jitter + consistent interval = likely beacon
/// 5. Matches against known C2 framework timing profiles
///
/// MITRE ATT&CK: T1071 (Application Layer Protocol), T1573 (Encrypted Channel),
/// T1571 (Non-Standard Port)
/// </summary>
public sealed class BeaconDetectionService
{
    private readonly string _dataDir;

    /// <summary>
    /// Known C2 framework timing profiles for signature matching.
    /// </summary>
    public static readonly List<BeaconProfile> KnownProfiles = new()
    {
        new() { Name = "Cobalt Strike (default)", TypicalIntervalSeconds = 60, TypicalJitterPercent = 10, Description = "Default sleep 60s with 10% jitter" },
        new() { Name = "Cobalt Strike (slow)", TypicalIntervalSeconds = 300, TypicalJitterPercent = 15, Description = "Low-and-slow profile: 5min sleep, 15% jitter" },
        new() { Name = "Metasploit Meterpreter", TypicalIntervalSeconds = 5, TypicalJitterPercent = 5, Description = "Aggressive callback every 5s" },
        new() { Name = "Empire (default)", TypicalIntervalSeconds = 5, TypicalJitterPercent = 0, Description = "Default 5s sleep, no jitter" },
        new() { Name = "Sliver C2", TypicalIntervalSeconds = 30, TypicalJitterPercent = 20, Description = "30s beacon with 20% jitter" },
        new() { Name = "Havoc C2", TypicalIntervalSeconds = 2, TypicalJitterPercent = 0, Description = "Very aggressive 2s callback" },
        new() { Name = "Covenant", TypicalIntervalSeconds = 10, TypicalJitterPercent = 10, Description = "10s sleep, 10% jitter" },
        new() { Name = "PoshC2", TypicalIntervalSeconds = 120, TypicalJitterPercent = 20, Description = "2min beacon, 20% jitter" },
        new() { Name = "Brute Ratel", TypicalIntervalSeconds = 60, TypicalJitterPercent = 30, Description = "60s with high jitter to evade" },
        new() { Name = "DNS Beacon (slow)", TypicalIntervalSeconds = 900, TypicalJitterPercent = 5, Description = "15min DNS-based beacon, low jitter" },
    };

    /// <summary>
    /// Minimum callbacks required to perform statistical analysis.
    /// </summary>
    private const int MinCallbacksForAnalysis = 4;

    /// <summary>
    /// Jitter threshold below which a connection pattern is suspicious (percentage).
    /// Real beacons typically have 0-30% jitter; legitimate traffic is much more random.
    /// </summary>
    private const double SuspiciousJitterThreshold = 35.0;

    /// <summary>
    /// High confidence jitter threshold — very regular timing.
    /// </summary>
    private const double HighConfidenceJitterThreshold = 15.0;

    public BeaconDetectionService(string? dataDir = null)
    {
        _dataDir = dataDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSentinel", "beacon-data");
        Directory.CreateDirectory(_dataDir);
    }

    /// <summary>
    /// Analyze a set of connection records for beaconing patterns.
    /// </summary>
    /// <param name="connections">Connection records with timestamps and endpoints.</param>
    /// <param name="observationWindowMinutes">Analysis window in minutes (default: 60).</param>
    /// <returns>Beacon detection report with candidates and recommendations.</returns>
    public BeaconDetectionReport Analyze(
        List<ConnectionRecord> connections,
        int observationWindowMinutes = 60)
    {
        var report = new BeaconDetectionReport
        {
            ConnectionsAnalyzed = connections.Count,
            AnalysisTimestamp = DateTimeOffset.UtcNow
        };

        if (connections.Count < MinCallbacksForAnalysis)
        {
            return report;
        }

        // Group connections by remote endpoint (IP:Port)
        var grouped = connections
            .GroupBy(c => $"{c.RemoteIp}:{c.RemotePort}")
            .Where(g => g.Count() >= MinCallbacksForAnalysis)
            .ToList();

        report.Stats.TotalUniqueEndpoints = grouped.Count;

        var candidates = new List<BeaconCandidate>();

        foreach (var group in grouped)
        {
            var records = group.OrderBy(c => c.Timestamp).ToList();
            var candidate = AnalyzeEndpoint(records);

            if (candidate != null)
            {
                candidates.Add(candidate);
            }
        }

        // Sort by risk score descending
        report.Candidates = candidates.OrderByDescending(c => c.RiskScore).ToList();
        report.BeaconsDetected = candidates.Count;
        report.HighConfidenceBeacons = candidates.Count(c => c.ConfidenceLevel == BeaconConfidence.Critical || c.ConfidenceLevel == BeaconConfidence.High);
        report.MediumConfidenceBeacons = candidates.Count(c => c.ConfidenceLevel == BeaconConfidence.Medium);
        report.LowConfidenceBeacons = candidates.Count(c => c.ConfidenceLevel == BeaconConfidence.Low);

        // Compute stats
        if (candidates.Count > 0)
        {
            var intervals = candidates.Select(c => c.IntervalSeconds).OrderBy(x => x).ToList();
            report.Stats.MeanInterval = intervals.Average();
            report.Stats.MedianInterval = intervals[intervals.Count / 2];
            report.Stats.EndpointsWithRegularIntervals = candidates.Count;
            report.Stats.ShortBeacons = candidates.Count(c => c.IntervalSeconds < 60);
            report.Stats.MediumBeacons = candidates.Count(c => c.IntervalSeconds >= 60 && c.IntervalSeconds <= 300);
            report.Stats.LongBeacons = candidates.Count(c => c.IntervalSeconds > 300);
            report.Stats.ProfileMatches = candidates.Count(c => c.MatchedProfile != null);
        }

        // Overall risk score
        report.OverallRiskScore = CalculateOverallRisk(candidates);

        // Generate recommendations
        report.Recommendations = GenerateRecommendations(candidates);

        // Persist results for trend tracking
        PersistReport(report);

        return report;
    }

    /// <summary>
    /// Analyze a single endpoint's connection pattern for beaconing.
    /// </summary>
    private BeaconCandidate? AnalyzeEndpoint(List<ConnectionRecord> records)
    {
        if (records.Count < MinCallbacksForAnalysis)
            return null;

        // Calculate inter-arrival times
        var intervals = new List<double>();
        for (int i = 1; i < records.Count; i++)
        {
            var delta = (records[i].Timestamp - records[i - 1].Timestamp).TotalSeconds;
            if (delta > 0) // Skip duplicate timestamps
                intervals.Add(delta);
        }

        if (intervals.Count < 3)
            return null;

        // Statistical analysis
        var mean = intervals.Average();
        var stdDev = Math.Sqrt(intervals.Sum(x => Math.Pow(x - mean, 2)) / intervals.Count);
        var jitterPercent = mean > 0 ? (stdDev / mean) * 100.0 : 100.0;

        // Filter: only consider if jitter is below suspicious threshold
        if (jitterPercent > SuspiciousJitterThreshold)
            return null;

        // Skip very short intervals that might be legitimate keep-alives or TCP retransmits
        if (mean < 1.0)
            return null;

        // Determine confidence
        var confidence = CalculateConfidence(jitterPercent, intervals.Count, mean);
        var confidenceLevel = confidence switch
        {
            >= 0.9 => BeaconConfidence.Critical,
            >= 0.7 => BeaconConfidence.High,
            >= 0.5 => BeaconConfidence.Medium,
            _ => BeaconConfidence.Low
        };

        // Match against known profiles
        var matchedProfile = MatchProfile(mean, jitterPercent);

        // Calculate risk score
        var riskScore = CalculateRiskScore(confidence, mean, jitterPercent, intervals.Count, matchedProfile != null);

        var remoteIp = records[0].RemoteIp;
        var remotePorts = records.Select(r => r.RemotePort).Distinct().ToList();

        var assessment = GenerateAssessment(confidenceLevel, mean, jitterPercent, matchedProfile);

        return new BeaconCandidate
        {
            RemoteIp = remoteIp,
            RemotePorts = remotePorts,
            ProcessName = records[0].ProcessName,
            Confidence = confidence,
            ConfidenceLevel = confidenceLevel,
            IntervalSeconds = Math.Round(mean, 2),
            JitterPercent = Math.Round(jitterPercent, 2),
            CallbackCount = records.Count,
            ObservationWindow = records[^1].Timestamp - records[0].Timestamp,
            IntervalStdDev = Math.Round(stdDev, 2),
            Assessment = assessment,
            MatchedProfile = matchedProfile?.Name,
            RiskScore = riskScore,
            FirstSeen = records[0].Timestamp,
            LastSeen = records[^1].Timestamp,
            BytesTransferred = records.Sum(r => r.BytesTransferred),
            FixCommand = $"netsh advfirewall firewall add rule name=\"Block Beacon {remoteIp}\" dir=out action=block remoteip={remoteIp}"
        };
    }

    /// <summary>
    /// Calculate confidence score based on statistical indicators.
    /// </summary>
    private static double CalculateConfidence(double jitterPercent, int sampleCount, double meanInterval)
    {
        var score = 0.0;

        // Low jitter = high confidence (weight: 40%)
        if (jitterPercent <= 5) score += 0.40;
        else if (jitterPercent <= 10) score += 0.35;
        else if (jitterPercent <= 15) score += 0.28;
        else if (jitterPercent <= 25) score += 0.18;
        else score += 0.08;

        // More samples = higher confidence (weight: 30%)
        var sampleFactor = Math.Min(sampleCount / 20.0, 1.0);
        score += 0.30 * sampleFactor;

        // Suspicious interval ranges boost confidence (weight: 20%)
        // Legitimate services rarely use odd intervals like 60s exactly
        if (meanInterval >= 2 && meanInterval <= 900)
            score += 0.20;
        else if (meanInterval > 900)
            score += 0.10; // Slow beacons are harder to confirm

        // Round numbers are more suspicious (C2 defaults) (weight: 10%)
        var roundness = IsRoundNumber(meanInterval) ? 0.10 : 0.03;
        score += roundness;

        return Math.Min(score, 1.0);
    }

    /// <summary>
    /// Check if an interval is approximately a round number (common in C2 configs).
    /// </summary>
    private static bool IsRoundNumber(double interval)
    {
        var roundNumbers = new[] { 2, 5, 10, 15, 30, 60, 120, 180, 300, 600, 900 };
        return roundNumbers.Any(r => Math.Abs(interval - r) / r < 0.1);
    }

    /// <summary>
    /// Match detected beacon pattern against known C2 framework profiles.
    /// </summary>
    private static BeaconProfile? MatchProfile(double meanInterval, double jitterPercent)
    {
        foreach (var profile in KnownProfiles)
        {
            var intervalMatch = Math.Abs(meanInterval - profile.TypicalIntervalSeconds) / profile.TypicalIntervalSeconds;
            var jitterMatch = Math.Abs(jitterPercent - profile.TypicalJitterPercent);

            // Allow 20% interval tolerance and 10% jitter tolerance
            if (intervalMatch < 0.20 && jitterMatch < 10)
            {
                return profile;
            }
        }
        return null;
    }

    /// <summary>
    /// Calculate overall risk score for a beacon candidate.
    /// </summary>
    private static double CalculateRiskScore(double confidence, double interval, double jitter, int samples, bool profileMatch)
    {
        var score = confidence * 60.0; // Base from confidence

        // Profile match bonus
        if (profileMatch) score += 20.0;

        // Low jitter bonus
        if (jitter < 5) score += 10.0;
        else if (jitter < 10) score += 5.0;

        // High sample count bonus
        if (samples > 20) score += 10.0;
        else if (samples > 10) score += 5.0;

        return Math.Min(Math.Round(score, 1), 100.0);
    }

    /// <summary>
    /// Calculate overall risk from all detected beacons.
    /// </summary>
    private static double CalculateOverallRisk(List<BeaconCandidate> candidates)
    {
        if (candidates.Count == 0) return 0;

        // Weighted by confidence level
        var maxRisk = candidates.Max(c => c.RiskScore);
        var avgRisk = candidates.Average(c => c.RiskScore);

        // Overall risk is biased toward the maximum (worst case matters)
        return Math.Round(maxRisk * 0.7 + avgRisk * 0.3, 1);
    }

    /// <summary>
    /// Generate human-readable assessment for a beacon candidate.
    /// </summary>
    private static string GenerateAssessment(BeaconConfidence confidence, double interval, double jitter, BeaconProfile? profile)
    {
        var parts = new List<string>();

        parts.Add(confidence switch
        {
            BeaconConfidence.Critical => "CRITICAL: Near-certain C2 beaconing detected",
            BeaconConfidence.High => "HIGH: Strong indicators of C2 beaconing",
            BeaconConfidence.Medium => "MEDIUM: Possible beaconing behavior",
            _ => "LOW: Weak beaconing indicators — may be legitimate"
        });

        parts.Add($"Interval: {interval:F1}s with {jitter:F1}% jitter");

        if (profile != null)
            parts.Add($"Matches known profile: {profile.Name} ({profile.Description})");

        if (jitter < 5)
            parts.Add("Extremely regular timing — unlikely to be human-initiated");
        else if (jitter < 15)
            parts.Add("Very consistent timing pattern");

        return string.Join(". ", parts) + ".";
    }

    /// <summary>
    /// Generate prioritized remediation recommendations.
    /// </summary>
    private static List<BeaconRecommendation> GenerateRecommendations(List<BeaconCandidate> candidates)
    {
        var recs = new List<BeaconRecommendation>();

        if (candidates.Count == 0)
        {
            recs.Add(new BeaconRecommendation
            {
                Priority = 1,
                Action = "No beacons detected — continue monitoring",
                Rationale = "Current network patterns show no periodic callback behavior",
                Impact = "None"
            });
            return recs;
        }

        var criticals = candidates.Where(c => c.ConfidenceLevel == BeaconConfidence.Critical).ToList();
        var highs = candidates.Where(c => c.ConfidenceLevel == BeaconConfidence.High).ToList();

        if (criticals.Count > 0)
        {
            recs.Add(new BeaconRecommendation
            {
                Priority = 1,
                Action = "IMMEDIATE: Isolate affected hosts and block beacon IPs",
                Rationale = $"{criticals.Count} critical beacon(s) detected with near-certain C2 communication",
                Command = string.Join(" && ", criticals.Select(c => c.FixCommand).Where(f => f != null)),
                Impact = "Blocks outbound C2 communication — may disrupt attacker access"
            });
        }

        if (highs.Count > 0)
        {
            recs.Add(new BeaconRecommendation
            {
                Priority = 2,
                Action = "Investigate high-confidence beacons and capture packet dumps",
                Rationale = $"{highs.Count} high-confidence beacon(s) require deeper analysis",
                Command = "netsh trace start capture=yes tracefile=beacon_capture.etl",
                Impact = "Captures network evidence for forensic analysis"
            });
        }

        if (candidates.Any(c => c.MatchedProfile != null))
        {
            var profiles = candidates.Where(c => c.MatchedProfile != null)
                .Select(c => c.MatchedProfile).Distinct().ToList();
            recs.Add(new BeaconRecommendation
            {
                Priority = 3,
                Action = $"Run targeted hunt for {string.Join(", ", profiles!)} indicators",
                Rationale = "Beacon timing matches known C2 framework defaults — check for additional IOCs",
                Impact = "May reveal lateral movement, persistence, or data staging"
            });
        }

        recs.Add(new BeaconRecommendation
        {
            Priority = recs.Count + 1,
            Action = "Enable continuous beacon monitoring with shorter polling intervals",
            Rationale = "Shorter observation windows improve detection of fast beacons",
            Command = "winsentinel beacon --watch --interval 30",
            Impact = "Increased CPU/network overhead but faster detection"
        });

        return recs;
    }

    /// <summary>
    /// Persist report for historical trend analysis.
    /// </summary>
    private void PersistReport(BeaconDetectionReport report)
    {
        try
        {
            var file = Path.Combine(_dataDir, $"beacon-{report.AnalysisTimestamp:yyyyMMdd-HHmmss}.json");
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(file, json);

            // Keep only last 100 reports
            var files = Directory.GetFiles(_dataDir, "beacon-*.json")
                .OrderByDescending(f => f)
                .Skip(100)
                .ToList();
            foreach (var f in files)
            {
                try { File.Delete(f); } catch { /* best effort */ }
            }
        }
        catch { /* Non-critical — don't fail analysis if persistence fails */ }
    }

    /// <summary>
    /// Load historical beacon reports for trend analysis.
    /// </summary>
    public List<BeaconDetectionReport> GetHistory(int maxReports = 20)
    {
        var results = new List<BeaconDetectionReport>();
        try
        {
            var files = Directory.GetFiles(_dataDir, "beacon-*.json")
                .OrderByDescending(f => f)
                .Take(maxReports);

            foreach (var file in files)
            {
                var json = File.ReadAllText(file);
                var report = JsonSerializer.Deserialize<BeaconDetectionReport>(json);
                if (report != null)
                    results.Add(report);
            }
        }
        catch { /* best effort */ }
        return results;
    }

    /// <summary>
    /// Simulate beacon detection from current system connections.
    /// Captures a snapshot of active TCP connections and synthesizes
    /// connection records for analysis.
    /// </summary>
    public BeaconDetectionReport AnalyzeCurrentConnections()
    {
        var records = CaptureConnectionSnapshot();
        return Analyze(records);
    }

    /// <summary>
    /// Capture current TCP connection state as connection records.
    /// For real beacon detection, this would be called repeatedly over time
    /// and timestamps would accumulate per endpoint.
    /// </summary>
    private List<ConnectionRecord> CaptureConnectionSnapshot()
    {
        var records = new List<ConnectionRecord>();
        try
        {
            var properties = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
            var connections = properties.GetActiveTcpConnections();
            var now = DateTimeOffset.UtcNow;

            foreach (var conn in connections)
            {
                if (conn.State != System.Net.NetworkInformation.TcpState.Established)
                    continue;

                if (System.Net.IPAddress.IsLoopback(conn.RemoteEndPoint.Address))
                    continue;

                records.Add(new ConnectionRecord
                {
                    RemoteIp = conn.RemoteEndPoint.Address.ToString(),
                    RemotePort = conn.RemoteEndPoint.Port,
                    LocalPort = conn.LocalEndPoint.Port,
                    Timestamp = now,
                    ProcessName = null // Would need netstat correlation
                });
            }
        }
        catch { /* best effort */ }

        // Load historical connection snapshots and merge
        var historical = LoadHistoricalSnapshots();
        records.AddRange(historical);

        // Save current snapshot
        SaveConnectionSnapshot(records.Where(r => r.Timestamp == records.Max(x => x.Timestamp)).ToList());

        return records;
    }

    private List<ConnectionRecord> LoadHistoricalSnapshots()
    {
        var results = new List<ConnectionRecord>();
        try
        {
            var file = Path.Combine(_dataDir, "connection-history.json");
            if (File.Exists(file))
            {
                var json = File.ReadAllText(file);
                var history = JsonSerializer.Deserialize<List<ConnectionRecord>>(json);
                if (history != null)
                {
                    // Keep only last 2 hours of history
                    var cutoff = DateTimeOffset.UtcNow.AddHours(-2);
                    results = history.Where(r => r.Timestamp > cutoff).ToList();
                }
            }
        }
        catch { /* best effort */ }
        return results;
    }

    private void SaveConnectionSnapshot(List<ConnectionRecord> current)
    {
        try
        {
            var file = Path.Combine(_dataDir, "connection-history.json");
            var existing = LoadHistoricalSnapshots();
            existing.AddRange(current);

            // Trim to last 2 hours
            var cutoff = DateTimeOffset.UtcNow.AddHours(-2);
            existing = existing.Where(r => r.Timestamp > cutoff).ToList();

            var json = JsonSerializer.Serialize(existing, new JsonSerializerOptions { WriteIndented = false });
            File.WriteAllText(file, json);
        }
        catch { /* best effort */ }
    }
}

/// <summary>
/// A network connection record with timestamp for beacon analysis.
/// </summary>
public class ConnectionRecord
{
    public string RemoteIp { get; set; } = "";
    public int RemotePort { get; set; }
    public int LocalPort { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string? ProcessName { get; set; }
    public long BytesTransferred { get; set; }
}
