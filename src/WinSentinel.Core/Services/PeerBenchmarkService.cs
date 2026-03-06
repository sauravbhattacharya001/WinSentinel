using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Compares a system's security posture against synthesized peer-group
/// benchmarks. Defines four peer groups (Home, Developer, Enterprise,
/// Server) with per-category score distributions, computes percentile
/// rankings, identifies strengths and weaknesses relative to the peer
/// median, and produces improvement recommendations.
/// </summary>
public class PeerBenchmarkService
{
    // -- Public types --

    /// <summary>Peer group environment type.</summary>
    public enum PeerGroup { Home, Developer, Enterprise, Server }

    /// <summary>How this system compares in a single category.</summary>
    public record CategoryComparison(
        string Category,
        int SystemScore,
        int PeerMedian,
        int PeerP25,
        int PeerP75,
        int Delta,
        double Percentile,
        ComparisonRating Rating);

    /// <summary>Qualitative rating for a category comparison.</summary>
    public enum ComparisonRating
    {
        WellAbovePeer,   // >= P75
        AbovePeer,       // > median & < P75
        AtPeer,          // within +/-5 of median
        BelowPeer,       // < median & > P25
        WellBelowPeer    // <= P25
    }

    /// <summary>A single suggestion for closing a gap with peers.</summary>
    public record ImprovementSuggestion(
        string Category,
        int CurrentScore,
        int PeerMedian,
        int Gap,
        string Recommendation,
        ImprovementPriority Priority);

    /// <summary>Priority level for an improvement suggestion.</summary>
    public enum ImprovementPriority { Critical, High, Medium, Low }

    /// <summary>Overall benchmark comparison result.</summary>
    public class BenchmarkResult
    {
        public PeerGroup Group { get; init; }
        public int SystemOverallScore { get; init; }
        public int PeerOverallMedian { get; init; }
        public double OverallPercentile { get; init; }
        public string OverallRating { get; init; } = "";
        public List<CategoryComparison> Categories { get; init; } = [];
        public List<ImprovementSuggestion> Suggestions { get; init; } = [];
        public List<CategoryComparison> TopStrengths { get; init; } = [];
        public List<CategoryComparison> TopWeaknesses { get; init; } = [];
        public int CategoriesAbovePeer { get; init; }
        public int CategoriesBelowPeer { get; init; }
        public int CategoriesAtPeer { get; init; }

        /// <summary>Generate a human-readable text summary.</summary>
        public string ToSummary()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"=== Peer Benchmark Comparison ({Group}) ===");
            sb.AppendLine();
            sb.AppendLine($"Overall Score:  {SystemOverallScore}/100  (Peer median: {PeerOverallMedian})");
            sb.AppendLine($"Percentile:     {OverallPercentile:F0}th  ({OverallRating})");
            sb.AppendLine($"Categories:     {CategoriesAbovePeer} above | {CategoriesAtPeer} at | {CategoriesBelowPeer} below peer");
            sb.AppendLine();

            if (TopStrengths.Count > 0)
            {
                sb.AppendLine("-- Strengths (above peers) --");
                foreach (var s in TopStrengths)
                    sb.AppendLine($"  + {s.Category}: {s.SystemScore} vs {s.PeerMedian} median (+{s.Delta})");
                sb.AppendLine();
            }

            if (TopWeaknesses.Count > 0)
            {
                sb.AppendLine("-- Weaknesses (below peers) --");
                foreach (var w in TopWeaknesses)
                    sb.AppendLine($"  - {w.Category}: {w.SystemScore} vs {w.PeerMedian} median ({w.Delta})");
                sb.AppendLine();
            }

            if (Suggestions.Count > 0)
            {
                sb.AppendLine("-- Improvement Suggestions --");
                foreach (var sug in Suggestions.Take(10))
                    sb.AppendLine($"  [{sug.Priority}] {sug.Category}: {sug.Recommendation} (gap: {sug.Gap} pts)");
            }

            return sb.ToString();
        }
    }

    // -- Benchmark data --

    private static readonly Dictionary<PeerGroup, Dictionary<string, (int Median, int P25, int P75)>> PeerData = new()
    {
        [PeerGroup.Home] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Accounts"] = (55, 40, 70), ["Applications"] = (50, 35, 65),
            ["Backup"] = (30, 15, 50), ["Bluetooth"] = (60, 45, 75),
            ["Browser"] = (45, 30, 60), ["Certificates"] = (70, 55, 85),
            ["Credentials"] = (40, 25, 55), ["Defender"] = (65, 50, 80),
            ["DNS"] = (55, 40, 70), ["Drivers"] = (70, 55, 80),
            ["Encryption"] = (35, 20, 55), ["Environment"] = (60, 45, 75),
            ["Event Logs"] = (50, 35, 65), ["Firewall"] = (60, 45, 75),
            ["GroupPolicy"] = (40, 25, 55), ["Network"] = (55, 40, 70),
            ["PowerShell"] = (45, 30, 60), ["Privacy"] = (40, 25, 55),
            ["Processes"] = (65, 50, 80), ["Registry"] = (50, 35, 65),
            ["Remote Access"] = (55, 40, 70), ["ScheduledTasks"] = (60, 45, 75),
            ["Services"] = (55, 40, 70), ["SMB"] = (50, 35, 65),
            ["Software"] = (45, 30, 60), ["Startup"] = (55, 40, 70),
            ["System"] = (60, 45, 75), ["Updates"] = (50, 35, 65),
            ["Virtualization"] = (65, 50, 80), ["WiFi"] = (50, 35, 65)
        },
        [PeerGroup.Developer] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Accounts"] = (65, 50, 80), ["Applications"] = (60, 45, 75),
            ["Backup"] = (45, 30, 60), ["Bluetooth"] = (65, 50, 80),
            ["Browser"] = (55, 40, 70), ["Certificates"] = (75, 60, 90),
            ["Credentials"] = (55, 40, 70), ["Defender"] = (70, 55, 85),
            ["DNS"] = (65, 50, 80), ["Drivers"] = (75, 60, 85),
            ["Encryption"] = (55, 40, 70), ["Environment"] = (70, 55, 85),
            ["Event Logs"] = (55, 40, 70), ["Firewall"] = (65, 50, 80),
            ["GroupPolicy"] = (50, 35, 65), ["Network"] = (65, 50, 80),
            ["PowerShell"] = (60, 45, 75), ["Privacy"] = (55, 40, 70),
            ["Processes"] = (70, 55, 85), ["Registry"] = (60, 45, 75),
            ["Remote Access"] = (60, 45, 75), ["ScheduledTasks"] = (65, 50, 80),
            ["Services"] = (65, 50, 80), ["SMB"] = (60, 45, 75),
            ["Software"] = (55, 40, 70), ["Startup"] = (60, 45, 75),
            ["System"] = (70, 55, 85), ["Updates"] = (60, 45, 75),
            ["Virtualization"] = (75, 60, 90), ["WiFi"] = (60, 45, 75)
        },
        [PeerGroup.Enterprise] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Accounts"] = (80, 70, 90), ["Applications"] = (75, 65, 85),
            ["Backup"] = (70, 55, 85), ["Bluetooth"] = (80, 70, 90),
            ["Browser"] = (70, 60, 85), ["Certificates"] = (85, 75, 95),
            ["Credentials"] = (75, 65, 85), ["Defender"] = (85, 75, 95),
            ["DNS"] = (80, 70, 90), ["Drivers"] = (85, 75, 92),
            ["Encryption"] = (80, 70, 90), ["Environment"] = (80, 70, 90),
            ["Event Logs"] = (75, 65, 85), ["Firewall"] = (85, 75, 95),
            ["GroupPolicy"] = (80, 70, 90), ["Network"] = (80, 70, 90),
            ["PowerShell"] = (75, 65, 85), ["Privacy"] = (70, 60, 85),
            ["Processes"] = (80, 70, 90), ["Registry"] = (75, 65, 85),
            ["Remote Access"] = (80, 70, 90), ["ScheduledTasks"] = (80, 70, 90),
            ["Services"] = (80, 70, 90), ["SMB"] = (75, 65, 85),
            ["Software"] = (70, 60, 80), ["Startup"] = (75, 65, 85),
            ["System"] = (85, 75, 95), ["Updates"] = (80, 70, 90),
            ["Virtualization"] = (85, 75, 95), ["WiFi"] = (75, 65, 85)
        },
        [PeerGroup.Server] = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Accounts"] = (85, 75, 95), ["Applications"] = (80, 70, 90),
            ["Backup"] = (80, 70, 90), ["Bluetooth"] = (90, 85, 98),
            ["Browser"] = (85, 75, 95), ["Certificates"] = (90, 80, 98),
            ["Credentials"] = (85, 75, 95), ["Defender"] = (90, 80, 98),
            ["DNS"] = (85, 75, 95), ["Drivers"] = (90, 80, 95),
            ["Encryption"] = (85, 75, 95), ["Environment"] = (85, 75, 95),
            ["Event Logs"] = (85, 75, 95), ["Firewall"] = (90, 80, 98),
            ["GroupPolicy"] = (85, 75, 95), ["Network"] = (85, 75, 95),
            ["PowerShell"] = (80, 70, 90), ["Privacy"] = (80, 70, 90),
            ["Processes"] = (85, 75, 95), ["Registry"] = (85, 75, 95),
            ["Remote Access"] = (85, 75, 95), ["ScheduledTasks"] = (85, 75, 95),
            ["Services"] = (85, 75, 95), ["SMB"] = (80, 70, 90),
            ["Software"] = (80, 70, 90), ["Startup"] = (80, 70, 90),
            ["System"] = (90, 80, 98), ["Updates"] = (85, 75, 95),
            ["Virtualization"] = (90, 80, 98), ["WiFi"] = (80, 70, 90)
        }
    };

    private static readonly Dictionary<string, string> CategoryRecommendations = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Accounts"] = "Review user accounts, disable unused ones, enforce strong passwords, configure lockout policies",
        ["Applications"] = "Remove unused software, update installed apps, verify digital signatures",
        ["Backup"] = "Enable System Restore, configure File History or Windows Backup, verify backup schedule",
        ["Bluetooth"] = "Disable Bluetooth when not in use, remove unknown paired devices, disable discoverability",
        ["Browser"] = "Review browser extensions, enable safe browsing, clear stored passwords",
        ["Certificates"] = "Remove expired certificates, replace weak algorithm certs, audit trusted root CAs",
        ["Credentials"] = "Use a password manager, remove plaintext credentials from files, rotate API keys",
        ["Defender"] = "Enable real-time protection, update definitions, enable cloud-delivered protection",
        ["DNS"] = "Use secure DNS (DoH/DoT), disable LLMNR and NetBIOS, verify DNS server settings",
        ["Drivers"] = "Update drivers, remove unsigned drivers, enable Secure Boot and HVCI",
        ["Encryption"] = "Enable BitLocker, use HTTPS everywhere, encrypt sensitive files",
        ["Environment"] = "Audit PATH for writable directories, remove secrets from env vars, secure TEMP paths",
        ["Event Logs"] = "Enable security auditing, increase log sizes, configure log forwarding",
        ["Firewall"] = "Review firewall rules, block unnecessary ports, enable on all profiles",
        ["GroupPolicy"] = "Apply security baselines, enforce UAC, configure audit policies",
        ["Network"] = "Review open ports, disable unused services, enable network-level authentication",
        ["PowerShell"] = "Enable script block logging, set Constrained Language mode, disable PowerShell v2",
        ["Privacy"] = "Review app permissions, disable telemetry, configure privacy settings",
        ["Processes"] = "Review running processes, check for unsigned executables, enable process auditing",
        ["Registry"] = "Enable UAC, disable autorun, protect LSASS, review Winlogon settings",
        ["Remote Access"] = "Disable unused remote services (RDP/WinRM/SSH), enable NLA, use strong encryption",
        ["ScheduledTasks"] = "Audit scheduled tasks, remove suspicious entries, verify task executables",
        ["Services"] = "Review services, fix unquoted paths, disable unnecessary SYSTEM services",
        ["SMB"] = "Disable SMBv1, enable signing and encryption, restrict share permissions",
        ["Software"] = "Uninstall unused software, update all applications, verify signatures",
        ["Startup"] = "Review startup items, remove unnecessary entries, verify executable paths",
        ["System"] = "Install OS updates, enable Secure Boot, configure system hardening",
        ["Updates"] = "Enable automatic updates, install pending patches, check update history",
        ["Virtualization"] = "Enable VBS and Credential Guard, secure Hyper-V VMs, restrict Docker",
        ["WiFi"] = "Remove insecure saved profiles, disable auto-connect, use WPA3 where possible"
    };

    // -- Public API --

    /// <summary>Compare a security report against a peer group.</summary>
    public BenchmarkResult Compare(SecurityReport report, PeerGroup group)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var peerScores = PeerData[group];
        var comparisons = new List<CategoryComparison>();

        foreach (var result in report.Results)
        {
            var category = result.Category;
            if (!peerScores.TryGetValue(category, out var peer))
                continue;

            var score = result.Score;
            var delta = score - peer.Median;
            var percentile = ComputePercentile(score, peer.P25, peer.Median, peer.P75);
            var rating = ClassifyRating(score, peer.Median, peer.P25, peer.P75);

            comparisons.Add(new CategoryComparison(
                category, score, peer.Median, peer.P25, peer.P75, delta, percentile, rating));
        }

        var overallMedian = (int)Math.Round(peerScores.Values.Average(p => p.Median));
        var overallP25 = (int)Math.Round(peerScores.Values.Average(p => p.P25));
        var overallP75 = (int)Math.Round(peerScores.Values.Average(p => p.P75));
        var overallPercentile = ComputePercentile(report.SecurityScore, overallP25, overallMedian, overallP75);

        var strengths = comparisons
            .Where(c => c.Rating is ComparisonRating.WellAbovePeer or ComparisonRating.AbovePeer)
            .OrderByDescending(c => c.Delta).Take(5).ToList();

        var weaknesses = comparisons
            .Where(c => c.Rating is ComparisonRating.WellBelowPeer or ComparisonRating.BelowPeer)
            .OrderBy(c => c.Delta).Take(5).ToList();

        var suggestions = comparisons
            .Where(c => c.Delta < -3).OrderBy(c => c.Delta)
            .Select(c => new ImprovementSuggestion(
                c.Category, c.SystemScore, c.PeerMedian, Math.Abs(c.Delta),
                CategoryRecommendations.GetValueOrDefault(c.Category, $"Improve {c.Category} security configuration"),
                ClassifyPriority(c.Delta, c.SystemScore)))
            .ToList();

        var aboveCount = comparisons.Count(c => c.Rating is ComparisonRating.WellAbovePeer or ComparisonRating.AbovePeer);
        var belowCount = comparisons.Count(c => c.Rating is ComparisonRating.WellBelowPeer or ComparisonRating.BelowPeer);
        var atCount = comparisons.Count(c => c.Rating == ComparisonRating.AtPeer);

        return new BenchmarkResult
        {
            Group = group,
            SystemOverallScore = report.SecurityScore,
            PeerOverallMedian = overallMedian,
            OverallPercentile = overallPercentile,
            OverallRating = DescribePercentile(overallPercentile),
            Categories = comparisons.OrderByDescending(c => c.Delta).ToList(),
            Suggestions = suggestions,
            TopStrengths = strengths,
            TopWeaknesses = weaknesses,
            CategoriesAbovePeer = aboveCount,
            CategoriesBelowPeer = belowCount,
            CategoriesAtPeer = atCount
        };
    }

    /// <summary>Compare a report against all four peer groups at once.</summary>
    public Dictionary<PeerGroup, BenchmarkResult> CompareAll(SecurityReport report)
    {
        return Enum.GetValues<PeerGroup>()
            .ToDictionary(g => g, g => Compare(report, g));
    }

    /// <summary>Find the best-fitting peer group for this system's score distribution.</summary>
    public PeerGroup SuggestPeerGroup(SecurityReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        var score = report.SecurityScore;

        return PeerData
            .MinBy(kv => Math.Abs(kv.Value.Values.Average(p => p.Median) - score))
            .Key;
    }

    /// <summary>Get benchmark data for a specific peer group and category.</summary>
    public (int Median, int P25, int P75)? GetBenchmark(PeerGroup group, string category)
    {
        return PeerData[group].TryGetValue(category, out var data) ? data : null;
    }

    /// <summary>All available peer groups.</summary>
    public static IReadOnlyList<PeerGroup> AvailableGroups => Enum.GetValues<PeerGroup>();

    /// <summary>All categories with benchmark data for a given peer group.</summary>
    public static IReadOnlyList<string> BenchmarkedCategories(PeerGroup group)
        => PeerData[group].Keys.ToList();

    // -- Private helpers --

    private static double ComputePercentile(int score, int p25, int median, int p75)
    {
        if (score <= p25) return Math.Max(5, 25.0 * score / Math.Max(p25, 1));
        if (score <= median) return 25.0 + 25.0 * (score - p25) / Math.Max(median - p25, 1);
        if (score <= p75) return 50.0 + 25.0 * (score - median) / Math.Max(p75 - median, 1);
        return Math.Min(99, 75.0 + 25.0 * (score - p75) / Math.Max(100 - p75, 1));
    }

    private static ComparisonRating ClassifyRating(int score, int median, int p25, int p75)
    {
        if (score >= p75) return ComparisonRating.WellAbovePeer;
        if (score > median + 5) return ComparisonRating.AbovePeer;
        if (score >= median - 5) return ComparisonRating.AtPeer;
        if (score > p25) return ComparisonRating.BelowPeer;
        return ComparisonRating.WellBelowPeer;
    }

    private static ImprovementPriority ClassifyPriority(int delta, int currentScore)
    {
        if (currentScore < 30 || delta < -30) return ImprovementPriority.Critical;
        if (currentScore < 50 || delta < -20) return ImprovementPriority.High;
        if (delta < -10) return ImprovementPriority.Medium;
        return ImprovementPriority.Low;
    }

    private static string DescribePercentile(double percentile) => percentile switch
    {
        >= 90 => "Excellent - top 10%",
        >= 75 => "Strong - top 25%",
        >= 50 => "Average",
        >= 25 => "Below average - bottom 25-50%",
        _ => "Needs improvement - bottom 25%"
    };
}
