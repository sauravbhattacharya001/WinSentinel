using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Adaptive threat memory that learns from past security findings and builds
/// defensive "antibodies" — patterns that detect similar threats faster.
/// Tracks vaccination records showing what the system is immunized against.
/// </summary>
public class SecurityImmuneSystem
{
    // ── Result types ─────────────────────────────────────────────────

    /// <summary>A defensive pattern learned from resolved findings.</summary>
    public record Antibody(
        string Id,
        string Pattern,
        string Category,
        string Severity,
        int ExposureCount,
        DateTimeOffset FirstSeen,
        DateTimeOffset LastSeen,
        string Status,
        double ConfidenceScore);

    /// <summary>Vaccination coverage for a threat category.</summary>
    public record VaccinationRecord(
        string ThreatCategory,
        int AntibodyCount,
        double CoveragePercent,
        string ImmunityLevel,
        DateTimeOffset LastBooster);

    /// <summary>Memory of a specific threat and its recurrence pattern.</summary>
    public record ThreatMemory(
        string FindingTitle,
        string Module,
        string Severity,
        int RecurrenceCount,
        bool IsImmunized,
        string RecommendedAction);

    /// <summary>Complete immune system health report.</summary>
    public class ImmuneHealthReport
    {
        public int TotalAntibodies { get; init; }
        public int ActiveAntibodies { get; init; }
        public int WeakenedAntibodies { get; init; }
        public int ExpiredAntibodies { get; init; }
        public double OverallImmunityScore { get; init; }
        public List<VaccinationRecord> Vaccinations { get; init; } = [];
        public List<ThreatMemory> RecentThreats { get; init; } = [];
        public List<Antibody> Antibodies { get; init; } = [];
        public List<string> VulnerableAreas { get; init; } = [];
        public List<string> ProactiveRecommendations { get; init; } = [];
    }

    // ── Configuration ────────────────────────────────────────────────

    /// <summary>Days since last exposure before antibody is considered weakened.</summary>
    private const int WeakeningThresholdDays = 60;

    /// <summary>Days since last exposure before antibody is considered expired.</summary>
    private const int ExpirationThresholdDays = 120;

    /// <summary>Minimum exposures needed for full confidence.</summary>
    private const int FullConfidenceExposures = 5;

    // ── Public API ───────────────────────────────────────────────────

    /// <summary>
    /// Build a complete immune system health report from audit history.
    /// </summary>
    public ImmuneHealthReport BuildImmuneProfile(List<AuditRunRecord> history, bool showExpired = false)
    {
        if (history.Count == 0)
        {
            return new ImmuneHealthReport
            {
                OverallImmunityScore = 0,
                ProactiveRecommendations = ["No audit history available. Run --audit to begin building immunity."]
            };
        }

        var antibodies = GetAntibodies(history);
        var vaccinations = GetVaccinations(antibodies);
        var threats = GetThreatMemory(history);
        var allModules = history
            .SelectMany(r => r.ModuleScores)
            .Select(m => m.ModuleName)
            .Distinct()
            .ToList();
        var vulnerableAreas = IdentifyVulnerableAreas(vaccinations, allModules);

        var active = antibodies.Count(a => a.Status == "Active");
        var weakened = antibodies.Count(a => a.Status == "Weakened");
        var expired = antibodies.Count(a => a.Status == "Expired");

        var displayAntibodies = showExpired
            ? antibodies
            : antibodies.Where(a => a.Status != "Expired").ToList();

        // Overall immunity = weighted score based on active/weakened antibodies vs total threat surface
        var totalCategories = Math.Max(1, allModules.Count);
        var coveredCategories = vaccinations.Count(v => v.ImmunityLevel is "Full" or "Partial");
        var immunityScore = Math.Round((coveredCategories * 100.0) / totalCategories, 1);

        var report = new ImmuneHealthReport
        {
            TotalAntibodies = antibodies.Count,
            ActiveAntibodies = active,
            WeakenedAntibodies = weakened,
            ExpiredAntibodies = expired,
            OverallImmunityScore = immunityScore,
            Vaccinations = vaccinations,
            RecentThreats = threats,
            Antibodies = displayAntibodies,
            VulnerableAreas = vulnerableAreas,
            ProactiveRecommendations = []
        };

        report.ProactiveRecommendations.AddRange(GenerateRecommendations(report));
        return report;
    }

    /// <summary>
    /// Extract antibodies from resolved findings across audit history.
    /// </summary>
    public List<Antibody> GetAntibodies(List<AuditRunRecord> history)
    {
        var now = DateTimeOffset.UtcNow;
        var orderedRuns = history.OrderBy(r => r.Timestamp).ToList();

        // Group all findings by title pattern to identify recurring threats
        var findingGroups = orderedRuns
            .SelectMany(r => r.Findings.Select(f => new { Run = r, Finding = f }))
            .GroupBy(x => NormalizePattern(x.Finding.Title))
            .Where(g => g.Any(x => x.Finding.Severity != "Pass"))
            .ToList();

        var antibodies = new List<Antibody>();
        int idCounter = 0;

        foreach (var group in findingGroups)
        {
            var nonPassFindings = group.Where(x => x.Finding.Severity != "Pass").ToList();
            if (nonPassFindings.Count == 0) continue;

            var firstSeen = nonPassFindings.Min(x => x.Run.Timestamp);
            var lastSeen = nonPassFindings.Max(x => x.Run.Timestamp);
            var exposureCount = nonPassFindings.Count;
            var representative = nonPassFindings.First().Finding;

            // Check if the finding was resolved (appeared in earlier runs but not in latest)
            var latestRun = orderedRuns.Last();
            var inLatest = latestRun.Findings.Any(f =>
                NormalizePattern(f.Title) == group.Key && f.Severity != "Pass");

            var daysSinceLastSeen = (now - lastSeen).TotalDays;
            string status;
            if (inLatest)
                status = "Active"; // Still present = actively fighting
            else if (daysSinceLastSeen > ExpirationThresholdDays)
                status = "Expired";
            else if (daysSinceLastSeen > WeakeningThresholdDays)
                status = "Weakened";
            else
                status = "Active";

            // Confidence based on exposure count and resolution
            var confidence = Math.Min(1.0, exposureCount / (double)FullConfidenceExposures);
            if (!inLatest) confidence = Math.Min(1.0, confidence + 0.2); // Bonus for resolved

            idCounter++;
            antibodies.Add(new Antibody(
                Id: $"AB-{idCounter:D4}",
                Pattern: group.Key,
                Category: representative.ModuleName,
                Severity: representative.Severity,
                ExposureCount: exposureCount,
                FirstSeen: firstSeen,
                LastSeen: lastSeen,
                Status: status,
                ConfidenceScore: Math.Round(confidence, 2)));
        }

        return antibodies.OrderByDescending(a => a.ExposureCount).ToList();
    }

    /// <summary>
    /// Build vaccination records from antibody collection.
    /// </summary>
    public List<VaccinationRecord> GetVaccinations(List<Antibody> antibodies)
    {
        return antibodies
            .GroupBy(a => a.Category)
            .Select(g =>
            {
                var count = g.Count();
                var activeCount = g.Count(a => a.Status == "Active");
                var coverage = Math.Round((activeCount * 100.0) / count, 1);
                var lastBooster = g.Max(a => a.LastSeen);

                string immunity;
                if (coverage >= 80) immunity = "Full";
                else if (coverage >= 50) immunity = "Partial";
                else if (coverage > 0) immunity = "Weakened";
                else immunity = "None";

                return new VaccinationRecord(
                    ThreatCategory: g.Key,
                    AntibodyCount: count,
                    CoveragePercent: coverage,
                    ImmunityLevel: immunity,
                    LastBooster: lastBooster);
            })
            .OrderByDescending(v => v.CoveragePercent)
            .ToList();
    }

    /// <summary>
    /// Track threat recurrence patterns and immunization status.
    /// </summary>
    public List<ThreatMemory> GetThreatMemory(List<AuditRunRecord> history)
    {
        var orderedRuns = history.OrderBy(r => r.Timestamp).ToList();
        if (orderedRuns.Count == 0) return [];

        var latestRun = orderedRuns.Last();
        var latestPatterns = new HashSet<string>(
            latestRun.Findings
                .Where(f => f.Severity != "Pass")
                .Select(f => NormalizePattern(f.Title)));

        var findingGroups = orderedRuns
            .SelectMany(r => r.Findings.Where(f => f.Severity != "Pass"))
            .GroupBy(f => NormalizePattern(f.Title))
            .OrderByDescending(g => g.Count())
            .Take(20)
            .ToList();

        return findingGroups.Select(g =>
        {
            var representative = g.First();
            var isImmunized = !latestPatterns.Contains(g.Key);
            var recurrence = g.Count();

            string action;
            if (isImmunized && recurrence >= 3)
                action = "Strong immunity — monitor for mutations";
            else if (isImmunized)
                action = "Resolved — booster scan recommended";
            else if (recurrence >= 5)
                action = "Chronic infection — escalate remediation";
            else if (recurrence >= 3)
                action = "Recurring — strengthen defenses";
            else
                action = "Active threat — apply fix";

            return new ThreatMemory(
                FindingTitle: representative.Title,
                Module: representative.ModuleName,
                Severity: representative.Severity,
                RecurrenceCount: recurrence,
                IsImmunized: isImmunized,
                RecommendedAction: action);
        }).ToList();
    }

    /// <summary>
    /// Find modules with no or weak immunity coverage.
    /// </summary>
    public List<string> IdentifyVulnerableAreas(
        List<VaccinationRecord> vaccinations, List<string> allModules)
    {
        var coveredModules = new HashSet<string>(
            vaccinations.Where(v => v.ImmunityLevel is "Full" or "Partial")
                .Select(v => v.ThreatCategory));

        return allModules
            .Where(m => !coveredModules.Contains(m))
            .OrderBy(m => m)
            .ToList();
    }

    /// <summary>
    /// Generate proactive recommendations based on immune health.
    /// </summary>
    public List<string> GenerateRecommendations(ImmuneHealthReport report)
    {
        var recs = new List<string>();

        if (report.WeakenedAntibodies > 0)
            recs.Add($"{report.WeakenedAntibodies} antibodies weakening — run targeted scans to boost immunity");

        if (report.ExpiredAntibodies > 0)
            recs.Add($"{report.ExpiredAntibodies} antibodies expired — system vulnerability increasing in dormant areas");

        var chronicThreats = report.RecentThreats.Count(t => !t.IsImmunized && t.RecurrenceCount >= 3);
        if (chronicThreats > 0)
            recs.Add($"{chronicThreats} chronic threats detected — consider automated remediation");

        if (report.VulnerableAreas.Count > 0)
            recs.Add($"No immunity in {report.VulnerableAreas.Count} modules: {string.Join(", ", report.VulnerableAreas.Take(3))}");

        var immunizedCount = report.RecentThreats.Count(t => t.IsImmunized);
        if (immunizedCount > 5)
            recs.Add($"Strong immune response — {immunizedCount} threats successfully neutralized");

        if (report.OverallImmunityScore >= 80)
            recs.Add("Excellent immune health — maintain regular scan cadence");
        else if (report.OverallImmunityScore < 40)
            recs.Add("Low immunity score — increase scan frequency to build stronger defenses");

        if (recs.Count == 0)
            recs.Add("Immune system developing — continue regular audits to build comprehensive coverage");

        return recs;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Normalize a finding title to a canonical pattern for grouping.
    /// Strips variable parts (paths, IPs, usernames) to group similar findings.
    /// </summary>
    private static string NormalizePattern(string title)
    {
        // Simple normalization: lowercase and trim
        return title.Trim().ToLowerInvariant();
    }
}
