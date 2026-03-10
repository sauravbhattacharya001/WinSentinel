using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Tracks remediation SLA compliance for security findings.
/// <para>
/// Each finding severity has a configurable remediation deadline:
/// Critical findings must be remediated within hours, warnings within days.
/// The tracker monitors which findings are on track, approaching their
/// deadline, or overdue, and computes SLA compliance metrics.
/// </para>
/// <para>
/// Use cases:
/// <list type="bullet">
///   <item>Track remediation progress against organizational SLA policies</item>
///   <item>Flag overdue findings before compliance audits</item>
///   <item>Generate SLA compliance reports for management</item>
///   <item>Prioritize remediation work by deadline urgency</item>
///   <item>Measure mean time to remediate (MTTR) by severity</item>
/// </list>
/// </para>
/// </summary>
public class SlaTracker
{
    // ── Configuration ────────────────────────────────────────────

    /// <summary>SLA policy defining remediation deadlines per severity.</summary>
    public class SlaPolicy
    {
        /// <summary>Maximum time to remediate Critical findings.</summary>
        public TimeSpan CriticalDeadline { get; set; } = TimeSpan.FromHours(24);

        /// <summary>Maximum time to remediate Warning findings.</summary>
        public TimeSpan WarningDeadline { get; set; } = TimeSpan.FromDays(7);

        /// <summary>Maximum time to remediate Info findings.</summary>
        public TimeSpan InfoDeadline { get; set; } = TimeSpan.FromDays(30);

        /// <summary>
        /// Fraction of the deadline at which a finding is considered "approaching"
        /// (e.g., 0.75 means the last 25% of the window triggers a warning).
        /// </summary>
        public double ApproachingThreshold { get; set; } = 0.75;

        /// <summary>Name of this policy (e.g., "SOC2", "Internal", "HIPAA").</summary>
        public string Name { get; set; } = "Default";

        /// <summary>Get the deadline for a given severity.</summary>
        public TimeSpan GetDeadline(Severity severity) => severity switch
        {
            Severity.Critical => CriticalDeadline,
            Severity.Warning => WarningDeadline,
            Severity.Info => InfoDeadline,
            _ => TimeSpan.MaxValue // Pass findings have no SLA
        };

        /// <summary>Standard enterprise policy: Critical 24h, Warning 7d, Info 30d.</summary>
        public static SlaPolicy Enterprise => new()
        {
            Name = "Enterprise",
            CriticalDeadline = TimeSpan.FromHours(24),
            WarningDeadline = TimeSpan.FromDays(7),
            InfoDeadline = TimeSpan.FromDays(30),
        };

        /// <summary>Strict compliance policy: Critical 4h, Warning 48h, Info 14d.</summary>
        public static SlaPolicy Strict => new()
        {
            Name = "Strict",
            CriticalDeadline = TimeSpan.FromHours(4),
            WarningDeadline = TimeSpan.FromHours(48),
            InfoDeadline = TimeSpan.FromDays(14),
            ApproachingThreshold = 0.5,
        };

        /// <summary>Relaxed policy for low-risk environments: Critical 72h, Warning 30d, Info 90d.</summary>
        public static SlaPolicy Relaxed => new()
        {
            Name = "Relaxed",
            CriticalDeadline = TimeSpan.FromHours(72),
            WarningDeadline = TimeSpan.FromDays(30),
            InfoDeadline = TimeSpan.FromDays(90),
        };
    }

    /// <summary>SLA status for a tracked finding.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum SlaStatus
    {
        /// <summary>Within the remediation window.</summary>
        OnTrack,
        /// <summary>Approaching the deadline (past the threshold).</summary>
        Approaching,
        /// <summary>Past the remediation deadline.</summary>
        Overdue,
        /// <summary>Finding has been resolved.</summary>
        Resolved,
        /// <summary>Finding severity has no SLA (Pass findings).</summary>
        Exempt
    }

    // ── Tracked finding record ───────────────────────────────────

    /// <summary>
    /// A finding being tracked for SLA compliance.
    /// </summary>
    public class TrackedFinding
    {
        /// <summary>Unique identifier for this tracked finding.</summary>
        public string Id { get; set; } = "";

        /// <summary>The finding title.</summary>
        public string Title { get; set; } = "";

        /// <summary>Category/module that produced the finding.</summary>
        public string Category { get; set; } = "";

        /// <summary>Finding severity at time of detection.</summary>
        public Severity Severity { get; set; }

        /// <summary>When the finding was first detected.</summary>
        public DateTimeOffset DetectedAt { get; set; }

        /// <summary>The remediation deadline based on policy.</summary>
        public DateTimeOffset Deadline { get; set; }

        /// <summary>When the finding was resolved (null if still open).</summary>
        public DateTimeOffset? ResolvedAt { get; set; }

        /// <summary>Whether the finding is still open.</summary>
        [JsonIgnore]
        public bool IsOpen => ResolvedAt == null;

        /// <summary>Time spent open (resolved or still ticking).</summary>
        [JsonIgnore]
        public TimeSpan TimeOpen => (ResolvedAt ?? DateTimeOffset.UtcNow) - DetectedAt;

        /// <summary>Whether remediation met the SLA deadline.</summary>
        [JsonIgnore]
        public bool MetSla => ResolvedAt.HasValue && ResolvedAt.Value <= Deadline;

        /// <summary>Optional notes about the resolution.</summary>
        public string? ResolutionNotes { get; set; }
    }

    // ── SLA assessment result ────────────────────────────────────

    /// <summary>SLA status assessment for a single finding.</summary>
    public class FindingSlaAssessment
    {
        /// <summary>The tracked finding.</summary>
        public required TrackedFinding Finding { get; init; }

        /// <summary>Current SLA status.</summary>
        public SlaStatus Status { get; init; }

        /// <summary>Time remaining until deadline (negative if overdue).</summary>
        public TimeSpan TimeRemaining { get; init; }

        /// <summary>Fraction of the SLA window consumed (0.0 to 1.0+).</summary>
        public double WindowConsumed { get; init; }

        /// <summary>Human-readable urgency description.</summary>
        public string UrgencyLabel => Status switch
        {
            SlaStatus.Overdue => $"OVERDUE by {FormatDuration(-TimeRemaining)}",
            SlaStatus.Approaching => $"{FormatDuration(TimeRemaining)} remaining",
            SlaStatus.OnTrack => $"{FormatDuration(TimeRemaining)} remaining",
            SlaStatus.Resolved => Finding.MetSla ? "Resolved within SLA" : "Resolved AFTER SLA",
            SlaStatus.Exempt => "No SLA",
            _ => "Unknown"
        };

        private static string FormatDuration(TimeSpan ts)
        {
            if (ts.TotalDays >= 1)
                return $"{ts.Days}d {ts.Hours}h";
            if (ts.TotalHours >= 1)
                return $"{ts.Hours}h {ts.Minutes}m";
            return $"{ts.Minutes}m";
        }
    }

    // ── SLA compliance report ────────────────────────────────────

    /// <summary>Overall SLA compliance report.</summary>
    public class SlaComplianceReport
    {
        /// <summary>Policy used for this report.</summary>
        public string PolicyName { get; init; } = "";

        /// <summary>Report generation timestamp.</summary>
        public DateTimeOffset GeneratedAt { get; init; }

        /// <summary>Total tracked findings.</summary>
        public int TotalTracked { get; init; }

        /// <summary>Currently open findings.</summary>
        public int OpenCount { get; init; }

        /// <summary>Resolved findings.</summary>
        public int ResolvedCount { get; init; }

        /// <summary>Findings currently overdue.</summary>
        public int OverdueCount { get; init; }

        /// <summary>Findings approaching their deadline.</summary>
        public int ApproachingCount { get; init; }

        /// <summary>Overall SLA compliance percentage (resolved within deadline / total resolved).</summary>
        public double CompliancePercent { get; init; }

        /// <summary>Per-severity compliance breakdown.</summary>
        public Dictionary<Severity, SeverityCompliance> BySeverity { get; init; } = new();

        /// <summary>Mean time to remediate (all resolved findings).</summary>
        public TimeSpan? MeanTimeToRemediate { get; init; }

        /// <summary>Per-severity MTTR.</summary>
        public Dictionary<Severity, TimeSpan> MttrBySeverity { get; init; } = new();

        /// <summary>Individual finding assessments, ordered by urgency.</summary>
        public List<FindingSlaAssessment> Assessments { get; init; } = [];

        /// <summary>Top overdue findings requiring immediate attention.</summary>
        public List<FindingSlaAssessment> TopOverdue { get; init; } = [];

        /// <summary>Findings approaching their deadline.</summary>
        public List<FindingSlaAssessment> ApproachingDeadline { get; init; } = [];
    }

    /// <summary>Compliance stats for a single severity level.</summary>
    public class SeverityCompliance
    {
        /// <summary>Total findings at this severity.</summary>
        public int Total { get; init; }

        /// <summary>Resolved within SLA.</summary>
        public int MetSla { get; init; }

        /// <summary>Resolved after SLA or still overdue.</summary>
        public int MissedSla { get; init; }

        /// <summary>Still open and on track.</summary>
        public int OnTrack { get; init; }

        /// <summary>Compliance percentage for this severity.</summary>
        public double CompliancePercent { get; init; }

        /// <summary>Mean time to remediate at this severity.</summary>
        public TimeSpan? Mttr { get; init; }
    }

    // ── State ────────────────────────────────────────────────────

    private readonly List<TrackedFinding> _findings = new();
    private readonly SlaPolicy _policy;
    private int _nextId;

    /// <summary>All tracked findings.</summary>
    public IReadOnlyList<TrackedFinding> Findings => _findings;

    /// <summary>The active SLA policy.</summary>
    public SlaPolicy Policy => _policy;

    /// <summary>
    /// Create a new SLA tracker with the specified policy.
    /// </summary>
    /// <param name="policy">SLA policy to enforce. Uses Enterprise defaults if null.</param>
    public SlaTracker(SlaPolicy? policy = null)
    {
        _policy = policy ?? SlaPolicy.Enterprise;
    }

    // ── Tracking operations ──────────────────────────────────────

    /// <summary>
    /// Begin tracking a finding for SLA compliance.
    /// </summary>
    /// <param name="finding">The security finding to track.</param>
    /// <param name="detectedAt">When the finding was detected. Defaults to now.</param>
    /// <returns>The tracked finding record with deadline assigned.</returns>
    /// <exception cref="ArgumentNullException">If finding is null.</exception>
    public TrackedFinding Track(Finding finding, DateTimeOffset? detectedAt = null)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var detected = detectedAt ?? DateTimeOffset.UtcNow;
        var deadline = _policy.GetDeadline(finding.Severity);

        var tracked = new TrackedFinding
        {
            Id = $"SLA-{++_nextId:D4}",
            Title = finding.Title,
            Category = finding.Category,
            Severity = finding.Severity,
            DetectedAt = detected,
            Deadline = deadline == TimeSpan.MaxValue
                ? DateTimeOffset.MaxValue
                : detected + deadline,
        };

        _findings.Add(tracked);
        return tracked;
    }

    /// <summary>
    /// Track all actionable findings from a security report.
    /// Only Critical, Warning, and Info findings are tracked (Pass is exempt).
    /// </summary>
    /// <param name="report">The security report to import.</param>
    /// <param name="detectedAt">Detection timestamp. Defaults to report generation time.</param>
    /// <returns>Number of findings now being tracked.</returns>
    public int TrackReport(SecurityReport report, DateTimeOffset? detectedAt = null)
    {
        ArgumentNullException.ThrowIfNull(report);

        var detected = detectedAt ?? report.GeneratedAt;
        int count = 0;

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                if (finding.Severity == Severity.Pass)
                    continue;

                Track(finding, detected);
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Mark a tracked finding as resolved.
    /// </summary>
    /// <param name="findingId">The tracked finding ID (e.g., "SLA-0001").</param>
    /// <param name="resolvedAt">Resolution timestamp. Defaults to now.</param>
    /// <param name="notes">Optional resolution notes.</param>
    /// <returns>The updated tracked finding.</returns>
    /// <exception cref="ArgumentException">If the finding ID is not found.</exception>
    /// <exception cref="InvalidOperationException">If the finding is already resolved.</exception>
    public TrackedFinding Resolve(string findingId, DateTimeOffset? resolvedAt = null, string? notes = null)
    {
        var tracked = _findings.FirstOrDefault(f =>
            f.Id.Equals(findingId, StringComparison.OrdinalIgnoreCase))
            ?? throw new ArgumentException($"Finding '{findingId}' not found");

        if (!tracked.IsOpen)
            throw new InvalidOperationException($"Finding '{findingId}' is already resolved");

        tracked.ResolvedAt = resolvedAt ?? DateTimeOffset.UtcNow;
        tracked.ResolutionNotes = notes;
        return tracked;
    }

    /// <summary>
    /// Resolve findings by title match (case-insensitive).
    /// Useful when a remediation fixes a known finding across modules.
    /// </summary>
    /// <param name="titlePattern">Substring to match against finding titles.</param>
    /// <param name="resolvedAt">Resolution timestamp. Defaults to now.</param>
    /// <returns>Number of findings resolved.</returns>
    public int ResolveByTitle(string titlePattern, DateTimeOffset? resolvedAt = null)
    {
        var resolved = resolvedAt ?? DateTimeOffset.UtcNow;
        int count = 0;

        foreach (var f in _findings.Where(f => f.IsOpen &&
            f.Title.Contains(titlePattern, StringComparison.OrdinalIgnoreCase)))
        {
            f.ResolvedAt = resolved;
            count++;
        }

        return count;
    }

    // ── Assessment ───────────────────────────────────────────────

    /// <summary>
    /// Assess the SLA status of a single tracked finding.
    /// </summary>
    /// <param name="finding">The tracked finding.</param>
    /// <param name="asOf">Point in time for assessment. Defaults to now.</param>
    /// <returns>SLA assessment with status, time remaining, and urgency.</returns>
    public FindingSlaAssessment Assess(TrackedFinding finding, DateTimeOffset? asOf = null)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var now = asOf ?? DateTimeOffset.UtcNow;

        // Exempt (Pass findings)
        if (finding.Severity == Severity.Pass || finding.Deadline == DateTimeOffset.MaxValue)
        {
            return new FindingSlaAssessment
            {
                Finding = finding,
                Status = SlaStatus.Exempt,
                TimeRemaining = TimeSpan.MaxValue,
                WindowConsumed = 0,
            };
        }

        // Resolved
        if (!finding.IsOpen)
        {
            return new FindingSlaAssessment
            {
                Finding = finding,
                Status = SlaStatus.Resolved,
                TimeRemaining = finding.Deadline - finding.ResolvedAt!.Value,
                WindowConsumed = finding.TimeOpen / (finding.Deadline - finding.DetectedAt),
            };
        }

        var remaining = finding.Deadline - now;
        var totalWindow = finding.Deadline - finding.DetectedAt;
        var consumed = totalWindow.TotalSeconds > 0
            ? (now - finding.DetectedAt).TotalSeconds / totalWindow.TotalSeconds
            : 1.0;

        SlaStatus status;
        if (remaining <= TimeSpan.Zero)
            status = SlaStatus.Overdue;
        else if (consumed >= _policy.ApproachingThreshold)
            status = SlaStatus.Approaching;
        else
            status = SlaStatus.OnTrack;

        return new FindingSlaAssessment
        {
            Finding = finding,
            Status = status,
            TimeRemaining = remaining,
            WindowConsumed = consumed,
        };
    }

    /// <summary>
    /// Generate a comprehensive SLA compliance report.
    /// </summary>
    /// <param name="asOf">Point in time for the report. Defaults to now.</param>
    /// <returns>Full SLA compliance report with metrics and assessments.</returns>
    public SlaComplianceReport GenerateReport(DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;

        var assessments = _findings
            .Select(f => Assess(f, now))
            .OrderBy(a => a.Status == SlaStatus.Overdue ? 0 :
                          a.Status == SlaStatus.Approaching ? 1 :
                          a.Status == SlaStatus.OnTrack ? 2 : 3)
            .ThenBy(a => a.TimeRemaining)
            .ToList();

        var resolved = _findings.Where(f => !f.IsOpen).ToList();
        var open = _findings.Where(f => f.IsOpen).ToList();

        // Overall compliance: resolved within SLA / total resolved
        var metSla = resolved.Count(f => f.MetSla);
        var compliancePct = resolved.Count > 0
            ? Math.Round(100.0 * metSla / resolved.Count, 1)
            : 100.0;

        // MTTR
        TimeSpan? overallMttr = resolved.Count > 0
            ? TimeSpan.FromSeconds(resolved.Average(f => f.TimeOpen.TotalSeconds))
            : null;

        // Per-severity breakdown
        var severities = new[] { Severity.Critical, Severity.Warning, Severity.Info };
        var bySeverity = new Dictionary<Severity, SeverityCompliance>();
        var mttrBySeverity = new Dictionary<Severity, TimeSpan>();

        foreach (var sev in severities)
        {
            var sevFindings = _findings.Where(f => f.Severity == sev).ToList();
            var sevResolved = sevFindings.Where(f => !f.IsOpen).ToList();
            var sevMetSla = sevResolved.Count(f => f.MetSla);
            var sevOnTrack = assessments.Count(a =>
                a.Finding.Severity == sev && a.Status == SlaStatus.OnTrack);

            bySeverity[sev] = new SeverityCompliance
            {
                Total = sevFindings.Count,
                MetSla = sevMetSla,
                MissedSla = sevFindings.Count - sevMetSla - sevOnTrack,
                OnTrack = sevOnTrack,
                CompliancePercent = sevResolved.Count > 0
                    ? Math.Round(100.0 * sevMetSla / sevResolved.Count, 1)
                    : 100.0,
                Mttr = sevResolved.Count > 0
                    ? TimeSpan.FromSeconds(sevResolved.Average(f => f.TimeOpen.TotalSeconds))
                    : null,
            };

            if (sevResolved.Count > 0)
                mttrBySeverity[sev] = TimeSpan.FromSeconds(
                    sevResolved.Average(f => f.TimeOpen.TotalSeconds));
        }

        var overdue = assessments.Where(a => a.Status == SlaStatus.Overdue).ToList();
        var approaching = assessments.Where(a => a.Status == SlaStatus.Approaching).ToList();

        return new SlaComplianceReport
        {
            PolicyName = _policy.Name,
            GeneratedAt = now,
            TotalTracked = _findings.Count,
            OpenCount = open.Count,
            ResolvedCount = resolved.Count,
            OverdueCount = overdue.Count,
            ApproachingCount = approaching.Count,
            CompliancePercent = compliancePct,
            BySeverity = bySeverity,
            MeanTimeToRemediate = overallMttr,
            MttrBySeverity = mttrBySeverity,
            Assessments = assessments,
            TopOverdue = overdue.Take(10).ToList(),
            ApproachingDeadline = approaching.Take(10).ToList(),
        };
    }

    // ── Query helpers ────────────────────────────────────────────

    /// <summary>Get all open findings.</summary>
    public IReadOnlyList<TrackedFinding> GetOpen() =>
        _findings.Where(f => f.IsOpen).ToList();

    /// <summary>Get all overdue findings.</summary>
    public IReadOnlyList<TrackedFinding> GetOverdue(DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;
        return _findings
            .Where(f => f.IsOpen && f.Deadline < now && f.Deadline != DateTimeOffset.MaxValue)
            .OrderBy(f => f.Deadline)
            .ToList();
    }

    /// <summary>Get findings approaching their deadline.</summary>
    public IReadOnlyList<TrackedFinding> GetApproaching(DateTimeOffset? asOf = null)
    {
        var now = asOf ?? DateTimeOffset.UtcNow;
        return _findings
            .Where(f =>
            {
                if (!f.IsOpen || f.Deadline == DateTimeOffset.MaxValue) return false;
                var total = (f.Deadline - f.DetectedAt).TotalSeconds;
                if (total <= 0) return false;
                var consumed = (now - f.DetectedAt).TotalSeconds / total;
                return consumed >= _policy.ApproachingThreshold && f.Deadline > now;
            })
            .OrderBy(f => f.Deadline)
            .ToList();
    }

    /// <summary>Get a tracked finding by its ID.</summary>
    public TrackedFinding? GetById(string id) =>
        _findings.FirstOrDefault(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>Get findings by category.</summary>
    public IReadOnlyList<TrackedFinding> GetByCategory(string category) =>
        _findings.Where(f => f.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>Get findings by severity.</summary>
    public IReadOnlyList<TrackedFinding> GetBySeverity(Severity severity) =>
        _findings.Where(f => f.Severity == severity).ToList();

    // ── Serialization ────────────────────────────────────────────

    /// <summary>
    /// Export tracked findings to JSON for persistence.
    /// </summary>
    public string ExportJson()
    {
        var data = new
        {
            policy = new
            {
                _policy.Name,
                CriticalHours = _policy.CriticalDeadline.TotalHours,
                WarningDays = _policy.WarningDeadline.TotalDays,
                InfoDays = _policy.InfoDeadline.TotalDays,
                _policy.ApproachingThreshold,
            },
            findings = _findings,
            exportedAt = DateTimeOffset.UtcNow,
        };

        return JsonSerializer.Serialize(data, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        });
    }

    /// <summary>
    /// Import previously exported findings.
    /// </summary>
    /// <param name="json">JSON string from <see cref="ExportJson"/>.</param>
    /// <returns>Number of findings imported.</returns>
    public int ImportJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!root.TryGetProperty("findings", out var findingsEl))
            throw new ArgumentException("JSON must contain a 'findings' array");

        int count = 0;
        foreach (var el in findingsEl.EnumerateArray())
        {
            var tracked = new TrackedFinding
            {
                Id = el.GetProperty("Id").GetString() ?? $"SLA-{++_nextId:D4}",
                Title = el.GetProperty("Title").GetString() ?? "",
                Category = el.GetProperty("Category").GetString() ?? "",
                Severity = Enum.Parse<Severity>(el.GetProperty("Severity").GetString() ?? "Info"),
                DetectedAt = el.GetProperty("DetectedAt").GetDateTimeOffset(),
                Deadline = el.GetProperty("Deadline").GetDateTimeOffset(),
            };

            if (el.TryGetProperty("ResolvedAt", out var resolvedEl) &&
                resolvedEl.ValueKind != JsonValueKind.Null)
            {
                tracked.ResolvedAt = resolvedEl.GetDateTimeOffset();
            }

            if (el.TryGetProperty("ResolutionNotes", out var notesEl) &&
                notesEl.ValueKind != JsonValueKind.Null)
            {
                tracked.ResolutionNotes = notesEl.GetString();
            }

            _findings.Add(tracked);

            // Keep ID sequence consistent
            if (tracked.Id.StartsWith("SLA-") &&
                int.TryParse(tracked.Id[4..], out var num) && num > _nextId)
            {
                _nextId = num;
            }

            count++;
        }

        return count;
    }

    // ── Text report ──────────────────────────────────────────────

    /// <summary>
    /// Generate a plain-text SLA compliance summary.
    /// </summary>
    public string GenerateTextReport(DateTimeOffset? asOf = null)
    {
        var report = GenerateReport(asOf);
        var sb = new StringBuilder();

        sb.AppendLine($"═══ SLA Compliance Report ({report.PolicyName}) ═══");
        sb.AppendLine($"Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        // Overall stats
        sb.AppendLine($"Total Tracked:    {report.TotalTracked}");
        sb.AppendLine($"Open:             {report.OpenCount}");
        sb.AppendLine($"Resolved:         {report.ResolvedCount}");
        sb.AppendLine($"Overdue:          {report.OverdueCount}");
        sb.AppendLine($"Approaching:      {report.ApproachingCount}");
        sb.AppendLine($"SLA Compliance:   {report.CompliancePercent}%");

        if (report.MeanTimeToRemediate.HasValue)
            sb.AppendLine($"Mean TTR:         {FormatTimeSpan(report.MeanTimeToRemediate.Value)}");

        sb.AppendLine();

        // Per-severity breakdown
        sb.AppendLine("── By Severity ──");
        foreach (var (sev, comp) in report.BySeverity.OrderByDescending(kv => (int)kv.Key))
        {
            if (comp.Total == 0) continue;
            var deadline = _policy.GetDeadline(sev);
            sb.AppendLine($"  {sev,-10} ({FormatTimeSpan(deadline)} SLA):");
            sb.AppendLine($"    Total: {comp.Total} | Met SLA: {comp.MetSla} | " +
                          $"Missed: {comp.MissedSla} | On Track: {comp.OnTrack}");
            sb.AppendLine($"    Compliance: {comp.CompliancePercent}%");
            if (comp.Mttr.HasValue)
                sb.AppendLine($"    MTTR: {FormatTimeSpan(comp.Mttr.Value)}");
        }

        // Overdue items
        if (report.TopOverdue.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("── OVERDUE ──");
            foreach (var a in report.TopOverdue)
            {
                sb.AppendLine($"  [{a.Finding.Severity}] {a.Finding.Title}");
                sb.AppendLine($"    Category: {a.Finding.Category} | {a.UrgencyLabel}");
            }
        }

        // Approaching deadline
        if (report.ApproachingDeadline.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("── APPROACHING DEADLINE ──");
            foreach (var a in report.ApproachingDeadline)
            {
                sb.AppendLine($"  [{a.Finding.Severity}] {a.Finding.Title}");
                sb.AppendLine($"    Category: {a.Finding.Category} | {a.UrgencyLabel}");
            }
        }

        return sb.ToString();
    }

    private static string FormatTimeSpan(TimeSpan ts)
    {
        if (ts == TimeSpan.MaxValue) return "∞";
        if (ts.TotalDays >= 1) return $"{ts.Days}d {ts.Hours}h";
        if (ts.TotalHours >= 1) return $"{(int)ts.TotalHours}h {ts.Minutes}m";
        return $"{(int)ts.TotalMinutes}m";
    }
}
