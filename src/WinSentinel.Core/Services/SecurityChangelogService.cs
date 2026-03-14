using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a chronological, versioned changelog of security posture changes.
/// Unlike <see cref="AuditDiffService"/> (which compares two snapshots) or
/// <see cref="SecurityDigestGenerator"/> (newsletter-style current summary),
/// this service produces a full changelog across multiple scans — tracking
/// every new finding, resolution, severity change, and score shift over time.
/// Output formats: Markdown, JSON, and plain text.
/// </summary>
public class SecurityChangelogService
{
    private readonly AuditDiffService _diffService = new();

    // ── Models ───────────────────────────────────────────────────────

    /// <summary>Impact level of a changelog entry.</summary>
    public enum Impact
    {
        /// <summary>Positive change — resolved finding, improved score.</summary>
        Positive,
        /// <summary>Negative change — new finding, degraded score.</summary>
        Negative,
        /// <summary>Neutral or informational change.</summary>
        Neutral
    }

    /// <summary>Type of change recorded in the changelog.</summary>
    public enum ChangeType
    {
        NewFinding,
        ResolvedFinding,
        SeverityUpgrade,
        SeverityDowngrade,
        ScoreImproved,
        ScoreDeclined,
        GradeChanged,
        ModuleAdded,
        ModuleRemoved
    }

    /// <summary>A single entry in the changelog.</summary>
    public class ChangelogEntry
    {
        /// <summary>Type of change.</summary>
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ChangeType Type { get; init; }

        /// <summary>Human-readable description.</summary>
        public string Description { get; init; } = "";

        /// <summary>Audit module involved (if applicable).</summary>
        public string? Module { get; init; }

        /// <summary>Category of the module/finding.</summary>
        public string? Category { get; init; }

        /// <summary>Severity of the finding (if applicable).</summary>
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public Severity? Severity { get; init; }

        /// <summary>Impact of this change.</summary>
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public Impact Impact { get; init; }
    }

    /// <summary>A version (release) in the changelog, corresponding to one scan-to-scan diff.</summary>
    public class ChangelogVersion
    {
        /// <summary>Version label (e.g. "v3" or "2026-03-13T20:00:00Z").</summary>
        public string Version { get; init; } = "";

        /// <summary>Timestamp of the newer scan.</summary>
        public DateTimeOffset Timestamp { get; init; }

        /// <summary>Score at this version.</summary>
        public int Score { get; init; }

        /// <summary>Grade at this version.</summary>
        public string Grade { get; init; } = "";

        /// <summary>Score at previous version.</summary>
        public int PreviousScore { get; init; }

        /// <summary>Grade at previous version.</summary>
        public string PreviousGrade { get; init; } = "";

        /// <summary>All changes in this version.</summary>
        public List<ChangelogEntry> Entries { get; init; } = [];

        /// <summary>Count of positive changes.</summary>
        public int Improvements => Entries.Count(e => e.Impact == Impact.Positive);

        /// <summary>Count of negative changes.</summary>
        public int Regressions => Entries.Count(e => e.Impact == Impact.Negative);

        /// <summary>Whether there are any entries.</summary>
        public bool HasChanges => Entries.Count > 0;
    }

    /// <summary>The full changelog across all scans.</summary>
    public class Changelog
    {
        /// <summary>Title for the changelog.</summary>
        public string Title { get; init; } = "Security Changelog";

        /// <summary>When the changelog was generated.</summary>
        public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

        /// <summary>Ordered versions (most recent first).</summary>
        public List<ChangelogVersion> Versions { get; init; } = [];

        /// <summary>Total changes across all versions.</summary>
        public int TotalChanges => Versions.Sum(v => v.Entries.Count);

        /// <summary>Total improvements across all versions.</summary>
        public int TotalImprovements => Versions.Sum(v => v.Improvements);

        /// <summary>Total regressions across all versions.</summary>
        public int TotalRegressions => Versions.Sum(v => v.Regressions);

        /// <summary>Latest score (from the most recent version).</summary>
        public int? LatestScore => Versions.Count > 0 ? Versions[0].Score : null;

        /// <summary>Earliest score (from the oldest version).</summary>
        public int? EarliestScore => Versions.Count > 0 ? Versions[^1].PreviousScore : null;

        /// <summary>Net score change from earliest to latest.</summary>
        public int? NetScoreChange => LatestScore.HasValue && EarliestScore.HasValue
            ? LatestScore.Value - EarliestScore.Value : null;
    }

    // ── Generation ───────────────────────────────────────────────────

    /// <summary>
    /// Generate a changelog from a chronologically ordered list of security reports.
    /// Reports should be ordered oldest-first.
    /// </summary>
    /// <param name="reports">At least 2 reports, ordered oldest to newest.</param>
    /// <param name="title">Optional title for the changelog.</param>
    /// <returns>A complete changelog.</returns>
    /// <exception cref="ArgumentException">If fewer than 2 reports are provided.</exception>
    public Changelog Generate(IReadOnlyList<SecurityReport> reports, string? title = null)
    {
        if (reports == null || reports.Count < 2)
            throw new ArgumentException("At least 2 reports are required to generate a changelog.", nameof(reports));

        var versions = new List<ChangelogVersion>();

        for (int i = 1; i < reports.Count; i++)
        {
            var older = reports[i - 1];
            var newer = reports[i];
            var diff = _diffService.Compare(older, newer);
            var version = BuildVersion(diff, i);
            versions.Add(version);
        }

        // Most recent first
        versions.Reverse();

        return new Changelog
        {
            Title = title ?? "Security Changelog",
            GeneratedAt = DateTimeOffset.UtcNow,
            Versions = versions
        };
    }

    /// <summary>
    /// Generate a changelog from pre-computed diffs.
    /// Diffs should be in chronological order (oldest first).
    /// </summary>
    public Changelog GenerateFromDiffs(IReadOnlyList<AuditDiffService.AuditDiffResult> diffs, string? title = null)
    {
        if (diffs == null || diffs.Count == 0)
            throw new ArgumentException("At least 1 diff is required.", nameof(diffs));

        var versions = new List<ChangelogVersion>();
        for (int i = 0; i < diffs.Count; i++)
        {
            versions.Add(BuildVersion(diffs[i], i + 1));
        }

        versions.Reverse();

        return new Changelog
        {
            Title = title ?? "Security Changelog",
            GeneratedAt = DateTimeOffset.UtcNow,
            Versions = versions
        };
    }

    // ── Export formats ───────────────────────────────────────────────

    /// <summary>Export changelog as Markdown.</summary>
    public string ToMarkdown(Changelog changelog)
    {
        ArgumentNullException.ThrowIfNull(changelog);

        var sb = new StringBuilder();
        sb.AppendLine($"# {changelog.Title}");
        sb.AppendLine();

        if (changelog.NetScoreChange.HasValue)
        {
            var trend = changelog.NetScoreChange.Value > 0 ? "📈" :
                        changelog.NetScoreChange.Value < 0 ? "📉" : "➡️";
            sb.AppendLine($"**Overall trend:** {trend} {changelog.EarliestScore} → {changelog.LatestScore} " +
                          $"({(changelog.NetScoreChange.Value >= 0 ? "+" : "")}{changelog.NetScoreChange.Value} points)  ");
            sb.AppendLine($"**Total changes:** {changelog.TotalChanges} " +
                          $"(✅ {changelog.TotalImprovements} improvements, ⚠️ {changelog.TotalRegressions} regressions)");
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine();

        foreach (var version in changelog.Versions)
        {
            sb.AppendLine($"## {version.Version} — {version.Timestamp:yyyy-MM-dd HH:mm}");
            sb.AppendLine();
            sb.AppendLine($"**Score:** {version.PreviousScore} → {version.Score} " +
                          $"({version.PreviousGrade} → {version.Grade})  ");

            if (!version.HasChanges)
            {
                sb.AppendLine("_No changes._");
                sb.AppendLine();
                continue;
            }

            sb.AppendLine($"**Changes:** {version.Entries.Count} " +
                          $"(✅ {version.Improvements}, ⚠️ {version.Regressions})");
            sb.AppendLine();

            // Group entries by impact
            var negative = version.Entries.Where(e => e.Impact == Impact.Negative).ToList();
            var positive = version.Entries.Where(e => e.Impact == Impact.Positive).ToList();
            var neutral = version.Entries.Where(e => e.Impact == Impact.Neutral).ToList();

            if (negative.Count > 0)
            {
                sb.AppendLine("### ⚠️ Regressions");
                sb.AppendLine();
                foreach (var entry in negative)
                    sb.AppendLine($"- **{FormatType(entry.Type)}:** {entry.Description}");
                sb.AppendLine();
            }

            if (positive.Count > 0)
            {
                sb.AppendLine("### ✅ Improvements");
                sb.AppendLine();
                foreach (var entry in positive)
                    sb.AppendLine($"- **{FormatType(entry.Type)}:** {entry.Description}");
                sb.AppendLine();
            }

            if (neutral.Count > 0)
            {
                sb.AppendLine("### ℹ️ Other Changes");
                sb.AppendLine();
                foreach (var entry in neutral)
                    sb.AppendLine($"- **{FormatType(entry.Type)}:** {entry.Description}");
                sb.AppendLine();
            }

            sb.AppendLine("---");
            sb.AppendLine();
        }

        return sb.ToString().TrimEnd();
    }

    /// <summary>Export changelog as plain text.</summary>
    public string ToText(Changelog changelog)
    {
        ArgumentNullException.ThrowIfNull(changelog);

        var sb = new StringBuilder();
        sb.AppendLine(changelog.Title.ToUpperInvariant());
        sb.AppendLine(new string('=', changelog.Title.Length));
        sb.AppendLine();

        if (changelog.NetScoreChange.HasValue)
        {
            sb.AppendLine($"Overall: {changelog.EarliestScore} -> {changelog.LatestScore} " +
                          $"({(changelog.NetScoreChange.Value >= 0 ? "+" : "")}{changelog.NetScoreChange.Value} pts)");
            sb.AppendLine($"Changes: {changelog.TotalChanges} total, " +
                          $"{changelog.TotalImprovements} improvements, {changelog.TotalRegressions} regressions");
            sb.AppendLine();
        }

        foreach (var version in changelog.Versions)
        {
            sb.AppendLine($"[{version.Version}] {version.Timestamp:yyyy-MM-dd HH:mm}");
            sb.AppendLine($"  Score: {version.PreviousScore} -> {version.Score} ({version.PreviousGrade} -> {version.Grade})");

            if (!version.HasChanges)
            {
                sb.AppendLine("  No changes.");
                sb.AppendLine();
                continue;
            }

            foreach (var entry in version.Entries)
            {
                var icon = entry.Impact switch
                {
                    Impact.Positive => "+",
                    Impact.Negative => "-",
                    _ => " "
                };
                sb.AppendLine($"  {icon} [{FormatType(entry.Type)}] {entry.Description}");
            }
            sb.AppendLine();
        }

        return sb.ToString().TrimEnd();
    }

    /// <summary>Export changelog as JSON.</summary>
    public string ToJson(Changelog changelog)
    {
        ArgumentNullException.ThrowIfNull(changelog);

        return JsonSerializer.Serialize(changelog, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
    }

    /// <summary>
    /// Filter a changelog to only include versions that have changes.
    /// </summary>
    public Changelog FilterEmpty(Changelog changelog)
    {
        ArgumentNullException.ThrowIfNull(changelog);

        return new Changelog
        {
            Title = changelog.Title,
            GeneratedAt = changelog.GeneratedAt,
            Versions = changelog.Versions.Where(v => v.HasChanges).ToList()
        };
    }

    /// <summary>
    /// Filter changelog entries by impact type.
    /// </summary>
    public Changelog FilterByImpact(Changelog changelog, Impact impact)
    {
        ArgumentNullException.ThrowIfNull(changelog);

        return new Changelog
        {
            Title = changelog.Title,
            GeneratedAt = changelog.GeneratedAt,
            Versions = changelog.Versions.Select(v => new ChangelogVersion
            {
                Version = v.Version,
                Timestamp = v.Timestamp,
                Score = v.Score,
                Grade = v.Grade,
                PreviousScore = v.PreviousScore,
                PreviousGrade = v.PreviousGrade,
                Entries = v.Entries.Where(e => e.Impact == impact).ToList()
            }).Where(v => v.Entries.Count > 0).ToList()
        };
    }

    /// <summary>
    /// Filter changelog to only include versions within a date range.
    /// </summary>
    public Changelog FilterByDateRange(Changelog changelog, DateTimeOffset from, DateTimeOffset to)
    {
        ArgumentNullException.ThrowIfNull(changelog);

        return new Changelog
        {
            Title = changelog.Title,
            GeneratedAt = changelog.GeneratedAt,
            Versions = changelog.Versions.Where(v => v.Timestamp >= from && v.Timestamp <= to).ToList()
        };
    }

    // ── Private helpers ──────────────────────────────────────────────

    private ChangelogVersion BuildVersion(AuditDiffService.AuditDiffResult diff, int index)
    {
        var entries = new List<ChangelogEntry>();

        // Score changes
        if (diff.ScoreDelta > 0)
        {
            entries.Add(new ChangelogEntry
            {
                Type = ChangeType.ScoreImproved,
                Description = $"Score improved by {diff.ScoreDelta} points ({diff.OldScore} → {diff.NewScore})",
                Impact = Impact.Positive
            });
        }
        else if (diff.ScoreDelta < 0)
        {
            entries.Add(new ChangelogEntry
            {
                Type = ChangeType.ScoreDeclined,
                Description = $"Score declined by {Math.Abs(diff.ScoreDelta)} points ({diff.OldScore} → {diff.NewScore})",
                Impact = Impact.Negative
            });
        }

        // Grade changes
        if (diff.GradeChanged)
        {
            var impact = string.Compare(diff.NewGrade, diff.OldGrade, StringComparison.OrdinalIgnoreCase) < 0
                ? Impact.Positive  // A < B means grade improved (A is better than B)
                : Impact.Negative;
            entries.Add(new ChangelogEntry
            {
                Type = ChangeType.GradeChanged,
                Description = $"Grade changed from {diff.OldGrade} to {diff.NewGrade}",
                Impact = impact
            });
        }

        // New findings
        foreach (var nf in diff.NewFindings)
        {
            entries.Add(new ChangelogEntry
            {
                Type = ChangeType.NewFinding,
                Description = $"[{nf.Finding.Severity}] {nf.Finding.Title} — {nf.Finding.Description}",
                Module = nf.Module,
                Category = nf.Category,
                Severity = nf.Finding.Severity,
                Impact = nf.Finding.Severity >= Models.Severity.Warning ? Impact.Negative : Impact.Neutral
            });
        }

        // Resolved findings
        foreach (var rf in diff.ResolvedFindings)
        {
            entries.Add(new ChangelogEntry
            {
                Type = ChangeType.ResolvedFinding,
                Description = $"Resolved: {rf.Finding.Title}",
                Module = rf.Module,
                Category = rf.Category,
                Severity = rf.Finding.Severity,
                Impact = Impact.Positive
            });
        }

        // Severity changes
        foreach (var sc in diff.SeverityChanges)
        {
            var isUpgrade = sc.NewSeverity > sc.OldSeverity;
            entries.Add(new ChangelogEntry
            {
                Type = isUpgrade ? ChangeType.SeverityUpgrade : ChangeType.SeverityDowngrade,
                Description = $"{sc.Title}: severity {sc.OldSeverity} → {sc.NewSeverity}",
                Module = sc.Module,
                Category = sc.Category,
                Severity = sc.NewSeverity,
                Impact = isUpgrade ? Impact.Negative : Impact.Positive
            });
        }

        // Module changes
        foreach (var mc in diff.ModuleChanges)
        {
            var isAdded = mc.Kind == AuditDiffService.ChangeKind.Added;
            entries.Add(new ChangelogEntry
            {
                Type = isAdded ? ChangeType.ModuleAdded : ChangeType.ModuleRemoved,
                Description = $"Module {(isAdded ? "added" : "removed")}: {mc.Module}",
                Module = mc.Module,
                Category = mc.Category,
                Impact = Impact.Neutral
            });
        }

        return new ChangelogVersion
        {
            Version = $"v{index}",
            Timestamp = diff.NewerTimestamp,
            Score = diff.NewScore,
            Grade = diff.NewGrade,
            PreviousScore = diff.OldScore,
            PreviousGrade = diff.OldGrade,
            Entries = entries
        };
    }

    private static string FormatType(ChangeType type) => type switch
    {
        ChangeType.NewFinding => "New Finding",
        ChangeType.ResolvedFinding => "Resolved",
        ChangeType.SeverityUpgrade => "Severity ↑",
        ChangeType.SeverityDowngrade => "Severity ↓",
        ChangeType.ScoreImproved => "Score ↑",
        ChangeType.ScoreDeclined => "Score ↓",
        ChangeType.GradeChanged => "Grade",
        ChangeType.ModuleAdded => "Module Added",
        ChangeType.ModuleRemoved => "Module Removed",
        _ => type.ToString()
    };
}
