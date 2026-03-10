using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Manages custom tags and annotations on security findings.
/// <para>
/// Security teams need to organize findings beyond severity and category —
/// tagging lets them assign ownership ("team-network"), track workflow
/// ("deferred", "sprint-23", "accepted-risk"), filter dashboards, and
/// annotate findings with notes explaining decisions.
/// </para>
/// <para>
/// Example usage:
/// <code>
/// var manager = new FindingTagManager();
/// manager.Tag("Open RDP Port", "Firewall", "team-infra", "sprint-24");
/// manager.Annotate("Open RDP Port", "Firewall", "Deferred — VPN migration in Q3");
/// var infraFindings = manager.GetByTag("team-infra");
/// var report = manager.GenerateReport();
/// </code>
/// </para>
/// </summary>
public class FindingTagManager
{
    /// <summary>A finding identifier (title + category).</summary>
    public readonly record struct FindingKey(string Title, string Category)
    {
        /// <summary>Create from a Finding instance.</summary>
        public static FindingKey From(Finding f) => new(f.Title, f.Category);
    }

    /// <summary>Metadata attached to a tagged finding.</summary>
    public class TaggedFinding
    {
        /// <summary>The finding title.</summary>
        public string Title { get; init; } = "";

        /// <summary>The finding category/module.</summary>
        public string Category { get; init; } = "";

        /// <summary>All tags assigned to this finding.</summary>
        public HashSet<string> Tags { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Annotations with timestamps — human notes explaining decisions.
        /// </summary>
        public List<Annotation> Annotations { get; init; } = [];

        /// <summary>When this finding was first tagged.</summary>
        public DateTimeOffset FirstTaggedAt { get; init; }

        /// <summary>When tags or annotations were last modified.</summary>
        public DateTimeOffset LastModifiedAt { get; set; }
    }

    /// <summary>A timestamped note attached to a finding.</summary>
    public class Annotation
    {
        /// <summary>The note text.</summary>
        public string Text { get; init; } = "";

        /// <summary>Who wrote the annotation (optional).</summary>
        public string? Author { get; init; }

        /// <summary>When the annotation was created.</summary>
        public DateTimeOffset CreatedAt { get; init; }
    }

    /// <summary>Summary report of tag usage across findings.</summary>
    public class TagReport
    {
        /// <summary>Report generation time.</summary>
        public DateTimeOffset GeneratedAt { get; init; }

        /// <summary>Total findings being tracked.</summary>
        public int TotalFindings { get; init; }

        /// <summary>Total unique tags in use.</summary>
        public int TotalTags { get; init; }

        /// <summary>Total annotations across all findings.</summary>
        public int TotalAnnotations { get; init; }

        /// <summary>Tag → count of findings with that tag.</summary>
        public Dictionary<string, int> TagCounts { get; init; } = new();

        /// <summary>Findings with no tags (orphans).</summary>
        public int UntaggedCount { get; init; }

        /// <summary>Most recently modified findings.</summary>
        public List<TaggedFinding> RecentlyModified { get; init; } = [];
    }

    // ── State ────────────────────────────────────────────────────

    private readonly Dictionary<FindingKey, TaggedFinding> _findings = new();

    /// <summary>All tracked findings.</summary>
    public IReadOnlyDictionary<FindingKey, TaggedFinding> Findings => _findings;

    /// <summary>Number of tracked findings.</summary>
    public int Count => _findings.Count;

    // ── Tag operations ───────────────────────────────────────────

    /// <summary>
    /// Add one or more tags to a finding. Creates the tracking entry if new.
    /// </summary>
    /// <param name="title">Finding title.</param>
    /// <param name="category">Finding category/module.</param>
    /// <param name="tags">Tags to add.</param>
    /// <returns>The updated TaggedFinding.</returns>
    /// <exception cref="ArgumentException">If title is empty or no tags provided.</exception>
    public TaggedFinding Tag(string title, string category, params string[] tags)
    {
        if (string.IsNullOrWhiteSpace(title))
            throw new ArgumentException("Title cannot be empty.", nameof(title));
        if (tags.Length == 0)
            throw new ArgumentException("At least one tag is required.", nameof(tags));

        var key = new FindingKey(title, category);
        var now = DateTimeOffset.UtcNow;

        if (!_findings.TryGetValue(key, out var tracked))
        {
            tracked = new TaggedFinding
            {
                Title = title,
                Category = category,
                FirstTaggedAt = now,
                LastModifiedAt = now,
            };
            _findings[key] = tracked;
        }

        foreach (var tag in tags)
        {
            if (!string.IsNullOrWhiteSpace(tag))
                tracked.Tags.Add(tag.Trim());
        }

        tracked.LastModifiedAt = now;
        return tracked;
    }

    /// <summary>
    /// Tag a Finding instance directly.
    /// </summary>
    public TaggedFinding Tag(Finding finding, params string[] tags)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return Tag(finding.Title, finding.Category, tags);
    }

    /// <summary>
    /// Remove one or more tags from a finding.
    /// </summary>
    /// <returns>True if any tags were actually removed.</returns>
    public bool Untag(string title, string category, params string[] tags)
    {
        var key = new FindingKey(title, category);
        if (!_findings.TryGetValue(key, out var tracked))
            return false;

        bool removed = false;
        foreach (var tag in tags)
        {
            if (tracked.Tags.Remove(tag))
                removed = true;
        }

        if (removed)
            tracked.LastModifiedAt = DateTimeOffset.UtcNow;

        return removed;
    }

    /// <summary>
    /// Remove all tags from a finding (keeps annotations).
    /// </summary>
    public bool ClearTags(string title, string category)
    {
        var key = new FindingKey(title, category);
        if (!_findings.TryGetValue(key, out var tracked) || tracked.Tags.Count == 0)
            return false;

        tracked.Tags.Clear();
        tracked.LastModifiedAt = DateTimeOffset.UtcNow;
        return true;
    }

    /// <summary>
    /// Rename a tag across all findings.
    /// </summary>
    /// <returns>Number of findings affected.</returns>
    public int RenameTag(string oldTag, string newTag)
    {
        if (string.IsNullOrWhiteSpace(oldTag))
            throw new ArgumentException("Old tag cannot be empty.", nameof(oldTag));
        if (string.IsNullOrWhiteSpace(newTag))
            throw new ArgumentException("New tag cannot be empty.", nameof(newTag));

        int count = 0;
        foreach (var tracked in _findings.Values)
        {
            if (tracked.Tags.Remove(oldTag))
            {
                tracked.Tags.Add(newTag.Trim());
                tracked.LastModifiedAt = DateTimeOffset.UtcNow;
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Delete a tag from all findings.
    /// </summary>
    /// <returns>Number of findings affected.</returns>
    public int DeleteTag(string tag)
    {
        int count = 0;
        foreach (var tracked in _findings.Values)
        {
            if (tracked.Tags.Remove(tag))
            {
                tracked.LastModifiedAt = DateTimeOffset.UtcNow;
                count++;
            }
        }

        return count;
    }

    // ── Annotations ──────────────────────────────────────────────

    /// <summary>
    /// Add an annotation (human note) to a finding.
    /// </summary>
    /// <param name="title">Finding title.</param>
    /// <param name="category">Finding category.</param>
    /// <param name="text">Annotation text.</param>
    /// <param name="author">Optional author name.</param>
    /// <returns>The updated TaggedFinding.</returns>
    public TaggedFinding Annotate(string title, string category, string text, string? author = null)
    {
        if (string.IsNullOrWhiteSpace(title))
            throw new ArgumentException("Title cannot be empty.", nameof(title));
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Annotation text cannot be empty.", nameof(text));

        var key = new FindingKey(title, category);
        var now = DateTimeOffset.UtcNow;

        if (!_findings.TryGetValue(key, out var tracked))
        {
            tracked = new TaggedFinding
            {
                Title = title,
                Category = category,
                FirstTaggedAt = now,
                LastModifiedAt = now,
            };
            _findings[key] = tracked;
        }

        tracked.Annotations.Add(new Annotation
        {
            Text = text,
            Author = author,
            CreatedAt = now,
        });

        tracked.LastModifiedAt = now;
        return tracked;
    }

    /// <summary>
    /// Add an annotation to a Finding instance directly.
    /// </summary>
    public TaggedFinding Annotate(Finding finding, string text, string? author = null)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return Annotate(finding.Title, finding.Category, text, author);
    }

    // ── Queries ──────────────────────────────────────────────────

    /// <summary>
    /// Get all findings with a specific tag.
    /// </summary>
    public IReadOnlyList<TaggedFinding> GetByTag(string tag) =>
        _findings.Values
            .Where(f => f.Tags.Contains(tag))
            .OrderByDescending(f => f.LastModifiedAt)
            .ToList();

    /// <summary>
    /// Get findings matching ALL specified tags.
    /// </summary>
    public IReadOnlyList<TaggedFinding> GetByAllTags(params string[] tags) =>
        _findings.Values
            .Where(f => tags.All(t => f.Tags.Contains(t)))
            .OrderByDescending(f => f.LastModifiedAt)
            .ToList();

    /// <summary>
    /// Get findings matching ANY of the specified tags.
    /// </summary>
    public IReadOnlyList<TaggedFinding> GetByAnyTag(params string[] tags) =>
        _findings.Values
            .Where(f => tags.Any(t => f.Tags.Contains(t)))
            .OrderByDescending(f => f.LastModifiedAt)
            .ToList();

    /// <summary>
    /// Get all unique tags currently in use.
    /// </summary>
    public IReadOnlySet<string> GetAllTags() =>
        _findings.Values
            .SelectMany(f => f.Tags)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Get the TaggedFinding for a specific finding.
    /// </summary>
    public TaggedFinding? Get(string title, string category) =>
        _findings.TryGetValue(new FindingKey(title, category), out var f) ? f : null;

    /// <summary>
    /// Get findings with annotations.
    /// </summary>
    public IReadOnlyList<TaggedFinding> GetAnnotated() =>
        _findings.Values
            .Where(f => f.Annotations.Count > 0)
            .OrderByDescending(f => f.LastModifiedAt)
            .ToList();

    /// <summary>
    /// Get findings by category.
    /// </summary>
    public IReadOnlyList<TaggedFinding> GetByCategory(string category) =>
        _findings.Values
            .Where(f => f.Category.Equals(category, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.LastModifiedAt)
            .ToList();

    /// <summary>
    /// Search findings by title substring.
    /// </summary>
    public IReadOnlyList<TaggedFinding> Search(string query) =>
        _findings.Values
            .Where(f => f.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        f.Category.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        f.Tags.Any(t => t.Contains(query, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(f => f.LastModifiedAt)
            .ToList();

    /// <summary>
    /// Remove a finding from tracking entirely.
    /// </summary>
    public bool Remove(string title, string category) =>
        _findings.Remove(new FindingKey(title, category));

    // ── Bulk operations ──────────────────────────────────────────

    /// <summary>
    /// Tag all findings from a security report with a batch tag.
    /// </summary>
    /// <param name="report">The security report.</param>
    /// <param name="tags">Tags to apply to all findings.</param>
    /// <returns>Number of findings tagged.</returns>
    public int TagFromReport(SecurityReport report, params string[] tags)
    {
        ArgumentNullException.ThrowIfNull(report);
        int count = 0;

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                if (finding.Severity == Severity.Pass)
                    continue;
                Tag(finding, tags);
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Auto-tag findings based on severity.
    /// Critical → "urgent", Warning → "review-needed", Info → "low-priority".
    /// </summary>
    public int AutoTagBySeverity(SecurityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        int count = 0;

        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                string? tag = finding.Severity switch
                {
                    Severity.Critical => "urgent",
                    Severity.Warning => "review-needed",
                    Severity.Info => "low-priority",
                    _ => null
                };

                if (tag != null)
                {
                    Tag(finding, tag);
                    count++;
                }
            }
        }

        return count;
    }

    // ── Report ───────────────────────────────────────────────────

    /// <summary>
    /// Generate a summary report of tag usage.
    /// </summary>
    public TagReport GenerateReport()
    {
        var tagCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var f in _findings.Values)
        {
            foreach (var tag in f.Tags)
            {
                tagCounts.TryGetValue(tag, out var count);
                tagCounts[tag] = count + 1;
            }
        }

        return new TagReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            TotalFindings = _findings.Count,
            TotalTags = tagCounts.Count,
            TotalAnnotations = _findings.Values.Sum(f => f.Annotations.Count),
            TagCounts = tagCounts.OrderByDescending(kv => kv.Value)
                .ToDictionary(kv => kv.Key, kv => kv.Value),
            UntaggedCount = _findings.Values.Count(f => f.Tags.Count == 0),
            RecentlyModified = _findings.Values
                .OrderByDescending(f => f.LastModifiedAt)
                .Take(10)
                .ToList(),
        };
    }

    // ── Serialization ────────────────────────────────────────────

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>
    /// Export all tagged findings and annotations to JSON.
    /// </summary>
    public string ExportJson()
    {
        var data = _findings.Values
            .OrderBy(f => f.Category)
            .ThenBy(f => f.Title)
            .ToList();

        return JsonSerializer.Serialize(new
        {
            exportedAt = DateTimeOffset.UtcNow,
            findings = data,
        }, _jsonOptions);
    }

    /// <summary>
    /// Import tagged findings from JSON.
    /// </summary>
    /// <param name="json">JSON string from <see cref="ExportJson"/>.</param>
    /// <param name="merge">If true, merges tags with existing. If false, overwrites.</param>
    /// <returns>Number of findings imported.</returns>
    public int ImportJson(string json, bool merge = true)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!root.TryGetProperty("findings", out var findingsEl))
            throw new ArgumentException("JSON must contain a 'findings' array.");

        int count = 0;
        foreach (var el in findingsEl.EnumerateArray())
        {
            var title = el.GetProperty("Title").GetString() ?? "";
            var category = el.GetProperty("Category").GetString() ?? "";
            var key = new FindingKey(title, category);

            var firstTagged = el.TryGetProperty("FirstTaggedAt", out var ftEl)
                ? ftEl.GetDateTimeOffset()
                : DateTimeOffset.UtcNow;

            var lastMod = el.TryGetProperty("LastModifiedAt", out var lmEl)
                ? lmEl.GetDateTimeOffset()
                : DateTimeOffset.UtcNow;

            if (!_findings.TryGetValue(key, out var tracked) || !merge)
            {
                tracked = new TaggedFinding
                {
                    Title = title,
                    Category = category,
                    FirstTaggedAt = firstTagged,
                    LastModifiedAt = lastMod,
                };
                _findings[key] = tracked;
            }

            // Import tags
            if (el.TryGetProperty("Tags", out var tagsEl))
            {
                foreach (var tagEl in tagsEl.EnumerateArray())
                {
                    var tag = tagEl.GetString();
                    if (!string.IsNullOrWhiteSpace(tag))
                        tracked.Tags.Add(tag);
                }
            }

            // Import annotations
            if (el.TryGetProperty("Annotations", out var annsEl))
            {
                foreach (var annEl in annsEl.EnumerateArray())
                {
                    var text = annEl.GetProperty("Text").GetString() ?? "";
                    var author = annEl.TryGetProperty("Author", out var authEl)
                        ? authEl.GetString()
                        : null;
                    var created = annEl.TryGetProperty("CreatedAt", out var crEl)
                        ? crEl.GetDateTimeOffset()
                        : DateTimeOffset.UtcNow;

                    // Avoid duplicate annotations on merge
                    if (!merge || !tracked.Annotations.Any(a =>
                        a.Text == text && a.CreatedAt == created))
                    {
                        tracked.Annotations.Add(new Annotation
                        {
                            Text = text,
                            Author = author,
                            CreatedAt = created,
                        });
                    }
                }
            }

            tracked.LastModifiedAt = lastMod > tracked.LastModifiedAt
                ? lastMod : tracked.LastModifiedAt;

            count++;
        }

        return count;
    }
}
