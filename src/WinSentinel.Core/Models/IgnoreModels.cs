using System.Text.Json.Serialization;

namespace WinSentinel.Core.Models;

/// <summary>
/// How the ignore rule matches finding titles.
/// </summary>
public enum IgnoreMatchMode
{
    /// <summary>Exact title match (case-insensitive).</summary>
    Exact,
    /// <summary>Title contains the pattern (case-insensitive).</summary>
    Contains,
    /// <summary>Title matches a regular expression pattern.</summary>
    Regex
}

/// <summary>
/// A rule that suppresses specific findings from audit results.
/// Ignored findings don't affect the security score and are hidden by default.
/// </summary>
public class IgnoreRule
{
    /// <summary>Unique identifier for this rule.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];

    /// <summary>The pattern to match finding titles against.</summary>
    public string Pattern { get; set; } = "";

    /// <summary>How the pattern matches finding titles.</summary>
    public IgnoreMatchMode MatchMode { get; set; } = IgnoreMatchMode.Contains;

    /// <summary>Optional: only match findings from this module/category (case-insensitive).</summary>
    public string? Module { get; set; }

    /// <summary>Optional: only match findings with this severity.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity? Severity { get; set; }

    /// <summary>Human-readable reason for ignoring this finding.</summary>
    public string? Reason { get; set; }

    /// <summary>When the rule was created.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Optional expiration date. Rule is inactive after this date.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>Whether the rule is currently enabled.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Check if this rule has expired.
    /// </summary>
    public bool IsExpired => ExpiresAt.HasValue && DateTimeOffset.UtcNow > ExpiresAt.Value;

    /// <summary>
    /// Check if this rule is currently active (enabled and not expired).
    /// </summary>
    public bool IsActive => Enabled && !IsExpired;
}

/// <summary>
/// Result of applying ignore rules to audit findings.
/// </summary>
public class IgnoreFilterResult
{
    /// <summary>Findings that passed through (not ignored).</summary>
    public List<Finding> ActiveFindings { get; set; } = [];

    /// <summary>Findings that were suppressed by ignore rules.</summary>
    public List<IgnoredFinding> IgnoredFindings { get; set; } = [];

    /// <summary>Total findings before filtering.</summary>
    public int TotalFindings => ActiveFindings.Count + IgnoredFindings.Count;

    /// <summary>Number of findings suppressed.</summary>
    public int SuppressedCount => IgnoredFindings.Count;
}

/// <summary>
/// A finding that was suppressed by an ignore rule, with the rule that matched it.
/// </summary>
public class IgnoredFinding
{
    /// <summary>The suppressed finding.</summary>
    public required Finding Finding { get; set; }

    /// <summary>The rule that caused it to be suppressed.</summary>
    public required IgnoreRule MatchedRule { get; set; }
}
