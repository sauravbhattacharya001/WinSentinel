using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Searches audit findings by keyword with filtering and relevance scoring.
/// </summary>
public class FindingSearchService
{
    /// <summary>
    /// Search across all findings in a security report.
    /// </summary>
    public SearchResult Search(SecurityReport report, SearchOptions options)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.Query))
            return new SearchResult { Query = options.Query ?? "", Matches = new List<SearchMatch>() };

        var query = options.Query.Trim();
        var queryLower = query.ToLowerInvariant();
        var queryWords = queryLower.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var matches = new List<SearchMatch>();

        foreach (var auditResult in report.Results)
        {
            foreach (var finding in auditResult.Findings)
            {
                // Apply severity filter
                if (options.SeverityFilter != null &&
                    !finding.Severity.ToString().Equals(options.SeverityFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                // Apply module filter
                if (!string.IsNullOrEmpty(options.ModuleFilter) &&
                    !auditResult.Category.Contains(options.ModuleFilter, StringComparison.OrdinalIgnoreCase) &&
                    !(finding.Category ?? "").Contains(options.ModuleFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                var score = CalculateRelevance(finding, auditResult.Category, queryWords, queryLower);

                if (score > 0)
                {
                    var matchFields = GetMatchFields(finding, auditResult.Category, queryLower);
                    matches.Add(new SearchMatch
                    {
                        Finding = finding,
                        ModuleCategory = auditResult.Category,
                        RelevanceScore = score,
                        MatchedFields = matchFields
                    });
                }
            }
        }

        // Sort by relevance (highest first), then severity
        var sorted = matches
            .OrderByDescending(m => m.RelevanceScore)
            .ThenByDescending(m => SeverityRank(m.Finding.Severity))
            .Take(options.Limit)
            .ToList();

        return new SearchResult
        {
            Query = query,
            TotalFindings = report.TotalFindings,
            Matches = sorted,
            SeverityFilter = options.SeverityFilter,
            ModuleFilter = options.ModuleFilter,
            SeverityBreakdown = sorted
                .GroupBy(m => m.Finding.Severity)
                .ToDictionary(g => g.Key.ToString(), g => g.Count()),
            ModuleBreakdown = sorted
                .GroupBy(m => m.ModuleCategory)
                .ToDictionary(g => g.Key, g => g.Count())
        };
    }

    private static int CalculateRelevance(Finding finding, string category, string[] queryWords, string queryLower)
    {
        int score = 0;
        var titleLower = (finding.Title ?? "").ToLowerInvariant();
        var descLower = (finding.Description ?? "").ToLowerInvariant();
        var remLower = (finding.Remediation ?? "").ToLowerInvariant();
        var catLower = category.ToLowerInvariant();
        var moduleLower = (finding.Category ?? "").ToLowerInvariant();

        // Exact phrase match in title = highest relevance
        if (titleLower.Contains(queryLower))
            score += 100;

        // Exact phrase match in description
        if (descLower.Contains(queryLower))
            score += 50;

        // Exact phrase match in remediation
        if (remLower.Contains(queryLower))
            score += 20;

        // Exact phrase match in category/module
        if (catLower.Contains(queryLower) || moduleLower.Contains(queryLower))
            score += 30;

        // Individual word matches (for multi-word queries)
        if (queryWords.Length > 1)
        {
            foreach (var word in queryWords)
            {
                if (word.Length < 2) continue;
                if (titleLower.Contains(word)) score += 15;
                if (descLower.Contains(word)) score += 8;
                if (remLower.Contains(word)) score += 3;
                if (catLower.Contains(word) || moduleLower.Contains(word)) score += 5;
            }
        }

        // Severity boost: critical findings rank higher
        if (score > 0)
        {
            score += SeverityRank(finding.Severity) * 2;
        }

        return score;
    }

    private static List<string> GetMatchFields(Finding finding, string category, string queryLower)
    {
        var fields = new List<string>();
        if ((finding.Title ?? "").Contains(queryLower, StringComparison.OrdinalIgnoreCase))
            fields.Add("title");
        if ((finding.Description ?? "").Contains(queryLower, StringComparison.OrdinalIgnoreCase))
            fields.Add("description");
        if ((finding.Remediation ?? "").Contains(queryLower, StringComparison.OrdinalIgnoreCase))
            fields.Add("remediation");
        if (category.Contains(queryLower, StringComparison.OrdinalIgnoreCase) ||
            (finding.Category ?? "").Contains(queryLower, StringComparison.OrdinalIgnoreCase))
            fields.Add("module");

        // If no exact phrase matches, note it's a partial/word match
        if (fields.Count == 0)
            fields.Add("partial");

        return fields;
    }

    private static int SeverityRank(Severity severity) => severity switch
    {
        Severity.Critical => 4,
        Severity.Warning => 3,
        Severity.Info => 2,
        Severity.Pass => 1,
        _ => 0
    };

    /// <summary>
    /// Highlight query matches in text for console display.
    /// Returns segments with isMatch flags for the caller to colorize.
    /// </summary>
    public static List<(string text, bool isMatch)> HighlightMatches(string text, string query)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(query))
            return new List<(string, bool)> { (text ?? "", false) };

        var segments = new List<(string text, bool isMatch)>();
        var idx = 0;
        var textLower = text.ToLowerInvariant();
        var queryLower = query.ToLowerInvariant();

        while (idx < text.Length)
        {
            var matchIdx = textLower.IndexOf(queryLower, idx, StringComparison.Ordinal);
            if (matchIdx < 0)
            {
                segments.Add((text[idx..], false));
                break;
            }

            if (matchIdx > idx)
                segments.Add((text[idx..matchIdx], false));

            segments.Add((text[matchIdx..(matchIdx + query.Length)], true));
            idx = matchIdx + query.Length;
        }

        return segments;
    }
}

/// <summary>Options for finding search.</summary>
public class SearchOptions
{
    public string Query { get; set; } = "";
    public string? SeverityFilter { get; set; }
    public string? ModuleFilter { get; set; }
    public int Limit { get; set; } = 50;
}

/// <summary>A single search match with relevance info.</summary>
public class SearchMatch
{
    public Finding Finding { get; set; } = null!;
    public string ModuleCategory { get; set; } = "";
    public int RelevanceScore { get; set; }
    public List<string> MatchedFields { get; set; } = new();
}

/// <summary>Search results with metadata.</summary>
public class SearchResult
{
    public string Query { get; set; } = "";
    public int TotalFindings { get; set; }
    public List<SearchMatch> Matches { get; set; } = new();
    public string? SeverityFilter { get; set; }
    public string? ModuleFilter { get; set; }
    public Dictionary<string, int> SeverityBreakdown { get; set; } = new();
    public Dictionary<string, int> ModuleBreakdown { get; set; } = new();
}
