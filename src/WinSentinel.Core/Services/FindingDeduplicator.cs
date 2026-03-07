using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Result of a single duplicate comparison between two findings.
/// </summary>
public record DuplicateMatch(
    Finding Original,
    Finding Duplicate,
    double Similarity,
    string MatchReason);

/// <summary>
/// A group of findings that are near-duplicates of each other.
/// The <see cref="Representative"/> is the finding kept after deduplication
/// (the one with highest severity, or first encountered on a tie).
/// </summary>
public record DuplicateGroup(
    Finding Representative,
    IReadOnlyList<Finding> Duplicates,
    double AverageSimilarity,
    string MatchReason);

/// <summary>
/// Summary statistics from a deduplication run.
/// </summary>
public record DeduplicationResult(
    IReadOnlyList<Finding> Deduplicated,
    IReadOnlyList<DuplicateGroup> Groups,
    int OriginalCount,
    int DeduplicatedCount,
    int DuplicatesRemoved,
    double ReductionPercent);

/// <summary>
/// Cross-module finding deduplication service.
///
/// Identifies near-duplicate findings across audit modules using a
/// multi-signal similarity score: exact title match, n-gram title
/// overlap, description similarity, category + severity match, and
/// fix-command equivalence.  Findings above a configurable similarity
/// threshold are grouped, and only the highest-severity representative
/// is kept.
///
/// This reduces report noise when multiple audit modules flag the same
/// underlying issue (e.g., two modules reporting the same registry key
/// or the same disabled security feature).
/// </summary>
public class FindingDeduplicator
{
    private readonly double _threshold;
    private readonly int _ngramSize;

    /// <summary>
    /// Initialise with a similarity threshold (0.0–1.0) and n-gram size.
    /// Findings with similarity ≥ <paramref name="threshold"/> are considered duplicates.
    /// </summary>
    /// <param name="threshold">Minimum similarity to count as duplicate (default 0.65).</param>
    /// <param name="ngramSize">Character n-gram size for fuzzy matching (default 3).</param>
    public FindingDeduplicator(double threshold = 0.65, int ngramSize = 3)
    {
        if (threshold < 0.0 || threshold > 1.0)
            throw new ArgumentOutOfRangeException(nameof(threshold), "Threshold must be between 0.0 and 1.0");
        if (ngramSize < 2 || ngramSize > 10)
            throw new ArgumentOutOfRangeException(nameof(ngramSize), "N-gram size must be between 2 and 10");

        _threshold = threshold;
        _ngramSize = ngramSize;
    }

    /// <summary>
    /// Deduplicate a flat list of findings.
    /// </summary>
    public DeduplicationResult Deduplicate(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count <= 1)
        {
            return new DeduplicationResult(
                Deduplicated: findings.ToList(),
                Groups: Array.Empty<DuplicateGroup>(),
                OriginalCount: findings.Count,
                DeduplicatedCount: findings.Count,
                DuplicatesRemoved: 0,
                ReductionPercent: 0.0);
        }

        // Pre-compute normalised strings and n-gram sets so each finding
        // is processed once (O(n)) instead of being re-normalised and
        // re-tokenised on every pairwise comparison (O(n²)).
        var cachedTitles = new string[findings.Count];
        var cachedDescs = new string[findings.Count];
        var cachedFixes = new string[findings.Count];
        var cachedTitleNgrams = new HashSet<string>[findings.Count];
        var cachedDescNgrams = new HashSet<string>[findings.Count];
        var cachedFixNgrams = new HashSet<string>[findings.Count];

        for (int i = 0; i < findings.Count; i++)
        {
            cachedTitles[i] = Normalize(findings[i].Title);
            cachedDescs[i] = Normalize(findings[i].Description);
            cachedFixes[i] = Normalize(findings[i].FixCommand);
            cachedTitleNgrams[i] = ExtractNgrams(cachedTitles[i]);
            cachedDescNgrams[i] = string.IsNullOrEmpty(cachedDescs[i])
                ? null! : ExtractNgrams(cachedDescs[i]);
            cachedFixNgrams[i] = string.IsNullOrEmpty(cachedFixes[i])
                ? null! : ExtractNgrams(cachedFixes[i]);
        }

        // Union-Find to group duplicates
        var parent = Enumerable.Range(0, findings.Count).ToArray();
        var matchReasons = new Dictionary<(int, int), string>();

        int Find(int x)
        {
            while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
            return x;
        }
        void Union(int a, int b) { parent[Find(a)] = Find(b); }

        // Pairwise comparison using cached data
        for (int i = 0; i < findings.Count; i++)
        {
            for (int j = i + 1; j < findings.Count; j++)
            {
                var (sim, reason) = ComputeSimilarityCached(
                    findings[i], findings[j],
                    cachedTitles[i], cachedTitles[j],
                    cachedTitleNgrams[i], cachedTitleNgrams[j],
                    cachedDescs[i], cachedDescs[j],
                    cachedDescNgrams[i], cachedDescNgrams[j],
                    cachedFixes[i], cachedFixes[j],
                    cachedFixNgrams[i], cachedFixNgrams[j]);
                if (sim >= _threshold)
                {
                    Union(i, j);
                    matchReasons[(i, j)] = reason;
                }
            }
        }

        // Build groups
        var groupMap = new Dictionary<int, List<int>>();
        for (int i = 0; i < findings.Count; i++)
        {
            int root = Find(i);
            if (!groupMap.TryGetValue(root, out var list))
            {
                list = new List<int>();
                groupMap[root] = list;
            }
            list.Add(i);
        }

        var deduplicated = new List<Finding>();
        var groups = new List<DuplicateGroup>();

        foreach (var (_, members) in groupMap)
        {
            // Pick representative: highest severity, then first encountered
            var sorted = members
                .OrderByDescending(idx => (int)findings[idx].Severity)
                .ToList();
            var repIdx = sorted[0];
            var rep = findings[repIdx];
            deduplicated.Add(rep);

            if (members.Count > 1)
            {
                var dups = sorted.Skip(1).Select(idx => findings[idx]).ToList();

                // Compute average similarity among group members
                double totalSim = 0;
                int comparisons = 0;
                string groupReason = "mixed";
                foreach (var m1 in members)
                {
                    foreach (var m2 in members)
                    {
                        if (m1 >= m2) continue;
                        var (s, r) = ComputeSimilarity(findings[m1], findings[m2]);
                        totalSim += s;
                        comparisons++;
                        groupReason = r; // last reason wins for simplicity
                    }
                }
                double avgSim = comparisons > 0 ? totalSim / comparisons : 1.0;

                groups.Add(new DuplicateGroup(rep, dups, Math.Round(avgSim, 4), groupReason));
            }
        }

        int removed = findings.Count - deduplicated.Count;
        double reduction = findings.Count > 0
            ? Math.Round(100.0 * removed / findings.Count, 2)
            : 0.0;

        return new DeduplicationResult(
            Deduplicated: deduplicated,
            Groups: groups,
            OriginalCount: findings.Count,
            DeduplicatedCount: deduplicated.Count,
            DuplicatesRemoved: removed,
            ReductionPercent: reduction);
    }

    /// <summary>
    /// Deduplicate findings from multiple <see cref="AuditResult"/>s (cross-module).
    /// Non-finding fields (Pass results, empty modules) are preserved.
    /// </summary>
    public DeduplicationResult DeduplicateAcrossModules(IReadOnlyList<AuditResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        var allFindings = results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity != Severity.Pass) // Don't deduplicate Pass findings
            .ToList();
        return Deduplicate(allFindings);
    }

    /// <summary>
    /// Compute similarity between two findings on multiple signals.
    /// Returns a score in [0, 1] and a human-readable reason.
    /// </summary>
    public (double Score, string Reason) ComputeSimilarity(Finding a, Finding b)
    {
        double score = 0.0;
        var reasons = new List<string>();

        // 1. Exact title match (weight: 0.50)
        string normA = Normalize(a.Title);
        string normB = Normalize(b.Title);
        if (normA == normB)
        {
            score += 0.50;
            reasons.Add("exact title");
        }
        else
        {
            // Fuzzy title match via character n-grams
            double titleSim = NgramSimilarity(normA, normB);
            double titleContribution = 0.50 * titleSim;
            score += titleContribution;
            if (titleSim > 0.5) reasons.Add($"title ~{titleSim * 100:F0}%");
        }

        // 2. Description similarity (weight: 0.15)
        if (!string.IsNullOrEmpty(a.Description) && !string.IsNullOrEmpty(b.Description))
        {
            double descSim = NgramSimilarity(
                Normalize(a.Description),
                Normalize(b.Description));
            score += 0.15 * descSim;
            if (descSim > 0.5) reasons.Add($"desc ~{descSim * 100:F0}%");
        }

        // 3. Same category (weight: 0.15)
        if (!string.IsNullOrEmpty(a.Category) && !string.IsNullOrEmpty(b.Category)
            && string.Equals(a.Category, b.Category, StringComparison.OrdinalIgnoreCase))
        {
            score += 0.15;
            reasons.Add("same category");
        }

        // 4. Same severity (weight: 0.05)
        if (a.Severity == b.Severity)
        {
            score += 0.05;
        }

        // 5. Fix command equivalence (weight: 0.15)
        if (!string.IsNullOrEmpty(a.FixCommand) && !string.IsNullOrEmpty(b.FixCommand))
        {
            string fixA = Normalize(a.FixCommand);
            string fixB = Normalize(b.FixCommand);
            if (fixA == fixB)
            {
                score += 0.15;
                reasons.Add("same fix");
            }
            else
            {
                double fixSim = NgramSimilarity(fixA, fixB);
                score += 0.15 * fixSim;
                if (fixSim > 0.5) reasons.Add($"fix ~{fixSim * 100:F0}%");
            }
        }

        string reason = reasons.Count > 0 ? string.Join(", ", reasons) : "low similarity";
        return (Math.Min(score, 1.0), reason);
    }

    /// <summary>
    /// Compute character n-gram Jaccard similarity between two strings.
    /// Returns a value in [0, 1].
    /// </summary>
    /// <summary>
    /// Compute similarity using pre-computed normalised strings and n-gram
    /// sets.  This avoids redundant Normalize() and ExtractNgrams() calls
    /// during the O(n²) pairwise comparison in Deduplicate().
    /// </summary>
    private (double Score, string Reason) ComputeSimilarityCached(
        Finding a, Finding b,
        string normTitleA, string normTitleB,
        HashSet<string> titleNgramsA, HashSet<string> titleNgramsB,
        string normDescA, string normDescB,
        HashSet<string>? descNgramsA, HashSet<string>? descNgramsB,
        string normFixA, string normFixB,
        HashSet<string>? fixNgramsA, HashSet<string>? fixNgramsB)
    {
        double score = 0.0;
        var reasons = new List<string>();

        // 1. Title match (weight: 0.50)
        if (normTitleA == normTitleB)
        {
            score += 0.50;
            reasons.Add("exact title");
        }
        else
        {
            double titleSim = NgramSimilarityFromSets(titleNgramsA, titleNgramsB);
            score += 0.50 * titleSim;
            if (titleSim > 0.5) reasons.Add($"title ~{titleSim * 100:F0}%");
        }

        // 2. Description similarity (weight: 0.15)
        if (descNgramsA != null && descNgramsB != null)
        {
            double descSim = normDescA == normDescB
                ? 1.0
                : NgramSimilarityFromSets(descNgramsA, descNgramsB);
            score += 0.15 * descSim;
            if (descSim > 0.5) reasons.Add($"desc ~{descSim * 100:F0}%");
        }

        // 3. Same category (weight: 0.15)
        if (!string.IsNullOrEmpty(a.Category) && !string.IsNullOrEmpty(b.Category)
            && string.Equals(a.Category, b.Category, StringComparison.OrdinalIgnoreCase))
        {
            score += 0.15;
            reasons.Add("same category");
        }

        // 4. Same severity (weight: 0.05)
        if (a.Severity == b.Severity)
        {
            score += 0.05;
        }

        // 5. Fix command equivalence (weight: 0.15)
        if (fixNgramsA != null && fixNgramsB != null)
        {
            if (normFixA == normFixB)
            {
                score += 0.15;
                reasons.Add("same fix");
            }
            else
            {
                double fixSim = NgramSimilarityFromSets(fixNgramsA, fixNgramsB);
                score += 0.15 * fixSim;
                if (fixSim > 0.5) reasons.Add($"fix ~{fixSim * 100:F0}%");
            }
        }

        string reason = reasons.Count > 0 ? string.Join(", ", reasons) : "low similarity";
        return (Math.Min(score, 1.0), reason);
    }

    /// <summary>
    /// Compute Jaccard similarity from pre-computed n-gram sets.
    /// </summary>
    private static double NgramSimilarityFromSets(HashSet<string> ngramsA, HashSet<string> ngramsB)
    {
        if (ngramsA.Count == 0 || ngramsB.Count == 0) return 0.0;

        int intersection = 0;
        // Iterate over the smaller set for efficiency
        var smaller = ngramsA.Count <= ngramsB.Count ? ngramsA : ngramsB;
        var larger = ngramsA.Count <= ngramsB.Count ? ngramsB : ngramsA;
        foreach (var ng in smaller)
        {
            if (larger.Contains(ng)) intersection++;
        }

        int union = ngramsA.Count + ngramsB.Count - intersection;
        return union > 0 ? (double)intersection / union : 0.0;
    }

    public double NgramSimilarity(string a, string b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return 0.0;
        if (a == b) return 1.0;

        var ngramsA = ExtractNgrams(a);
        var ngramsB = ExtractNgrams(b);

        if (ngramsA.Count == 0 || ngramsB.Count == 0) return 0.0;

        int intersection = 0;
        foreach (var ng in ngramsA)
        {
            if (ngramsB.Contains(ng)) intersection++;
        }

        int union = ngramsA.Count + ngramsB.Count - intersection;
        return union > 0 ? (double)intersection / union : 0.0;
    }

    private HashSet<string> ExtractNgrams(string text)
    {
        var ngrams = new HashSet<string>();
        for (int i = 0; i <= text.Length - _ngramSize; i++)
        {
            ngrams.Add(text.Substring(i, _ngramSize));
        }
        return ngrams;
    }

    private static string Normalize(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        return text.Trim().ToLowerInvariant();
    }
}
