using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Service for managing ignore/suppress rules that filter out specific findings
/// from audit results. Rules are stored as a JSON file in %LocalAppData%/WinSentinel/ignore-rules.json.
/// </summary>
public class IgnoreRuleService
{
    private readonly string _rulesFilePath;
    private List<IgnoreRule>? _cachedRules;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Create an IgnoreRuleService using the default rules file path.
    /// </summary>
    public IgnoreRuleService()
        : this(GetDefaultRulesPath())
    {
    }

    /// <summary>
    /// Create an IgnoreRuleService with a custom rules file path (useful for testing).
    /// </summary>
    public IgnoreRuleService(string rulesFilePath)
    {
        _rulesFilePath = rulesFilePath;
        var dir = Path.GetDirectoryName(rulesFilePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
    }

    /// <summary>
    /// Get the default rules file path.
    /// </summary>
    public static string GetDefaultRulesPath()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(localAppData, "WinSentinel", "ignore-rules.json");
    }

    // ── CRUD Operations ──────────────────────────────────────────────────

    /// <summary>
    /// Add a new ignore rule.
    /// </summary>
    /// <returns>The created rule with its generated ID.</returns>
    /// <exception cref="ArgumentException">If the pattern is empty or the regex is invalid.</exception>
    public IgnoreRule AddRule(string pattern, IgnoreMatchMode matchMode = IgnoreMatchMode.Contains,
        string? module = null, Severity? severity = null, string? reason = null,
        DateTimeOffset? expiresAt = null)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            throw new ArgumentException("Pattern cannot be empty.", nameof(pattern));

        // Validate regex patterns
        if (matchMode == IgnoreMatchMode.Regex)
        {
            try
            {
                _ = new Regex(pattern, RegexOptions.IgnoreCase);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException($"Invalid regex pattern: {ex.Message}", nameof(pattern));
            }
        }

        var rule = new IgnoreRule
        {
            Pattern = pattern,
            MatchMode = matchMode,
            Module = module,
            Severity = severity,
            Reason = reason,
            ExpiresAt = expiresAt,
            CreatedAt = DateTimeOffset.UtcNow,
            Enabled = true
        };

        var rules = LoadRules();
        rules.Add(rule);
        SaveRules(rules);

        return rule;
    }

    /// <summary>
    /// Get all rules (both active and inactive).
    /// </summary>
    public List<IgnoreRule> GetAllRules()
    {
        return LoadRules();
    }

    /// <summary>
    /// Get only active rules (enabled and not expired).
    /// </summary>
    public List<IgnoreRule> GetActiveRules()
    {
        return LoadRules().Where(r => r.IsActive).ToList();
    }

    /// <summary>
    /// Get a specific rule by ID.
    /// </summary>
    public IgnoreRule? GetRule(string id)
    {
        return LoadRules().FirstOrDefault(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Remove a rule by ID.
    /// </summary>
    /// <returns>True if the rule was found and removed.</returns>
    public bool RemoveRule(string id)
    {
        var rules = LoadRules();
        var removed = rules.RemoveAll(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (removed > 0)
        {
            SaveRules(rules);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Enable or disable a rule by ID.
    /// </summary>
    /// <returns>True if the rule was found and updated.</returns>
    public bool ToggleRule(string id, bool enabled)
    {
        var rules = LoadRules();
        var rule = rules.FirstOrDefault(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (rule == null) return false;

        rule.Enabled = enabled;
        SaveRules(rules);
        return true;
    }

    /// <summary>
    /// Remove all rules.
    /// </summary>
    /// <returns>Number of rules removed.</returns>
    public int ClearAllRules()
    {
        var rules = LoadRules();
        var count = rules.Count;
        rules.Clear();
        SaveRules(rules);
        return count;
    }

    /// <summary>
    /// Remove expired rules.
    /// </summary>
    /// <returns>Number of expired rules removed.</returns>
    public int PurgeExpiredRules()
    {
        var rules = LoadRules();
        var removed = rules.RemoveAll(r => r.IsExpired);
        if (removed > 0)
        {
            SaveRules(rules);
        }
        return removed;
    }

    // ── Filtering ──────────────────────────────────────────────────────

    /// <summary>
    /// Apply ignore rules to a list of findings, separating them into active and ignored.
    /// </summary>
    public IgnoreFilterResult ApplyRules(List<Finding> findings)
    {
        var activeRules = GetActiveRules();
        var result = new IgnoreFilterResult();

        foreach (var finding in findings)
        {
            var matchedRule = FindMatchingRule(finding, activeRules);
            if (matchedRule != null)
            {
                result.IgnoredFindings.Add(new IgnoredFinding
                {
                    Finding = finding,
                    MatchedRule = matchedRule
                });
            }
            else
            {
                result.ActiveFindings.Add(finding);
            }
        }

        return result;
    }

    /// <summary>
    /// Apply ignore rules to a SecurityReport, returning a new report with ignored findings removed.
    /// Optionally returns the ignored findings via the out parameter.
    /// </summary>
    public SecurityReport ApplyRulesToReport(SecurityReport report, out List<IgnoredFinding> ignoredFindings)
    {
        var activeRules = GetActiveRules();
        ignoredFindings = new List<IgnoredFinding>();

        if (activeRules.Count == 0)
        {
            return report;
        }

        var filteredResults = new List<AuditResult>();

        foreach (var auditResult in report.Results)
        {
            var filteredFindings = new List<Finding>();

            foreach (var finding in auditResult.Findings)
            {
                var matchedRule = FindMatchingRule(finding, activeRules, auditResult.Category);
                if (matchedRule != null)
                {
                    ignoredFindings.Add(new IgnoredFinding
                    {
                        Finding = finding,
                        MatchedRule = matchedRule
                    });
                }
                else
                {
                    filteredFindings.Add(finding);
                }
            }

            // Create a new AuditResult with the filtered findings
            filteredResults.Add(new AuditResult
            {
                ModuleName = auditResult.ModuleName,
                Category = auditResult.Category,
                Findings = filteredFindings,
                StartTime = auditResult.StartTime,
                EndTime = auditResult.EndTime,
                Success = auditResult.Success,
                Error = auditResult.Error
            });
        }

        // Recalculate the security score with filtered findings
        var filteredReport = new SecurityReport
        {
            Results = filteredResults,
            GeneratedAt = report.GeneratedAt
        };
        filteredReport.SecurityScore = SecurityScorer.CalculateScore(filteredReport);

        return filteredReport;
    }

    /// <summary>
    /// Check if a specific finding would be ignored by any active rule.
    /// </summary>
    public bool IsIgnored(Finding finding, string? moduleCategory = null)
    {
        var activeRules = GetActiveRules();
        return FindMatchingRule(finding, activeRules, moduleCategory) != null;
    }

    /// <summary>
    /// Get statistics about how many findings each rule would match in a report.
    /// </summary>
    public Dictionary<string, int> GetRuleMatchCounts(SecurityReport report)
    {
        var rules = GetAllRules();
        var counts = new Dictionary<string, int>();

        foreach (var rule in rules)
        {
            int count = 0;
            foreach (var auditResult in report.Results)
            {
                foreach (var finding in auditResult.Findings)
                {
                    if (MatchesFinding(rule, finding, auditResult.Category))
                    {
                        count++;
                    }
                }
            }
            counts[rule.Id] = count;
        }

        return counts;
    }

    // ── Private Helpers ──────────────────────────────────────────────────

    private IgnoreRule? FindMatchingRule(Finding finding, List<IgnoreRule> rules, string? moduleCategory = null)
    {
        foreach (var rule in rules)
        {
            if (MatchesFinding(rule, finding, moduleCategory))
            {
                return rule;
            }
        }
        return null;
    }

    /// <summary>
    /// Check if a rule matches a specific finding.
    /// </summary>
    public bool MatchesFinding(IgnoreRule rule, Finding finding, string? moduleCategory = null)
    {
        // Check severity filter
        if (rule.Severity.HasValue && finding.Severity != rule.Severity.Value)
        {
            return false;
        }

        // Check module filter
        if (!string.IsNullOrEmpty(rule.Module))
        {
            var category = moduleCategory ?? finding.Category;
            if (!category.Contains(rule.Module, StringComparison.OrdinalIgnoreCase) &&
                !rule.Module.Equals(category, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // Check pattern match
        return rule.MatchMode switch
        {
            IgnoreMatchMode.Exact => finding.Title.Equals(rule.Pattern, StringComparison.OrdinalIgnoreCase),
            IgnoreMatchMode.Contains => finding.Title.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase),
            IgnoreMatchMode.Regex => IsRegexMatch(rule.Pattern, finding.Title),
            _ => false
        };
    }

    private static bool IsRegexMatch(string pattern, string input)
    {
        try
        {
            return Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        }
        catch
        {
            return false;
        }
    }

    private List<IgnoreRule> LoadRules()
    {
        if (_cachedRules != null)
            return _cachedRules;

        if (!File.Exists(_rulesFilePath))
        {
            _cachedRules = new List<IgnoreRule>();
            return _cachedRules;
        }

        try
        {
            var json = File.ReadAllText(_rulesFilePath);
            _cachedRules = JsonSerializer.Deserialize<List<IgnoreRule>>(json, JsonOptions) ?? new List<IgnoreRule>();
            return _cachedRules;
        }
        catch
        {
            _cachedRules = new List<IgnoreRule>();
            return _cachedRules;
        }
    }

    private void SaveRules(List<IgnoreRule> rules)
    {
        _cachedRules = rules;
        var json = JsonSerializer.Serialize(rules, JsonOptions);
        File.WriteAllText(_rulesFilePath, json);
    }
}
