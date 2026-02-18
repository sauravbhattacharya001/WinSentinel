using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Service for saving, loading, and checking security baselines.
/// Baselines are stored as JSON files in %LocalAppData%/WinSentinel/baselines/.
/// </summary>
public class BaselineService
{
    private readonly string _baselineDir;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Create a BaselineService using the default baselines directory.
    /// </summary>
    public BaselineService()
        : this(GetDefaultBaselineDir())
    {
    }

    /// <summary>
    /// Create a BaselineService with a custom baselines directory (useful for testing).
    /// </summary>
    public BaselineService(string baselineDir)
    {
        _baselineDir = baselineDir;
        Directory.CreateDirectory(_baselineDir);
    }

    /// <summary>
    /// Get the default baselines directory path.
    /// </summary>
    public static string GetDefaultBaselineDir()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(localAppData, "WinSentinel", "baselines");
    }

    /// <summary>
    /// Save a security report as a named baseline snapshot.
    /// </summary>
    /// <param name="name">Baseline name (alphanumeric, hyphens, underscores).</param>
    /// <param name="report">The security report to snapshot.</param>
    /// <param name="description">Optional description.</param>
    /// <param name="overwrite">If true, overwrite existing baseline with same name.</param>
    /// <returns>The saved baseline.</returns>
    public SecurityBaseline SaveBaseline(string name, SecurityReport report, string? description = null, bool overwrite = false)
    {
        ValidateName(name);

        var filePath = GetBaselinePath(name);
        if (File.Exists(filePath) && !overwrite)
        {
            throw new InvalidOperationException(
                $"Baseline '{name}' already exists. Use --force to overwrite.");
        }

        var baseline = new SecurityBaseline
        {
            Name = name,
            Description = description,
            CreatedAt = DateTimeOffset.UtcNow,
            MachineName = Environment.MachineName,
            OverallScore = report.SecurityScore,
            Grade = SecurityScorer.GetGrade(report.SecurityScore),
            TotalFindings = report.TotalFindings,
            CriticalCount = report.TotalCritical,
            WarningCount = report.TotalWarnings,
            InfoCount = report.TotalInfo,
            PassCount = report.TotalPass
        };

        // Snapshot module scores
        foreach (var result in report.Results)
        {
            baseline.ModuleScores.Add(new BaselineModuleScore
            {
                ModuleName = result.ModuleName,
                Category = result.Category,
                Score = result.Score,
                FindingCount = result.Findings.Count,
                CriticalCount = result.CriticalCount,
                WarningCount = result.WarningCount
            });
        }

        // Snapshot findings
        foreach (var result in report.Results)
        {
            foreach (var finding in result.Findings)
            {
                baseline.Findings.Add(new BaselineFinding
                {
                    ModuleName = result.ModuleName,
                    Title = finding.Title,
                    Severity = finding.Severity.ToString(),
                    Description = finding.Description,
                    Remediation = finding.Remediation
                });
            }
        }

        var json = JsonSerializer.Serialize(baseline, JsonOptions);
        File.WriteAllText(filePath, json);

        return baseline;
    }

    /// <summary>
    /// Load a named baseline.
    /// </summary>
    public SecurityBaseline? LoadBaseline(string name)
    {
        ValidateName(name);

        var filePath = GetBaselinePath(name);
        if (!File.Exists(filePath)) return null;

        var json = File.ReadAllText(filePath);
        return JsonSerializer.Deserialize<SecurityBaseline>(json, JsonOptions);
    }

    /// <summary>
    /// List all saved baselines (summaries only).
    /// </summary>
    public List<BaselineSummary> ListBaselines()
    {
        var summaries = new List<BaselineSummary>();

        if (!Directory.Exists(_baselineDir)) return summaries;

        foreach (var file in Directory.GetFiles(_baselineDir, "*.json").OrderBy(f => f))
        {
            try
            {
                var json = File.ReadAllText(file);
                var baseline = JsonSerializer.Deserialize<SecurityBaseline>(json, JsonOptions);
                if (baseline != null)
                {
                    summaries.Add(new BaselineSummary
                    {
                        Name = baseline.Name,
                        Description = baseline.Description,
                        CreatedAt = baseline.CreatedAt,
                        MachineName = baseline.MachineName,
                        OverallScore = baseline.OverallScore,
                        Grade = baseline.Grade,
                        TotalFindings = baseline.TotalFindings,
                        CriticalCount = baseline.CriticalCount,
                        WarningCount = baseline.WarningCount
                    });
                }
            }
            catch
            {
                // Skip corrupt files
            }
        }

        return summaries;
    }

    /// <summary>
    /// Delete a named baseline.
    /// </summary>
    /// <returns>True if deleted, false if not found.</returns>
    public bool DeleteBaseline(string name)
    {
        ValidateName(name);

        var filePath = GetBaselinePath(name);
        if (!File.Exists(filePath)) return false;

        File.Delete(filePath);
        return true;
    }

    /// <summary>
    /// Check a current security report against a saved baseline.
    /// Returns deviations: regressions, improvements, and unchanged findings.
    /// </summary>
    public BaselineCheckResult CheckBaseline(string name, SecurityReport currentReport)
    {
        var baseline = LoadBaseline(name)
            ?? throw new InvalidOperationException($"Baseline '{name}' not found.");

        return CheckBaseline(baseline, currentReport);
    }

    /// <summary>
    /// Check a current security report against a baseline.
    /// </summary>
    public BaselineCheckResult CheckBaseline(SecurityBaseline baseline, SecurityReport currentReport)
    {
        var result = new BaselineCheckResult
        {
            Baseline = baseline,
            CurrentScore = currentReport.SecurityScore
        };

        // Build sets of finding titles for comparison
        var baselineTitles = new HashSet<string>(baseline.Findings.Select(f => f.Title));

        var currentFindings = new List<BaselineFinding>();
        foreach (var auditResult in currentReport.Results)
        {
            foreach (var finding in auditResult.Findings)
            {
                currentFindings.Add(new BaselineFinding
                {
                    ModuleName = auditResult.ModuleName,
                    Title = finding.Title,
                    Severity = finding.Severity.ToString(),
                    Description = finding.Description,
                    Remediation = finding.Remediation
                });
            }
        }
        var currentTitles = new HashSet<string>(currentFindings.Select(f => f.Title));

        // Regressions: present now but not in baseline
        result.Regressions = currentFindings
            .Where(f => !baselineTitles.Contains(f.Title))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Title)
            .ToList();

        // Resolved: in baseline but not present now
        result.Resolved = baseline.Findings
            .Where(f => !currentTitles.Contains(f.Title))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Title)
            .ToList();

        // Unchanged: present in both
        result.Unchanged = currentFindings
            .Where(f => baselineTitles.Contains(f.Title))
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Title)
            .ToList();

        // Module deviations
        var baselineModules = baseline.ModuleScores.ToDictionary(m => m.ModuleName, m => m);
        foreach (var auditResult in currentReport.Results)
        {
            var deviation = new BaselineModuleDeviation
            {
                ModuleName = auditResult.ModuleName,
                Category = auditResult.Category,
                CurrentScore = auditResult.Score,
                BaselineScore = baselineModules.TryGetValue(auditResult.ModuleName, out var bm) ? bm.Score : 0
            };
            result.ModuleDeviations.Add(deviation);
        }

        // Add modules that were in baseline but not in current run
        foreach (var bm in baseline.ModuleScores)
        {
            if (!result.ModuleDeviations.Any(d => d.ModuleName == bm.ModuleName))
            {
                result.ModuleDeviations.Add(new BaselineModuleDeviation
                {
                    ModuleName = bm.ModuleName,
                    Category = bm.Category,
                    CurrentScore = 0,
                    BaselineScore = bm.Score
                });
            }
        }

        result.ModuleDeviations = result.ModuleDeviations
            .OrderBy(d => d.Category)
            .ToList();

        return result;
    }

    /// <summary>
    /// Check if a named baseline exists.
    /// </summary>
    public bool BaselineExists(string name)
    {
        ValidateName(name);
        return File.Exists(GetBaselinePath(name));
    }

    /// <summary>
    /// Get the file path for a named baseline.
    /// </summary>
    private string GetBaselinePath(string name)
    {
        return Path.Combine(_baselineDir, $"{name}.json");
    }

    /// <summary>
    /// Validate a baseline name (alphanumeric, hyphens, underscores, 1-50 chars).
    /// </summary>
    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Baseline name cannot be empty.");

        if (name.Length > 50)
            throw new ArgumentException("Baseline name must be 50 characters or less.");

        if (!Regex.IsMatch(name, @"^[a-zA-Z0-9_-]+$"))
            throw new ArgumentException(
                "Baseline name can only contain letters, numbers, hyphens, and underscores.");
    }
}
