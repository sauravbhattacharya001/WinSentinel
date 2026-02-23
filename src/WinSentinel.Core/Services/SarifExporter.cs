using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates SARIF (Static Analysis Results Interchange Format) v2.1.0 reports.
/// SARIF is the OASIS standard for security tool output, supported by GitHub Code Scanning,
/// VS Code (SARIF Viewer extension), Azure DevOps, and many CI/CD platforms.
///
/// Usage: Upload to GitHub via `gh api /repos/{owner}/{repo}/code-scanning/sarifs`
/// or process with any SARIF-compatible viewer/aggregator.
/// </summary>
public class SarifExporter
{
    private const string SarifVersion = "2.1.0";
    private const string SchemaUri = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json";
    private const string ToolName = "WinSentinel";
    private const string ToolVersion = "1.1.0";
    private const string ToolUri = "https://github.com/sauravbhattacharya001/WinSentinel";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Generate a SARIF 2.1.0 JSON report from a SecurityReport.
    /// </summary>
    /// <param name="report">The security audit report to convert.</param>
    /// <param name="includePassFindings">Whether to include Pass-severity findings (default: false).</param>
    /// <returns>SARIF JSON string.</returns>
    public string GenerateSarif(SecurityReport report, bool includePassFindings = false)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var rules = new List<SarifRule>();
        var results = new List<SarifResult>();
        var ruleIndex = new Dictionary<string, int>();

        foreach (var auditResult in report.Results)
        {
            foreach (var finding in auditResult.Findings)
            {
                if (!includePassFindings && finding.Severity == Severity.Pass)
                    continue;

                var ruleId = GenerateRuleId(auditResult.Category, finding.Title);

                if (!ruleIndex.ContainsKey(ruleId))
                {
                    ruleIndex[ruleId] = rules.Count;
                    rules.Add(CreateRule(ruleId, finding, auditResult.Category));
                }

                results.Add(CreateResult(ruleId, ruleIndex[ruleId], finding, auditResult));
            }
        }

        var sarifLog = new SarifLog
        {
            Schema = SchemaUri,
            Version = SarifVersion,
            Runs = new List<SarifRun>
            {
                new SarifRun
                {
                    Tool = new SarifTool
                    {
                        Driver = new SarifToolComponent
                        {
                            Name = ToolName,
                            Version = ToolVersion,
                            InformationUri = ToolUri,
                            SemanticVersion = ToolVersion,
                            Rules = rules.Count > 0 ? rules : null,
                            Properties = new Dictionary<string, object>
                            {
                                ["securityScore"] = report.SecurityScore,
                                ["grade"] = SecurityScorer.GetGrade(report.SecurityScore),
                            }
                        }
                    },
                    Results = results,
                    Invocations = new List<SarifInvocation>
                    {
                        new SarifInvocation
                        {
                            ExecutionSuccessful = report.Results.All(r => r.Success),
                            StartTimeUtc = report.GeneratedAt.UtcDateTime.ToString("o"),
                            EndTimeUtc = report.Results.Count > 0
                                ? report.Results.Max(r => r.EndTime).UtcDateTime.ToString("o")
                                : report.GeneratedAt.UtcDateTime.ToString("o"),
                            ToolExecutionNotifications = GetNotifications(report),
                            Properties = new Dictionary<string, object>
                            {
                                ["machineName"] = Environment.MachineName,
                                ["totalModules"] = report.Results.Count,
                                ["totalFindings"] = report.TotalFindings,
                                ["criticalCount"] = report.TotalCritical,
                                ["warningCount"] = report.TotalWarnings,
                                ["infoCount"] = report.TotalInfo,
                                ["passCount"] = report.TotalPass,
                            }
                        }
                    },
                    AutomationDetails = new SarifAutomationDetails
                    {
                        Id = $"WinSentinel/{Environment.MachineName}/{report.GeneratedAt.UtcDateTime:yyyyMMdd-HHmmss}",
                        Description = new SarifMessage
                        {
                            Text = $"WinSentinel security audit of {Environment.MachineName}"
                        }
                    }
                }
            }
        };

        return JsonSerializer.Serialize(sarifLog, JsonOptions);
    }

    /// <summary>
    /// Generate a stable, human-readable rule ID from category and finding title.
    /// Format: WS{CategoryCode}/{normalized-title}
    /// </summary>
    public static string GenerateRuleId(string category, string title)
    {
        var categoryCode = GetCategoryCode(category);
        var normalizedTitle = NormalizeForId(title);
        return $"WS{categoryCode}/{normalizedTitle}";
    }

    public static string GetCategoryCode(string category)
    {
        // Map common category names to short codes
        return category.ToUpperInvariant() switch
        {
            "FIREWALL" => "FW",
            "WINDOWS DEFENDER" or "DEFENDER" => "DF",
            "WINDOWS UPDATE" or "UPDATES" => "UP",
            "USER ACCOUNTS" or "ACCOUNTS" => "UA",
            "ENCRYPTION" => "EN",
            "NETWORK" or "NETWORK SECURITY" => "NW",
            "BROWSER SECURITY" or "BROWSER" => "BR",
            "PRIVACY" => "PV",
            "PROCESS SECURITY" or "PROCESSES" => "PS",
            "STARTUP PROGRAMS" or "STARTUP" => "ST",
            "SYSTEM CONFIGURATION" or "SYSTEM" => "SY",
            "EVENT LOG" or "EVENT LOGGING" => "EL",
            "APPLICATION SECURITY" or "APPLICATIONS" => "AP",
            _ => category.Length >= 2
                ? category.Substring(0, 2).ToUpperInvariant()
                : category.ToUpperInvariant()
        };
    }

    public static string NormalizeForId(string text)
    {
        if (string.IsNullOrEmpty(text)) return "unknown";

        // Convert to lowercase, replace non-alphanumeric with hyphens, collapse, trim
        var chars = new char[text.Length];
        var len = 0;
        var lastWasHyphen = false;

        foreach (var c in text.ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(c))
            {
                chars[len++] = c;
                lastWasHyphen = false;
            }
            else if (!lastWasHyphen && len > 0)
            {
                chars[len++] = '-';
                lastWasHyphen = true;
            }
        }

        // Trim trailing hyphen
        if (len > 0 && chars[len - 1] == '-') len--;

        // Cap at 60 chars for readability
        var maxLen = Math.Min(len, 60);
        return new string(chars, 0, maxLen);
    }

    private SarifRule CreateRule(string ruleId, Finding finding, string category)
    {
        var rule = new SarifRule
        {
            Id = ruleId,
            Name = finding.Title,
            ShortDescription = new SarifMessage { Text = finding.Title },
            FullDescription = new SarifMessage { Text = finding.Description },
            DefaultConfiguration = new SarifRuleConfiguration
            {
                Level = MapSeverityToLevel(finding.Severity),
                Enabled = finding.Severity != Severity.Pass
            },
            Properties = new Dictionary<string, object>
            {
                ["category"] = category,
                ["severity"] = finding.Severity.ToString()
            }
        };

        if (!string.IsNullOrEmpty(finding.Remediation))
        {
            rule.Help = new SarifMessage
            {
                Text = finding.Remediation,
                Markdown = $"**Remediation:** {finding.Remediation}"
            };
        }

        return rule;
    }

    private SarifResult CreateResult(string ruleId, int ruleIndex, Finding finding, AuditResult auditResult)
    {
        var result = new SarifResult
        {
            RuleId = ruleId,
            RuleIndex = ruleIndex,
            Level = MapSeverityToLevel(finding.Severity),
            Message = new SarifMessage
            {
                Text = finding.Description
            },
            Locations = new List<SarifLocation>
            {
                new SarifLocation
                {
                    LogicalLocations = new List<SarifLogicalLocation>
                    {
                        new SarifLogicalLocation
                        {
                            Name = auditResult.Category,
                            Kind = "module",
                            FullyQualifiedName = $"WinSentinel/{auditResult.ModuleName}"
                        }
                    }
                }
            },
            Properties = new Dictionary<string, object>
            {
                ["module"] = auditResult.ModuleName,
                ["category"] = auditResult.Category,
                ["timestamp"] = finding.Timestamp.UtcDateTime.ToString("o")
            }
        };

        // Add fix information if available
        if (!string.IsNullOrEmpty(finding.Remediation) || !string.IsNullOrEmpty(finding.FixCommand))
        {
            var fixes = new List<SarifFix>();
            var fixDesc = finding.Remediation ?? "Apply recommended fix";

            if (!string.IsNullOrEmpty(finding.FixCommand))
            {
                fixDesc += $"\n\nFix command: {finding.FixCommand}";
            }

            fixes.Add(new SarifFix
            {
                Description = new SarifMessage { Text = fixDesc }
            });

            result.Fixes = fixes;
        }

        return result;
    }

    private List<SarifNotification>? GetNotifications(SecurityReport report)
    {
        var notifications = new List<SarifNotification>();

        foreach (var result in report.Results.Where(r => !r.Success))
        {
            notifications.Add(new SarifNotification
            {
                Message = new SarifMessage
                {
                    Text = $"Module '{result.Category}' failed: {result.Error ?? "Unknown error"}"
                },
                Level = "error",
                AssociatedRule = new SarifAssociatedRule
                {
                    Id = $"WS{GetCategoryCode(result.Category)}/module-error"
                }
            });
        }

        return notifications.Count > 0 ? notifications : null;
    }

    public static string MapSeverityToLevel(Severity severity) => severity switch
    {
        Severity.Critical => "error",
        Severity.Warning => "warning",
        Severity.Info => "note",
        Severity.Pass => "none",
        _ => "note"
    };

    // ──────────────── SARIF Model Classes ────────────────

    // These follow the SARIF v2.1.0 OASIS standard schema.
    // Only the subset needed for WinSentinel output is modeled.

    internal class SarifLog
    {
        [JsonPropertyName("$schema")]
        public string? Schema { get; set; }
        public string? Version { get; set; }
        public List<SarifRun>? Runs { get; set; }
    }

    internal class SarifRun
    {
        public SarifTool? Tool { get; set; }
        public List<SarifResult>? Results { get; set; }
        public List<SarifInvocation>? Invocations { get; set; }
        public SarifAutomationDetails? AutomationDetails { get; set; }
    }

    internal class SarifTool
    {
        public SarifToolComponent? Driver { get; set; }
    }

    internal class SarifToolComponent
    {
        public string? Name { get; set; }
        public string? Version { get; set; }
        public string? SemanticVersion { get; set; }
        public string? InformationUri { get; set; }
        public List<SarifRule>? Rules { get; set; }
        public Dictionary<string, object>? Properties { get; set; }
    }

    internal class SarifRule
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public SarifMessage? ShortDescription { get; set; }
        public SarifMessage? FullDescription { get; set; }
        public SarifMessage? Help { get; set; }
        public SarifRuleConfiguration? DefaultConfiguration { get; set; }
        public Dictionary<string, object>? Properties { get; set; }
    }

    internal class SarifRuleConfiguration
    {
        public string? Level { get; set; }
        public bool? Enabled { get; set; }
    }

    internal class SarifResult
    {
        public string? RuleId { get; set; }
        public int? RuleIndex { get; set; }
        public string? Level { get; set; }
        public SarifMessage? Message { get; set; }
        public List<SarifLocation>? Locations { get; set; }
        public List<SarifFix>? Fixes { get; set; }
        public Dictionary<string, object>? Properties { get; set; }
    }

    internal class SarifMessage
    {
        public string? Text { get; set; }
        public string? Markdown { get; set; }
    }

    internal class SarifLocation
    {
        public List<SarifLogicalLocation>? LogicalLocations { get; set; }
    }

    internal class SarifLogicalLocation
    {
        public string? Name { get; set; }
        public string? Kind { get; set; }
        public string? FullyQualifiedName { get; set; }
    }

    internal class SarifFix
    {
        public SarifMessage? Description { get; set; }
    }

    internal class SarifInvocation
    {
        public bool ExecutionSuccessful { get; set; }
        public string? StartTimeUtc { get; set; }
        public string? EndTimeUtc { get; set; }
        public List<SarifNotification>? ToolExecutionNotifications { get; set; }
        public Dictionary<string, object>? Properties { get; set; }
    }

    internal class SarifNotification
    {
        public SarifMessage? Message { get; set; }
        public string? Level { get; set; }
        public SarifAssociatedRule? AssociatedRule { get; set; }
    }

    internal class SarifAssociatedRule
    {
        public string? Id { get; set; }
    }

    internal class SarifAutomationDetails
    {
        public string? Id { get; set; }
        public SarifMessage? Description { get; set; }
    }
}

