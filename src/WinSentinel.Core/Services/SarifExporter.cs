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
    // See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

    /// <summary>
    /// Top-level SARIF log object. Contains the schema reference, version,
    /// and one or more <see cref="SarifRun"/> objects.
    /// </summary>
    internal class SarifLog
    {
        /// <summary>URI of the SARIF JSON schema for validation.</summary>
        [JsonPropertyName("$schema")]
        public string? Schema { get; set; }

        /// <summary>SARIF specification version (e.g. "2.1.0").</summary>
        public string? Version { get; set; }

        /// <summary>One run per tool invocation.</summary>
        public List<SarifRun>? Runs { get; set; }
    }

    /// <summary>
    /// A single invocation of a SARIF-producing tool and its results.
    /// </summary>
    internal class SarifRun
    {
        /// <summary>The tool that produced this run.</summary>
        public SarifTool? Tool { get; set; }

        /// <summary>Individual findings/results from the run.</summary>
        public List<SarifResult>? Results { get; set; }

        /// <summary>Metadata about the tool invocation (timing, success, machine info).</summary>
        public List<SarifInvocation>? Invocations { get; set; }

        /// <summary>Identifies this run for correlation across multiple reports.</summary>
        public SarifAutomationDetails? AutomationDetails { get; set; }
    }

    /// <summary>
    /// Describes the analysis tool. Contains a <see cref="SarifToolComponent"/> driver.
    /// </summary>
    internal class SarifTool
    {
        /// <summary>Primary driver component (WinSentinel itself).</summary>
        public SarifToolComponent? Driver { get; set; }
    }

    /// <summary>
    /// Tool component descriptor — name, version, rules, and custom properties.
    /// </summary>
    internal class SarifToolComponent
    {
        /// <summary>Display name of the tool.</summary>
        public string? Name { get; set; }

        /// <summary>Tool version string.</summary>
        public string? Version { get; set; }

        /// <summary>Semantic version for tooling that distinguishes version formats.</summary>
        public string? SemanticVersion { get; set; }

        /// <summary>URI for the tool's homepage or documentation.</summary>
        public string? InformationUri { get; set; }

        /// <summary>Rules (findings definitions) that the tool can report.</summary>
        public List<SarifRule>? Rules { get; set; }

        /// <summary>Custom properties (e.g. security score, grade).</summary>
        public Dictionary<string, object>? Properties { get; set; }
    }

    /// <summary>
    /// A rule definition — describes a class of finding the tool can report.
    /// </summary>
    internal class SarifRule
    {
        /// <summary>Stable rule identifier (e.g. "WSFW/firewall-disabled").</summary>
        public string? Id { get; set; }

        /// <summary>Human-readable rule name.</summary>
        public string? Name { get; set; }

        /// <summary>One-line summary of what this rule detects.</summary>
        public SarifMessage? ShortDescription { get; set; }

        /// <summary>Detailed explanation of the rule.</summary>
        public SarifMessage? FullDescription { get; set; }

        /// <summary>Remediation guidance in text and/or markdown.</summary>
        public SarifMessage? Help { get; set; }

        /// <summary>Default severity level and enabled state.</summary>
        public SarifRuleConfiguration? DefaultConfiguration { get; set; }

        /// <summary>Custom properties (category, severity string).</summary>
        public Dictionary<string, object>? Properties { get; set; }
    }

    /// <summary>
    /// Default configuration for a SARIF rule (severity level and enabled flag).
    /// </summary>
    internal class SarifRuleConfiguration
    {
        /// <summary>SARIF severity: "error", "warning", "note", or "none".</summary>
        public string? Level { get; set; }

        /// <summary>Whether this rule is enabled by default.</summary>
        public bool? Enabled { get; set; }
    }

    /// <summary>
    /// A single result (finding instance) reported by the tool.
    /// </summary>
    internal class SarifResult
    {
        /// <summary>The rule ID this result corresponds to.</summary>
        public string? RuleId { get; set; }

        /// <summary>Index into the <see cref="SarifToolComponent.Rules"/> array.</summary>
        public int? RuleIndex { get; set; }

        /// <summary>Severity level for this specific result.</summary>
        public string? Level { get; set; }

        /// <summary>Human-readable result message (finding description).</summary>
        public SarifMessage? Message { get; set; }

        /// <summary>Where in the system this finding was detected.</summary>
        public List<SarifLocation>? Locations { get; set; }

        /// <summary>Suggested fixes for this finding.</summary>
        public List<SarifFix>? Fixes { get; set; }

        /// <summary>Custom properties (module, category, timestamp).</summary>
        public Dictionary<string, object>? Properties { get; set; }
    }

    /// <summary>
    /// A SARIF message with plain text and optional markdown rendering.
    /// </summary>
    internal class SarifMessage
    {
        /// <summary>Plain text content.</summary>
        public string? Text { get; set; }

        /// <summary>Markdown-formatted content (for rich rendering).</summary>
        public string? Markdown { get; set; }
    }

    /// <summary>
    /// A location where a result was detected. Uses logical locations
    /// (module/category) since WinSentinel audits system state, not source files.
    /// </summary>
    internal class SarifLocation
    {
        /// <summary>Logical locations (e.g. module name, category).</summary>
        public List<SarifLogicalLocation>? LogicalLocations { get; set; }
    }

    /// <summary>
    /// A named logical location within the audited system.
    /// </summary>
    internal class SarifLogicalLocation
    {
        /// <summary>Display name (e.g. audit category).</summary>
        public string? Name { get; set; }

        /// <summary>Kind of location (e.g. "module").</summary>
        public string? Kind { get; set; }

        /// <summary>Fully qualified name (e.g. "WinSentinel/FirewallAudit").</summary>
        public string? FullyQualifiedName { get; set; }
    }

    /// <summary>
    /// A suggested fix for a SARIF result, with a human-readable description.
    /// </summary>
    internal class SarifFix
    {
        /// <summary>Description of the fix (may include PowerShell commands).</summary>
        public SarifMessage? Description { get; set; }
    }

    /// <summary>
    /// Metadata about a single tool invocation — timing, success, and diagnostics.
    /// </summary>
    internal class SarifInvocation
    {
        /// <summary>Whether all audit modules completed without errors.</summary>
        public bool ExecutionSuccessful { get; set; }

        /// <summary>ISO 8601 start time of the audit run.</summary>
        public string? StartTimeUtc { get; set; }

        /// <summary>ISO 8601 end time of the audit run.</summary>
        public string? EndTimeUtc { get; set; }

        /// <summary>Notifications about module failures or warnings during execution.</summary>
        public List<SarifNotification>? ToolExecutionNotifications { get; set; }

        /// <summary>Custom properties (machine name, module counts, finding counts).</summary>
        public Dictionary<string, object>? Properties { get; set; }
    }

    /// <summary>
    /// A diagnostic notification (e.g. module execution failure).
    /// </summary>
    internal class SarifNotification
    {
        /// <summary>Notification message text.</summary>
        public SarifMessage? Message { get; set; }

        /// <summary>Severity level ("error", "warning", "note").</summary>
        public string? Level { get; set; }

        /// <summary>The rule associated with this notification, if any.</summary>
        public SarifAssociatedRule? AssociatedRule { get; set; }
    }

    /// <summary>
    /// Reference to a rule from a notification context.
    /// </summary>
    internal class SarifAssociatedRule
    {
        /// <summary>Rule identifier.</summary>
        public string? Id { get; set; }
    }

    /// <summary>
    /// Identifies a run for correlation across multiple SARIF reports.
    /// </summary>
    internal class SarifAutomationDetails
    {
        /// <summary>Unique automation run ID (e.g. "WinSentinel/HOSTNAME/20260320-181300").</summary>
        public string? Id { get; set; }

        /// <summary>Human-readable description of this automation run.</summary>
        public SarifMessage? Description { get; set; }
    }
}

