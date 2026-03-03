using WinSentinel.Core.Audits;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Orchestrates running all audit modules and producing a security report.
/// </summary>
public class AuditEngine
{
    private readonly List<IAuditModule> _modules;
    private AuditHistoryService? _historyService;

    public AuditEngine()
    {
        _modules = new List<IAuditModule>
        {
            new FirewallAudit(),
            new UpdateAudit(),
            new DefenderAudit(),
            new AccountAudit(),
            new NetworkAudit(),
            new ProcessAudit(),
            new StartupAudit(),
            new SystemAudit(),
            new PrivacyAudit(),
            new BrowserAudit(),
            new AppSecurityAudit(),
            new EncryptionAudit(),
            new EventLogAudit(),
            new SoftwareInventoryAudit(),
            new CertificateAudit(),
            new PowerShellAudit(),
        };
    }

    public AuditEngine(IEnumerable<IAuditModule> modules)
    {
        _modules = modules.ToList();
    }

    /// <summary>
    /// Set the history service for auto-saving audit results.
    /// </summary>
    public void SetHistoryService(AuditHistoryService historyService)
    {
        _historyService = historyService;
    }

    /// <summary>
    /// Get the configured history service, if any.
    /// </summary>
    public AuditHistoryService? HistoryService => _historyService;

    public IReadOnlyList<IAuditModule> Modules => _modules.AsReadOnly();

    /// <summary>
    /// Run all audit modules and return a security report.
    /// Automatically saves to history database if a history service is configured.
    /// </summary>
    public async Task<SecurityReport> RunFullAuditAsync(
        IProgress<(string module, int current, int total)>? progress = null,
        CancellationToken cancellationToken = default,
        bool isScheduled = false)
    {
        var report = new SecurityReport();

        // Run all audit modules concurrently.  Each module inspects
        // independent system facets (firewall, defender, accounts, …)
        // so there are no shared-state conflicts.  Running in parallel
        // cuts wall-clock time from O(n × avg_module) to roughly
        // O(max_module) — a significant win when modules wait on WMI
        // queries, registry reads, or process enumeration.
        var tasks = _modules.Select(async (module, index) =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var result = await module.RunAuditAsync(cancellationToken);
                progress?.Report((module.Name, index + 1, _modules.Count));
                return result;
            }
            catch (Exception ex)
            {
                progress?.Report((module.Name, index + 1, _modules.Count));
                return new AuditResult
                {
                    ModuleName = module.Name,
                    Category = module.Category,
                    Success = false,
                    Error = ex.Message,
                    StartTime = DateTimeOffset.UtcNow,
                    EndTime = DateTimeOffset.UtcNow
                };
            }
        }).ToList();

        var results = await Task.WhenAll(tasks);
        report.Results.AddRange(results);

        report.SecurityScore = SecurityScorer.CalculateScore(report);
        report.GeneratedAt = DateTimeOffset.UtcNow;

        // Auto-save to history database
        try
        {
            _historyService?.SaveAuditResult(report, isScheduled);
        }
        catch
        {
            // Don't fail the scan if history save fails
        }

        return report;
    }

    /// <summary>
    /// Run a single audit module by category name.
    /// </summary>
    public async Task<AuditResult?> RunSingleAuditAsync(string category,
        CancellationToken cancellationToken = default)
    {
        var module = _modules.FirstOrDefault(m =>
            m.Category.Equals(category, StringComparison.OrdinalIgnoreCase) ||
            m.Name.Contains(category, StringComparison.OrdinalIgnoreCase));

        if (module == null) return null;
        return await module.RunAuditAsync(cancellationToken);
    }

    /// <summary>
    /// Generate a formatted text summary of a security report for console/log output.
    /// </summary>
    public static string GenerateTextSummary(SecurityReport report)
    {
        var sb = new System.Text.StringBuilder();
        var score = report.SecurityScore;
        var grade = SecurityScorer.GetGrade(score);

        sb.AppendLine("═══════════════════════════════════════════");
        sb.AppendLine("  WinSentinel Security Report");
        sb.AppendLine($"  Score: {score}/100 (Grade: {grade})");
        sb.AppendLine($"  Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("═══════════════════════════════════════════");
        sb.AppendLine();

        foreach (var result in report.Results)
        {
            sb.AppendLine($"📋 {result.ModuleName} [{result.Category}] — Score: {SecurityScorer.CalculateCategoryScore(result)}/100");

            if (!result.Success)
            {
                sb.AppendLine($"   ⚠️ Error: {result.Error}");
            }
            else
            {
                foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
                {
                    var icon = finding.Severity switch
                    {
                        Severity.Critical => "🔴",
                        Severity.Warning => "🟡",
                        Severity.Info => "🔵",
                        Severity.Pass => "🟢",
                        _ => "⚪"
                    };
                    sb.AppendLine($"   {icon} {finding.Title}");
                    sb.AppendLine($"      {finding.Description}");
                    if (finding.Remediation != null)
                        sb.AppendLine($"      💡 Fix: {finding.Remediation}");
                }
            }

            sb.AppendLine();
        }

        sb.AppendLine("═══════════════════════════════════════════");
        sb.AppendLine($"  Critical: {report.TotalCritical} | Warnings: {report.TotalWarnings} | Total: {report.TotalFindings}");
        sb.AppendLine("═══════════════════════════════════════════");

        return sb.ToString();
    }
}
