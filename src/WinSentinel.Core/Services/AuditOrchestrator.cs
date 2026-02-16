using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Orchestrates running audit modules and producing reports.
/// </summary>
public class AuditOrchestrator
{
    private readonly List<IAuditModule> _modules;

    public AuditOrchestrator()
    {
        _modules =
        [
            new FirewallAudit(),
            new UpdateAudit(),
            new DefenderAudit(),
            new AccountAudit(),
            new NetworkAudit(),
            new ProcessAudit(),
            new StartupAudit(),
            new SystemAudit()
        ];
    }

    public AuditOrchestrator(IEnumerable<IAuditModule> modules)
    {
        _modules = modules.ToList();
    }

    /// <summary>
    /// Get list of available audit modules.
    /// </summary>
    public IReadOnlyList<IAuditModule> Modules => _modules.AsReadOnly();

    /// <summary>
    /// Run all audit modules and produce a full report.
    /// </summary>
    public async Task<FullAuditReport> RunFullAuditAsync(
        IProgress<(string module, int current, int total)>? progress = null,
        CancellationToken ct = default)
    {
        var report = new FullAuditReport { Timestamp = DateTime.UtcNow };

        for (int i = 0; i < _modules.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var module = _modules[i];
            progress?.Report((module.Name, i + 1, _modules.Count));

            try
            {
                var result = await module.RunAuditAsync(ct);
                report.Results.Add(result);
            }
            catch (Exception ex)
            {
                report.Results.Add(new AuditResult
                {
                    ModuleName = module.Name,
                    Category = module.Category,
                    Success = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        return report;
    }

    /// <summary>
    /// Run a single audit module by name.
    /// </summary>
    public async Task<AuditResult?> RunSingleAuditAsync(string moduleName, CancellationToken ct = default)
    {
        var module = _modules.FirstOrDefault(m =>
            m.Name.Contains(moduleName, StringComparison.OrdinalIgnoreCase) ||
            m.Category.Contains(moduleName, StringComparison.OrdinalIgnoreCase));

        if (module == null) return null;
        return await module.RunAuditAsync(ct);
    }

    /// <summary>
    /// Generate a text summary of a full audit report.
    /// </summary>
    public static string GenerateTextSummary(FullAuditReport report)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("═══════════════════════════════════════════");
        sb.AppendLine($"  WinSentinel Security Report");
        sb.AppendLine($"  Score: {report.OverallScore}/100 (Grade: {report.Grade})");
        sb.AppendLine($"  Generated: {report.Timestamp:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("═══════════════════════════════════════════");
        sb.AppendLine();

        foreach (var result in report.Results)
        {
            sb.AppendLine($"📋 {result.ModuleName} [{result.Category}] — Score: {result.Score}/100");

            if (!result.Success)
            {
                sb.AppendLine($"   ⚠️ Error: {result.ErrorMessage}");
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
