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
        int current = 0;

        foreach (var module in _modules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            current++;
            progress?.Report((module.Name, current, _modules.Count));

            try
            {
                var result = await module.RunAuditAsync(cancellationToken);
                report.Results.Add(result);
            }
            catch (Exception ex)
            {
                report.Results.Add(new AuditResult
                {
                    ModuleName = module.Name,
                    Category = module.Category,
                    Success = false,
                    Error = ex.Message,
                    StartTime = DateTimeOffset.UtcNow,
                    EndTime = DateTimeOffset.UtcNow
                });
            }
        }

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
}
