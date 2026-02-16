using WinSentinel.Core.Services;

namespace WinSentinel.Service;

/// <summary>
/// Background worker that periodically runs security audits.
/// </summary>
public class SecurityMonitorWorker : BackgroundService
{
    private readonly ILogger<SecurityMonitorWorker> _logger;
    private readonly AuditOrchestrator _orchestrator = new();
    private readonly TimeSpan _auditInterval = TimeSpan.FromHours(1);

    public SecurityMonitorWorker(ILogger<SecurityMonitorWorker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WinSentinel Security Monitor starting.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _logger.LogInformation("Running scheduled security audit at {time}", DateTimeOffset.Now);

                var report = await _orchestrator.RunFullAuditAsync(ct: stoppingToken);

                _logger.LogInformation(
                    "Audit complete. Score: {score}/100, Critical: {critical}, Warnings: {warnings}",
                    report.OverallScore, report.TotalCritical, report.TotalWarnings);

                // Log critical findings
                foreach (var finding in report.Results
                    .SelectMany(r => r.Findings)
                    .Where(f => f.Severity == Core.Models.Severity.Critical))
                {
                    _logger.LogWarning("CRITICAL: {title} — {description}", finding.Title, finding.Description);
                }

                // Write report to event log (Windows Application log)
                if (report.TotalCritical > 0)
                {
                    _logger.LogWarning(
                        "Security audit found {count} critical issue(s). Review WinSentinel dashboard.",
                        report.TotalCritical);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during security audit.");
            }

            await Task.Delay(_auditInterval, stoppingToken);
        }

        _logger.LogInformation("WinSentinel Security Monitor stopping.");
    }
}
