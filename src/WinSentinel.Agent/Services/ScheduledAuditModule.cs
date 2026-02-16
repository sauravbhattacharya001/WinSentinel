using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Agent module that runs security audits on a configurable schedule.
/// Also handles on-demand audit requests from IPC.
/// </summary>
public class ScheduledAuditModule : IAgentModule
{
    public string Name => "ScheduledAudit";
    public bool IsActive { get; private set; }

    private readonly ILogger<ScheduledAuditModule> _logger;
    private readonly AgentState _state;
    private readonly AgentConfig _config;
    private readonly ThreatLog _threatLog;
    private readonly IpcServer _ipcServer;
    private CancellationTokenSource? _cts;
    private Task? _runLoop;

    public ScheduledAuditModule(
        ILogger<ScheduledAuditModule> logger,
        AgentState state,
        AgentConfig config,
        ThreatLog threatLog,
        IpcServer ipcServer)
    {
        _logger = logger;
        _state = state;
        _config = config;
        _threatLog = threatLog;
        _ipcServer = ipcServer;

        // Register for on-demand audit requests
        _ipcServer.AuditRequested += RunAuditNowAsync;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        IsActive = true;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _runLoop = Task.Run(() => ScheduleLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        IsActive = false;
        _cts?.Cancel();
        if (_runLoop != null)
        {
            try { await _runLoop; }
            catch (OperationCanceledException) { }
        }
    }

    private async Task ScheduleLoopAsync(CancellationToken ct)
    {
        // Run initial audit after a short delay (let the agent fully start)
        await Task.Delay(TimeSpan.FromSeconds(30), ct);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await RunAuditAsync(isScheduled: true, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scheduled audit failed");
                _threatLog.Add(new ThreatEvent
                {
                    Source = Name,
                    Severity = ThreatSeverity.Medium,
                    Title = "Scheduled Audit Failed",
                    Description = $"The scheduled security audit failed: {ex.Message}"
                });
            }

            // Wait for the configured interval
            var interval = TimeSpan.FromHours(_config.ScanIntervalHours);
            _logger.LogInformation("Next scheduled audit in {Hours:F1} hours", interval.TotalHours);

            try
            {
                await Task.Delay(interval, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>Run an audit immediately (called from IPC).</summary>
    private Task RunAuditNowAsync() => RunAuditAsync(isScheduled: false, CancellationToken.None);

    private async Task RunAuditAsync(bool isScheduled, CancellationToken ct)
    {
        if (_state.IsScanRunning)
        {
            _logger.LogWarning("Audit already running, skipping");
            return;
        }

        _state.IsScanRunning = true;
        _logger.LogInformation("Starting {Type} security audit...", isScheduled ? "scheduled" : "on-demand");

        try
        {
            var engine = new AuditEngine();
            var historyService = new AuditHistoryService();
            engine.SetHistoryService(historyService);

            var progress = new Progress<(string module, int current, int total)>(async p =>
            {
                await _ipcServer.BroadcastScanProgressAsync(p.module, p.current, p.total);
            });

            var report = await engine.RunFullAuditAsync(progress, ct, isScheduled);

            _state.LastScanTime = DateTimeOffset.UtcNow;
            _state.LastScanScore = report.SecurityScore;

            // Convert critical/warning findings to threat events
            foreach (var result in report.Results)
            {
                foreach (var finding in result.Findings.Where(f => f.Severity >= Severity.Warning))
                {
                    _threatLog.Add(new ThreatEvent
                    {
                        Source = result.ModuleName,
                        Severity = finding.Severity == Severity.Critical ? ThreatSeverity.Critical : ThreatSeverity.Medium,
                        Title = finding.Title,
                        Description = finding.Description,
                        AutoFixable = !string.IsNullOrEmpty(finding.FixCommand),
                        FixCommand = finding.FixCommand
                    });
                }
            }

            // Broadcast completion
            await _ipcServer.BroadcastAuditCompletedAsync(report.SecurityScore);

            _logger.LogInformation(
                "Audit complete. Score: {Score}/100, Findings: {Total} ({Critical} critical, {Warning} warnings)",
                report.SecurityScore, report.TotalFindings, report.TotalCritical, report.TotalWarnings);

            historyService.Dispose();
        }
        finally
        {
            _state.IsScanRunning = false;
        }
    }
}
