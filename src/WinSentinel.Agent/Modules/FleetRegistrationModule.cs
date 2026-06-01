using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using WinSentinel.Core.Licensing;
using WinSentinel.Core.Models;

namespace WinSentinel.Agent.Modules;

/// <summary>
/// Agent module that registers with a WinSentinel fleet control plane when a Pro
/// license is active. Provides:
/// <list type="bullet">
///   <item>Node registration on startup</item>
///   <item>Heartbeat every 5 minutes with basic telemetry</item>
///   <item>Scan result reporting after each scheduled audit</item>
///   <item>Remote command polling (scan-now, apply-fix, push-policy)</item>
/// </list>
/// Without a Pro license, this module is a no-op (agent still runs locally as free).
/// </summary>
public sealed class FleetRegistrationModule : IAgentModule
{
    public string Name => "FleetRegistration";
    public bool IsActive { get; private set; }

    private readonly ILogger<FleetRegistrationModule> _logger;
    private readonly AgentConfig _config;
    private readonly AgentState _state;
    private readonly ThreatLog _threatLog;
    private CancellationTokenSource? _cts;
    private Task? _heartbeatTask;
    private Task? _commandPollTask;
    private HttpClient? _http;
    private string? _nodeId;

    /// <summary>Default fleet API endpoint. Overridable via config or env var.</summary>
    private const string DefaultFleetEndpoint = "https://api.winsentinel.ai/fleet";
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CommandPollInterval = TimeSpan.FromSeconds(30);

    public FleetRegistrationModule(
        ILogger<FleetRegistrationModule> logger,
        AgentConfig config,
        AgentState state,
        ThreatLog threatLog)
    {
        _logger = logger;
        _config = config;
        _state = state;
        _threatLog = threatLog;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Check Pro license
        var status = LicenseManager.GetStatus();
        if (!status.IsPro)
        {
            _logger.LogInformation("Fleet registration skipped — no active Pro license. Agent runs locally (free mode).");
            return;
        }

        // Check fleet endpoint configuration
        var endpoint = GetFleetEndpoint();
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            _logger.LogInformation("Fleet registration skipped — no fleet endpoint configured.");
            return;
        }

        _nodeId = GetMachineFingerprint();
        _http = new HttpClient
        {
            BaseAddress = new Uri(endpoint.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(30),
        };

        // Add license key as auth header
        var licenseRecord = LicenseManager.Load();
        if (licenseRecord != null && !string.IsNullOrEmpty(licenseRecord.Key))
        {
            _http.DefaultRequestHeaders.Add("X-WinSentinel-License", licenseRecord.Key);
        }
        _http.DefaultRequestHeaders.Add("X-WinSentinel-Node", _nodeId);

        // Register with the control plane
        var registered = await TryRegisterAsync(cancellationToken);
        if (!registered)
        {
            _logger.LogWarning("Fleet registration failed — will retry on next heartbeat.");
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _heartbeatTask = RunHeartbeatLoopAsync(_cts.Token);
        _commandPollTask = RunCommandPollLoopAsync(_cts.Token);
        IsActive = true;

        _logger.LogInformation("Fleet registration active. Node={NodeId}, Endpoint={Endpoint}",
            _nodeId[..12] + "...", endpoint);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (!IsActive) return;

        IsActive = false;
        _cts?.Cancel();

        try
        {
            if (_heartbeatTask != null) await _heartbeatTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
            if (_commandPollTask != null) await _commandPollTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
        }
        catch (OperationCanceledException) { }
        catch (TimeoutException) { }

        // Send deregistration signal
        try
        {
            if (_http != null)
            {
                await _http.PostAsJsonAsync("nodes/deregister", new { nodeId = _nodeId }, cancellationToken);
            }
        }
        catch { /* best effort */ }

        _http?.Dispose();
        _cts?.Dispose();
        _logger.LogInformation("Fleet registration module stopped.");
    }

    /// <summary>Reports scan results to the fleet control plane.</summary>
    public async Task ReportScanAsync(SecurityReport report, CancellationToken ct = default)
    {
        if (!IsActive || _http == null) return;

        try
        {
            var payload = new FleetScanReport
            {
                NodeId = _nodeId!,
                Timestamp = DateTimeOffset.UtcNow,
                OverallScore = report.SecurityScore,
                TotalFindings = report.TotalFindings,
                CriticalCount = report.TotalCritical,
                WarningCount = report.TotalWarnings,
                ModuleResults = report.Results?.Select(m => new FleetModuleResult
                {
                    ModuleName = m.ModuleName,
                    Score = m.Score,
                    FindingCount = m.Findings?.Count ?? 0,
                }).ToList() ?? [],
            };

            var response = await _http.PostAsJsonAsync("nodes/report", payload, ct);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogDebug("Scan report sent to fleet control plane.");
            }
            else
            {
                _logger.LogWarning("Fleet report rejected: {Status}", response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to report scan to fleet control plane.");
        }
    }

    private async Task<bool> TryRegisterAsync(CancellationToken ct)
    {
        try
        {
            var registration = new FleetNodeRegistration
            {
                NodeId = _nodeId!,
                Hostname = Environment.MachineName,
                OsVersion = Environment.OSVersion.VersionString,
                AgentVersion = _state.Version ?? "unknown",
                RegisteredAt = DateTimeOffset.UtcNow,
            };

            var response = await _http!.PostAsJsonAsync("nodes/register", registration, ct);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Registration attempt failed.");
            return false;
        }
    }

    private async Task RunHeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(HeartbeatInterval, ct);

                // Re-check license each heartbeat (handles expiry mid-session)
                var status = LicenseManager.GetStatus();
                if (!status.IsPro)
                {
                    _logger.LogInformation("Pro license no longer active — suspending fleet heartbeat.");
                    IsActive = false;
                    return;
                }

                var heartbeat = new FleetHeartbeat
                {
                    NodeId = _nodeId!,
                    Timestamp = DateTimeOffset.UtcNow,
                    UptimeMinutes = (int)(DateTimeOffset.UtcNow - _state.StartTime).TotalMinutes,
                    ActiveModules = _state.ActiveModules.Where(kv => kv.Value).Select(kv => kv.Key).ToList(),
                    RecentThreats = _threatLog.GetRecent(5).Select(t => t.Title).ToList(),
                };

                var response = await _http!.PostAsJsonAsync("nodes/heartbeat", heartbeat, ct);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogDebug("Heartbeat rejected: {Status}", response.StatusCode);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Heartbeat failed, will retry.");
            }
        }
    }

    private async Task RunCommandPollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CommandPollInterval, ct);

                var response = await _http!.GetAsync($"nodes/{_nodeId}/commands", ct);
                if (!response.IsSuccessStatusCode) continue;

                var commands = await response.Content.ReadFromJsonAsync<List<FleetCommand>>(cancellationToken: ct);
                if (commands == null || commands.Count == 0) continue;

                foreach (var cmd in commands)
                {
                    await ExecuteRemoteCommandAsync(cmd, ct);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Command poll failed, will retry.");
            }
        }
    }

    private async Task ExecuteRemoteCommandAsync(FleetCommand command, CancellationToken ct)
    {
        _logger.LogInformation("Executing remote command: {Type} (id={Id})", command.Type, command.Id);

        try
        {
            switch (command.Type?.ToLowerInvariant())
            {
                case "scan-now":
                    // Trigger an immediate scan via the scheduled audit module
                    _threatLog.Add(new ThreatEvent
                    {
                        Source = "Fleet",
                        Severity = ThreatSeverity.Info,
                        Title = "Remote scan requested",
                        Description = $"Fleet control plane dispatched scan-now (command {command.Id}).",
                    });
                    // Signal the state so ScheduledAuditModule picks it up
                    _state.ForceImmediateScan = true;
                    await AckCommandAsync(command.Id, "accepted", ct);
                    break;

                case "push-policy":
                    if (command.Payload is { } policyPayload)
                    {
                        ApplyRemotePolicy(policyPayload);
                        await AckCommandAsync(command.Id, "applied", ct);
                    }
                    else
                    {
                        await AckCommandAsync(command.Id, "rejected:no-payload", ct);
                    }
                    break;

                default:
                    _logger.LogWarning("Unknown remote command type: {Type}", command.Type);
                    await AckCommandAsync(command.Id, "rejected:unknown-type", ct);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute remote command {Id}", command.Id);
            await AckCommandAsync(command.Id, $"error:{ex.Message}", ct);
        }
    }

    private async Task AckCommandAsync(string commandId, string status, CancellationToken ct)
    {
        try
        {
            await _http!.PostAsJsonAsync("nodes/commands/ack", new { commandId, nodeId = _nodeId, status }, ct);
        }
        catch { /* best effort */ }
    }

    private void ApplyRemotePolicy(JsonElement payload)
    {
        // Apply policy overrides to agent config
        if (payload.TryGetProperty("scanIntervalHours", out var interval) && interval.TryGetDouble(out var hours))
        {
            _config.ScanIntervalHours = Math.Max(0.5, hours);
        }
        if (payload.TryGetProperty("autoFixCritical", out var afc) && afc.ValueKind == JsonValueKind.True)
        {
            _config.AutoFixCritical = true;
        }
        if (payload.TryGetProperty("riskTolerance", out var rt))
        {
            if (Enum.TryParse<RiskTolerance>(rt.GetString(), true, out var parsed))
                _config.RiskTolerance = parsed;
        }
        _config.Save();
        _logger.LogInformation("Remote policy applied and saved.");
    }

    private string GetFleetEndpoint()
    {
        // Priority: env var > config > default
        var envEndpoint = Environment.GetEnvironmentVariable("WINSENTINEL_FLEET_ENDPOINT");
        if (!string.IsNullOrWhiteSpace(envEndpoint)) return envEndpoint;

        if (!string.IsNullOrWhiteSpace(_config.FleetEndpoint)) return _config.FleetEndpoint;

        return DefaultFleetEndpoint;
    }

    /// <summary>
    /// Generates a stable machine fingerprint from hardware identifiers.
    /// Used to uniquely identify this node in the fleet without requiring user input.
    /// </summary>
    private static string GetMachineFingerprint()
    {
        var raw = $"{Environment.MachineName}|{Environment.UserName}|{Environment.ProcessorCount}";

        // Add machine GUID from registry if available (Windows-specific)
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Cryptography");
            var machineGuid = key?.GetValue("MachineGuid") as string;
            if (!string.IsNullOrEmpty(machineGuid))
                raw = machineGuid;
        }
        catch { /* fallback to composite key */ }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

#region Fleet DTOs

internal sealed class FleetNodeRegistration
{
    [JsonPropertyName("nodeId")] public string NodeId { get; set; } = "";
    [JsonPropertyName("hostname")] public string Hostname { get; set; } = "";
    [JsonPropertyName("osVersion")] public string OsVersion { get; set; } = "";
    [JsonPropertyName("agentVersion")] public string AgentVersion { get; set; } = "";
    [JsonPropertyName("registeredAt")] public DateTimeOffset RegisteredAt { get; set; }
}

internal sealed class FleetHeartbeat
{
    [JsonPropertyName("nodeId")] public string NodeId { get; set; } = "";
    [JsonPropertyName("timestamp")] public DateTimeOffset Timestamp { get; set; }
    [JsonPropertyName("uptimeMinutes")] public int UptimeMinutes { get; set; }
    [JsonPropertyName("activeModules")] public List<string> ActiveModules { get; set; } = [];
    [JsonPropertyName("recentThreats")] public List<string> RecentThreats { get; set; } = [];
}

internal sealed class FleetScanReport
{
    [JsonPropertyName("nodeId")] public string NodeId { get; set; } = "";
    [JsonPropertyName("timestamp")] public DateTimeOffset Timestamp { get; set; }
    [JsonPropertyName("overallScore")] public int OverallScore { get; set; }
    [JsonPropertyName("totalFindings")] public int TotalFindings { get; set; }
    [JsonPropertyName("criticalCount")] public int CriticalCount { get; set; }
    [JsonPropertyName("warningCount")] public int WarningCount { get; set; }
    [JsonPropertyName("moduleResults")] public List<FleetModuleResult> ModuleResults { get; set; } = [];
}

internal sealed class FleetModuleResult
{
    [JsonPropertyName("moduleName")] public string ModuleName { get; set; } = "";
    [JsonPropertyName("score")] public int Score { get; set; }
    [JsonPropertyName("findingCount")] public int FindingCount { get; set; }
}

internal sealed class FleetCommand
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("payload")] public JsonElement? Payload { get; set; }
    [JsonPropertyName("issuedAt")] public DateTimeOffset IssuedAt { get; set; }
}

#endregion
