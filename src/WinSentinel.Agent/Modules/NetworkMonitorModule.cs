using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace WinSentinel.Agent.Modules;

/// <summary>
/// Real-time network monitoring module.
/// Periodically scans TCP connections, detects new listening ports,
/// connections to known-bad IPs, unusual outbound bursts, suspicious port usage,
/// and ARP changes (gateway MAC changes).
/// </summary>
public class NetworkMonitorModule : IAgentModule
{
    public string Name => "NetworkMonitor";
    public bool IsActive { get; private set; }

    private readonly ILogger<NetworkMonitorModule> _logger;
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;

    // ── State tracking ──

    /// <summary>Previously known listening ports (port → process name).</summary>
    private readonly ConcurrentDictionary<int, string> _knownListeningPorts = new();

    /// <summary>Connection counts per process in the current window (PID → count).</summary>
    private readonly ConcurrentDictionary<int, ConnectionBurst> _connectionBursts = new();

    /// <summary>Known gateway MAC address (for ARP spoofing detection).</summary>
    private string? _lastGatewayMac;

    /// <summary>Rate-limit: recent alert keys with timestamps.</summary>
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentAlerts = new();

    /// <summary>Previously seen active connections (for churn detection).</summary>
    private int _previousConnectionCount;

    /// <summary>Whether we have completed at least one scan (to avoid false positives on startup).</summary>
    private bool _baselineEstablished;

    // ── Constants ──

    /// <summary>How often to poll network state (seconds).</summary>
    internal const int PollIntervalSeconds = 30;

    /// <summary>Rate-limit: minimum seconds between identical alerts.</summary>
    private const int RateLimitSeconds = 120;

    /// <summary>Burst threshold: connections from one process in a single poll window.</summary>
    internal const int BurstThreshold = 50;

    /// <summary>Connection churn threshold: spike in new connections between polls.</summary>
    internal const int ChurnThreshold = 100;

    /// <summary>Common RAT / C2 ports.</summary>
    internal static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 1337, 6666, 6667, 6668, 6669, // Common RAT/IRC ports
        1234, 1337, 31337, 12345, 54321, // Classic backdoor ports
        3389, // RDP (suspicious if unexpected listener)
        5900, 5901, // VNC
        8080, 8888, 9090, 9999, // Common web-based C2
        2222, // Alternative SSH
        7777, 8443, // Common staging ports
    };

    /// <summary>Known Tor exit node port (SOCKS).</summary>
    internal const int TorSocksPort = 9050;
    internal const int TorBrowserPort = 9150;

    /// <summary>
    /// Known malicious/C2 IP ranges (CIDR-style prefixes for quick matching).
    /// This is a curated sample list — in production, use a threat intel feed.
    /// </summary>
    internal static readonly string[] KnownBadIpPrefixes = new[]
    {
        // Example C2 infrastructure ranges (well-known bad actors)
        "185.220.100.", "185.220.101.", "185.220.102.", // Tor exit nodes (bulk)
        "45.154.255.",    // Known bulletproof hosting
        "5.188.86.",      // Known malware hosting
        "91.219.236.",    // Known C2 infrastructure
        "194.26.29.",     // Known botnet C2
        "23.106.122.",    // Known malicious hosting
        "193.142.146.",   // Known phishing infrastructure
    };

    /// <summary>
    /// Known Tor exit node IP prefixes (major ranges).
    /// For a real deployment, this would be updated from dan.me.uk/torlist or similar.
    /// </summary>
    internal static readonly string[] TorExitNodePrefixes = new[]
    {
        "185.220.100.", "185.220.101.", "185.220.102.", "185.220.103.",
        "204.85.191.", "199.249.230.", "171.25.193.",
        "195.176.3.", "62.102.148.", "77.247.181.",
    };

    /// <summary>
    /// Known-safe listening processes (won't alert for new listening ports).
    /// </summary>
    private static readonly HashSet<string> SafeListeningProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "svchost", "lsass", "spoolsv", "dns",
        "wininit", "services", "httpd", "nginx", "iis",
        "sqlservr", "sqlwriter", "WinSentinel.Agent",
        "WinSentinel.App", "Microsoft.SharePoint",
        "SearchIndexer"
    };

    public NetworkMonitorModule(
        ILogger<NetworkMonitorModule> logger,
        ThreatLog threatLog,
        AgentConfig config)
    {
        _logger = logger;
        _threatLog = threatLog;
        _config = config;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("NetworkMonitor starting — polling every {Interval}s", PollIntervalSeconds);
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Establish baseline on first run
        try
        {
            EstablishBaseline();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to establish network baseline — will build on first poll");
        }

        _monitorTask = Task.Run(() => MonitorLoopAsync(_cts.Token), _cts.Token);

        IsActive = true;
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("NetworkMonitor stopping...");
        IsActive = false;
        _cts?.Cancel();

        if (_monitorTask != null)
        {
            try { await _monitorTask; }
            catch (OperationCanceledException) { }
        }

        _knownListeningPorts.Clear();
        _connectionBursts.Clear();
        _recentAlerts.Clear();
        _lastGatewayMac = null;
        _baselineEstablished = false;
    }

    // ── Baseline ──

    private void EstablishBaseline()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();

        // Record current listening ports
        foreach (var listener in properties.GetActiveTcpListeners())
        {
            var processName = GetProcessForPort(listener.Port) ?? "unknown";
            _knownListeningPorts[listener.Port] = processName;
        }

        // Record current connection count
        try
        {
            var connections = properties.GetActiveTcpConnections();
            _previousConnectionCount = connections.Length;
        }
        catch
        {
            _previousConnectionCount = 0;
        }

        // Record gateway MAC
        _lastGatewayMac = GetGatewayMacAddress();

        _baselineEstablished = true;
        _logger.LogInformation(
            "Network baseline: {Ports} listening ports, {Conns} active connections, gateway MAC: {Mac}",
            _knownListeningPorts.Count, _previousConnectionCount, _lastGatewayMac ?? "unknown");
    }

    // ── Monitor Loop ──

    private async Task MonitorLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(PollIntervalSeconds), ct);
            }
            catch (OperationCanceledException) { return; }

            try
            {
                PollNetworkState();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error during network poll");
            }

            // Cleanup stale rate-limit entries
            CleanupRateLimits();
        }
    }

    /// <summary>
    /// Core poll method — checks all network detection rules.
    /// Internal for testability.
    /// </summary>
    internal void PollNetworkState()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();

        // 1. Check for new listening ports
        CheckListeningPorts(properties);

        // 2. Analyze active TCP connections
        TcpConnectionInformation[] connections;
        try
        {
            connections = properties.GetActiveTcpConnections();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to get active TCP connections");
            return;
        }

        // 3. Check for known-bad IPs
        CheckKnownBadIps(connections);

        // 4. Check for Tor connections
        CheckTorConnections(connections);

        // 5. Check for suspicious port usage
        CheckSuspiciousPorts(connections);

        // 6. Check outbound burst (connection count per process)
        CheckOutboundBurst(connections);

        // 7. Check connection churn
        CheckConnectionChurn(connections.Length);

        // 8. Check ARP / gateway MAC changes
        CheckArpChanges();
    }

    // ── Detection Rules ──

    /// <summary>
    /// Rule: Detect new listening ports opened since baseline.
    /// </summary>
    internal void CheckListeningPorts(IPGlobalProperties properties)
    {
        IPEndPoint[] listeners;
        try
        {
            listeners = properties.GetActiveTcpListeners();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to get TCP listeners");
            return;
        }

        var currentPorts = new HashSet<int>();

        foreach (var listener in listeners)
        {
            currentPorts.Add(listener.Port);

            if (!_knownListeningPorts.ContainsKey(listener.Port) && _baselineEstablished)
            {
                var processName = GetProcessForPort(listener.Port);

                // Skip safe processes
                if (processName != null && SafeListeningProcesses.Contains(processName))
                {
                    _knownListeningPorts[listener.Port] = processName;
                    continue;
                }

                var severity = ThreatSeverity.Medium;
                var description = $"New listening port {listener.Port} opened";

                if (processName != null)
                {
                    description += $" by process '{processName}'";

                    // Check if the process is unsigned — elevates severity
                    var exePath = GetProcessPath(processName);
                    if (exePath != null && !VerifySignature(exePath))
                    {
                        severity = ThreatSeverity.High;
                        description += " (unsigned executable)";
                    }
                }

                // Well-known suspicious ports get elevated
                if (SuspiciousPorts.Contains(listener.Port))
                {
                    severity = ThreatSeverity.High;
                    description += $" — port {listener.Port} is commonly used by malware/RATs";
                }

                EmitThreat(new ThreatEvent
                {
                    Source = "NetworkMonitor",
                    Severity = severity,
                    Title = "New Listening Port Detected",
                    Description = description + ".",
                    AutoFixable = processName != null,
                    FixCommand = processName != null
                        ? $"taskkill /F /IM \"{processName}.exe\""
                        : null
                });

                _knownListeningPorts[listener.Port] = processName ?? "unknown";
            }
        }

        // Remove ports that are no longer listening
        foreach (var port in _knownListeningPorts.Keys.ToList())
        {
            if (!currentPorts.Contains(port))
            {
                _knownListeningPorts.TryRemove(port, out _);
            }
        }
    }

    /// <summary>
    /// Rule: Detect connections to known-malicious IP ranges.
    /// </summary>
    internal void CheckKnownBadIps(TcpConnectionInformation[] connections)
    {
        foreach (var conn in connections)
        {
            if (conn.State != TcpState.Established)
                continue;

            var remoteIp = conn.RemoteEndPoint.Address.ToString();

            foreach (var prefix in KnownBadIpPrefixes)
            {
                if (remoteIp.StartsWith(prefix))
                {
                    EmitThreat(new ThreatEvent
                    {
                        Source = "NetworkMonitor",
                        Severity = ThreatSeverity.Critical,
                        Title = "Connection to Known-Malicious IP",
                        Description = $"Active connection to known-malicious IP {remoteIp}:{conn.RemoteEndPoint.Port}. " +
                                      $"Local endpoint: {conn.LocalEndPoint}. " +
                                      $"This IP is in a known C2/malware hosting range.",
                        AutoFixable = true,
                        FixCommand = $"netsh advfirewall firewall add rule name=\"Block {remoteIp}\" dir=out action=block remoteip={remoteIp}"
                    });
                    break; // Don't emit multiple alerts for the same connection
                }
            }
        }
    }

    /// <summary>
    /// Rule: Detect connections to Tor exit nodes.
    /// </summary>
    internal void CheckTorConnections(TcpConnectionInformation[] connections)
    {
        foreach (var conn in connections)
        {
            if (conn.State != TcpState.Established)
                continue;

            var remoteIp = conn.RemoteEndPoint.Address.ToString();
            var remotePort = conn.RemoteEndPoint.Port;
            var localPort = conn.LocalEndPoint.Port;

            // Check for local Tor SOCKS proxy
            if (localPort == TorSocksPort || localPort == TorBrowserPort ||
                remotePort == TorSocksPort || remotePort == TorBrowserPort)
            {
                EmitThreat(new ThreatEvent
                {
                    Source = "NetworkMonitor",
                    Severity = ThreatSeverity.High,
                    Title = "Tor Network Connection Detected",
                    Description = $"Connection using Tor SOCKS port detected. " +
                                  $"Local: {conn.LocalEndPoint} → Remote: {conn.RemoteEndPoint}. " +
                                  $"Tor can be used to anonymize malicious traffic.",
                    AutoFixable = false
                });
                continue;
            }

            // Check for connections to known Tor exit nodes
            foreach (var prefix in TorExitNodePrefixes)
            {
                if (remoteIp.StartsWith(prefix))
                {
                    EmitThreat(new ThreatEvent
                    {
                        Source = "NetworkMonitor",
                        Severity = ThreatSeverity.High,
                        Title = "Connection to Tor Exit Node",
                        Description = $"Connection to known Tor exit node IP {remoteIp}:{remotePort}. " +
                                      $"Local endpoint: {conn.LocalEndPoint}. " +
                                      $"This may indicate anonymized C2 communication.",
                        AutoFixable = true,
                        FixCommand = $"netsh advfirewall firewall add rule name=\"Block Tor {remoteIp}\" dir=out action=block remoteip={remoteIp}"
                    });
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Rule: Detect connections using suspicious/common RAT ports.
    /// </summary>
    internal void CheckSuspiciousPorts(TcpConnectionInformation[] connections)
    {
        foreach (var conn in connections)
        {
            if (conn.State != TcpState.Established)
                continue;

            var remotePort = conn.RemoteEndPoint.Port;
            var localPort = conn.LocalEndPoint.Port;
            var remoteIp = conn.RemoteEndPoint.Address.ToString();

            // Skip localhost connections
            if (IPAddress.IsLoopback(conn.RemoteEndPoint.Address))
                continue;

            // Check if remote port is suspicious
            if (SuspiciousPorts.Contains(remotePort))
            {
                EmitThreat(new ThreatEvent
                {
                    Source = "NetworkMonitor",
                    Severity = ThreatSeverity.Medium,
                    Title = "Suspicious Port Usage",
                    Description = $"Connection to {remoteIp}:{remotePort} — port {remotePort} is commonly " +
                                  $"associated with RATs, backdoors, or C2 frameworks. " +
                                  $"Local endpoint: {conn.LocalEndPoint}.",
                    AutoFixable = false
                });
            }
        }
    }

    /// <summary>
    /// Rule: Detect unusual outbound burst (>50 connections from one process in a poll window).
    /// Since GetActiveTcpConnections doesn't give PIDs directly, we approximate
    /// by counting total established outbound connections and looking at port ranges.
    /// </summary>
    internal void CheckOutboundBurst(TcpConnectionInformation[] connections)
    {
        // Count established outbound connections per local port range to detect bursts
        var outboundCount = connections.Count(c =>
            c.State == TcpState.Established &&
            !IPAddress.IsLoopback(c.RemoteEndPoint.Address));

        // If we see a huge spike compared to previous poll, that's suspicious
        if (_baselineEstablished && outboundCount > BurstThreshold &&
            outboundCount > _previousConnectionCount * 2)
        {
            EmitThreat(new ThreatEvent
            {
                Source = "NetworkMonitor",
                Severity = ThreatSeverity.High,
                Title = "Unusual Outbound Connection Burst",
                Description = $"Detected {outboundCount} active outbound connections (previous: {_previousConnectionCount}). " +
                              $"A sudden spike in outbound connections may indicate data exfiltration, " +
                              $"C2 beaconing, or a worm spreading.",
                AutoFixable = false
            });
        }
    }

    /// <summary>
    /// Rule: Detect connection churn (sudden spike in total connections between polls).
    /// </summary>
    internal void CheckConnectionChurn(int currentCount)
    {
        if (_baselineEstablished)
        {
            var delta = currentCount - _previousConnectionCount;
            if (delta > ChurnThreshold)
            {
                EmitThreat(new ThreatEvent
                {
                    Source = "NetworkMonitor",
                    Severity = ThreatSeverity.Medium,
                    Title = "Connection Churn Spike",
                    Description = $"Connection count jumped from {_previousConnectionCount} to {currentCount} " +
                                  $"(+{delta}) in {PollIntervalSeconds}s. High connection churn may indicate " +
                                  $"port scanning, C2 activity, or DDoS participation.",
                    AutoFixable = false
                });
            }
        }

        _previousConnectionCount = currentCount;
    }

    /// <summary>
    /// Rule: Detect ARP spoofing by monitoring gateway MAC changes.
    /// </summary>
    internal void CheckArpChanges()
    {
        var currentMac = GetGatewayMacAddress();
        if (currentMac == null || _lastGatewayMac == null)
        {
            _lastGatewayMac = currentMac;
            return;
        }

        if (!string.Equals(currentMac, _lastGatewayMac, StringComparison.OrdinalIgnoreCase))
        {
            EmitThreat(new ThreatEvent
            {
                Source = "NetworkMonitor",
                Severity = ThreatSeverity.Critical,
                Title = "Possible ARP Spoofing — Gateway MAC Changed",
                Description = $"Gateway MAC address changed from {_lastGatewayMac} to {currentMac}. " +
                              $"This may indicate an ARP spoofing / man-in-the-middle attack on the local network.",
                AutoFixable = false
            }, forceEmit: true);

            _lastGatewayMac = currentMac;
        }
    }

    // ── Helpers ──

    /// <summary>
    /// Get the process name that owns a specific listening port.
    /// Uses netstat-equivalent via Process queries.
    /// </summary>
    private static string? GetProcessForPort(int port)
    {
        try
        {
            // Use netstat to find the PID for the port
            var psi = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = $"-ano -p TCP",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return null;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.Contains($":{port} ") || trimmed.Contains($":{port}\t"))
                {
                    // Find the LISTENING line
                    if (!trimmed.Contains("LISTENING", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Last column is PID
                    var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0 && int.TryParse(parts[^1], out var pid))
                    {
                        try
                        {
                            using var proc = Process.GetProcessById(pid);
                            return proc.ProcessName;
                        }
                        catch { }
                    }
                }
            }
        }
        catch { }

        return null;
    }

    /// <summary>Get the executable path for a process by name.</summary>
    private static string? GetProcessPath(string processName)
    {
        try
        {
            var processes = Process.GetProcessesByName(processName);
            if (processes.Length > 0)
            {
                using var proc = processes[0];
                return proc.MainModule?.FileName;
            }
        }
        catch { }
        return null;
    }

    /// <summary>Verify Authenticode signature of an executable.</summary>
    private static bool VerifySignature(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            return cert != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Get the MAC address of the default gateway.
    /// Uses arp -a and parses the output.
    /// </summary>
    internal static string? GetGatewayMacAddress()
    {
        try
        {
            // Find default gateway IP
            var gatewayIp = GetDefaultGatewayIp();
            if (gatewayIp == null) return null;

            // Query ARP table
            var psi = new ProcessStartInfo
            {
                FileName = "arp",
                Arguments = "-a",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return null;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith(gatewayIp, StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        return parts[1].ToUpperInvariant(); // MAC address
                    }
                }
            }
        }
        catch { }

        return null;
    }

    /// <summary>Get the default gateway IP address.</summary>
    private static string? GetDefaultGatewayIp()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;

                var props = ni.GetIPProperties();
                foreach (var gw in props.GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(gw.Address) &&
                        gw.Address.ToString() != "0.0.0.0")
                    {
                        return gw.Address.ToString();
                    }
                }
            }
        }
        catch { }
        return null;
    }

    /// <summary>Emit a threat event with rate limiting.</summary>
    private void EmitThreat(ThreatEvent threat, bool forceEmit = false)
    {
        if (!forceEmit && ShouldRateLimit(threat))
            return;

        _threatLog.Add(threat);
        _logger.LogWarning("[{Severity}] {Title}: {Desc}", threat.Severity, threat.Title, threat.Description);
    }

    /// <summary>Rate-limit by threat content.</summary>
    private bool ShouldRateLimit(ThreatEvent threat)
    {
        var descSnippet = threat.Description?.Length > 80
            ? threat.Description[..80]
            : threat.Description ?? "";
        var key = $"{threat.Source}|{threat.Title}|{descSnippet}";

        if (_recentAlerts.TryGetValue(key, out var lastAlert))
        {
            if ((DateTimeOffset.UtcNow - lastAlert).TotalSeconds < RateLimitSeconds)
                return true;
        }

        _recentAlerts[key] = DateTimeOffset.UtcNow;
        return false;
    }

    /// <summary>Cleanup stale rate-limit entries.</summary>
    private void CleanupRateLimits()
    {
        var cutoff = DateTimeOffset.UtcNow.AddSeconds(-RateLimitSeconds * 2);
        foreach (var key in _recentAlerts.Keys.ToList())
        {
            if (_recentAlerts.TryGetValue(key, out var ts) && ts < cutoff)
                _recentAlerts.TryRemove(key, out _);
        }
    }
}

/// <summary>
/// Tracks connection burst information for a process.
/// </summary>
public class ConnectionBurst
{
    public int Count { get; set; }
    public DateTimeOffset WindowStart { get; set; }
}
