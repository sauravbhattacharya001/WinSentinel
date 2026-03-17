using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using WinSentinel.Core.Helpers;

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

    /// <summary>Known gateway MAC address (for ARP spoofing detection).</summary>
    private string? _lastGatewayMac;

    /// <summary>Shared rate limiter for threat alert dedup.</summary>
    private readonly ThreatRateLimiter _rateLimiter = new(RateLimitSeconds);

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
        1234, 31337, 12345, 54321, // Classic backdoor ports
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
            catch (OperationCanceledException ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        }

        _knownListeningPorts.Clear();
        _rateLimiter.Clear();
        _lastGatewayMac = null;
        _baselineEstablished = false;
    }

    // ── Baseline ──

    private void EstablishBaseline()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();

        // Record current listening ports — single netstat call for all ports
        var portMap = BuildListeningPortProcessMap();
        foreach (var listener in properties.GetActiveTcpListeners())
        {
            var processName = portMap.GetValueOrDefault(listener.Port) ?? "unknown";
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

        // Track remote IPs already alerted during this poll cycle to avoid
        // duplicate alerts when a connection matches multiple rules (e.g.,
        // known-bad IP + Tor exit node + suspicious port).
        var alertedRemoteIps = new HashSet<string>();

        // Pre-compute established connections grouped by remote IP to avoid
        // redundant O(n) scans in each detection method. Each method previously
        // iterated all connections and then did nested Count/Where lookups,
        // resulting in O(n²) per method. Now the grouping is O(n) and each
        // method iterates only the groups.
        var establishedByRemoteIp = connections
            .Where(c => c.State == TcpState.Established)
            .GroupBy(c => c.RemoteEndPoint.Address.ToString())
            .ToDictionary(
                g => g.Key,
                g => g.ToList());

        // 3. Check for known-bad IPs (highest priority — checked first)
        CheckKnownBadIps(connections, alertedRemoteIps, establishedByRemoteIp);

        // 4. Check for Tor connections (skip IPs already alerted above)
        CheckTorConnections(connections, alertedRemoteIps, establishedByRemoteIp);

        // 5. Check for suspicious port usage (skip IPs already alerted above)
        CheckSuspiciousPorts(connections, alertedRemoteIps, establishedByRemoteIp);

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

        // Build a port→process map once for all new ports (instead of
        // spawning a separate netstat process per port — see issue #114).
        Dictionary<int, string>? portProcessMap = null;
        if (_baselineEstablished)
        {
            var newPorts = listeners.Where(l => !_knownListeningPorts.ContainsKey(l.Port)).ToList();
            if (newPorts.Count > 0)
            {
                portProcessMap = BuildListeningPortProcessMap();
            }
        }

        foreach (var listener in listeners)
        {
            currentPorts.Add(listener.Port);

            if (!_knownListeningPorts.ContainsKey(listener.Port) && _baselineEstablished)
            {
                portProcessMap?.TryGetValue(listener.Port, out var processName);

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
    internal void CheckKnownBadIps(TcpConnectionInformation[] connections, HashSet<string>? alertedRemoteIps = null,
        Dictionary<string, List<TcpConnectionInformation>>? groupedByIp = null)
    {
        // Use pre-computed groups when available (O(1) per IP instead of O(n) scans).
        var ipGroups = groupedByIp ?? connections
            .Where(c => c.State == TcpState.Established)
            .GroupBy(c => c.RemoteEndPoint.Address.ToString())
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var (remoteIp, conns) in ipGroups)
        {
            foreach (var prefix in KnownBadIpPrefixes)
            {
                if (remoteIp.StartsWith(prefix))
                {
                    var ports = conns
                        .Select(c => c.RemoteEndPoint.Port)
                        .Distinct()
                        .OrderBy(p => p)
                        .ToList();

                    var portList = string.Join(", ", ports);

                    EmitThreat(new ThreatEvent
                    {
                        Source = "NetworkMonitor",
                        Severity = ThreatSeverity.Critical,
                        Title = "Connection to Known-Malicious IP",
                        Description = $"{conns.Count} active connection(s) to known-malicious IP {remoteIp} " +
                                      $"on port(s) {portList}. " +
                                      $"This IP is in a known C2/malware hosting range.",
                        AutoFixable = InputSanitizer.SanitizeIpAddress(remoteIp) != null,
                        FixCommand = InputSanitizer.SanitizeIpAddress(remoteIp) is { } safeMalIp
                            ? $"netsh advfirewall firewall add rule name=\"Block {safeMalIp}\" dir=out action=block remoteip={safeMalIp}"
                            : null
                    });
                    alertedRemoteIps?.Add(remoteIp);
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Rule: Detect connections to Tor exit nodes.
    /// </summary>
    internal void CheckTorConnections(TcpConnectionInformation[] connections, HashSet<string>? alertedRemoteIps = null,
        Dictionary<string, List<TcpConnectionInformation>>? groupedByIp = null)
    {
        // Track IPs already alerted within this poll cycle to avoid duplicate
        // alerts when multiple connections exist to the same Tor exit node.
        var seenTorIps = new HashSet<string>();

        foreach (var conn in connections)
        {
            if (conn.State != TcpState.Established)
                continue;

            var remoteIp = conn.RemoteEndPoint.Address.ToString();
            var remotePort = conn.RemoteEndPoint.Port;
            var localPort = conn.LocalEndPoint.Port;

            // Skip IPs already alerted by a higher-priority rule (e.g., known-bad IP)
            if (alertedRemoteIps?.Contains(remoteIp) == true)
                continue;

            // Skip IPs already alerted within this Tor check
            if (seenTorIps.Contains(remoteIp))
            {
                alertedRemoteIps?.Add(remoteIp);
                continue;
            }

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
                seenTorIps.Add(remoteIp);
                alertedRemoteIps?.Add(remoteIp);
                continue;
            }

            // Check for connections to known Tor exit nodes
            foreach (var prefix in TorExitNodePrefixes)
            {
                if (remoteIp.StartsWith(prefix))
                {
                    var connCount = groupedByIp?.GetValueOrDefault(remoteIp)?.Count
                        ?? connections.Count(c =>
                            c.State == TcpState.Established &&
                            c.RemoteEndPoint.Address.ToString() == remoteIp);

                    EmitThreat(new ThreatEvent
                    {
                        Source = "NetworkMonitor",
                        Severity = ThreatSeverity.High,
                        Title = "Connection to Tor Exit Node",
                        Description = $"{connCount} connection(s) to known Tor exit node IP {remoteIp}:{remotePort}. " +
                                      $"Local endpoint: {conn.LocalEndPoint}. " +
                                      $"This may indicate anonymized C2 communication.",
                        AutoFixable = InputSanitizer.SanitizeIpAddress(remoteIp) != null,
                        FixCommand = InputSanitizer.SanitizeIpAddress(remoteIp) is { } safeTorIp
                            ? $"netsh advfirewall firewall add rule name=\"Block Tor {safeTorIp}\" dir=out action=block remoteip={safeTorIp}"
                            : null
                    });
                    seenTorIps.Add(remoteIp);
                    alertedRemoteIps?.Add(remoteIp);
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Rule: Detect connections using suspicious/common RAT ports.
    /// </summary>
    internal void CheckSuspiciousPorts(TcpConnectionInformation[] connections, HashSet<string>? alertedRemoteIps = null,
        Dictionary<string, List<TcpConnectionInformation>>? groupedByIp = null)
    {
        // Track remote IP:port pairs already alerted to avoid duplicate alerts
        // when multiple connections exist to the same suspicious endpoint.
        var seenEndpoints = new HashSet<string>();

        foreach (var conn in connections)
        {
            if (conn.State != TcpState.Established)
                continue;

            var remotePort = conn.RemoteEndPoint.Port;
            var remoteIp = conn.RemoteEndPoint.Address.ToString();

            // Skip localhost connections
            if (IPAddress.IsLoopback(conn.RemoteEndPoint.Address))
                continue;

            // Skip IPs already alerted by a higher-priority rule
            if (alertedRemoteIps?.Contains(remoteIp) == true)
                continue;

            // Check if remote port is suspicious
            if (SuspiciousPorts.Contains(remotePort))
            {
                var endpointKey = $"{remoteIp}:{remotePort}";
                if (seenEndpoints.Contains(endpointKey))
                    continue;

                // Use pre-computed groups to get connection count in O(1) instead of O(n).
                var connCount = groupedByIp?.GetValueOrDefault(remoteIp)
                    ?.Count(c => c.RemoteEndPoint.Port == remotePort)
                    ?? connections.Count(c =>
                        c.State == TcpState.Established &&
                        c.RemoteEndPoint.Address.ToString() == remoteIp &&
                        c.RemoteEndPoint.Port == remotePort);

                EmitThreat(new ThreatEvent
                {
                    Source = "NetworkMonitor",
                    Severity = ThreatSeverity.Medium,
                    Title = "Suspicious Port Usage",
                    Description = $"{connCount} connection(s) to {remoteIp}:{remotePort} — port {remotePort} is commonly " +
                                  $"associated with RATs, backdoors, or C2 frameworks.",
                    AutoFixable = false
                });
                seenEndpoints.Add(endpointKey);
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
    /// Build a map of listening port → process name from a single netstat call.
    /// Replaces per-port GetProcessForPort calls to avoid spawning N processes
    /// when N new ports appear in one poll cycle (issue #114).
    /// </summary>
    private static Dictionary<int, string> BuildListeningPortProcessMap()
    {
        var map = new Dictionary<int, string>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano -p TCP",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return map;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(5000);

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (!trimmed.Contains("LISTENING", StringComparison.OrdinalIgnoreCase))
                    continue;

                var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                // Parse local address port (format: 0.0.0.0:PORT or [::]:PORT)
                var addrPart = parts[1];
                var colonIdx = addrPart.LastIndexOf(':');
                if (colonIdx >= 0 &&
                    int.TryParse(addrPart[(colonIdx + 1)..], out var port) &&
                    int.TryParse(parts[^1], out var pid))
                {
                    if (map.ContainsKey(port)) continue;
                    try
                    {
                        using var proc = Process.GetProcessById(pid);
                        map[port] = proc.ProcessName;
                    }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
                }
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        return map;
    }

    /// <summary>Get the executable path for a process by name.</summary>
    private static string? GetProcessPath(string processName)
    {
        Process[]? processes = null;
        try
        {
            processes = Process.GetProcessesByName(processName);
            if (processes.Length > 0)
            {
                return processes[0].MainModule?.FileName;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        finally
        {
            // Dispose ALL returned Process objects to avoid native handle leaks.
            // Previously only processes[0] was disposed via 'using', leaking the rest.
            if (processes != null)
            {
                foreach (var p in processes) p.Dispose();
            }
        }
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
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

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
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
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
    private bool ShouldRateLimit(ThreatEvent threat) => _rateLimiter.ShouldRateLimit(threat);

    /// <summary>Cleanup stale rate-limit entries.</summary>
    private void CleanupRateLimits() => _rateLimiter.PurgeStale();
}
