using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits network configuration: open ports, listening services, SMB/RDP exposure,
/// IPv6, Wi-Fi security, network profile, LLMNR/NetBIOS poisoning, and ARP anomalies.
/// </summary>
public class NetworkAudit : IAuditModule
{
    public string Name => "Network Audit";
    public string Category => "Network";
    public string Description => "Checks open ports, listening services, SMB/RDP exposure, IPv6, Wi-Fi security, network profile, LLMNR/NetBIOS, and ARP anomalies.";

    private static readonly HashSet<int> HighRiskPorts = new()
    {
        21,    // FTP
        23,    // Telnet
        135,   // RPC
        139,   // NetBIOS
        445,   // SMB
        1433,  // SQL Server
        1434,  // SQL Browser
        3389,  // RDP
        5900,  // VNC
        5985,  // WinRM HTTP
        5986,  // WinRM HTTPS
    };

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            await CheckListeningPorts(result, cancellationToken);
            await CheckSmbExposure(result, cancellationToken);
            await CheckRdpExposure(result, cancellationToken);
            await CheckWinRm(result, cancellationToken);
            await CheckDnsSettings(result, cancellationToken);
            await CheckNetworkProfile(result, cancellationToken);
            await CheckWiFiSecurity(result, cancellationToken);
            await CheckLlmnrNetBios(result, cancellationToken);
            await CheckArpAnomalies(result, cancellationToken);
            await CheckIPv6Exposure(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckListeningPorts(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
              Select-Object LocalPort, OwningProcess | 
              Sort-Object LocalPort -Unique | 
              ForEach-Object { 
                  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                  '{0}|{1}' -f $_.LocalPort, $proc.ProcessName 
              }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var highRiskOpen = new List<string>();

        foreach (var line in lines)
        {
            var parts = line.Split('|');
            if (parts.Length >= 2 && int.TryParse(parts[0], out int port))
            {
                var processName = parts[1];
                if (HighRiskPorts.Contains(port))
                {
                    highRiskOpen.Add($"Port {port} ({processName})");
                }
            }
        }

        if (highRiskOpen.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"High-Risk Ports Listening ({highRiskOpen.Count})",
                $"The following high-risk ports are open and listening: {string.Join(", ", highRiskOpen)}",
                Category,
                "Review each listening service and disable any that are not needed. Block unused ports in the firewall.",
                "Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Sort-Object LocalPort | Format-Table"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Common High-Risk Ports Exposed",
                "No commonly targeted high-risk ports were found listening.",
                Category));
        }

        result.Findings.Add(Finding.Info(
            $"Total Listening Ports: {lines.Length}",
            $"{lines.Length} TCP ports are currently in LISTEN state.",
            Category));
    }

    private async Task CheckSmbExposure(AuditResult result, CancellationToken ct)
    {
        // Check SMBv1
        var smbv1 = await ShellHelper.RunPowerShellAsync(
            @"try { (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { 'ERROR' }", ct);

        if (smbv1.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                "SMBv1 Protocol Enabled",
                "SMBv1 is enabled. This is a critical vulnerability exploited by WannaCry, EternalBlue, and other attacks.",
                Category,
                "Disable SMBv1 immediately. It is deprecated and insecure.",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"));
        }
        else if (smbv1.Trim().Equals("False", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "SMBv1 Protocol Disabled",
                "SMBv1 is properly disabled.",
                Category));
        }

        // Check SMB signing
        var smbSigning = await ShellHelper.RunPowerShellAsync(
            @"try { (Get-SmbServerConfiguration).RequireSecuritySignature } catch { 'ERROR' }", ct);

        if (smbSigning.Trim().Equals("False", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "SMB Signing Not Required",
                "SMB packet signing is not required. This allows potential man-in-the-middle attacks on file sharing.",
                Category,
                "Enable SMB signing requirement.",
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"));
        }
        else if (smbSigning.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "SMB Signing Required",
                "SMB packet signing is required for all connections.",
                Category));
        }

        // Check for open shares
        var shares = await ShellHelper.RunPowerShellAsync(
            @"Get-SmbShare | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne 'IPC$' } | Select-Object -ExpandProperty Name", ct);

        var shareList = shares.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => !string.IsNullOrWhiteSpace(s)).ToList();

        if (shareList.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Non-Default SMB Shares ({shareList.Count})",
                $"Custom SMB shares found: {string.Join(", ", shareList)}. Verify these shares are intentional and properly secured.",
                Category));
        }
    }

    private async Task CheckRdpExposure(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections", ct);

        if (output.Trim() == "0")
        {
            // RDP is enabled — check NLA
            var nla = await ShellHelper.RunPowerShellAsync(
                @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication", ct);

            if (nla.Trim() == "0")
            {
                result.Findings.Add(Finding.Critical(
                    "RDP Enabled Without NLA",
                    "Remote Desktop is enabled but Network Level Authentication (NLA) is DISABLED. This allows unauthenticated users to reach the login screen.",
                    Category,
                    "Enable Network Level Authentication for RDP.",
                    @"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1"));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "RDP Enabled with NLA",
                    "Remote Desktop is enabled with Network Level Authentication. Ensure RDP is only accessible from trusted networks.",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "RDP Disabled",
                "Remote Desktop Protocol is disabled.",
                Category));
        }
    }

    private async Task CheckWinRm(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"try { $status = Get-Service WinRM -ErrorAction SilentlyContinue; $status.Status } catch { 'NotFound' }", ct);

        if (output.Trim().Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "WinRM Service Running",
                "Windows Remote Management (WinRM) service is running. This allows remote PowerShell sessions.",
                Category,
                "Disable WinRM if remote management is not needed.",
                "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "WinRM Service Not Running",
                "Windows Remote Management service is not running.",
                Category));
        }
    }

    private async Task CheckDnsSettings(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-DnsClientServerAddress -AddressFamily IPv4 | 
              Where-Object { $_.ServerAddresses.Count -gt 0 } | 
              Select-Object -ExpandProperty ServerAddresses -Unique", ct);

        if (!string.IsNullOrWhiteSpace(output))
        {
            var dnsServers = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            result.Findings.Add(Finding.Info(
                $"DNS Servers Configured ({dnsServers.Length})",
                $"DNS servers in use: {string.Join(", ", dnsServers)}",
                Category));
        }
    }

    private async Task CheckNetworkProfile(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' } |
              ForEach-Object { '{0}|{1}' -f $_.Name, $_.NetworkCategory }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var publicNets = new List<string>();

        foreach (var line in lines)
        {
            var parts = line.Split('|');
            if (parts.Length >= 2)
            {
                var name = parts[0];
                var category = parts[1];

                if (category.Equals("Public", StringComparison.OrdinalIgnoreCase))
                {
                    publicNets.Add(name);
                }
            }
        }

        if (publicNets.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"Public Network Profile Active ({publicNets.Count})",
                $"The following network(s) are set to Public profile: {string.Join(", ", publicNets)}. " +
                "Public profile exposes the machine to stricter firewall rules but may indicate an untrusted network connection. " +
                "If this is your home/office network, switch to Private for local sharing or keep Public for security.",
                Category,
                "Set the network to Private if it is a trusted network, or keep Public for untrusted networks.",
                @"Set-NetConnectionProfile -Name '<NetworkName>' -NetworkCategory Private"));
        }
        else if (lines.Length > 0)
        {
            result.Findings.Add(Finding.Pass(
                "Network Profile: Private/Domain",
                "All active network connections are set to Private or Domain profile.",
                Category));
        }
    }

    private async Task CheckWiFiSecurity(AuditResult result, CancellationToken ct)
    {
        // Use netsh to get current WiFi connection info (fast, no PowerShell module needed)
        var output = await ShellHelper.RunNetshAsync("wlan show interfaces", ct);

        if (string.IsNullOrWhiteSpace(output) || output.Contains("not running", StringComparison.OrdinalIgnoreCase))
        {
            // WLAN not available or no wireless adapter
            return;
        }

        // Parse SSID, authentication, and cipher
        string? ssid = null;
        string? auth = null;
        string? cipher = null;
        string? state = null;

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) && !line.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
            {
                var idx = line.IndexOf(':');
                if (idx >= 0) ssid = line[(idx + 1)..].Trim();
            }
            else if (line.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
            {
                var idx = line.IndexOf(':');
                if (idx >= 0) auth = line[(idx + 1)..].Trim();
            }
            else if (line.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase))
            {
                var idx = line.IndexOf(':');
                if (idx >= 0) cipher = line[(idx + 1)..].Trim();
            }
            else if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase))
            {
                var idx = line.IndexOf(':');
                if (idx >= 0) state = line[(idx + 1)..].Trim();
            }
        }

        if (state == null || !state.Contains("connected", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Info(
                "Wi-Fi Not Connected",
                "No active Wi-Fi connection detected.",
                Category));
            return;
        }

        if (string.IsNullOrEmpty(auth) || string.IsNullOrEmpty(ssid))
            return;

        // Evaluate Wi-Fi security strength
        if (auth.Contains("Open", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                $"Open Wi-Fi Network: {ssid}",
                $"Connected to an open (unencrypted) Wi-Fi network '{ssid}'. All traffic can be intercepted.",
                Category,
                "Disconnect from open networks. Use a VPN if you must connect to open Wi-Fi.",
                "netsh wlan disconnect"));
        }
        else if (auth.Contains("WEP", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                $"WEP Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' using WEP encryption, which can be cracked in minutes.",
                Category,
                "Switch to WPA2 or WPA3 encryption on your router immediately.",
                "netsh wlan disconnect"));
        }
        else if (auth.Contains("WPA-Personal", StringComparison.OrdinalIgnoreCase) &&
                 !auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase) &&
                 !auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                $"WPA1 Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' using WPA1 (TKIP), which has known vulnerabilities.",
                Category,
                "Upgrade your router to use WPA2-AES or WPA3.",
                "netsh wlan disconnect"));
        }
        else if (auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                $"WPA3 Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' with WPA3 encryption (strongest available). Cipher: {cipher ?? "N/A"}.",
                Category));
        }
        else if (auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase))
        {
            var cipherInfo = cipher ?? "N/A";
            if (cipherInfo.Contains("TKIP", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(Finding.Warning(
                    $"WPA2-TKIP Wi-Fi: {ssid}",
                    $"Connected to Wi-Fi network '{ssid}' using WPA2 with TKIP cipher. TKIP has known weaknesses.",
                    Category,
                    "Configure your router to use WPA2-AES (CCMP) instead of TKIP.",
                "netsh wlan disconnect"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    $"WPA2-AES Wi-Fi Security: {ssid}",
                    $"Connected to Wi-Fi network '{ssid}' with WPA2-AES encryption. Cipher: {cipherInfo}.",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Info(
                $"Wi-Fi Security: {auth}",
                $"Connected to Wi-Fi network '{ssid}' with authentication: {auth}, cipher: {cipher ?? "N/A"}.",
                Category));
        }
    }

    private async Task CheckLlmnrNetBios(AuditResult result, CancellationToken ct)
    {
        // Check LLMNR (Link-Local Multicast Name Resolution) — used in LLMNR/NBT-NS poisoning attacks
        var llmnrOutput = await ShellHelper.RunPowerShellAsync(
            @"try {
                $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue
                if ($key) { $key.EnableMulticast } else { 'NOT_SET' }
            } catch { 'ERROR' }", ct);

        var llmnrValue = llmnrOutput.Trim();
        if (llmnrValue == "0")
        {
            result.Findings.Add(Finding.Pass(
                "LLMNR Disabled",
                "Link-Local Multicast Name Resolution is disabled, preventing LLMNR poisoning attacks.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning(
                "LLMNR Enabled (Poisoning Risk)",
                "Link-Local Multicast Name Resolution (LLMNR) is enabled. Attackers on the local network can respond to LLMNR queries " +
                "to capture NTLMv2 hashes (tools like Responder/Inveigh). This is one of the most common internal network attack vectors.",
                Category,
                "Disable LLMNR via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution.",
                @"New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0"));
        }

        // Check NetBIOS over TCP/IP — also used in NBT-NS poisoning
        var netbiosOutput = await ShellHelper.RunPowerShellAsync(
            @"Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
              ForEach-Object { '{0}|{1}' -f $_.Description, $_.TcpipNetbiosOptions }", ct);

        var netbiosLines = netbiosOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var enabledAdapters = new List<string>();

        foreach (var line in netbiosLines)
        {
            var parts = line.Split('|');
            if (parts.Length >= 2)
            {
                var adapter = parts[0];
                var option = parts[1].Trim();
                // TcpipNetbiosOptions: 0 = Default (enabled via DHCP), 1 = Enabled, 2 = Disabled
                if (option == "0" || option == "1")
                {
                    enabledAdapters.Add(adapter);
                }
            }
        }

        if (enabledAdapters.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"NetBIOS over TCP/IP Enabled ({enabledAdapters.Count} adapter(s))",
                $"NetBIOS Name Service (NBT-NS) is enabled on: {string.Join("; ", enabledAdapters.Take(3))}. " +
                "Like LLMNR, NBT-NS can be poisoned to capture credentials on the local network.",
                Category,
                "Disable NetBIOS over TCP/IP on each adapter: Network Adapter Properties > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP.",
                @"Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.SetTcpipNetbios(2) }"));
        }
        else if (netbiosLines.Length > 0)
        {
            result.Findings.Add(Finding.Pass(
                "NetBIOS over TCP/IP Disabled",
                "NetBIOS Name Service is disabled on all network adapters.",
                Category));
        }
    }

    private async Task CheckArpAnomalies(AuditResult result, CancellationToken ct)
    {
        // Parse ARP table looking for duplicate MACs (potential ARP spoofing)
        var output = await ShellHelper.RunCmdAsync("arp -a", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var macToIps = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        int entryCount = 0;

        foreach (var line in lines)
        {
            // ARP table lines look like: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3)
            {
                var ip = parts[0];
                var mac = parts[1];

                // Validate it looks like an IP and MAC
                if (ip.Contains('.') && mac.Contains('-') && mac.Length >= 17)
                {
                    // Skip broadcast/multicast MACs
                    if (mac.Equals("ff-ff-ff-ff-ff-ff", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (mac.StartsWith("01-00-5e", StringComparison.OrdinalIgnoreCase)) // IPv4 multicast
                        continue;
                    if (mac.StartsWith("33-33", StringComparison.OrdinalIgnoreCase)) // IPv6 multicast
                        continue;

                    entryCount++;
                    if (!macToIps.TryGetValue(mac, out var ips))
                    {
                        ips = new List<string>();
                        macToIps[mac] = ips;
                    }
                    ips.Add(ip);
                }
            }
        }

        // Check for duplicate MACs (same MAC for different IPs = possible ARP spoofing)
        var duplicates = macToIps.Where(kv => kv.Value.Count > 1).ToList();

        if (duplicates.Count > 0)
        {
            var details = string.Join("; ", duplicates.Select(d =>
                $"MAC {d.Key} → IPs: {string.Join(", ", d.Value)}"));

            result.Findings.Add(Finding.Warning(
                $"Duplicate MAC Addresses Detected ({duplicates.Count})",
                $"Multiple IP addresses share the same MAC address in the ARP table, which could indicate ARP spoofing: {details}",
                Category,
                "Investigate the duplicate MAC entries. Use static ARP entries for critical hosts (e.g., default gateway) if ARP spoofing is suspected.",
                "arp -a"));
        }
        else if (entryCount > 0)
        {
            result.Findings.Add(Finding.Pass(
                "ARP Table: No Anomalies",
                $"ARP table has {entryCount} entries with no duplicate MAC addresses detected.",
                Category));
        }
    }

    private async Task CheckIPv6Exposure(AuditResult result, CancellationToken ct)
    {
        // Check if IPv6 is enabled and if there are global IPv6 addresses
        var output = await ShellHelper.RunPowerShellAsync(
            @"$addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | 
              Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^fe80' -and $_.IPAddress -ne '::1' }
              $addrs | ForEach-Object { '{0}|{1}|{2}' -f $_.IPAddress, $_.InterfaceAlias, $_.PrefixOrigin }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains('|')).ToList();

        if (lines.Count > 0)
        {
            var addresses = lines.Select(l => l.Split('|')[0]).Take(5).ToList();
            result.Findings.Add(Finding.Info(
                $"Global IPv6 Addresses Active ({lines.Count})",
                $"This machine has {lines.Count} global IPv6 address(es): {string.Join(", ", addresses)}. " +
                "Ensure IPv6 firewall rules are configured. Many firewalls only filter IPv4 traffic, leaving IPv6 unprotected.",
                Category,
                "If IPv6 is not needed, disable it on network adapters. If needed, ensure firewall rules cover IPv6 traffic."));
        }

        // Check for IPv6 transition tunneling (Teredo, 6to4, ISATAP) — can bypass IPv4 firewalls
        var tunnelingOutput = await ShellHelper.RunNetshAsync("interface teredo show state", ct);

        if (!string.IsNullOrWhiteSpace(tunnelingOutput))
        {
            bool teredoActive = false;
            foreach (var rawLine in tunnelingOutput.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("Type", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx >= 0)
                    {
                        var typeValue = line[(idx + 1)..].Trim();
                        if (!typeValue.Equals("disabled", StringComparison.OrdinalIgnoreCase) &&
                            !typeValue.Equals("default", StringComparison.OrdinalIgnoreCase))
                        {
                            teredoActive = true;
                        }
                    }
                }
            }

            if (teredoActive)
            {
                result.Findings.Add(Finding.Warning(
                    "Teredo IPv6 Tunnel Active",
                    "Teredo IPv6 tunneling is active. This encapsulates IPv6 traffic in IPv4 UDP packets, " +
                    "which can bypass IPv4-only firewalls and security monitoring tools.",
                    Category,
                    "Disable Teredo if IPv6 tunneling is not needed.",
                    "netsh interface teredo set state disabled"));
            }
        }
    }
}
