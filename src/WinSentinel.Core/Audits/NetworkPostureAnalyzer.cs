using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="NetworkAudit"/> module.
///
/// Every network-posture decision lives here - the rules that turn collected raw
/// state (listening ports, SMB/RDP/WinRM exposure, DNS servers, the active network
/// profile, the connected Wi-Fi's authentication/cipher, LLMNR + NetBIOS settings,
/// the ARP table and global IPv6 / Teredo tunnelling) into <see cref="Finding"/>
/// objects.
///
/// Nothing here touches PowerShell, netsh, cmd, WMI, the registry, the clock or the
/// console, so every threshold (which ports are "high risk", the RDP-without-NLA
/// critical, the Wi-Fi WEP/WPA classification, the duplicate-MAC ARP heuristic, ...)
/// can be unit-tested directly with synthetic <see cref="NetworkState"/> instances.
/// <see cref="NetworkAudit"/> owns only the collection of raw data and delegates
/// every decision to this class.
///
/// Mirrors the established <see cref="PowerShellSecurityAnalyzer"/> /
/// <see cref="BrowserSecurityAnalyzer"/> / <see cref="EncryptionAnalyzer"/> /
/// <see cref="EventLogAnalyzer"/> / <see cref="IdentityCredentialAnalyzer"/> pattern.
/// </summary>
public static class NetworkPostureAnalyzer
{
    /// <summary>Category label shared with <see cref="NetworkAudit"/>.</summary>
    public const string Category = "Network";

    /// <summary>
    /// TCP ports that should rarely be exposed on a client machine - they are the
    /// classic lateral-movement / remote-access targets.
    /// </summary>
    public static readonly IReadOnlySet<int> HighRiskPorts = new HashSet<int>
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

    // ──────────────────────────────────────────────────────────────────────
    // State DTO
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>A single listening TCP port with its owning process name.</summary>
    public sealed class ListeningPort
    {
        public int Port { get; set; }
        public string ProcessName { get; set; } = "";

        public ListeningPort() { }
        public ListeningPort(int port, string processName)
        {
            Port = port;
            ProcessName = processName ?? "";
        }
    }

    /// <summary>An ARP table entry (IPv4 + MAC).</summary>
    public sealed class ArpEntry
    {
        public string Ip { get; set; } = "";
        public string Mac { get; set; } = "";

        public ArpEntry() { }
        public ArpEntry(string ip, string mac)
        {
            Ip = ip ?? "";
            Mac = mac ?? "";
        }
    }

    /// <summary>Tri-state for a setting that may be unknown / unreadable.</summary>
    public enum Toggle { Unknown = 0, Enabled, Disabled }

    /// <summary>
    /// Data transfer object for the network environment. All checks operate on this
    /// record so they can be unit-tested without running real PowerShell/netsh/cmd
    /// commands.
    /// </summary>
    public sealed class NetworkState
    {
        // Listening ports
        public List<ListeningPort> ListeningPorts { get; set; } = new();

        // SMB
        public Toggle Smbv1 { get; set; } = Toggle.Unknown;
        public Toggle SmbSigningRequired { get; set; } = Toggle.Unknown;
        public List<string> NonDefaultShares { get; set; } = new();

        // RDP
        public bool RdpEnabled { get; set; }
        public bool RdpNlaEnabled { get; set; } = true;

        // WinRM
        public bool WinRmRunning { get; set; }

        // DNS
        public List<string> DnsServers { get; set; } = new();

        // Network profile - names of any active connection on the Public category.
        public List<string> PublicNetworks { get; set; } = new();
        public int ActiveNetworkCount { get; set; }

        // Wi-Fi (only meaningful when connected to a wireless network)
        public bool WiFiConnected { get; set; }
        public string? WiFiSsid { get; set; }
        public string? WiFiAuth { get; set; }
        public string? WiFiCipher { get; set; }

        // LLMNR ("EnableMulticast" GPO value): Disabled = key explicitly set to 0.
        public Toggle Llmnr { get; set; } = Toggle.Unknown;

        // NetBIOS over TCP/IP - adapters where NBT is still enabled (option 0 or 1).
        public List<string> NetBiosEnabledAdapters { get; set; } = new();
        // Number of IP-enabled adapters seen at all (so "all disabled" can Pass).
        public int NetBiosAdapterCount { get; set; }

        // ARP table
        public List<ArpEntry> ArpEntries { get; set; } = new();
        public bool ArpQueryFailed { get; set; }
        public string? ArpError { get; set; }

        // IPv6
        public List<string> GlobalIPv6Addresses { get; set; } = new();
        public bool TeredoActive { get; set; }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Aggregate entry point
    // ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs every network-posture check against <paramref name="state"/> and returns
    /// the findings in a stable order. Pure - no I/O.
    /// </summary>
    public static List<Finding> Analyze(NetworkState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var findings = new List<Finding>();
        findings.AddRange(CheckListeningPorts(state));
        findings.AddRange(CheckSmb(state));
        findings.Add(CheckRdp(state));
        findings.Add(CheckWinRm(state));
        var dns = CheckDns(state);
        if (dns != null) findings.Add(dns);
        findings.AddRange(CheckNetworkProfile(state));
        var wifi = CheckWiFi(state);
        if (wifi != null) findings.Add(wifi);
        findings.AddRange(CheckLlmnrNetBios(state));
        findings.Add(CheckArp(state));
        findings.AddRange(CheckIPv6(state));
        return findings;
    }

    // ── Listening ports ─────────────────────────────────────────────────────

    /// <summary>
    /// Flags any high-risk listening ports and always emits the total-count info.
    /// </summary>
    public static List<Finding> CheckListeningPorts(NetworkState state)
    {
        var findings = new List<Finding>();
        var highRisk = state.ListeningPorts
            .Where(p => HighRiskPorts.Contains(p.Port))
            .Select(p => $"Port {p.Port} ({p.ProcessName})")
            .ToList();

        if (highRisk.Count > 0)
        {
            findings.Add(Finding.Warning(
                $"High-Risk Ports Listening ({highRisk.Count})",
                $"The following high-risk ports are open and listening: {string.Join(", ", highRisk)}",
                Category,
                "Review each listening service and disable any that are not needed. Block unused ports in the firewall.",
                "Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Sort-Object LocalPort | Format-Table"));
        }
        else
        {
            findings.Add(Finding.Pass(
                "No Common High-Risk Ports Exposed",
                "No commonly targeted high-risk ports were found listening.",
                Category));
        }

        findings.Add(Finding.Info(
            $"Total Listening Ports: {state.ListeningPorts.Count}",
            $"{state.ListeningPorts.Count} TCP ports are currently in LISTEN state.",
            Category));

        return findings;
    }

    // ── SMB ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates SMBv1, SMB signing, and non-default shares. Unknown (unreadable)
    /// states emit no finding for that sub-check.
    /// </summary>
    public static List<Finding> CheckSmb(NetworkState state)
    {
        var findings = new List<Finding>();

        // SMBv1
        if (state.Smbv1 == Toggle.Enabled)
        {
            findings.Add(Finding.Critical(
                "SMBv1 Protocol Enabled",
                "SMBv1 is enabled. This is a critical vulnerability exploited by WannaCry, EternalBlue, and other attacks.",
                Category,
                "Disable SMBv1 immediately. It is deprecated and insecure.",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"));
        }
        else if (state.Smbv1 == Toggle.Disabled)
        {
            findings.Add(Finding.Pass(
                "SMBv1 Protocol Disabled",
                "SMBv1 is properly disabled.",
                Category));
        }

        // SMB signing
        if (state.SmbSigningRequired == Toggle.Disabled)
        {
            findings.Add(Finding.Warning(
                "SMB Signing Not Required",
                "SMB packet signing is not required. This allows potential man-in-the-middle attacks on file sharing.",
                Category,
                "Enable SMB signing requirement.",
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"));
        }
        else if (state.SmbSigningRequired == Toggle.Enabled)
        {
            findings.Add(Finding.Pass(
                "SMB Signing Required",
                "SMB packet signing is required for all connections.",
                Category));
        }

        // Non-default shares
        if (state.NonDefaultShares.Count > 0)
        {
            findings.Add(Finding.Info(
                $"Non-Default SMB Shares ({state.NonDefaultShares.Count})",
                $"Custom SMB shares found: {string.Join(", ", state.NonDefaultShares)}. Verify these shares are intentional and properly secured.",
                Category));
        }

        return findings;
    }

    // ── RDP ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates RDP exposure. Critical when RDP is enabled without Network Level
    /// Authentication; otherwise Info (enabled + NLA) or Pass (disabled).
    /// </summary>
    public static Finding CheckRdp(NetworkState state)
    {
        if (!state.RdpEnabled)
        {
            return Finding.Pass(
                "RDP Disabled",
                "Remote Desktop Protocol is disabled.",
                Category);
        }

        if (!state.RdpNlaEnabled)
        {
            return Finding.Critical(
                "RDP Enabled Without NLA",
                "Remote Desktop is enabled but Network Level Authentication (NLA) is DISABLED. This allows unauthenticated users to reach the login screen.",
                Category,
                "Enable Network Level Authentication for RDP.",
                @"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1");
        }

        return Finding.Info(
            "RDP Enabled with NLA",
            "Remote Desktop is enabled with Network Level Authentication. Ensure RDP is only accessible from trusted networks.",
            Category);
    }

    // ── WinRM ─────────────────────────────────────────────────────────────────

    public static Finding CheckWinRm(NetworkState state)
    {
        if (state.WinRmRunning)
        {
            return Finding.Warning(
                "WinRM Service Running",
                "Windows Remote Management (WinRM) service is running. This allows remote PowerShell sessions.",
                Category,
                "Disable WinRM if remote management is not needed.",
                "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled");
        }

        return Finding.Pass(
            "WinRM Service Not Running",
            "Windows Remote Management service is not running.",
            Category);
    }

    // ── DNS ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// Informational list of configured DNS servers, or <c>null</c> when none were
    /// detected.
    /// </summary>
    public static Finding? CheckDns(NetworkState state)
    {
        if (state.DnsServers.Count == 0) return null;

        return Finding.Info(
            $"DNS Servers Configured ({state.DnsServers.Count})",
            $"DNS servers in use: {string.Join(", ", state.DnsServers)}",
            Category);
    }

    // ── Network profile ───────────────────────────────────────────────────────

    /// <summary>
    /// Warns when any active connection uses the Public profile; passes when all
    /// active connections are Private/Domain. Emits nothing when no connection is
    /// active.
    /// </summary>
    public static List<Finding> CheckNetworkProfile(NetworkState state)
    {
        var findings = new List<Finding>();

        if (state.PublicNetworks.Count > 0)
        {
            findings.Add(Finding.Warning(
                $"Public Network Profile Active ({state.PublicNetworks.Count})",
                $"The following network(s) are set to Public profile: {string.Join(", ", state.PublicNetworks)}. " +
                "Public profile exposes the machine to stricter firewall rules but may indicate an untrusted network connection. " +
                "If this is your home/office network, switch to Private for local sharing or keep Public for security.",
                Category,
                "Set the network to Private if it is a trusted network, or keep Public for untrusted networks.",
                @"Set-NetConnectionProfile -Name '<NetworkName>' -NetworkCategory Private"));
        }
        else if (state.ActiveNetworkCount > 0)
        {
            findings.Add(Finding.Pass(
                "Network Profile: Private/Domain",
                "All active network connections are set to Private or Domain profile.",
                Category));
        }

        return findings;
    }

    // ── Wi-Fi ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Classifies the connected Wi-Fi's security. Returns <c>null</c> when no Wi-Fi
    /// adapter / state was collected; an Info "not connected" when a radio exists but
    /// is idle; otherwise Critical (Open/WEP), Warning (WPA1, WPA2-TKIP) or Pass
    /// (WPA2-AES, WPA3) based on the authentication + cipher strings.
    /// </summary>
    public static Finding? CheckWiFi(NetworkState state)
    {
        // No wireless data collected at all => nothing to report.
        if (!state.WiFiConnected &&
            string.IsNullOrEmpty(state.WiFiSsid) &&
            string.IsNullOrEmpty(state.WiFiAuth))
        {
            return null;
        }

        if (!state.WiFiConnected)
        {
            return Finding.Info(
                "Wi-Fi Not Connected",
                "No active Wi-Fi connection detected.",
                Category);
        }

        var ssid = state.WiFiSsid;
        var auth = state.WiFiAuth;
        var cipher = state.WiFiCipher;

        if (string.IsNullOrEmpty(auth) || string.IsNullOrEmpty(ssid))
            return null;

        if (auth.Contains("Open", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Critical(
                $"Open Wi-Fi Network: {ssid}",
                $"Connected to an open (unencrypted) Wi-Fi network '{ssid}'. All traffic can be intercepted.",
                Category,
                "Disconnect from open networks. Use a VPN if you must connect to open Wi-Fi.",
                "netsh wlan disconnect");
        }

        if (auth.Contains("WEP", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Critical(
                $"WEP Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' using WEP encryption, which can be cracked in minutes.",
                Category,
                "Switch to WPA2 or WPA3 encryption on your router immediately.",
                "netsh wlan disconnect");
        }

        if (auth.Contains("WPA-Personal", StringComparison.OrdinalIgnoreCase) &&
            !auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase) &&
            !auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Warning(
                $"WPA1 Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' using WPA1 (TKIP), which has known vulnerabilities.",
                Category,
                "Upgrade your router to use WPA2-AES or WPA3.",
                "netsh wlan disconnect");
        }

        if (auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Pass(
                $"WPA3 Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' with WPA3 encryption (strongest available). Cipher: {cipher ?? "N/A"}.",
                Category);
        }

        if (auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase))
        {
            var cipherInfo = cipher ?? "N/A";
            if (cipherInfo.Contains("TKIP", StringComparison.OrdinalIgnoreCase))
            {
                return Finding.Warning(
                    $"WPA2-TKIP Wi-Fi: {ssid}",
                    $"Connected to Wi-Fi network '{ssid}' using WPA2 with TKIP cipher. TKIP has known weaknesses.",
                    Category,
                    "Configure your router to use WPA2-AES (CCMP) instead of TKIP.",
                    "netsh wlan disconnect");
            }

            return Finding.Pass(
                $"WPA2-AES Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' with WPA2-AES encryption. Cipher: {cipherInfo}.",
                Category);
        }

        return Finding.Info(
            $"Wi-Fi Security: {auth}",
            $"Connected to Wi-Fi network '{ssid}' with authentication: {auth}, cipher: {cipher ?? "N/A"}.",
            Category);
    }

    // ── LLMNR + NetBIOS ───────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates LLMNR and NetBIOS-over-TCP/IP, the two classic name-resolution
    /// poisoning vectors (Responder / Inveigh). LLMNR emits Pass when explicitly
    /// disabled, otherwise Warning. NetBIOS emits Warning when any adapter still has
    /// it enabled, Pass when adapters were seen and all disable it, and nothing when
    /// no adapter state was collected.
    /// </summary>
    public static List<Finding> CheckLlmnrNetBios(NetworkState state)
    {
        var findings = new List<Finding>();

        // LLMNR (matches the original audit: warn on anything other than explicit 0).
        if (state.Llmnr == Toggle.Disabled)
        {
            findings.Add(Finding.Pass(
                "LLMNR Disabled",
                "Link-Local Multicast Name Resolution is disabled, preventing LLMNR poisoning attacks.",
                Category));
        }
        else
        {
            findings.Add(Finding.Warning(
                "LLMNR Enabled (Poisoning Risk)",
                "Link-Local Multicast Name Resolution (LLMNR) is enabled. Attackers on the local network can respond to LLMNR queries " +
                "to capture NTLMv2 hashes (tools like Responder/Inveigh). This is one of the most common internal network attack vectors.",
                Category,
                "Disable LLMNR via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution.",
                @"New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0"));
        }

        // NetBIOS over TCP/IP
        if (state.NetBiosEnabledAdapters.Count > 0)
        {
            findings.Add(Finding.Warning(
                $"NetBIOS over TCP/IP Enabled ({state.NetBiosEnabledAdapters.Count} adapter(s))",
                $"NetBIOS Name Service (NBT-NS) is enabled on: {string.Join("; ", state.NetBiosEnabledAdapters.Take(3))}. " +
                "Like LLMNR, NBT-NS can be poisoned to capture credentials on the local network.",
                Category,
                "Disable NetBIOS over TCP/IP on each adapter: Network Adapter Properties > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP.",
                @"Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.SetTcpipNetbios(2) }"));
        }
        else if (state.NetBiosAdapterCount > 0)
        {
            findings.Add(Finding.Pass(
                "NetBIOS over TCP/IP Disabled",
                "NetBIOS Name Service is disabled on all network adapters.",
                Category));
        }

        return findings;
    }

    // ── ARP ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Inspects the ARP table for duplicate MAC addresses (the same MAC claiming
    /// multiple IPs), a classic ARP-spoofing indicator. Broadcast / multicast MACs
    /// are ignored. Always returns exactly one finding so downstream consumers can
    /// confirm the check ran: Warning on duplicates, Pass otherwise (incl. an empty
    /// table or a failed query, which are benign on offline / CI hosts).
    /// </summary>
    public static Finding CheckArp(NetworkState state)
    {
        if (state.ArpQueryFailed)
        {
            return Finding.Pass(
                "ARP Table: Unavailable",
                $"Unable to query ARP table{(string.IsNullOrEmpty(state.ArpError) ? "" : ": " + state.ArpError)}",
                Category);
        }

        // Group non-broadcast/multicast entries by MAC.
        var macToIps = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        int entryCount = 0;
        foreach (var e in state.ArpEntries)
        {
            if (string.IsNullOrWhiteSpace(e.Mac) || string.IsNullOrWhiteSpace(e.Ip)) continue;
            if (IsBroadcastOrMulticastMac(e.Mac)) continue;

            entryCount++;
            if (!macToIps.TryGetValue(e.Mac, out var ips))
            {
                ips = new List<string>();
                macToIps[e.Mac] = ips;
            }
            ips.Add(e.Ip);
        }

        var duplicates = macToIps.Where(kv => kv.Value.Count > 1).ToList();

        if (duplicates.Count > 0)
        {
            var details = string.Join("; ", duplicates.Select(d =>
                $"MAC {d.Key} → IPs: {string.Join(", ", d.Value)}"));
            return Finding.Warning(
                $"ARP Table: Duplicate MAC Addresses Detected ({duplicates.Count})",
                $"Multiple IP addresses share the same MAC address in the ARP table, which could indicate ARP spoofing: {details}",
                Category,
                "Investigate the duplicate MAC entries. Use static ARP entries for critical hosts (e.g., default gateway) if ARP spoofing is suspected.",
                "arp -a");
        }

        if (entryCount > 0)
        {
            return Finding.Pass(
                "ARP Table: No Anomalies",
                $"ARP table has {entryCount} entries with no duplicate MAC addresses detected.",
                Category);
        }

        return Finding.Pass(
            "ARP Table: Empty",
            "ARP table contained no parseable IPv4 entries (host may be offline or running in a minimal CI environment).",
            Category);
    }

    /// <summary>
    /// True for broadcast (ff-ff-...) and IPv4/IPv6 multicast (01-00-5e / 33-33)
    /// MAC prefixes, which should never be treated as spoofing duplicates.
    /// </summary>
    public static bool IsBroadcastOrMulticastMac(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return false;
        return mac.Equals("ff-ff-ff-ff-ff-ff", StringComparison.OrdinalIgnoreCase)
            || mac.StartsWith("01-00-5e", StringComparison.OrdinalIgnoreCase)   // IPv4 multicast
            || mac.StartsWith("33-33", StringComparison.OrdinalIgnoreCase);      // IPv6 multicast
    }

    // ── IPv6 ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reports active global (routable) IPv6 addresses and any active Teredo tunnel.
    /// Both are informational/Warning hygiene items: many firewalls only filter IPv4,
    /// and Teredo encapsulates IPv6 in IPv4 UDP, bypassing IPv4-only controls.
    /// </summary>
    public static List<Finding> CheckIPv6(NetworkState state)
    {
        var findings = new List<Finding>();

        if (state.GlobalIPv6Addresses.Count > 0)
        {
            var addresses = state.GlobalIPv6Addresses.Take(5).ToList();
            findings.Add(Finding.Info(
                $"Global IPv6 Addresses Active ({state.GlobalIPv6Addresses.Count})",
                $"This machine has {state.GlobalIPv6Addresses.Count} global IPv6 address(es): {string.Join(", ", addresses)}. " +
                "Ensure IPv6 firewall rules are configured. Many firewalls only filter IPv4 traffic, leaving IPv6 unprotected.",
                Category,
                "If IPv6 is not needed, disable it on network adapters. If needed, ensure firewall rules cover IPv6 traffic."));
        }

        if (state.TeredoActive)
        {
            findings.Add(Finding.Warning(
                "Teredo IPv6 Tunnel Active",
                "Teredo IPv6 tunneling is active. This encapsulates IPv6 traffic in IPv4 UDP packets, " +
                "which can bypass IPv4-only firewalls and security monitoring tools.",
                Category,
                "Disable Teredo if IPv6 tunneling is not needed.",
                "netsh interface teredo set state disabled"));
        }

        return findings;
    }
}