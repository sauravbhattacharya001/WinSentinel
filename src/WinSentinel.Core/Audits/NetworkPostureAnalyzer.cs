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

        /// <summary>
        /// The local bind address the port is listening on (e.g. <c>0.0.0.0</c>,
        /// <c>::</c>, or <c>127.0.0.1</c>). Empty when the collector could not
        /// determine it (older data / a locale where the column was dropped) - in
        /// which case it is treated conservatively as publicly bound.
        /// </summary>
        public string LocalAddress { get; set; } = "";

        /// <summary>
        /// True when the port is reachable from OFF this machine - i.e. bound to
        /// all interfaces (<c>0.0.0.0</c> / <c>::</c>) or a concrete non-loopback
        /// address - rather than to loopback only (<c>127.0.0.1</c> / <c>::1</c>).
        /// A high-risk service on loopback is a much smaller exposure than the
        /// same service answering the network, so the port checks weight the two
        /// very differently. Unknown/blank binds are treated as public (fail safe).
        /// </summary>
        public bool IsPubliclyBound => IsPublicBindAddress(LocalAddress);

        public ListeningPort() { }
        public ListeningPort(int port, string processName)
        {
            Port = port;
            ProcessName = processName ?? "";
        }
        public ListeningPort(int port, string processName, string localAddress)
        {
            Port = port;
            ProcessName = processName ?? "";
            LocalAddress = localAddress ?? "";
        }
    }

    /// <summary>
    /// Classify a listening bind address as publicly reachable (true) vs
    /// loopback-only (false). Pure/allocation-light so it can be unit-tested and
    /// reused. Loopback = <c>127.0.0.0/8</c> IPv4, IPv6 <c>::1</c>, or the literal
    /// <c>localhost</c>. Everything else - including all-interfaces wildcards
    /// (<c>0.0.0.0</c>, <c>::</c>, <c>[::]</c>) and any concrete LAN/public IP -
    /// counts as public. A blank/unknown address is treated as public so a
    /// collector gap can never silently downgrade a real exposure.
    /// </summary>
    public static bool IsPublicBindAddress(string? address)
    {
        var a = address?.Trim();
        if (string.IsNullOrEmpty(a)) return true; // unknown -> fail safe (assume exposed)

        // Strip an IPv6 bracket wrapper and any zone/scope id or :port suffix that
        // may have ridden along (e.g. "[::1]", "fe80::1%eth0").
        if (a.Length >= 2 && a[0] == '[')
        {
            var close = a.IndexOf(']');
            a = close > 1 ? a.Substring(1, close - 1) : a.Substring(1);
        }
        var pct = a.IndexOf('%');
        if (pct >= 0) a = a.Substring(0, pct);
        a = a.Trim();
        if (a.Length == 0) return true;

        if (a.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return false;
        if (a == "::1") return false;                 // IPv6 loopback
        if (a.StartsWith("127.", StringComparison.Ordinal)) return false; // 127.0.0.0/8

        return true; // 0.0.0.0, ::, concrete LAN/public IPs -> reachable
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

        // WPAD (Web Proxy Auto-Discovery) hardening. Tracks the Microsoft-documented
        // machine-wide kill switch
        // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad
        // (Windows 10 1809+ / Server 2019+). To avoid a double negative the toggle
        // encodes the *posture*, not the raw value: Enabled = WPAD auto-discovery is
        // hardened OFF (DisableWpad = 1, the secure state); Disabled = the kill switch
        // is absent or 0 (WPAD auto-discovery still active); Unknown = the value could
        // not be read. WPAD is the third classic local name-resolution poisoning vector
        // alongside LLMNR and NBT-NS - Responder/Inveigh answer the client's
        // "wpad" WPAD/PAC lookup to feed a rogue proxy and harvest NTLM auth.
        public Toggle WpadHardened { get; set; } = Toggle.Unknown;

        // mDNS (Multicast DNS, UDP 5353) hardening. Tracks the Microsoft-documented
        // machine-wide DNS Client control
        // HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS
        // (0 = the Windows DNS Client mDNS responder/listener is turned off). To avoid
        // a double negative the toggle encodes the *posture*, not the raw value:
        // Enabled = mDNS is hardened OFF (EnableMDNS = 0, the secure state); Disabled =
        // EnableMDNS is 1 OR the value is absent (Windows ships with mDNS ON by
        // default, so a missing key is still exposed); Unknown = the value could not be
        // read. mDNS is the fourth classic local name-resolution poisoning vector
        // alongside LLMNR, NBT-NS and WPAD - Responder/Inveigh answer the client's
        // multicast ".local" lookups to harvest NTLM auth.
        public Toggle MdnsHardened { get; set; } = Toggle.Unknown;

        // ICMP Redirect acceptance hardening. Tracks the Microsoft-documented
        // machine-wide control
        // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect
        // (0 = the IPv4 stack ignores ICMP redirect packets and does NOT rewrite its
        // route table in response to them). To avoid a double negative the toggle
        // encodes the *posture*, not the raw value: Enabled = ICMP redirects are
        // hardened OFF (EnableICMPRedirect = 0, the secure state); Disabled =
        // EnableICMPRedirect is 1 OR the value is absent (Windows accepts ICMP
        // redirects by default, so a missing key is still exposed); Unknown = the
        // value could not be read. An attacker on the local segment who can forge an
        // ICMP Redirect (Type 5) can inject a bogus host route and man-in-the-middle
        // or blackhole the victim's traffic - the network-layer analogue of the
        // ARP/name-resolution poisoning vectors already checked here.
        public Toggle IcmpRedirectHardened { get; set; } = Toggle.Unknown;

        // IPv4 Source Routing hardening. Tracks the Microsoft-documented machine-wide
        // control
        // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting
        // which governs whether the IPv4 stack honours source-routed packets (packets
        // that carry their own hop-by-hop path in an IP option). Values: 0 = source
        // routing fully allowed, 1 = source-routed packets forwarded but not received
        // locally, 2 = source routing completely disabled ("highest protection", the
        // CIS/MSS-recommended state). To avoid a double negative the toggle encodes the
        // *posture*, not the raw value: Enabled = source routing is hardened OFF
        // (DisableIPSourceRouting = 2, the secure state); Disabled = the value is 0, 1,
        // or absent (Windows does not fully disable it by default, so a missing key is
        // still exposed); Unknown = the value could not be read. Source-routed packets
        // let an attacker dictate the return path of a spoofed packet - bypassing
        // ingress/anti-spoofing filters and reaching hosts that a normal route would not
        // - the same class of network-layer path manipulation as the ICMP redirect
        // vector checked above.
        public Toggle IpSourceRoutingHardened { get; set; } = Toggle.Unknown;

        // ICMP Router Discovery (IRDP) hardening. Tracks the Microsoft-documented
        // machine-wide control
        // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery
        // which governs whether the IPv4 stack solicits/accepts ICMP Router
        // Discovery Protocol (RFC 1256) Router Advertisements to learn its default
        // gateway. Values: 0 = disabled, 1 = enabled, 2 = enable only if DHCP sends
        // the Perform Router Discovery option (the Windows default). To avoid a double
        // negative the toggle encodes the *posture*, not the raw value: Enabled = IRDP
        // is hardened OFF (PerformRouterDiscovery = 0, the secure state); Disabled =
        // the value is 1, 2, or absent (Windows defaults to 2, so a missing key still
        // leaves IRDP active); Unknown = the value could not be read. An attacker on
        // the local segment who forges an ICMP Router Advertisement can install a
        // rogue default gateway on the victim and man-in-the-middle or blackhole its
        // traffic - the same route-injection class as the ICMP redirect and IPv4
        // source-routing vectors checked above.
        public Toggle IrdpHardened { get; set; } = Toggle.Unknown;

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

        /// <summary>
        /// True when a 6to4 IPv6 transition tunnel is active. 6to4 (RFC 3056)
        /// encapsulates IPv6 in IPv4 protocol-41 packets to a public relay,
        /// bypassing IPv4-only firewalls and monitoring the same way Teredo does.
        /// It is a legacy, largely-deprecated transition technology and should be
        /// off on a hardened host.
        /// </summary>
        public bool SixToFourActive { get; set; }

        /// <summary>
        /// True when an ISATAP (Intra-Site Automatic Tunnel Addressing Protocol)
        /// tunnel is active. ISATAP carries IPv6 over an IPv4 intranet and, like
        /// 6to4 and Teredo, opens an IPv6 path that IPv4-only controls miss. It is
        /// legacy transition tech and should be disabled unless explicitly required.
        /// </summary>
        public bool IsatapActive { get; set; }
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
        findings.Add(CheckWpad(state));
        findings.Add(CheckMdns(state));
        findings.Add(CheckIcmpRedirect(state));
        findings.Add(CheckIpSourceRouting(state));
        findings.Add(CheckIrdp(state));
        findings.Add(CheckArp(state));
        findings.AddRange(CheckIPv6(state));
        return findings;
    }

    // ── Listening ports ─────────────────────────────────────────────────────

    /// <summary>
    /// Flags high-risk listening ports, separating those exposed to the network
    /// (bound to all interfaces or a concrete non-loopback address) from those
    /// bound to loopback only, and always emits the total-count info.
    /// </summary>
    public static List<Finding> CheckListeningPorts(NetworkState state)
    {
        var findings = new List<Finding>();

        var highRiskPorts = state.ListeningPorts
            .Where(p => HighRiskPorts.Contains(p.Port))
            .ToList();

        // Exposure matters: a high-risk service answering the network (0.0.0.0 / a
        // LAN IP) is a real remote attack surface, while the same service on
        // loopback is only reachable locally. Split them so the network-exposed
        // ports raise a Warning and loopback-only ports get a calmer Info note
        // (unknown/blank binds count as exposed - see IsPublicBindAddress).
        var exposed = highRiskPorts.Where(p => p.IsPubliclyBound).ToList();
        var loopbackOnly = highRiskPorts.Where(p => !p.IsPubliclyBound).ToList();

        if (exposed.Count > 0)
        {
            var list = string.Join(", ", exposed.Select(FormatExposedPort));
            findings.Add(Finding.Warning(
                $"High-Risk Ports Exposed to Network ({exposed.Count})",
                $"The following high-risk ports are listening on a network-reachable address: {list}. " +
                "Because they are not bound to loopback, they can be reached by other hosts.",
                Category,
                // No FixCommand: which listening service to stop is a human judgement
                // call (closing a port may break a needed service), so there is no
                // single safe auto-fix. The investigative command lives in the
                // remediation text instead of as an (un-runnable) FixCommand - the
                // pipeline + calculated-property ';' tripped InputSanitizer, making
                // the "Fix" button a guaranteed-to-fail dead button.
                "Review each listening service and disable any that are not needed, then block " +
                "unused ports in the firewall. List the owning processes with: " +
                "Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort"));
        }

        if (loopbackOnly.Count > 0)
        {
            var list = string.Join(", ", loopbackOnly.Select(p => $"Port {p.Port} ({p.ProcessName})"));
            findings.Add(Finding.Info(
                $"High-Risk Ports Listening on Loopback Only ({loopbackOnly.Count})",
                $"The following high-risk ports are listening on loopback only (not reachable from other hosts): {list}. " +
                "This is a much smaller exposure than a network-bound service, but confirm the bind stays local-only.",
                Category));
        }

        if (exposed.Count == 0 && loopbackOnly.Count == 0)
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

    /// <summary>
    /// Render an exposed high-risk port for the finding text, appending the bind
    /// address when it is known (so an operator sees whether it is the
    /// all-interfaces wildcard or a specific LAN IP). A blank address is omitted
    /// rather than shown as an empty "on ".
    /// </summary>
    private static string FormatExposedPort(ListeningPort p)
    {
        var addr = p.LocalAddress?.Trim();
        return string.IsNullOrEmpty(addr)
            ? $"Port {p.Port} ({p.ProcessName})"
            : $"Port {p.Port} ({p.ProcessName}) on {addr}";
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
                "Disable WinRM if remote management is not needed: stop it now with `Stop-Service WinRM`, then disable startup (the fix below) so it stays off after reboot.",
                // Single sanitizer-safe command. The previous "Stop-Service WinRM; Set-Service
                // WinRM ..." form was rejected by InputSanitizer.CheckDangerousCommand (semicolon
                // chaining), so FixEngine refused to run it. -StartupType Disabled is the durable
                // fix; stopping the live instance is covered in the remediation text above.
                "Set-Service WinRM -StartupType Disabled");
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
    /// (WPA2-AES, WPA2 with an unconfirmed cipher, WPA3) based on the authentication
    /// + cipher strings. The confident "WPA2-AES" label is only used when the cipher
    /// actually reports AES/CCMP - an unreadable cipher passes as a plain "WPA2" so
    /// the finding never overstates encryption it did not verify.
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

        // WPA1 (any flavour: "WPA-Personal", "WPA-Enterprise", or a bare "WPA").
        // netsh reports the 802.1X variant as "WPA-Enterprise", which is just as
        // deprecated/vulnerable (TKIP) as WPA-Personal -- matching only the
        // literal "WPA-Personal" let a WPA1-Enterprise network fall through to the
        // benign generic Info branch instead of warning. Match anything that
        // mentions WPA but is neither WPA2 nor WPA3 (those are handled below).
        if (auth.Contains("WPA", StringComparison.OrdinalIgnoreCase) &&
            !auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase) &&
            !auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Warning(
                $"WPA1 Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' using WPA1 ({auth}, TKIP), which has known vulnerabilities.",
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

            // Only assert the strong "WPA2-AES" posture when the cipher actually
            // reports AES/CCMP. When the cipher could not be read (null/empty/N/A or
            // some other value), WPA2 is still acceptable -- so this stays a Pass --
            // but the finding must not overstate an unverified AES cipher (the link
            // could in fact be running TKIP).
            bool aesConfirmed =
                cipherInfo.Contains("CCMP", StringComparison.OrdinalIgnoreCase) ||
                cipherInfo.Contains("AES", StringComparison.OrdinalIgnoreCase) ||
                cipherInfo.Contains("GCMP", StringComparison.OrdinalIgnoreCase);

            if (aesConfirmed)
            {
                return Finding.Pass(
                    $"WPA2-AES Wi-Fi Security: {ssid}",
                    $"Connected to Wi-Fi network '{ssid}' with WPA2-AES encryption. Cipher: {cipherInfo}.",
                    Category);
            }

            return Finding.Pass(
                $"WPA2 Wi-Fi Security: {ssid}",
                $"Connected to Wi-Fi network '{ssid}' using WPA2. The exact cipher could not be confirmed " +
                "(reported as '" + cipherInfo + "'); verify the router is using WPA2-AES (CCMP) rather than the weaker TKIP.",
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
                // Single-statement PowerShell (no semicolon chaining, so it passes
                // InputSanitizer.CheckDangerousCommand). Matches the same fix in
                // IncidentResponsePlaybook.cs. Set-ItemProperty requires the DNSClient
                // policy key to exist; that is the standard remediation path.
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0"));
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

    // ── WPAD (Web Proxy Auto-Discovery) ───────────────────────────────────────

    /// <summary>
    /// Evaluates WPAD (Web Proxy Auto-Discovery) hardening - the third classic
    /// local name-resolution poisoning vector next to LLMNR and NBT-NS. When a
    /// client is set to "automatically detect settings", it broadcasts a lookup for
    /// the host <c>wpad</c> (and requests <c>http://wpad/wpad.dat</c>) to find a
    /// proxy auto-config file. An attacker on the LAN running Responder/Inveigh can
    /// answer that name (over LLMNR/NBT-NS/DNS) with a rogue host, serve a malicious
    /// PAC, and force the victim's HTTP stack to authenticate to them - harvesting
    /// NTLMv2 hashes or MITM-ing web traffic, with no user interaction.
    ///
    /// <para>The durable, machine-wide mitigation Microsoft documents (Windows 10
    /// 1809+ / Server 2019+) is the <c>DisableWpad</c> kill switch under
    /// <c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp</c>.
    /// The analyzer grades the collected posture in
    /// <see cref="NetworkState.WpadHardened"/>: <see cref="Toggle.Enabled"/> (the kill
    /// switch is on, DisableWpad = 1) passes; <see cref="Toggle.Disabled"/> (absent or
    /// 0) warns; <see cref="Toggle.Unknown"/> (unreadable) also warns, fail-safe, so a
    /// blocked read surfaces the exposure rather than hiding it. Always returns exactly
    /// one finding.</para>
    /// </summary>
    public static Finding CheckWpad(NetworkState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.WpadHardened == Toggle.Enabled)
        {
            return Finding.Pass(
                "WPAD Auto-Discovery Disabled",
                "Web Proxy Auto-Discovery (WPAD) is disabled machine-wide " +
                "(WinHttp DisableWpad = 1). Attackers on the local network cannot " +
                "poison the 'wpad' proxy lookup to serve a rogue PAC and harvest NTLM " +
                "credentials or man-in-the-middle web traffic.",
                Category);
        }

        var stateNote = state.WpadHardened == Toggle.Disabled
            ? "The WinHttp 'DisableWpad' kill switch is not set (absent or 0), so WPAD " +
              "proxy auto-discovery is still active."
            : "The WinHttp 'DisableWpad' kill switch could not be read, so WPAD proxy " +
              "auto-discovery must be assumed active.";

        return Finding.Warning(
            "WPAD Auto-Discovery Enabled (Poisoning Risk)",
            stateNote + " When a client automatically detects proxy settings it " +
            "broadcasts a lookup for the host 'wpad'; an attacker on the local network " +
            "(Responder/Inveigh) can answer it, serve a malicious proxy auto-config " +
            "file, and capture NTLMv2 hashes or intercept web traffic. WPAD is the third " +
            "classic name-resolution poisoning vector alongside LLMNR and NBT-NS.",
            Category,
            "Disable WPAD machine-wide by setting the WinHttp DisableWpad DWORD to 1, " +
            "then restart the WinHTTP Web Proxy Auto-Discovery Service (WinHttpAutoProxySvc). " +
            "Also turn off 'Automatically detect settings' in the proxy configuration.",
            // Single sanitizer-safe PowerShell statement (no ';'/'|'/'&&' chaining, so it
            // survives InputSanitizer.CheckDangerousCommand AND satisfies NetworkAudit's
            // PowerShell/netsh-only fix convention, unlike a `reg add`). The target
            // WinHttp key exists by default on Windows, so Set-ItemProperty succeeds
            // without a New-Item first; the service restart is human-guided detail above.
            @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' " +
            "-Name DisableWpad -Value 1");
    }

    // ── mDNS (Multicast DNS / .local) ─────────────────────────────────────────

    /// <summary>
    /// Evaluates mDNS (Multicast DNS, UDP 5353) hardening - the fourth classic local
    /// name-resolution poisoning vector next to LLMNR, NBT-NS and WPAD. The Windows
    /// DNS Client resolves <c>.local</c> names (and, when LLMNR/NBT-NS are already
    /// disabled, other single-label names) by multicasting a query to the whole LAN.
    /// An attacker running Responder/Inveigh answers that multicast with a rogue host
    /// and coerces the victim into authenticating - harvesting NTLMv2 hashes exactly
    /// as with LLMNR, with no user interaction.
    ///
    /// <para>The durable, machine-wide mitigation Microsoft documents is the
    /// <c>EnableMDNS</c> DWORD under
    /// <c>HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters</c> set to 0,
    /// which turns off the DNS Client mDNS responder/listener. The analyzer grades the
    /// collected posture in <see cref="NetworkState.MdnsHardened"/>:
    /// <see cref="Toggle.Enabled"/> (EnableMDNS = 0, mDNS hardened off) passes;
    /// <see cref="Toggle.Disabled"/> (EnableMDNS = 1, OR the value is absent - Windows
    /// ships with mDNS ON by default, so a missing key is still exposed) warns;
    /// <see cref="Toggle.Unknown"/> (unreadable) also warns, fail-safe, so a blocked
    /// read surfaces the exposure rather than hiding it. Always returns exactly one
    /// finding.</para>
    /// </summary>
    public static Finding CheckMdns(NetworkState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.MdnsHardened == Toggle.Enabled)
        {
            return Finding.Pass(
                "mDNS Disabled",
                "Multicast DNS (mDNS, UDP 5353) is disabled machine-wide " +
                "(Dnscache EnableMDNS = 0). Attackers on the local network cannot " +
                "poison the client's multicast '.local' name lookups to coerce NTLM " +
                "authentication and harvest credentials.",
                Category);
        }

        var stateNote = state.MdnsHardened == Toggle.Disabled
            ? "The Dnscache 'EnableMDNS' value is 1 or absent (Windows enables mDNS by " +
              "default), so the multicast DNS responder is still active."
            : "The Dnscache 'EnableMDNS' value could not be read, so multicast DNS must " +
              "be assumed active.";

        return Finding.Warning(
            "mDNS Enabled (Poisoning Risk)",
            stateNote + " The Windows DNS Client resolves '.local' names (and other " +
            "single-label names when LLMNR/NBT-NS are already off) by multicasting to " +
            "the whole LAN; an attacker (Responder/Inveigh) can answer that multicast, " +
            "impersonate the requested host, and capture NTLMv2 hashes. mDNS is the " +
            "fourth classic name-resolution poisoning vector alongside LLMNR, NBT-NS " +
            "and WPAD.",
            Category,
            "Disable the Windows DNS Client mDNS responder machine-wide by setting the " +
            "Dnscache EnableMDNS DWORD to 0, then restart the DNS Client service " +
            "(Dnscache) or reboot. Note: on Windows this suppresses the OS mDNS " +
            "resolver; some apps (printing, casting) ship their own mDNS stack and are " +
            "unaffected.",
            // Single sanitizer-safe PowerShell statement (no ';'/'|'/'&&' chaining, so it
            // survives InputSanitizer.CheckDangerousCommand AND satisfies NetworkAudit's
            // PowerShell/netsh-only fix convention). The Dnscache\Parameters key exists
            // by default on Windows, so Set-ItemProperty succeeds without a New-Item; the
            // service restart is human-guided detail above.
            @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' " +
            "-Name EnableMDNS -Value 0");
    }

    // ── ICMP Redirect ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates ICMP Redirect acceptance - a network-layer route-injection vector
    /// that sits alongside the ARP and name-resolution poisoning checks. An ICMP
    /// Redirect (Type 5) tells a host "use a better next-hop for this destination";
    /// an attacker on the same segment who forges one can insert a bogus host route
    /// into the victim's IPv4 route table and man-in-the-middle or blackhole its
    /// traffic, with no authentication on the redirect itself.
    ///
    /// <para>The durable, machine-wide mitigation Microsoft documents is the
    /// <c>EnableICMPRedirect</c> DWORD under
    /// <c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters</c> set to 0,
    /// which stops the IPv4 stack from altering its route table in response to
    /// received redirects. The analyzer grades the collected posture in
    /// <see cref="NetworkState.IcmpRedirectHardened"/>: <see cref="Toggle.Enabled"/>
    /// (EnableICMPRedirect = 0, redirects ignored) passes; <see cref="Toggle.Disabled"/>
    /// (EnableICMPRedirect = 1, OR the value is absent - Windows accepts redirects by
    /// default, so a missing key is still exposed) warns; <see cref="Toggle.Unknown"/>
    /// (unreadable) also warns, fail-safe, so a blocked read surfaces the exposure
    /// rather than hiding it. Always returns exactly one finding.</para>
    /// </summary>
    public static Finding CheckIcmpRedirect(NetworkState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.IcmpRedirectHardened == Toggle.Enabled)
        {
            return Finding.Pass(
                "ICMP Redirects Ignored",
                "The IPv4 stack ignores ICMP Redirect packets machine-wide " +
                "(Tcpip EnableICMPRedirect = 0). An attacker on the local segment " +
                "cannot forge an ICMP Redirect to inject a bogus host route and " +
                "man-in-the-middle or blackhole this host's traffic.",
                Category);
        }

        var stateNote = state.IcmpRedirectHardened == Toggle.Disabled
            ? "The Tcpip 'EnableICMPRedirect' value is 1 or absent (Windows accepts " +
              "ICMP redirects by default), so the stack will rewrite its route table " +
              "in response to received redirects."
            : "The Tcpip 'EnableICMPRedirect' value could not be read, so ICMP redirect " +
              "acceptance must be assumed active.";

        return Finding.Warning(
            "ICMP Redirects Accepted (Route Injection Risk)",
            stateNote + " An ICMP Redirect (Type 5) instructs a host to change the " +
            "next-hop for a destination; because the redirect carries no " +
            "authentication, an attacker on the same segment can forge one to insert " +
            "a rogue host route into this machine's IPv4 route table and " +
            "man-in-the-middle or blackhole its traffic - the network-layer analogue " +
            "of ARP and LLMNR/NBT-NS poisoning.",
            Category,
            "Stop the IPv4 stack from acting on received ICMP redirects machine-wide by " +
            "setting the Tcpip EnableICMPRedirect DWORD to 0, then reboot (the TCP/IP " +
            "stack reads this at start-up). This aligns with the CIS Windows benchmark " +
            "'MSS: (EnableICMPRedirect)' recommendation.",
            // Single sanitizer-safe PowerShell statement (no ';'/'|'/'&&' chaining) so it
            // survives InputSanitizer.CheckDangerousCommand and matches the PowerShell-only
            // fix convention of the sibling name-resolution checks. The Tcpip\Parameters
            // key exists by default on Windows, so Set-ItemProperty succeeds directly.
            @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' " +
            "-Name EnableICMPRedirect -Value 0");
    }

    // ── IPv4 Source Routing ────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates IPv4 source-routing acceptance - a network-layer path-manipulation
    /// vector alongside the ICMP redirect check. A source-routed IP packet carries its
    /// own hop-by-hop path in an IP option, letting the sender dictate the route
    /// (including the return path of a spoofed packet). An attacker can use this to
    /// bypass ingress/anti-spoofing filters and reach hosts that normal routing would
    /// not expose.
    ///
    /// <para>The durable, machine-wide mitigation Microsoft documents is the
    /// <c>DisableIPSourceRouting</c> DWORD under
    /// <c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters</c> set to 2
    /// ("highest protection" - source routing completely disabled), which is the CIS /
    /// MSS-recommended value. The analyzer grades the collected posture in
    /// <see cref="NetworkState.IpSourceRoutingHardened"/>: <see cref="Toggle.Enabled"/>
    /// (DisableIPSourceRouting = 2, fully disabled) passes; <see cref="Toggle.Disabled"/>
    /// (value is 0, 1, OR absent - Windows does not fully disable source routing by
    /// default, so a missing or partial value is still exposed) warns;
    /// <see cref="Toggle.Unknown"/> (unreadable) also warns, fail-safe, so a blocked
    /// read surfaces the exposure rather than hiding it. Always returns exactly one
    /// finding.</para>
    /// </summary>
    public static Finding CheckIpSourceRouting(NetworkState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.IpSourceRoutingHardened == Toggle.Enabled)
        {
            return Finding.Pass(
                "IPv4 Source Routing Disabled",
                "IPv4 source routing is fully disabled machine-wide " +
                "(Tcpip DisableIPSourceRouting = 2, 'highest protection'). An attacker " +
                "cannot use source-routed packets to dictate a spoofed packet's return " +
                "path and bypass this host's anti-spoofing / ingress filtering.",
                Category);
        }

        var stateNote = state.IpSourceRoutingHardened == Toggle.Disabled
            ? "The Tcpip 'DisableIPSourceRouting' value is 0, 1, or absent (Windows does " +
              "not fully disable source routing by default), so the IPv4 stack still " +
              "honours source-routed packets to some degree."
            : "The Tcpip 'DisableIPSourceRouting' value could not be read, so source " +
              "routing must be assumed active.";

        return Finding.Warning(
            "IPv4 Source Routing Accepted (Spoofing / Filter-Bypass Risk)",
            stateNote + " A source-routed IP packet carries its own hop-by-hop path in " +
            "an IP option, letting the sender - not the routers - choose the route, " +
            "including the return path of a spoofed source address. An attacker can use " +
            "this to bypass ingress/anti-spoofing filters and reach hosts normal routing " +
            "would not expose - the same class of network-layer path manipulation as the " +
            "ICMP redirect vector.",
            Category,
            "Fully disable IPv4 source routing machine-wide by setting the Tcpip " +
            "DisableIPSourceRouting DWORD to 2 ('highest protection'), then reboot (the " +
            "TCP/IP stack reads this at start-up). This aligns with the CIS Windows " +
            "benchmark 'MSS: (DisableIPSourceRouting)' recommendation.",
            // Single sanitizer-safe PowerShell statement (no ';'/'|'/'&&' chaining) so it
            // survives InputSanitizer.CheckDangerousCommand and matches the PowerShell-only
            // fix convention of the sibling network-layer checks. The Tcpip\Parameters key
            // exists by default on Windows, so Set-ItemProperty succeeds directly.
            @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' " +
            "-Name DisableIPSourceRouting -Value 2");
    }

    // ── ARP ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Evaluates ICMP Router Discovery Protocol (IRDP, RFC 1256) acceptance - a
    /// network-layer default-gateway-injection vector alongside the ICMP redirect
    /// and IPv4 source-routing checks. When IRDP is active the IPv4 stack learns its
    /// default gateway from unauthenticated ICMP Router Advertisements; an attacker
    /// on the same segment who forges a Router Advertisement (with a higher
    /// preference) can install a rogue default gateway on the victim and
    /// man-in-the-middle or blackhole its traffic, with no authentication on the
    /// advertisement itself.
    ///
    /// <para>The durable, machine-wide mitigation Microsoft documents is the
    /// <c>PerformRouterDiscovery</c> DWORD under
    /// <c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters</c> set to 0,
    /// which stops the stack from soliciting or honouring IRDP advertisements. The
    /// analyzer grades the collected posture in
    /// <see cref="NetworkState.IrdpHardened"/>: <see cref="Toggle.Enabled"/>
    /// (PerformRouterDiscovery = 0, IRDP disabled) passes; <see cref="Toggle.Disabled"/>
    /// (the value is 1, 2, OR absent - Windows defaults to 2, so a missing key still
    /// leaves IRDP active) warns; <see cref="Toggle.Unknown"/> (unreadable) also warns,
    /// fail-safe, so a blocked read surfaces the exposure rather than hiding it.
    /// Always returns exactly one finding.</para>
    /// </summary>
    public static Finding CheckIrdp(NetworkState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.IrdpHardened == Toggle.Enabled)
        {
            return Finding.Pass(
                "ICMP Router Discovery Disabled",
                "ICMP Router Discovery Protocol (IRDP) is disabled machine-wide " +
                "(Tcpip PerformRouterDiscovery = 0). An attacker on the local segment " +
                "cannot forge an ICMP Router Advertisement to install a rogue default " +
                "gateway and man-in-the-middle or blackhole this host's traffic.",
                Category);
        }

        var stateNote = state.IrdpHardened == Toggle.Disabled
            ? "The Tcpip 'PerformRouterDiscovery' value is 1, 2, or absent (Windows " +
              "defaults to 2, enabling IRDP whenever DHCP requests it), so the stack " +
              "can still learn its default gateway from ICMP Router Advertisements."
            : "The Tcpip 'PerformRouterDiscovery' value could not be read, so ICMP " +
              "Router Discovery must be assumed active.";

        return Finding.Warning(
            "ICMP Router Discovery Enabled (Gateway Injection Risk)",
            stateNote + " ICMP Router Discovery (IRDP, RFC 1256) lets a host learn its " +
            "default gateway from ICMP Router Advertisements; because those " +
            "advertisements carry no authentication, an attacker on the same segment " +
            "can forge one to install a rogue default gateway on this machine and " +
            "man-in-the-middle or blackhole its traffic - the same route-injection " +
            "class as the ICMP redirect and IPv4 source-routing vectors.",
            Category,
            "Disable IRDP machine-wide by setting the Tcpip PerformRouterDiscovery " +
            "DWORD to 0, then reboot (the TCP/IP stack reads this at start-up). This " +
            "aligns with the CIS Windows benchmark 'MSS: (PerformRouterDiscovery)' " +
            "recommendation.",
            // Single sanitizer-safe PowerShell statement (no ';'/'|'/'&&' chaining) so it
            // survives InputSanitizer.CheckDangerousCommand and matches the PowerShell-only
            // fix convention of the sibling network-layer checks. The Tcpip\Parameters
            // key exists by default on Windows, so Set-ItemProperty succeeds directly.
            @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' " +
            "-Name PerformRouterDiscovery -Value 0");
    }

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
    /// True for the broadcast address and for any group/multicast MAC, which
    /// must never be treated as ARP-spoofing duplicates.
    /// <para>
    /// A MAC is group/multicast iff the least-significant bit of the FIRST octet
    /// (the I/G bit) is set — i.e. the first hex byte is odd. This covers far more
    /// than the two most common prefixes: besides IPv4 multicast (01-00-5e) and
    /// IPv6 multicast (33-33), it correctly classifies IEEE 802.1 bridge/STP/LLDP
    /// group addresses (01-80-c2-…), Cisco CDP/VTP/PVST (01-00-0c-…) and any other
    /// odd-first-octet group MAC. These legitimately appear against multiple IPs
    /// on a switched network, so the previous prefix-only check false-flagged them
    /// as duplicate-MAC spoofing.
    /// </para>
    /// </summary>
    public static bool IsBroadcastOrMulticastMac(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return false;
        if (mac.Equals("ff-ff-ff-ff-ff-ff", StringComparison.OrdinalIgnoreCase)) return true; // broadcast
        // Group/multicast: I/G bit (LSB of the first octet) set ⇒ first byte is odd.
        return TryGetFirstOctet(mac, out var first) && (first & 0x01) != 0;
    }

    /// <summary>
    /// Parse the first octet of a MAC address. Tolerant of the formats that can
    /// reach this code: hyphen- or colon-separated (aa-bb-… / aa:bb:…), a single
    /// contiguous run of hex (aabbcc…), or dot groups (aabb.ccdd.…). Returns false
    /// if no leading hex byte can be read.
    /// </summary>
    private static bool TryGetFirstOctet(string mac, out int value)
    {
        value = 0;
        var trimmed = mac.Trim();
        if (trimmed.Length == 0) return false;
        // Take leading hex chars up to the first separator (- : .) or two chars.
        int i = 0;
        var hex = new char[2];
        int n = 0;
        while (i < trimmed.Length && n < 2)
        {
            char c = trimmed[i];
            if (c == '-' || c == ':' || c == '.') break;
            bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHex) return false;
            hex[n++] = c;
            i++;
        }
        if (n == 0) return false;
        return int.TryParse(new string(hex, 0, n), System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out value);
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

        if (state.SixToFourActive)
        {
            findings.Add(Finding.Warning(
                "6to4 IPv6 Tunnel Active",
                "A 6to4 IPv6 transition tunnel is active. 6to4 encapsulates IPv6 traffic in IPv4 " +
                "protocol-41 packets to a public relay, which can bypass IPv4-only firewalls and " +
                "security monitoring. 6to4 is a deprecated legacy transition technology.",
                Category,
                "Disable 6to4 if IPv6 tunneling is not needed.",
                "netsh interface 6to4 set state disabled"));
        }

        if (state.IsatapActive)
        {
            findings.Add(Finding.Warning(
                "ISATAP IPv6 Tunnel Active",
                "An ISATAP IPv6 transition tunnel is active. ISATAP carries IPv6 over the IPv4 intranet, " +
                "opening an IPv6 path that IPv4-only firewalls and monitoring tools may miss. ISATAP is a " +
                "legacy transition technology and should be disabled unless explicitly required.",
                Category,
                "Disable ISATAP if IPv6 tunneling is not needed.",
                "netsh interface isatap set state disabled"));
        }

        return findings;
    }
}