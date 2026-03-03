using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits DNS security configuration for risks including:
/// - DNS servers set to known-insecure or unexpected addresses
/// - DNS-over-HTTPS (DoH) not enabled
/// - DNS cache poisoning exposure (large cache, no secure validation)
/// - LLMNR/NetBIOS name resolution enabled (spoofing risk)
/// - DNS client settings that leak queries to untrusted networks
/// - Hosts file tampering
/// </summary>
public class DnsAudit : IAuditModule
{
    public string Name => "DNS Security Audit";
    public string Category => "DNS";
    public string Description =>
        "Checks DNS server configuration, DNS-over-HTTPS status, " +
        "LLMNR/NetBIOS exposure, hosts file integrity, and cache settings.";

    /// <summary>
    /// Well-known secure DNS providers (IPv4 + IPv6).
    /// </summary>
    public static readonly Dictionary<string, string> KnownSecureDns = new()
    {
        ["1.1.1.1"] = "Cloudflare",
        ["1.0.0.1"] = "Cloudflare",
        ["8.8.8.8"] = "Google",
        ["8.8.4.4"] = "Google",
        ["9.9.9.9"] = "Quad9",
        ["149.112.112.112"] = "Quad9",
        ["208.67.222.222"] = "OpenDNS",
        ["208.67.220.220"] = "OpenDNS",
        ["2606:4700:4700::1111"] = "Cloudflare",
        ["2606:4700:4700::1001"] = "Cloudflare",
        ["2001:4860:4860::8888"] = "Google",
        ["2001:4860:4860::8844"] = "Google",
        ["2620:fe::fe"] = "Quad9",
        ["2620:fe::9"] = "Quad9",
    };

    /// <summary>
    /// Known suspicious DNS servers (malware, ad-injection, etc.).
    /// </summary>
    public static readonly HashSet<string> SuspiciousDns = new()
    {
        "198.54.117.10", // known malware DNS
        "198.54.117.11",
        "95.211.158.134", // DNSChanger
    };

    /// <summary>
    /// Suspicious hosts file entries (domains that should not be redirected).
    /// </summary>
    public static readonly HashSet<string> SensitiveDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "windowsupdate.microsoft.com",
        "update.microsoft.com",
        "microsoft.com",
        "google.com",
        "login.microsoftonline.com",
        "accounts.google.com",
        "banking",
    };

    /// <summary>
    /// Data transfer object for DNS environment state.
    /// All checks operate on this record for testability.
    /// </summary>
    public sealed class DnsState
    {
        /// <summary>Per-adapter DNS configuration.</summary>
        public List<AdapterDns> Adapters { get; set; } = new();

        /// <summary>Whether DNS-over-HTTPS is enabled system-wide (Win11+).</summary>
        public bool? DohEnabled { get; set; }

        /// <summary>LLMNR enabled (multicast DNS fallback, spoofable).</summary>
        public bool LlmnrEnabled { get; set; } = true;

        /// <summary>NetBIOS over TCP/IP enabled (legacy name resolution, spoofable).</summary>
        public bool NetBiosEnabled { get; set; } = true;

        /// <summary>DNS cache max entry count (0 = default).</summary>
        public int DnsCacheMaxEntries { get; set; }

        /// <summary>DNS cache max TTL in seconds.</summary>
        public int DnsCacheMaxTtl { get; set; }

        /// <summary>Parsed hosts file entries (hostname → IP).</summary>
        public List<HostsEntry> HostsFileEntries { get; set; } = new();

        /// <summary>Whether the hosts file was readable.</summary>
        public bool HostsFileReadable { get; set; } = true;

        /// <summary>Total number of hosts file entries (including comments removed).</summary>
        public int HostsFileTotalLines { get; set; }

        /// <summary>Whether DNSSEC validation is enabled on the client.</summary>
        public bool DnssecValidationEnabled { get; set; }
    }

    public sealed class AdapterDns
    {
        public string AdapterName { get; set; } = string.Empty;
        public List<string> DnsServers { get; set; } = new();
        public bool IsDhcp { get; set; }
        public string InterfaceAlias { get; set; } = string.Empty;
    }

    public sealed class HostsEntry
    {
        public string IpAddress { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public int LineNumber { get; set; }
    }

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
            var state = await GatherStateAsync(cancellationToken);
            AnalyzeState(state, result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    /// <summary>
    /// Gather live DNS state from the system. Separated for testability.
    /// </summary>
    internal async Task<DnsState> GatherStateAsync(CancellationToken ct)
    {
        var state = new DnsState();

        // Get per-adapter DNS servers
        var adapterOutput = await ShellHelper.RunPowerShellAsync(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | " +
            "Select-Object InterfaceAlias, @{N='Servers';E={$_.ServerAddresses -join ','}} | " +
            "ConvertTo-Csv -NoTypeInformation", ct);

        foreach (var line in adapterOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim().Trim('"');
            if (trimmed.StartsWith("InterfaceAlias", StringComparison.OrdinalIgnoreCase)) continue;

            var parts = trimmed.Split("\",\"");
            if (parts.Length >= 2)
            {
                var alias = parts[0].Trim('"');
                var servers = parts[1].Trim('"')
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .ToList();

                if (servers.Count > 0)
                {
                    state.Adapters.Add(new AdapterDns
                    {
                        AdapterName = alias,
                        InterfaceAlias = alias,
                        DnsServers = servers
                    });
                }
            }
        }

        // Check DoH status (Windows 11+)
        try
        {
            var dohOutput = await ShellHelper.RunPowerShellAsync(
                "Get-DnsClientDohServerAddress | ConvertTo-Json -Compress", ct);
            state.DohEnabled = !string.IsNullOrWhiteSpace(dohOutput) && dohOutput != "[]";
        }
        catch
        {
            state.DohEnabled = null; // cmdlet not available
        }

        // Check LLMNR
        var llmnrOutput = await ShellHelper.RunPowerShellAsync(
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' " +
            "-Name EnableMulticast -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableMulticast", ct);
        state.LlmnrEnabled = !int.TryParse(llmnrOutput.Trim(), out var llmnrVal) || llmnrVal != 0;

        // Check NetBIOS
        var netbiosOutput = await ShellHelper.RunPowerShellAsync(
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters' " +
            "-Name NodeType -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NodeType", ct);
        // NodeType 2 = P-node (point-to-point only, no broadcast) is most secure
        state.NetBiosEnabled = !int.TryParse(netbiosOutput.Trim(), out var nodeType) || nodeType != 2;

        // DNS cache settings
        var cacheTtlOutput = await ShellHelper.RunPowerShellAsync(
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' " +
            "-Name MaxCacheTtl -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MaxCacheTtl", ct);
        if (int.TryParse(cacheTtlOutput.Trim(), out var maxTtl))
            state.DnsCacheMaxTtl = maxTtl;

        // Read hosts file
        try
        {
            var hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
            var hostsContent = await File.ReadAllLinesAsync(hostsPath, ct);
            state.HostsFileTotalLines = hostsContent.Length;

            for (int i = 0; i < hostsContent.Length; i++)
            {
                var hLine = hostsContent[i].Trim();
                if (string.IsNullOrEmpty(hLine) || hLine.StartsWith('#')) continue;

                // Remove inline comments
                var commentIdx = hLine.IndexOf('#');
                if (commentIdx >= 0) hLine = hLine[..commentIdx].Trim();

                var hParts = hLine.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (hParts.Length >= 2)
                {
                    state.HostsFileEntries.Add(new HostsEntry
                    {
                        IpAddress = hParts[0],
                        Hostname = hParts[1],
                        LineNumber = i + 1
                    });
                }
            }
        }
        catch
        {
            state.HostsFileReadable = false;
        }

        return state;
    }

    /// <summary>
    /// Analyze the gathered DNS state and populate findings.
    /// Public for unit testing.
    /// </summary>
    public void AnalyzeState(DnsState state, AuditResult result)
    {
        CheckDnsServers(state, result);
        CheckDoh(state, result);
        CheckLlmnr(state, result);
        CheckNetBios(state, result);
        CheckHostsFile(state, result);
        CheckCacheSettings(state, result);
    }

    private void CheckDnsServers(DnsState state, AuditResult result)
    {
        if (state.Adapters.Count == 0)
        {
            result.Findings.Add(Finding.Info(
                "No DNS Adapters Found",
                "Could not enumerate network adapter DNS configuration.",
                Category));
            return;
        }

        foreach (var adapter in state.Adapters)
        {
            foreach (var server in adapter.DnsServers)
            {
                if (SuspiciousDns.Contains(server))
                {
                    result.Findings.Add(Finding.Critical(
                        $"Suspicious DNS Server on {adapter.InterfaceAlias}",
                        $"DNS server {server} is associated with malware or DNS hijacking.",
                        Category,
                        $"Change DNS to a trusted provider (e.g., 1.1.1.1, 8.8.8.8, 9.9.9.9).",
                        $"Set-DnsClientServerAddress -InterfaceAlias '{adapter.InterfaceAlias}' -ServerAddresses ('1.1.1.1','1.0.0.1')"));
                }
                else if (KnownSecureDns.TryGetValue(server, out var provider))
                {
                    result.Findings.Add(Finding.Pass(
                        $"Trusted DNS on {adapter.InterfaceAlias}",
                        $"Using {provider} DNS ({server}).",
                        Category));
                }
                else if (server.StartsWith("10.") || server.StartsWith("192.168.") || server.StartsWith("172."))
                {
                    // Private/LAN DNS — typical for corporate/home routers
                    result.Findings.Add(Finding.Info(
                        $"Private DNS on {adapter.InterfaceAlias}",
                        $"DNS server {server} is a private/LAN address (router or internal DNS). " +
                        "Ensure upstream DNS is trustworthy.",
                        Category));
                }
                else
                {
                    result.Findings.Add(Finding.Warning(
                        $"Unknown DNS Server on {adapter.InterfaceAlias}",
                        $"DNS server {server} is not a recognized secure provider. " +
                        "Verify this server is trustworthy.",
                        Category,
                        "Consider using a well-known DNS provider (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9)."));
                }
            }
        }
    }

    private void CheckDoh(DnsState state, AuditResult result)
    {
        if (state.DohEnabled == null)
        {
            result.Findings.Add(Finding.Info(
                "DNS-over-HTTPS Status Unknown",
                "Could not determine DoH status. This feature requires Windows 11 or later.",
                Category));
        }
        else if (state.DohEnabled == true)
        {
            result.Findings.Add(Finding.Pass(
                "DNS-over-HTTPS Configured",
                "DoH server addresses are configured, encrypting DNS queries.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Warning(
                "DNS-over-HTTPS Not Configured",
                "DNS queries are sent in plaintext, allowing network observers to see visited domains.",
                Category,
                "Enable DNS-over-HTTPS in Windows Settings → Network → DNS, or use a DNS provider that supports DoH.",
                "Add-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $true -AutoUpgrade $true"));
        }
    }

    private void CheckLlmnr(DnsState state, AuditResult result)
    {
        if (state.LlmnrEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "LLMNR Enabled",
                "Link-Local Multicast Name Resolution is enabled. Attackers on the local network " +
                "can respond to LLMNR queries to capture credentials (LLMNR poisoning/Responder attacks).",
                Category,
                "Disable LLMNR via Group Policy or registry.",
                "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' " +
                "-Name EnableMulticast -Value 0 -PropertyType DWord -Force"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "LLMNR Disabled",
                "Link-Local Multicast Name Resolution is disabled, preventing LLMNR poisoning attacks.",
                Category));
        }
    }

    private void CheckNetBios(DnsState state, AuditResult result)
    {
        if (state.NetBiosEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "NetBIOS Name Resolution Enabled",
                "NetBIOS over TCP/IP allows broadcast-based name resolution, which is vulnerable to " +
                "spoofing and man-in-the-middle attacks on the local network.",
                Category,
                "Set NetBIOS node type to P-node (2) to disable broadcast name resolution.",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters' " +
                "-Name NodeType -Value 2"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "NetBIOS Broadcast Disabled",
                "NetBIOS is configured for point-to-point only (P-node), preventing broadcast spoofing.",
                Category));
        }
    }

    private void CheckHostsFile(DnsState state, AuditResult result)
    {
        if (!state.HostsFileReadable)
        {
            result.Findings.Add(Finding.Warning(
                "Hosts File Unreadable",
                "Could not read the system hosts file. It may have restrictive permissions or be missing.",
                Category,
                "Check permissions on C:\\Windows\\System32\\drivers\\etc\\hosts."));
            return;
        }

        var suspiciousEntries = new List<HostsEntry>();
        foreach (var entry in state.HostsFileEntries)
        {
            // Check if a sensitive domain is being redirected
            foreach (var domain in SensitiveDomains)
            {
                if (entry.Hostname.Contains(domain, StringComparison.OrdinalIgnoreCase) &&
                    entry.IpAddress != "127.0.0.1" && entry.IpAddress != "::1")
                {
                    suspiciousEntries.Add(entry);
                }
            }
        }

        if (suspiciousEntries.Count > 0)
        {
            var details = string.Join("; ",
                suspiciousEntries.Select(e => $"Line {e.LineNumber}: {e.IpAddress} → {e.Hostname}"));
            result.Findings.Add(Finding.Critical(
                "Suspicious Hosts File Entries",
                $"The hosts file redirects sensitive domains to unexpected addresses: {details}. " +
                "This could indicate malware or DNS hijacking.",
                Category,
                "Review and remove suspicious entries from C:\\Windows\\System32\\drivers\\etc\\hosts."));
        }
        else if (state.HostsFileEntries.Count > 50)
        {
            result.Findings.Add(Finding.Info(
                "Large Hosts File",
                $"The hosts file contains {state.HostsFileEntries.Count} entries. " +
                "While not necessarily malicious, large hosts files can indicate ad-blockers or " +
                "potentially unwanted modifications.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Hosts File Clean",
                $"The hosts file has {state.HostsFileEntries.Count} entries with no suspicious redirections.",
                Category));
        }
    }

    private void CheckCacheSettings(DnsState state, AuditResult result)
    {
        if (state.DnsCacheMaxTtl > 0 && state.DnsCacheMaxTtl < 300)
        {
            result.Findings.Add(Finding.Info(
                "Low DNS Cache TTL",
                $"DNS cache max TTL is set to {state.DnsCacheMaxTtl} seconds. " +
                "Very low TTL increases DNS query volume but reduces stale-cache risk.",
                Category));
        }
        else if (state.DnsCacheMaxTtl > 86400)
        {
            result.Findings.Add(Finding.Warning(
                "High DNS Cache TTL",
                $"DNS cache max TTL is {state.DnsCacheMaxTtl} seconds ({state.DnsCacheMaxTtl / 3600}h). " +
                "Excessively long cache TTL can serve stale or poisoned records longer.",
                Category,
                "Reduce DNS cache TTL to a reasonable value (e.g., 86400 seconds / 24 hours).",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' " +
                "-Name MaxCacheTtl -Value 86400"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "DNS Cache TTL Normal",
                state.DnsCacheMaxTtl > 0
                    ? $"DNS cache max TTL is {state.DnsCacheMaxTtl} seconds — within normal range."
                    : "DNS cache TTL is at the system default.",
                Category));
        }
    }
}
