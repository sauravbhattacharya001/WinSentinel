using System.Net;
using System.Net.Sockets;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;
using NetworkState = WinSentinel.Core.Audits.NetworkPostureAnalyzer.NetworkState;
using Toggle = WinSentinel.Core.Audits.NetworkPostureAnalyzer.Toggle;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits network configuration: open ports, listening services, SMB/RDP exposure,
/// IPv6, Wi-Fi security, network profile, LLMNR/NetBIOS poisoning, and ARP anomalies.
///
/// This module owns only data collection from the live system (PowerShell, netsh,
/// cmd). Every security decision (which ports are high-risk, the RDP-without-NLA
/// critical, the Wi-Fi/SMB/LLMNR classifications, the duplicate-MAC ARP heuristic,
/// ...) lives in the pure, unit-tested <see cref="NetworkPostureAnalyzer"/>. Mirrors
/// the PowerShellAudit / PowerShellSecurityAnalyzer split.
/// </summary>
public class NetworkAudit : AuditModuleBase
{
    public override string Name => "Network Audit";
    public override string Category => "Network";
    public override string Description => "Checks open ports, listening services, SMB/RDP exposure, IPv6, Wi-Fi security, network profile, LLMNR/NetBIOS/WPAD, and ARP anomalies.";

    /// <summary>
    /// High-risk TCP ports. Kept for backwards compatibility; the source of truth is
    /// <see cref="NetworkPostureAnalyzer.HighRiskPorts"/>.
    /// </summary>
    public static IReadOnlySet<int> HighRiskPorts => NetworkPostureAnalyzer.HighRiskPorts;

    // ── Audit entry point ───────────────────────────────────────

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = await CollectStateAsync(cancellationToken);
        AnalyzeState(state, result);
    }

    // ── Analysis (delegates to the pure analyzer) ───────────────

    /// <summary>
    /// Analyzes a <see cref="NetworkState"/> and populates findings by delegating to
    /// <see cref="NetworkPostureAnalyzer.Analyze"/>. Thin wrapper so the I/O and the
    /// decision logic stay testable in isolation.
    /// </summary>
    public void AnalyzeState(NetworkState state, AuditResult result)
    {
        result.Findings.AddRange(NetworkPostureAnalyzer.Analyze(state));
    }

    // ── Data collection (calls real system) ─────────────────────

    /// <summary>Collects the current network security state from the system.</summary>
    public async Task<NetworkState> CollectStateAsync(CancellationToken ct = default)
    {
        var state = new NetworkState();

        await CollectListeningPorts(state, ct);
        await CollectSmb(state, ct);
        await CollectRdp(state, ct);
        await CollectWinRm(state, ct);
        await CollectDns(state, ct);
        await CollectNetworkProfile(state, ct);
        await CollectWiFi(state, ct);
        await CollectLlmnrNetBios(state, ct);
        await CollectWpad(state, ct);
        await CollectArp(state, ct);
        await CollectIPv6(state, ct);

        return state;
    }

    private async Task CollectListeningPorts(NetworkState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
              Select-Object LocalPort, OwningProcess | 
              Sort-Object LocalPort -Unique | 
              ForEach-Object { 
                  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                  '{0}|{1}' -f $_.LocalPort, $proc.ProcessName 
              }", ct);

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (TryParseListeningPortLine(line, out var listeningPort))
            {
                state.ListeningPorts.Add(listeningPort);
            }
        }
    }

    /// <summary>
    /// Parse a single line of the listening-ports collector's pipe-delimited PowerShell
    /// output (<c>'{0}|{1}' -f $_.LocalPort, $proc.ProcessName</c>) into a
    /// <see cref="NetworkPostureAnalyzer.ListeningPort"/>. Returns false for anything
    /// that is not a real <c>port|process</c> row.
    ///
    /// <para>The previous inline parse accepted column 0 as a port whenever
    /// <see cref="int.TryParse(string, out int)"/> succeeded, with no range check, and
    /// stored column 1 verbatim. That was both too permissive and locale-fragile:
    /// a stray header/diagnostic line (or a localized <c>Get-NetTCPConnection</c> banner)
    /// whose first token happened to be numeric — e.g. a year, a PID, <c>0</c>, or an
    /// out-of-range <c>999999</c> — was ingested as a bogus "listening port", which then
    /// feeds the open-port exposure analysis and can manufacture a phantom finding. And
    /// when the owning process had exited between enumeration and <c>Get-Process</c> the
    /// line came through as <c>445|</c>, storing a port with a blank owner. We now require
    /// column 0 to be a genuine TCP port (1–65535) by structure and normalize a
    /// missing/blank process name to <c>"unknown"</c>, so junk lines are rejected for what
    /// they are — on any Windows display language — and a real port always carries a
    /// non-empty owner label.</para>
    /// </summary>
    internal static bool TryParseListeningPortLine(string? line, out NetworkPostureAnalyzer.ListeningPort port)
    {
        port = new NetworkPostureAnalyzer.ListeningPort();
        if (string.IsNullOrWhiteSpace(line)) return false;

        // Rows look like "445|System" or "49664|svchost"; an exited owner yields "445|".
        var parts = line.Split('|');
        if (parts.Length < 2) return false; // need both a port and a (possibly empty) owner column

        if (!IsValidTcpPort(parts[0].Trim(), out int portNumber)) return false;

        var processName = parts[1].Trim();
        if (processName.Length == 0) processName = "unknown";

        port = new NetworkPostureAnalyzer.ListeningPort(portNumber, processName);
        return true;
    }

    /// <summary>True only for a valid, in-range TCP port number (1-65535). Rejects
    /// non-numeric tokens, 0, negatives, and anything above 65535.</summary>
    internal static bool IsValidTcpPort(string? value, out int port)
    {
        port = 0;
        if (string.IsNullOrWhiteSpace(value)) return false;
        foreach (var c in value) if (c < '0' || c > '9') return false; // digits only (rejects '-1', '5e3', '0x1f')
        if (!int.TryParse(value, out var n)) return false;
        if (n < 1 || n > 65535) return false;
        port = n;
        return true;
    }

    private async Task CollectSmb(NetworkState state, CancellationToken ct)
    {
        var smbv1 = await ShellHelper.RunPowerShellAsync(
            @"try { (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { 'ERROR' }", ct);
        state.Smbv1 = ParseToggle(smbv1);

        var smbSigning = await ShellHelper.RunPowerShellAsync(
            @"try { (Get-SmbServerConfiguration).RequireSecuritySignature } catch { 'ERROR' }", ct);
        state.SmbSigningRequired = ParseToggle(smbSigning);

        var shares = await ShellHelper.RunPowerShellAsync(
            @"Get-SmbShare | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne 'IPC$' } | Select-Object -ExpandProperty Name", ct);
        state.NonDefaultShares = shares
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
    }

    private async Task CollectRdp(NetworkState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections", ct);

        // fDenyTSConnections == 0 means RDP is enabled. Parse defensively: only a
        // clean lone DWORD counts (see IsRdpEnabledFromDeny) so a noisy/multi-line
        // PowerShell blob can't be misread as "0" and report RDP exposed when it
        // isn't (or vice-versa).
        state.RdpEnabled = IsRdpEnabledFromDeny(output);

        if (state.RdpEnabled)
        {
            var nla = await ShellHelper.RunPowerShellAsync(
                @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication", ct);
            // UserAuthentication == 1 means NLA is enabled. Fail SAFE: NLA counts as
            // enabled ONLY for a clean lone "1"; a clean "0" or any unreadable/garbage
            // output is treated as NOT enabled, so a failed registry read surfaces the
            // "RDP without NLA" exposure rather than silently suppressing it.
            state.RdpNlaEnabled = IsNlaEnabledFromValue(nla);
        }
    }

    private async Task CollectWinRm(NetworkState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"try { $status = Get-Service WinRM -ErrorAction SilentlyContinue; $status.Status } catch { 'NotFound' }", ct);
        state.WinRmRunning = output.Trim().Equals("Running", StringComparison.OrdinalIgnoreCase);
    }

    private async Task CollectDns(NetworkState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-DnsClientServerAddress -AddressFamily IPv4 | 
              Where-Object { $_.ServerAddresses.Count -gt 0 } | 
              Select-Object -ExpandProperty ServerAddresses -Unique", ct);

        if (!string.IsNullOrWhiteSpace(output))
        {
            state.DnsServers = output
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        }
    }

    private async Task CollectNetworkProfile(NetworkState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' } |
              ForEach-Object { '{0}|{1}' -f $_.Name, $_.NetworkCategory }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        state.ActiveNetworkCount = lines.Length;

        foreach (var line in lines)
        {
            var parts = line.Split('|');
            if (parts.Length >= 2 && parts[1].Equals("Public", StringComparison.OrdinalIgnoreCase))
            {
                state.PublicNetworks.Add(parts[0]);
            }
        }
    }

    private async Task CollectWiFi(NetworkState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunNetshAsync("wlan show interfaces", ct);

        if (string.IsNullOrWhiteSpace(output) || output.Contains("not running", StringComparison.OrdinalIgnoreCase))
        {
            // No wireless adapter / WLAN service - leave Wi-Fi state empty so the
            // analyzer emits nothing.
            return;
        }

        string? ssid = null, auth = null, cipher = null, connState = null;

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) && !line.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                ssid = AfterColon(line) ?? ssid;
            else if (line.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
                auth = AfterColon(line) ?? auth;
            else if (line.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase))
                cipher = AfterColon(line) ?? cipher;
            else if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase))
                connState = AfterColon(line) ?? connState;
        }

        state.WiFiConnected = connState != null && connState.Contains("connected", StringComparison.OrdinalIgnoreCase);
        state.WiFiSsid = ssid;
        state.WiFiAuth = auth;
        state.WiFiCipher = cipher;
    }

    private async Task CollectLlmnrNetBios(NetworkState state, CancellationToken ct)
    {
        var llmnrOutput = await ShellHelper.RunPowerShellAsync(
            @"try {
                $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue
                if ($key) { $key.EnableMulticast } else { 'NOT_SET' }
            } catch { 'ERROR' }", ct);

        // Decide LLMNR from the first recognised token line, tolerating a
        // prepended CIM/registry warning or banner that a whole-blob Trim()=="0"
        // would have mis-read as enabled. 0 => Disabled; 1/NOT_SET/ERROR/none =>
        // Enabled (the analyzer only passes on Disabled, so unknown still warns).
        state.Llmnr = ClassifyLlmnrValue(llmnrOutput);

        var netbiosOutput = await ShellHelper.RunPowerShellAsync(
            @"Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
              ForEach-Object { '{0}|{1}' -f $_.Description, $_.TcpipNetbiosOptions }", ct);

        var netbiosLines = netbiosOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var line in netbiosLines)
        {
            var parts = line.Split('|');
            // Only count lines that actually look like an adapter row (Description|
            // Options); a stray CIM warning without a '|' must not inflate the
            // adapter count (which gates the "all adapters disabled" Pass message).
            if (parts.Length < 2) continue;
            state.NetBiosAdapterCount++;
            // TcpipNetbiosOptions: 0 = Default (enabled via DHCP), 1 = Enabled,
            // 2 = Disabled. IsNetBiosEnabledFromOption fails SAFE -- a clean 2 is
            // the only "disabled"; a garbage value is treated as enabled so the
            // adapter still surfaces rather than being silently dropped.
            if (IsNetBiosEnabledFromOption(parts[1]))
            {
                state.NetBiosEnabledAdapters.Add(parts[0]);
            }
        }
    }

    private async Task CollectWpad(NetworkState state, CancellationToken ct)
    {
        // Read the Microsoft-documented machine-wide WPAD kill switch
        // (HKLM\...\Internet Settings\WinHttp\DisableWpad; 1 = WPAD auto-discovery
        // disabled). Emit one of 0 / 1 / NOT_SET / ERROR so the classifier can decide
        // the posture from a clean token line even if a CIM/registry banner is
        // prepended.
        var output = await ShellHelper.RunPowerShellAsync(
            @"try {
                $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -ErrorAction SilentlyContinue
                if ($key -ne $null -and $key.PSObject.Properties.Name -contains 'DisableWpad') { $key.DisableWpad } else { 'NOT_SET' }
            } catch { 'ERROR' }", ct);

        state.WpadHardened = ClassifyWpadValue(output);
    }

    private async Task CollectArp(NetworkState state, CancellationToken ct)
    {
        string output;
        try
        {
            output = await ShellHelper.RunCmdAsync("arp -a", ct);
        }
        catch (Exception ex)
        {
            state.ArpQueryFailed = true;
            state.ArpError = ex.Message;
            return;
        }

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (TryParseArpLine(line, out var entry))
                state.ArpEntries.Add(entry);
        }
    }

    /// <summary>
    /// Parse a single line of <c>arp -a</c> output into an <see cref="NetworkPostureAnalyzer.ArpEntry"/>.
    /// Returns false for anything that is not a real IPv4+MAC row.
    ///
    /// <para>This is structural validation rather than the old positional heuristic
    /// (<c>parts[0].Contains('.') &amp;&amp; parts[1].Contains('-') &amp;&amp; parts[1].Length &gt;= 17</c>),
    /// which only rejected the <c>Interface: 192.168.1.5 --- 0x5</c> header and the
    /// <c>Internet Address / Physical Address / Type</c> column header by the accident of
    /// where their dotted/hyphenated tokens happened to land. That heuristic was both too
    /// permissive (any &gt;=17-char token containing a '-' in column 2 was accepted as a MAC,
    /// so a localized header whose second column carries a hyphenated word would be ingested
    /// as a bogus ARP entry and could even manufacture a phantom "duplicate MAC" spoofing
    /// alert) and locale-fragile. We now require column 0 to be a real dotted-quad IPv4
    /// address and column 1 to be a real 6-octet MAC (<c>xx-xx-xx-xx-xx-xx</c>), so header /
    /// interface lines are rejected by what they are, not by luck — on any Windows display
    /// language.</para>
    /// </summary>
    internal static bool TryParseArpLine(string? line, out NetworkPostureAnalyzer.ArpEntry entry)
    {
        entry = new NetworkPostureAnalyzer.ArpEntry();
        if (string.IsNullOrWhiteSpace(line)) return false;

        // ARP table rows look like: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return false; // need IP, MAC, and a Type column

        var ip = parts[0];
        var mac = parts[1];
        if (!IsIPv4DottedQuad(ip)) return false;
        if (!IsMacAddress(mac)) return false;

        entry = new NetworkPostureAnalyzer.ArpEntry(ip, mac);
        return true;
    }

    /// <summary>True only for a well-formed dotted-quad IPv4 address (each octet 0-255).</summary>
    internal static bool IsIPv4DottedQuad(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var octets = value.Split('.');
        if (octets.Length != 4) return false;
        foreach (var octet in octets)
        {
            if (octet.Length == 0 || octet.Length > 3) return false;
            foreach (var c in octet) if (c < '0' || c > '9') return false;
            if (!int.TryParse(octet, out var n) || n < 0 || n > 255) return false;
        }
        return true;
    }

    /// <summary>
    /// True only for a 6-octet MAC in Windows <c>arp -a</c> form: six hyphen-separated
    /// pairs of hex digits (e.g. <c>aa-bb-cc-dd-ee-ff</c>). Rejects partial/incomplete
    /// entries and any hyphenated non-MAC token.
    /// </summary>
    internal static bool IsMacAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var groups = value.Split('-');
        if (groups.Length != 6) return false;
        foreach (var g in groups)
        {
            if (g.Length != 2) return false;
            foreach (var c in g)
            {
                bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!isHex) return false;
            }
        }
        return true;
    }

    private async Task CollectIPv6(NetworkState state, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"$addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | 
              Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^fe80' -and $_.IPAddress -ne '::1' }
              $addrs | ForEach-Object { '{0}|{1}|{2}' -f $_.IPAddress, $_.InterfaceAlias, $_.PrefixOrigin }", ct);

        state.GlobalIPv6Addresses = output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => TryParseGlobalIPv6Line(l, out var addr) ? addr : null)
            .Where(addr => addr != null)
            .Select(addr => addr!)
            .ToList();

        var tunnelingOutput = await ShellHelper.RunNetshAsync("interface teredo show state", ct);
        if (!string.IsNullOrWhiteSpace(tunnelingOutput))
        {
            foreach (var rawLine in tunnelingOutput.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("Type", StringComparison.OrdinalIgnoreCase))
                {
                    if (IsTeredoActiveState(AfterColon(line)))
                    {
                        state.TeredoActive = true;
                    }
                }
            }
        }
    }

    /// <summary>
    /// Parses one line of the IPv6 collector's pipe-delimited PowerShell output
    /// (<c>address|interfaceAlias|prefixOrigin</c>) and returns the address only when
    /// column 0 is a genuine, routable global IPv6 address. Rejects malformed lines,
    /// non-IPv6 / non-parseable column-0 tokens, and non-global scopes (link-local
    /// <c>fe80::/10</c>, loopback <c>::1</c>, unspecified <c>::</c>, multicast
    /// <c>ff00::/8</c>) by <em>structure</em>, so a localized header or stray output
    /// line can never be ingested as a bogus "global IPv6 address" finding.
    /// </summary>
    internal static bool TryParseGlobalIPv6Line(string? line, out string address)
    {
        address = string.Empty;
        if (string.IsNullOrWhiteSpace(line)) return false;
        var trimmed = line.Trim();
        if (!trimmed.Contains('|')) return false;

        var candidate = trimmed.Split('|')[0].Trim();
        if (!IsGlobalIPv6Address(candidate)) return false;

        address = candidate;
        return true;
    }

    /// <summary>
    /// True only for a syntactically valid IPv6 address that is also <em>global</em>:
    /// not loopback (<c>::1</c>), not the unspecified address (<c>::</c>), not
    /// link-local (<c>fe80::/10</c>), and not multicast (<c>ff00::/8</c>). Uses
    /// <see cref="IPAddress.TryParse(string, out IPAddress)"/> + address-family /
    /// scope flags rather than string matching, so it is locale- and format-robust.
    /// </summary>
    internal static bool IsGlobalIPv6Address(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        // Reject any zone/scope suffix (e.g. "fe80::1%eth0") explicitly so we never
        // accept a scoped link-local that happens to parse.
        if (value.Contains('%')) return false;
        if (!IPAddress.TryParse(value, out var ip)) return false;
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
        if (IPAddress.IsLoopback(ip)) return false;                 // ::1
        if (ip.IsIPv6LinkLocal) return false;                       // fe80::/10
        if (ip.IsIPv6Multicast) return false;                       // ff00::/8
        if (ip.Equals(IPAddress.IPv6Any)) return false;             // ::
        return true;
    }

    /// <summary>
    /// Classifies the <c>Type:</c> value from <c>netsh interface teredo show state</c>.
    /// Teredo is only "active" for client-class states (<c>client</c>,
    /// <c>enterpriseclient</c>) or an explicit relay/server role; <c>disabled</c>,
    /// <c>default</c>, <c>offline</c>, <c>dormant</c>, blank and unknown values are
    /// treated as inactive. Matching specific active states (rather than "anything
    /// not disabled/default") prevents a stray/localized token from manufacturing a
    /// phantom Teredo-active warning.
    /// </summary>
    internal static bool IsTeredoActiveState(string? typeValue)
    {
        if (string.IsNullOrWhiteSpace(typeValue)) return false;
        var v = typeValue.Trim();
        return v.Equals("client", StringComparison.OrdinalIgnoreCase)
            || v.Equals("enterpriseclient", StringComparison.OrdinalIgnoreCase)
            || v.Equals("relay", StringComparison.OrdinalIgnoreCase)
            || v.Equals("server", StringComparison.OrdinalIgnoreCase);
    }

    // ── Collection helpers ──────────────────────────────────────

    /// <summary>
    /// Parses a PowerShell boolean string ("True"/"False") into a <see cref="Toggle"/>,
    /// tolerating noisy / multi-line output. Plain <c>raw.Trim() == "True"</c> failed
    /// whenever the value was preceded or followed by another line -- a CIM/WMI
    /// warning, a verbose banner, or the <c>'ERROR'</c> catch sentinel emitted
    /// alongside the value -- silently degrading a known True/False to Unknown.
    /// This scans the output and returns the toggle for the first line that is
    /// EXACTLY a boolean token (case-insensitive); any other line (including the
    /// 'ERROR' sentinel) is ignored. Returns <see cref="Toggle.Unknown"/> when no
    /// such line is present.
    /// </summary>
    internal static Toggle ParseToggle(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return Toggle.Unknown;
        foreach (var line in raw.Split('\n'))
        {
            var t = line.Trim();
            if (t.Length == 0) continue;
            if (t.Equals("True", StringComparison.OrdinalIgnoreCase)) return Toggle.Enabled;
            if (t.Equals("False", StringComparison.OrdinalIgnoreCase)) return Toggle.Disabled;
        }
        return Toggle.Unknown;
    }

    /// <summary>
    /// Parses a single registry DWORD value from PowerShell output. Accepts ONLY a
    /// clean lone non-negative integer (optionally surrounded by whitespace / blank
    /// lines); rejects multi-valued output, hex, signs, and any line containing
    /// non-digit noise. This is the trust gate behind the RDP flag readers so a
    /// noisy blob can never be coerced into a security-relevant 0/1.
    /// </summary>
    internal static bool TryParseRegistryDword(string? raw, out int value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(raw)) return false;
        string? token = null;
        foreach (var line in raw.Split('\n'))
        {
            var t = line.Trim();
            if (t.Length == 0) continue;
            if (token != null) return false; // more than one non-blank line -> ambiguous
            token = t;
        }
        if (token == null) return false;
        // Digits only (no sign, no hex, no decimal, no embedded space).
        foreach (var c in token)
        {
            if (c < '0' || c > '9') return false;
        }
        return int.TryParse(token, out value);
    }

    /// <summary>
    /// True only when <c>fDenyTSConnections</c> output is a clean lone <c>0</c>
    /// (RDP enabled). Any other value, missing key, or noisy output -> false
    /// (RDP treated as not enabled).
    /// </summary>
    internal static bool IsRdpEnabledFromDeny(string? raw)
        => TryParseRegistryDword(raw, out var v) && v == 0;

    /// <summary>
    /// True only when the <c>UserAuthentication</c> output is a clean lone <c>1</c>
    /// (NLA enabled). Fails SAFE: a clean <c>0</c> OR any unreadable / multi-line /
    /// non-numeric output returns false, so a failed registry read surfaces the
    /// "RDP without NLA" exposure instead of hiding it.
    /// </summary>
    internal static bool IsNlaEnabledFromValue(string? raw)
        => TryParseRegistryDword(raw, out var v) && v == 1;

    /// <summary>
    /// Classifies the <c>EnableMulticast</c> (LLMNR GPO) reader output into a
    /// <see cref="Toggle"/>. The reader emits one of <c>0</c> / <c>1</c> /
    /// <c>NOT_SET</c> / <c>ERROR</c>, but a prepended CIM/registry warning or
    /// verbose banner line would make a whole-blob <c>Trim() == "0"</c> test
    /// mis-read a genuinely-disabled (<c>0</c>) value as enabled. Instead, scan
    /// for the FIRST line that is exactly a recognised token and decide from it,
    /// ignoring surrounding noise: a clean lone <c>0</c> =&gt; Disabled, a clean
    /// lone <c>1</c> =&gt; Enabled. <c>NOT_SET</c> / <c>ERROR</c> / no recognised
    /// line =&gt; Enabled, preserving the original audit's conservative "warn on
    /// anything other than explicit 0" stance (the analyzer only emits Pass for
    /// Toggle.Disabled, so unknown safely surfaces the LLMNR-poisoning exposure).
    /// </summary>
    internal static Toggle ClassifyLlmnrValue(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return Toggle.Enabled;
        foreach (var line in raw.Split('\n'))
        {
            var t = line.Trim();
            if (t.Length == 0) continue;
            if (t == "0") return Toggle.Disabled;
            if (t == "1") return Toggle.Enabled;
            if (t.Equals("NOT_SET", StringComparison.OrdinalIgnoreCase)) return Toggle.Enabled;
            if (t.Equals("ERROR", StringComparison.OrdinalIgnoreCase)) return Toggle.Enabled;
            // Unrecognised noise line (e.g. a CIM warning): skip and keep scanning
            // for the real token line rather than letting it decide the verdict.
        }
        return Toggle.Enabled; // no recognised token -> treat as enabled/unknown (warn)
    }

    /// <summary>
    /// Classifies the <c>DisableWpad</c> (WPAD kill switch) reader output into the
    /// <see cref="NetworkState.WpadHardened"/> posture toggle. The reader emits one of
    /// <c>0</c> / <c>1</c> / <c>NOT_SET</c> / <c>ERROR</c>. Because a CIM/registry
    /// warning line can be prepended, scan for the FIRST line that is exactly a
    /// recognised token rather than testing the whole blob: a clean lone <c>1</c>
    /// =&gt; <see cref="Toggle.Enabled"/> (hardened - the only Pass state); a clean lone
    /// <c>0</c> =&gt; <see cref="Toggle.Disabled"/> (kill switch present but off). A
    /// missing value (<c>NOT_SET</c>), an <c>ERROR</c>, or no recognised token map to
    /// <see cref="Toggle.Unknown"/>. The analyzer warns on both Disabled and Unknown,
    /// so an absent/unreadable kill switch fails SAFE and surfaces the WPAD-poisoning
    /// exposure instead of hiding it.
    /// </summary>
    internal static Toggle ClassifyWpadValue(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return Toggle.Unknown;
        foreach (var line in raw.Split('\n'))
        {
            var t = line.Trim();
            if (t.Length == 0) continue;
            if (t == "1") return Toggle.Enabled;   // DisableWpad = 1 => WPAD hardened OFF
            if (t == "0") return Toggle.Disabled;  // present but 0 => WPAD still active
            if (t.Equals("NOT_SET", StringComparison.OrdinalIgnoreCase)) return Toggle.Unknown;
            if (t.Equals("ERROR", StringComparison.OrdinalIgnoreCase)) return Toggle.Unknown;
            // Unrecognised noise line (e.g. a registry warning): skip and keep scanning.
        }
        return Toggle.Unknown; // no recognised token -> unknown (analyzer warns, fail-safe)
    }

    /// <summary>
    /// True when an adapter's <c>TcpipNetbiosOptions</c> value means NetBIOS over
    /// TCP/IP is still ENABLED on that adapter (0 = default/DHCP-enabled, 1 =
    /// explicitly enabled; 2 = disabled). Fails SAFE: only a clean lone <c>2</c>
    /// counts as disabled -- a clean <c>0</c>/<c>1</c> OR any unparseable value
    /// (multi-token, hex, decimal, signed, empty, or noisy) is treated as enabled
    /// so a malformed value surfaces the NBT-NS poisoning exposure instead of
    /// silently dropping the adapter (the old <c>== "0" || == "1"</c> test
    /// classified every non-0/1 value, including garbage, as disabled).
    /// </summary>
    internal static bool IsNetBiosEnabledFromOption(string? option)
    {
        // A clean lone non-negative DWORD equal to 2 is the ONLY "disabled".
        if (TryParseRegistryDword(option, out var v)) return v != 2;
        // Unparseable / noisy / missing -> fail safe to enabled (surface it).
        return true;
    }

    /// <summary>Returns the trimmed text after the first ':' in a line, or null.</summary>
    private static string? AfterColon(string line)
    {
        var idx = line.IndexOf(':');
        if (idx < 0) return null;
        var v = line[(idx + 1)..].Trim();
        return v.Length == 0 ? null : v;
    }
}
