using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for single-machine name-resolution poisoning hardening.
/// LLMNR, NetBIOS-over-TCP/IP (NBT-NS), mDNS and WPAD are legacy multicast/broadcast
/// name-resolution fallbacks that Windows uses when DNS fails. On any untrusted LAN
/// they are the classic Responder attack surface: an attacker on the same segment
/// answers a broadcast "who is FILESERVR?" query, the victim then authenticates to
/// the attacker and leaks a NetNTLMv2 hash (crackable offline or relayable to SMB /
/// LDAP). Disabling these fallbacks is a cheap, high-value endpoint hardening because
/// almost every environment resolves real names through DNS anyway.
///
/// The checks (all local registry / policy state):
///   * <b>LLMNR</b> - HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\
///     EnableMulticast. 0 = LLMNR disabled (hardened); absent/1 = enabled (default).
///   * <b>NetBIOS-over-TCP/IP (NBT-NS)</b> - the per-interface NetbiosOptions value
///     under ...\Services\NetBT\Parameters\Interfaces\*. 2 = NetBIOS disabled on that
///     interface (hardened); 0 = use DHCP default (effectively on); 1 = explicitly on.
///     Reported as the weakest interface state so one exposed adapter is not hidden.
///   * <b>mDNS</b> - ...\Services\Dnscache\Parameters\EnableMDNS. 0 = mDNS off
///     (hardened); absent/1 = on (default). Another multicast responder surface.
///   * <b>WPAD auto-detect</b> - HKLM WinHttp\...\Connections + the DisableWpad policy
///     ...\Internet Settings\Wpad\WpadOverride and the AutoDetect flag. WPAD lets a
///     LAN attacker answer "wpad" and MITM the machine's proxy config. WpadOverride=1
///     / DisableWpad=1 = disabled (hardened).
///
/// Everything here is single-machine (reads only local host state) and therefore
/// FREE / OSS - nothing multi-machine, nothing license-gated. All rules operate on a
/// synthetic <see cref="NameResolutionState"/> so they can be unit tested directly,
/// mirroring the established <see cref="WindowsScriptHostAnalyzer"/> pattern
/// (collector owns I/O, analyzer owns decisions).
/// </summary>
public static class NameResolutionAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Name Resolution";

    /// <summary>
    /// Evaluate the collected name-resolution state and return one finding per check
    /// (a Pass when the fallback is already disabled, otherwise Info/Warning).
    /// Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(NameResolutionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeLlmnr(state),
            AnalyzeNetbios(state),
            AnalyzeMdns(state),
            AnalyzeWpad(state),
        };
    }

    /// <summary>LLMNR EnableMulticast=0 disables the LLMNR responder surface.</summary>
    public static Finding AnalyzeLlmnr(NameResolutionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // Absent means the policy is not set: LLMNR is ENABLED (the Windows default).
        // Only an explicit 0 disables it.
        if (state.EnableMulticast == 0)
        {
            return Finding.Pass(
                "LLMNR is disabled",
                "The DNSClient EnableMulticast policy is 0, so Link-Local Multicast Name Resolution " +
                "is turned off. The machine will not answer or send LLMNR broadcasts, removing a " +
                "classic Responder/NetNTLM-capture surface on untrusted networks.",
                Category);
        }

        return Finding.Warning(
            "LLMNR is enabled (NetNTLM capture surface)",
            "Link-Local Multicast Name Resolution (LLMNR) is enabled (the default). On any shared or " +
            "untrusted network an attacker can answer an LLMNR broadcast, coerce the machine into " +
            "authenticating to them, and capture a crackable/relayable NetNTLMv2 hash. Almost every " +
            "environment resolves names through DNS, so LLMNR is safe to disable.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0 " +
                         "(DWORD) to disable LLMNR (Group Policy: Turn off multicast name resolution = Enabled).",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Type DWord -Value 0");
    }

    /// <summary>
    /// NetBIOS-over-TCP/IP name service (NBT-NS) is the other broadcast responder
    /// surface. Reported as the weakest per-interface state: 2 = disabled on every
    /// interface (hardened); anything else means at least one adapter still resolves
    /// names over NBT-NS.
    /// </summary>
    public static Finding AnalyzeNetbios(NameResolutionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // No interfaces enumerated (null/empty) = unknown; treat as default-on Info,
        // never a false pass.
        if (state.NetbiosOptionsPerInterface is { Count: > 0 })
        {
            // 2 = disabled. Any interface not explicitly 2 is still exposed.
            var allDisabled = state.NetbiosOptionsPerInterface.All(v => v == 2);
            if (allDisabled)
            {
                return Finding.Pass(
                    "NetBIOS over TCP/IP is disabled on all interfaces",
                    "Every network interface has NetbiosOptions = 2, so NetBIOS-over-TCP/IP name " +
                    "service (NBT-NS) is disabled. The machine will not answer NBT-NS broadcasts, " +
                    "removing that Responder/NetNTLM-capture surface.",
                    Category);
            }

            var exposed = state.NetbiosOptionsPerInterface.Count(v => v != 2);
            return Finding.Warning(
                "NetBIOS over TCP/IP is enabled on one or more interfaces",
                $"{exposed} network interface(s) do not have NetbiosOptions = 2, so NBT-NS name " +
                "resolution is active. Like LLMNR, an on-segment attacker can answer NBT-NS " +
                "broadcasts and capture a crackable/relayable NetNTLMv2 hash. Disable NetBIOS over " +
                "TCP/IP on every interface unless a legacy dependency requires it.",
                Category,
                remediation: "Set NetbiosOptions = 2 (DWORD) under HKLM\\SYSTEM\\CurrentControlSet\\Services\\" +
                             "NetBT\\Parameters\\Interfaces\\Tcpip_* for each adapter (or set it in the NIC's " +
                             "IPv4 > WINS > 'Disable NetBIOS over TCP/IP').",
                fixCommand: "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | " +
                            "ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Type DWord -Value 2 }");
        }

        return Finding.Info(
            "NetBIOS over TCP/IP state could not be determined",
            "No per-interface NetbiosOptions values were readable, so NBT-NS name resolution may be " +
            "active (the DHCP default). NBT-NS is a broadcast responder surface equivalent to LLMNR; " +
            "confirm it is disabled (NetbiosOptions = 2) on every interface.",
            Category,
            remediation: "Set NetbiosOptions = 2 (DWORD) under HKLM\\SYSTEM\\CurrentControlSet\\Services\\" +
                         "NetBT\\Parameters\\Interfaces\\Tcpip_* for each adapter.",
            fixCommand: "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | " +
                        "ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Type DWord -Value 2 }");
    }

    /// <summary>mDNS EnableMDNS=0 disables the multicast DNS responder surface.</summary>
    public static Finding AnalyzeMdns(NameResolutionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.EnableMdns == 0)
        {
            return Finding.Pass(
                "mDNS is disabled",
                "The Dnscache EnableMDNS value is 0, so multicast DNS is turned off. The machine will " +
                "not answer or send mDNS queries, removing another multicast name-resolution surface.",
                Category);
        }

        return Finding.Info(
            "mDNS is enabled",
            "Multicast DNS (mDNS) is enabled (the default). Like LLMNR/NBT-NS it is a multicast " +
            "name-resolution fallback that an on-segment attacker can spoof. If local .local " +
            "service discovery is not required, disabling mDNS shrinks the responder surface.",
            Category,
            remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\EnableMDNS = 0 " +
                         "(DWORD) to disable multicast DNS.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name EnableMDNS -Type DWord -Value 0");
    }

    /// <summary>
    /// WPAD (Web Proxy Auto-Discovery) lets a LAN attacker answer "wpad" and hand the
    /// machine a malicious proxy config, MITMing its traffic. Disabled when the policy
    /// DisableWpad=1 or the per-connection AutoDetect flag is off.
    /// </summary>
    public static Finding AnalyzeWpad(NameResolutionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.DisableWpad == 1 || state.WpadAutoDetect == 0)
        {
            return Finding.Pass(
                "WPAD auto-detection is disabled",
                "Web Proxy Auto-Discovery (WPAD) auto-detection is turned off (DisableWpad=1 or the " +
                "connection AutoDetect flag is cleared), so the machine will not ask the network for a " +
                "'wpad' proxy config. This removes a LAN proxy-MITM surface.",
                Category);
        }

        return Finding.Warning(
            "WPAD auto-detection is enabled (proxy MITM surface)",
            "Web Proxy Auto-Discovery (WPAD) auto-detection is enabled. On an untrusted network an " +
            "attacker can answer the 'wpad' name-resolution request (via DNS, LLMNR or NBT-NS) and " +
            "supply a malicious proxy configuration, silently man-in-the-middling the machine's web " +
            "traffic. Disable WPAD auto-detect unless a managed proxy explicitly requires it.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad\\" +
                         "WpadOverride = 1 (DWORD) and clear the 'Automatically detect settings' proxy option.",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad' -Name WpadOverride -Type DWord -Value 1");
    }
}

/// <summary>
/// Raw, collector-supplied name-resolution state. Populated by the audit module's I/O
/// layer and handed to <see cref="NameResolutionAnalyzer"/> for a pure decision. Null
/// fields mean "value absent / not readable"; the analyzer treats absence as the
/// Windows default (fallback enabled) so a missing key is never silently reported as
/// hardened.
/// </summary>
public sealed record NameResolutionState
{
    /// <summary>DNSClient policy EnableMulticast (DWORD). 0 = LLMNR disabled; absent/1 = enabled (default).</summary>
    public int? EnableMulticast { get; init; }

    /// <summary>Per-interface NetBT NetbiosOptions values. 2 = NBT-NS disabled on that interface;
    /// 0 = DHCP default (on); 1 = explicitly on. Null/empty = no interfaces readable.</summary>
    public IReadOnlyList<int>? NetbiosOptionsPerInterface { get; init; }

    /// <summary>Dnscache EnableMDNS (DWORD). 0 = mDNS off; absent/1 = on (default).</summary>
    public int? EnableMdns { get; init; }

    /// <summary>Internet Settings Wpad\WpadOverride / DisableWpad policy (DWORD). 1 = WPAD auto-detect disabled.</summary>
    public int? DisableWpad { get; init; }

    /// <summary>Per-connection WPAD AutoDetect flag. 0 = auto-detect off (hardened); 1/absent = on.</summary>
    public int? WpadAutoDetect { get; init; }
}
