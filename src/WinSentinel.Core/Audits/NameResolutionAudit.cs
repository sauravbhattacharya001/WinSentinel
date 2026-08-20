using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine name-resolution poisoning hardening in a
/// live <c>--audit</c> run: whether the legacy multicast/broadcast name-resolution
/// fallbacks (LLMNR, NetBIOS-over-TCP/IP / NBT-NS, mDNS) and WPAD proxy auto-discovery
/// are disabled. Those fallbacks are the classic Responder attack surface - an
/// on-segment attacker answers a broadcast name query, coerces the machine into
/// authenticating, and captures a crackable/relayable NetNTLMv2 hash (or MITMs the
/// proxy config via WPAD). Almost every environment resolves real names through DNS,
/// so disabling these is cheap, high-value endpoint hardening.
///
/// <para>This is the thin I/O layer for <see cref="NameResolutionAnalyzer"/>: it owns
/// the reading of the DNSClient / NetBT / Dnscache / Internet Settings registry values
/// and delegates every pass/fail decision to the pure, unit-tested analyzer (collector
/// owns I/O, analyzer owns decisions - the same split as <see cref="WindowsScriptHostAudit"/>
/// / <see cref="WindowsScriptHostAnalyzer"/>). It reads only local machine state, so it
/// is single-machine and therefore FREE / OSS - nothing multi-machine, nothing
/// license-gated.</para>
/// </summary>
public class NameResolutionAudit : AuditModuleBase
{
    public override string Name => "Name Resolution Audit";
    public override string Category => NameResolutionAnalyzer.Category;
    public override string Description =>
        "Checks single-machine name-resolution poisoning hardening - whether LLMNR, NetBIOS over TCP/IP (NBT-NS), " +
        "mDNS and WPAD proxy auto-discovery are disabled - to remove the Responder/NetNTLM-capture and proxy-MITM " +
        "surface on untrusted networks.";

    private const string DnsClientPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string NetbtInterfacesKey = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
    private const string DnscacheParamsKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
    private const string WpadPolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in NameResolutionAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local name-resolution state into the pure <see cref="NameResolutionState"/>. Each value is a
    /// best-effort registry read whose absence maps to null so the analyzer treats it as the Windows
    /// default (fallback enabled) - never a false pass.
    /// </summary>
    internal static NameResolutionState CollectState()
    {
        return new NameResolutionState
        {
            EnableMulticast = ReadDword(RegistryHive.LocalMachine, DnsClientPolicyKey, "EnableMulticast"),
            NetbiosOptionsPerInterface = CollectNetbiosOptions(),
            EnableMdns = ReadDword(RegistryHive.LocalMachine, DnscacheParamsKey, "EnableMDNS"),
            DisableWpad = ReadDword(RegistryHive.LocalMachine, WpadPolicyKey, "WpadOverride"),
            WpadAutoDetect = null,
        };
    }

    /// <summary>
    /// Enumerate each NetBT interface subkey and read its NetbiosOptions value. Returns null when the
    /// interfaces key is unreadable (so the analyzer reports "could not determine" instead of a false
    /// pass). Interfaces missing the value are reported as 0 (the DHCP-default, effectively on) so a
    /// silently-on adapter is never mistaken for disabled.
    /// </summary>
    internal static IReadOnlyList<int>? CollectNetbiosOptions()
    {
        try
        {
            var interfaces = RegistryHelper.GetSubKeyNames(RegistryHive.LocalMachine, NetbtInterfacesKey);
            if (interfaces is null || interfaces.Length == 0) return null;

            var values = new List<int>();
            foreach (var iface in interfaces)
            {
                var subKey = NetbtInterfacesKey + "\\" + iface;
                var v = ReadDword(RegistryHive.LocalMachine, subKey, "NetbiosOptions");
                values.Add(v ?? 0);
            }

            return values.Count > 0 ? values : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Best-effort read of a DWORD; null when missing/unreadable. Tolerates REG_SZ ("0"/"1")
    /// as well as REG_DWORD.</summary>
    private static int? ReadDword(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(hive, subKey, valueName, null);
            if (raw is null) return null;
            return raw is int i ? i : (int.TryParse(raw.ToString(), out var parsed) ? parsed : (int?)null);
        }
        catch
        {
            return null;
        }
    }
}
