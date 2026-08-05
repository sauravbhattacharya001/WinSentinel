using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Remote Desktop (RDP) hardening posture in a live
/// <c>--audit</c> run: whether inbound RDP is enabled, whether Network Level Authentication is
/// required, whether a strong minimum encryption level and the TLS security layer are enforced,
/// and whether RDP is on the default port 3389.
///
/// <para>This is the thin I/O layer for <see cref="RdpHardeningAnalyzer"/>: it owns the reading
/// of local Terminal Server registry state and delegates every pass/fail decision to the pure,
/// unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="WerExposureAudit"/> / <see cref="WerExposureAnalyzer"/>). It reads only local
/// registry state, so it is single-machine and therefore FREE / OSS - nothing multi-machine,
/// nothing license-gated.</para>
/// </summary>
public class RdpHardeningAudit : AuditModuleBase
{
    public override string Name => "Remote Desktop Hardening Audit";
    public override string Category => RdpHardeningAnalyzer.Category;
    public override string Description =>
        "Checks Remote Desktop (RDP) hardening on a single machine: whether RDP is enabled, whether Network Level " +
        "Authentication is required, the minimum encryption level, the TLS security layer, and whether RDP listens on " +
        "the default port 3389 - the primary controls on one of the most-attacked Windows remote-access surfaces.";

    private const string TerminalServerSubKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcpSubKey = TerminalServerSubKey + @"\WinStations\RDP-Tcp";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in RdpHardeningAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read local Terminal Server / RDP-Tcp registry state into the pure
    /// <see cref="RdpHardeningState"/>. Registry reads are best-effort: an unreadable value
    /// falls back to the safer default (see <see cref="RdpHardeningState"/>) so a missing key
    /// never false-positives the dangerous posture.
    /// </summary>
    internal static RdpHardeningState CollectState()
    {
        // fDenyTSConnections defaults to 1 (RDP off) so a missing value is treated as disabled
        // rather than exposing a false enabled posture.
        bool rdpEnabled = ReadDword(TerminalServerSubKey, "fDenyTSConnections", defaultValue: 1) == 0;

        // UserAuthentication defaults to 1 (NLA required) so an unreadable value is not flagged
        // as the insecure "no NLA" case.
        bool nlaRequired = ReadDword(RdpTcpSubKey, "UserAuthentication", defaultValue: 1) == 1;

        // MinEncryptionLevel defaults to 3 (High) so an unreadable value is treated as strong.
        int minEncryptionLevel = ReadDword(RdpTcpSubKey, "MinEncryptionLevel", defaultValue: 3);

        // SecurityLayer defaults to 2 (TLS) so an unreadable value is treated as secure.
        int securityLayer = ReadDword(RdpTcpSubKey, "SecurityLayer", defaultValue: 2);

        // PortNumber defaults to 3389 (the well-known RDP port).
        int portNumber = ReadDword(RdpTcpSubKey, "PortNumber", defaultValue: RdpHardeningAnalyzer.DefaultRdpPort);

        return new RdpHardeningState
        {
            RdpEnabled = rdpEnabled,
            NlaRequired = nlaRequired,
            MinEncryptionLevel = minEncryptionLevel,
            SecurityLayer = securityLayer,
            PortNumber = portNumber,
        };
    }

    /// <summary>
    /// Best-effort read of a REG_DWORD from HKLM, returning <paramref name="defaultValue"/>
    /// when the key/value is missing or unreadable.
    /// </summary>
    private static int ReadDword(string subKey, string valueName, int defaultValue = 0)
    {
        try
        {
            return RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine, subKey, valueName, defaultValue);
        }
        catch
        {
            return defaultValue;
        }
    }
}
