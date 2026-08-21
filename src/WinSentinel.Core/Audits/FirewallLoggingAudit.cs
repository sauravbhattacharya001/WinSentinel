using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces Windows Firewall LOGGING configuration in a live
/// <c>--audit</c> run, per profile (Domain / Private / Public): whether dropped
/// packets are logged, whether successful connections are logged, whether the log
/// file is large enough not to wrap away evidence, and whether a log file path is
/// configured.
///
/// <para>This is the thin I/O layer for <see cref="FirewallLoggingAnalyzer"/>: it
/// owns reading the HKLM FirewallPolicy per-profile <c>Logging</c> registry values
/// and delegates every pass/fail decision to the pure, unit-tested analyzer
/// (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="LsaHardeningAudit"/> / <see cref="LsaHardeningAnalyzer"/>). It reads
/// only local machine state, so it is single-machine and therefore FREE / OSS -
/// nothing multi-machine, nothing license-gated. It complements the existing
/// <see cref="FirewallAudit"/> (profile on/off) and <see cref="FirewallRuleAudit"/>
/// (rule hygiene) by covering the audit-trail dimension the firewall itself needs.</para>
/// </summary>
public class FirewallLoggingAudit : AuditModuleBase
{
    public override string Name => "Firewall Logging Audit";
    public override string Category => FirewallLoggingAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows Firewall logging per profile (Domain/Private/Public) - dropped-packet " +
        "logging, successful-connection logging, log file size, and log file path - the CIS L1 controls that " +
        "decide whether the firewall leaves any evidence of scans, blocked C2, or unexpected egress.";

    private const string FirewallPolicyRoot =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in FirewallLoggingAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local firewall logging state for all three profiles into the pure
    /// <see cref="FirewallLoggingState"/>. Each value is a best-effort registry read
    /// whose absence maps to null; the analyzer then treats absence as the
    /// unconfigured default (logging off / size 0 / no path).
    /// </summary>
    internal static FirewallLoggingState CollectState()
    {
        return new FirewallLoggingState
        {
            Domain = CollectProfile("DomainProfile"),
            Private = CollectProfile("StandardProfile"),
            Public = CollectProfile("PublicProfile"),
        };
    }

    private static FirewallProfileLogging CollectProfile(string profileKey)
    {
        string logging = $@"{FirewallPolicyRoot}\{profileKey}\Logging";
        return new FirewallProfileLogging
        {
            LogDroppedPackets = ReadDword(logging, "LogDroppedPackets"),
            LogSuccessfulConnections = ReadDword(logging, "LogSuccessfulConnections"),
            LogFileSizeKb = ReadDword(logging, "LogFileSize"),
            LogFilePath = ReadString(logging, "LogFilePath"),
        };
    }

    /// <summary>Best-effort read of a REG_DWORD as an int; null when missing/unreadable.</summary>
    private static int? ReadDword(string subKey, string valueName)
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(RegistryHive.LocalMachine, subKey, valueName, null);
            if (raw is null) return null;
            return raw is int i ? i : (int.TryParse(raw.ToString(), out var parsed) ? parsed : (int?)null);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Best-effort read of a REG_SZ/REG_EXPAND_SZ, returning null when missing/unreadable.</summary>
    private static string? ReadString(string subKey, string valueName)
    {
        try
        {
            return RegistryHelper.GetValue<string?>(RegistryHive.LocalMachine, subKey, valueName, null);
        }
        catch
        {
            return null;
        }
    }
}
