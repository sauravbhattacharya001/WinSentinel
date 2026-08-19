using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows diagnostics / troubleshooting
/// hardening in a live <c>--audit</c> run: whether the scripted-diagnostics engine
/// that the Microsoft Support Diagnostic Tool (MSDT) drives is disabled, whether the
/// <c>ms-msdt:</c> URL protocol handler (the Follina, CVE-2022-30190, vector) is
/// still registered, whether built-in MSDT troubleshooters are restricted by policy,
/// and whether the diagnostic-data (telemetry) level is held at its minimum floor.
///
/// <para>This is the thin I/O layer for <see cref="DiagnosticsHardeningAnalyzer"/>:
/// it owns the reading of the HKLM policy keys and the HKCR ms-msdt registration and
/// delegates every pass/fail decision to the pure, unit-tested analyzer (collector
/// owns I/O, analyzer owns decisions - the same split as
/// <see cref="ScreenLockAudit"/> / <see cref="ScreenLockAnalyzer"/>). It reads only
/// local machine state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class DiagnosticsHardeningAudit : AuditModuleBase
{
    public override string Name => "Diagnostics Hardening Audit";
    public override string Category => DiagnosticsHardeningAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows diagnostics / troubleshooting hardening - the scripted-diagnostics " +
        "(MSDT) engine, the ms-msdt: URL protocol handler behind Follina (CVE-2022-30190), built-in MSDT " +
        "troubleshooter policy, and the diagnostic-data (telemetry) floor - the local controls that decide " +
        "how much of the MSDT / diagnostics attack surface is exposed on this box.";

    private const string ScriptedDiagnosticsSubKey = @"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics";
    private const string WdiTroubleshootingSubKey = @"SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}";
    private const string DataCollectionSubKey = @"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
    private const string MsdtProtocolSubKey = "ms-msdt";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in DiagnosticsHardeningAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local diagnostics-hardening state into the pure <see cref="DiagnosticsHardeningState"/>.
    /// Each value is a best-effort registry read whose absence maps to null / false; the analyzer then
    /// treats absence as the less-hardened OS default for each control, so a missing value never becomes
    /// a false pass.
    /// </summary>
    internal static DiagnosticsHardeningState CollectState()
    {
        return new DiagnosticsHardeningState
        {
            ScriptedDiagnosticsEnabled = ReadDword(RegistryHive.LocalMachine, ScriptedDiagnosticsSubKey, "EnableDiagnostics"),
            MsdtProtocolHandlerRegistered = MsdtProtocolRegistered(),
            AllowBuiltInTroubleshooting = ReadDword(RegistryHive.LocalMachine, WdiTroubleshootingSubKey, "ScenarioExecutionEnabled"),
            AllowTelemetry = ReadDword(RegistryHive.LocalMachine, DataCollectionSubKey, "AllowTelemetry"),
        };
    }

    /// <summary>
    /// True when the ms-msdt: URL protocol is registered under HKCR. A registered URL-protocol handler
    /// carries a REG_SZ "URL Protocol" value on its root key; we treat the presence of that value (or any
    /// value under the key) as "registered". Absence / unreadable maps to not registered (the hardened state).
    /// </summary>
    private static bool MsdtProtocolRegistered()
    {
        try
        {
            // The canonical marker of a URL-protocol handler is the "URL Protocol" value on the class root.
            var marker = RegistryHelper.GetValue<object?>(RegistryHive.ClassesRoot, MsdtProtocolSubKey, "URL Protocol", null);
            if (marker is not null) return true;

            // Fall back to key existence: any value present under HKCR\ms-msdt means the key is registered.
            var names = RegistryHelper.GetValueNames(RegistryHive.ClassesRoot, MsdtProtocolSubKey);
            return names.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Best-effort read of a REG_DWORD as an int; null when missing/unreadable.</summary>
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
