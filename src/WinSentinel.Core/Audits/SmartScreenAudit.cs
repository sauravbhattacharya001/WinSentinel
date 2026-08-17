using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows SmartScreen reputation
/// posture in a live <c>--audit</c> run: whether App &amp; File (Explorer/shell)
/// SmartScreen is enabled and set to Block, whether Microsoft Edge SmartScreen and
/// its PUA blocking are on, and whether SmartScreen still evaluates Store / App
/// Installer web content. SmartScreen is the built-in reputation check that catches
/// downloaded-executable droppers and browser-borne phishing/malware, so this is
/// high-value single-machine hardening.
///
/// <para>This is the thin I/O layer for <see cref="SmartScreenAnalyzer"/>: it owns
/// the reading of the HKLM policy and per-user AppHost registry values and delegates
/// every pass/fail decision to the pure, unit-tested analyzer (collector owns I/O,
/// analyzer owns decisions - the same split as <see cref="WindowsScriptHostAudit"/>
/// / <see cref="WindowsScriptHostAnalyzer"/>). It reads only local machine /
/// current-user state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class SmartScreenAudit : AuditModuleBase
{
    public override string Name => "SmartScreen Audit";
    public override string Category => SmartScreenAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows SmartScreen reputation posture - whether App & File (Explorer) " +
        "SmartScreen is enabled and set to Block, whether Microsoft Edge SmartScreen and PUA blocking are on, " +
        "and whether SmartScreen still evaluates Store/App Installer web content - to preserve the built-in " +
        "reputation check against downloaded-executable droppers and browser-borne malware.";

    private const string SystemPolicySubKey = @"SOFTWARE\Policies\Microsoft\Windows\System";
    private const string EdgePolicySubKey = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string AppHostSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in SmartScreenAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local SmartScreen state into the pure <see cref="SmartScreenState"/>. Each value is a
    /// best-effort registry read whose absence maps to null so the analyzer treats it as the Windows
    /// default (SmartScreen on but the block level not policy-pinned) - never a false full-pass. The
    /// policy values come from HKLM; <see cref="SmartScreenState.EnableWebContentEvaluation"/> is the
    /// per-user HKCU AppHost value.
    /// </summary>
    internal static SmartScreenState CollectState()
    {
        return new SmartScreenState
        {
            EnableSmartScreen = ReadDword(RegistryHive.LocalMachine, SystemPolicySubKey, "EnableSmartScreen"),
            ShellSmartScreenLevel = ReadString(RegistryHive.LocalMachine, SystemPolicySubKey, "ShellSmartScreenLevel"),
            EdgeSmartScreenEnabled = ReadDword(RegistryHive.LocalMachine, EdgePolicySubKey, "SmartScreenEnabled"),
            EdgeSmartScreenPuaEnabled = ReadDword(RegistryHive.LocalMachine, EdgePolicySubKey, "SmartScreenPuaEnabled"),
            EnableWebContentEvaluation = ReadDword(RegistryHive.CurrentUser, AppHostSubKey, "EnableWebContentEvaluation"),
        };
    }

    /// <summary>
    /// Best-effort read of a DWORD; null when missing/unreadable. Tolerates REG_SZ "0"/"1" values
    /// (some SmartScreen knobs have historically been written as strings).
    /// </summary>
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

    /// <summary>Best-effort read of a REG_SZ; null/empty maps to null.</summary>
    private static string? ReadString(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            var raw = RegistryHelper.GetValue<object?>(hive, subKey, valueName, null);
            var s = raw?.ToString();
            return string.IsNullOrWhiteSpace(s) ? null : s;
        }
        catch
        {
            return null;
        }
    }
}
