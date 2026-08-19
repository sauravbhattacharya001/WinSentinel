using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for single-machine Windows diagnostics / troubleshooting
/// hardening. These are the local registry / policy controls that decide whether
/// the legacy Microsoft Support Diagnostic Tool (MSDT) attack surface - most
/// famously the Follina remote-code-execution chain (CVE-2022-30190), where a
/// malicious <c>ms-msdt:</c> URL launches MSDT to run attacker script - is left
/// exposed on this box:
///
///   * ScriptedDiagnostics EnableDiagnostics -
///       HKLM\...\Policies\Microsoft\Windows\ScriptedDiagnostics\EnableDiagnostics.
///       0 = the scripted-diagnostics engine (which MSDT drives) is turned off,
///       the recommended Follina mitigation for hosts that don't need it.
///   * ms-msdt protocol handler -
///       whether the <c>ms-msdt:</c> URL protocol is still registered under
///       HKCR. Microsoft's interim Follina workaround was to delete this key so a
///       document can no longer hand a payload to MSDT via a URL.
///   * WindowsErrorReporting / MSDT Troubleshooting policy -
///       HKLM\...\Policies\Microsoft\Windows\WDI (diagnostics) allow flags -
///       whether users can run built-in troubleshooters that invoke MSDT.
///   * CEIP / diagnostic data floor -
///       HKLM\...\DataCollection\AllowTelemetry, kept here as a diagnostics-surface
///       control: the Security (0) / Basic (1) floor limits how much diagnostic
///       data the machine ships and how much of the diagnostics pipeline is active.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// registry / policy state only. Nothing multi-machine, nothing license-gated.
/// All rules operate on a synthetic <see cref="DiagnosticsHardeningState"/> so they
/// can be unit tested directly, mirroring the established
/// <see cref="LsaHardeningAnalyzer"/> / <see cref="ScreenLockAnalyzer"/> pattern
/// (collector owns I/O, the analyzer owns decisions).
/// </summary>
public static class DiagnosticsHardeningAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Diagnostics Hardening";

    /// <summary>
    /// Evaluate the collected diagnostics-hardening state and return one finding per
    /// check (a Pass when the setting is already safe, a Warning when it is not).
    /// Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(DiagnosticsHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeScriptedDiagnostics(state),
            AnalyzeMsdtProtocolHandler(state),
            AnalyzeTroubleshootingPolicy(state),
            AnalyzeDiagnosticDataFloor(state),
        };
    }

    /// <summary>
    /// The scripted-diagnostics engine (which MSDT drives) should be disabled on
    /// hosts that do not need interactive troubleshooters - EnableDiagnostics = 0 is
    /// the recommended Follina (CVE-2022-30190) mitigation.
    /// </summary>
    public static Finding AnalyzeScriptedDiagnostics(DiagnosticsHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.ScriptedDiagnosticsEnabled == 0)
        {
            return Finding.Pass(
                "Scripted diagnostics (MSDT engine) is disabled",
                "ScriptedDiagnostics EnableDiagnostics is 0, so the diagnostics engine that MSDT " +
                "drives is turned off. This removes the Follina (CVE-2022-30190) ms-msdt code-execution surface.",
                Category);
        }

        return Finding.Warning(
            "Scripted diagnostics (MSDT engine) is enabled",
            "ScriptedDiagnostics EnableDiagnostics is not set to 0, so the scripted-diagnostics engine " +
            "that the Microsoft Support Diagnostic Tool (MSDT) drives is available. This is the engine " +
            "abused by the Follina chain (CVE-2022-30190), where a crafted ms-msdt URL launches MSDT to " +
            "run attacker-controlled script. On hosts that do not rely on built-in troubleshooters, disabling it removes that surface.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnostics\\EnableDiagnostics = 0 (DWORD) " +
                         "on machines that do not need interactive troubleshooters.",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnostics' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnostics' -Name EnableDiagnostics -Type DWord -Value 0");
    }

    /// <summary>
    /// The <c>ms-msdt:</c> URL protocol handler should be removed - Microsoft's
    /// interim Follina workaround was to delete the HKCR\ms-msdt key so a document
    /// can no longer hand a payload to MSDT through a URL.
    /// </summary>
    public static Finding AnalyzeMsdtProtocolHandler(DiagnosticsHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.MsdtProtocolHandlerRegistered)
        {
            return Finding.Pass(
                "ms-msdt: URL protocol handler is not registered",
                "The ms-msdt: URL protocol is not registered, so a document or link cannot invoke the " +
                "Microsoft Support Diagnostic Tool via a URL - the interim Follina (CVE-2022-30190) workaround is in place.",
                Category);
        }

        return Finding.Warning(
            "ms-msdt: URL protocol handler is registered",
            "The ms-msdt: URL protocol handler is registered under HKCR, so a crafted ms-msdt: URL " +
            "(the Follina, CVE-2022-30190, vector) can hand a payload to the Microsoft Support Diagnostic " +
            "Tool. Microsoft's interim workaround was to remove this protocol registration on hosts that do not need it.",
            Category,
            remediation: "Back up and delete the HKCR\\ms-msdt registration (reg export HKEY_CLASSES_ROOT\\ms-msdt msdt.reg, " +
                         "then reg delete HKEY_CLASSES_ROOT\\ms-msdt /f) on machines that do not require MSDT URL launching.",
            fixCommand: "reg export HKEY_CLASSES_ROOT\\ms-msdt \"$env:TEMP\\ms-msdt-backup.reg\" /y; reg delete HKEY_CLASSES_ROOT\\ms-msdt /f");
    }

    /// <summary>
    /// The built-in troubleshooting pages that launch MSDT should be restricted -
    /// EnableDiagnostics under the WDI troubleshooting policy = 0 blocks users from
    /// running the interactive troubleshooters that invoke MSDT.
    /// </summary>
    public static Finding AnalyzeTroubleshootingPolicy(DiagnosticsHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.AllowBuiltInTroubleshooting == 0)
        {
            return Finding.Pass(
                "Built-in MSDT troubleshooting is restricted by policy",
                "The Windows troubleshooting policy (WDI) blocks users from running the built-in " +
                "troubleshooters that launch MSDT, narrowing the interactive diagnostics attack surface.",
                Category);
        }

        return Finding.Warning(
            "Built-in MSDT troubleshooting is allowed",
            "The Windows troubleshooting policy does not restrict the built-in troubleshooters (WDI " +
            "EnableDiagnostics is not 0), so users can launch MSDT-backed troubleshooters interactively. " +
            "Combined with the scripted-diagnostics engine this widens the MSDT attack surface.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\\ScenarioExecutionEnabled = 0 " +
                         "(or disable the 'Troubleshooting: Allow users to access online/local troubleshooting content' policy).",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' -Name ScenarioExecutionEnabled -Type DWord -Value 0");
    }

    /// <summary>
    /// The diagnostic-data (telemetry) level should sit at the Security (0) or Basic
    /// (1) floor. Higher levels keep more of the diagnostics pipeline active and ship
    /// more data off the machine.
    /// </summary>
    public static Finding AnalyzeDiagnosticDataFloor(DiagnosticsHardeningState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int? level = state.AllowTelemetry;
        if (level is 0 or 1)
        {
            string tierName = level == 0 ? "Security (0)" : "Basic (1)";
            return Finding.Pass(
                "Diagnostic data is held at the minimum floor",
                $"AllowTelemetry is {tierName}, keeping the diagnostics pipeline and the volume of " +
                "diagnostic data leaving this machine at the recommended minimum.",
                Category);
        }

        string current = level.HasValue ? level.Value.ToString() : "unset (defaults to Full on client SKUs)";
        return Finding.Warning(
            "Diagnostic data level is above the minimum floor",
            $"AllowTelemetry is {current}. Levels above Basic (1) keep more of the diagnostics pipeline " +
            "active and ship enhanced/full diagnostic data off the machine. CIS L1 recommends holding it " +
            "at Security (0) or Basic (1).",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry = 0 (Security) or 1 (Basic).",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name AllowTelemetry -Type DWord -Value 1");
    }
}

/// <summary>
/// Raw, collector-supplied Windows diagnostics / troubleshooting registry state.
/// Populated by <see cref="DiagnosticsHardeningAudit"/>'s I/O layer and handed to
/// <see cref="DiagnosticsHardeningAnalyzer"/> for a pure decision. Null numeric
/// fields mean "value absent / not readable"; the analyzer treats absence as the
/// less-hardened OS default for each control, so a missing key never becomes a
/// false pass.
/// </summary>
public sealed record DiagnosticsHardeningState
{
    /// <summary>
    /// HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics\EnableDiagnostics (DWORD).
    /// 0 = scripted-diagnostics (MSDT) engine disabled. Null = unset (engine available).
    /// </summary>
    public int? ScriptedDiagnosticsEnabled { get; init; }

    /// <summary>True when the ms-msdt: URL protocol handler is registered under HKCR (the Follina vector).</summary>
    public bool MsdtProtocolHandlerRegistered { get; init; }

    /// <summary>
    /// WDI troubleshooting policy (ScenarioExecutionEnabled) for the built-in MSDT troubleshooters.
    /// 0 = restricted. Null = unset (allowed).
    /// </summary>
    public int? AllowBuiltInTroubleshooting { get; init; }

    /// <summary>
    /// HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry (DWORD).
    /// 0 = Security, 1 = Basic, 2 = Enhanced, 3 = Full. Null = unset.
    /// </summary>
    public int? AllowTelemetry { get; init; }
}
