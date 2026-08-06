using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing Print Spooler / "PrintNightmare" hardening on a single
/// machine. The Windows Print Spooler service (CVE-2021-34527 "PrintNightmare" and a long tail
/// of related RCE/LPE bugs) is one of the most exploited local-privilege-escalation and remote
/// code-execution surfaces on Windows: a running spooler that lets non-administrators install
/// print drivers is a standard path from a normal user to SYSTEM. The checks here evaluate the
/// spooler posture that matters most on a single host:
///
///   * Spooler running          - whether the Print Spooler service is running at all. On a
///                                machine that never prints, a disabled spooler removes the
///                                entire attack surface (Pass). Running is Info - legitimate,
///                                but the hardening checks below then matter.
///   * Restrict driver install  - RestrictDriverInstallationToAdministrators = 1 is the primary
///     to admins                  PrintNightmare mitigation: only administrators may install
///                                printer drivers. 0 or missing lets any user install a driver
///                                (the exploited condition) - Warning.
///   * Point-and-Print no-warn   - NoWarningNoElevationOnInstall = 1 suppresses the elevation
///                                prompt when installing a Point-and-Print driver, silently
///                                letting a malicious print server push a driver - Warning.
///   * Point-and-Print update    - UpdatePromptSettings != 0 similarly suppresses prompts on
///     prompt                     driver *update*, another silent-driver-push vector - Warning.
///
/// <para>The checks read only local service state and Point-and-Print policy registry values
/// (<c>HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers</c> and its
/// <c>PointAndPrint</c> subkey), so this module is single-machine and therefore FREE / OSS:
/// nothing multi-machine, nothing license-gated. Every rule operates on a synthetic
/// <see cref="PrintSpoolerState"/> so it can be unit tested directly, mirroring the established
/// <see cref="RdpHardeningAnalyzer"/> split (collector owns I/O, analyzer owns decisions).</para>
/// </summary>
public static class PrintSpoolerAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Print Spooler";

    /// <summary>
    /// Evaluate the collected Print Spooler state and return one finding per check (a Pass when
    /// the setting is already safe, otherwise Info/Warning). Ordering is stable and
    /// deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeSpoolerRunning(state),
            AnalyzeRestrictDriverInstall(state),
            AnalyzeNoWarningNoElevation(state),
            AnalyzeUpdatePrompt(state),
        };
    }

    /// <summary>
    /// Whether the Print Spooler service is running. A stopped/disabled spooler on a machine
    /// that does not print removes the entire PrintNightmare-class attack surface and is
    /// reported as Pass; a running spooler is Info (legitimate, but the hardening checks below
    /// then apply).
    /// </summary>
    public static Finding AnalyzeSpoolerRunning(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.SpoolerRunning)
        {
            return Finding.Pass(
                "Print Spooler service is not running",
                "The Print Spooler service is stopped, so this machine does not expose the spooler - removing the entire " +
                "PrintNightmare-class (CVE-2021-34527 and related) print-driver attack surface. This is the safest posture " +
                "on a machine that does not need to print.",
                Category);
        }

        return Finding.Info(
            "Print Spooler service is running",
            "The Print Spooler service is running. The spooler is a legitimate feature, but it has been the source of a " +
            "long line of remote-code-execution and local-privilege-escalation bugs (PrintNightmare, CVE-2021-34527 and " +
            "related). If this machine does not need to print, disabling the spooler removes the entire attack surface; " +
            "otherwise ensure driver installation is restricted to administrators (see the checks below).",
            Category,
            remediation: "If printing is not required, disable the Print Spooler service. If it is required, restrict " +
                "printer-driver installation to administrators and lock down Point-and-Print.");
    }

    /// <summary>
    /// RestrictDriverInstallationToAdministrators = 1 is the primary PrintNightmare mitigation:
    /// only administrators may install printer drivers. 0 or missing lets any user install a
    /// driver (the exploited condition) and is a Warning.
    /// </summary>
    public static Finding AnalyzeRestrictDriverInstall(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.RestrictDriverInstallationToAdministrators)
        {
            return Finding.Pass(
                "Printer-driver installation is restricted to administrators",
                "RestrictDriverInstallationToAdministrators = 1, so only administrators may install printer drivers. This " +
                "is the primary PrintNightmare (CVE-2021-34527) mitigation and blocks the standard non-admin-to-SYSTEM " +
                "print-driver escalation path.",
                Category);
        }

        return Finding.Warning(
            "Printer-driver installation is not restricted to administrators",
            "RestrictDriverInstallationToAdministrators is not enabled (0 or missing), so a non-administrator can install " +
            "printer drivers. This is exactly the condition exploited by PrintNightmare (CVE-2021-34527) and related bugs " +
            "to escalate from a normal user to SYSTEM.",
            Category,
            remediation: "Restrict printer-driver installation to administrators (RestrictDriverInstallationToAdministrators = 1).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -Value 1 -Type DWord");
    }

    /// <summary>
    /// Point-and-Print NoWarningNoElevationOnInstall = 1 suppresses the elevation prompt when
    /// installing a driver from a print server, silently allowing a malicious server to push a
    /// driver. Enabled is a Warning; disabled/absent is a Pass.
    /// </summary>
    public static Finding AnalyzeNoWarningNoElevation(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.NoWarningNoElevationOnInstall)
        {
            return Finding.Pass(
                "Point-and-Print does not suppress the install elevation prompt",
                "NoWarningNoElevationOnInstall is not enabled, so users are still warned / prompted for elevation before a " +
                "Point-and-Print driver is installed. This preserves a control against a malicious print server silently " +
                "pushing a driver.",
                Category);
        }

        return Finding.Warning(
            "Point-and-Print suppresses the install elevation prompt",
            "NoWarningNoElevationOnInstall = 1, so Point-and-Print installs printer drivers without warning or an elevation " +
            "prompt. A malicious or compromised print server can silently push a driver of its choice, a known " +
            "PrintNightmare-class code-execution vector.",
            Category,
            remediation: "Do not suppress the Point-and-Print install prompt (NoWarningNoElevationOnInstall = 0).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name NoWarningNoElevationOnInstall -Value 0 -Type DWord");
    }

    /// <summary>
    /// Point-and-Print UpdatePromptSettings != 0 suppresses the prompt when a driver is
    /// *updated* from a print server - another silent-driver-push vector. Non-zero is a
    /// Warning; 0 (prompt) is a Pass.
    /// </summary>
    public static Finding AnalyzeUpdatePrompt(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.UpdatePromptSettings == 0)
        {
            return Finding.Pass(
                "Point-and-Print does not suppress the update elevation prompt",
                "UpdatePromptSettings = 0, so users are still prompted before a Point-and-Print driver is updated. This " +
                "keeps a control against a malicious print server silently pushing an updated driver.",
                Category);
        }

        return Finding.Warning(
            "Point-and-Print suppresses the update elevation prompt",
            $"UpdatePromptSettings = {state.UpdatePromptSettings} (non-zero), so Point-and-Print updates printer drivers " +
            "without warning or an elevation prompt. As with the install prompt, this lets a malicious print server " +
            "silently push a driver update - a PrintNightmare-class code-execution vector.",
            Category,
            remediation: "Do not suppress the Point-and-Print update prompt (UpdatePromptSettings = 0).",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name UpdatePromptSettings -Value 0 -Type DWord");
    }
}

/// <summary>
/// Raw, collector-supplied Print Spooler / PrintNightmare hardening state. Populated by the
/// audit module's I/O layer (querying the Print Spooler service and reading
/// <c>HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint</c>) and handed to
/// <see cref="PrintSpoolerAnalyzer"/> for a pure decision. Defaults are chosen so an unreadable
/// value never false-positives the dangerous posture: the spooler defaults to not-running,
/// driver installation defaults to restricted, and both Point-and-Print prompt-suppression
/// settings default to the safe (prompting) value.
/// </summary>
public sealed record PrintSpoolerState
{
    /// <summary>Whether the Print Spooler service is running. Secure default <c>false</c> (spooler off).</summary>
    public bool SpoolerRunning { get; init; }

    /// <summary>
    /// Whether printer-driver installation is restricted to administrators
    /// (RestrictDriverInstallationToAdministrators = 1). Secure default <c>true</c>.
    /// </summary>
    public bool RestrictDriverInstallationToAdministrators { get; init; } = true;

    /// <summary>
    /// Whether Point-and-Print suppresses the install elevation prompt
    /// (NoWarningNoElevationOnInstall = 1). Secure default <c>false</c> (prompt shown).
    /// </summary>
    public bool NoWarningNoElevationOnInstall { get; init; }

    /// <summary>
    /// Point-and-Print update prompt setting (UpdatePromptSettings). 0 = prompt (secure).
    /// Secure default 0.
    /// </summary>
    public int UpdatePromptSettings { get; init; }
}
