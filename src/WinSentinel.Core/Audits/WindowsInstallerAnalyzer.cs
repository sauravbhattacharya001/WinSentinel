using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for Windows Installer (MSI) hardening on a single machine.
/// The Windows Installer service (<c>msiexec.exe</c>) has a handful of registry
/// policies that, when misconfigured, turn routine software installation into a
/// local privilege-escalation and malware-delivery surface. All state read here is
/// local registry policy, so this is single-machine and therefore FREE / OSS -
/// nothing multi-machine, nothing license-gated.
///
/// The checks:
///   * <b>AlwaysInstallElevated</b> - the classic MSI privilege-escalation flaw.
///     When BOTH HKLM and HKCU <c>...\Installer\AlwaysInstallElevated</c> are 1,
///     ANY user can install an arbitrary <c>.msi</c> with NT AUTHORITY\SYSTEM
///     privileges - a trivial local admin escalation that offensive tooling
///     (Metasploit, PowerUp) checks for first. It is exploitable ONLY when both
///     hives are 1; either one being 0/absent closes it. This is the highest-value
///     finding in the module and maps to CIS "Always install with elevated
///     privileges = Disabled".
///   * <b>DisableMSI</b> - HKLM\...\Installer\DisableMSI. 0/absent = all MSI
///     installs allowed (default). 1 = only managed (GPO-assigned) installs. 2 =
///     installs fully disabled. Non-zero reduces the install surface on locked-down
///     endpoints; this is informational, not a defect.
///   * <b>EnableUserControl</b> - HKLM\...\Installer\EnableUserControl. 1 lets
///     unprivileged users change normally-restricted install properties (e.g.
///     redirect paths), which combined with a crafted package can widen what a
///     low-priv user influences during a SYSTEM-context install. 0/absent = safe.
///
/// Rules operate on a synthetic <see cref="WindowsInstallerState"/> so they can be
/// unit tested directly, mirroring the established
/// <see cref="WindowsScriptHostAnalyzer"/> / <see cref="LsaHardeningAnalyzer"/>
/// pattern (collector owns I/O, analyzer owns decisions).
/// </summary>
public static class WindowsInstallerAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Windows Installer";

    /// <summary>
    /// Evaluate the collected Windows Installer state and return one finding per
    /// check. Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(WindowsInstallerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeAlwaysInstallElevated(state),
            AnalyzeDisableMsi(state),
            AnalyzeEnableUserControl(state),
        };
    }

    /// <summary>
    /// AlwaysInstallElevated is a local privilege-escalation flaw ONLY when BOTH
    /// the machine (HKLM) and per-user (HKCU) values are 1. Either being 0/absent
    /// closes the hole.
    /// </summary>
    public static Finding AnalyzeAlwaysInstallElevated(WindowsInstallerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.MachineAlwaysInstallElevated == 1 && state.UserAlwaysInstallElevated == 1)
        {
            return Finding.Critical(
                "AlwaysInstallElevated is enabled (local privilege escalation)",
                "Both the machine (HKLM) and per-user (HKCU) AlwaysInstallElevated policy values " +
                "are 1, so any user can install an arbitrary .msi package with SYSTEM privileges. " +
                "This is a well-known local privilege-escalation path that offensive tooling checks " +
                "for first: a low-privileged user can craft a malicious MSI and gain full local admin.",
                Category,
                remediation: "Set both HKLM and HKCU \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\" +
                             "AlwaysInstallElevated to 0 (DWORD), or remove them, so MSI packages install " +
                             "in the invoking user's context, not as SYSTEM.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -Type DWord -Value 0; " +
                            "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -Type DWord -Value 0");
        }

        // If only one hive is 1, the escalation is not exploitable but the intent
        // is suspicious and worth surfacing as Info so an admin can clean it up.
        if (state.MachineAlwaysInstallElevated == 1 || state.UserAlwaysInstallElevated == 1)
        {
            return Finding.Info(
                "AlwaysInstallElevated is set in one hive only",
                "One of the machine (HKLM) or per-user (HKCU) AlwaysInstallElevated policy values " +
                "is 1 while the other is not. The privilege-escalation path requires BOTH to be 1, " +
                "so it is not currently exploitable, but a leftover half-configured policy is a " +
                "latent risk: if the second hive is ever set to 1 the escalation opens.",
                Category,
                remediation: "Set the remaining AlwaysInstallElevated value to 0 (DWORD) or remove it so " +
                             "the policy is unambiguously disabled in both HKLM and HKCU.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -Type DWord -Value 0; " +
                            "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -Type DWord -Value 0");
        }

        return Finding.Pass(
            "AlwaysInstallElevated is disabled",
            "The AlwaysInstallElevated policy is not enabled in both hives, so MSI packages install " +
            "in the invoking user's context rather than as SYSTEM. The classic MSI privilege-" +
            "escalation path is closed.",
            Category);
    }

    /// <summary>DisableMSI restricts which MSI installs are allowed. Informational.</summary>
    public static Finding AnalyzeDisableMsi(WindowsInstallerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        switch (state.DisableMsi)
        {
            case 2:
                return Finding.Pass(
                    "Windows Installer is disabled",
                    "The DisableMSI policy value is 2, so Windows Installer will not process any MSI " +
                    "package install. On a locked-down endpoint that never installs MSI software this " +
                    "removes the MSI install surface entirely.",
                    Category);
            case 1:
                return Finding.Pass(
                    "Windows Installer allows only managed installs",
                    "The DisableMSI policy value is 1, so Windows Installer only processes managed " +
                    "(GPO-assigned/published) installs and blocks ad-hoc user-initiated MSI installs. " +
                    "This limits the MSI install surface.",
                    Category);
            default:
                return Finding.Info(
                    "Windows Installer allows all MSI installs",
                    "The DisableMSI policy value is 0 or absent (the default), so Windows Installer will " +
                    "process any MSI package. This is expected on general-purpose machines; on locked-down " +
                    "endpoints that never install MSI software, restricting installs reduces the surface.",
                    Category,
                    remediation: "On endpoints that should not run ad-hoc installs, set HKLM\\SOFTWARE\\Policies\\" +
                                 "Microsoft\\Windows\\Installer\\DisableMSI = 1 (managed only) or 2 (disabled).",
                    fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Force | Out-Null; " +
                                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name DisableMSI -Type DWord -Value 1");
        }
    }

    /// <summary>
    /// EnableUserControl=1 lets unprivileged users override normally-restricted
    /// install properties during a SYSTEM-context install, widening influence.
    /// </summary>
    public static Finding AnalyzeEnableUserControl(WindowsInstallerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.EnableUserControl == 1)
        {
            return Finding.Warning(
                "Windows Installer lets users override install properties",
                "The EnableUserControl policy value is 1, so unprivileged users can change normally-" +
                "restricted Windows Installer properties (such as redirecting install paths) during a " +
                "package install. Combined with a crafted package this widens what a low-privileged " +
                "user can influence during an elevated install.",
                Category,
                remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\EnableUserControl = 0 " +
                             "(DWORD), or remove it, so users cannot override restricted install properties.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name EnableUserControl -Type DWord -Value 0");
        }

        return Finding.Pass(
            "Windows Installer does not let users override install properties",
            "The EnableUserControl policy value is 0 or absent, so unprivileged users cannot override " +
            "restricted Windows Installer properties during a package install.",
            Category);
    }
}

/// <summary>
/// Raw, collector-supplied Windows Installer policy state. Populated by the audit
/// module's I/O layer and handed to <see cref="WindowsInstallerAnalyzer"/> for a
/// pure decision. Null fields mean "value absent / not readable"; the analyzer
/// treats absence as the Windows default (installs allowed, no elevation, no user
/// control) so a missing key is never silently reported as a defect.
/// </summary>
public sealed record WindowsInstallerState
{
    /// <summary>HKLM Policies\...\Installer\AlwaysInstallElevated (DWORD). 1 with the HKCU value also 1
    /// enables SYSTEM-context MSI installs for any user (privilege escalation); 0/absent = safe.</summary>
    public int? MachineAlwaysInstallElevated { get; init; }

    /// <summary>HKCU Policies\...\Installer\AlwaysInstallElevated (DWORD). Must be 1 together with the
    /// HKLM value for the AlwaysInstallElevated privilege-escalation path to be exploitable.</summary>
    public int? UserAlwaysInstallElevated { get; init; }

    /// <summary>HKLM Policies\...\Installer\DisableMSI (DWORD). 0/absent = all installs; 1 = managed only;
    /// 2 = installs disabled.</summary>
    public int? DisableMsi { get; init; }

    /// <summary>HKLM Policies\...\Installer\EnableUserControl (DWORD). 1 = users may override restricted
    /// install properties; 0/absent = safe.</summary>
    public int? EnableUserControl { get; init; }
}
