using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for Print Spooler / Point-and-Print hardening on a single
/// machine. This is the local-registry surface behind the PrintNightmare family
/// of bugs (CVE-2021-34527 and friends), where an attacker with a foothold abuses
/// the Print Spooler service and permissive Point-and-Print driver installation to
/// run code as SYSTEM.
///
/// The checks:
///   * <b>Spooler running while no printers are shared</b> - the spooler service is
///     a recurring attack surface. If the machine neither prints nor shares
///     printers, the service can simply be disabled. Running + sharing is normal;
///     running + not-needed is worth flagging (Info).
///   * <b>RestrictDriverInstallationToAdministrators</b> - the definitive
///     PrintNightmare mitigation. When 1, only admins can install printer drivers,
///     which closes the remote code-execution path. Absent/0 = exposed.
///   * <b>Point-and-Print NoWarningNoElevationOnInstall</b> - when 1, Windows
///     installs printer drivers with NO UAC prompt and NO warning. This is the
///     exact setting PrintNightmare exploits rely on. Must be 0/absent.
///   * <b>Point-and-Print UpdatePromptSettings</b> - when non-zero, suppresses the
///     elevation prompt on driver <i>update</i>. Same class of risk. Must be 0/absent.
///   * <b>RegisterSpoolerRemoteRpcEndPoint</b> - when 2, the spooler stops
///     accepting remote RPC print connections, shrinking the remote surface. On a
///     workstation that does not act as a print server this is desirable.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// registry / service state only. Nothing multi-machine, nothing license-gated.
/// All rules operate on a synthetic <see cref="PrintSpoolerState"/> so they can be
/// unit tested directly, mirroring the established
/// <see cref="LsaHardeningAnalyzer"/> analyzer pattern (collector owns I/O,
/// analyzer owns decisions).
/// </summary>
public static class PrintSpoolerAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Print Spooler";

    /// <summary>
    /// Evaluate the collected Print Spooler / Point-and-Print state and return one
    /// finding per check (a Pass when the setting is already safe, otherwise
    /// Info/Warning/Critical). Ordering is stable and deterministic for diffable
    /// reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeSpoolerService(state),
            AnalyzeRestrictDriverInstallation(state),
            AnalyzeNoWarningNoElevation(state),
            AnalyzeUpdatePromptSettings(state),
            AnalyzeRemoteRpcEndpoint(state),
        };
    }

    /// <summary>Spooler running while nothing is shared/printed is needless attack surface.</summary>
    public static Finding AnalyzeSpoolerService(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.SpoolerRunning)
        {
            return Finding.Pass(
                "Print Spooler service is not running",
                "The Print Spooler service is stopped/disabled, removing the entire " +
                "PrintNightmare-class attack surface on this machine.",
                Category);
        }

        if (state.SharesPrinters)
        {
            return Finding.Pass(
                "Print Spooler is running and this machine shares printers",
                "The spooler is running and the machine shares one or more printers, so " +
                "the service is in legitimate use. Ensure the driver-install hardening " +
                "below is in place.",
                Category);
        }

        return Finding.Info(
            "Print Spooler is running but no printers are shared",
            "The Print Spooler service is running even though this machine does not " +
            "share any printers. The spooler is a recurring attack surface " +
            "(PrintNightmare); if the device never prints it can be disabled entirely.",
            Category,
            remediation: "If printing is not needed, disable the service: " +
                         "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled.",
            fixCommand: "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled");
    }

    /// <summary>The definitive PrintNightmare mitigation: restrict driver install to admins.</summary>
    public static Finding AnalyzeRestrictDriverInstallation(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // Absent (null) is treated as NOT restricted: the mitigation only applies
        // when the value is explicitly present and set to 1.
        if (state.RestrictDriverInstallationToAdministrators == 1)
        {
            return Finding.Pass(
                "Printer driver installation is restricted to administrators",
                "RestrictDriverInstallationToAdministrators is 1, so only administrators " +
                "can install printer drivers. This is the primary PrintNightmare " +
                "(CVE-2021-34527) mitigation.",
                Category);
        }

        return Finding.Critical(
            "Printer driver installation is NOT restricted to administrators",
            "RestrictDriverInstallationToAdministrators is not enabled. Non-admins can " +
            "trigger printer-driver installation, which is the code-execution path " +
            "PrintNightmare-class exploits use to run code as SYSTEM.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\" +
                         "RestrictDriverInstallationToAdministrators = 1 (DWORD).",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -Type DWord -Value 1");
    }

    /// <summary>Point-and-Print NoWarningNoElevationOnInstall must be 0 / absent.</summary>
    public static Finding AnalyzeNoWarningNoElevation(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.NoWarningNoElevationOnInstall == 1)
        {
            return Finding.Critical(
                "Point-and-Print installs drivers with no warning or elevation",
                "NoWarningNoElevationOnInstall is 1: Windows installs printer drivers " +
                "silently, with no UAC prompt and no warning. This is exactly the " +
                "configuration PrintNightmare exploitation depends on.",
                Category,
                remediation: "Set the PointAndPrint\\NoWarningNoElevationOnInstall value to 0 (or remove it).",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name NoWarningNoElevationOnInstall -Type DWord -Value 0");
        }

        return Finding.Pass(
            "Point-and-Print prompts/elevates on driver install",
            "NoWarningNoElevationOnInstall is 0 or absent, so driver installation is not " +
            "silently elevated.",
            Category);
    }

    /// <summary>Point-and-Print UpdatePromptSettings must be 0 / absent.</summary>
    public static Finding AnalyzeUpdatePromptSettings(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // 0 = prompt on update (safe). 1/2 = suppress warning and/or elevation.
        if ((state.UpdatePromptSettings ?? 0) != 0)
        {
            return Finding.Warning(
                "Point-and-Print suppresses the prompt on driver update",
                $"UpdatePromptSettings is {state.UpdatePromptSettings}, which suppresses the " +
                "warning and/or elevation prompt when an existing printer driver is " +
                "updated - the same class of risk as silent install.",
                Category,
                remediation: "Set the PointAndPrint\\UpdatePromptSettings value to 0 (or remove it).",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' -Name UpdatePromptSettings -Type DWord -Value 0");
        }

        return Finding.Pass(
            "Point-and-Print prompts/elevates on driver update",
            "UpdatePromptSettings is 0 or absent, so driver updates are not silently " +
            "elevated.",
            Category);
    }

    /// <summary>Disabling remote RPC print connections shrinks the remote spooler surface.</summary>
    public static Finding AnalyzeRemoteRpcEndpoint(PrintSpoolerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // 1 = RPC over named pipes and TCP (default, remotely reachable).
        // 2 = RPC over TCP only combined with RestrictDriverInstallation, or per
        // MS guidance the value that limits remote connections. We flag anything
        // other than 2 as Info on a non-print-server, since it is a hardening
        // opportunity rather than a live vulnerability by itself.
        if (state.RegisterSpoolerRemoteRpcEndPoint == 2)
        {
            return Finding.Pass(
                "Remote spooler RPC endpoint is restricted",
                "RegisterSpoolerRemoteRpcEndPoint is 2, so the spooler does not accept " +
                "the default remote RPC print connections, shrinking the remote attack " +
                "surface.",
                Category);
        }

        if (state.SharesPrinters)
        {
            return Finding.Pass(
                "Remote spooler RPC endpoint is enabled (machine is a print server)",
                "The spooler accepts remote RPC print connections, which is expected " +
                "because this machine shares printers. Ensure driver-install hardening " +
                "is applied.",
                Category);
        }

        return Finding.Info(
            "Remote spooler RPC endpoint is enabled but no printers are shared",
            "RegisterSpoolerRemoteRpcEndPoint is not set to 2, so the spooler still " +
            "accepts remote RPC print connections even though this machine does not " +
            "share printers - unnecessary remote attack surface.",
            Category,
            remediation: "On a non-print-server, set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\" +
                         "RegisterSpoolerRemoteRpcEndPoint = 2 (DWORD) to block inbound remote print RPC.",
            fixCommand: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print' -Name RegisterSpoolerRemoteRpcEndPoint -Type DWord -Value 2");
    }
}

/// <summary>
/// Raw, collector-supplied Print Spooler / Point-and-Print state. Populated by the
/// audit module's I/O layer and handed to <see cref="PrintSpoolerAnalyzer"/> for a
/// pure decision. Null numeric fields mean "value absent / not readable"; the
/// analyzer treats absence conservatively (a mitigation that is not explicitly
/// present is treated as not applied).
/// </summary>
public sealed record PrintSpoolerState
{
    /// <summary>Whether the Print Spooler (Spooler) service is currently running.</summary>
    public bool SpoolerRunning { get; init; }

    /// <summary>Whether this machine shares one or more printers (acts as a print server).</summary>
    public bool SharesPrinters { get; init; }

    /// <summary>PointAndPrint\RestrictDriverInstallationToAdministrators (DWORD). 1 = admins only.</summary>
    public int? RestrictDriverInstallationToAdministrators { get; init; }

    /// <summary>PointAndPrint\NoWarningNoElevationOnInstall (DWORD). 1 = silent, elevated install.</summary>
    public int? NoWarningNoElevationOnInstall { get; init; }

    /// <summary>PointAndPrint\UpdatePromptSettings (DWORD). non-zero = suppresses update prompt.</summary>
    public int? UpdatePromptSettings { get; init; }

    /// <summary>Control\Print\RegisterSpoolerRemoteRpcEndPoint (DWORD). 2 = remote RPC restricted.</summary>
    public int? RegisterSpoolerRemoteRpcEndPoint { get; init; }
}
