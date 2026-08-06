using System.ServiceProcess;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Print Spooler / "PrintNightmare" hardening posture
/// in a live <c>--audit</c> run: whether the Print Spooler service is running, whether
/// printer-driver installation is restricted to administrators (the primary CVE-2021-34527
/// mitigation), and whether Point-and-Print suppresses the install / update elevation prompts.
///
/// <para>This is the thin I/O layer for <see cref="PrintSpoolerAnalyzer"/>: it owns querying the
/// local Print Spooler service and reading Point-and-Print policy registry state, and delegates
/// every pass/fail decision to the pure, unit-tested analyzer (collector owns I/O, analyzer owns
/// decisions - the same split as <see cref="RdpHardeningAudit"/> / <see cref="RdpHardeningAnalyzer"/>).
/// It reads only local service + registry state, so it is single-machine and therefore FREE /
/// OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class PrintSpoolerAudit : AuditModuleBase
{
    public override string Name => "Print Spooler Hardening Audit";
    public override string Category => PrintSpoolerAnalyzer.Category;
    public override string Description =>
        "Checks Print Spooler / PrintNightmare hardening on a single machine: whether the spooler is running, whether " +
        "printer-driver installation is restricted to administrators (CVE-2021-34527), and whether Point-and-Print " +
        "suppresses the install/update elevation prompts - the controls on one of the most-exploited Windows " +
        "privilege-escalation surfaces.";

    private const string PointAndPrintSubKey =
        @"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
    private const string SpoolerServiceName = "Spooler";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in PrintSpoolerAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read local Print Spooler service + Point-and-Print policy state into the pure
    /// <see cref="PrintSpoolerState"/>. Reads are best-effort: an unreadable value falls back to
    /// the safer default (see <see cref="PrintSpoolerState"/>) so a missing key never
    /// false-positives the dangerous posture.
    /// </summary>
    internal static PrintSpoolerState CollectState()
    {
        bool spoolerRunning = IsServiceRunning(SpoolerServiceName);

        // RestrictDriverInstallationToAdministrators defaults to 1 (restricted) so an unreadable
        // value is treated as the safe posture rather than flagged as the exploited condition.
        bool restrictDriverInstall =
            ReadDword(PointAndPrintSubKey, "RestrictDriverInstallationToAdministrators", defaultValue: 1) != 0;

        // NoWarningNoElevationOnInstall defaults to 0 (prompt shown) so a missing value is not
        // flagged as the insecure "silent install" case.
        bool noWarningNoElevation =
            ReadDword(PointAndPrintSubKey, "NoWarningNoElevationOnInstall", defaultValue: 0) != 0;

        // UpdatePromptSettings defaults to 0 (prompt shown).
        int updatePromptSettings =
            ReadDword(PointAndPrintSubKey, "UpdatePromptSettings", defaultValue: 0);

        return new PrintSpoolerState
        {
            SpoolerRunning = spoolerRunning,
            RestrictDriverInstallationToAdministrators = restrictDriverInstall,
            NoWarningNoElevationOnInstall = noWarningNoElevation,
            UpdatePromptSettings = updatePromptSettings,
        };
    }

    /// <summary>
    /// Best-effort check of whether a Windows service is currently running, returning
    /// <c>false</c> when the service is missing or unreadable.
    /// </summary>
    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            return false;
        }
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
