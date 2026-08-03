using System.ServiceProcess;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine application-control (allowlisting) posture in a
/// live <c>--audit</c> run: AppLocker rule-collection enforcement (Exe/Msi/Script/Dll/Appx),
/// the Application Identity enforcement service, WDAC/Code Integrity policy state, and Smart
/// App Control. Application allowlisting is Essential 8 mitigation #1 and a CIS Windows L1
/// control - the strongest single defense against untrusted-code execution.
///
/// <para>This is the thin I/O layer for <see cref="ApplicationControlAnalyzer"/>: it owns the
/// reading of local AppLocker policy registry state, the AppIDSvc service state, the CI/WDAC
/// deployed-policy key, and the Smart App Control value, and delegates every pass/fail decision
/// to the pure, unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same
/// split as <see cref="UacHardeningAudit"/> / <see cref="UacHardeningAnalyzer"/>). It reads only
/// local registry/service state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class ApplicationControlAudit : AuditModuleBase
{
    public override string Name => "Application Control (AppLocker/WDAC) Audit";
    public override string Category => ApplicationControlAnalyzer.Category;
    public override string Description =>
        "Checks application allowlisting - AppLocker rule collections and enforcement, the Application " +
        "Identity service, WDAC/Code Integrity policy, and Smart App Control - against Essential 8 #1 and CIS Windows L1.";

    // AppLocker (SrpV2) policy per-collection enforcement lives here.
    private const string SrpV2Base = @"SOFTWARE\Policies\Microsoft\Windows\SrpV2";

    // WDAC / Code Integrity deployed-policy state.
    private const string CiPolicyKey = @"SYSTEM\CurrentControlSet\Control\CI\Policy";

    // Smart App Control (Windows 11).
    private const string SacKey = @"SYSTEM\CurrentControlSet\Control\CI\Policy";
    private const string SacValue = "VerifiedAndReputablePolicyState";

    private static readonly string[] CollectionKeys = { "Exe", "Msi", "Script", "Dll", "Appx" };

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in ApplicationControlAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read local application-control state from the registry and the service database into the
    /// pure <see cref="ApplicationControlState"/>. All reads are best-effort: an unreadable value
    /// falls back to the "nothing configured" posture (see <see cref="ApplicationControlState"/>)
    /// so a missing key never invents a control that is not present.
    /// </summary>
    internal static ApplicationControlState CollectState()
    {
        var collections = new Dictionary<string, AppLockerEnforcementMode>();
        foreach (var key in CollectionKeys)
        {
            collections[key] = ReadCollectionMode(key);
        }

        bool anyEnforcing = collections.Values.Any(m => m == AppLockerEnforcementMode.Enabled);

        // Only bother querying the enforcement service when a collection actually enforces; a
        // stopped AppIDSvc is only material to enforced AppLocker.
        bool appIdRunning = anyEnforcing && IsServiceRunning("AppIDSvc");

        var (wdacEnforced, wdacAudit) = ReadWdacState();
        int sac = ReadSmartAppControlState();

        return new ApplicationControlState
        {
            AppLockerCollections = collections,
            AppIdServiceRunning = appIdRunning,
            WdacEnforced = wdacEnforced,
            WdacAuditOnly = wdacAudit,
            SmartAppControlState = sac,
        };
    }

    /// <summary>
    /// Read one AppLocker collection's enforcement mode from
    /// <c>SrpV2\{collection}\EnforcementMode</c>. The subkey being absent means the collection is
    /// not configured; EnforcementMode 1 = Enabled (block), 0 = AuditOnly.
    /// </summary>
    private static AppLockerEnforcementMode ReadCollectionMode(string collection)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey($@"{SrpV2Base}\{collection}");
            if (key == null)
            {
                return AppLockerEnforcementMode.NotConfigured;
            }

            var raw = key.GetValue("EnforcementMode");
            if (raw == null)
            {
                // Subkey exists but no explicit mode - treat a present policy as audit staging.
                return AppLockerEnforcementMode.AuditOnly;
            }

            int mode = Convert.ToInt32(raw);
            return mode == 1 ? AppLockerEnforcementMode.Enabled : AppLockerEnforcementMode.AuditOnly;
        }
        catch
        {
            return AppLockerEnforcementMode.NotConfigured;
        }
    }

    /// <summary>
    /// Read WDAC / Code Integrity deployed-policy state. Returns (enforced, auditOnly). A deployed
    /// policy typically surfaces a <c>DeployedPolicies</c> subkey or a nonzero policy value; when
    /// audit mode is set the policy logs without blocking. Best-effort: unreadable => (false, false).
    /// </summary>
    private static (bool Enforced, bool AuditOnly) ReadWdacState()
    {
        try
        {
            var deployed = RegistryHelper.GetSubKeyNames(RegistryHive.LocalMachine, $@"{CiPolicyKey}\DeployedPolicies");
            if (deployed.Length == 0)
            {
                return (false, false);
            }

            // If any deployed policy is flagged audit-mode, report audit; otherwise enforced.
            foreach (var pol in deployed)
            {
                int auditFlag = RegistryHelper.GetValue<int>(
                    RegistryHive.LocalMachine, $@"{CiPolicyKey}\DeployedPolicies\{pol}", "PolicyAuditMode", 0);
                if (auditFlag == 1)
                {
                    return (false, true);
                }
            }

            return (true, false);
        }
        catch
        {
            return (false, false);
        }
    }

    /// <summary>
    /// Read Smart App Control state (Windows 11). 0 = Off, 1 = On, 2 = Evaluation; -1 when the
    /// value is absent (older OS) or unreadable.
    /// </summary>
    private static int ReadSmartAppControlState()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(SacKey);
            var raw = key?.GetValue(SacValue);
            return raw == null ? -1 : Convert.ToInt32(raw);
        }
        catch
        {
            return -1;
        }
    }

    /// <summary>
    /// Best-effort check of whether a Windows service is currently running. A missing service, or
    /// any query error, is treated as "not running".
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
}
