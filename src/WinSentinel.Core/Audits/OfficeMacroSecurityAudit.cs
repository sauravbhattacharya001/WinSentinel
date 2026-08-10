using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine <b>Microsoft Office macro-security</b>
/// posture in a live <c>--audit</c> run: whether macros are enabled without
/// prompting (<c>VBAWarnings</c>), whether macros in Mark-of-the-Web files are
/// hard-blocked (<c>blockcontentexecutionfrominternet</c>), and whether Protected
/// View is disabled for risky document origins.
///
/// <para>Malicious Office macros remain one of the most common initial-access
/// vectors (MITRE ATT&amp;CK T1566 phishing → T1204.002 user execution → T1137
/// Office application startup). The hardened posture is signed-only / disable-all
/// macros, internet-macro blocking on, and Protected View left enabled.</para>
///
/// <para>This is the thin I/O layer for <see cref="OfficeMacroSecurityAnalyzer"/>:
/// it owns reading the per-app <c>HKCU\Software\Policies\Microsoft\Office\&lt;ver&gt;\
/// &lt;app&gt;\Security</c> policy values (reporting the WEAKEST value seen across
/// Word/Excel/PowerPoint so one lax app is never masked) and delegates every
/// pass/fail decision to the pure, unit-tested analyzer (collector owns I/O,
/// analyzer owns decisions - the same split as <see cref="WindowsRecallAudit"/> /
/// <see cref="WindowsRecallAnalyzer"/>). It reads only local current-user /
/// machine state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class OfficeMacroSecurityAudit : AuditModuleBase
{
    public override string Name => "Office Macro Security Audit";
    public override string Category => OfficeMacroSecurityAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Microsoft Office macro-security posture - whether macros run without a prompt " +
        "(VBAWarnings), whether macros in files from the internet are hard-blocked, and whether Protected View " +
        "is disabled for risky document origins - to reduce the phishing-borne macro initial-access surface.";

    /// <summary>Office version subkey. 16.0 covers Office 2016/2019/2021 and Microsoft 365.</summary>
    private const string OfficeVersion = "16.0";

    private static readonly string[] Apps = { "Word", "Excel", "PowerPoint" };

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in OfficeMacroSecurityAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local Office macro-security policy state into the pure
    /// <see cref="OfficeMacroSecurityState"/>. Reports the weakest (least restrictive) value observed
    /// across Word/Excel/PowerPoint per field so a single lax app cannot be masked by a stricter one.
    /// Every read is best-effort; absence maps to null so the analyzer applies its documented default
    /// semantics (never a false pass).
    /// </summary>
    internal static OfficeMacroSecurityState CollectState()
    {
        var installed = OfficeInstalled();
        if (!installed)
        {
            return new OfficeMacroSecurityState { OfficeInstalled = false };
        }

        // VBAWarnings: report the LOWEST (most permissive) value seen. 1 = enable all is worst.
        int? weakestVba = null;
        // BlockInternetMacros: hardened only if EVERY present app blocks; a single false weakens.
        bool? weakestBlock = null;
        // Protected View: report OFF (true) if ANY app disables it for that origin.
        bool? disableInternetPv = null;
        bool? disableUnsafePv = null;
        bool? disableAttachPv = null;

        foreach (var app in Apps)
        {
            var securityKey = $@"Software\Policies\Microsoft\Office\{OfficeVersion}\{app}\Security";
            var pvKey = securityKey + @"\ProtectedView";

            var vba = ReadDword(RegistryHive.CurrentUser, securityKey, "VBAWarnings");
            if (vba.HasValue)
            {
                weakestVba = weakestVba.HasValue ? Math.Min(weakestVba.Value, vba.Value) : vba.Value;
            }

            var block = ReadBool(RegistryHive.CurrentUser, securityKey, "blockcontentexecutionfrominternet");
            weakestBlock = WeakestBlock(weakestBlock, block);

            disableInternetPv = OrDisable(disableInternetPv, ReadBool(RegistryHive.CurrentUser, pvKey, "DisableInternetFilesInPV"));
            disableUnsafePv = OrDisable(disableUnsafePv, ReadBool(RegistryHive.CurrentUser, pvKey, "DisableUnsafeLocationsInPV"));
            disableAttachPv = OrDisable(disableAttachPv, ReadBool(RegistryHive.CurrentUser, pvKey, "DisableAttachmentsInPV"));
        }

        return new OfficeMacroSecurityState
        {
            OfficeInstalled = true,
            VbaWarnings = weakestVba,
            BlockInternetMacros = weakestBlock,
            DisableInternetFilesInProtectedView = disableInternetPv,
            DisableUnsafeLocationsInProtectedView = disableUnsafePv,
            DisableAttachmentsInProtectedView = disableAttachPv,
        };
    }

    /// <summary>
    /// Combine internet-macro-block readings across apps. The hardened state requires every present app
    /// to block, so: any explicit false wins (weakest), otherwise true if any app is true, else null.
    /// </summary>
    private static bool? WeakestBlock(bool? current, bool? next)
    {
        if (next == false) return false;      // one app not blocking weakens the whole posture
        if (current == false) return false;
        if (next == true || current == true) return true;
        return current ?? next;               // both null-ish
    }

    /// <summary>Protected-View "disabled" is OR-combined: if ANY app disables PV for an origin, report OFF.</summary>
    private static bool? OrDisable(bool? current, bool? next)
    {
        if (current == true || next == true) return true;
        if (current == false || next == false) return false;
        return null;
    }

    /// <summary>
    /// Best-effort detection of any Microsoft Office install: a ClickToRun product configuration, or a
    /// classic per-app InstallRoot under the Office version key. Never throws.
    /// </summary>
    internal static bool OfficeInstalled()
    {
        try
        {
            // Microsoft 365 / Click-to-Run
            var c2r = RegistryHelper.GetValue<object?>(
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
                "ProductReleaseIds", null);
            if (c2r != null) return true;

            // Classic per-app InstallRoot (Word/Excel/PowerPoint)
            foreach (var app in Apps)
            {
                var installRoot = RegistryHelper.GetValue<object?>(
                    RegistryHive.LocalMachine,
                    $@"SOFTWARE\Microsoft\Office\{OfficeVersion}\{app}\InstallRoot",
                    "Path", null);
                if (installRoot != null) return true;
            }

            // Presence of the Office version root key at all (covers policy-only / GPO-managed hosts)
            if (RegistryHelper.GetSubKeyNames(RegistryHive.LocalMachine, $@"SOFTWARE\Microsoft\Office\{OfficeVersion}").Length > 0)
            {
                // Only treat as installed if an app subkey exists, not just a bare Office key.
                foreach (var app in Apps)
                {
                    if (RegistryHelper.GetSubKeyNames(
                            RegistryHive.LocalMachine,
                            $@"SOFTWARE\Microsoft\Office\{OfficeVersion}\{app}").Length > 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Best-effort read of a REG_DWORD as an int; null when missing/unreadable. Tolerates REG_SZ.</summary>
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

    /// <summary>Best-effort read of a DWORD as a bool (1 = true, 0 = false); null when missing/unreadable.</summary>
    private static bool? ReadBool(RegistryHive hive, string subKey, string valueName)
    {
        var v = ReadDword(hive, subKey, valueName);
        return v.HasValue ? v.Value != 0 : (bool?)null;
    }
}
