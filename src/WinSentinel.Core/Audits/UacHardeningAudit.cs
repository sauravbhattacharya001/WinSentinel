using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine User Account Control (UAC) hardening in a live
/// <c>--audit</c> run: the master UAC switch, the admin-approval-mode consent prompt, the
/// secure-desktop prompt, Admin Approval Mode for the built-in Administrator, installer
/// detection, and the remote-UAC-filtering override (LocalAccountTokenFilterPolicy) that
/// enables Pass-the-Hash lateral movement.
///
/// <para>This is the thin I/O layer for <see cref="UacHardeningAnalyzer"/>: it owns the
/// reading of local UAC policy registry state and delegates every pass/fail decision to the
/// pure, unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same split
/// as <see cref="SmbSecurityAudit"/> / <see cref="SmbSecurityAnalyzer"/>). It reads only
/// local registry state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class UacHardeningAudit : AuditModuleBase
{
    public override string Name => "User Account Control (UAC) Hardening Audit";
    public override string Category => UacHardeningAnalyzer.Category;
    public override string Description =>
        "Checks UAC enablement, the admin elevation-prompt behaviour, secure-desktop prompting, " +
        "Admin Approval Mode for the built-in Administrator, installer detection, and the remote " +
        "UAC token-filtering override (Pass-the-Hash enabler) against CIS Windows L1.";

    private const string PoliciesSystem =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in UacHardeningAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read local UAC policy state from the registry into the pure
    /// <see cref="UacHardeningState"/>. Registry reads are best-effort: an unreadable value
    /// falls back to the safer default (see <see cref="UacHardeningState"/>) so a missing key
    /// never false-positives the dangerous posture. The on-by-default UAC values default to 1
    /// (secure) and LocalAccountTokenFilterPolicy defaults to 0 (secure).
    /// </summary>
    internal static UacHardeningState CollectState()
    {
        // On-by-default UAC toggles: default to 1 (secure) so a missing value is treated as the
        // hardened OS default rather than a false gap.
        bool enableLua = ReadDword("EnableLUA", defaultValue: 1) == 1;
        bool promptSecureDesktop = ReadDword("PromptOnSecureDesktop", defaultValue: 1) == 1;
        bool filterAdminToken = ReadDword("FilterAdministratorToken", defaultValue: 1) == 1;
        bool installerDetection = ReadDword("EnableInstallerDetection", defaultValue: 1) == 1;

        // ConsentPromptBehaviorAdmin: default to 5 (the OS default, a prompting value) so an
        // unreadable value is not misread as the silent-elevation setting (0).
        int consentPromptAdmin = ReadDword("ConsentPromptBehaviorAdmin", defaultValue: 5);

        // LocalAccountTokenFilterPolicy: default to 0 (secure/absent). Only 1 disables remote
        // UAC filtering and enables Pass-the-Hash.
        bool latfpEnabled = ReadDword("LocalAccountTokenFilterPolicy", defaultValue: 0) == 1;

        return new UacHardeningState
        {
            EnableLua = enableLua,
            ConsentPromptBehaviorAdmin = consentPromptAdmin,
            PromptOnSecureDesktop = promptSecureDesktop,
            FilterAdministratorToken = filterAdminToken,
            EnableInstallerDetection = installerDetection,
            LocalAccountTokenFilterPolicyEnabled = latfpEnabled,
        };
    }

    /// <summary>
    /// Best-effort read of a REG_DWORD from HKLM, returning <paramref name="defaultValue"/>
    /// when the key/value is missing or unreadable.
    /// </summary>
    private static int ReadDword(string valueName, int defaultValue = 0)
    {
        try
        {
            return RegistryHelper.GetValue<int>(
                RegistryHive.LocalMachine, PoliciesSystem, valueName, defaultValue);
        }
        catch
        {
            return defaultValue;
        }
    }
}
