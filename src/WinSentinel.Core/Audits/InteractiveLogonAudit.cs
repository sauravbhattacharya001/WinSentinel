using System.ServiceProcess;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows interactive-logon policy hardening in a live
/// <c>--audit</c> run: whether a pre-logon legal-notice banner is configured (LegalNoticeCaption /
/// LegalNoticeText) and, when smart-card logon is in use, whether removing the card locks or logs off
/// the session (ScRemoveOption).
///
/// <para>This is the thin I/O layer for <see cref="InteractiveLogonAnalyzer"/>: it owns the reading
/// of the Winlogon and Policies\System registry values (and the Smart Card service state to decide
/// whether the removal check applies), and delegates every pass/fail decision to the pure,
/// unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="TimeSyncSecurityAudit"/> / <see cref="TimeSyncSecurityAnalyzer"/>). It reads only local
/// machine state, so it is single-machine and therefore FREE / OSS - nothing multi-machine, nothing
/// license-gated.</para>
/// </summary>
public class InteractiveLogonAudit : AuditModuleBase
{
    public override string Name => "Interactive Logon Audit";
    public override string Category => InteractiveLogonAnalyzer.Category;
    public override string Description =>
        "Checks single-machine Windows interactive-logon policy hardening - whether a pre-logon legal-notice banner is " +
        "configured (LegalNoticeCaption / LegalNoticeText) and, when smart-card logon is in use, whether removing the card " +
        "locks or logs off the session (ScRemoveOption) - CIS L1 interactive-logon controls.";

    private const string PoliciesSystemSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string WinlogonSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        await Task.CompletedTask.ConfigureAwait(false);
        foreach (var finding in InteractiveLogonAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }
    }

    /// <summary>
    /// Read local Winlogon / Policies\System state into the pure <see cref="InteractiveLogonState"/>.
    /// Each value is a best-effort registry read whose absence maps to the safer default (see
    /// <see cref="InteractiveLogonState"/>) so a missing key never false-positives the dangerous
    /// posture. Smart-card-in-use is inferred from the Smart Card (SCardSvr) service running.
    /// </summary>
    internal static InteractiveLogonState CollectState()
    {
        // LegalNotice values live under Policies\System. Absent => empty => no banner. We do NOT
        // fall back to the secure placeholder here (unlike defaults) because a genuinely absent
        // banner is exactly the Info we want to surface.
        string caption = ReadString(PoliciesSystemSubKey, "LegalNoticeCaption") ?? string.Empty;
        string text = ReadString(PoliciesSystemSubKey, "LegalNoticeText") ?? string.Empty;

        // ScRemoveOption is a REG_SZ under Winlogon ("0"/"1"/"2"). Absent => treat as unset (empty).
        string scRemove = ReadString(WinlogonSubKey, "ScRemoveOption") ?? string.Empty;

        bool smartCardInUse = IsServiceRunning("SCardSvr");

        return new InteractiveLogonState
        {
            LegalNoticeCaption = caption,
            LegalNoticeText = text,
            SmartCardLogonInUse = smartCardInUse,
            ScRemoveOption = scRemove,
        };
    }

    /// <summary>Best-effort check of whether a Windows service is currently running.</summary>
    private static bool IsServiceRunning(string serviceName)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch
        {
            // If we cannot read the service (non-Windows / access denied), assume smart-card logon is
            // NOT in use so the removal check does not spuriously warn.
            return false;
        }
    }

    /// <summary>Best-effort read of a REG_SZ from HKLM, returning <c>null</c> when missing/unreadable.</summary>
    private static string? ReadString(string subKey, string valueName)
    {
        try
        {
            return RegistryHelper.GetValue<string?>(RegistryHive.LocalMachine, subKey, valueName, null);
        }
        catch
        {
            return null;
        }
    }
}
