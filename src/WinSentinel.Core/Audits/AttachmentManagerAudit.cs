using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows Attachment Manager /
/// Mark-of-the-Web (MoTW) hardening posture in a live <c>--audit</c> run:
/// whether downloaded and saved files keep their untrusted zone mark (so
/// SmartScreen and Office Protected View still fire), whether the "Unblock"
/// control is visible, whether saved attachments are scanned by antivirus, and
/// whether any file types have been force-classified as low-risk.
///
/// <para>This is the thin I/O layer for <see cref="AttachmentManagerAnalyzer"/>:
/// it owns reading the per-user Attachment Manager / Associations policy values
/// and delegates every pass/fail decision to the pure, unit-tested analyzer
/// (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="PrintSpoolerAudit"/> / <see cref="PrintSpoolerAnalyzer"/>). It
/// reads only local (HKCU) policy state, so it is single-machine and therefore
/// FREE / OSS - nothing multi-machine, nothing license-gated.</para>
/// </summary>
public class AttachmentManagerAudit : AuditModuleBase
{
    public override string Name => "Attachment Manager / Mark-of-the-Web Audit";
    public override string Category => AttachmentManagerAnalyzer.Category;
    public override string Description =>
        "Checks Windows Attachment Manager / Mark-of-the-Web hardening on a single machine: whether " +
        "downloaded files keep their untrusted zone mark (so SmartScreen and Office Protected View " +
        "still fire), whether saved attachments are scanned for malware, and whether any file types " +
        "have been force-classified as low-risk - the controls that decide how safely untrusted " +
        "downloads are handled.";

    private const string AttachmentsSubKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments";
    private const string AssociationsSubKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations";

    /// <summary>
    /// Sentinel returned by <see cref="ReadOptionalDword"/> when a DWORD value is
    /// absent/unreadable, so the analyzer can distinguish "not set" (null) from a
    /// real 0.
    /// </summary>
    private const int Absent = int.MinValue;

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in AttachmentManagerAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read the local (HKCU) Attachment Manager / Associations policy values into
    /// the pure <see cref="AttachmentManagerState"/>. Reads are best-effort: an
    /// unreadable value maps to null so the analyzer treats it as the safe OS
    /// default rather than false-positiving a dangerous posture.
    /// </summary>
    internal static AttachmentManagerState CollectState()
    {
        return new AttachmentManagerState
        {
            SaveZoneInformation = ReadOptionalDword(AttachmentsSubKey, "SaveZoneInformation"),
            HideZoneInfoOnProperties = ReadOptionalDword(AttachmentsSubKey, "HideZoneInfoOnProperties"),
            ScanWithAntiVirus = ReadOptionalDword(AttachmentsSubKey, "ScanWithAntiVirus"),
            DefaultFileTypeRisk = ReadOptionalDword(AssociationsSubKey, "DefaultFileTypeRisk"),
            LowRiskFileTypes = ReadString(AssociationsSubKey, "LowRiskFileTypes"),
        };
    }

    /// <summary>
    /// Best-effort read of a REG_DWORD from HKCU, returning <c>null</c> when the
    /// value is missing or unreadable so absence is distinguishable from a real 0.
    /// </summary>
    private static int? ReadOptionalDword(string subKey, string valueName)
    {
        try
        {
            int value = RegistryHelper.GetValue<int>(
                RegistryHive.CurrentUser, subKey, valueName, Absent);
            return value == Absent ? (int?)null : value;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Best-effort read of a REG_SZ from HKCU, returning <c>null</c> when the
    /// value is missing or unreadable.
    /// </summary>
    private static string? ReadString(string subKey, string valueName)
    {
        try
        {
            return RegistryHelper.GetValue<string>(
                RegistryHive.CurrentUser, subKey, valueName, null);
        }
        catch
        {
            return null;
        }
    }
}
