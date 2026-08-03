using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audit module that surfaces single-machine Windows Error Reporting (WER) and crash-dump
/// exposure in a live <c>--audit</c> run: whether WER may upload the additional in-memory
/// data slice to Microsoft, whether it auto-sends all crash data without prompting, whether
/// full user-mode crash dumps are written to local disk (a prime credential-harvesting
/// target), and whether WER is disabled entirely.
///
/// <para>This is the thin I/O layer for <see cref="WerExposureAnalyzer"/>: it owns the
/// reading of local WER registry state and delegates every pass/fail decision to the pure,
/// unit-tested analyzer (collector owns I/O, analyzer owns decisions - the same split as
/// <see cref="UacHardeningAudit"/> / <see cref="UacHardeningAnalyzer"/>). It reads only
/// local registry state, so it is single-machine and therefore FREE / OSS - nothing
/// multi-machine, nothing license-gated.</para>
/// </summary>
public class WerExposureAudit : AuditModuleBase
{
    public override string Name => "Windows Error Reporting Exposure Audit";
    public override string Category => WerExposureAnalyzer.Category;
    public override string Description =>
        "Checks Windows Error Reporting upload posture (additional in-memory data, automatic consent level), " +
        "local crash-dump writing (WER LocalDumps and full-dump type), and whether WER is disabled - all data " +
        "exposure / credential-harvesting surfaces on a single machine.";

    private const string WerSubKey = @"SOFTWARE\Microsoft\Windows\Windows Error Reporting";
    private const string ConsentSubKey = WerSubKey + @"\Consent";
    private const string LocalDumpsSubKey = WerSubKey + @"\LocalDumps";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        var state = CollectState();
        foreach (var finding in WerExposureAnalyzer.Analyze(state))
        {
            result.Findings.Add(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Read local WER registry state into the pure <see cref="WerState"/>. Registry reads are
    /// best-effort: an unreadable value falls back to the safer default (see
    /// <see cref="WerState"/>) so a missing key never false-positives the dangerous posture.
    /// LocalDumps is treated as enabled only when its subkey actually exists.
    /// </summary>
    internal static WerState CollectState()
    {
        // DontSendAdditionalData defaults to 1 (secure) so a missing value is treated as the
        // safe posture rather than a false gap.
        bool dontSendAdditionalData = ReadDword(WerSubKey, "DontSendAdditionalData", defaultValue: 1) == 1;

        // Consent\DefaultConsent defaults to 1 (a non-auto value) so an unreadable value is not
        // misread as the auto-send-all setting (4).
        int defaultConsent = ReadDword(ConsentSubKey, "DefaultConsent", defaultValue: 1);

        // WER Disabled defaults to 0 (WER on).
        bool werDisabled = ReadDword(WerSubKey, "Disabled", defaultValue: 0) == 1;

        // LocalDumps is only "enabled" when its subkey exists (its presence is what turns the
        // feature on). DumpType 2 = full memory dump; anything else (incl. default 1) = mini.
        bool localDumpsEnabled = SubKeyExists(LocalDumpsSubKey);
        bool localDumpsFullType = localDumpsEnabled && ReadDword(LocalDumpsSubKey, "DumpType", defaultValue: 1) == 2;

        return new WerState
        {
            DontSendAdditionalData = dontSendAdditionalData,
            DefaultConsent = defaultConsent,
            LocalDumpsEnabled = localDumpsEnabled,
            LocalDumpsFullType = localDumpsFullType,
            WerDisabled = werDisabled,
        };
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

    /// <summary>
    /// Best-effort check for whether an HKLM subkey exists (used to detect the presence of the
    /// WER LocalDumps feature). Returns <c>false</c> on any error.
    /// </summary>
    private static bool SubKeyExists(string subKey)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey);
            return key is not null;
        }
        catch
        {
            return false;
        }
    }
}
