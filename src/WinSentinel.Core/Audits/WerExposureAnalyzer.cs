using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing Windows Error Reporting (WER) and crash-dump exposure
/// on a single machine. When a process crashes, Windows can (a) upload an error report -
/// which may include a minidump and a slice of process memory - to Microsoft, and (b) write
/// full user-mode crash dumps to local disk via the WER <c>LocalDumps</c> feature. Both are
/// data-exfiltration / credential-exposure surfaces: crash dumps routinely contain
/// decrypted secrets, tokens, connection strings and in-memory credentials, so an
/// unrestricted "send everything to Microsoft" posture leaks data off the machine, and
/// world-readable full dumps on disk hand those same secrets to any local process.
///
/// <para>The checks here read only local WER policy registry state
/// (<c>HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting</c> and its
/// <c>Consent</c> / <c>LocalDumps</c> subkeys), so this module is single-machine and
/// therefore FREE / OSS: nothing multi-machine, nothing license-gated. Every rule operates
/// on a synthetic <see cref="WerState"/> so it can be unit tested directly, mirroring the
/// established <see cref="UacHardeningAnalyzer"/> pattern (collector owns I/O, analyzer owns
/// decisions).</para>
///
///   * DontSendAdditionalData - 1 stops WER from attaching the additional in-memory data
///                              (the memory slice most likely to contain secrets) to reports
///                              sent to Microsoft. Secure default is to set this to 1.
///   * ConsentDefaultConsent  - the automatic-consent level. 4 = "send all data
///                              automatically" (no prompt, maximum data leaves the machine);
///                              lower values prompt or send less. 4 is the risky value.
///   * LocalDumps enabled     - the WER LocalDumps feature writes full user-mode crash dumps
///                              to disk. Convenient for debugging, but a full dump is a raw
///                              memory image and a prime credential-harvesting target.
///   * LocalDumps DumpType    - 2 = full memory dump (whole process address space, most
///                              sensitive); 1 = mini dump (much smaller). Full dumps are the
///                              higher-exposure setting when LocalDumps is on.
///   * WER Disabled           - 1 turns WER off entirely. Not a security win (you lose
///                              crash telemetry and some OS self-diagnostics) but worth
///                              surfacing so the posture is explicit.
/// </summary>
public static class WerExposureAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Error Reporting";

    private const string WerKey = @"HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting";
    private const string ConsentKey = WerKey + @"\Consent";
    private const string LocalDumpsKey = WerKey + @"\LocalDumps";

    /// <summary>
    /// Evaluate the collected WER state and return one finding per check (a Pass when the
    /// setting is already safe, otherwise Info/Warning). Ordering is stable and deterministic
    /// for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(WerState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        return new List<Finding>
        {
            AnalyzeDontSendAdditionalData(state),
            AnalyzeDefaultConsent(state),
            AnalyzeLocalDumps(state),
            AnalyzeWerDisabled(state),
        };
    }

    /// <summary>
    /// WER should not attach the additional in-memory data slice to reports uploaded to
    /// Microsoft (DontSendAdditionalData = 1), since that slice is the part most likely to
    /// carry secrets from process memory.
    /// </summary>
    public static Finding AnalyzeDontSendAdditionalData(WerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.DontSendAdditionalData)
        {
            return Finding.Pass(
                "WER does not send additional crash data",
                "Windows Error Reporting is configured not to attach the additional in-memory data slice to reports " +
                "(DontSendAdditionalData = 1), so the part of a crash report most likely to contain secrets from process " +
                "memory is not uploaded to Microsoft.",
                Category);
        }

        return Finding.Warning(
            "WER may send additional in-memory crash data",
            "Windows Error Reporting is allowed to attach the additional in-memory data slice to crash reports uploaded " +
            "to Microsoft (DontSendAdditionalData is not set to 1). That slice is a raw fragment of the crashed process's " +
            "memory and routinely contains decrypted secrets, tokens, connection strings and in-memory credentials, so " +
            "sensitive data can leave the machine automatically when an application crashes.",
            Category,
            remediation: "Set DontSendAdditionalData = 1 so WER omits the extra memory slice from uploaded reports.",
            fixCommand: "Set-ItemProperty -Path '" + WerKey + "' -Name DontSendAdditionalData -Value 1 -Type DWord");
    }

    /// <summary>
    /// The automatic-consent level (Consent\DefaultConsent). 4 = "always send all data
    /// automatically" (no prompt, maximum data leaves the machine). Lower values prompt the
    /// user or send less, which is the safer posture.
    /// </summary>
    public static Finding AnalyzeDefaultConsent(WerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.DefaultConsent == 4)
        {
            return Finding.Warning(
                "WER auto-sends all crash data without prompting",
                "The Windows Error Reporting consent level is set to 'Send all data automatically' " +
                "(Consent\\DefaultConsent = 4). Full crash reports - including memory slices that can hold secrets - are " +
                "uploaded to Microsoft with no prompt and no chance to review what is being sent.",
                Category,
                remediation: "Lower the automatic consent level (Consent\\DefaultConsent < 4) so full crash data is not sent " +
                    "automatically, or prompt before sending.",
                fixCommand: "Set-ItemProperty -Path '" + ConsentKey + "' -Name DefaultConsent -Value 1 -Type DWord");
        }

        return Finding.Pass(
            "WER does not auto-send all crash data",
            $"The Windows Error Reporting consent level (Consent\\DefaultConsent = {state.DefaultConsent}) is not set to " +
            "'Send all data automatically' (4), so full crash reports are not uploaded to Microsoft without review.",
            Category);
    }

    /// <summary>
    /// The WER LocalDumps feature writes user-mode crash dumps to disk. A full dump
    /// (DumpType = 2) is a raw memory image and a prime credential-harvesting target.
    /// </summary>
    public static Finding AnalyzeLocalDumps(WerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.LocalDumpsEnabled)
        {
            return Finding.Pass(
                "WER local crash dumps are not enabled",
                "The Windows Error Reporting LocalDumps feature is not enabled, so full user-mode crash dumps - which are " +
                "raw memory images that frequently contain secrets - are not being written to local disk.",
                Category);
        }

        if (state.LocalDumpsFullType)
        {
            return Finding.Warning(
                "WER writes full local crash dumps to disk",
                "The Windows Error Reporting LocalDumps feature is enabled and configured to write FULL user-mode crash " +
                "dumps (DumpType = 2). A full dump is a complete image of the crashed process's memory and routinely " +
                "contains decrypted secrets, tokens and in-memory credentials; left on disk it is a prime local " +
                "credential-harvesting target for any process that can read the dump folder.",
                Category,
                remediation: "If local dumps are needed, prefer mini dumps (DumpType = 1) and restrict the DumpFolder ACL; " +
                    "otherwise disable LocalDumps entirely.",
                fixCommand: "Set-ItemProperty -Path '" + LocalDumpsKey + "' -Name DumpType -Value 1 -Type DWord");
        }

        return Finding.Info(
            "WER writes local crash dumps to disk",
            "The Windows Error Reporting LocalDumps feature is enabled (writing mini dumps to disk). Even mini dumps can " +
            "contain sensitive stack/heap fragments, so ensure the DumpFolder is ACL-restricted and dumps are cleaned up.",
            Category,
            remediation: "Restrict the LocalDumps DumpFolder ACL to administrators and periodically clear old dumps, or " +
                "disable LocalDumps if it is not needed.");
    }

    /// <summary>
    /// WER Disabled = 1 turns error reporting off entirely. This is surfaced as Info: it is
    /// not a security improvement (you lose crash telemetry and some OS self-diagnostics),
    /// but the posture should be explicit in the report.
    /// </summary>
    public static Finding AnalyzeWerDisabled(WerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.WerDisabled)
        {
            return Finding.Pass(
                "Windows Error Reporting is enabled",
                "Windows Error Reporting is enabled (Disabled != 1), so crash telemetry and OS self-diagnostics continue " +
                "to function. Upload/dump exposure is controlled by the consent and LocalDumps settings above rather than " +
                "by turning WER off.",
                Category);
        }

        return Finding.Info(
            "Windows Error Reporting is disabled",
            "Windows Error Reporting is turned off entirely (Disabled = 1). No crash reports are uploaded, which limits " +
            "data exposure, but you also lose crash telemetry and some OS self-diagnostics. This is a posture choice, not " +
            "a hardening requirement.",
            Category,
            remediation: "Leave WER enabled and instead control exposure via DontSendAdditionalData and the consent level, " +
                "unless your policy specifically requires WER off.");
    }
}

/// <summary>
/// Raw, collector-supplied Windows Error Reporting (WER) state. Populated by the audit
/// module's I/O layer (reading
/// <c>HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting</c> and its <c>Consent</c> /
/// <c>LocalDumps</c> subkeys) and handed to <see cref="WerExposureAnalyzer"/> for a pure
/// decision. Defaults are chosen so an unreadable value never false-positives the dangerous
/// posture: LocalDumps defaults to off, DefaultConsent defaults to a non-auto value, and
/// DontSendAdditionalData defaults to <c>true</c> (secure).
/// </summary>
public sealed record WerState
{
    /// <summary>DontSendAdditionalData (DWORD). 1 = do not attach the extra in-memory slice to uploaded reports. Secure default <c>true</c>.</summary>
    public bool DontSendAdditionalData { get; init; } = true;

    /// <summary>
    /// Consent\DefaultConsent (DWORD). 4 = send all data automatically (risky); lower values
    /// prompt or send less. Defaults to 1 (a non-auto value) so an unreadable value is not
    /// flagged as the auto-send case.
    /// </summary>
    public int DefaultConsent { get; init; } = 1;

    /// <summary>Whether the WER LocalDumps feature is enabled (full user-mode dumps written to disk). Secure default <c>false</c>.</summary>
    public bool LocalDumpsEnabled { get; init; }

    /// <summary>Whether LocalDumps\DumpType is 2 (full memory dump - the highest-exposure setting). Only meaningful when <see cref="LocalDumpsEnabled"/> is true.</summary>
    public bool LocalDumpsFullType { get; init; }

    /// <summary>Whether WER is disabled entirely (Disabled = 1). Surfaced as Info; secure default <c>false</c> (WER on).</summary>
    public bool WerDisabled { get; init; }
}
