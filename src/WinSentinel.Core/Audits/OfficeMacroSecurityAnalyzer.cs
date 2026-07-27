using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for auditing Microsoft Office macro-security posture on a
/// single machine.
///
/// Malicious Office (Word/Excel/PowerPoint) macros remain one of the most common
/// initial-access vectors (MITRE ATT&amp;CK T1566 phishing → T1204.002 user
/// execution → T1137 Office application startup). Windows/Office exposes several
/// local policy controls that decide whether a macro from an untrusted document
/// can run at all. The checks below all read local per-application policy state:
///
///   * VBAWarnings - the master macro-enablement setting for an app:
///       1 = enable ALL macros (no prompt)         → dangerous
///       2 = disable with notification (the default; one click enables)
///       3 = digitally-signed macros only
///       4 = disable ALL macros without notification → hardened
///   * BlockContentExecutionFromInternet - when 1, macros in files carrying a
///     Mark-of-the-Web (downloaded / e-mailed) are blocked outright regardless of
///     VBAWarnings. This is the single highest-value macro control.
///   * Protected View - opening internet / unsafe-location / e-mail-attachment
///     files in the sandboxed Protected View. Disabling any of these removes a
///     containment layer for weaponised documents.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// per-app Office policy state only. Nothing multi-machine, nothing license-gated.
/// All rules operate on a synthetic <see cref="OfficeMacroSecurityState"/> so they
/// can be unit tested directly, mirroring the established
/// <see cref="WindowsRecallAnalyzer"/> analyzer pattern (collector owns I/O,
/// analyzer owns decisions).
/// </summary>
public static class OfficeMacroSecurityAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Application Security";

    /// <summary>
    /// Evaluate the collected Office macro-security state and return one finding
    /// per check. Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(OfficeMacroSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (!state.OfficeInstalled)
        {
            return new List<Finding>
            {
                Finding.Pass(
                    "Microsoft Office not detected",
                    "No Microsoft Office installation was found, so Office macro policy " +
                    "does not apply on this machine.",
                    Category),
            };
        }

        return new List<Finding>
        {
            AnalyzeVbaWarnings(state),
            AnalyzeBlockInternetMacros(state),
            AnalyzeProtectedView(state),
        };
    }

    /// <summary>
    /// VBAWarnings governs whether macros run and whether the user is warned.
    /// null = policy unset (Office default = "disable with notification", still a
    /// one-click enable) → Warning. 1 (enable all) → Critical. 2 → Warning.
    /// 3 (signed only) or 4 (disable all) → Pass.
    /// </summary>
    public static Finding AnalyzeVbaWarnings(OfficeMacroSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        const string remediation =
            "Set HKCU\\Software\\Policies\\Microsoft\\Office\\<ver>\\<app>\\Security\\VBAWarnings = 4 " +
            "(disable all macros without notification) or 3 (digitally-signed only) for Word, Excel and PowerPoint.";
        const string fixCommand =
            "$apps=@('Word','Excel','PowerPoint'); foreach($a in $apps){ " +
            "$p=\"HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\$a\\Security\"; " +
            "New-Item -Path $p -Force | Out-Null; " +
            "Set-ItemProperty -Path $p -Name VBAWarnings -Type DWord -Value 4 }";

        switch (state.VbaWarnings)
        {
            case 1:
                return Finding.Critical(
                    "Office macros: all macros enabled without prompting",
                    "VBAWarnings is set to 1 (Enable all macros), so Office runs macros from any " +
                    "document with no warning. A single weaponised document executes code immediately.",
                    Category, remediation, fixCommand);
            case 3:
                return Finding.Pass(
                    "Office macros: only digitally-signed macros allowed",
                    "VBAWarnings is 3, so only macros signed by a trusted publisher can run.",
                    Category);
            case 4:
                return Finding.Pass(
                    "Office macros: all macros disabled without notification",
                    "VBAWarnings is 4, the most restrictive setting - macros are disabled and the " +
                    "user is not offered a one-click enable.",
                    Category);
            case 2:
                return Finding.Warning(
                    "Office macros: disabled with notification (one-click enable)",
                    "VBAWarnings is 2 (disable with notification). Macros are blocked by default but " +
                    "the user is offered an 'Enable Content' button, which social engineering routinely " +
                    "defeats. Prefer signed-only (3) or disable-all (4).",
                    Category, remediation, fixCommand);
            default:
                return Finding.Warning(
                    "Office macros: enablement policy not enforced",
                    "No VBAWarnings macro-enablement policy is set, so macro behaviour follows the " +
                    "per-user Office default (disable with a one-click enable prompt). Enforce a signed-only " +
                    "or disable-all policy so it cannot be relaxed per user.",
                    Category, remediation, fixCommand);
        }
    }

    /// <summary>
    /// BlockContentExecutionFromInternet = 1 blocks macros in Mark-of-the-Web
    /// (downloaded / e-mailed) files outright. This is the highest-value macro
    /// control and its absence is the single biggest macro exposure.
    /// </summary>
    public static Finding AnalyzeBlockInternetMacros(OfficeMacroSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        if (state.BlockInternetMacros == true)
        {
            return Finding.Pass(
                "Office macros: blocked in files from the internet",
                "BlockContentExecutionFromInternet is enabled, so macros in documents carrying a " +
                "Mark-of-the-Web (downloaded or e-mailed) cannot run regardless of the enable prompt.",
                Category);
        }

        return Finding.Warning(
            "Office macros: not blocked in files from the internet",
            "Macros in files carrying a Mark-of-the-Web (downloaded from the web or received as an " +
            "e-mail attachment) are not hard-blocked. These are exactly the files used in phishing-borne " +
            "macro attacks (MITRE T1204.002).",
            Category,
            remediation: "Set HKCU\\Software\\Policies\\Microsoft\\Office\\<ver>\\<app>\\Security\\" +
                         "blockcontentexecutionfrominternet = 1 for Word, Excel and PowerPoint.",
            fixCommand: "$apps=@('Word','Excel','PowerPoint'); foreach($a in $apps){ " +
                        "$p=\"HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\$a\\Security\"; " +
                        "New-Item -Path $p -Force | Out-Null; " +
                        "Set-ItemProperty -Path $p -Name blockcontentexecutionfrominternet -Type DWord -Value 1 }");
    }

    /// <summary>
    /// Protected View sandboxes documents from risky origins (internet, unsafe
    /// locations, e-mail attachments). Any of these being explicitly disabled
    /// removes a containment layer; all present-or-enabled is a Pass.
    /// </summary>
    public static Finding AnalyzeProtectedView(OfficeMacroSecurityState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var disabled = new List<string>();
        // These policy values are "Disable...InPV"; 1 means Protected View is turned OFF for that origin.
        if (state.DisableInternetFilesInProtectedView == true) disabled.Add("internet files");
        if (state.DisableUnsafeLocationsInProtectedView == true) disabled.Add("unsafe locations");
        if (state.DisableAttachmentsInProtectedView == true) disabled.Add("e-mail attachments");

        if (disabled.Count == 0)
        {
            return Finding.Pass(
                "Office Protected View: enabled for risky document origins",
                "Protected View is not disabled for internet files, unsafe locations or e-mail " +
                "attachments, so documents from those origins open sandboxed and read-only first.",
                Category);
        }

        return Finding.Warning(
            "Office Protected View: disabled for some risky origins",
            "Protected View has been turned off for: " + string.Join(", ", disabled) + ". " +
            "Documents from those origins open with full editing/macro capability instead of being " +
            "sandboxed first, removing a containment layer for weaponised files.",
            Category,
            remediation: "Under HKCU\\Software\\Policies\\Microsoft\\Office\\<ver>\\<app>\\Security\\ProtectedView, " +
                         "set DisableInternetFilesInPV, DisableUnsafeLocationsInPV and " +
                         "DisableAttachmentsInPV to 0 (Protected View enabled) for Word, Excel and PowerPoint.");
    }
}

/// <summary>
/// Raw, collector-supplied Microsoft Office macro-security policy state. Populated
/// by the audit module's I/O layer and handed to
/// <see cref="OfficeMacroSecurityAnalyzer"/> for a pure decision. When multiple
/// Office apps are present the collector should report the WEAKEST (least
/// restrictive) observed value per field, so a single lax app is not masked.
/// Null fields mean "policy absent / not readable"; the analyzer treats absence
/// per the semantics documented on each rule.
/// </summary>
public sealed record OfficeMacroSecurityState
{
    /// <summary>Whether any Microsoft Office installation was detected.</summary>
    public bool OfficeInstalled { get; init; }

    /// <summary>
    /// Security\VBAWarnings (DWORD): 1 = enable all, 2 = disable with notification,
    /// 3 = signed only, 4 = disable all without notification. Null = policy unset.
    /// Report the lowest (most permissive) value seen across apps.
    /// </summary>
    public int? VbaWarnings { get; init; }

    /// <summary>
    /// Security\blockcontentexecutionfrominternet (DWORD): true = macros blocked in
    /// Mark-of-the-Web files. Null = policy unset.
    /// </summary>
    public bool? BlockInternetMacros { get; init; }

    /// <summary>Security\ProtectedView\DisableInternetFilesInPV = 1 turns Protected View OFF for internet files.</summary>
    public bool? DisableInternetFilesInProtectedView { get; init; }

    /// <summary>Security\ProtectedView\DisableUnsafeLocationsInPV = 1 turns Protected View OFF for unsafe locations.</summary>
    public bool? DisableUnsafeLocationsInProtectedView { get; init; }

    /// <summary>Security\ProtectedView\DisableAttachmentsInPV = 1 turns Protected View OFF for e-mail attachments.</summary>
    public bool? DisableAttachmentsInProtectedView { get; init; }
}
