using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the Windows Attachment Manager / Mark-of-the-Web
/// (MoTW) hardening posture on a single machine.
///
/// When a file arrives from an untrusted location (a download, an email
/// attachment, a network share), Windows tags it with a "zone" via the
/// Attachment Manager - the same NTFS <c>Zone.Identifier</c> alternate data
/// stream commonly called the Mark-of-the-Web. That mark is what makes
/// SmartScreen prompt, Office open the file in Protected View, and script
/// engines refuse to run it silently. A handful of policy values under
/// <c>...\Policies\Microsoft\Windows\Associations</c> and
/// <c>...\Policies\Microsoft\Windows\Attachments</c> can weaken or entirely
/// remove that protection:
///
///   * SaveZoneInformation            - when 1, the Attachment Manager does NOT
///                                      persist the zone/MoTW, so downloaded and
///                                      saved files lose their untrusted mark and
///                                      run without any SmartScreen/Protected-View
///                                      warning. The safe value is 2 (or absent):
///                                      preserve the zone information.
///   * HideZoneInfoOnProperties       - when 1, the "This file came from another
///                                      computer... Unblock" control is hidden and
///                                      users are steered away from realising a file
///                                      is untrusted. Informational; safe value 0.
///   * ScanWithAntiVirus              - controls whether saved attachments are
///                                      handed to the registered AV/SmartScreen for
///                                      scanning: 1 = OFF (never scan - dangerous),
///                                      2 = optional (default), 3 = always scan.
///   * DefaultFileTypeRisk            - the baseline risk applied to file types not
///                                      otherwise classified: 0x1808 = High (safe),
///                                      0x1807 = Moderate, 0x1806 = Low (treats
///                                      everything as low-risk, suppressing warnings).
///   * LowRiskFileTypes               - an explicit allow-list of extensions the
///                                      Attachment Manager treats as low-risk and
///                                      never blocks/warns on. A populated value
///                                      (especially one containing executable
///                                      extensions like .exe/.bat/.ps1/.js) silently
///                                      whitelists dangerous downloads.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// policy state only. Nothing multi-machine, nothing license-gated. All rules
/// operate on a synthetic <see cref="AttachmentManagerState"/> so they can be
/// unit tested directly, mirroring the established
/// <see cref="PrintSpoolerAnalyzer"/> / <see cref="LsaHardeningAnalyzer"/>
/// analyzer pattern (collector owns I/O, analyzer owns decisions).
/// </summary>
public static class AttachmentManagerAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "Attachment Manager";

    /// <summary>Attachment Manager "always scan saved attachments" value for ScanWithAntiVirus.</summary>
    public const int ScanAlways = 3;

    /// <summary>Attachment Manager "optional / default" value for ScanWithAntiVirus.</summary>
    public const int ScanOptional = 2;

    /// <summary>Attachment Manager "never scan saved attachments" value for ScanWithAntiVirus.</summary>
    public const int ScanOff = 1;

    /// <summary>DefaultFileTypeRisk value that treats unclassified types as High risk (safe).</summary>
    public const int RiskHigh = 0x1808;

    /// <summary>DefaultFileTypeRisk value that treats unclassified types as Moderate risk.</summary>
    public const int RiskModerate = 0x1807;

    /// <summary>DefaultFileTypeRisk value that treats unclassified types as Low risk (weak).</summary>
    public const int RiskLow = 0x1806;

    /// <summary>
    /// Executable / script extensions that are especially dangerous to fold into
    /// the Attachment Manager's low-risk allow-list, because doing so removes the
    /// Mark-of-the-Web warning from downloaded code.
    /// </summary>
    public static readonly IReadOnlyList<string> DangerousLowRiskExtensions = new[]
    {
        ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
        ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi",
    };

    /// <summary>
    /// Evaluate the collected Attachment Manager state and return one finding per
    /// check (a Pass when the setting is already safe, a Warning/Critical when it
    /// is not). Ordering is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(AttachmentManagerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var findings = new List<Finding>
        {
            AnalyzeSaveZoneInformation(state),
            AnalyzeHideZoneInfo(state),
            AnalyzeScanWithAntiVirus(state),
            AnalyzeDefaultFileTypeRisk(state),
            AnalyzeLowRiskFileTypes(state),
        };
        return findings;
    }

    /// <summary>
    /// SaveZoneInformation: 1 strips the Mark-of-the-Web from saved files, so
    /// downloads run with no SmartScreen / Protected-View warning. Safe value is
    /// 2 or absent (preserve the zone).
    /// </summary>
    public static Finding AnalyzeSaveZoneInformation(AttachmentManagerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // Absent (null) is safe: the OS preserves zone info by default.
        if (state.SaveZoneInformation == 1)
        {
            return Finding.Critical(
                "Mark-of-the-Web is stripped from downloaded files",
                "SaveZoneInformation is 1, so the Attachment Manager does NOT persist the " +
                "zone/Mark-of-the-Web on files saved from untrusted locations. Downloaded " +
                "executables, scripts and Office documents lose their untrusted mark and run " +
                "without any SmartScreen warning or Office Protected View.",
                Category,
                remediation: "Set (or remove) HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\SaveZoneInformation " +
                             "so it is 2 (preserve zone info). Removing the value restores the safe default.",
                fixCommand: "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' -Name SaveZoneInformation -Type DWord -Value 2");
        }

        return Finding.Pass(
            "Mark-of-the-Web is preserved on downloaded files",
            "SaveZoneInformation is 2 or absent, so the Attachment Manager keeps the zone/" +
            "Mark-of-the-Web on saved files - SmartScreen and Office Protected View still " +
            "trigger on untrusted downloads.",
            Category);
    }

    /// <summary>
    /// HideZoneInfoOnProperties: 1 hides the "Unblock" control on a file's
    /// Properties dialog, steering users away from noticing a file is untrusted.
    /// Informational (Warning), safe value 0/absent.
    /// </summary>
    public static Finding AnalyzeHideZoneInfo(AttachmentManagerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.HideZoneInfoOnProperties == 1)
        {
            return Finding.Warning(
                "The file 'Unblock' / zone control is hidden from users",
                "HideZoneInfoOnProperties is 1: the \"This file came from another computer... " +
                "Unblock\" control is hidden on the file Properties dialog, so users cannot see " +
                "that a downloaded file is still marked untrusted.",
                Category,
                remediation: "Set HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\HideZoneInfoOnProperties = 0 " +
                             "(or remove the value) so the zone/Unblock control is shown.",
                fixCommand: "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' -Name HideZoneInfoOnProperties -Type DWord -Value 0");
        }

        return Finding.Pass(
            "The file zone / 'Unblock' control is visible",
            "HideZoneInfoOnProperties is 0 or absent, so the zone information and the " +
            "\"Unblock\" control remain visible on a file's Properties dialog.",
            Category);
    }

    /// <summary>
    /// ScanWithAntiVirus: 1 = never scan saved attachments (Critical), 2 =
    /// optional/default (Pass), 3 = always scan (Pass, strongest). Absence is the
    /// OS default (optional).
    /// </summary>
    public static Finding AnalyzeScanWithAntiVirus(AttachmentManagerState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        int value = state.ScanWithAntiVirus ?? ScanOptional; // OS default when unset
        if (value == ScanOff)
        {
            return Finding.Critical(
                "Saved attachments are never scanned for malware",
                "ScanWithAntiVirus is 1 (OFF): files saved from untrusted locations are never " +
                "handed to the registered antivirus / SmartScreen for scanning, so malicious " +
                "downloads are written to disk without any inspection.",
                Category,
                remediation: "Set HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\ScanWithAntiVirus = 3 " +
                             "(always scan) - or remove it to restore the default (2, optional).",
                fixCommand: "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments' -Name ScanWithAntiVirus -Type DWord -Value 3");
        }

        return Finding.Pass(
            "Saved attachments are scanned for malware",
            $"ScanWithAntiVirus is {value}: saved attachments are handed to the registered " +
            "antivirus / SmartScreen for scanning" +
            (value == ScanAlways ? " on every save." : " (default optional behaviour)."),
            Category);
    }

    /// <summary>
    /// DefaultFileTypeRisk: the baseline risk for unclassified file types. High
    /// (0x1808) is safe; Moderate (0x1807) is a Warning; Low (0x1806) treats
    /// everything as low-risk and suppresses warnings (Critical). Absence is the
    /// OS default (High/Moderate depending on build) and is treated as safe.
    /// </summary>
    public static Finding AnalyzeDefaultFileTypeRisk(AttachmentManagerState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        // Absent -> treat as the safe High default; nothing to flag.
        if (state.DefaultFileTypeRisk is null || state.DefaultFileTypeRisk == RiskHigh)
        {
            return Finding.Pass(
                "Unclassified downloads default to High risk",
                "DefaultFileTypeRisk is High (0x1808) or absent, so file types that are not " +
                "otherwise classified are treated as high-risk and still trigger the untrusted-" +
                "file prompt.",
                Category);
        }

        if (state.DefaultFileTypeRisk == RiskLow)
        {
            return Finding.Critical(
                "Unclassified downloads default to Low risk",
                "DefaultFileTypeRisk is Low (0x1806): every file type that is not explicitly " +
                "classified is treated as low-risk, so downloaded files - including executables " +
                "- open with no untrusted-file warning.",
                Category,
                remediation: "Set HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\DefaultFileTypeRisk = 6152 (0x1808, High), " +
                             "or remove the value to restore the default.",
                fixCommand: "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations' -Name DefaultFileTypeRisk -Type DWord -Value 6152");
        }

        // Moderate or any other non-High value.
        return Finding.Warning(
            "Unclassified downloads default to Moderate risk",
            $"DefaultFileTypeRisk is 0x{state.DefaultFileTypeRisk:X4} (not High/0x1808): " +
            "unclassified file types are treated as less than high-risk, weakening the " +
            "untrusted-file prompt on downloads.",
            Category,
            remediation: "Set HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\DefaultFileTypeRisk = 6152 (0x1808, High), " +
                         "or remove the value to restore the default.",
            fixCommand: "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations' -Name DefaultFileTypeRisk -Type DWord -Value 6152");
    }

    /// <summary>
    /// LowRiskFileTypes: an explicit low-risk allow-list. A populated value that
    /// contains executable/script extensions silently whitelists dangerous
    /// downloads (Critical). A populated value with only benign extensions is a
    /// Warning; empty/absent is a Pass.
    /// </summary>
    public static Finding AnalyzeLowRiskFileTypes(AttachmentManagerState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        var raw = state.LowRiskFileTypes;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Finding.Pass(
                "No file types are force-classified as low-risk",
                "LowRiskFileTypes is empty or absent, so no extensions are exempted from the " +
                "Attachment Manager's untrusted-file handling.",
                Category);
        }

        var extensions = raw
            .Split(new[] { ';', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(e => e.Trim().ToLowerInvariant())
            .Select(e => e.StartsWith('.') ? e : "." + e)
            .ToList();

        var dangerous = extensions
            .Where(e => DangerousLowRiskExtensions.Contains(e))
            .Distinct()
            .ToList();

        if (dangerous.Count > 0)
        {
            return Finding.Critical(
                "Executable file types are force-classified as low-risk",
                "LowRiskFileTypes includes executable/script extensions (" +
                string.Join(", ", dangerous) +
                "): downloads of these types are treated as low-risk and open with no " +
                "SmartScreen / untrusted-file warning, even when they came from the internet.",
                Category,
                remediation: "Remove executable/script extensions from " +
                             "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\LowRiskFileTypes " +
                             "(ideally delete the value entirely).");
        }

        return Finding.Warning(
            "Some file types are force-classified as low-risk",
            "LowRiskFileTypes is populated (" + string.Join(", ", extensions) +
            "): those extensions bypass the Attachment Manager's untrusted-file warnings. " +
            "None are executable, but confirm this allow-list is intentional.",
            Category,
            remediation: "Review HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\LowRiskFileTypes " +
                         "and remove any extensions that should keep their untrusted-file warning.");
    }
}

/// <summary>
/// Raw, collector-supplied Attachment Manager / Mark-of-the-Web policy state.
/// Populated by the audit module's I/O layer and handed to
/// <see cref="AttachmentManagerAnalyzer"/> for a pure decision. Null numeric
/// fields mean "value absent / not readable"; the analyzer treats absence as the
/// OS default for each value.
/// </summary>
public sealed record AttachmentManagerState
{
    /// <summary>Attachments\SaveZoneInformation (DWORD). 1 = strip MoTW; 2/absent = preserve.</summary>
    public int? SaveZoneInformation { get; init; }

    /// <summary>Attachments\HideZoneInfoOnProperties (DWORD). 1 = hide the Unblock/zone control.</summary>
    public int? HideZoneInfoOnProperties { get; init; }

    /// <summary>Attachments\ScanWithAntiVirus (DWORD). 1 = off, 2 = optional (default), 3 = always.</summary>
    public int? ScanWithAntiVirus { get; init; }

    /// <summary>Associations\DefaultFileTypeRisk (DWORD). 0x1808 High, 0x1807 Moderate, 0x1806 Low. Null = OS default (High).</summary>
    public int? DefaultFileTypeRisk { get; init; }

    /// <summary>Associations\LowRiskFileTypes raw REG_SZ (a delimited extension allow-list), if present.</summary>
    public string? LowRiskFileTypes { get; init; }
}
