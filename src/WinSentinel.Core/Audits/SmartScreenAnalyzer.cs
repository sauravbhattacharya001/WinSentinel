using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for Windows SmartScreen reputation checking on a single
/// machine. SmartScreen is the built-in cloud-backed reputation service that warns
/// on (or blocks) low-reputation executables and websites. It has three distinct
/// enforcement surfaces, each with its own registry knob:
///
///   * <b>App &amp; File SmartScreen (Explorer/shell)</b> -
///     HKLM\...\Policies\Microsoft\Windows\System\EnableSmartScreen (+ the
///     ShellSmartScreenLevel string). This is what warns when you run a downloaded
///     .exe carrying a Mark-of-the-Web. "Block" is the hardened state, "Warn"
///     prompts, and disabled removes the check entirely - the single biggest gap,
///     because it is the check that catches commodity malware droppers.
///   * <b>Microsoft Edge SmartScreen</b> - ...\Policies\Microsoft\Edge\SmartScreenEnabled
///     (+ SmartScreenPuaEnabled for potentially-unwanted apps). Guards phishing/
///     malicious-download warnings in the default browser.
///   * <b>Store-app / MSIX install SmartScreen</b> - the per-user
///     ...\AppHost\EnableWebContentEvaluation value used by the App Installer and
///     Store to reputation-check web content.
///
/// Everything here is single-machine and therefore FREE / OSS: it reads local
/// registry policy state only. Nothing multi-machine, nothing license-gated. All
/// rules operate on a synthetic <see cref="SmartScreenState"/> so they can be unit
/// tested directly, mirroring the established <see cref="WindowsScriptHostAnalyzer"/>
/// / <see cref="LsaHardeningAnalyzer"/> pattern (collector owns I/O, analyzer owns
/// decisions).
/// </summary>
public static class SmartScreenAnalyzer
{
    /// <summary>Category label for every finding this analyzer emits.</summary>
    public const string Category = "SmartScreen";

    /// <summary>
    /// Evaluate the collected SmartScreen state and return one finding per check
    /// (a Pass when the setting is already safe, otherwise Info/Warning). Ordering
    /// is stable and deterministic for diffable reports.
    /// </summary>
    public static IReadOnlyList<Finding> Analyze(SmartScreenState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return new List<Finding>
        {
            AnalyzeShellSmartScreen(state),
            AnalyzeEdgeSmartScreen(state),
            AnalyzeEdgePua(state),
            AnalyzeStoreAppReputation(state),
        };
    }

    /// <summary>
    /// App &amp; File (Explorer/shell) SmartScreen. EnableSmartScreen=1 turns the
    /// check on; ShellSmartScreenLevel selects "Block" (hardened) vs "Warn" (prompt).
    /// EnableSmartScreen=0 disables the check that catches downloaded-executable
    /// droppers entirely - the highest-value finding here.
    /// </summary>
    public static Finding AnalyzeShellSmartScreen(SmartScreenState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        // Explicit disable is the worst case.
        if (state.EnableSmartScreen == 0)
        {
            return Finding.Warning(
                "App & File SmartScreen is disabled",
                "The EnableSmartScreen policy value is 0, so Windows does not reputation-check " +
                "executables and files carrying a Mark-of-the-Web when they are run. This removes " +
                "the built-in warning/block that catches commodity malware and downloaded droppers.",
                Category,
                remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableSmartScreen = 1 (DWORD) " +
                             "and ShellSmartScreenLevel = Block to enforce reputation checking of downloaded files.",
                fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Force | Out-Null; " +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name EnableSmartScreen -Type DWord -Value 1; " +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name ShellSmartScreenLevel -Type String -Value Block");
        }

        // Enabled (explicit 1, or absent => Windows default is on for supported SKUs).
        var level = state.ShellSmartScreenLevel?.Trim();
        if (string.Equals(level, "Block", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Pass(
                "App & File SmartScreen blocks low-reputation files",
                "App & File SmartScreen is enabled and set to Block (ShellSmartScreenLevel=Block), so " +
                "unrecognized/low-reputation downloaded executables are blocked rather than merely warned on.",
                Category);
        }

        if (string.Equals(level, "Warn", StringComparison.OrdinalIgnoreCase))
        {
            return Finding.Info(
                "App & File SmartScreen warns but does not block",
                "App & File SmartScreen is enabled but set to Warn (ShellSmartScreenLevel=Warn), so a user " +
                "can click through the reputation warning and run an unrecognized executable anyway. Block " +
                "is the stronger setting.",
                Category,
                remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\ShellSmartScreenLevel = Block " +
                             "(REG_SZ) so low-reputation files are blocked, not just warned on.",
                fixCommand: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name ShellSmartScreenLevel -Type String -Value Block");
        }

        // Enabled but no explicit level policy: on by default, level not pinned by policy.
        return Finding.Info(
            "App & File SmartScreen is on but the block level is not pinned by policy",
            "App & File SmartScreen is enabled (EnableSmartScreen is 1 or absent, the default), but no " +
            "ShellSmartScreenLevel policy pins it to Block. The effective behaviour depends on user/OS " +
            "defaults; pinning Block by policy guarantees low-reputation files are blocked.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableSmartScreen = 1 (DWORD) and " +
                         "ShellSmartScreenLevel = Block (REG_SZ) to enforce blocking of low-reputation files.",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name EnableSmartScreen -Type DWord -Value 1; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name ShellSmartScreenLevel -Type String -Value Block");
    }

    /// <summary>Microsoft Edge SmartScreen: SmartScreenEnabled should be 1.</summary>
    public static Finding AnalyzeEdgeSmartScreen(SmartScreenState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.EdgeSmartScreenEnabled == 0)
        {
            return Finding.Warning(
                "Microsoft Edge SmartScreen is disabled",
                "The Edge SmartScreenEnabled policy value is 0, so Microsoft Edge does not warn on phishing " +
                "sites or malicious downloads. This is a primary browser-borne malware and credential-theft surface.",
                Category,
                remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\SmartScreenEnabled = 1 (DWORD) to " +
                             "re-enable Edge SmartScreen phishing/malware protection.",
                fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Force | Out-Null; " +
                            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name SmartScreenEnabled -Type DWord -Value 1");
        }

        return Finding.Pass(
            "Microsoft Edge SmartScreen is enabled",
            "Edge SmartScreen is enabled (SmartScreenEnabled is 1 or absent, the default), so Edge warns on " +
            "phishing sites and reputation-checks downloads.",
            Category);
    }

    /// <summary>Edge PUA protection: SmartScreenPuaEnabled blocks potentially-unwanted apps.</summary>
    public static Finding AnalyzeEdgePua(SmartScreenState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.EdgeSmartScreenPuaEnabled == 1)
        {
            return Finding.Pass(
                "Microsoft Edge blocks potentially-unwanted apps",
                "Edge SmartScreen PUA protection is enabled (SmartScreenPuaEnabled=1), so Edge blocks " +
                "potentially-unwanted apps such as bundleware, cryptominers, and adware installers.",
                Category);
        }

        return Finding.Info(
            "Microsoft Edge PUA blocking is not enabled",
            "Edge SmartScreen PUA (potentially-unwanted app) blocking is not enabled (SmartScreenPuaEnabled " +
            "is 0 or absent), so bundleware, adware installers, and cryptominers are not proactively blocked " +
            "by the browser.",
            Category,
            remediation: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\SmartScreenPuaEnabled = 1 (DWORD) to block " +
                         "potentially-unwanted apps in Edge.",
            fixCommand: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Force | Out-Null; " +
                        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name SmartScreenPuaEnabled -Type DWord -Value 1");
    }

    /// <summary>
    /// Store / App Installer web-content reputation. EnableWebContentEvaluation=0
    /// turns off SmartScreen reputation checks for content evaluated by the App
    /// Installer / Store path (e.g. MSIX web installs).
    /// </summary>
    public static Finding AnalyzeStoreAppReputation(SmartScreenState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.EnableWebContentEvaluation == 0)
        {
            return Finding.Info(
                "SmartScreen check for Store/app web content is disabled",
                "EnableWebContentEvaluation is 0, so SmartScreen does not reputation-check web content " +
                "evaluated through the App Installer / Store path (for example MSIX packages installed " +
                "from the web). Re-enabling restores that reputation check.",
                Category,
                remediation: "Set HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\\" +
                             "EnableWebContentEvaluation = 1 (DWORD) to re-enable SmartScreen for app/Store web content.",
                fixCommand: "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost' -Name EnableWebContentEvaluation -Type DWord -Value 1");
        }

        return Finding.Pass(
            "SmartScreen evaluates Store/app web content",
            "EnableWebContentEvaluation is 1 or absent (the default), so SmartScreen reputation-checks web " +
            "content evaluated through the App Installer / Store path.",
            Category);
    }
}

/// <summary>
/// Raw, collector-supplied SmartScreen state. Populated by the audit module's I/O
/// layer and handed to <see cref="SmartScreenAnalyzer"/> for a pure decision. Null
/// integer fields mean "value absent / not readable" and a null string means the
/// level is not pinned by policy; the analyzer treats absence as the Windows
/// default (SmartScreen on but the block level not policy-pinned) so a missing key
/// is never silently reported as fully hardened.
/// </summary>
public sealed record SmartScreenState
{
    /// <summary>Policies\Microsoft\Windows\System\EnableSmartScreen (DWORD). 0 = App/File SmartScreen off; 1/absent = on.</summary>
    public int? EnableSmartScreen { get; init; }

    /// <summary>Policies\Microsoft\Windows\System\ShellSmartScreenLevel (REG_SZ). "Block" = hardened; "Warn" = prompt; absent = not pinned.</summary>
    public string? ShellSmartScreenLevel { get; init; }

    /// <summary>Policies\Microsoft\Edge\SmartScreenEnabled (DWORD). 0 = Edge SmartScreen off; 1/absent = on.</summary>
    public int? EdgeSmartScreenEnabled { get; init; }

    /// <summary>Policies\Microsoft\Edge\SmartScreenPuaEnabled (DWORD). 1 = block PUAs; 0/absent = not blocking.</summary>
    public int? EdgeSmartScreenPuaEnabled { get; init; }

    /// <summary>AppHost\EnableWebContentEvaluation (DWORD). 0 = Store/app web-content SmartScreen off; 1/absent = on.</summary>
    public int? EnableWebContentEvaluation { get; init; }
}
