using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Pure, I/O-free logic for the <see cref="BrowserAudit"/> module.
///
/// All browser-security decisions live here - the rules that turn collected raw
/// state (registry policy values, installed versions, parsed extension manifests,
/// saved-password DB sizes) into <see cref="Finding"/> objects: browser version
/// freshness, dangerous / over-permissioned extension classification, auto-update
/// policy, Safe Browsing / SmartScreen policy, saved-password exposure, popup
/// blocker, Do-Not-Track / tracking prevention, and hardening policies (site
/// isolation, download restrictions, JavaScript, external password manager).
///
/// Nothing here touches the registry, the filesystem, WMI, the clock or the console,
/// so the security-relevant thresholds can be unit tested directly with synthetic
/// state. <see cref="BrowserAudit"/> owns only the collection of raw data and
/// delegates every decision to this class.
///
/// Mirrors the established <see cref="EncryptionAnalyzer"/> /
/// <see cref="IdentityCredentialAnalyzer"/> / <see cref="EventLogAnalyzer"/> pattern.
/// </summary>
public static class BrowserSecurityAnalyzer
{
    /// <summary>Category label shared with <see cref="BrowserAudit"/>.</summary>
    public const string Category = "Browser";

    // Known latest stable baselines - any installed version older than these is flagged.
    // Kept here (not in the audit) so version-comparison logic is unit testable.
    public static readonly Version LatestChromeVersion = new(133, 0, 6943, 0);
    public static readonly Version LatestEdgeVersion = new(133, 0, 3065, 0);
    public static readonly Version LatestFirefoxVersion = new(135, 0, 0, 0);

    /// <summary>
    /// A Chrome "Login Data" SQLite DB this size (bytes) or larger is assumed to
    /// contain saved credentials. An empty DB is ~40 KB.
    /// </summary>
    public const long SavedPasswordSizeThreshold = 45000;

    /// <summary>Known dangerous / malicious Chrome extension IDs (Web Store takedowns, advisories).</summary>
    public static readonly IReadOnlySet<string> DangerousExtensionIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "bopakagnckmlgajfccecajhmlejigiag", // Hola VPN (known to sell bandwidth)
        "gcknhkkoolaabfmlnjonogaaifnjlfnp", // FVD Video Downloader (data harvesting)
        "lmjegmlicamnimmfhcmpkclmigmmcbeh", // Web of Trust (sold browsing data)
        "bhmmomiinigofkjcejlfkalodjnkpfgm", // SearchEncrypt (browser hijacker)
        "pbpohikckhbcljgombipcdoinclbkggm", // PDF Viewer (fake malware loader)
        "oocalimimngaihdkbihfgmpkcpnmlaoa", // Telemetry extension
    };

    /// <summary>Permissions considered excessive / dangerous for a Chrome extension.</summary>
    public static readonly IReadOnlySet<string> DangerousPermissions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "debugger",
        "proxy",
        "nativeMessaging",
        "webRequestBlocking",       // can intercept & modify all traffic
        "clipboardRead",
        "cookies",
        "management",               // can manage other extensions
        "<all_urls>",               // access to every website
        "http://*/*",
        "https://*/*",
    };

    // ---------------------------------------------------------------------
    // State DTOs (filled by BrowserAudit from Windows; never reference Win32 here)
    // ---------------------------------------------------------------------

    public enum BrowserKind { Chrome, Edge, Firefox }

    /// <summary>Installation / version state for a single browser.</summary>
    public sealed class BrowserVersionState
    {
        public BrowserKind Kind { get; set; }
        /// <summary>True if the browser binary exists on disk (even if version unknown).</summary>
        public bool Installed { get; set; }
        /// <summary>Raw version string as read from the registry, e.g. "133.0.6943.98" or "135.0 (x64 en-US)".</summary>
        public string? RawVersion { get; set; }
    }

    /// <summary>One installed extension, already parsed from its manifest.</summary>
    public sealed class ExtensionState
    {
        public string Id { get; set; } = string.Empty;
        public string? Name { get; set; }
        /// <summary>Union of permissions / host_permissions / optional_permissions from the manifest.</summary>
        public IReadOnlyList<string> Permissions { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// Browser policy + state collected from the machine. Nullable ints carry the raw
    /// policy value (null = policy not set) so the analyzer owns the threshold rules.
    /// </summary>
    public sealed class BrowserPolicyState
    {
        // Auto-update (0 = disabled via policy)
        public int? ChromeUpdateDefault { get; set; }
        public int? ChromePerAppUpdate { get; set; }
        public int? EdgeUpdateDefault { get; set; }

        // Safe Browsing / SmartScreen
        public int? ChromeSafeBrowsingProtectionLevel { get; set; } // 0 off, 1 standard, 2 enhanced
        public int? ChromeSafeBrowsingEnabledLegacy { get; set; }   // 0 off
        public int? EdgeSmartScreenEnabled { get; set; }            // 0 off
        public string? WindowsSmartScreen { get; set; }             // "Off"/"Warn"/...

        // Popup blocker (1 = allow all popups = bad)
        public int? ChromeDefaultPopupsSetting { get; set; }
        public int? EdgeDefaultPopupsSetting { get; set; }

        // DNT / tracking prevention
        public int? EdgeConfigureDoNotTrack { get; set; }           // 1 = DNT header on
        public int? EdgeTrackingPrevention { get; set; }            // 0 off,1 basic,2 balanced,3 strict

        // Hardening policies
        public int? ChromeDefaultJavaScriptSetting { get; set; }    // 2 = block
        public int? ChromePasswordManagerEnabled { get; set; }      // 0 = disabled (good w/ external mgr)
        public int? EdgePasswordManagerEnabled { get; set; }        // 0 = disabled
        public int? ChromeSitePerProcess { get; set; }              // 1 = site isolation enforced
        public int? ChromeDownloadRestrictions { get; set; }        // >=1 = restrictions active
    }

    /// <summary>Saved-password DB presence/size for Chrome and Edge.</summary>
    public sealed class SavedPasswordState
    {
        public long ChromeLoginDataBytes { get; set; }   // 0 = no file
        public long EdgeLoginDataBytes { get; set; }     // 0 = no file
    }

    // ---------------------------------------------------------------------
    // Version freshness
    // ---------------------------------------------------------------------

    /// <summary>
    /// Normalize a version string for parsing - ensures at least major.minor.build.revision.
    /// </summary>
    public static string NormalizeVersion(string version)
    {
        var parts = version.Split('.');
        return parts.Length switch
        {
            1 => $"{parts[0]}.0.0.0",
            2 => $"{parts[0]}.{parts[1]}.0.0",
            3 => $"{parts[0]}.{parts[1]}.{parts[2]}.0",
            _ => version
        };
    }

    private static (string display, string product, Version latest, string updateHint, string fixCmd) Meta(BrowserKind kind) => kind switch
    {
        BrowserKind.Chrome => ("Chrome", "Google Chrome", LatestChromeVersion,
            "Update Chrome to the latest version: chrome://settings/help or reinstall.",
            "Start-Process 'chrome://settings/help'"),
        BrowserKind.Edge => ("Edge", "Microsoft Edge", LatestEdgeVersion,
            "Update Edge to the latest version: edge://settings/help.",
            "Start-Process 'edge://settings/help'"),
        _ => ("Firefox", "Mozilla Firefox", LatestFirefoxVersion,
            "Update Firefox: Help > About Firefox, or download from mozilla.org.",
            "Start-Process 'https://www.mozilla.org/firefox/new/'"),
    };

    /// <summary>
    /// Build the installation/version finding for one browser. Edge always emits something
    /// (it ships with Windows); Chrome/Firefox emit a "Not Installed" Info when absent.
    /// </summary>
    public static Finding BuildVersionFinding(BrowserVersionState state)
    {
        var (display, product, latest, updateHint, fixCmd) = Meta(state.Kind);

        // No version string available.
        if (string.IsNullOrWhiteSpace(state.RawVersion))
        {
            if (state.Kind == BrowserKind.Edge)
            {
                return Finding.Info(
                    "Edge Version Unknown",
                    "Microsoft Edge version could not be determined. Edge may not be the Chromium-based version.",
                    Category);
            }

            if (state.Installed)
            {
                return Finding.Info(
                    $"{display} Installed (Version Unknown)",
                    $"{product} is installed but the version could not be determined.",
                    Category);
            }

            return Finding.Info(
                $"{display} Not Installed",
                $"{product} is not installed on this system.",
                Category);
        }

        // Firefox version strings can look like "135.0 (x64 en-US)" - take the first token.
        var versionStr = state.Kind == BrowserKind.Firefox
            ? state.RawVersion.Split(' ')[0].Trim()
            : state.RawVersion.Trim();

        if (Version.TryParse(NormalizeVersion(versionStr), out var parsed))
        {
            if (parsed < latest)
            {
                var latestText = state.Kind == BrowserKind.Firefox ? latest.ToString(3) : latest.ToString();
                return Finding.Warning(
                    $"{display} Outdated",
                    $"{product} version {versionStr} is installed. The latest known version is {latestText}. " +
                    "Outdated browsers may have unpatched security vulnerabilities.",
                    Category,
                    updateHint,
                    fixCmd);
            }

            return Finding.Pass(
                $"{display} Up to Date",
                $"{product} version {versionStr} is installed and appears to be current.",
                Category);
        }

        return Finding.Info(
            $"{display} Installed",
            $"{product} version {state.RawVersion} is installed (could not parse version for comparison).",
            Category);
    }

    // ---------------------------------------------------------------------
    // Extensions
    // ---------------------------------------------------------------------

    /// <summary>Returns the dangerous permissions present on a single extension.</summary>
    public static List<string> FindExcessivePermissions(ExtensionState ext)
    {
        var found = new List<string>();
        foreach (var perm in ext.Permissions)
        {
            if (perm != null && DangerousPermissions.Contains(perm))
                found.Add(perm);
        }
        return found;
    }

    /// <summary>True if the extension id is on the known-dangerous list.</summary>
    public static bool IsDangerousExtension(ExtensionState ext) =>
        !string.IsNullOrEmpty(ext.Id) && DangerousExtensionIds.Contains(ext.Id);

    /// <summary>
    /// Classify a profile's extensions into zero or more findings (dangerous extensions,
    /// excessive permissions, and an "all OK" pass when at least one extension exists and
    /// nothing was flagged). An empty list yields no findings.
    /// </summary>
    public static List<Finding> AnalyzeExtensions(IReadOnlyList<ExtensionState> extensions)
    {
        var findings = new List<Finding>();
        if (extensions == null || extensions.Count == 0)
            return findings;

        var dangerous = new List<string>();
        var excessive = new List<string>();

        foreach (var ext in extensions)
        {
            var label = string.IsNullOrEmpty(ext.Name) ? ext.Id : ext.Name;
            if (IsDangerousExtension(ext))
            {
                dangerous.Add($"\u26A0\uFE0F {label} ({ext.Id}) \u2014 known dangerous extension");
                continue;
            }

            var perms = FindExcessivePermissions(ext);
            if (perms.Count > 0)
            {
                excessive.Add($"\uD83D\uDD11 {label} ({ext.Id}) \u2014 excessive permissions: {string.Join(", ", perms)}");
            }
        }

        if (dangerous.Count > 0)
        {
            findings.Add(Finding.Critical(
                "Dangerous Chrome Extensions Detected",
                $"{dangerous.Count} known-dangerous Chrome extension(s) found:\n" + string.Join("\n", dangerous),
                Category,
                "Remove dangerous extensions from chrome://extensions immediately.",
                "Start-Process 'chrome://extensions'"));
        }

        if (excessive.Count > 0)
        {
            findings.Add(Finding.Warning(
                "Chrome Extensions with Excessive Permissions",
                $"{excessive.Count} Chrome extension(s) have potentially dangerous permissions:\n" + string.Join("\n", excessive),
                Category,
                "Review extensions and their permissions at chrome://extensions. Remove any you don't actively use.",
                "Start-Process 'chrome://extensions'"));
        }

        if (dangerous.Count == 0 && excessive.Count == 0)
        {
            findings.Add(Finding.Pass(
                "Chrome Extensions OK",
                $"{extensions.Count} Chrome extension(s) installed. None flagged as dangerous or having excessive permissions.",
                Category));
        }

        return findings;
    }

    // ---------------------------------------------------------------------
    // Auto-update
    // ---------------------------------------------------------------------

    public static bool IsChromeUpdateDisabled(BrowserPolicyState p) =>
        p.ChromeUpdateDefault == 0 || p.ChromePerAppUpdate == 0;

    public static bool IsEdgeUpdateDisabled(BrowserPolicyState p) => p.EdgeUpdateDefault == 0;

    /// <summary>Auto-update findings (one per disabled browser, plus a pass when both are fine).</summary>
    public static List<Finding> AnalyzeAutoUpdate(BrowserPolicyState p)
    {
        var findings = new List<Finding>();
        var chromeDisabled = IsChromeUpdateDisabled(p);
        var edgeDisabled = IsEdgeUpdateDisabled(p);

        if (chromeDisabled)
        {
            findings.Add(Finding.Critical(
                "Chrome Auto-Update Disabled",
                "Google Chrome auto-update is disabled via policy. The browser will not receive security patches automatically.",
                Category,
                "Enable Chrome auto-update by removing the update policy.",
                @"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Update' -Name 'UpdateDefault' -ErrorAction SilentlyContinue"));
        }

        if (edgeDisabled)
        {
            findings.Add(Finding.Critical(
                "Edge Auto-Update Disabled",
                "Microsoft Edge auto-update is disabled via policy. The browser will not receive security patches automatically.",
                Category,
                "Enable Edge auto-update by removing the update policy.",
                @"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name 'UpdateDefault' -ErrorAction SilentlyContinue"));
        }

        if (!chromeDisabled && !edgeDisabled)
        {
            findings.Add(Finding.Pass(
                "Browser Auto-Update Enabled",
                "No policies are disabling browser auto-updates. Browsers should update automatically.",
                Category));
        }

        return findings;
    }

    // ---------------------------------------------------------------------
    // Safe Browsing / SmartScreen
    // ---------------------------------------------------------------------

    public static bool IsChromeSafeBrowsingDisabled(BrowserPolicyState p) =>
        p.ChromeSafeBrowsingProtectionLevel == 0 || p.ChromeSafeBrowsingEnabledLegacy == 0;

    public static bool IsEdgeSmartScreenDisabled(BrowserPolicyState p) => p.EdgeSmartScreenEnabled == 0;

    public static bool IsWindowsSmartScreenDisabled(BrowserPolicyState p) =>
        string.Equals(p.WindowsSmartScreen, "Off", StringComparison.OrdinalIgnoreCase);

    /// <summary>Safe Browsing / SmartScreen findings.</summary>
    public static List<Finding> AnalyzeSafeBrowsing(BrowserPolicyState p)
    {
        var findings = new List<Finding>();
        var chrome = IsChromeSafeBrowsingDisabled(p);
        var edge = IsEdgeSmartScreenDisabled(p);
        var windows = IsWindowsSmartScreenDisabled(p);

        if (chrome)
        {
            findings.Add(Finding.Critical(
                "Chrome Safe Browsing Disabled",
                "Chrome Safe Browsing is disabled via policy. Phishing and malware protection is inactive.",
                Category,
                "Enable Chrome Safe Browsing via policy or in chrome://settings/security.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'SafeBrowsingProtectionLevel' -Value 1"));
        }

        if (edge)
        {
            findings.Add(Finding.Critical(
                "Edge SmartScreen Disabled",
                "Microsoft Edge SmartScreen is disabled via policy. Phishing and malware download protection is inactive.",
                Category,
                "Enable Edge SmartScreen via policy or in edge://settings/privacy.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenEnabled' -Value 1"));
        }

        if (windows)
        {
            findings.Add(Finding.Warning(
                "Windows SmartScreen Disabled",
                "Windows SmartScreen is disabled. Downloaded files and apps will not be scanned for threats.",
                Category,
                "Enable SmartScreen in Windows Security > App & browser control.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Warn'"));
        }

        if (!chrome && !edge && !windows)
        {
            findings.Add(Finding.Pass(
                "Safe Browsing / SmartScreen Enabled",
                "No policies are disabling browser phishing and malware protection. Safe Browsing and SmartScreen should be active.",
                Category));
        }

        return findings;
    }

    // ---------------------------------------------------------------------
    // Saved passwords
    // ---------------------------------------------------------------------

    public static bool HasChromeSavedPasswords(SavedPasswordState s) => s.ChromeLoginDataBytes > SavedPasswordSizeThreshold;
    public static bool HasEdgeSavedPasswords(SavedPasswordState s) => s.EdgeLoginDataBytes > SavedPasswordSizeThreshold;

    /// <summary>Saved-password finding (warning when present in any browser, else pass).</summary>
    public static Finding BuildSavedPasswordFinding(SavedPasswordState s)
    {
        var chrome = HasChromeSavedPasswords(s);
        var edge = HasEdgeSavedPasswords(s);

        if (chrome || edge)
        {
            var browsers = new List<string>();
            if (chrome) browsers.Add("Chrome");
            if (edge) browsers.Add("Edge");

            return Finding.Warning(
                "Saved Passwords in Browser",
                $"Passwords appear to be saved in {string.Join(" and ", browsers)}. " +
                "Browser-saved passwords are vulnerable to local attacks, malware, and data breaches. " +
                "Anyone with access to your Windows account can view them.",
                Category,
                "Use a dedicated password manager (Bitwarden, 1Password, KeePassXC) instead of saving passwords in browsers. " +
                "Export your saved passwords first, then disable the built-in password manager.",
                "Start-Process 'chrome://settings/passwords'");
        }

        return Finding.Pass(
            "No Browser Saved Passwords Detected",
            "No significant saved password data was detected in Chrome or Edge.",
            Category);
    }

    // ---------------------------------------------------------------------
    // Popup blocker
    // ---------------------------------------------------------------------

    public static bool IsChromePopupsAllowed(BrowserPolicyState p) => p.ChromeDefaultPopupsSetting == 1;
    public static bool IsEdgePopupsAllowed(BrowserPolicyState p) => p.EdgeDefaultPopupsSetting == 1;

    /// <summary>Popup-blocker findings (warning per browser allowing all popups, else pass).</summary>
    public static List<Finding> AnalyzePopupBlocker(BrowserPolicyState p)
    {
        var findings = new List<Finding>();
        var chrome = IsChromePopupsAllowed(p);
        var edge = IsEdgePopupsAllowed(p);

        if (chrome)
        {
            findings.Add(Finding.Warning(
                "Chrome Popup Blocker Disabled",
                "Chrome's popup blocker is disabled via policy. Popups can be used for phishing and malware delivery.",
                Category,
                "Enable the popup blocker in Chrome policies.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'DefaultPopupsSetting' -Value 2"));
        }

        if (edge)
        {
            findings.Add(Finding.Warning(
                "Edge Popup Blocker Disabled",
                "Edge's popup blocker is disabled via policy. Popups can be used for phishing and malware delivery.",
                Category,
                "Enable the popup blocker in Edge policies.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'DefaultPopupsSetting' -Value 2"));
        }

        if (!chrome && !edge)
        {
            findings.Add(Finding.Pass(
                "Popup Blockers Active",
                "No policies are disabling popup blockers. Browsers should block unwanted popups by default.",
                Category));
        }

        return findings;
    }

    // ---------------------------------------------------------------------
    // Do Not Track / tracking prevention
    // ---------------------------------------------------------------------

    public static bool IsEdgeDntEnabled(BrowserPolicyState p) => p.EdgeConfigureDoNotTrack == 1;

    /// <summary>Edge tracking prevention is "meaningful" at Balanced (2) or Strict (3).</summary>
    public static bool IsEdgeTrackingPreventionEnabled(BrowserPolicyState p) =>
        p.EdgeTrackingPrevention is int v && v >= 2;

    /// <summary>Do-Not-Track / tracking-prevention finding (info when nothing enforced, else pass).</summary>
    public static Finding BuildTrackingProtectionFinding(BrowserPolicyState p)
    {
        var dnt = IsEdgeDntEnabled(p);
        var tracking = IsEdgeTrackingPreventionEnabled(p);

        if (!dnt && !tracking)
        {
            return Finding.Info(
                "Do Not Track / Tracking Prevention",
                "Do Not Track and enhanced tracking prevention are not enforced via policy. " +
                "Consider enabling tracking prevention in your browser settings for better privacy.",
                Category,
                "Enable tracking prevention in Edge: Settings > Privacy > Tracking prevention (Balanced or Strict). " +
                "In Chrome: Settings > Privacy > Send Do Not Track request.");
        }

        var details = new List<string>();
        if (dnt) details.Add("Do Not Track header");
        if (tracking) details.Add("Edge Tracking Prevention");
        return Finding.Pass(
            "Tracking Protection Enabled",
            $"Browser tracking protection is enabled via policy: {string.Join(", ", details)}.",
            Category);
    }

    // ---------------------------------------------------------------------
    // Hardening policies (each emits a finding only when the good/bad signal is present)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Findings for optional hardening policies: JS blocked, external password manager,
    /// site isolation, download restrictions. Order matches the legacy audit.
    /// </summary>
    public static List<Finding> AnalyzeSecurityPolicies(BrowserPolicyState p)
    {
        var findings = new List<Finding>();

        if (p.ChromeDefaultJavaScriptSetting == 2)
        {
            findings.Add(Finding.Info(
                "Chrome JavaScript Blocked by Policy",
                "JavaScript is blocked by policy in Chrome. This improves security but may break many websites.",
                Category));
        }

        if (p.ChromePasswordManagerEnabled == 0)
        {
            findings.Add(Finding.Pass(
                "Chrome Password Manager Disabled by Policy",
                "Chrome's built-in password manager is disabled via policy. This is good if you use a dedicated password manager.",
                Category));
        }

        if (p.EdgePasswordManagerEnabled == 0)
        {
            findings.Add(Finding.Pass(
                "Edge Password Manager Disabled by Policy",
                "Edge's built-in password manager is disabled via policy. This is good if you use a dedicated password manager.",
                Category));
        }

        if (p.ChromeSitePerProcess == 1)
        {
            findings.Add(Finding.Pass(
                "Chrome Site Isolation Enforced",
                "Site isolation (one process per site) is enforced via policy in Chrome, providing stronger protection against Spectre-type attacks.",
                Category));
        }

        if (p.ChromeDownloadRestrictions is int dr && dr >= 1)
        {
            findings.Add(Finding.Pass(
                "Chrome Download Restrictions Active",
                $"Chrome download restrictions are set (level {dr}), blocking dangerous downloads.",
                Category));
        }

        return findings;
    }
}
