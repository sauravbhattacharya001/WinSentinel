using System.Text.Json;
using Microsoft.Win32;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits browser security: Chrome, Edge, and Firefox installation status, versions,
/// extension safety, saved passwords, auto-update, Safe Browsing / SmartScreen,
/// Do Not Track, popup blocker, and general security settings.
/// </summary>
public class BrowserAudit : IAuditModule
{
    public string Name => "Browser Audit";
    public string Category => "Browser";
    public string Description =>
        "Checks installed browsers (Chrome, Edge, Firefox), versions, extensions, " +
        "saved passwords, auto-update, Safe Browsing, SmartScreen, and security settings.";

    // Known latest stable versions — update periodically.
    // These are approximate baselines; any version older than these is flagged.
    private static readonly Version LatestChromeVersion = new(133, 0, 6943, 0);
    private static readonly Version LatestEdgeVersion = new(133, 0, 3065, 0);
    private static readonly Version LatestFirefoxVersion = new(135, 0, 0, 0);

    // Known dangerous / malicious Chrome extension IDs.
    // Sources: Chrome Web Store takedowns, security advisories.
    private static readonly HashSet<string> DangerousExtensionIds = new(StringComparer.OrdinalIgnoreCase)
    {
        // Adware / spyware extensions that were removed from the Chrome Web Store
        "gighmmpiobklfepjocnamgkkbiglidom", // example dangerous ext placeholder — AdBlock Plus copycat
        "bopakagnckmlgajfccecajhmlejigiag", // Hola VPN (known to sell bandwidth)
        "gcknhkkoolaabfmlnjonogaaifnjlfnp", // FVD Video Downloader (data harvesting)
        "lmjegmlicamnimmfhcmpkclmigmmcbeh", // Web of Trust (sold browsing data)
        "bhmmomiinigofkjcejlfkalodjnkpfgm", // SearchEncrypt (browser hijacker)
        "pbpohikckhbcljgombipcdoinclbkggm", // PDF Viewer (fake malware loader)
        "oocalimimngaihdkbihfgmpkcpnmlaoa", // Telemetry extension
        "efaidnbmnnnibpcajpcglclefindmkaj", // Adobe Acrobat extension (excessive permissions)
    };

    // Permissions considered excessive or dangerous for Chrome extensions.
    private static readonly HashSet<string> DangerousPermissions = new(StringComparer.OrdinalIgnoreCase)
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

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            CheckChromeInstallation(result);
            CheckEdgeInstallation(result);
            CheckFirefoxInstallation(result);
            CheckChromeExtensions(result);
            CheckBrowserAutoUpdate(result);
            CheckSafeBrowsingSmartScreen(result);
            CheckSavedPasswords(result);
            CheckPopupBlocker(result);
            CheckDoNotTrack(result);
            CheckBrowserSecurityPolicies(result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return await Task.FromResult(result);
    }

    #region Browser Installation & Version Checks

    private void CheckChromeInstallation(AuditResult result)
    {
        var version = GetBrowserVersion(
            @"SOFTWARE\Google\Chrome\BLBeacon", "version",
            @"SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon", "version");

        if (version == null)
        {
            // Try file-based detection
            var chromePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Google", "Chrome", "Application", "chrome.exe");
            var chromePathX86 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Google", "Chrome", "Application", "chrome.exe");

            if (File.Exists(chromePath) || File.Exists(chromePathX86))
            {
                result.Findings.Add(Finding.Info(
                    "Chrome Installed (Version Unknown)",
                    "Google Chrome is installed but the version could not be determined from the registry.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "Chrome Not Installed",
                    "Google Chrome is not installed on this system.",
                    Category));
            }
            return;
        }

        if (Version.TryParse(version, out var chromeVersion))
        {
            if (chromeVersion < LatestChromeVersion)
            {
                result.Findings.Add(Finding.Warning(
                    "Chrome Outdated",
                    $"Google Chrome version {version} is installed. The latest known version is {LatestChromeVersion}. " +
                    "Outdated browsers may have unpatched security vulnerabilities.",
                    Category,
                    "Update Chrome to the latest version: chrome://settings/help or reinstall.",
                    "Start-Process 'chrome://settings/help'"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Chrome Up to Date",
                    $"Google Chrome version {version} is installed and appears to be current.",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Chrome Installed",
                $"Google Chrome version {version} is installed (could not parse version for comparison).",
                Category));
        }
    }

    private void CheckEdgeInstallation(AuditResult result)
    {
        var version = GetBrowserVersion(
            @"SOFTWARE\Microsoft\Edge\BLBeacon", "version",
            @"SOFTWARE\WOW6432Node\Microsoft\Edge\BLBeacon", "version");

        // Edge is pre-installed on Windows 10/11
        if (version == null)
        {
            // Try HKCU
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Edge\BLBeacon");
                version = key?.GetValue("version")?.ToString();
            }
            catch { }
        }

        if (version == null)
        {
            result.Findings.Add(Finding.Info(
                "Edge Version Unknown",
                "Microsoft Edge version could not be determined. Edge may not be the Chromium-based version.",
                Category));
            return;
        }

        if (Version.TryParse(version, out var edgeVersion))
        {
            if (edgeVersion < LatestEdgeVersion)
            {
                result.Findings.Add(Finding.Warning(
                    "Edge Outdated",
                    $"Microsoft Edge version {version} is installed. The latest known version is {LatestEdgeVersion}. " +
                    "Outdated browsers may have unpatched security vulnerabilities.",
                    Category,
                    "Update Edge to the latest version: edge://settings/help.",
                    "Start-Process 'edge://settings/help'"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Edge Up to Date",
                    $"Microsoft Edge version {version} is installed and appears to be current.",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Edge Installed",
                $"Microsoft Edge version {version} is installed.",
                Category));
        }
    }

    private void CheckFirefoxInstallation(AuditResult result)
    {
        string? version = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Mozilla\Mozilla Firefox");
            version = key?.GetValue("CurrentVersion")?.ToString();
        }
        catch { }

        if (version == null)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox");
                version = key?.GetValue("CurrentVersion")?.ToString();
            }
            catch { }
        }

        if (version == null)
        {
            var firefoxPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Mozilla Firefox", "firefox.exe");
            var firefoxPathX86 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Mozilla Firefox", "firefox.exe");

            if (!File.Exists(firefoxPath) && !File.Exists(firefoxPathX86))
            {
                result.Findings.Add(Finding.Info(
                    "Firefox Not Installed",
                    "Mozilla Firefox is not installed on this system.",
                    Category));
                return;
            }

            result.Findings.Add(Finding.Info(
                "Firefox Installed (Version Unknown)",
                "Mozilla Firefox is installed but the version could not be determined.",
                Category));
            return;
        }

        // Firefox version string might be like "135.0 (x64 en-US)" — extract the version part
        var versionStr = version.Split(' ')[0].Trim();

        if (Version.TryParse(NormalizeVersion(versionStr), out var ffVersion))
        {
            if (ffVersion < LatestFirefoxVersion)
            {
                result.Findings.Add(Finding.Warning(
                    "Firefox Outdated",
                    $"Mozilla Firefox version {versionStr} is installed. The latest known version is {LatestFirefoxVersion.ToString(3)}. " +
                    "Outdated browsers may have unpatched security vulnerabilities.",
                    Category,
                    "Update Firefox: Help > About Firefox, or download from mozilla.org.",
                    "Start-Process 'https://www.mozilla.org/firefox/new/'"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Firefox Up to Date",
                    $"Mozilla Firefox version {versionStr} is installed and appears to be current.",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Firefox Installed",
                $"Mozilla Firefox version {version} is installed.",
                Category));
        }
    }

    #endregion

    #region Chrome Extensions

    private void CheckChromeExtensions(AuditResult result)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var extensionsDir = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions");

        if (!Directory.Exists(extensionsDir))
        {
            // No Chrome profile or no extensions
            return;
        }

        var extensionDirs = Directory.GetDirectories(extensionsDir);
        int dangerousCount = 0;
        int excessivePermCount = 0;
        var flaggedExtensions = new List<string>();

        foreach (var extDir in extensionDirs)
        {
            var extId = Path.GetFileName(extDir);
            if (string.IsNullOrEmpty(extId)) continue;

            // Check against known-dangerous list
            if (DangerousExtensionIds.Contains(extId))
            {
                dangerousCount++;
                var extName = GetExtensionName(extDir) ?? extId;
                flaggedExtensions.Add($"⚠️ {extName} ({extId}) — known dangerous extension");
                continue;
            }

            // Check permissions in manifest.json
            var excessivePerms = CheckExtensionPermissions(extDir);
            if (excessivePerms.Count > 0)
            {
                excessivePermCount++;
                var extName = GetExtensionName(extDir) ?? extId;
                flaggedExtensions.Add(
                    $"🔑 {extName} ({extId}) — excessive permissions: {string.Join(", ", excessivePerms)}");
            }
        }

        if (dangerousCount > 0)
        {
            result.Findings.Add(Finding.Critical(
                "Dangerous Chrome Extensions Detected",
                $"{dangerousCount} known-dangerous Chrome extension(s) found:\n" +
                string.Join("\n", flaggedExtensions.Where(f => f.StartsWith("⚠️"))),
                Category,
                "Remove dangerous extensions from chrome://extensions immediately.",
                "Start-Process 'chrome://extensions'"));
        }

        if (excessivePermCount > 0)
        {
            result.Findings.Add(Finding.Warning(
                "Chrome Extensions with Excessive Permissions",
                $"{excessivePermCount} Chrome extension(s) have potentially dangerous permissions:\n" +
                string.Join("\n", flaggedExtensions.Where(f => f.StartsWith("🔑"))),
                Category,
                "Review extensions and their permissions at chrome://extensions. Remove any you don't actively use.",
                "Start-Process 'chrome://extensions'"));
        }

        if (dangerousCount == 0 && excessivePermCount == 0 && extensionDirs.Length > 0)
        {
            result.Findings.Add(Finding.Pass(
                "Chrome Extensions OK",
                $"{extensionDirs.Length} Chrome extension(s) installed. None flagged as dangerous or having excessive permissions.",
                Category));
        }
    }

    private static string? GetExtensionName(string extensionDir)
    {
        try
        {
            // Extensions are in subdirectories named by version
            var versionDirs = Directory.GetDirectories(extensionDir);
            if (versionDirs.Length == 0) return null;

            // Pick latest version directory
            var latestDir = versionDirs.OrderByDescending(d => d).First();
            var manifestPath = Path.Combine(latestDir, "manifest.json");

            if (!File.Exists(manifestPath)) return null;

            var json = File.ReadAllText(manifestPath);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("name", out var nameEl))
            {
                var name = nameEl.GetString();
                // Skip __MSG_ localized names — they require locale lookup
                if (name != null && !name.StartsWith("__MSG_"))
                    return name;
            }
        }
        catch { }

        return null;
    }

    private static List<string> CheckExtensionPermissions(string extensionDir)
    {
        var found = new List<string>();
        try
        {
            var versionDirs = Directory.GetDirectories(extensionDir);
            if (versionDirs.Length == 0) return found;

            var latestDir = versionDirs.OrderByDescending(d => d).First();
            var manifestPath = Path.Combine(latestDir, "manifest.json");
            if (!File.Exists(manifestPath)) return found;

            var json = File.ReadAllText(manifestPath);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Check "permissions" array
            if (root.TryGetProperty("permissions", out var permsEl) && permsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in permsEl.EnumerateArray())
                {
                    var permStr = perm.GetString();
                    if (permStr != null && DangerousPermissions.Contains(permStr))
                        found.Add(permStr);
                }
            }

            // Check "host_permissions" (Manifest V3)
            if (root.TryGetProperty("host_permissions", out var hostPermsEl) && hostPermsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in hostPermsEl.EnumerateArray())
                {
                    var permStr = perm.GetString();
                    if (permStr != null && DangerousPermissions.Contains(permStr))
                        found.Add(permStr);
                }
            }

            // Check "optional_permissions"
            if (root.TryGetProperty("optional_permissions", out var optPermsEl) && optPermsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in optPermsEl.EnumerateArray())
                {
                    var permStr = perm.GetString();
                    if (permStr != null && DangerousPermissions.Contains(permStr))
                        found.Add("optional:" + permStr);
                }
            }
        }
        catch { }

        return found;
    }

    #endregion

    #region Auto-Update

    private void CheckBrowserAutoUpdate(AuditResult result)
    {
        // Chrome: Check if Google Update is disabled via policy
        var chromeUpdateDisabled = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Update");
            var updateDefault = key?.GetValue("UpdateDefault");
            if (updateDefault != null && Convert.ToInt32(updateDefault) == 0)
                chromeUpdateDisabled = true;

            // Also check per-app update policy for Chrome
            var chromeUpdate = key?.GetValue("Update{8A69D345-D564-463C-AFF1-A69D9E530F96}");
            if (chromeUpdate != null && Convert.ToInt32(chromeUpdate) == 0)
                chromeUpdateDisabled = true;
        }
        catch { }

        if (chromeUpdateDisabled)
        {
            result.Findings.Add(Finding.Critical(
                "Chrome Auto-Update Disabled",
                "Google Chrome auto-update is disabled via policy. The browser will not receive security patches automatically.",
                Category,
                "Enable Chrome auto-update by removing the update policy.",
                @"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Update' -Name 'UpdateDefault' -ErrorAction SilentlyContinue"));
        }

        // Edge: Check if update is disabled via policy
        var edgeUpdateDisabled = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\EdgeUpdate");
            var updateDefault = key?.GetValue("UpdateDefault");
            if (updateDefault != null && Convert.ToInt32(updateDefault) == 0)
                edgeUpdateDisabled = true;
        }
        catch { }

        if (edgeUpdateDisabled)
        {
            result.Findings.Add(Finding.Critical(
                "Edge Auto-Update Disabled",
                "Microsoft Edge auto-update is disabled via policy. The browser will not receive security patches automatically.",
                Category,
                "Enable Edge auto-update by removing the update policy.",
                @"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name 'UpdateDefault' -ErrorAction SilentlyContinue"));
        }

        if (!chromeUpdateDisabled && !edgeUpdateDisabled)
        {
            result.Findings.Add(Finding.Pass(
                "Browser Auto-Update Enabled",
                "No policies are disabling browser auto-updates. Browsers should update automatically.",
                Category));
        }
    }

    #endregion

    #region Safe Browsing / SmartScreen

    private void CheckSafeBrowsingSmartScreen(AuditResult result)
    {
        // Chrome Safe Browsing — policy check
        bool chromeSafeBrowsingDisabled = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
            var safeBrowsing = key?.GetValue("SafeBrowsingProtectionLevel");
            // 0 = off, 1 = standard, 2 = enhanced
            if (safeBrowsing != null && Convert.ToInt32(safeBrowsing) == 0)
                chromeSafeBrowsingDisabled = true;

            // Legacy key
            var safeBrowsingEnabled = key?.GetValue("SafeBrowsingEnabled");
            if (safeBrowsingEnabled != null && Convert.ToInt32(safeBrowsingEnabled) == 0)
                chromeSafeBrowsingDisabled = true;
        }
        catch { }

        if (chromeSafeBrowsingDisabled)
        {
            result.Findings.Add(Finding.Critical(
                "Chrome Safe Browsing Disabled",
                "Chrome Safe Browsing is disabled via policy. Phishing and malware protection is inactive.",
                Category,
                "Enable Chrome Safe Browsing via policy or in chrome://settings/security.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'SafeBrowsingProtectionLevel' -Value 1"));
        }

        // Edge SmartScreen — policy check
        bool edgeSmartScreenDisabled = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge");
            var smartScreen = key?.GetValue("SmartScreenEnabled");
            if (smartScreen != null && Convert.ToInt32(smartScreen) == 0)
                edgeSmartScreenDisabled = true;
        }
        catch { }

        // Windows SmartScreen (system-wide)
        bool windowsSmartScreenDisabled = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer");
            var smartScreen = key?.GetValue("SmartScreenEnabled")?.ToString();
            if (smartScreen?.Equals("Off", StringComparison.OrdinalIgnoreCase) == true)
                windowsSmartScreenDisabled = true;
        }
        catch { }

        if (edgeSmartScreenDisabled)
        {
            result.Findings.Add(Finding.Critical(
                "Edge SmartScreen Disabled",
                "Microsoft Edge SmartScreen is disabled via policy. Phishing and malware download protection is inactive.",
                Category,
                "Enable Edge SmartScreen via policy or in edge://settings/privacy.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenEnabled' -Value 1"));
        }

        if (windowsSmartScreenDisabled)
        {
            result.Findings.Add(Finding.Warning(
                "Windows SmartScreen Disabled",
                "Windows SmartScreen is disabled. Downloaded files and apps will not be scanned for threats.",
                Category,
                "Enable SmartScreen in Windows Security > App & browser control.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Warn'"));
        }

        if (!chromeSafeBrowsingDisabled && !edgeSmartScreenDisabled && !windowsSmartScreenDisabled)
        {
            result.Findings.Add(Finding.Pass(
                "Safe Browsing / SmartScreen Enabled",
                "No policies are disabling browser phishing and malware protection. Safe Browsing and SmartScreen should be active.",
                Category));
        }
    }

    #endregion

    #region Saved Passwords

    private void CheckSavedPasswords(AuditResult result)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Chrome Login Data
        var chromeLoginData = Path.Combine(localAppData,
            "Google", "Chrome", "User Data", "Default", "Login Data");
        bool chromeSavedPasswords = false;

        if (File.Exists(chromeLoginData))
        {
            try
            {
                var fileInfo = new FileInfo(chromeLoginData);
                // An empty Login Data SQLite DB is ~40KB. If it's larger, it likely has entries.
                chromeSavedPasswords = fileInfo.Length > 45000;
            }
            catch { }
        }

        // Edge Login Data
        var edgeLoginData = Path.Combine(localAppData,
            "Microsoft", "Edge", "User Data", "Default", "Login Data");
        bool edgeSavedPasswords = false;

        if (File.Exists(edgeLoginData))
        {
            try
            {
                var fileInfo = new FileInfo(edgeLoginData);
                edgeSavedPasswords = fileInfo.Length > 45000;
            }
            catch { }
        }

        if (chromeSavedPasswords || edgeSavedPasswords)
        {
            var browsers = new List<string>();
            if (chromeSavedPasswords) browsers.Add("Chrome");
            if (edgeSavedPasswords) browsers.Add("Edge");

            result.Findings.Add(Finding.Warning(
                "Saved Passwords in Browser",
                $"Passwords appear to be saved in {string.Join(" and ", browsers)}. " +
                "Browser-saved passwords are vulnerable to local attacks, malware, and data breaches. " +
                "Anyone with access to your Windows account can view them.",
                Category,
                "Use a dedicated password manager (Bitwarden, 1Password, KeePassXC) instead of saving passwords in browsers. " +
                "Export your saved passwords first, then disable the built-in password manager.",
                "Start-Process 'chrome://settings/passwords'"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Browser Saved Passwords Detected",
                "No significant saved password data was detected in Chrome or Edge.",
                Category));
        }
    }

    #endregion

    #region Popup Blocker & Security Settings

    private void CheckPopupBlocker(AuditResult result)
    {
        // Chrome popup policy
        bool chromePopupsAllowed = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
            var defaultPopups = key?.GetValue("DefaultPopupsSetting");
            // 1 = allow all, 2 = block all
            if (defaultPopups != null && Convert.ToInt32(defaultPopups) == 1)
                chromePopupsAllowed = true;
        }
        catch { }

        // Edge popup policy
        bool edgePopupsAllowed = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge");
            var defaultPopups = key?.GetValue("DefaultPopupsSetting");
            if (defaultPopups != null && Convert.ToInt32(defaultPopups) == 1)
                edgePopupsAllowed = true;
        }
        catch { }

        if (chromePopupsAllowed)
        {
            result.Findings.Add(Finding.Warning(
                "Chrome Popup Blocker Disabled",
                "Chrome's popup blocker is disabled via policy. Popups can be used for phishing and malware delivery.",
                Category,
                "Enable the popup blocker in Chrome policies.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'DefaultPopupsSetting' -Value 2"));
        }

        if (edgePopupsAllowed)
        {
            result.Findings.Add(Finding.Warning(
                "Edge Popup Blocker Disabled",
                "Edge's popup blocker is disabled via policy. Popups can be used for phishing and malware delivery.",
                Category,
                "Enable the popup blocker in Edge policies.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'DefaultPopupsSetting' -Value 2"));
        }

        if (!chromePopupsAllowed && !edgePopupsAllowed)
        {
            result.Findings.Add(Finding.Pass(
                "Popup Blockers Active",
                "No policies are disabling popup blockers. Browsers should block unwanted popups by default.",
                Category));
        }
    }

    #endregion

    #region Do Not Track

    private void CheckDoNotTrack(AuditResult result)
    {
        // Edge Do Not Track policy
        bool edgeDntEnabled = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge");
            var dnt = key?.GetValue("ConfigureDoNotTrack");
            if (dnt != null && Convert.ToInt32(dnt) == 1)
                edgeDntEnabled = true;
        }
        catch { }

        // Chrome doesn't have a direct registry policy for DNT — it's a user setting.
        // We can check if tracking prevention is enforced via policy on Edge.
        bool edgeTrackingPrevention = false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge");
            var trackingLevel = key?.GetValue("TrackingPrevention");
            // 0 = off, 1 = basic, 2 = balanced, 3 = strict
            if (trackingLevel != null && Convert.ToInt32(trackingLevel) >= 2)
                edgeTrackingPrevention = true;
        }
        catch { }

        if (!edgeDntEnabled && !edgeTrackingPrevention)
        {
            result.Findings.Add(Finding.Info(
                "Do Not Track / Tracking Prevention",
                "Do Not Track and enhanced tracking prevention are not enforced via policy. " +
                "Consider enabling tracking prevention in your browser settings for better privacy.",
                Category,
                "Enable tracking prevention in Edge: Settings > Privacy > Tracking prevention (Balanced or Strict). " +
                "In Chrome: Settings > Privacy > Send Do Not Track request."));
        }
        else
        {
            var details = new List<string>();
            if (edgeDntEnabled) details.Add("Do Not Track header");
            if (edgeTrackingPrevention) details.Add("Edge Tracking Prevention");
            result.Findings.Add(Finding.Pass(
                "Tracking Protection Enabled",
                $"Browser tracking protection is enabled via policy: {string.Join(", ", details)}.",
                Category));
        }
    }

    #endregion

    #region Browser Security Policies

    private void CheckBrowserSecurityPolicies(AuditResult result)
    {
        // Check Chrome JavaScript settings (policy)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
            var jsSetting = key?.GetValue("DefaultJavaScriptSetting");
            // 1 = allow (default), 2 = block
            if (jsSetting != null && Convert.ToInt32(jsSetting) == 2)
            {
                result.Findings.Add(Finding.Info(
                    "Chrome JavaScript Blocked by Policy",
                    "JavaScript is blocked by policy in Chrome. This improves security but may break many websites.",
                    Category));
            }
        }
        catch { }

        // Check if Chrome password manager is disabled via policy (good if using external manager)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
            var pwMgrEnabled = key?.GetValue("PasswordManagerEnabled");
            if (pwMgrEnabled != null && Convert.ToInt32(pwMgrEnabled) == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "Chrome Password Manager Disabled by Policy",
                    "Chrome's built-in password manager is disabled via policy. This is good if you use a dedicated password manager.",
                    Category));
            }
        }
        catch { }

        // Check Edge password manager policy
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge");
            var pwMgrEnabled = key?.GetValue("PasswordManagerEnabled");
            if (pwMgrEnabled != null && Convert.ToInt32(pwMgrEnabled) == 0)
            {
                result.Findings.Add(Finding.Pass(
                    "Edge Password Manager Disabled by Policy",
                    "Edge's built-in password manager is disabled via policy. This is good if you use a dedicated password manager.",
                    Category));
            }
        }
        catch { }

        // Check if Chrome site isolation is enforced
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
            var siteIsolation = key?.GetValue("SitePerProcess");
            if (siteIsolation != null && Convert.ToInt32(siteIsolation) == 1)
            {
                result.Findings.Add(Finding.Pass(
                    "Chrome Site Isolation Enforced",
                    "Site isolation (one process per site) is enforced via policy in Chrome, providing stronger protection against Spectre-type attacks.",
                    Category));
            }
        }
        catch { }

        // Check if download restrictions are set
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
            var downloadRestrictions = key?.GetValue("DownloadRestrictions");
            // 1 = block dangerous, 2 = block potentially dangerous, 3 = block all
            if (downloadRestrictions != null && Convert.ToInt32(downloadRestrictions) >= 1)
            {
                result.Findings.Add(Finding.Pass(
                    "Chrome Download Restrictions Active",
                    $"Chrome download restrictions are set (level {downloadRestrictions}), blocking dangerous downloads.",
                    Category));
            }
        }
        catch { }
    }

    #endregion

    #region Helpers

    private static string? GetBrowserVersion(string primaryKey, string valueName,
        string fallbackKey, string fallbackValueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(primaryKey);
            var version = key?.GetValue(valueName)?.ToString();
            if (!string.IsNullOrEmpty(version)) return version;
        }
        catch { }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(fallbackKey);
            var version = key?.GetValue(fallbackValueName)?.ToString();
            if (!string.IsNullOrEmpty(version)) return version;
        }
        catch { }

        // Try HKCU
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(primaryKey);
            var version = key?.GetValue(valueName)?.ToString();
            if (!string.IsNullOrEmpty(version)) return version;
        }
        catch { }

        return null;
    }

    /// <summary>
    /// Normalize a version string for parsing — ensures at least major.minor.build format.
    /// </summary>
    private static string NormalizeVersion(string version)
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

    #endregion
}
