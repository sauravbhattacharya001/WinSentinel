using System.Text.Json;
using Microsoft.Win32;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits browser security: Chrome, Edge, and Firefox installation status, versions,
/// extension safety, saved passwords, auto-update, Safe Browsing / SmartScreen,
/// Do Not Track, popup blocker, and general security settings.
///
/// This class owns ONLY the collection of raw state from Windows (registry, files,
/// extension manifests). Every security decision - version freshness, extension risk
/// scoring, policy evaluation - is delegated to the pure, unit-tested
/// <see cref="BrowserSecurityAnalyzer"/>. Mirrors the EncryptionAudit / EncryptionAnalyzer
/// split.
/// </summary>
public class BrowserAudit : AuditModuleBase
{
    public override string Name => "Browser Audit";
    public override string Category => "Browser";
    public override string Description =>
        "Checks installed browsers (Chrome, Edge, Firefox), versions, extensions, " +
        "saved passwords, auto-update, Safe Browsing, SmartScreen, and security settings.";

    protected override Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        // Collect raw browser state from Windows, then delegate every decision to the
        // pure, unit-tested BrowserSecurityAnalyzer.
        var policy = CollectPolicyState();

        CheckChromeInstallation(result);
        CheckEdgeInstallation(result);
        CheckFirefoxInstallation(result);
        result.Findings.AddRange(BrowserSecurityAnalyzer.AnalyzeExtensions(CollectChromeExtensions()));
        result.Findings.AddRange(BrowserSecurityAnalyzer.AnalyzeAutoUpdate(policy));
        result.Findings.AddRange(BrowserSecurityAnalyzer.AnalyzeSafeBrowsing(policy));
        result.Findings.Add(BrowserSecurityAnalyzer.BuildSavedPasswordFinding(CollectSavedPasswordState()));
        result.Findings.AddRange(BrowserSecurityAnalyzer.AnalyzePopupBlocker(policy));
        result.Findings.Add(BrowserSecurityAnalyzer.BuildTrackingProtectionFinding(policy));
        result.Findings.AddRange(BrowserSecurityAnalyzer.AnalyzeSecurityPolicies(policy));
        return Task.CompletedTask;
    }

    #region Browser Installation & Version Checks

    private void CheckChromeInstallation(AuditResult result)
    {
        var version = GetBrowserVersion(
            @"SOFTWARE\Google\Chrome\BLBeacon", "version",
            @"SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon", "version");

        var installed = version != null;
        if (version == null)
        {
            var chromePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Google", "Chrome", "Application", "chrome.exe");
            var chromePathX86 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Google", "Chrome", "Application", "chrome.exe");
            installed = File.Exists(chromePath) || File.Exists(chromePathX86);
        }

        result.Findings.Add(BrowserSecurityAnalyzer.BuildVersionFinding(new BrowserSecurityAnalyzer.BrowserVersionState
        {
            Kind = BrowserSecurityAnalyzer.BrowserKind.Chrome,
            Installed = installed,
            RawVersion = version,
        }));
    }

    private void CheckEdgeInstallation(AuditResult result)
    {
        var version = GetBrowserVersion(
            @"SOFTWARE\Microsoft\Edge\BLBeacon", "version",
            @"SOFTWARE\WOW6432Node\Microsoft\Edge\BLBeacon", "version");

        // Edge is pre-installed on Windows 10/11
        if (version == null)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Edge\BLBeacon");
                version = key?.GetValue("version")?.ToString();
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        }

        result.Findings.Add(BrowserSecurityAnalyzer.BuildVersionFinding(new BrowserSecurityAnalyzer.BrowserVersionState
        {
            Kind = BrowserSecurityAnalyzer.BrowserKind.Edge,
            Installed = version != null,
            RawVersion = version,
        }));
    }

    private void CheckFirefoxInstallation(AuditResult result)
    {
        string? version = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Mozilla\Mozilla Firefox");
            version = key?.GetValue("CurrentVersion")?.ToString();
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        if (version == null)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox");
                version = key?.GetValue("CurrentVersion")?.ToString();
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }
        }

        var installed = version != null;
        if (version == null)
        {
            var firefoxPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Mozilla Firefox", "firefox.exe");
            var firefoxPathX86 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Mozilla Firefox", "firefox.exe");
            installed = File.Exists(firefoxPath) || File.Exists(firefoxPathX86);
        }

        result.Findings.Add(BrowserSecurityAnalyzer.BuildVersionFinding(new BrowserSecurityAnalyzer.BrowserVersionState
        {
            Kind = BrowserSecurityAnalyzer.BrowserKind.Firefox,
            Installed = installed,
            RawVersion = version,
        }));
    }

    #endregion

    #region Chrome Extensions

    /// <summary>Read installed Chrome extensions + their manifest permissions (no analysis here).</summary>
    private static IReadOnlyList<BrowserSecurityAnalyzer.ExtensionState> CollectChromeExtensions()
    {
        var extensions = new List<BrowserSecurityAnalyzer.ExtensionState>();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var extensionsDir = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions");

        if (!Directory.Exists(extensionsDir))
            return extensions;

        foreach (var extDir in Directory.GetDirectories(extensionsDir))
        {
            var extId = Path.GetFileName(extDir);
            if (string.IsNullOrEmpty(extId)) continue;

            extensions.Add(new BrowserSecurityAnalyzer.ExtensionState
            {
                Id = extId,
                Name = GetExtensionName(extDir),
                Permissions = ReadExtensionPermissions(extDir),
            });
        }

        return extensions;
    }

    private static string? GetExtensionName(string extensionDir)
    {
        try
        {
            // Extensions are in subdirectories named by version
            var versionDirs = Directory.GetDirectories(extensionDir);
            if (versionDirs.Length == 0) return null;

            var latestDir = versionDirs.OrderByDescending(d => d).First();
            var manifestPath = Path.Combine(latestDir, "manifest.json");
            if (!File.Exists(manifestPath)) return null;

            var json = File.ReadAllText(manifestPath);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("name", out var nameEl))
            {
                var name = nameEl.GetString();
                // Skip __MSG_ localized names - they require locale lookup
                if (name != null && !name.StartsWith("__MSG_"))
                    return name;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        return null;
    }

    /// <summary>Read permissions / host_permissions / optional_permissions from a manifest.</summary>
    private static IReadOnlyList<string> ReadExtensionPermissions(string extensionDir)
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

            void AddArray(string prop)
            {
                if (root.TryGetProperty(prop, out var el) && el.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in el.EnumerateArray())
                    {
                        var s = item.GetString();
                        if (s != null) found.Add(s);
                    }
                }
            }

            AddArray("permissions");
            AddArray("host_permissions");

            // Optional permissions are surfaced with an "optional:" prefix, matching the
            // legacy report format; only dangerous ones are kept so the prefixed string
            // isn't mistaken for a plain permission.
            if (root.TryGetProperty("optional_permissions", out var optEl) && optEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in optEl.EnumerateArray())
                {
                    var s = item.GetString();
                    if (s != null && BrowserSecurityAnalyzer.DangerousPermissions.Contains(s))
                        found.Add("optional:" + s);
                }
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        return found;
    }

    #endregion

    #region Saved Passwords

    private static BrowserSecurityAnalyzer.SavedPasswordState CollectSavedPasswordState()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new BrowserSecurityAnalyzer.SavedPasswordState
        {
            ChromeLoginDataBytes = FileSizeOrZero(Path.Combine(localAppData,
                "Google", "Chrome", "User Data", "Default", "Login Data")),
            EdgeLoginDataBytes = FileSizeOrZero(Path.Combine(localAppData,
                "Microsoft", "Edge", "User Data", "Default", "Login Data")),
        };
    }

    private static long FileSizeOrZero(string path)
    {
        try
        {
            return File.Exists(path) ? new FileInfo(path).Length : 0;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}");
            return 0;
        }
    }

    #endregion

    #region Policy collection

    /// <summary>
    /// Read all browser policy registry values into a single state object. Returns the
    /// raw values (null = policy not set); the analyzer owns the threshold rules.
    /// </summary>
    private static BrowserSecurityAnalyzer.BrowserPolicyState CollectPolicyState()
    {
        var state = new BrowserSecurityAnalyzer.BrowserPolicyState();

        // Chrome Update policy
        state.ChromeUpdateDefault = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Update", "UpdateDefault");
        state.ChromePerAppUpdate = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Update",
            "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}");
        // Edge Update policy
        state.EdgeUpdateDefault = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\EdgeUpdate", "UpdateDefault");

        // Safe Browsing / SmartScreen
        state.ChromeSafeBrowsingProtectionLevel = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "SafeBrowsingProtectionLevel");
        state.ChromeSafeBrowsingEnabledLegacy = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "SafeBrowsingEnabled");
        state.EdgeSmartScreenEnabled = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenEnabled");
        state.WindowsSmartScreen = ReadString(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled");

        // Popup blocker
        state.ChromeDefaultPopupsSetting = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "DefaultPopupsSetting");
        state.EdgeDefaultPopupsSetting = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "DefaultPopupsSetting");

        // DNT / tracking prevention
        state.EdgeConfigureDoNotTrack = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "ConfigureDoNotTrack");
        state.EdgeTrackingPrevention = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "TrackingPrevention");

        // Hardening policies
        state.ChromeDefaultJavaScriptSetting = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "DefaultJavaScriptSetting");
        state.ChromePasswordManagerEnabled = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "PasswordManagerEnabled");
        state.EdgePasswordManagerEnabled = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "PasswordManagerEnabled");
        state.ChromeSitePerProcess = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "SitePerProcess");
        state.ChromeDownloadRestrictions = ReadDword(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "DownloadRestrictions");

        return state;
    }

    private static int? ReadDword(RegistryKey hive, string subKey, string valueName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey);
            var raw = key?.GetValue(valueName);
            return raw == null ? null : Convert.ToInt32(raw);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}");
            return null;
        }
    }

    private static string? ReadString(RegistryKey hive, string subKey, string valueName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey);
            return key?.GetValue(valueName)?.ToString();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}");
            return null;
        }
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
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(fallbackKey);
            var version = key?.GetValue(fallbackValueName)?.ToString();
            if (!string.IsNullOrEmpty(version)) return version;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        // Try HKCU
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(primaryKey);
            var version = key?.GetValue(valueName)?.ToString();
            if (!string.IsNullOrEmpty(version)) return version;
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[WinSentinel] Error: {ex.GetType().Name} - {ex.Message}"); }

        return null;
    }

    #endregion
}
