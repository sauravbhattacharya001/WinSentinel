using System.Text.RegularExpressions;
using Microsoft.Win32;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits installed applications for outdated, end-of-life, and insecure software.
/// Enumerates installed programs from the registry and checks against known-safe
/// minimum versions, EOL software lists, and suspicious installation patterns.
/// </summary>
public class AppSecurityAudit : IAuditModule
{
    public string Name => "App Security Audit";
    public string Category => "Applications";
    public string Description =>
        "Detects outdated, end-of-life, and insecure software by scanning installed programs " +
        "against known-safe minimum versions, flagging EOL products, suspicious installs, " +
        "and duplicate x86/x64 installations.";

    /// <summary>Threshold for total installed programs — above this suggests potential bloatware.</summary>
    private const int BloatwareThreshold = 120;

    #region Known-Safe Minimum Versions

    /// <summary>
    /// Minimum safe versions for common software. Apps below these versions
    /// are flagged as having known security vulnerabilities.
    /// </summary>
    private static readonly List<AppVersionRule> KnownSafeVersions = new()
    {
        new("7-Zip", new[] { "7-zip" }, new Version(24, 0), "https://7-zip.org/"),
        new("WinRAR", new[] { "winrar" }, new Version(7, 0), "https://www.win-rar.com/"),
        new("VLC media player", new[] { "vlc media player", "vlc" }, new Version(3, 0, 20), "https://www.videolan.org/"),
        new("Git", new[] { "git" }, new Version(2, 43), "https://git-scm.com/"),
        new("Node.js", new[] { "node.js", "node" }, new Version(20, 0), "https://nodejs.org/"),
        new("PuTTY", new[] { "putty" }, new Version(0, 80), "https://www.chiark.greenend.org.uk/~sgtatham/putty/"),
        new("FileZilla", new[] { "filezilla client", "filezilla" }, new Version(3, 66), "https://filezilla-project.org/"),
        new("Notepad++", new[] { "notepad++", "notepad++" }, new Version(8, 6), "https://notepad-plus-plus.org/"),
        new("Python", new[] { "python 3" }, new Version(3, 12), "https://python.org/"),
        new("WinSCP", new[] { "winscp" }, new Version(6, 1), "https://winscp.net/"),
        new("KeePass", new[] { "keepass" }, new Version(2, 55), "https://keepass.info/"),
        new("Wireshark", new[] { "wireshark" }, new Version(4, 2), "https://www.wireshark.org/"),
        new("Audacity", new[] { "audacity" }, new Version(3, 4), "https://www.audacityteam.org/"),
        new("GIMP", new[] { "gimp" }, new Version(2, 10, 36), "https://www.gimp.org/"),
        new("LibreOffice", new[] { "libreoffice" }, new Version(7, 6), "https://www.libreoffice.org/"),
        new("Thunderbird", new[] { "mozilla thunderbird" }, new Version(115, 0), "https://www.thunderbird.net/"),
        new("Zoom", new[] { "zoom" }, new Version(5, 17), "https://zoom.us/"),
    };

    #endregion

    #region EOL Software Patterns

    /// <summary>
    /// Patterns that indicate end-of-life / unsupported / dangerous software.
    /// </summary>
    private static readonly List<EolPattern> EolPatterns = new()
    {
        // Python 2.x — EOL since January 2020
        new("Python 2", new Regex(@"Python\s+2\.\d", RegexOptions.IgnoreCase),
            "Python 2 reached end-of-life in January 2020 and receives no security updates.",
            Severity.Critical),

        // Java 7 — EOL
        new("Java 7", new Regex(@"Java.*\b7[\.\s]|Java\(TM\)\s+7\b", RegexOptions.IgnoreCase),
            "Java 7 is end-of-life and has numerous unpatched CVEs.",
            Severity.Critical),

        // Java 8 old builds (below 8u401)
        new("Java 8 (old build)", new Regex(@"Java.*\b8\s+Update\s+([1-3]\d{0,2}|40[0-0]?)\b", RegexOptions.IgnoreCase),
            "This version of Java 8 is outdated and has known security vulnerabilities. Update to the latest Java 8 or migrate to Java 17+.",
            Severity.Warning),

        // Adobe Flash Player — EOL since December 2020
        new("Adobe Flash Player", new Regex(@"Adobe\s+Flash\s+Player", RegexOptions.IgnoreCase),
            "Adobe Flash Player reached end-of-life in December 2020. It is a major security risk and should be uninstalled.",
            Severity.Critical),

        // Microsoft Silverlight — EOL since October 2021
        new("Microsoft Silverlight", new Regex(@"Microsoft\s+Silverlight", RegexOptions.IgnoreCase),
            "Microsoft Silverlight reached end-of-life in October 2021 and should be uninstalled.",
            Severity.Critical),

        // Java browser plugin (any version)
        new("Java Browser Plugin", new Regex(@"Java.*Browser.*Plugin|Java.*Web\s+Start|Java\(TM\).*Plug-in", RegexOptions.IgnoreCase),
            "The Java browser plugin is deprecated and a frequent attack vector. It should be disabled or uninstalled.",
            Severity.Warning),

        // PHP < 8.0
        new("PHP (< 8.0)", new Regex(@"PHP\s+[5-7]\.\d", RegexOptions.IgnoreCase),
            "PHP versions below 8.0 are end-of-life and no longer receive security updates.",
            Severity.Warning),

        // Node.js odd versions (15.x, 17.x, 19.x, 21.x, 23.x) — non-LTS, short-lived
        new("Node.js (non-LTS)", new Regex(@"Node\.?js\s+v?(15|17|19|21|23)\.\d", RegexOptions.IgnoreCase),
            "This is a non-LTS (odd-numbered) Node.js version with a short support window. Migrate to an even-numbered LTS version.",
            Severity.Warning),

        // .NET Framework < 4.8 (old runtimes)
        new(".NET Framework (< 4.8)", new Regex(@"Microsoft\s+\.NET\s+Framework\s+[1-3]\.|Microsoft\s+\.NET\s+Framework\s+4\.[0-7]\b", RegexOptions.IgnoreCase),
            ".NET Framework versions below 4.8 are outdated. .NET Framework 4.8 is the final version; consider migrating to .NET 8+.",
            Severity.Info),

        // Windows 7/8 compatibility components
        new("Windows Compatibility Pack", new Regex(@"Windows\s+(7|8|8\.1)\s+(Compatibility|Service\s+Pack)", RegexOptions.IgnoreCase),
            "Windows 7/8 compatibility components are present. These may indicate legacy dependencies.",
            Severity.Info),

        // Internet Explorer
        new("Internet Explorer", new Regex(@"Internet\s+Explorer", RegexOptions.IgnoreCase),
            "Internet Explorer is end-of-life. Use Microsoft Edge or another modern browser.",
            Severity.Warning),

        // Adobe Reader very old versions (below 2020/DC)
        new("Adobe Reader (old)", new Regex(@"Adobe\s+(Reader|Acrobat\s+Reader)\s+(9|1[0-4]|XI|X\b)", RegexOptions.IgnoreCase),
            "This version of Adobe Reader is very outdated and has known security vulnerabilities.",
            Severity.Warning),

        // QuickTime for Windows — EOL since 2016
        new("QuickTime", new Regex(@"Apple\s+QuickTime|QuickTime\s+\d", RegexOptions.IgnoreCase),
            "Apple QuickTime for Windows has been end-of-life since 2016 and has unpatched vulnerabilities.",
            Severity.Critical),
    };

    #endregion

    #region Installed Program Model

    /// <summary>Represents an installed program from the registry.</summary>
    private record InstalledProgram(
        string DisplayName,
        string? DisplayVersion,
        string? Publisher,
        string? InstallLocation,
        string? UninstallString,
        string RegistrySource, // "HKLM64", "HKLM32", "HKCU"
        bool IsSystemComponent);

    #endregion

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
            var programs = EnumerateInstalledPrograms();

            CheckEolSoftware(result, programs);
            CheckOutdatedSoftware(result, programs);
            CheckSuspiciousInstallLocations(result, programs);
            CheckDualInstallations(result, programs);
            CheckBloatware(result, programs);
            CheckVisualCppRedistributables(result, programs);
            CheckStoreAutoUpdate(result);
            CheckTotalProgramsSummary(result, programs);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return await Task.FromResult(result);
    }

    #region Enumerate Installed Programs

    /// <summary>
    /// Enumerates all installed programs from multiple registry hives:
    /// HKLM 64-bit, HKLM 32-bit (Wow6432Node), and HKCU.
    /// </summary>
    private static List<InstalledProgram> EnumerateInstalledPrograms()
    {
        var programs = new List<InstalledProgram>();

        // HKLM 64-bit Uninstall
        EnumerateFromKey(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM64", programs);

        // HKLM 32-bit (Wow6432Node) Uninstall
        EnumerateFromKey(Registry.LocalMachine,
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM32", programs);

        // HKCU Uninstall (per-user installs)
        EnumerateFromKey(Registry.CurrentUser,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU", programs);

        return programs;
    }

    private static void EnumerateFromKey(RegistryKey rootKey, string subKeyPath,
        string source, List<InstalledProgram> programs)
    {
        try
        {
            using var uninstallKey = rootKey.OpenSubKey(subKeyPath);
            if (uninstallKey == null) return;

            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                try
                {
                    using var appKey = uninstallKey.OpenSubKey(subKeyName);
                    if (appKey == null) continue;

                    var displayName = appKey.GetValue("DisplayName")?.ToString();
                    if (string.IsNullOrWhiteSpace(displayName)) continue;

                    var systemComponent = appKey.GetValue("SystemComponent");
                    bool isSystem = systemComponent != null &&
                                    (Convert.ToInt32(systemComponent) == 1);

                    programs.Add(new InstalledProgram(
                        DisplayName: displayName.Trim(),
                        DisplayVersion: appKey.GetValue("DisplayVersion")?.ToString()?.Trim(),
                        Publisher: appKey.GetValue("Publisher")?.ToString()?.Trim(),
                        InstallLocation: appKey.GetValue("InstallLocation")?.ToString()?.Trim(),
                        UninstallString: appKey.GetValue("UninstallString")?.ToString()?.Trim(),
                        RegistrySource: source,
                        IsSystemComponent: isSystem));
                }
                catch
                {
                    // Skip inaccessible entries
                }
            }
        }
        catch
        {
            // Registry hive may not be accessible
        }
    }

    #endregion

    #region EOL Software Detection

    private static void CheckEolSoftware(AuditResult result, List<InstalledProgram> programs)
    {
        int eolCount = 0;
        var detectedEol = new HashSet<string>(); // Avoid duplicate findings for same EOL pattern

        foreach (var program in programs.Where(p => !p.IsSystemComponent))
        {
            foreach (var pattern in EolPatterns)
            {
                if (detectedEol.Contains(pattern.Name)) continue;

                if (pattern.Regex.IsMatch(program.DisplayName))
                {
                    detectedEol.Add(pattern.Name);
                    eolCount++;

                    var finding = pattern.Severity switch
                    {
                        Severity.Critical => Finding.Critical(
                            $"EOL Software: {pattern.Name}",
                            $"'{program.DisplayName}' is installed. {pattern.Reason}",
                            "Applications",
                            $"Uninstall {program.DisplayName} or upgrade to a supported version.",
                            program.UninstallString != null
                                ? $"Start-Process -FilePath 'appwiz.cpl'"
                                : null),
                        Severity.Warning => Finding.Warning(
                            $"EOL Software: {pattern.Name}",
                            $"'{program.DisplayName}' is installed. {pattern.Reason}",
                            "Applications",
                            $"Uninstall {program.DisplayName} or upgrade to a supported version.",
                            "Start-Process -FilePath 'appwiz.cpl'"),
                        _ => Finding.Info(
                            $"Legacy Software: {pattern.Name}",
                            $"'{program.DisplayName}' is installed. {pattern.Reason}",
                            "Applications",
                            $"Consider upgrading or removing {program.DisplayName}.")
                    };

                    result.Findings.Add(finding);
                }
            }
        }

        if (eolCount == 0)
        {
            result.Findings.Add(Finding.Pass(
                "No EOL Software Detected",
                "No known end-of-life or deprecated software was found installed.",
                "Applications"));
        }
    }

    #endregion

    #region Outdated Software Detection

    private static void CheckOutdatedSoftware(AuditResult result, List<InstalledProgram> programs)
    {
        int outdatedCount = 0;
        int upToDateCount = 0;

        foreach (var rule in KnownSafeVersions)
        {
            // Find matching installed programs
            var matches = programs
                .Where(p => !p.IsSystemComponent && rule.MatchesName(p.DisplayName))
                .ToList();

            if (matches.Count == 0) continue;

            foreach (var match in matches)
            {
                var installedVersion = ParseVersion(match.DisplayVersion);
                if (installedVersion == null)
                {
                    result.Findings.Add(Finding.Info(
                        $"{rule.AppName} Version Unknown",
                        $"'{match.DisplayName}' is installed but the version '{match.DisplayVersion}' could not be parsed for comparison.",
                        "Applications"));
                    continue;
                }

                if (installedVersion < rule.MinimumSafe)
                {
                    outdatedCount++;
                    result.Findings.Add(Finding.Warning(
                        $"Outdated: {rule.AppName}",
                        $"'{match.DisplayName}' version {match.DisplayVersion} is installed. " +
                        $"Minimum recommended version is {rule.MinimumSafe}. " +
                        "Older versions may have known security vulnerabilities (CVEs).",
                        "Applications",
                        $"Update {rule.AppName} to version {rule.MinimumSafe} or later from {rule.DownloadUrl}.",
                        $"Start-Process '{rule.DownloadUrl}'"));
                }
                else
                {
                    upToDateCount++;
                }
            }
        }

        if (outdatedCount == 0 && upToDateCount > 0)
        {
            result.Findings.Add(Finding.Pass(
                "Known Software Up to Date",
                $"{upToDateCount} monitored application(s) are at or above recommended minimum versions.",
                "Applications"));
        }
    }

    #endregion

    #region Suspicious Install Locations

    private static void CheckSuspiciousInstallLocations(AuditResult result, List<InstalledProgram> programs)
    {
        var tempDir = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
        var downloadsDir = Path.Combine(userProfile, "downloads").ToLowerInvariant();
        var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop).ToLowerInvariant();
        var appDataDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToLowerInvariant();
        var localAppDataDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData).ToLowerInvariant();

        var suspiciousPrograms = new List<string>();

        foreach (var program in programs.Where(p => !p.IsSystemComponent))
        {
            var installLoc = program.InstallLocation?.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(installLoc)) continue;

            installLoc = installLoc.TrimEnd(Path.DirectorySeparatorChar);

            bool suspicious = false;
            string reason = "";

            if (installLoc.StartsWith(tempDir) || installLoc.Contains("\\temp\\"))
            {
                suspicious = true;
                reason = "temp directory";
            }
            else if (installLoc.StartsWith(downloadsDir))
            {
                suspicious = true;
                reason = "Downloads folder";
            }
            else if (installLoc.StartsWith(desktopDir))
            {
                suspicious = true;
                reason = "Desktop";
            }

            if (suspicious)
            {
                suspiciousPrograms.Add($"• {program.DisplayName} — installed in {reason} ({program.InstallLocation})");
            }
        }

        if (suspiciousPrograms.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                "Suspicious Install Locations",
                $"{suspiciousPrograms.Count} program(s) are installed in unusual locations " +
                "(temp/Downloads/Desktop directories). This can indicate unofficial or potentially " +
                "malicious software:\n" + string.Join("\n", suspiciousPrograms),
                "Applications",
                "Review these programs and reinstall them to standard locations (Program Files) or remove them if unknown.",
                "Start-Process -FilePath 'appwiz.cpl'"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Install Locations OK",
                "No programs found installed in suspicious locations (temp, Downloads, Desktop).",
                "Applications"));
        }
    }

    #endregion

    #region Dual x86/x64 Installations

    private static void CheckDualInstallations(AuditResult result, List<InstalledProgram> programs)
    {
        // Group non-system-component programs by normalized name
        var visiblePrograms = programs.Where(p => !p.IsSystemComponent).ToList();

        // Find programs that appear in both HKLM64 and HKLM32
        var hklm64Names = visiblePrograms
            .Where(p => p.RegistrySource == "HKLM64")
            .Select(p => NormalizeProgramName(p.DisplayName))
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var hklm32Names = visiblePrograms
            .Where(p => p.RegistrySource == "HKLM32")
            .Select(p => NormalizeProgramName(p.DisplayName))
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var dualInstalls = hklm64Names.Intersect(hklm32Names, StringComparer.OrdinalIgnoreCase).ToList();

        // Filter out known apps that legitimately have both architectures
        var legitimateDual = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "microsoft visual c++ redistributable",
            "microsoft visual c++",
            "microsoft .net",
            "microsoft .net runtime",
            "microsoft .net framework",
            "microsoft asp.net",
            "microsoft windows desktop runtime",
        };

        var unnecessaryDual = dualInstalls
            .Where(name => !legitimateDual.Any(l => name.Contains(l, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (unnecessaryDual.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Dual x86/x64 Installations Detected",
                $"{unnecessaryDual.Count} program(s) have both 32-bit and 64-bit versions installed. " +
                "This is usually unnecessary and wastes disk space:\n" +
                string.Join("\n", unnecessaryDual.Select(n => $"• {n}")),
                "Applications",
                "Remove the 32-bit (x86) version unless specifically needed by a dependent application."));
        }
    }

    #endregion

    #region Bloatware Check

    private static void CheckBloatware(AuditResult result, List<InstalledProgram> programs)
    {
        var visiblePrograms = programs.Where(p => !p.IsSystemComponent).ToList();
        int count = visiblePrograms.Count;

        if (count > BloatwareThreshold)
        {
            result.Findings.Add(Finding.Warning(
                "Excessive Installed Programs",
                $"{count} programs are installed (threshold: {BloatwareThreshold}). " +
                "An excessive number of installed programs increases the attack surface and may include bloatware. " +
                "Review and remove programs you no longer need.",
                "Applications",
                "Open Programs and Features to review installed software.",
                "Start-Process -FilePath 'appwiz.cpl'"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Installed Program Count OK",
                $"{count} programs installed (threshold: {BloatwareThreshold}). Program count is within reasonable limits.",
                "Applications"));
        }
    }

    #endregion

    #region Visual C++ Redistributable Check

    private static void CheckVisualCppRedistributables(AuditResult result, List<InstalledProgram> programs)
    {
        var vcRedists = programs
            .Where(p => p.DisplayName.Contains("Visual C++", StringComparison.OrdinalIgnoreCase) &&
                        p.DisplayName.Contains("Redistributable", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (vcRedists.Count == 0) return;

        // Check for very old redistributables (2005, 2008, 2010) — these are outdated
        var oldYears = new[] { "2005", "2008", "2010" };
        var oldRedists = vcRedists
            .Where(p => oldYears.Any(y => p.DisplayName.Contains(y)))
            .ToList();

        if (oldRedists.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                "Old Visual C++ Redistributables Installed",
                $"{oldRedists.Count} old Visual C++ Redistributable(s) found (2005/2008/2010). " +
                "These are required by some legacy software but represent older runtimes:\n" +
                string.Join("\n", oldRedists.Select(r => $"• {r.DisplayName}")),
                "Applications",
                "These are only needed if you run software that depends on them. " +
                "If you've uninstalled all legacy apps that need them, you can remove them from Programs and Features."));
        }

        // Count total redists — excessive?
        if (vcRedists.Count > 10)
        {
            result.Findings.Add(Finding.Info(
                "Many Visual C++ Redistributables",
                $"{vcRedists.Count} Visual C++ Redistributable packages are installed. " +
                "While many apps require these, having too many may indicate leftover packages from uninstalled software.",
                "Applications",
                "Review the list and remove any that aren't needed by installed applications."));
        }
    }

    #endregion

    #region Windows Store Auto-Update

    private static void CheckStoreAutoUpdate(AuditResult result)
    {
        // Check if Windows Store auto-update is disabled via policy
        // Policy: HKLM\SOFTWARE\Policies\Microsoft\WindowsStore -> AutoDownload
        // 2 = Always off, 4 = Always on
        bool autoUpdateDisabled = false;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\WindowsStore");
            if (key != null)
            {
                var autoDownload = key.GetValue("AutoDownload");
                if (autoDownload != null && Convert.ToInt32(autoDownload) == 2)
                    autoUpdateDisabled = true;

                // Also check if Store is disabled entirely
                var removeStore = key.GetValue("RemoveWindowsStore");
                if (removeStore != null && Convert.ToInt32(removeStore) == 1)
                {
                    result.Findings.Add(Finding.Info(
                        "Windows Store Disabled",
                        "The Microsoft Store is disabled via policy. Store apps will not receive updates.",
                        "Applications",
                        "If Store apps are installed, consider enabling the Store for security updates."));
                    return;
                }
            }
        }
        catch { }

        // Also check HKCU policy
        if (!autoUpdateDisabled)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager");
                if (key != null)
                {
                    var silentInstalled = key.GetValue("SilentInstalledAppsEnabled");
                    // This is more about content delivery than security updates, but worth noting
                }
            }
            catch { }
        }

        if (autoUpdateDisabled)
        {
            result.Findings.Add(Finding.Warning(
                "Store App Auto-Update Disabled",
                "Windows Store automatic app updates are disabled via policy. " +
                "Store apps (including system components like Calculator, Photos, etc.) will not receive security updates automatically.",
                "Applications",
                "Enable Store auto-updates via Group Policy or remove the AutoDownload registry value.",
                @"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'AutoDownload' -ErrorAction SilentlyContinue"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Store App Auto-Update Enabled",
                "Windows Store app auto-update is not disabled by policy. Store apps should update automatically.",
                "Applications"));
        }
    }

    #endregion

    #region Total Programs Summary

    private static void CheckTotalProgramsSummary(AuditResult result, List<InstalledProgram> programs)
    {
        var visiblePrograms = programs.Where(p => !p.IsSystemComponent).ToList();
        int hklm64 = visiblePrograms.Count(p => p.RegistrySource == "HKLM64");
        int hklm32 = visiblePrograms.Count(p => p.RegistrySource == "HKLM32");
        int hkcu = visiblePrograms.Count(p => p.RegistrySource == "HKCU");

        result.Findings.Add(Finding.Info(
            "Installed Programs Summary",
            $"Total installed programs: {visiblePrograms.Count} " +
            $"(System-wide 64-bit: {hklm64}, System-wide 32-bit: {hklm32}, Per-user: {hkcu}).",
            "Applications"));
    }

    #endregion

    #region Helpers

    /// <summary>
    /// Attempts to parse a version string that may contain extra text.
    /// Handles formats like "24.09", "3.0.20.0", "2.43.0.windows.1", "v20.11.0", etc.
    /// </summary>
    public static Version? ParseVersion(string? versionStr)
    {
        if (string.IsNullOrWhiteSpace(versionStr)) return null;

        // Remove leading 'v' or 'V'
        versionStr = versionStr.TrimStart('v', 'V').Trim();

        // Try direct parse first
        if (Version.TryParse(versionStr, out var directVersion))
            return directVersion;

        // Extract version-like pattern from the string
        var match = Regex.Match(versionStr, @"(\d+(?:\.\d+){0,3})");
        if (match.Success && Version.TryParse(match.Groups[1].Value, out var extractedVersion))
            return extractedVersion;

        // Try parsing just the major version number
        if (int.TryParse(versionStr.Split('.', ' ', '-')[0], out int major))
            return new Version(major, 0);

        return null;
    }

    /// <summary>
    /// Normalizes a program name for comparison: removes version numbers,
    /// architecture indicators, and extra whitespace.
    /// </summary>
    private static string NormalizeProgramName(string displayName)
    {
        // Remove common suffixes: version numbers, (x86), (x64), (64-bit), etc.
        var normalized = Regex.Replace(displayName,
            @"\s*[\(\[]?(x86|x64|32-bit|64-bit|amd64|arm64)[\)\]]?\s*",
            " ", RegexOptions.IgnoreCase);

        // Remove trailing version numbers
        normalized = Regex.Replace(normalized,
            @"\s+v?\d+(\.\d+)*\s*$", "", RegexOptions.IgnoreCase);

        return normalized.Trim();
    }

    #endregion

    #region Rule Types

    /// <summary>Defines a minimum version rule for a known application.</summary>
    private record AppVersionRule(
        string AppName,
        string[] NamePatterns,
        Version MinimumSafe,
        string DownloadUrl)
    {
        /// <summary>Check if a program display name matches this rule.</summary>
        public bool MatchesName(string displayName) =>
            NamePatterns.Any(pattern =>
                displayName.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Defines a pattern for detecting end-of-life software.</summary>
    private record EolPattern(string Name, Regex Regex, string Reason, Severity Severity);

    #endregion
}
