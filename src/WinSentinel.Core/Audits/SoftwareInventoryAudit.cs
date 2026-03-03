using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits installed software for security risks including:
/// - Unsigned or tampered executables
/// - Programs installed in non-standard/suspicious locations
/// - Outdated software with known vulnerability indicators
/// - Potentially Unwanted Programs (PUPs) based on heuristic patterns
/// - Orphaned installations (uninstaller missing or broken)
/// </summary>
public class SoftwareInventoryAudit : IAuditModule
{
    public string Name => "Software Inventory Audit";
    public string Category => "Software";
    public string Description => "Scans installed programs for unsigned executables, outdated software, suspicious install locations, and potentially unwanted programs.";

    // Registry paths for installed software
    private static readonly string[] UninstallKeyPaths = new[]
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    };

    // Directories where legitimate software should be installed
    private static readonly string[] StandardInstallPaths = new[]
    {
        @"C:\Program Files",
        @"C:\Program Files (x86)",
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
    };

    // Known PUP publisher patterns (case-insensitive match)
    private static readonly string[] PupPublisherPatterns = new[]
    {
        "ask.com", "babylon", "conduit", "delta-homes", "driverupdate",
        "iobit", "mindspark", "mywebsearch", "opencandy", "softonic",
        "superfish", "wajam", "webcompanion", "webdiscover", "yontoo",
    };

    // Known PUP name patterns
    private static readonly string[] PupNamePatterns = new[]
    {
        "toolbar", "browser hijack", "search protect", "coupon",
        "pc cleaner", "driver updater", "registry cleaner",
        "system optimizer", "speed up", "booster", "adware",
    };

    // Suspicious install location patterns
    private static readonly string[] SuspiciousPathPatterns = new[]
    {
        @"\Temp\", @"\tmp\", @"\Downloads\", @"\Desktop\",
        @"\Recycle", @"\$Recycle",
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
            var inventory = CollectSoftwareInventory();

            CheckInventorySize(result, inventory);
            CheckSuspiciousLocations(result, inventory);
            CheckPotentiallyUnwantedPrograms(result, inventory);
            CheckOrphanedInstallations(result, inventory);
            await CheckUnsignedExecutables(result, inventory, cancellationToken);
            await CheckOutdatedSoftware(result, inventory, cancellationToken);
            CheckSoftwareAge(result, inventory);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    /// <summary>
    /// Collects a unified inventory of installed software from the registry.
    /// Reads from both HKLM and HKCU uninstall keys (32-bit and 64-bit).
    /// Excludes system components.
    /// </summary>
    public List<SoftwareEntry> CollectSoftwareInventory()
    {
        var entries = new List<SoftwareEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rootKey in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            foreach (var path in UninstallKeyPaths)
            {
                try
                {
                    using var key = rootKey.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var sub = key.OpenSubKey(subKeyName);
                            if (sub == null) continue;

                            var name = sub.GetValue("DisplayName")?.ToString();
                            if (string.IsNullOrWhiteSpace(name)) continue;

                            // De-duplicate by name + version
                            var version = sub.GetValue("DisplayVersion")?.ToString() ?? "";
                            var dedupeKey = $"{name}|{version}".ToLowerInvariant();
                            if (!seen.Add(dedupeKey)) continue;

                            entries.Add(new SoftwareEntry
                            {
                                Name = name,
                                Version = version,
                                Publisher = sub.GetValue("Publisher")?.ToString() ?? "",
                                InstallLocation = sub.GetValue("InstallLocation")?.ToString() ?? "",
                                InstallDate = sub.GetValue("InstallDate")?.ToString() ?? "",
                                UninstallString = sub.GetValue("UninstallString")?.ToString() ?? "",
                                RegistryHive = rootKey == Registry.LocalMachine ? "HKLM" : "HKCU",
                                RegistryPath = $"{path}\\{subKeyName}",
                                EstimatedSizeKB = sub.GetValue("EstimatedSize") is int size ? size : 0,
                                IsSystemComponent = sub.GetValue("SystemComponent") is int sc && sc == 1,
                            });
                        }
                        catch { /* Access denied or corrupted entry — skip */ }
                    }
                }
                catch { /* Access denied — skip */ }
            }
        }

        return entries.Where(e => !e.IsSystemComponent).ToList();
    }

    private void CheckInventorySize(AuditResult result, List<SoftwareEntry> inventory)
    {
        result.Findings.Add(Finding.Info(
            $"Installed Software: {inventory.Count} programs",
            $"Found {inventory.Count} non-system programs registered in the Windows installer database.",
            Category));

        if (inventory.Count > 200)
        {
            result.Findings.Add(Finding.Warning(
                "Very Large Software Inventory",
                $"{inventory.Count} programs installed — a large number increases attack surface. Consider removing unused software.",
                Category,
                "Review installed programs and uninstall any that are no longer needed. Use 'winget list' for a clean overview.",
                "winget list --source winget"));
        }
    }

    private void CheckSuspiciousLocations(AuditResult result, List<SoftwareEntry> inventory)
    {
        var suspicious = new List<string>();

        foreach (var entry in inventory)
        {
            if (string.IsNullOrWhiteSpace(entry.InstallLocation)) continue;

            foreach (var pattern in SuspiciousPathPatterns)
            {
                if (entry.InstallLocation.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    suspicious.Add($"{entry.Name} ({entry.InstallLocation})");
                    break;
                }
            }
        }

        if (suspicious.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"Software in Suspicious Locations ({suspicious.Count})",
                $"Programs installed in temporary or unusual directories: {string.Join("; ", suspicious.Take(10))}",
                Category,
                "Software installed in temp/download directories may indicate malware or improper installation. Verify these programs and reinstall from official sources if legitimate."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Software in Suspicious Locations",
                "All installed programs are in standard installation directories.",
                Category));
        }
    }

    private void CheckPotentiallyUnwantedPrograms(AuditResult result, List<SoftwareEntry> inventory)
    {
        var pups = new List<(SoftwareEntry Entry, string Reason)>();

        foreach (var entry in inventory)
        {
            if (!string.IsNullOrWhiteSpace(entry.Publisher))
            {
                foreach (var pattern in PupPublisherPatterns)
                {
                    if (entry.Publisher.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        pups.Add((entry, $"publisher matches known PUP: {pattern}"));
                        break;
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(entry.Name))
            {
                foreach (var pattern in PupNamePatterns)
                {
                    if (entry.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
                        !pups.Any(p => p.Entry == entry))
                    {
                        pups.Add((entry, $"name matches PUP pattern: {pattern}"));
                        break;
                    }
                }
            }
        }

        if (pups.Count > 0)
        {
            var details = pups.Take(10)
                .Select(p => $"{p.Entry.Name} v{p.Entry.Version} ({p.Reason})")
                .ToList();

            result.Findings.Add(Finding.Critical(
                $"Potentially Unwanted Programs ({pups.Count})",
                $"Detected programs matching known PUP patterns: {string.Join("; ", details)}",
                Category,
                "Uninstall potentially unwanted programs. These often bundle adware, browser hijackers, or spyware."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Potentially Unwanted Programs Detected",
                "No installed programs match known PUP publisher or name patterns.",
                Category));
        }
    }

    private void CheckOrphanedInstallations(AuditResult result, List<SoftwareEntry> inventory)
    {
        var orphaned = inventory
            .Where(e => string.IsNullOrWhiteSpace(e.UninstallString) &&
                        !string.IsNullOrWhiteSpace(e.InstallLocation))
            .ToList();

        if (orphaned.Count > 5)
        {
            var names = orphaned.Take(10).Select(e => e.Name).ToList();
            result.Findings.Add(Finding.Warning(
                $"Orphaned Software Entries ({orphaned.Count})",
                $"Programs with no uninstall string but a recorded install location — may indicate incomplete uninstalls or leftover malware: {string.Join(", ", names)}",
                Category,
                "Manually verify these programs. If no longer needed, remove their install directories and clean up registry entries."));
        }
        else if (orphaned.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Orphaned Software Entries: {orphaned.Count}",
                $"Found {orphaned.Count} programs without uninstall strings: {string.Join(", ", orphaned.Select(e => e.Name))}",
                Category));
        }
    }

    private async Task CheckUnsignedExecutables(AuditResult result, List<SoftwareEntry> inventory, CancellationToken ct)
    {
        var pathsToCheck = inventory
            .Where(e => !string.IsNullOrWhiteSpace(e.InstallLocation) && Directory.Exists(e.InstallLocation))
            .Select(e => (e.Name, e.InstallLocation))
            .Take(50)
            .ToList();

        if (pathsToCheck.Count == 0)
        {
            result.Findings.Add(Finding.Info(
                "Signature Check Skipped",
                "No install locations available for signature verification.",
                Category));
            return;
        }

        var pathList = string.Join(",", pathsToCheck.Select(p => $"'{EscapePsString(p.InstallLocation)}'"));
        var psCommand = $@"
            $paths = @({pathList})
            foreach ($p in $paths) {{
                $exes = Get-ChildItem $p -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 3
                foreach ($exe in $exes) {{
                    $sig = Get-AuthenticodeSignature $exe.FullName -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -ne 'Valid') {{
                        '{{0}}|{{1}}|{{2}}' -f $sig.Status, $exe.Name, $exe.DirectoryName
                    }}
                }}
            }}";

        try
        {
            var output = await ShellHelper.RunPowerShellAsync(psCommand, TimeSpan.FromSeconds(60), ct);
            var unsigned = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(l => l.Contains('|'))
                .Select(l =>
                {
                    var parts = l.Split('|', 3);
                    return new { Status = parts[0], File = parts.Length > 1 ? parts[1] : "", Path = parts.Length > 2 ? parts[2] : "" };
                })
                .ToList();

            if (unsigned.Count > 0)
            {
                var details = unsigned.Take(10)
                    .Select(u => $"{u.File} ({u.Status}) in {u.Path}")
                    .ToList();

                var severity = unsigned.Count > 5 ? Severity.Critical : Severity.Warning;
                result.Findings.Add(new Finding
                {
                    Title = $"Unsigned/Invalid Executables ({unsigned.Count})",
                    Description = $"Executables with invalid or missing Authenticode signatures: {string.Join("; ", details)}",
                    Severity = severity,
                    Category = Category,
                    Remediation = "Unsigned executables may be tampered with or from untrusted sources. Verify these files against known good hashes from the software vendor."
                });
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "All Checked Executables are Signed",
                    $"Verified Authenticode signatures on executables across {pathsToCheck.Count} install locations.",
                    Category));
            }
        }
        catch (Exception ex)
        {
            result.Findings.Add(Finding.Info(
                "Signature Check Incomplete",
                $"Could not complete signature verification: {ex.Message}",
                Category));
        }
    }

    private async Task CheckOutdatedSoftware(AuditResult result, List<SoftwareEntry> inventory, CancellationToken ct)
    {
        try
        {
            var output = await ShellHelper.RunPowerShellAsync(
                "winget upgrade --accept-source-agreements 2>$null | Select-String -Pattern '^\\S' | Measure-Object | Select-Object -ExpandProperty Count",
                TimeSpan.FromSeconds(45), ct);

            if (int.TryParse(output.Trim(), out int upgradeCount) && upgradeCount > 0)
            {
                var actualCount = Math.Max(0, upgradeCount - 3);

                if (actualCount > 20)
                {
                    result.Findings.Add(Finding.Warning(
                        $"Many Outdated Programs ({actualCount}+)",
                        $"Winget reports {actualCount}+ programs with available updates. Outdated software may contain known security vulnerabilities.",
                        Category,
                        "Run 'winget upgrade --all' to update all programs, or selectively update critical ones first."));
                }
                else if (actualCount > 0)
                {
                    result.Findings.Add(Finding.Info(
                        $"Software Updates Available: {actualCount}",
                        $"Winget reports {actualCount} programs with available updates.",
                        Category));
                }
                else
                {
                    result.Findings.Add(Finding.Pass(
                        "All Winget-Managed Software is Up-to-Date",
                        "No pending updates found via winget.",
                        Category));
                }
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Winget Upgrade Check Skipped",
                "Could not query winget for available updates. Ensure winget is installed.",
                Category));
        }
    }

    private void CheckSoftwareAge(AuditResult result, List<SoftwareEntry> inventory)
    {
        var veryOld = new List<SoftwareEntry>();
        var cutoff = DateTime.UtcNow.AddYears(-3);

        foreach (var entry in inventory)
        {
            if (string.IsNullOrWhiteSpace(entry.InstallDate)) continue;

            if (entry.InstallDate.Length == 8 &&
                DateTime.TryParseExact(entry.InstallDate, "yyyyMMdd",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var date))
            {
                if (date < cutoff)
                {
                    veryOld.Add(entry);
                }
            }
        }

        if (veryOld.Count > 10)
        {
            var oldest = veryOld.OrderBy(e => e.InstallDate).Take(10)
                .Select(e => $"{e.Name} (installed {FormatInstallDate(e.InstallDate)})")
                .ToList();

            result.Findings.Add(Finding.Warning(
                $"Very Old Software Installations ({veryOld.Count})",
                $"Programs installed more than 3 years ago that may be forgotten or abandoned: {string.Join("; ", oldest)}",
                Category,
                "Review old installations. If no longer needed, uninstall them to reduce attack surface."));
        }
        else if (veryOld.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Old Software: {veryOld.Count} programs over 3 years old",
                $"Found {veryOld.Count} programs installed more than 3 years ago.",
                Category));
        }
    }

    private static string EscapePsString(string value)
        => value.Replace("'", "''");

    private static string FormatInstallDate(string yyyymmdd)
    {
        if (yyyymmdd.Length == 8)
            return $"{yyyymmdd[0..4]}-{yyyymmdd[4..6]}-{yyyymmdd[6..8]}";
        return yyyymmdd;
    }

    /// <summary>
    /// Represents a single installed software entry from the registry.
    /// </summary>
    public record SoftwareEntry
    {
        public required string Name { get; init; }
        public string Version { get; init; } = "";
        public string Publisher { get; init; } = "";
        public string InstallLocation { get; init; } = "";
        public string InstallDate { get; init; } = "";
        public string UninstallString { get; init; } = "";
        public string RegistryHive { get; init; } = "";
        public string RegistryPath { get; init; } = "";
        public int EstimatedSizeKB { get; init; }
        public bool IsSystemComponent { get; init; }
    }
}
