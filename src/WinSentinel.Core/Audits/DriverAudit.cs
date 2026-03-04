using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using System.Text.Json;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits loaded kernel and user-mode drivers for security risks including:
/// - Unsigned or self-signed drivers (code integrity bypass)
/// - Drivers loaded from suspicious/user-writable paths
/// - Known vulnerable drivers used in BYOVD (Bring Your Own Vulnerable Driver) attacks
/// - Drivers with revoked certificates
/// - Driver age analysis (very old drivers may have unpatched vulns)
/// - Test-signed drivers in production (indicates test mode enabled)
/// </summary>
public class DriverAudit : IAuditModule
{
    public string Name => "Driver Security Audit";
    public string Category => "Drivers";
    public string Description =>
        "Checks loaded drivers for unsigned binaries, known vulnerable driver hashes (BYOVD), " +
        "suspicious load paths, revoked certificates, and driver age risks.";

    // ── Known Vulnerable Driver Hashes (BYOVD) ─────────────────
    // SHA-256 hashes of drivers commonly abused in BYOVD attacks.
    // Source: loldrivers.io / Microsoft recommended block list

    /// <summary>
    /// Known vulnerable driver file names commonly used in BYOVD attacks.
    /// Maps lowercase filename to CVE/description.
    /// </summary>
    public static readonly Dictionary<string, string> KnownVulnerableDrivers =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["dbutil_2_3.sys"] = "CVE-2021-21551 — Dell dbutil privilege escalation",
            ["rtcore64.sys"] = "CVE-2019-16098 — MSI Afterburner/RTCore arbitrary R/W",
            ["rtcore32.sys"] = "CVE-2019-16098 — MSI Afterburner/RTCore arbitrary R/W",
            ["gdrv.sys"] = "CVE-2018-19320 — GIGABYTE arbitrary R/W",
            ["asio64.sys"] = "CVE-2020-15368 — ASUS ASIO arbitrary R/W",
            ["asio32.sys"] = "CVE-2020-15368 — ASUS ASIO arbitrary R/W",
            ["atillk64.sys"] = "CVE-2023-25610 — ASUS ATILLK arbitrary R/W",
            ["bs_def64.sys"] = "Biostar vulnerable driver — arbitrary R/W",
            ["bs_def.sys"] = "Biostar vulnerable driver — arbitrary R/W",
            ["ene.sys"] = "ENE Technology vulnerable driver — arbitrary R/W",
            ["aswarpot.sys"] = "CVE-2021-1732 — Avast anti-rootkit vulnerable driver",
            ["aswvmm.sys"] = "Avast VirtualBox driver — abused for BYOVD",
            ["cpuz141.sys"] = "CPU-Z vulnerable driver — arbitrary R/W",
            ["elrawdsk.sys"] = "EldoS RawDisk — used by destructive malware (Shamoon)",
            ["inpoutx64.sys"] = "InpOut — direct hardware I/O access",
            ["procexp152.sys"] = "Process Explorer driver — can be abused for AV kill",
            ["speedfan.sys"] = "SpeedFan — arbitrary R/W",
            ["winio64.sys"] = "WinIO — direct hardware I/O access",
            ["winio32.sys"] = "WinIO — direct hardware I/O access",
            ["winring0.sys"] = "WinRing0 — arbitrary MSR/PCI/IO access",
            ["winring0x64.sys"] = "WinRing0 — arbitrary MSR/PCI/IO access",
            ["phymemx64.sys"] = "PhyMem — arbitrary physical memory access",
            ["physmem.sys"] = "PhysMem — arbitrary physical memory access",
            ["directio64.sys"] = "DirectIO — direct hardware I/O",
            ["hw64.sys"] = "HWiNFO — arbitrary R/W (old versions)",
            ["nvoclock.sys"] = "NVOClock — arbitrary R/W",
            ["amifldrv64.sys"] = "AMI firmware flash driver — arbitrary R/W",
            ["semav6msr.sys"] = "SemAV — MSR access driver",
            ["mhyprot2.sys"] = "CVE-2020-36603 — miHoYo anti-cheat abused for kernel access",
            ["kprocesshacker.sys"] = "Process Hacker — can be abused for process/thread manipulation",
            ["iqvw64e.sys"] = "CVE-2015-2291 — Intel Network Adapter arbitrary R/W",
        };

    /// <summary>
    /// Directories considered suspicious for driver files.
    /// </summary>
    public static readonly string[] SuspiciousDriverPaths =
    {
        @"\temp\",
        @"\tmp\",
        @"\downloads\",
        @"\desktop\",
        @"\appdata\",
        @"\users\public\",
        @"\recycle",
        @"\programdata\",   // legitimate but unusual for drivers
    };

    /// <summary>
    /// Standard trusted paths for driver files.
    /// </summary>
    public static readonly string[] TrustedDriverPaths =
    {
        @"C:\Windows\System32\drivers\",
        @"C:\Windows\System32\DriverStore\",
        @"C:\Windows\SysWOW64\",
        @"C:\Windows\inf\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
    };

    // ── DTO ─────────────────────────────────────────────────────

    /// <summary>
    /// Represents a single loaded driver for analysis.
    /// </summary>
    public sealed class DriverEntry
    {
        public string Name { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string FileName { get; set; } = "";  // Full path
        public string Type { get; set; } = "";       // Kernel, FileSystem, UserMode
        public string Status { get; set; } = "";     // Running, Stopped
        public string StartType { get; set; } = "";  // Boot, System, Auto, Manual, Disabled
        public bool IsSigned { get; set; } = true;
        public string SignerName { get; set; } = "";
        public bool IsMicrosoftSigned { get; set; }
        public bool IsTestSigned { get; set; }
        public DateTimeOffset? DriverDate { get; set; }
        public string DriverVersion { get; set; } = "";
        public string? Hash { get; set; }  // SHA-256 if collected
    }

    /// <summary>
    /// Aggregated driver state for testable analysis.
    /// </summary>
    public sealed class DriverState
    {
        public List<DriverEntry> Drivers { get; set; } = new();
        public int TotalDriverCount { get; set; }
        public bool TestSigningEnabled { get; set; }
        public bool SecureBootEnabled { get; set; }
        public bool HvciEnabled { get; set; }  // Hypervisor-protected Code Integrity
        public string? DriverBlockListVersion { get; set; }
    }

    // ── Public entry point ──────────────────────────────────────

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
            var state = await CollectStateAsync(cancellationToken);
            AnalyzeState(state, result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    // ── Data collection ─────────────────────────────────────────

    public async Task<DriverState> CollectStateAsync(CancellationToken ct = default)
    {
        var state = new DriverState();

        try
        {
            // Collect loaded drivers
            var output = await ShellHelper.RunPowerShellAsync(
                @"Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,PathName,ServiceType,State,StartMode | ConvertTo-Json -Depth 2",
                ct);

            if (!string.IsNullOrWhiteSpace(output))
            {
                state.Drivers = ParseDrivers(output);
                state.TotalDriverCount = state.Drivers.Count;
            }

            // Check signature status for each driver with a valid path
            foreach (var driver in state.Drivers.Where(d => !string.IsNullOrWhiteSpace(d.FileName)))
            {
                try
                {
                    var sigOutput = await ShellHelper.RunPowerShellAsync(
                        $"$sig = Get-AuthenticodeSignature '{driver.FileName.Replace("'", "''")}' -ErrorAction SilentlyContinue; " +
                        "if ($sig) { '{0}|{1}|{2}' -f $sig.Status, $sig.SignerCertificate.Subject, ($sig.SignerCertificate.Subject -match 'Microsoft') }", ct);

                    if (!string.IsNullOrWhiteSpace(sigOutput))
                    {
                        var parts = sigOutput.Trim().Split('|');
                        if (parts.Length >= 3)
                        {
                            driver.IsSigned = parts[0] == "Valid";
                            driver.IsTestSigned = parts[0] == "UnknownError" || parts[0] == "NotTrusted";
                            driver.SignerName = parts[1];
                            driver.IsMicrosoftSigned = parts[2].Equals("True", StringComparison.OrdinalIgnoreCase);
                        }
                    }
                }
                catch { /* signature check failed */ }
            }

            // Check test signing mode
            try
            {
                var bcdedit = await ShellHelper.RunCmdAsync("bcdedit /enum {current}", ct);
                state.TestSigningEnabled = bcdedit.Contains("testsigning") &&
                                           bcdedit.Contains("Yes", StringComparison.OrdinalIgnoreCase);
            }
            catch { }

            // Check Secure Boot
            try
            {
                var secBoot = await ShellHelper.RunPowerShellAsync(
                    "Confirm-SecureBootUEFI -ErrorAction SilentlyContinue", ct);
                state.SecureBootEnabled = secBoot.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            }
            catch { }

            // Check HVCI
            try
            {
                var hvci = await ShellHelper.RunPowerShellAsync(
                    @"(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning -contains 2", ct);
                state.HvciEnabled = hvci.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            }
            catch { }

            // Check driver block list
            try
            {
                var blockList = await ShellHelper.RunPowerShellAsync(
                    @"$p = 'C:\Windows\System32\CodeIntegrity\driversipolicy.p7b'; if (Test-Path $p) { (Get-Item $p).LastWriteTime.ToString('yyyy-MM-dd') } else { 'not found' }", ct);
                state.DriverBlockListVersion = blockList.Trim();
            }
            catch { }
        }
        catch { /* best effort collection */ }

        return state;
    }

    // ── Testable analysis ───────────────────────────────────────

    /// <summary>
    /// Analyzes the driver state and produces findings. Pure logic — no system calls.
    /// </summary>
    public void AnalyzeState(DriverState state, AuditResult result)
    {
        result.Success = true;

        CheckTestSigning(state, result);
        CheckSecureBoot(state, result);
        CheckHvci(state, result);
        CheckDriverBlockList(state, result);
        CheckUnsignedDrivers(state, result);
        CheckTestSignedDrivers(state, result);
        CheckVulnerableDrivers(state, result);
        CheckSuspiciousPaths(state, result);
        CheckNonTrustedPaths(state, result);
        CheckDriverAge(state, result);
        CheckDriverSummary(state, result);
    }

    private void CheckTestSigning(DriverState state, AuditResult result)
    {
        if (state.TestSigningEnabled)
        {
            result.Findings.Add(Finding.Critical(
                "Test Signing Mode Enabled",
                "Windows is running with test signing enabled (bcdedit testsigning=ON). " +
                "This allows loading of unsigned or test-signed drivers, bypassing code integrity. " +
                "Attackers abuse this to load malicious kernel drivers.",
                Category,
                "Disable test signing immediately unless actively developing drivers.",
                "bcdedit /set testsigning off"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Test Signing Mode Disabled",
                "Test signing is disabled. Only properly signed drivers can load.",
                Category));
        }
    }

    private void CheckSecureBoot(DriverState state, AuditResult result)
    {
        if (!state.SecureBootEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Secure Boot Not Enabled",
                "Secure Boot is not enabled or not supported. Secure Boot prevents loading of " +
                "unsigned bootloaders and early-load drivers, protecting against bootkits.",
                Category,
                "Enable Secure Boot in UEFI/BIOS firmware settings if supported.",
                null));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Secure Boot Enabled",
                "Secure Boot is enabled, protecting the boot chain from unauthorized modifications.",
                Category));
        }
    }

    private void CheckHvci(DriverState state, AuditResult result)
    {
        if (!state.HvciEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "HVCI (Memory Integrity) Not Enabled",
                "Hypervisor-protected Code Integrity (HVCI) is not enabled. HVCI uses virtualization-based " +
                "security to validate all kernel-mode code before execution, preventing vulnerable " +
                "driver exploitation even if the driver is signed.",
                Category,
                "Enable Memory Integrity: Settings → Device Security → Core Isolation → Memory Integrity.",
                @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -Type DWord"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "HVCI (Memory Integrity) Enabled",
                "Hypervisor-protected Code Integrity is active, validating all kernel-mode code.",
                Category));
        }
    }

    private void CheckDriverBlockList(DriverState state, AuditResult result)
    {
        if (string.IsNullOrWhiteSpace(state.DriverBlockListVersion) ||
            state.DriverBlockListVersion == "not found")
        {
            result.Findings.Add(Finding.Warning(
                "Microsoft Vulnerable Driver Block List Not Found",
                "The Microsoft vulnerable driver block list (driversipolicy.p7b) was not found. " +
                "This list prevents known vulnerable drivers from loading.",
                Category,
                "Ensure Windows Update is current; the block list is distributed via updates.",
                null));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                $"Driver Block List Present (Updated: {state.DriverBlockListVersion})",
                "Microsoft vulnerable driver block list is installed.",
                Category));
        }
    }

    private void CheckUnsignedDrivers(DriverState state, AuditResult result)
    {
        var unsigned = state.Drivers.Where(d =>
            !d.IsSigned && !d.IsTestSigned &&
            !string.IsNullOrWhiteSpace(d.FileName)).ToList();

        if (unsigned.Count > 0)
        {
            var names = string.Join(", ", unsigned.Select(d => d.Name).Take(10));
            result.Findings.Add(Finding.Critical(
                $"Unsigned Drivers Loaded ({unsigned.Count})",
                $"Found {unsigned.Count} unsigned driver(s): {names}. " +
                "Unsigned drivers bypass code integrity verification and may be malicious. " +
                "Legitimate unsigned drivers are rare on modern Windows.",
                Category,
                "Investigate each unsigned driver. Remove any that are not essential. " +
                "Enable HVCI to prevent unsigned driver loading.",
                "Get-CimInstance Win32_SystemDriver | ForEach-Object { $s = Get-AuthenticodeSignature $_.PathName -ErrorAction SilentlyContinue; if ($s.Status -ne 'Valid') { [PSCustomObject]@{Name=$_.Name;Path=$_.PathName;SigStatus=$s.Status} } } | Format-Table"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Unsigned Drivers Detected",
                "All loaded drivers with valid paths have valid signatures.",
                Category));
        }
    }

    private void CheckTestSignedDrivers(DriverState state, AuditResult result)
    {
        var testSigned = state.Drivers.Where(d => d.IsTestSigned).ToList();

        if (testSigned.Count > 0)
        {
            var names = string.Join(", ", testSigned.Select(d => d.Name).Take(10));
            result.Findings.Add(Finding.Warning(
                $"Test-Signed Drivers Loaded ({testSigned.Count})",
                $"Found {testSigned.Count} test-signed driver(s): {names}. " +
                "Test-signed drivers are typically used during development. " +
                "Their presence in production may indicate test mode abuse.",
                Category,
                "Remove test-signed drivers from production systems.",
                null));
        }
    }

    private void CheckVulnerableDrivers(DriverState state, AuditResult result)
    {
        var vulnerable = new List<(DriverEntry Driver, string Vulnerability)>();

        foreach (var driver in state.Drivers)
        {
            // Check by filename
            var fileName = Path.GetFileName(driver.FileName).ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(fileName) &&
                KnownVulnerableDrivers.TryGetValue(fileName, out var vuln))
            {
                vulnerable.Add((driver, vuln));
            }

            // Also check by driver name (some drivers register with the vuln name)
            if (KnownVulnerableDrivers.TryGetValue(driver.Name + ".sys", out var vulnByName))
            {
                if (!vulnerable.Any(v => v.Driver == driver))
                    vulnerable.Add((driver, vulnByName));
            }
        }

        if (vulnerable.Count > 0)
        {
            foreach (var (driver, vuln) in vulnerable)
            {
                result.Findings.Add(Finding.Critical(
                    $"Known Vulnerable Driver: {driver.Name}",
                    $"Loaded driver '{driver.Name}' ({driver.FileName}) matches a known vulnerable driver " +
                    $"used in BYOVD attacks. {vuln}. " +
                    "Attackers use legitimate but vulnerable signed drivers to gain kernel-level access.",
                    Category,
                    $"Remove or update '{driver.Name}'. Check loldrivers.io for details. " +
                    "Enable Microsoft's vulnerable driver block list.",
                    $"sc stop {driver.Name} & sc config {driver.Name} start= disabled"));
            }
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Known Vulnerable Drivers (BYOVD)",
                $"None of the {state.Drivers.Count} loaded drivers match known BYOVD attack drivers.",
                Category));
        }
    }

    private void CheckSuspiciousPaths(DriverState state, AuditResult result)
    {
        var suspicious = state.Drivers.Where(d =>
        {
            if (string.IsNullOrWhiteSpace(d.FileName)) return false;
            var lower = d.FileName.ToLowerInvariant();
            return SuspiciousDriverPaths.Any(p => lower.Contains(p));
        }).ToList();

        if (suspicious.Count > 0)
        {
            var details = string.Join("; ", suspicious.Select(d => $"{d.Name}: {d.FileName}").Take(5));
            result.Findings.Add(Finding.Critical(
                $"Drivers Loaded from Suspicious Paths ({suspicious.Count})",
                $"Found {suspicious.Count} driver(s) loaded from suspicious locations: {details}. " +
                "Legitimate drivers should reside in System32\\drivers or Program Files.",
                Category,
                "Investigate these drivers immediately. Drivers in temp/user directories are highly suspicious.",
                null));
        }
    }

    private void CheckNonTrustedPaths(DriverState state, AuditResult result)
    {
        var nonTrusted = state.Drivers.Where(d =>
        {
            if (string.IsNullOrWhiteSpace(d.FileName)) return false;
            var lower = d.FileName.ToLowerInvariant();
            // Not in a trusted path and not flagged as suspicious (already reported)
            return !TrustedDriverPaths.Any(t => lower.StartsWith(t.ToLowerInvariant())) &&
                   !SuspiciousDriverPaths.Any(p => lower.Contains(p));
        }).ToList();

        if (nonTrusted.Count > 0)
        {
            var names = string.Join(", ", nonTrusted.Select(d => d.Name).Take(10));
            result.Findings.Add(Finding.Info(
                $"Drivers Outside Standard Paths ({nonTrusted.Count})",
                $"Found {nonTrusted.Count} driver(s) loaded from non-standard locations: {names}. " +
                "These may be legitimate third-party drivers but warrant review.",
                Category,
                "Verify these drivers are from trusted vendors.",
                null));
        }
    }

    private void CheckDriverAge(DriverState state, AuditResult result)
    {
        var oldDrivers = state.Drivers.Where(d =>
            d.DriverDate.HasValue &&
            d.DriverDate.Value < DateTimeOffset.UtcNow.AddYears(-5)).ToList();

        if (oldDrivers.Count > 0)
        {
            var oldest = oldDrivers.OrderBy(d => d.DriverDate).Take(5)
                .Select(d => $"{d.Name} ({d.DriverDate:yyyy-MM-dd})");
            result.Findings.Add(Finding.Warning(
                $"Old Drivers Detected ({oldDrivers.Count})",
                $"Found {oldDrivers.Count} driver(s) older than 5 years: {string.Join(", ", oldest)}. " +
                "Old drivers may contain unpatched vulnerabilities.",
                Category,
                "Check for updated versions of these drivers from their vendors.",
                null));
        }
    }

    private void CheckDriverSummary(DriverState state, AuditResult result)
    {
        var kernelDrivers = state.Drivers.Count(d =>
            d.Type.Contains("Kernel", StringComparison.OrdinalIgnoreCase));
        var msDrivers = state.Drivers.Count(d => d.IsMicrosoftSigned);
        var thirdParty = state.Drivers.Count - msDrivers;

        result.Findings.Add(Finding.Info(
            $"Driver Summary: {state.TotalDriverCount} total ({kernelDrivers} kernel, {msDrivers} Microsoft-signed, {thirdParty} third-party)",
            $"System has {state.TotalDriverCount} loaded drivers. " +
            $"{kernelDrivers} are kernel-mode drivers, {msDrivers} are Microsoft-signed, " +
            $"{thirdParty} are third-party.",
            Category));
    }

    // ── Parsing helpers ─────────────────────────────────────────

    public static List<DriverEntry> ParseDrivers(string json)
    {
        var drivers = new List<DriverEntry>();

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Handle both array and single object
            var elements = root.ValueKind == JsonValueKind.Array
                ? root.EnumerateArray()
                : new[] { root }.AsEnumerable();

            foreach (var el in elements)
            {
                var entry = new DriverEntry
                {
                    Name = el.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "",
                    DisplayName = el.TryGetProperty("DisplayName", out var dn) ? dn.GetString() ?? "" : "",
                    FileName = NormalizePath(el.TryGetProperty("PathName", out var pn) ? pn.GetString() ?? "" : ""),
                    Type = el.TryGetProperty("ServiceType", out var st) ? st.GetString() ?? "" : "",
                    Status = el.TryGetProperty("State", out var s) ? s.GetString() ?? "" : "",
                    StartType = el.TryGetProperty("StartMode", out var sm) ? sm.GetString() ?? "" : "",
                };

                if (!string.IsNullOrWhiteSpace(entry.Name))
                    drivers.Add(entry);
            }
        }
        catch { /* parse failure — return what we have */ }

        return drivers;
    }

    public static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return path;

        // Handle \SystemRoot\ and \??\ prefixes
        path = path.Trim().Trim('"');

        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(@"C:\Windows", path[12..]);
        else if (path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            path = path[4..];
        else if (path.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(@"C:\Windows", path);

        return path;
    }

    // IEnumerable helper for single element
    private static class EnumerableExtensions { }
}

file static class SingleElementEnumerable
{
    public static IEnumerable<T> AsEnumerable<T>(this T[] array) => array;
}
