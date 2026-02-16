using System.Management;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits system configuration: OS version, Secure Boot, BitLocker, UAC, RDP settings.
/// </summary>
public class SystemAudit : IAuditModule
{
    public string Name => "System Audit";
    public string Category => "System";
    public string Description => "Checks OS version, Secure Boot, BitLocker, UAC level, and RDP configuration.";

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
            await CheckOsVersion(result, cancellationToken);
            await CheckSecureBoot(result, cancellationToken);
            await CheckBitLocker(result, cancellationToken);
            CheckUacLevel(result);
            await CheckRdpConfig(result, cancellationToken);
            CheckDevGuard(result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckOsVersion(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"$os = Get-CimInstance Win32_OperatingSystem
            '{0}|{1}|{2}' -f $os.Caption, $os.Version, $os.BuildNumber", ct);

        var parts = output.Trim().Split('|');
        if (parts.Length >= 3)
        {
            var caption = parts[0];
            var version = parts[1];
            var build = parts[2];

            result.Findings.Add(Finding.Info(
                $"OS: {caption}",
                $"Version: {version}, Build: {build}",
                Category));

            // Check if OS is still supported (basic check)
            if (int.TryParse(build, out int buildNumber))
            {
                if (buildNumber < 19041) // Before Windows 10 2004
                {
                    result.Findings.Add(Finding.Critical(
                        "Outdated Windows Version",
                        $"Windows build {build} may no longer receive security updates.",
                        Category,
                        "Upgrade to the latest supported version of Windows.",
                        "Start-Process ms-settings:windowsupdate"));
                }
                else if (buildNumber < 22000) // Windows 10
                {
                    result.Findings.Add(Finding.Info(
                        "Windows 10 Detected",
                        "Running Windows 10. Consider upgrading to Windows 11 for enhanced security features.",
                        Category));
                }
                else
                {
                    result.Findings.Add(Finding.Pass(
                        "Modern Windows Version",
                        $"Running Windows 11 (build {build}) with current security features.",
                        Category));
                }
            }
        }
    }

    private async Task CheckSecureBoot(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "try { Confirm-SecureBootUEFI } catch { 'ERROR' }", ct);

        if (output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "Secure Boot Enabled",
                "UEFI Secure Boot is enabled, protecting against boot-level malware.",
                Category));
        }
        else if (output.Trim().Equals("False", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "Secure Boot Disabled",
                "UEFI Secure Boot is disabled. Boot-level malware (bootkits) could run undetected.",
                Category,
                "Enable Secure Boot in UEFI/BIOS settings."));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Secure Boot Status Unknown",
                "Could not determine Secure Boot status. This may require elevated permissions or UEFI firmware.",
                Category));
        }
    }

    private async Task CheckBitLocker(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"try {
                $vol = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
                if ($vol) { '{0}|{1}' -f $vol.ProtectionStatus, $vol.EncryptionMethod }
                else { 'NOT_AVAILABLE' }
            } catch { 'ERROR' }", ct);

        if (output.Contains("On", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "BitLocker Enabled on C:",
                $"BitLocker drive encryption is active on the system drive. {output.Trim()}",
                Category));
        }
        else if (output.Contains("Off", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "BitLocker Not Active on C:",
                "BitLocker drive encryption is not enabled on the system drive. Data could be accessed if the drive is removed.",
                Category,
                "Enable BitLocker on the system drive.",
                "manage-bde -on C:"));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "BitLocker Status Unknown",
                "Could not determine BitLocker status. This requires elevated permissions.",
                Category));
        }
    }

    private void CheckUacLevel(AuditResult result)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key == null) return;

            var enableLUA = key.GetValue("EnableLUA");
            var consentPrompt = key.GetValue("ConsentPromptBehaviorAdmin");
            var secureDesktop = key.GetValue("PromptOnSecureDesktop");

            if (enableLUA?.ToString() == "0")
            {
                result.Findings.Add(Finding.Critical(
                    "UAC Completely Disabled",
                    "User Account Control is DISABLED. All applications run with full admin privileges without prompting.",
                    Category,
                    "Enable UAC immediately.",
                    @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1"));
            }
            else if (consentPrompt?.ToString() == "0")
            {
                result.Findings.Add(Finding.Warning(
                    "UAC Set to Never Notify",
                    "UAC is enabled but set to never notify. Admin applications run without prompts.",
                    Category,
                    "Set UAC to at least 'Notify me only when apps try to make changes'.",
                    @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 5"));
            }
            else if (secureDesktop?.ToString() == "0")
            {
                result.Findings.Add(Finding.Info(
                    "UAC Secure Desktop Disabled",
                    "UAC prompts appear on the regular desktop instead of the secure desktop. Malware could potentially interact with UAC prompts.",
                    Category,
                    "Enable secure desktop for UAC prompts.",
                    @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "UAC Properly Configured",
                    "User Account Control is enabled with appropriate settings.",
                    Category));
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "UAC Status Unknown",
                "Could not determine UAC configuration.",
                Category));
        }
    }

    private async Task CheckRdpConfig(AuditResult result, CancellationToken ct)
    {
        // Check RDP security layer
        var output = await ShellHelper.RunPowerShellAsync(
            @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -ErrorAction SilentlyContinue).SecurityLayer", ct);

        if (int.TryParse(output.Trim(), out int secLayer))
        {
            if (secLayer == 0)
            {
                result.Findings.Add(Finding.Warning(
                    "RDP Using Legacy Security",
                    "RDP is configured to use RDP Security Layer (legacy). This is less secure than TLS/NLA.",
                    Category,
                    "Configure RDP to use TLS or NLA.",
                    @"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2"));
            }
            else if (secLayer >= 2)
            {
                result.Findings.Add(Finding.Pass(
                    "RDP Using TLS/NLA Security",
                    "RDP is configured to use TLS-based security.",
                    Category));
            }
        }

        // Check RDP port
        var portOutput = await ShellHelper.RunPowerShellAsync(
            @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -ErrorAction SilentlyContinue).PortNumber", ct);

        if (int.TryParse(portOutput.Trim(), out int rdpPort) && rdpPort == 3389)
        {
            result.Findings.Add(Finding.Info(
                "RDP Using Default Port (3389)",
                "RDP is configured on the default port. Consider changing to reduce automated scan exposure.",
                Category));
        }
    }

    private void CheckDevGuard(AuditResult result)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard");
            if (key != null)
            {
                var cgEnabled = key.GetValue("EnableVirtualizationBasedSecurity");
                if (cgEnabled?.ToString() == "1")
                {
                    result.Findings.Add(Finding.Pass(
                        "Virtualization-Based Security Enabled",
                        "VBS/Device Guard is enabled, providing hardware-level security isolation.",
                        Category));
                }
                else
                {
                    result.Findings.Add(Finding.Info(
                        "Virtualization-Based Security Not Enabled",
                        "VBS/Device Guard is not enabled. This provides additional hardware-level protection on supported hardware.",
                        Category));
                }
            }
        }
        catch { /* Access denied */ }
    }
}
