using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows privacy settings: telemetry level, location tracking,
/// advertising ID, diagnostic data, clipboard sync, and activity history.
/// </summary>
public class PrivacyAudit : IAuditModule
{
    public string Name => "Privacy Audit";
    public string Category => "Privacy";
    public string Description => "Checks telemetry level, location tracking, advertising ID, diagnostic data, clipboard sync, and activity history.";

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
            CheckTelemetryLevel(result);
            CheckAdvertisingId(result);
            CheckLocationTracking(result);
            CheckDiagnosticData(result);
            CheckClipboardSync(result);
            CheckActivityHistory(result);
            CheckWiFiSense(result);
            await CheckRemoteAssistance(result, cancellationToken);
            CheckOnlineSpeechRecognition(result);
            CheckCameraMicPermissions(result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private void CheckTelemetryLevel(AuditResult result)
    {
        try
        {
            // Windows 10/11 telemetry setting: 0 = Security (Enterprise only), 1 = Basic, 2 = Enhanced, 3 = Full
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\DataCollection");
            var level = key?.GetValue("AllowTelemetry");

            // Also check the non-policy key
            using var key2 = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection");
            var level2 = key2?.GetValue("AllowTelemetry");

            int telemetryLevel = -1;
            if (level != null && int.TryParse(level.ToString(), out int v1))
                telemetryLevel = v1;
            else if (level2 != null && int.TryParse(level2.ToString(), out int v2))
                telemetryLevel = v2;

            switch (telemetryLevel)
            {
                case 0:
                    result.Findings.Add(Finding.Pass(
                        "Telemetry: Security Only",
                        "Windows telemetry is set to Security level (minimum data collection). Enterprise-only setting.",
                        Category));
                    break;
                case 1:
                    result.Findings.Add(Finding.Pass(
                        "Telemetry: Required/Basic",
                        "Windows telemetry is set to Required (Basic) level — only essential diagnostic data is sent.",
                        Category));
                    break;
                case 2:
                    result.Findings.Add(Finding.Warning(
                        "Telemetry: Enhanced",
                        "Windows telemetry is set to Enhanced level. Additional usage data beyond basic diagnostics is being collected.",
                        Category,
                        "Reduce telemetry to Basic/Required for better privacy.",
                        @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1"));
                    break;
                case 3:
                    result.Findings.Add(Finding.Warning(
                        "Telemetry: Full",
                        "Windows telemetry is set to Full (Optional). Microsoft collects enhanced diagnostic data including browsing, app usage, and error reports.",
                        Category,
                        "Reduce telemetry to Basic/Required for better privacy.",
                        @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1"));
                    break;
                default:
                    // If no policy is set, default on consumer Windows is Full/Optional
                    result.Findings.Add(Finding.Info(
                        "Telemetry: Default (Full/Optional)",
                        "No telemetry policy is configured. Consumer Windows defaults to Full/Optional diagnostic data collection.",
                        Category,
                        "Set telemetry to Basic/Required via Settings > Privacy > Diagnostics & feedback.",
                        @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1"));
                    break;
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Telemetry Level Unknown",
                "Could not determine the telemetry level. Registry access may be restricted.",
                Category));
        }
    }

    private void CheckAdvertisingId(AuditResult result)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo");
            var enabled = key?.GetValue("Enabled");

            if (enabled?.ToString() == "1")
            {
                result.Findings.Add(Finding.Warning(
                    "Advertising ID Enabled",
                    "The Windows advertising ID is enabled, allowing apps to track you across applications for targeted advertising.",
                    Category,
                    "Disable the advertising ID for better privacy.",
                    @"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0"));
            }
            else if (enabled?.ToString() == "0")
            {
                result.Findings.Add(Finding.Pass(
                    "Advertising ID Disabled",
                    "The Windows advertising ID is disabled. Apps cannot use it for cross-app tracking.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "Advertising ID Status Unknown",
                    "Could not determine advertising ID setting. It may be enabled by default.",
                    Category));
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Advertising ID Check Failed",
                "Could not check advertising ID status.",
                Category));
        }
    }

    private void CheckLocationTracking(AuditResult result)
    {
        try
        {
            // System-wide location setting
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location");
            var value = key?.GetValue("Value")?.ToString();

            if (value?.Equals("Deny", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Findings.Add(Finding.Pass(
                    "Location Tracking Disabled",
                    "System-wide location access is disabled. Apps cannot access your location.",
                    Category));
            }
            else if (value?.Equals("Allow", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Findings.Add(Finding.Info(
                    "Location Tracking Enabled",
                    "System-wide location access is enabled. Apps with permission can access your physical location.",
                    Category,
                    "Disable location access if not needed: Settings > Privacy > Location."));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "Location Setting Unknown",
                    "Could not determine location tracking status.",
                    Category));
            }

            // Check location history
            using var histKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location");
            // Location history is stored separately — check if location service is running
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Location Check Failed",
                "Could not check location tracking settings.",
                Category));
        }
    }

    private void CheckDiagnosticData(AuditResult result)
    {
        try
        {
            // Check if tailored experiences (personalized tips/ads based on diagnostics) are enabled
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy");
            var tailored = key?.GetValue("TailoredExperiencesWithDiagnosticDataEnabled");

            if (tailored?.ToString() == "1")
            {
                result.Findings.Add(Finding.Warning(
                    "Tailored Experiences Enabled",
                    "Windows uses your diagnostic data to provide personalized tips, ads, and recommendations.",
                    Category,
                    "Disable tailored experiences for better privacy.",
                    @"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Value 0"));
            }
            else if (tailored?.ToString() == "0")
            {
                result.Findings.Add(Finding.Pass(
                    "Tailored Experiences Disabled",
                    "Windows does not use diagnostic data for personalized recommendations.",
                    Category));
            }

            // Check feedback frequency
            using var fbKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Siuf\Rules");
            var numFeedback = fbKey?.GetValue("NumberOfSIUFInPeriod");

            if (numFeedback == null || numFeedback.ToString() != "0")
            {
                result.Findings.Add(Finding.Info(
                    "Feedback Prompts May Appear",
                    "Windows may show feedback prompts periodically. Consider disabling for a less intrusive experience.",
                    Category,
                    "Disable feedback prompts.",
                    @"New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Force | Out-Null; Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'NumberOfSIUFInPeriod' -Value 0"));
            }
        }
        catch
        {
            // Registry access issues — not critical
        }
    }

    private void CheckClipboardSync(AuditResult result)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Clipboard");
            var cloudEnabled = key?.GetValue("EnableClipboardHistory");
            var crossDevice = key?.GetValue("EnableCloudClipboard");

            if (crossDevice?.ToString() == "1")
            {
                result.Findings.Add(Finding.Warning(
                    "Cross-Device Clipboard Sync Enabled",
                    "Clipboard content is synced across your devices via the cloud. Sensitive data (passwords, tokens) copied to clipboard may be transmitted to Microsoft servers.",
                    Category,
                    "Disable cloud clipboard sync unless you actively need it.",
                    @"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Clipboard' -Name 'EnableCloudClipboard' -Value 0"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Cross-Device Clipboard Sync Disabled",
                    "Clipboard content is not synced across devices.",
                    Category));
            }

            if (cloudEnabled?.ToString() == "1")
            {
                result.Findings.Add(Finding.Info(
                    "Clipboard History Enabled",
                    "Clipboard history is enabled (Win+V). Sensitive data may be retained in clipboard history.",
                    Category,
                    "Review clipboard history settings: Settings > System > Clipboard."));
            }
        }
        catch
        {
            // Not critical
        }
    }

    private void CheckActivityHistory(AuditResult result)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\System");
            var publishActivity = key?.GetValue("PublishUserActivities");
            var uploadActivity = key?.GetValue("UploadUserActivities");

            // Also check the user-level setting
            using var userKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy");
            var activityFeed = userKey?.GetValue("ActivityFeed");

            bool uploadEnabled = uploadActivity?.ToString() != "0";
            bool publishEnabled = publishActivity?.ToString() != "0";

            if (uploadEnabled && publishEnabled)
            {
                result.Findings.Add(Finding.Info(
                    "Activity History Sync Enabled",
                    "Windows activity history is being collected and may be synced to Microsoft. This includes apps used, files opened, and websites visited.",
                    Category,
                    "Disable activity history sync: Settings > Privacy > Activity history.",
                    @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Value 0"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Activity History Sync Disabled",
                    "Windows activity history sync is disabled via policy.",
                    Category));
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Activity History Check Failed",
                "Could not determine activity history settings.",
                Category));
        }
    }

    private void CheckWiFiSense(AuditResult result)
    {
        try
        {
            // WiFi Sense auto-connects to suggested open hotspots
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config");
            var autoConnect = key?.GetValue("AutoConnectAllowedOEM");

            if (autoConnect?.ToString() == "1")
            {
                result.Findings.Add(Finding.Warning(
                    "Auto-Connect to Suggested Hotspots Enabled",
                    "Windows may automatically connect to suggested open Wi-Fi hotspots. This can expose traffic to untrusted networks.",
                    Category,
                    "Disable auto-connect to suggested hotspots in Wi-Fi settings.",
                    @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Value 0"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Auto-Connect to Hotspots Disabled",
                    "Windows does not auto-connect to suggested open Wi-Fi hotspots.",
                    Category));
            }
        }
        catch
        {
            // Key may not exist on newer Windows — that's fine
        }
    }

    private async Task CheckRemoteAssistance(AuditResult result, CancellationToken ct)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Remote Assistance");
            var allowRA = key?.GetValue("fAllowToGetHelp");

            if (allowRA?.ToString() == "1")
            {
                result.Findings.Add(Finding.Warning(
                    "Remote Assistance Enabled",
                    "Windows Remote Assistance is enabled. Someone could request to view or control your screen if you accept a connection.",
                    Category,
                    "Disable Remote Assistance if not needed.",
                    @"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Remote Assistance Disabled",
                    "Windows Remote Assistance is disabled.",
                    Category));
            }
        }
        catch
        {
            result.Findings.Add(Finding.Info(
                "Remote Assistance Check Failed",
                "Could not determine Remote Assistance status.",
                Category));
        }
    }

    private void CheckOnlineSpeechRecognition(AuditResult result)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy");
            var hasAccepted = key?.GetValue("HasAccepted");

            if (hasAccepted?.ToString() == "1")
            {
                result.Findings.Add(Finding.Info(
                    "Online Speech Recognition Enabled",
                    "Online speech recognition is enabled. Voice data may be sent to Microsoft cloud for processing.",
                    Category,
                    "Disable online speech recognition if not using voice features: Settings > Privacy > Speech."));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Online Speech Recognition Disabled",
                    "Online speech recognition is disabled. Voice data is not sent to the cloud.",
                    Category));
            }
        }
        catch
        {
            // Not critical
        }
    }

    private void CheckCameraMicPermissions(AuditResult result)
    {
        try
        {
            // Check system-wide camera access
            using var camKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam");
            var camValue = camKey?.GetValue("Value")?.ToString();

            if (camValue?.Equals("Allow", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Findings.Add(Finding.Info(
                    "Camera Access: System-Wide Allowed",
                    "Apps can request camera access. Review which apps have camera permission in Settings > Privacy > Camera.",
                    Category));
            }
            else if (camValue?.Equals("Deny", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Findings.Add(Finding.Pass(
                    "Camera Access: System-Wide Blocked",
                    "Camera access is blocked system-wide. No apps can use the camera.",
                    Category));
            }

            // Check system-wide microphone access
            using var micKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone");
            var micValue = micKey?.GetValue("Value")?.ToString();

            if (micValue?.Equals("Allow", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Findings.Add(Finding.Info(
                    "Microphone Access: System-Wide Allowed",
                    "Apps can request microphone access. Review which apps have microphone permission in Settings > Privacy > Microphone.",
                    Category));
            }
            else if (micValue?.Equals("Deny", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Findings.Add(Finding.Pass(
                    "Microphone Access: System-Wide Blocked",
                    "Microphone access is blocked system-wide. No apps can use the microphone.",
                    Category));
            }
        }
        catch
        {
            // Not critical — permissions system may vary
        }
    }
}
