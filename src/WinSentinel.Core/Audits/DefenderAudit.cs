using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Defender status, real-time protection, and definition freshness.
/// </summary>
public class DefenderAudit : IAuditModule
{
    public string Name => "Defender Audit";
    public string Category => "Defender";
    public string Description => "Checks Windows Defender status, real-time protection, and antivirus definition freshness.";

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
            await CheckRealTimeProtection(result, cancellationToken);
            await CheckDefinitionFreshness(result, cancellationToken);
            await CheckCloudProtection(result, cancellationToken);
            await CheckTamperProtection(result, cancellationToken);
            await CheckQuickScanAge(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckRealTimeProtection(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).DisableRealtimeMonitoring", ct);

        if (output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                "Real-Time Protection Disabled",
                "Windows Defender real-time protection is DISABLED. Malware can run without detection.",
                Category,
                "Enable real-time protection immediately.",
                "Set-MpPreference -DisableRealtimeMonitoring $false"));
        }
        else if (output.Trim().Equals("False", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "Real-Time Protection Enabled",
                "Windows Defender real-time protection is active.",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Real-Time Protection Status Unknown",
                "Could not determine real-time protection status. A third-party antivirus may be managing protection.",
                Category));
        }
    }

    private async Task CheckDefinitionFreshness(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpComputerStatus).AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm:ss')", ct);

        if (DateTime.TryParse(output.Trim(), out DateTime lastUpdated))
        {
            var hoursSinceUpdate = (DateTime.Now - lastUpdated).TotalHours;

            if (hoursSinceUpdate > 72)
            {
                result.Findings.Add(Finding.Critical(
                    "Antivirus Definitions Severely Outdated",
                    $"Virus definitions were last updated {hoursSinceUpdate:F0} hours ago ({lastUpdated:g}). System is vulnerable to new threats.",
                    Category,
                    "Update antivirus definitions immediately.",
                    "Update-MpSignature"));
            }
            else if (hoursSinceUpdate > 24)
            {
                result.Findings.Add(Finding.Warning(
                    "Antivirus Definitions Outdated",
                    $"Virus definitions were last updated {hoursSinceUpdate:F0} hours ago ({lastUpdated:g}).",
                    Category,
                    "Update antivirus definitions.",
                    "Update-MpSignature"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Antivirus Definitions Current",
                    $"Virus definitions were last updated {hoursSinceUpdate:F0} hours ago ({lastUpdated:g}).",
                    Category));
            }
        }
    }

    private async Task CheckCloudProtection(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).MAPSReporting", ct);

        if (int.TryParse(output.Trim(), out int mapsLevel))
        {
            if (mapsLevel == 0)
            {
                result.Findings.Add(Finding.Warning(
                    "Cloud Protection Disabled",
                    "Microsoft cloud-based protection (MAPS) is disabled. Cloud protection provides faster detection of new threats.",
                    Category,
                    "Enable cloud-based protection for better threat detection.",
                    "Set-MpPreference -MAPSReporting Advanced"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Cloud Protection Enabled",
                    $"Microsoft cloud-based protection is enabled (level: {mapsLevel}).",
                    Category));
            }
        }
    }

    private async Task CheckTamperProtection(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpComputerStatus).IsTamperProtected", ct);

        if (output.Trim().Equals("False", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "Tamper Protection Disabled",
                "Tamper Protection is disabled. Malware could potentially modify or disable Windows Defender settings.",
                Category,
                "Enable Tamper Protection in Windows Security settings.",
                "Start-Process 'windowsdefender://ThreatSettings'"));
        }
        else if (output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "Tamper Protection Enabled",
                "Tamper Protection is active, preventing unauthorized changes to security settings.",
                Category));
        }
    }

    private async Task CheckQuickScanAge(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpComputerStatus).QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss')", ct);

        if (DateTime.TryParse(output.Trim(), out DateTime lastScan))
        {
            var daysSinceScan = (DateTime.Now - lastScan).Days;

            if (daysSinceScan > 14)
            {
                result.Findings.Add(Finding.Warning(
                    "No Recent Quick Scan",
                    $"Last quick scan was {daysSinceScan} days ago ({lastScan:d}). Regular scans help detect dormant threats.",
                    Category,
                    "Run a quick scan to check for threats.",
                    "Start-MpScan -ScanType QuickScan"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Recent Scan Completed",
                    $"Last quick scan was {daysSinceScan} days ago ({lastScan:d}).",
                    Category));
            }
        }
    }
}
