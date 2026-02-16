using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Update status, pending updates, and last update date.
/// </summary>
public class UpdateAudit : IAuditModule
{
    public string Name => "Update Audit";
    public string Category => "Updates";
    public string Description => "Checks Windows Update status, pending updates, and last install date.";

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
            await CheckLastUpdateDate(result, cancellationToken);
            await CheckPendingUpdates(result, cancellationToken);
            await CheckAutoUpdateSettings(result, cancellationToken);
            await CheckPendingReboot(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckLastUpdateDate(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd')", ct);

        if (DateTime.TryParse(output.Trim(), out DateTime lastUpdate))
        {
            var daysSinceUpdate = (DateTime.Now - lastUpdate).Days;

            if (daysSinceUpdate > 60)
            {
                result.Findings.Add(Finding.Critical(
                    "System Severely Out of Date",
                    $"Last update was installed {daysSinceUpdate} days ago ({lastUpdate:yyyy-MM-dd}). Critical security patches may be missing.",
                    Category,
                    "Run Windows Update immediately to install all pending updates.",
                    "Start-Process ms-settings:windowsupdate"));
            }
            else if (daysSinceUpdate > 30)
            {
                result.Findings.Add(Finding.Warning(
                    "System Updates Overdue",
                    $"Last update was installed {daysSinceUpdate} days ago ({lastUpdate:yyyy-MM-dd}). Check for pending updates.",
                    Category,
                    "Run Windows Update to check for and install available updates.",
                    "Start-Process ms-settings:windowsupdate"));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "System Recently Updated",
                    $"Last update was installed {daysSinceUpdate} days ago ({lastUpdate:yyyy-MM-dd}).",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Unable to Determine Last Update Date",
                "Could not determine when the last update was installed.",
                Category));
        }
    }

    private async Task CheckPendingUpdates(AuditResult result, CancellationToken ct)
    {
        // Use COM-free approach via PowerShell to check pending updates
        var output = await ShellHelper.RunPowerShellAsync(
            @"try {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $searchResult = $searcher.Search('IsInstalled=0')
                $searchResult.Updates.Count
            } catch { Write-Output 'ERROR' }", ct);

        if (int.TryParse(output.Trim(), out int pendingCount))
        {
            if (pendingCount > 0)
            {
                var severity = pendingCount > 5 ? Severity.Warning : Severity.Info;
                result.Findings.Add(new Finding
                {
                    Title = $"{pendingCount} Pending Updates",
                    Description = $"There are {pendingCount} updates available but not yet installed.",
                    Severity = severity,
                    Category = Category,
                    Remediation = "Install all pending Windows updates.",
                    FixCommand = "Start-Process ms-settings:windowsupdate"
                });
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "No Pending Updates",
                    "All available Windows updates are installed.",
                    Category));
            }
        }
    }

    private async Task CheckAutoUpdateSettings(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"try {
                $au = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
                $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
                if ($key -and $key.NoAutoUpdate -eq 1) { 'DISABLED' }
                else { 'ENABLED' }
            } catch { 'UNKNOWN' }", ct);

        if (output.Trim().Contains("DISABLED"))
        {
            result.Findings.Add(Finding.Warning(
                "Automatic Updates Disabled",
                "Windows automatic updates are disabled via Group Policy. System may miss critical security patches.",
                Category,
                "Enable automatic updates or ensure a patch management solution is in place.",
                "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name 'NoAutoUpdate'"));
        }
        else if (output.Trim().Contains("ENABLED"))
        {
            result.Findings.Add(Finding.Pass(
                "Automatic Updates Enabled",
                "Windows automatic updates are enabled.",
                Category));
        }
    }

    private async Task CheckPendingReboot(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"$rebootPending = $false
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rebootPending = $true }
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootPending = $true }
            $rebootPending", ct);

        if (output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "Reboot Required",
                "A system reboot is pending to complete update installation. Security patches may not be fully applied.",
                Category,
                "Reboot the system to complete pending updates.",
                "shutdown /r /t 60 /c \"WinSentinel: Reboot to complete updates\""));
        }
    }
}
