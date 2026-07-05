using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Update status, pending updates, and last update date.
/// </summary>
public class UpdateAudit : AuditModuleBase
{
    public override string Name => "Update Audit";
    public override string Category => "Updates";
    public override string Description => "Checks Windows Update status, pending updates, and last install date.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        await CheckWindowsSupportStatus(result, cancellationToken);
        await CheckLastUpdateDate(result, cancellationToken);
        await CheckPendingUpdates(result, cancellationToken);
        await CheckAutoUpdateSettings(result, cancellationToken);
        await CheckPendingReboot(result, cancellationToken);
    }

    private async Task CheckWindowsSupportStatus(AuditResult result, CancellationToken ct)
    {
        // The single most important update finding: is this Windows *build* still
        // serviced at all? A machine on an out-of-support feature update receives
        // NO security fixes regardless of how recently it "last updated", so this
        // ranks above the last-hotfix-date heuristic. Read the build number and
        // classify it against Microsoft's published lifecycle table below.
        var output = await ShellHelper.RunPowerShellAsync(
            @"$os = Get-CimInstance Win32_OperatingSystem
            $ver = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
            '{0}|{1}|{2}' -f $os.Caption, $os.BuildNumber, $ver", ct);

        var parts = output.Trim().Split('|');
        var caption = parts.Length > 0 ? parts[0].Trim() : string.Empty;
        var displayVersion = parts.Length > 2 ? parts[2].Trim() : string.Empty;

        if (parts.Length < 2 || !int.TryParse(parts[1].Trim(), out int build) || build <= 0)
        {
            result.Findings.Add(Finding.Info(
                "Windows Support Status Unknown",
                "Could not determine the Windows build number to check its support lifecycle.",
                Category));
            return;
        }

        var status = ClassifyWindowsSupport(build, DateTime.UtcNow);
        var label = string.IsNullOrEmpty(displayVersion)
            ? $"{caption} (build {build})"
            : $"{caption} {displayVersion} (build {build})";

        switch (status.Level)
        {
            case Severity.Critical:
                result.Findings.Add(Finding.Critical(
                    "Windows Build Out of Support",
                    $"{label} reached end of support on {status.EndDate:yyyy-MM-dd} and no longer receives security updates. " +
                    "Unpatched OS vulnerabilities cannot be remediated on this build.",
                    Category,
                    "Upgrade to a supported Windows feature update (or a newer Windows release) to resume receiving security patches.",
                    "Start-Process ms-settings:windowsupdate"));
                break;
            case Severity.Warning:
                result.Findings.Add(Finding.Warning(
                    "Windows Build Approaching End of Support",
                    $"{label} reaches end of support on {status.EndDate:yyyy-MM-dd} (in {status.DaysRemaining} day(s)). " +
                    "After that date this build stops receiving security updates.",
                    Category,
                    "Plan a feature-update upgrade before the end-of-support date to avoid running an unpatched build.",
                    "Start-Process ms-settings:windowsupdate"));
                break;
            case Severity.Pass:
                result.Findings.Add(Finding.Pass(
                    "Windows Build Supported",
                    status.EndDate.HasValue
                        ? $"{label} is within its support lifecycle (end of support {status.EndDate:yyyy-MM-dd})."
                        : $"{label} is a current, supported Windows build.",
                    Category));
                break;
            default:
                result.Findings.Add(Finding.Info(
                    "Windows Support Status Unrecognized",
                    $"{label}: this build is not in the known lifecycle table, so its support status could not be confirmed. " +
                    "It may be a very new or insider build.",
                    Category));
                break;
        }
    }

    /// <summary>
    /// Result of classifying a Windows build against the support-lifecycle table.
    /// </summary>
    public readonly record struct WindowsSupportStatus(Severity Level, DateTime? EndDate, int DaysRemaining);

    /// <summary>
    /// Pure, side-effect-free classification of a Windows build number against
    /// Microsoft's published end-of-servicing dates. Kept static and dependency
    /// free so it can be unit-tested deterministically for any (build, date).
    ///
    /// The <paramref name="nowUtc"/> is compared against the *latest* end-of-support
    /// date across editions for that feature update (Enterprise/Education, which
    /// outlast Home/Pro). Using the most generous date means a still-serviced
    /// machine is never mis-flagged Critical; consumer editions that die earlier
    /// are covered by the general last-update-date and pending-update checks.
    /// </summary>
    /// <param name="build">OS build number (e.g. 19045 for Windows 10 22H2).</param>
    /// <param name="nowUtc">The reference "now" (UTC).</param>
    /// <param name="warnWithinDays">Window before EOS to raise a Warning. Default 60.</param>
    public static WindowsSupportStatus ClassifyWindowsSupport(int build, DateTime nowUtc, int warnWithinDays = 60)
    {
        // build -> latest documented end-of-support date (UTC midnight).
        // Dates are Microsoft Lifecycle end-of-servicing for the feature update.
        // Only builds with a known, fixed EOS date are listed; anything newer or
        // unknown returns Info (do not guess a date we don't have).
        var eos = build switch
        {
            // Windows 11 feature updates (build >= 22000)
            26100 => new DateTime(2027, 10, 12), // 24H2 (Ent/Edu)
            22631 => new DateTime(2026, 11, 10), // 23H2 (Ent/Edu)
            22621 => new DateTime(2025, 10, 14), // 22H2 (Ent/Edu)
            22000 => new DateTime(2024, 10, 8),  // 21H2 (Ent/Edu)
            // Windows 10 feature updates
            19045 => new DateTime(2025, 10, 14), // 22H2 - final Windows 10 (all editions)
            19044 => new DateTime(2024, 6, 11),  // 21H2 (Ent/Edu/IoT)
            19043 => new DateTime(2022, 12, 13), // 21H1
            19042 => new DateTime(2023, 5, 9),   // 20H2 (Ent/Edu)
            19041 => new DateTime(2021, 12, 14), // 2004
            18363 => new DateTime(2022, 5, 10),  // 1909 (Ent/Edu)
            _ => (DateTime?)null,
        };

        if (eos is null)
        {
            // No known EOS date for this build. If it's newer than the newest build
            // we track, treat it as a current supported build (Pass, no date);
            // otherwise Info (genuinely unrecognized, e.g. an old Server/insider build).
            if (build > 26100)
            {
                return new WindowsSupportStatus(Severity.Pass, null, 0);
            }
            return new WindowsSupportStatus(Severity.Info, null, 0);
        }

        var end = eos.Value;
        if (nowUtc.Date > end.Date)
        {
            return new WindowsSupportStatus(Severity.Critical, end, 0);
        }

        var daysRemaining = (int)Math.Ceiling((end.Date - nowUtc.Date).TotalDays);
        if (daysRemaining <= warnWithinDays)
        {
            return new WindowsSupportStatus(Severity.Warning, end, daysRemaining);
        }

        return new WindowsSupportStatus(Severity.Pass, end, daysRemaining);
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
        // Use registry and update history (fast) instead of COM Search (can take minutes)
        var output = await ShellHelper.RunPowerShellAsync(
            @"$indicators = 0
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $indicators++ }
            try {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $history = $searcher.QueryHistory(0, 20)
                $failed = @($history | Where-Object { $_.ResultCode -eq 4 -or $_.ResultCode -eq 5 }).Count
                $indicators += $failed
            } catch { }
            $indicators", ct);

        if (int.TryParse(output.Trim(), out int pendingCount))
        {
            if (pendingCount > 0)
            {
                var severity = pendingCount > 5 ? Severity.Warning : Severity.Info;
                result.Findings.Add(new Finding
                {
                    Title = $"{pendingCount} Update Issue(s) Detected",
                    Description = $"Found {pendingCount} indicators of pending or failed updates.",
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
                    "No indicators of pending or failed Windows updates found.",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Info(
                "Update Status Check Incomplete",
                "Could not fully determine pending update status.",
                Category));
        }
    }

    private async Task CheckAutoUpdateSettings(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"try {
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
