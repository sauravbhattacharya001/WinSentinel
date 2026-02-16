using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;
using Microsoft.Win32;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits startup items, scheduled tasks, and registry run keys.
/// </summary>
public class StartupAudit : IAuditModule
{
    public string Name => "Startup Audit";
    public string Category => "Startup";
    public string Description => "Checks startup items, scheduled tasks, and registry run keys for persistence mechanisms.";

    private static readonly string[] RunKeyPaths = new[]
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
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
            CheckRegistryRunKeys(result);
            await CheckStartupFolder(result, cancellationToken);
            await CheckScheduledTasks(result, cancellationToken);
            await CheckServices(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private void CheckRegistryRunKeys(AuditResult result)
    {
        var allEntries = new List<string>();
        var suspiciousEntries = new List<string>();

        // Check HKLM keys
        foreach (var path in RunKeyPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    allEntries.Add($"HKLM\\{path}: {valueName} = {value}");

                    // Check for suspicious patterns
                    if (IsSuspiciousStartupEntry(value))
                    {
                        suspiciousEntries.Add($"{valueName}: {value}");
                    }
                }
            }
            catch { /* Access denied — skip */ }
        }

        // Check HKCU keys
        foreach (var path in RunKeyPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(path);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    allEntries.Add($"HKCU\\{path}: {valueName} = {value}");

                    if (IsSuspiciousStartupEntry(value))
                    {
                        suspiciousEntries.Add($"{valueName}: {value}");
                    }
                }
            }
            catch { /* Access denied */ }
        }

        result.Findings.Add(Finding.Info(
            $"Registry Run Keys: {allEntries.Count} entries",
            $"Found {allEntries.Count} registry run key entries across HKLM and HKCU.",
            Category));

        if (suspiciousEntries.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"Suspicious Startup Entries ({suspiciousEntries.Count})",
                $"Potentially suspicious startup registry entries found: {string.Join("; ", suspiciousEntries.Take(5))}",
                Category,
                "Review these startup entries. Malware commonly uses registry run keys for persistence.",
                @"Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Format-List"));
        }
    }

    private async Task CheckStartupFolder(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"$paths = @(
                [Environment]::GetFolderPath('Startup'),
                [Environment]::GetFolderPath('CommonStartup')
            )
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    Get-ChildItem $p -ErrorAction SilentlyContinue | 
                    ForEach-Object { '{0}|{1}' -f $_.Name, $_.FullName }
                }
            }", ct);

        var items = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains('|')).ToList();

        if (items.Count > 5)
        {
            result.Findings.Add(Finding.Warning(
                $"Many Startup Folder Items ({items.Count})",
                $"Found {items.Count} items in startup folders. Too many startup items can slow boot and may indicate unwanted software.",
                Category,
                "Review startup folder items and remove any that are unnecessary.",
                "explorer.exe shell:startup"));
        }
        else if (items.Count > 0)
        {
            var names = items.Select(i => i.Split('|')[0]).ToList();
            result.Findings.Add(Finding.Info(
                $"Startup Folder Items ({items.Count})",
                $"Startup folder items: {string.Join(", ", names)}",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Startup Folder Items",
                "No items found in startup folders.",
                Category));
        }
    }

    private async Task CheckScheduledTasks(AuditResult result, CancellationToken ct)
    {
        // Check for non-Microsoft scheduled tasks
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-ScheduledTask | Where-Object { 
                $_.State -eq 'Ready' -and 
                $_.TaskPath -notmatch '\\Microsoft\\' -and
                $_.Author -notmatch 'Microsoft' 
            } | ForEach-Object { '{0}|{1}|{2}' -f $_.TaskName, $_.TaskPath, $_.Author }", ct);

        var tasks = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains('|')).ToList();

        if (tasks.Count > 20)
        {
            result.Findings.Add(Finding.Warning(
                $"Many Non-Microsoft Scheduled Tasks ({tasks.Count})",
                $"Found {tasks.Count} non-Microsoft scheduled tasks. Review for potential persistence mechanisms.",
                Category,
                "Review scheduled tasks: Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\\\Microsoft\\\\' }",
                "Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -and $_.TaskPath -notmatch '\\\\Microsoft\\\\' } | Format-Table TaskName, TaskPath, State"));
        }
        else
        {
            result.Findings.Add(Finding.Info(
                $"Non-Microsoft Scheduled Tasks: {tasks.Count}",
                $"Found {tasks.Count} non-Microsoft scheduled tasks.",
                Category));
        }

        // Check for tasks running from temp or suspicious locations
        var suspiciousTasks = await ShellHelper.RunPowerShellAsync(
            @"Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | 
              ForEach-Object { 
                  $actions = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                  $_.Actions | Where-Object { $_.Execute -match 'Temp|AppData|cmd\.exe|powershell\.exe.*-enc' } |
                  ForEach-Object { $_.Execute }
              }", ct);

        var suspicious = suspiciousTasks.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => !string.IsNullOrWhiteSpace(l)).ToList();

        if (suspicious.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"Suspicious Scheduled Task Actions ({suspicious.Count})",
                $"Scheduled tasks with suspicious actions (temp dirs, encoded commands): {string.Join("; ", suspicious.Take(5))}",
                Category,
                "Investigate these scheduled tasks for potential malware persistence.",
                "Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | ForEach-Object { $t = $_; $_.Actions | Where-Object { $_.Execute -match 'Temp|AppData|cmd\\.exe|powershell.*-enc' } | ForEach-Object { [PSCustomObject]@{Task=$t.TaskName;Action=$_.Execute} } } | Format-Table"));
        }
    }

    private async Task CheckServices(AuditResult result, CancellationToken ct)
    {
        // Check for non-Microsoft services set to auto-start
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-CimInstance Win32_Service | Where-Object { 
                $_.StartMode -eq 'Auto' -and 
                $_.PathName -and 
                $_.PathName -notmatch 'Windows|Microsoft|System32' 
            } | Measure-Object | Select-Object -ExpandProperty Count", ct);

        if (int.TryParse(output.Trim(), out int count))
        {
            result.Findings.Add(Finding.Info(
                $"Third-Party Auto-Start Services: {count}",
                $"Found {count} non-Microsoft services configured to start automatically.",
                Category));
        }
    }

    private static bool IsSuspiciousStartupEntry(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;

        var lower = value.ToLowerInvariant();
        return lower.Contains(@"\temp\") ||
               lower.Contains(@"\tmp\") ||
               lower.Contains("cmd.exe /c") ||
               lower.Contains("powershell") && lower.Contains("-enc") ||
               lower.Contains("mshta") ||
               lower.Contains("wscript") ||
               lower.Contains("cscript") ||
               lower.Contains("regsvr32") && lower.Contains("/s") ||
               lower.Contains("rundll32") && lower.Contains("javascript");
    }
}
