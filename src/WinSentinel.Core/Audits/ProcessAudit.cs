using System.Diagnostics;
using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits running processes for unsigned executables and suspicious locations.
/// </summary>
public class ProcessAudit : IAuditModule
{
    public string Name => "Process Audit";
    public string Category => "Processes";
    public string Description => "Checks running processes for unsigned executables, suspicious locations, and known risks.";

    private static readonly HashSet<string> SuspiciousDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\Users\Public",
        @"C:\ProgramData",
        @"C:\Windows\Temp",
    };

    private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation",
        "Microsoft Windows",
        "Google LLC",
        "Mozilla Corporation",
        "Adobe Inc.",
        "Apple Inc.",
        "Intel Corporation",
        "NVIDIA Corporation",
        "Advanced Micro Devices",
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
            await CheckSuspiciousProcessLocations(result, cancellationToken);
            await CheckUnsignedProcesses(result, cancellationToken);
            await CheckHighPrivilegeProcesses(result, cancellationToken);
            await CheckProcessCount(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckSuspiciousProcessLocations(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-Process | Where-Object { $_.Path } | 
              Select-Object ProcessName, Path, Id | 
              ForEach-Object { '{0}|{1}|{2}' -f $_.ProcessName, $_.Path, $_.Id }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var suspiciousProcesses = new List<string>();
        var tempProcesses = new List<string>();

        foreach (var line in lines)
        {
            var parts = line.Split('|');
            if (parts.Length < 2) continue;

            var processName = parts[0];
            var path = parts[1];

            // Check if running from temp directories
            if (path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\tmp\", StringComparison.OrdinalIgnoreCase))
            {
                tempProcesses.Add($"{processName} ({path})");
            }

            // Check suspicious directories
            foreach (var dir in SuspiciousDirectories)
            {
                if (path.StartsWith(dir, StringComparison.OrdinalIgnoreCase) &&
                    !path.Contains(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
                {
                    suspiciousProcesses.Add($"{processName} ({path})");
                    break;
                }
            }
        }

        if (tempProcesses.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"Processes Running from Temp ({tempProcesses.Count})",
                $"Processes running from temporary directories (common for malware): {string.Join("; ", tempProcesses.Take(10))}",
                Category,
                "Investigate processes running from temp directories. Malware often drops executables in temp folders.",
                "Get-Process | Where-Object { $_.Path -match '\\\\Temp\\\\' } | Select-Object ProcessName, Id, Path | Format-Table"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Processes from Temp Directories",
                "No processes are running from temporary directories.",
                Category));
        }

        if (suspiciousProcesses.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Processes in Unusual Locations ({suspiciousProcesses.Count})",
                $"Processes found in non-standard locations: {string.Join("; ", suspiciousProcesses.Take(10))}",
                Category));
        }
    }

    private async Task CheckUnsignedProcesses(AuditResult result, CancellationToken ct)
    {
        // Get unique executable paths first, then check signatures to avoid
        // running Get-AuthenticodeSignature on duplicate paths (much faster).
        var output = await ShellHelper.RunPowerShellAsync(
            @"$paths = Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique
              foreach ($p in $paths) { 
                  $sig = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue
                  if ($sig.Status -ne 'Valid') { 
                      '{0}|{1}|{2}' -f [IO.Path]::GetFileNameWithoutExtension($p), $p, $sig.Status 
                  }
              }", TimeSpan.FromSeconds(60), ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains('|')).ToList();

        if (lines.Count > 10)
        {
            result.Findings.Add(Finding.Warning(
                $"Unsigned/Invalid Processes ({lines.Count})",
                $"Found {lines.Count} running processes without valid digital signatures. Some examples: {string.Join("; ", lines.Take(5))}",
                Category,
                "Review unsigned processes and verify they are legitimate software.",
                "Get-Process | Where-Object { $_.Path } | ForEach-Object { $sig = Get-AuthenticodeSignature $_.Path -EA SilentlyContinue; if ($sig.Status -ne 'Valid') { [PSCustomObject]@{Name=$_.ProcessName;Path=$_.Path;Status=$sig.Status} } } | Format-Table"));
        }
        else if (lines.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Some Unsigned Processes ({lines.Count})",
                $"Found {lines.Count} processes without valid signatures: {string.Join("; ", lines)}",
                Category));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "All Processes Properly Signed",
                "All running processes have valid digital signatures.",
                Category));
        }
    }

    private async Task CheckHighPrivilegeProcesses(AuditResult result, CancellationToken ct)
    {
        // Use a filtered WMI query to only check SYSTEM processes outside Windows dir.
        // This avoids calling GetOwner on every process (very slow).
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -notmatch 'Windows' } |
              ForEach-Object { 
                  $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
                  if ($owner.User -eq 'SYSTEM') {
                      '{0}|{1}' -f $_.Name, $_.ExecutablePath
                  }
              }", TimeSpan.FromSeconds(45), ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains('|')).ToList();

        if (lines.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Non-Windows SYSTEM Processes ({lines.Count})",
                $"Found {lines.Count} SYSTEM-level processes outside Windows directory: {string.Join("; ", lines.Take(5))}",
                Category));
        }
    }

    private async Task CheckProcessCount(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-Process).Count", ct);

        if (int.TryParse(output.Trim(), out int count))
        {
            if (count > 200)
            {
                result.Findings.Add(Finding.Info(
                    $"High Process Count ({count})",
                    $"There are {count} running processes. A high number may indicate unnecessary services or potential unwanted software.",
                    Category));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    $"Normal Process Count ({count})",
                    $"There are {count} running processes.",
                    Category));
            }
        }
    }
}
