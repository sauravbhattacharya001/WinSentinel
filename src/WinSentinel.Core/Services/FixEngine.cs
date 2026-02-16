using System.Diagnostics;
using System.Security.Principal;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Executes fix commands for security findings.
/// Handles PowerShell execution, elevation (admin), dry-run mode, and timeouts.
/// </summary>
public class FixEngine
{
    /// <summary>Default timeout for fix commands.</summary>
    public TimeSpan DefaultTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Returns true if the current process is running with administrator privileges.
    /// </summary>
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Execute a fix for the given finding.
    /// </summary>
    /// <param name="finding">The finding to fix.</param>
    /// <param name="dryRun">If true, returns what would be done without executing.</param>
    /// <param name="forceElevate">If true, launches an elevated PowerShell process even if current process is admin.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<FixResult> ExecuteFixAsync(
        Finding finding,
        bool dryRun = false,
        bool forceElevate = false,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(finding.FixCommand))
            return FixResult.NoFixAvailable(finding.Title);

        if (dryRun)
            return FixResult.DryRunResult(finding.FixCommand, finding.Title);

        var command = finding.FixCommand;
        bool needsElevation = RequiresElevation(command);
        var sw = Stopwatch.StartNew();

        try
        {
            if ((needsElevation || forceElevate) && !IsElevated())
            {
                return await ExecuteElevatedAsync(command, finding.Title, sw, cancellationToken);
            }
            else
            {
                return await ExecuteInlineAsync(command, finding.Title, sw, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return FixResult.Failed(command, "Fix operation was cancelled.", sw.Elapsed, findingTitle: finding.Title);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return FixResult.Failed(command, ex.Message, sw.Elapsed, findingTitle: finding.Title);
        }
    }

    /// <summary>
    /// Execute a raw PowerShell command (not tied to a finding).
    /// </summary>
    public async Task<FixResult> ExecuteCommandAsync(
        string command,
        bool dryRun = false,
        CancellationToken cancellationToken = default)
    {
        var finding = new Finding
        {
            Title = "Manual Command",
            Description = command,
            FixCommand = command
        };
        return await ExecuteFixAsync(finding, dryRun, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Execute a fix inline (same process privilege level).
    /// </summary>
    private async Task<FixResult> ExecuteInlineAsync(
        string command, string findingTitle, Stopwatch sw, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{EscapeCommand(command)}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null)
        {
            sw.Stop();
            return FixResult.Failed(command, "Failed to start PowerShell process.", sw.Elapsed, findingTitle: findingTitle);
        }

        using var timeoutCts = new CancellationTokenSource(DefaultTimeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            var outputTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var errorTask = process.StandardError.ReadToEndAsync(linkedCts.Token);
            await process.WaitForExitAsync(linkedCts.Token);

            var output = await outputTask;
            var error = await errorTask;

            sw.Stop();

            if (process.ExitCode == 0)
            {
                return new FixResult
                {
                    Success = true,
                    Command = command,
                    Output = output.Trim(),
                    ExitCode = 0,
                    Duration = sw.Elapsed,
                    FindingTitle = findingTitle
                };
            }
            else
            {
                return new FixResult
                {
                    Success = false,
                    Command = command,
                    Output = output.Trim(),
                    Error = string.IsNullOrWhiteSpace(error) ? $"Process exited with code {process.ExitCode}" : error.Trim(),
                    ExitCode = process.ExitCode,
                    Duration = sw.Elapsed,
                    FindingTitle = findingTitle
                };
            }
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            KillProcess(process);
            sw.Stop();
            return FixResult.Failed(command, $"Fix command timed out after {DefaultTimeout.TotalSeconds}s.", sw.Elapsed, findingTitle: findingTitle);
        }
    }

    /// <summary>
    /// Execute a fix in an elevated (Run As Administrator) PowerShell process.
    /// Uses Start-Process with -Verb RunAs to trigger the UAC prompt.
    /// Writes output to a temp file since elevated processes can't redirect stdout.
    /// </summary>
    private async Task<FixResult> ExecuteElevatedAsync(
        string command, string findingTitle, Stopwatch sw, CancellationToken ct)
    {
        var tempOutputFile = Path.GetTempFileName();
        var tempErrorFile = Path.GetTempFileName();

        try
        {
            // Wrap command to write output to temp files
            var wrappedCommand = $"try {{ {command} | Out-File -FilePath '{tempOutputFile}' -Encoding UTF8 }} catch {{ $_.Exception.Message | Out-File -FilePath '{tempErrorFile}' -Encoding UTF8; exit 1 }}";

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{EscapeCommand(wrappedCommand)}\"",
                UseShellExecute = true,
                Verb = "runas",     // Triggers UAC elevation
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                sw.Stop();
                var result = FixResult.Failed(command, "Failed to start elevated PowerShell process.", sw.Elapsed, findingTitle: findingTitle);
                result.RequiredElevation = true;
                return result;
            }

            using var timeoutCts = new CancellationTokenSource(DefaultTimeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            try
            {
                await process.WaitForExitAsync(linkedCts.Token);
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                KillProcess(process);
                sw.Stop();
                var timeoutResult = FixResult.Failed(command, $"Elevated fix command timed out after {DefaultTimeout.TotalSeconds}s.", sw.Elapsed, findingTitle: findingTitle);
                timeoutResult.RequiredElevation = true;
                return timeoutResult;
            }

            sw.Stop();

            var output = File.Exists(tempOutputFile) ? (await File.ReadAllTextAsync(tempOutputFile, ct)).Trim() : "";
            var error = File.Exists(tempErrorFile) ? (await File.ReadAllTextAsync(tempErrorFile, ct)).Trim() : "";

            var fixResult = new FixResult
            {
                Success = process.ExitCode == 0 && string.IsNullOrWhiteSpace(error),
                Command = command,
                Output = output,
                Error = string.IsNullOrWhiteSpace(error) ? null : error,
                ExitCode = process.ExitCode,
                Duration = sw.Elapsed,
                RequiredElevation = true,
                FindingTitle = findingTitle
            };

            return fixResult;
        }
        finally
        {
            // Clean up temp files
            TryDeleteFile(tempOutputFile);
            TryDeleteFile(tempErrorFile);
        }
    }

    /// <summary>
    /// Determines if a command likely needs admin elevation.
    /// Checks for known patterns that require HKLM writes, service changes, etc.
    /// </summary>
    public static bool RequiresElevation(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return false;

        var lower = command.ToLowerInvariant();
        return lower.Contains("hklm:") ||
               lower.Contains("hkey_local_machine") ||
               lower.Contains("set-mppreference") ||
               lower.Contains("update-mpsignature") ||
               lower.Contains("start-mpscan") ||
               lower.Contains("set-smbserverconfiguration") ||
               lower.Contains("disable-localuser") ||
               lower.Contains("enable-localuser") ||
               lower.Contains("net accounts") ||
               lower.Contains("netsh advfirewall") ||
               lower.Contains("manage-bde") ||
               lower.Contains("stop-service") ||
               lower.Contains("set-service") ||
               lower.Contains("shutdown") ||
               lower.Contains("set-netconnectionprofile") ||
               lower.Contains("set-itemproperty -path 'hklm:") ||
               lower.Contains("new-item -path 'hklm:");
    }

    /// <summary>
    /// Escape double quotes in PowerShell commands for passing via -Command argument.
    /// </summary>
    private static string EscapeCommand(string command)
    {
        // Replace double quotes with escaped double quotes for the outer shell
        return command.Replace("\"", "\\\"");
    }

    private static void KillProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch { /* Process may have already exited */ }
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* Ignore cleanup errors */ }
    }
}
