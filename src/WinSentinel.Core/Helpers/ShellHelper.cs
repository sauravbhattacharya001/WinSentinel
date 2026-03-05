using System.Diagnostics;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Helper to execute shell commands and capture output with timeout support.
/// </summary>
public static class ShellHelper
{
    /// <summary>
    /// Default timeout for shell commands (30 seconds).
    /// </summary>
    public static TimeSpan DefaultTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public static Task<string> RunPowerShellAsync(string command, CancellationToken ct = default)
        => RunPowerShellAsync(command, DefaultTimeout, ct);

    public static async Task<string> RunPowerShellAsync(string command, TimeSpan timeout, CancellationToken ct = default)
    {
        var encodedCmd = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(command));
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encodedCmd}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        return await RunProcessAsync(psi, timeout, ct);
    }

    public static Task<string> RunCmdAsync(string command, CancellationToken ct = default)
        => RunCmdAsync(command, DefaultTimeout, ct);

    public static async Task<string> RunCmdAsync(string command, TimeSpan timeout, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c {command}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        return await RunProcessAsync(psi, timeout, ct);
    }

    public static Task<string> RunNetshAsync(string arguments, CancellationToken ct = default)
        => RunNetshAsync(arguments, DefaultTimeout, ct);

    public static async Task<string> RunNetshAsync(string arguments, TimeSpan timeout, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        return await RunProcessAsync(psi, timeout, ct);
    }

    /// <summary>
    /// Core process runner with timeout and cancellation support.
    /// Reads stdout and stderr concurrently to prevent deadlocks when
    /// a child process fills one of the OS pipe buffers (typically 4-64 KB).
    /// Returns partial output if the process is killed due to timeout.
    /// </summary>
    private static async Task<string> RunProcessAsync(ProcessStartInfo psi, TimeSpan timeout, CancellationToken ct)
    {
        using var process = Process.Start(psi);
        if (process == null) return string.Empty;

        using var timeoutCts = new CancellationTokenSource(timeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
        var token = linkedCts.Token;

        try
        {
            // Read stdout and stderr concurrently to avoid deadlocks.
            // If only one stream is read synchronously, the other's OS pipe
            // buffer can fill up, blocking the child process indefinitely.
            var stdoutTask = process.StandardOutput.ReadToEndAsync(token);
            var stderrTask = process.StandardError.ReadToEndAsync(token);

            await Task.WhenAll(stdoutTask, stderrTask);
            await process.WaitForExitAsync(token);

            var stdout = stdoutTask.Result.Trim();

            // If stdout is empty but stderr has content, return stderr
            // so callers still get diagnostic output from failed commands.
            if (string.IsNullOrEmpty(stdout))
            {
                var stderr = stderrTask.Result.Trim();
                if (!string.IsNullOrEmpty(stderr))
                    return stderr;
            }

            return stdout;
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            // Timeout - kill the process and return empty
            KillProcess(process);
            return string.Empty;
        }
        catch (OperationCanceledException)
        {
            // Caller cancelled - kill and rethrow
            KillProcess(process);
            throw;
        }
    }

    /// <summary>
    /// Run a PowerShell command and return lines of output (split by newline, trimmed, empty removed).
    /// </summary>
    public static async Task<string[]> RunPowerShellLinesAsync(string command, CancellationToken ct = default)
    {
        var output = await RunPowerShellAsync(command, ct);
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static void KillProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Process may have already exited - ignore
        }
    }
}
