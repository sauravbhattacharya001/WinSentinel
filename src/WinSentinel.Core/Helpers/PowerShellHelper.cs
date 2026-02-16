using System.Diagnostics;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Helper to run PowerShell commands and capture output with timeout support.
/// </summary>
public static class PowerShellHelper
{
    /// <summary>
    /// Default timeout for PowerShell commands (30 seconds).
    /// </summary>
    public static TimeSpan DefaultTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Run a PowerShell command and return stdout.
    /// </summary>
    public static Task<string> RunCommandAsync(string command, CancellationToken ct = default)
        => RunCommandAsync(command, DefaultTimeout, ct);

    /// <summary>
    /// Run a PowerShell command with explicit timeout and return stdout.
    /// </summary>
    public static async Task<string> RunCommandAsync(string command, TimeSpan timeout, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -Command \"{command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = psi };
        process.Start();

        using var timeoutCts = new CancellationTokenSource(timeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            // Read stdout and stderr concurrently to prevent buffer deadlocks
            var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await process.WaitForExitAsync(linkedCts.Token);

            var output = await stdoutTask;
            return output.Trim();
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }

            if (ct.IsCancellationRequested) throw;
            return string.Empty; // Timeout — degrade gracefully
        }
    }

    /// <summary>
    /// Run a PowerShell command and return lines of output.
    /// </summary>
    public static async Task<string[]> RunCommandLinesAsync(string command, CancellationToken ct = default)
    {
        var output = await RunCommandAsync(command, ct);
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
