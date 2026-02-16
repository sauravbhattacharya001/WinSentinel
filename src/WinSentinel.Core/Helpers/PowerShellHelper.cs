using System.Diagnostics;

namespace WinSentinel.Core.Helpers;

/// <summary>
/// Helper to run PowerShell commands and capture output.
/// </summary>
public static class PowerShellHelper
{
    /// <summary>
    /// Run a PowerShell command and return stdout.
    /// </summary>
    public static async Task<string> RunCommandAsync(string command, CancellationToken ct = default)
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

        var output = await process.StandardOutput.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);

        return output.Trim();
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
