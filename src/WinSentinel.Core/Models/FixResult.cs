namespace WinSentinel.Core.Models;

/// <summary>
/// Result of executing a fix command for a finding.
/// </summary>
public class FixResult
{
    /// <summary>Whether the fix command executed successfully.</summary>
    public bool Success { get; set; }

    /// <summary>Standard output from the fix command.</summary>
    public string Output { get; set; } = string.Empty;

    /// <summary>Error output if the command failed.</summary>
    public string? Error { get; set; }

    /// <summary>The fix command that was executed.</summary>
    public string Command { get; set; } = string.Empty;

    /// <summary>Whether this was a dry-run (command was not actually executed).</summary>
    public bool DryRun { get; set; }

    /// <summary>Whether the command required elevation (admin).</summary>
    public bool RequiredElevation { get; set; }

    /// <summary>Exit code from the process.</summary>
    public int ExitCode { get; set; }

    /// <summary>How long the fix took to execute.</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>The finding this fix was applied to.</summary>
    public string FindingTitle { get; set; } = string.Empty;

    public static FixResult Succeeded(string command, string output, TimeSpan duration, string findingTitle = "") => new()
    {
        Success = true,
        Command = command,
        Output = output,
        Duration = duration,
        FindingTitle = findingTitle
    };

    public static FixResult Failed(string command, string error, TimeSpan duration, int exitCode = 1, string findingTitle = "") => new()
    {
        Success = false,
        Command = command,
        Error = error,
        Duration = duration,
        ExitCode = exitCode,
        FindingTitle = findingTitle
    };

    public static FixResult DryRunResult(string command, string findingTitle = "") => new()
    {
        Success = true,
        DryRun = true,
        Command = command,
        Output = $"[DRY RUN] Would execute: {command}",
        FindingTitle = findingTitle
    };

    public static FixResult NoFixAvailable(string findingTitle) => new()
    {
        Success = false,
        Error = "No fix command available for this finding.",
        FindingTitle = findingTitle
    };

    public override string ToString()
    {
        if (DryRun) return $"[DRY RUN] {Command}";
        return Success
            ? $"[OK] {FindingTitle}: {Output}"
            : $"[FAIL] {FindingTitle}: {Error}";
    }
}
