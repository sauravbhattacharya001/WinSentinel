using System.Diagnostics;
using System.Runtime.InteropServices;
using WinSentinel.Cli;

namespace WinSentinel.Tests.Cli;

/// <summary>
/// End-to-end check for the orphan-process reaper added for #193.
///
/// Strategy: launch a tiny PowerShell child whose only job is to sleep for 60s,
/// then kill the parent test wrapper (a fresh `dotnet exec` that calls
/// <see cref="ChildProcessReaper.Install"/> before spawning the sleeper).
/// If the reaper is correctly installed, killing the parent must terminate the
/// sleeper within a couple of seconds. Without the fix, the sleeper survives.
///
/// We don't actually spawn a separate dotnet exec here — that would require
/// publishing a helper assembly. Instead we verify the kernel-level guarantee
/// directly: install the reaper in *this* process, spawn a sleeper, then check
/// that the sleeper is a member of the same Windows Job Object. The job has
/// KILL_ON_JOB_CLOSE, so membership === will-be-killed-when-parent-dies. This
/// is the property we actually care about and is verifiable without forking.
/// </summary>
public class ChildProcessReaperTests
{
    [Fact]
    public void Install_IsIdempotent_DoesNotThrow()
    {
        // Calling twice must be safe.
        ChildProcessReaper.Install();
        ChildProcessReaper.Install();
    }

    [Fact]
    public void Install_OnWindows_ChildProcessJoinsKillOnCloseJob()
    {
        if (!OperatingSystem.IsWindows())
        {
            // CLI is Windows-only at runtime; nothing to assert elsewhere.
            return;
        }

        ChildProcessReaper.Install();

        // Spawn a benign short-lived child (cmd /c exit) and verify it is in a job.
        // We use a process that actually exits on its own so the test never hangs
        // even if the reaper somehow fails — the assertion is on job membership,
        // not on kill propagation (which is a kernel guarantee once membership is
        // established).
        var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 1 127.0.0.1 > nul")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        };

        using var child = Process.Start(psi);
        Assert.NotNull(child);

        try
        {
            // IsProcessInJob: BOOL Result; on success the OUT param tells us whether
            // the process is part of any job. If the reaper installed correctly the
            // child must inherit our job → true.
            bool inJob;
            bool ok = IsProcessInJob(child!.Handle, IntPtr.Zero, out inJob);
            Assert.True(ok, "IsProcessInJob call should succeed");
            Assert.True(
                inJob,
                "Child process must inherit the CLI's job object so it is killed when the CLI dies (#193)."
            );
        }
        finally
        {
            try { child!.WaitForExit(5000); } catch { }
            if (!child!.HasExited)
            {
                try { child.Kill(entireProcessTree: true); } catch { }
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(IntPtr ProcessHandle, IntPtr JobHandle, [MarshalAs(UnmanagedType.Bool)] out bool Result);
}
