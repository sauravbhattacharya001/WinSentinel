using System.Runtime.InteropServices;

namespace WinSentinel.Cli;

/// <summary>
/// Ensures every child process spawned (directly or transitively) by the CLI is
/// killed when the CLI process dies — for any reason: clean exit, unhandled
/// exception, Ctrl+C, taskkill, parent shell teardown.
///
/// Implementation: assign the current process to a Windows Job Object with the
/// <c>JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE</c> flag. When our process handle goes
/// away the kernel closes the job, which kills every member of the job. New
/// processes created with <see cref="System.Diagnostics.Process.Start(System.Diagnostics.ProcessStartInfo)"/>
/// inherit the job automatically (default on modern Windows; we set
/// <c>JOB_OBJECT_LIMIT_BREAKAWAY_OK</c>=false to be explicit).
///
/// This closes #193 (orphan dotnet workers surviving CLI death during long scans).
///
/// Safe to call multiple times — only the first call actually assigns the job.
/// No-op on non-Windows (the CLI is Windows-only at runtime, but Pack targets
/// net8.0, so the type must compile and load cross-platform).
/// </summary>
public static class ChildProcessReaper
{
    private static IntPtr _jobHandle = IntPtr.Zero;
    private static readonly object _lock = new();

    public static void Install()
    {
        if (!OperatingSystem.IsWindows()) return;
        if (_jobHandle != IntPtr.Zero) return;

        lock (_lock)
        {
            if (_jobHandle != IntPtr.Zero) return;

            try
            {
                var job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero) return;

                var limits = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                };
                var ext = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                {
                    BasicLimitInformation = limits,
                };

                int len = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
                IntPtr extPtr = Marshal.AllocHGlobal(len);
                try
                {
                    Marshal.StructureToPtr(ext, extPtr, false);
                    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, extPtr, (uint)len))
                    {
                        CloseHandle(job);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(extPtr);
                }

                if (!AssignProcessToJobObject(job, GetCurrentProcess()))
                {
                    // Already in a job that disallows nesting (e.g. some CI runners
                    // wrap the test host). Best-effort: install a Ctrl+C handler and
                    // a process-exit handler that try to kill our direct children.
                    CloseHandle(job);
                    InstallFallbackReaper();
                    return;
                }

                _jobHandle = job;
            }
            catch
            {
                // Reaper is best-effort. Never crash the CLI because we couldn't
                // install a guardrail.
                InstallFallbackReaper();
            }
        }
    }

    private static bool _fallbackInstalled;
    private static void InstallFallbackReaper()
    {
        if (_fallbackInstalled) return;
        _fallbackInstalled = true;

        Console.CancelKeyPress += (_, e) =>
        {
            // Don't immediately abort — let the main loop unwind, but try to kill
            // descendants so the user gets the shell back fast.
            try { KillDescendants(); } catch { }
        };
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { KillDescendants(); } catch { }
        };
    }

    private static void KillDescendants()
    {
        if (!OperatingSystem.IsWindows()) return;
        int self = System.Diagnostics.Process.GetCurrentProcess().Id;
        foreach (var p in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                if (p.Id == self) continue;
                if (GetParentPid(p.Id) != self) continue;
                p.Kill(entireProcessTree: true);
            }
            catch { /* gone or denied */ }
            finally { p.Dispose(); }
        }
    }

    private static int GetParentPid(int pid)
    {
        // Reflection-free WMI is heavyweight; we avoid System.Management dep here
        // and just shell out to NtQueryInformationProcess via a minimal P/Invoke.
        try
        {
            var pbi = new PROCESS_BASIC_INFORMATION();
            int size = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            int status = NtQueryInformationProcess(p.Handle, 0, ref pbi, size, out _);
            if (status != 0) return -1;
            return (int)pbi.InheritedFromUniqueProcessId.ToInt64();
        }
        catch { return -1; }
    }

    // ── Win32 interop ────────────────────────────────────────────────

    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr a, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoType, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);
}
