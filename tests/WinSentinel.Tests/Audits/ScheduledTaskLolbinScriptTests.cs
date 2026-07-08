using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.ScheduledTaskAudit;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Deterministic unit tests for <see cref="ScheduledTaskAudit"/>'s
/// "signed interpreter launches a writable script/payload" detection
/// (<c>CheckLolbinScriptFromUserPath</c>) and its two pure helpers
/// (<see cref="ScheduledTaskAudit.IsLolbinInterpreter"/> and
/// <see cref="ScheduledTaskAudit.FindUserWritablePayloadPath"/>).
///
/// This closes the gap where a task runs a legitimate in-box interpreter
/// (powershell/cmd/wscript/mshta/rundll32/...) whose *Execute* path is System32
/// (so the suspicious-Execute-path check passes it) but whose *arguments* point at
/// a script in a user-writable directory (Temp, Downloads, AppData\Roaming,
/// ProgramData, Public, ...) - a classic living-off-the-land persistence /
/// privilege-escalation foothold (MITRE ATT&amp;CK T1053.005 + T1059) that neither
/// the suspicious-path nor the suspicious-command checks catch on their own.
///
/// All state is synthetic; nothing here touches schtasks, PowerShell, cmd or the
/// registry, so every classification is pinned directly.
/// </summary>
public class ScheduledTaskLolbinScriptTests
{
    // ── helpers ──────────────────────────────────────────────────────────────

    private static TaskEntry Task(
        string name,
        string execute,
        string arguments,
        string principal = "",
        string runLevel = "LeastPrivilege",
        params string[] triggers) => new()
    {
        TaskName = name,
        TaskPath = @"\",
        Principal = principal,
        RunLevel = runLevel,
        Triggers = triggers.ToList(),
        Actions = new List<TaskAction>
        {
            new() { Execute = execute, Arguments = arguments }
        },
    };

    private static AuditResult Analyze(params TaskEntry[] tasks)
    {
        var audit = new ScheduledTaskAudit();
        var result = new AuditResult { ModuleName = audit.Name, Category = audit.Category };
        audit.AnalyzeState(new ScheduledTaskState { Tasks = tasks.ToList() }, result);
        return result;
    }

    private static IEnumerable<Finding> WritableScriptFindings(AuditResult r) =>
        r.Findings.Where(f => f.Title.StartsWith("Interpreter Runs Writable Script"));

    // ── IsLolbinInterpreter ──────────────────────────────────────────────────

    [Theory]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", true)]
    [InlineData("powershell.exe", true)]
    [InlineData("POWERSHELL.EXE", true)]
    [InlineData(@"C:\Windows\System32\cmd.exe", true)]
    [InlineData("mshta.exe", true)]
    [InlineData("rundll32.exe", true)]
    [InlineData("regsvr32.exe", true)]
    [InlineData("wscript.exe", true)]
    [InlineData("pwsh.exe", true)]
    [InlineData("\"C:\\Windows\\System32\\cscript.exe\"", true)]
    [InlineData(@"C:\Program Files\App\app.exe", false)]
    [InlineData("notepad.exe", false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData(null, false)]
    public void IsLolbinInterpreter_ClassifiesByTrailingName(string? execute, bool expected)
    {
        Assert.Equal(expected, ScheduledTaskAudit.IsLolbinInterpreter(execute));
    }

    [Fact]
    public void IsLolbinInterpreter_ForwardSlashesAlsoMatch()
    {
        Assert.True(ScheduledTaskAudit.IsLolbinInterpreter("C:/Windows/System32/powershell.exe"));
    }

    // ── FindUserWritablePayloadPath ──────────────────────────────────────────

    [Theory]
    [InlineData(@"-File C:\Users\bob\AppData\Roaming\update.ps1", @"C:\Users\bob\AppData\Roaming\update.ps1")]
    [InlineData(@"-nop -w hidden -File C:\Users\bob\Downloads\run.ps1", @"C:\Users\bob\Downloads\run.ps1")]
    [InlineData(@"/c C:\ProgramData\stage\go.bat", @"C:\ProgramData\stage\go.bat")]
    [InlineData(@"C:\Windows\Temp\payload.vbs //nologo", @"C:\Windows\Temp\payload.vbs")]
    public void FindUserWritablePayloadPath_ReturnsWritablePayload(string args, string expected)
    {
        var found = ScheduledTaskAudit.FindUserWritablePayloadPath(args);
        Assert.Equal(expected, found);
    }

    [Fact]
    public void FindUserWritablePayloadPath_QuotedPathWithSpaces_KeptWhole()
    {
        var args = "-File \"C:\\Users\\bob\\AppData\\Roaming\\My App\\run script.ps1\"";
        var found = ScheduledTaskAudit.FindUserWritablePayloadPath(args);
        Assert.Equal(@"C:\Users\bob\AppData\Roaming\My App\run script.ps1", found);
    }

    [Theory]
    [InlineData(@"-File C:\Program Files\Vendor\tool.ps1")]      // script, but admin-only dir
    [InlineData(@"-Command Get-Process")]                        // no script path at all
    [InlineData(@"-File C:\Windows\System32\WindowsPowerShell\v1.0\Modules\x.ps1")] // system dir
    [InlineData("")]
    [InlineData("   ")]
    public void FindUserWritablePayloadPath_ReturnsNull_WhenNotWritablePayload(string args)
    {
        Assert.Null(ScheduledTaskAudit.FindUserWritablePayloadPath(args));
    }

    [Fact]
    public void FindUserWritablePayloadPath_WritableDirButNoScriptExtension_ReturnsNull()
    {
        // References Temp but the token is not a payload-extension file.
        Assert.Null(ScheduledTaskAudit.FindUserWritablePayloadPath(@"-WorkingDirectory C:\Users\bob\AppData\Local\Temp"));
    }

    [Fact]
    public void TokenizeArguments_HonoursDoubleQuotes()
    {
        var tokens = ScheduledTaskAudit.TokenizeArguments("-File \"C:\\a b\\c.ps1\" -x 1");
        Assert.Equal(new[] { "-File", "\"C:\\a b\\c.ps1\"", "-x", "1" }, tokens);
    }

    // ── AnalyzeState end-to-end ──────────────────────────────────────────────

    [Fact]
    public void Analyze_PowerShellFileFromRoaming_AsSystem_IsCritical()
    {
        var t = Task("Updater",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            @"-nop -w hidden -File C:\Users\bob\AppData\Roaming\update.ps1",
            principal: "SYSTEM");

        var findings = WritableScriptFindings(Analyze(t)).ToList();

        var f = Assert.Single(findings);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("update.ps1", f.Description);
        Assert.Contains("powershell.exe", f.Description);
        // Elevated payload swap => must surface the query as an actionable fix.
        Assert.False(string.IsNullOrWhiteSpace(f.FixCommand));
    }

    [Fact]
    public void Analyze_LogonTriggerEscalatesToCritical_EvenWithoutHighPrivilege()
    {
        var t = Task("LogonRun",
            "powershell.exe",
            @"-File C:\Users\bob\Downloads\run.ps1",
            principal: "bob",
            runLevel: "LeastPrivilege",
            triggers: "AtLogon");

        var f = Assert.Single(WritableScriptFindings(Analyze(t)));
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void Analyze_NonPrivileged_NoPersistTrigger_IsWarning()
    {
        var t = Task("AdHoc",
            "cmd.exe",
            @"/c C:\Users\bob\AppData\Local\Temp\go.bat",
            principal: "bob",
            runLevel: "LeastPrivilege"); // no trigger

        var f = Assert.Single(WritableScriptFindings(Analyze(t)));
        Assert.Equal(Severity.Warning, f.Severity);
    }

    [Fact]
    public void Analyze_ScriptInAdminOnlyDir_ProducesNoWritableScriptFinding()
    {
        var t = Task("Legit",
            "powershell.exe",
            @"-File C:\Program Files\Vendor\maintenance.ps1",
            principal: "SYSTEM",
            triggers: "AtLogon");

        Assert.Empty(WritableScriptFindings(Analyze(t)));
    }

    [Fact]
    public void Analyze_NonInterpreterExecutable_ProducesNoWritableScriptFinding()
    {
        // A real EXE (not an interpreter) that happens to take a writable path arg is
        // out of scope for THIS check (the suspicious-Execute-path check owns exe paths).
        var t = Task("VendorSvc",
            @"C:\Program Files\Vendor\vendor.exe",
            @"--config C:\Users\bob\AppData\Roaming\settings.ps1",
            principal: "SYSTEM");

        Assert.Empty(WritableScriptFindings(Analyze(t)));
    }

    [Fact]
    public void Analyze_EmitsAtMostOneWritableScriptFindingPerTask()
    {
        // Two writable payloads referenced; the check must not double-report.
        var t = Task("Multi",
            "powershell.exe",
            @"-File C:\Users\bob\Downloads\a.ps1 -Extra C:\Users\Public\b.ps1",
            principal: "SYSTEM");

        Assert.Single(WritableScriptFindings(Analyze(t)));
    }

    [Fact]
    public void Analyze_MicrosoftBuiltInTask_IsSkippedEntirely()
    {
        // Known-safe prefix tasks are skipped before per-task checks run.
        var t = new TaskEntry
        {
            TaskName = "SomeTask",
            TaskPath = @"\Microsoft\Windows\",
            Principal = "SYSTEM",
            Actions = new List<TaskAction>
            {
                new()
                {
                    Execute = "powershell.exe",
                    Arguments = @"-File C:\Users\bob\AppData\Roaming\update.ps1"
                }
            },
        };

        Assert.Empty(WritableScriptFindings(Analyze(t)));
    }
}
