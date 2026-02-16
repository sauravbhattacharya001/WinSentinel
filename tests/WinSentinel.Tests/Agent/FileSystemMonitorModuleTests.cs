using WinSentinel.Agent;
using WinSentinel.Agent.Modules;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace WinSentinel.Tests.Agent;

public class FileSystemMonitorModuleTests
{
    private readonly ThreatLog _threatLog;
    private readonly AgentConfig _config;
    private readonly FileSystemMonitorModule _module;

    public FileSystemMonitorModuleTests()
    {
        _threatLog = new ThreatLog();
        _config = new AgentConfig { RiskTolerance = RiskTolerance.Medium };
        _module = new FileSystemMonitorModule(
            NullLogger<FileSystemMonitorModule>.Instance,
            _threatLog,
            _config);
    }

    // ── Module Lifecycle ──

    [Fact]
    public void Name_ReturnsFileSystemMonitor()
    {
        Assert.Equal("FileSystemMonitor", _module.Name);
    }

    [Fact]
    public void IsActive_InitiallyFalse()
    {
        Assert.False(_module.IsActive);
    }

    // ── System32 Drop Detection ──

    [Theory]
    [InlineData("malware.exe")]
    [InlineData("evil.dll")]
    [InlineData("dropper.scr")]
    [InlineData("payload.bat")]
    [InlineData("loader.cmd")]
    [InlineData("script.ps1")]
    [InlineData("macro.vbs")]
    [InlineData("implant.js")]
    public void AnalyzeEvent_DetectsSystem32Drop(string fileName)
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\" + fileName,
            fileName,
            FileEventType.Created,
            DirectoryCategory.System32);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "New Executable in System32");
        Assert.Contains(threats, t => t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void AnalyzeEvent_IgnoresNonExecutableInSystem32()
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\readme.txt",
            "readme.txt",
            FileEventType.Created,
            DirectoryCategory.System32);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "New Executable in System32");
    }

    [Fact]
    public void AnalyzeEvent_IgnoresSystem32ChangedEvent()
    {
        // Changed events (not Created) should not trigger System32 drop detection
        var evt = CreateEvent(
            @"C:\Windows\System32\existing.dll",
            "existing.dll",
            FileEventType.Changed,
            DirectoryCategory.System32);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "New Executable in System32");
    }

    // ── Hosts File Detection ──

    [Fact]
    public void AnalyzeEvent_DetectsHostsFileModification()
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\drivers\etc\hosts",
            "hosts",
            FileEventType.Changed,
            DirectoryCategory.HostsFile);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Hosts File Modified");
        Assert.Contains(threats, t => t.Severity == ThreatSeverity.High);
    }

    [Fact]
    public void AnalyzeEvent_DetectsHostsFileDeletion()
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\drivers\etc\hosts",
            "hosts",
            FileEventType.Deleted,
            DirectoryCategory.HostsFile);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Hosts File Deleted");
        Assert.Contains(threats, t => t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void AnalyzeEvent_IgnoresNonHostsFileInEtcDir()
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\drivers\etc\networks",
            "networks",
            FileEventType.Changed,
            DirectoryCategory.HostsFile);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Empty(threats);
    }

    // ── Startup Folder Persistence ──

    [Theory]
    [InlineData("malware.exe", ThreatSeverity.Critical)]
    [InlineData("backdoor.bat", ThreatSeverity.Critical)]
    [InlineData("script.vbs", ThreatSeverity.Critical)]
    [InlineData("shortcut.lnk", ThreatSeverity.High)]
    [InlineData("readme.txt", ThreatSeverity.High)]
    public void AnalyzeEvent_DetectsStartupPersistence(string fileName, ThreatSeverity expectedMinSeverity)
    {
        var evt = CreateEvent(
            @"C:\Users\Test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" + fileName,
            fileName,
            FileEventType.Created,
            DirectoryCategory.StartupFolder);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Startup Folder Persistence");
        Assert.Contains(threats, t => t.Severity >= expectedMinSeverity);
    }

    [Fact]
    public void AnalyzeEvent_IgnoresStartupChangedEvent()
    {
        // Only Created events should trigger startup detection
        var evt = CreateEvent(
            @"C:\Users\Test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\existing.exe",
            "existing.exe",
            FileEventType.Changed,
            DirectoryCategory.StartupFolder);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "Startup Folder Persistence");
    }

    // ── Suspicious Script Detection ──

    [Theory]
    [InlineData("dropper.bat", DirectoryCategory.TempDirectory)]
    [InlineData("payload.ps1", DirectoryCategory.TempDirectory)]
    [InlineData("macro.vbs", DirectoryCategory.Downloads)]
    [InlineData("loader.js", DirectoryCategory.Downloads)]
    [InlineData("exploit.cmd", DirectoryCategory.TempDirectory)]
    [InlineData("backdoor.hta", DirectoryCategory.Downloads)]
    public void AnalyzeEvent_DetectsSuspiciousScript(string fileName, DirectoryCategory category)
    {
        var basePath = category == DirectoryCategory.TempDirectory
            ? @"C:\Users\Test\AppData\Local\Temp\"
            : @"C:\Users\Test\Downloads\";

        var evt = CreateEvent(
            basePath + fileName,
            fileName,
            FileEventType.Created,
            category);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Suspicious Script Created");
    }

    [Fact]
    public void AnalyzeEvent_IgnoresNonScriptInTemp()
    {
        var evt = CreateEvent(
            @"C:\Users\Test\AppData\Local\Temp\data.csv",
            "data.csv",
            FileEventType.Created,
            DirectoryCategory.TempDirectory);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "Suspicious Script Created");
    }

    // ── File Extension Masquerading ──

    [Theory]
    [InlineData("report.pdf.exe")]
    [InlineData("photo.jpg.scr")]
    [InlineData("invoice.docx.bat")]
    [InlineData("archive.zip.ps1")]
    [InlineData("document.txt.vbs")]
    [InlineData("video.mp4.exe")]
    public void AnalyzeEvent_DetectsExtensionMasquerading(string fileName)
    {
        var evt = CreateEvent(
            @"C:\Users\Test\Downloads\" + fileName,
            fileName,
            FileEventType.Created,
            DirectoryCategory.Downloads);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "File Extension Masquerading");
        Assert.Contains(threats, t => t.Severity == ThreatSeverity.Critical);
    }

    [Theory]
    [InlineData("report.pdf")]
    [InlineData("photo.jpg")]
    [InlineData("setup.exe")]
    [InlineData("archive.tar.gz")] // tar.gz is not doc+exe
    public void AnalyzeEvent_NoFalsePositiveMasquerading(string fileName)
    {
        var evt = CreateEvent(
            @"C:\Users\Test\Downloads\" + fileName,
            fileName,
            FileEventType.Created,
            DirectoryCategory.Downloads);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "File Extension Masquerading");
    }

    // ── Scheduled Task Persistence ──

    [Theory]
    [InlineData("malware.exe")]
    [InlineData("implant.dll")]
    [InlineData("dropper.bat")]
    public void AnalyzeEvent_DetectsExecutableInTasks(string fileName)
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\Tasks\" + fileName,
            fileName,
            FileEventType.Created,
            DirectoryCategory.ScheduledTasks);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Executable in Tasks Directory");
        Assert.Contains(threats, t => t.Severity == ThreatSeverity.Critical);
    }

    [Fact]
    public void AnalyzeEvent_DetectsNewScheduledTask()
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\Tasks\SuspiciousTask.xml",
            "SuspiciousTask.xml",
            FileEventType.Created,
            DirectoryCategory.ScheduledTasks);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "New Scheduled Task Created");
        Assert.Contains(threats, t => t.Severity == ThreatSeverity.Medium);
    }

    [Fact]
    public void AnalyzeEvent_DetectsNewJobFile()
    {
        var evt = CreateEvent(
            @"C:\Windows\Tasks\evil.job",
            "evil.job",
            FileEventType.Created,
            DirectoryCategory.ScheduledTasks);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "New Scheduled Task Created");
    }

    // ── New Executable in Downloads ──

    [Theory]
    [InlineData("setup.exe")]
    [InlineData("installer.msi")]
    [InlineData("screensaver.scr")]
    public void AnalyzeEvent_DetectsNewExecutableInDownloads(string fileName)
    {
        var evt = CreateEvent(
            @"C:\Users\Test\Downloads\" + fileName,
            fileName,
            FileEventType.Created,
            DirectoryCategory.Downloads);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "New Executable Downloaded");
    }

    [Fact]
    public void AnalyzeEvent_IgnoresNonExecutableDownload()
    {
        var evt = CreateEvent(
            @"C:\Users\Test\Downloads\document.pdf",
            "document.pdf",
            FileEventType.Created,
            DirectoryCategory.Downloads);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.DoesNotContain(threats, t => t.Title == "New Executable Downloaded");
    }

    // ── Known-Safe Pattern Detection ──

    [Theory]
    [InlineData(@"C:\Windows\SoftwareDistribution\update.exe")]
    [InlineData(@"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\mpam.dll")]
    [InlineData(@"C:\Users\Test\AppData\Local\WinSentinel\config.json")]
    [InlineData(@"C:\System Volume Information\data.bin")]
    [InlineData(@"C:\Windows\Prefetch\APP.EXE-12345.pf")]
    public void IsKnownSafe_ReturnsTrueForSafePatterns(string path)
    {
        Assert.True(FileSystemMonitorModule.IsKnownSafe(path));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\malware.exe")]
    [InlineData(@"C:\Users\Test\Downloads\suspicious.bat")]
    [InlineData(@"C:\Windows\Tasks\evil.exe")]
    public void IsKnownSafe_ReturnsFalseForSuspiciousPaths(string path)
    {
        Assert.False(FileSystemMonitorModule.IsKnownSafe(path));
    }

    [Theory]
    [InlineData(@"C:\Users\Test\AppData\Local\Temp\data.tmp")]
    [InlineData(@"C:\Users\Test\AppData\Local\Temp\session.log")]
    [InlineData(@"C:\Users\Test\AppData\Local\Temp\trace.etl")]
    public void IsKnownSafe_ReturnsTrueForSafeTempExtensions(string path)
    {
        Assert.True(FileSystemMonitorModule.IsKnownSafe(path));
    }

    // ── System32 Drop Detection (static method) ──

    [Fact]
    public void CheckSystem32Drop_OnlyTriggersForCreated()
    {
        var threats = new List<ThreatEvent>();
        var evt = CreateEvent(@"C:\Windows\System32\test.exe", "test.exe",
            FileEventType.Changed, DirectoryCategory.System32);

        FileSystemMonitorModule.CheckSystem32Drop(evt, threats);
        Assert.Empty(threats);
    }

    // ── Hosts File Detection (static method) ──

    [Fact]
    public void CheckHostsFileModification_Created()
    {
        var threats = new List<ThreatEvent>();
        var evt = CreateEvent(@"C:\Windows\System32\drivers\etc\hosts", "hosts",
            FileEventType.Created, DirectoryCategory.HostsFile);

        FileSystemMonitorModule.CheckHostsFileModification(evt, threats);
        Assert.Single(threats);
        Assert.Equal("Hosts File Modified", threats[0].Title);
    }

    // ── Extension Masquerading (static method) ──

    [Fact]
    public void CheckExtensionMasquerading_DetectsDocExeCombo()
    {
        var threats = new List<ThreatEvent>();
        var evt = CreateEvent(@"C:\Users\Test\Downloads\report.pdf.exe", "report.pdf.exe",
            FileEventType.Created, DirectoryCategory.Downloads);

        FileSystemMonitorModule.CheckExtensionMasquerading(evt, threats);
        Assert.Single(threats);
        Assert.Equal(ThreatSeverity.Critical, threats[0].Severity);
    }

    [Fact]
    public void CheckExtensionMasquerading_IgnoresSingleExtension()
    {
        var threats = new List<ThreatEvent>();
        var evt = CreateEvent(@"C:\Users\Test\Downloads\report.exe", "report.exe",
            FileEventType.Created, DirectoryCategory.Downloads);

        FileSystemMonitorModule.CheckExtensionMasquerading(evt, threats);
        Assert.Empty(threats);
    }

    [Fact]
    public void CheckExtensionMasquerading_IgnoresNonDangerousDoubleExt()
    {
        var threats = new List<ThreatEvent>();
        var evt = CreateEvent(@"C:\Users\Test\Downloads\archive.tar.gz", "archive.tar.gz",
            FileEventType.Created, DirectoryCategory.Downloads);

        FileSystemMonitorModule.CheckExtensionMasquerading(evt, threats);
        Assert.Empty(threats);
    }

    // ── Risk Tolerance Response ──

    [Fact]
    public void AnalyzeEvent_MediumRisk_AlertsOnly()
    {
        _config.RiskTolerance = RiskTolerance.Medium;
        var evt = CreateEvent(
            @"C:\Windows\System32\malware.exe",
            "malware.exe",
            FileEventType.Created,
            DirectoryCategory.System32);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.ResponseTaken != null && t.ResponseTaken.Contains("Alert"));
    }

    [Fact]
    public void AnalyzeEvent_HighRisk_LogsOnly()
    {
        _config.RiskTolerance = RiskTolerance.High;
        var evt = CreateEvent(
            @"C:\Windows\System32\malware.exe",
            "malware.exe",
            FileEventType.Created,
            DirectoryCategory.System32);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.ResponseTaken != null && t.ResponseTaken.Contains("Logged only"));
    }

    // ── Multiple Rules Can Fire ──

    [Fact]
    public void AnalyzeEvent_DownloadsScriptAndMasquerading()
    {
        // A file like "invoice.pdf.bat" in Downloads should trigger both script and masquerading
        var evt = CreateEvent(
            @"C:\Users\Test\Downloads\invoice.pdf.bat",
            "invoice.pdf.bat",
            FileEventType.Created,
            DirectoryCategory.Downloads);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Suspicious Script Created");
        Assert.Contains(threats, t => t.Title == "File Extension Masquerading");
    }

    // ── Rate Limiting ──

    [Fact]
    public void AnalyzeEvent_RateLimitsDuplicateAlerts()
    {
        var evt = CreateEvent(
            @"C:\Windows\System32\malware.exe",
            "malware.exe",
            FileEventType.Created,
            DirectoryCategory.System32);

        _module.AnalyzeEvent(evt);
        _module.AnalyzeEvent(evt); // Should be rate-limited
        _module.AnalyzeEvent(evt); // Should be rate-limited

        var threats = _threatLog.GetAll();
        var system32Threats = threats.Where(t => t.Title == "New Executable in System32").ToList();
        Assert.Single(system32Threats);
    }

    // ── File Hash Utility ──

    [Fact]
    public void ComputeFileHash_ReturnsNullForNonexistentFile()
    {
        var hash = FileSystemMonitorModule.ComputeFileHash(@"C:\NonExistent\file.txt");
        Assert.Null(hash);
    }

    [Fact]
    public void HasContentChanged_ReturnsTrueForNewFile()
    {
        // First time seeing a non-existent file should return true
        var changed = _module.HasContentChanged(@"C:\NonExistent\file.txt");
        Assert.True(changed);
    }

    // ── Startup Persistence — All Users ──

    [Fact]
    public void AnalyzeEvent_DetectsAllUsersStartupPersistence()
    {
        var evt = CreateEvent(
            @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.exe",
            "backdoor.exe",
            FileEventType.Created,
            DirectoryCategory.StartupFolder);

        _module.AnalyzeEvent(evt);

        var threats = _threatLog.GetAll();
        Assert.Contains(threats, t => t.Title == "Startup Folder Persistence" &&
                                      t.Severity == ThreatSeverity.Critical);
    }

    // ── Dangerous Extensions Set ──

    [Theory]
    [InlineData(".exe")]
    [InlineData(".dll")]
    [InlineData(".scr")]
    [InlineData(".bat")]
    [InlineData(".cmd")]
    [InlineData(".ps1")]
    [InlineData(".vbs")]
    [InlineData(".js")]
    [InlineData(".com")]
    [InlineData(".pif")]
    [InlineData(".msi")]
    [InlineData(".wsf")]
    [InlineData(".hta")]
    public void DangerousExtensions_ContainsExpected(string ext)
    {
        Assert.Contains(ext, FileSystemMonitorModule.DangerousExtensions);
    }

    // ── Helpers ──

    private static BufferedEvent CreateEvent(
        string fullPath,
        string fileName,
        FileEventType eventType,
        DirectoryCategory category)
    {
        return new BufferedEvent
        {
            FullPath = fullPath,
            FileName = fileName,
            EventType = eventType,
            Directory = new WatchedDirectory
            {
                Path = Path.GetDirectoryName(fullPath) ?? "",
                Category = category,
                IncludeSubdirectories = false
            },
            FirstSeen = DateTimeOffset.UtcNow,
            LastSeen = DateTimeOffset.UtcNow,
            Count = 1
        };
    }
}
