namespace WinSentinel.Core.Services;

using System.Text.Json.Serialization;

public class ShadowItDetectorService
{
    public ShadowItResult Detect()
    {
        var services = GetUnknownServices();
        var ports = GetSuspiciousListeningPorts();
        var startup = GetUnauthorizedStartupPrograms();
        var tasks = GetShadowScheduledTasks();

        var allRisks = services.Select(s => s.RiskLevel)
            .Concat(ports.Select(p => p.RiskLevel))
            .Concat(startup.Select(s => s.RiskLevel))
            .Concat(tasks.Select(t => t.RiskLevel))
            .ToList();

        int highCount = allRisks.Count(r => r == "High");
        int medCount = allRisks.Count(r => r == "Medium");
        int lowCount = allRisks.Count(r => r == "Low");
        int total = allRisks.Count;

        int riskScore = Math.Min(100, highCount * 20 + medCount * 8 + lowCount * 2);

        var recommendations = new List<string>();
        if (highCount > 0)
            recommendations.Add("Immediately investigate high-risk findings — potential unauthorized software detected");
        if (services.Count > 0)
            recommendations.Add($"Review {services.Count} unknown service(s) and add legitimate ones to your whitelist");
        if (ports.Count > 0)
            recommendations.Add($"Audit {ports.Count} suspicious listening port(s) — block unauthorized network services");
        if (startup.Count > 0)
            recommendations.Add($"Remove or authorize {startup.Count} startup program(s) to reduce attack surface");
        if (tasks.Count > 0)
            recommendations.Add($"Review {tasks.Count} non-standard scheduled task(s) for persistence mechanisms");
        if (riskScore > 50)
            recommendations.Add("Consider implementing application whitelisting (AppLocker/WDAC)");
        if (riskScore <= 20)
            recommendations.Add("Low shadow IT footprint — maintain monitoring to keep it that way");

        var breakdown = new Dictionary<string, int>
        {
            ["Unknown Services"] = services.Count,
            ["Suspicious Ports"] = ports.Count,
            ["Unauthorized Startup"] = startup.Count,
            ["Shadow Tasks"] = tasks.Count
        };

        return new ShadowItResult
        {
            UnknownServices = services,
            SuspiciousListeningPorts = ports,
            UnauthorizedStartupPrograms = startup,
            ShadowScheduledTasks = tasks,
            OverallRiskScore = riskScore,
            TotalFindings = total,
            HighRiskCount = highCount,
            MediumRiskCount = medCount,
            LowRiskCount = lowCount,
            CategoryBreakdown = breakdown,
            Recommendations = recommendations,
            ScanTimestamp = DateTime.UtcNow
        };
    }

    private List<UnknownServiceInfo> GetUnknownServices()
    {
        // Demo data — in production would query ServiceController
        return new List<UnknownServiceInfo>
        {
            new() { Name = "CryptoMinerSvc", DisplayName = "System Optimization Helper", Status = "Running", StartType = "Automatic", RiskLevel = "High" },
            new() { Name = "RemoteToolDaemon", DisplayName = "Remote Tool Daemon", Status = "Running", StartType = "Automatic", RiskLevel = "High" },
            new() { Name = "CloudSyncAgent", DisplayName = "Personal Cloud Sync", Status = "Running", StartType = "Automatic", RiskLevel = "Medium" },
            new() { Name = "GameLauncherSvc", DisplayName = "Game Platform Service", Status = "Stopped", StartType = "Manual", RiskLevel = "Low" },
            new() { Name = "VpnBypassTunnel", DisplayName = "Network Optimizer", Status = "Running", StartType = "Automatic", RiskLevel = "High" },
        };
    }

    private List<SuspiciousPortInfo> GetSuspiciousListeningPorts()
    {
        return new List<SuspiciousPortInfo>
        {
            new() { Port = 4444, Protocol = "TCP", ProcessName = "svchost_helper.exe", Pid = 8812, RiskLevel = "High" },
            new() { Port = 8888, Protocol = "TCP", ProcessName = "proxy_agent.exe", Pid = 5520, RiskLevel = "Medium" },
            new() { Port = 9090, Protocol = "TCP", ProcessName = "cloud_sync.exe", Pid = 3344, RiskLevel = "Medium" },
            new() { Port = 6667, Protocol = "TCP", ProcessName = "chat_relay.exe", Pid = 7712, RiskLevel = "High" },
        };
    }

    private List<UnauthorizedStartupInfo> GetUnauthorizedStartupPrograms()
    {
        return new List<UnauthorizedStartupInfo>
        {
            new() { Name = "SystemOptimizer", Command = @"C:\ProgramData\sysopt\optimizer.exe --silent", Location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RiskLevel = "High" },
            new() { Name = "CloudBackup", Command = @"C:\Users\user\AppData\Local\CloudBak\sync.exe", Location = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RiskLevel = "Medium" },
            new() { Name = "GameOverlay", Command = @"C:\Program Files\GamePlatform\overlay.exe", Location = "Startup Folder", RiskLevel = "Low" },
        };
    }

    private List<ShadowTaskInfo> GetShadowScheduledTasks()
    {
        return new List<ShadowTaskInfo>
        {
            new() { Name = @"\CustomTasks\DataExfil", NextRunTime = DateTime.UtcNow.AddHours(2), Author = "UNKNOWN", RiskLevel = "High" },
            new() { Name = @"\UserTasks\SyncPhotos", NextRunTime = DateTime.UtcNow.AddHours(6), Author = "LocalUser", RiskLevel = "Low" },
            new() { Name = @"\Maintenance\CryptoUpdate", NextRunTime = DateTime.UtcNow.AddMinutes(30), Author = "SYSTEM", RiskLevel = "Medium" },
        };
    }
}

public class ShadowItResult
{
    public List<UnknownServiceInfo> UnknownServices { get; set; } = new();
    public List<SuspiciousPortInfo> SuspiciousListeningPorts { get; set; } = new();
    public List<UnauthorizedStartupInfo> UnauthorizedStartupPrograms { get; set; } = new();
    public List<ShadowTaskInfo> ShadowScheduledTasks { get; set; } = new();
    public int OverallRiskScore { get; set; }
    public int TotalFindings { get; set; }
    public int HighRiskCount { get; set; }
    public int MediumRiskCount { get; set; }
    public int LowRiskCount { get; set; }
    public Dictionary<string, int> CategoryBreakdown { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
    public DateTime ScanTimestamp { get; set; }
}

public class UnknownServiceInfo
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Status { get; set; } = "";
    public string StartType { get; set; } = "";
    public string RiskLevel { get; set; } = "";
}

public class SuspiciousPortInfo
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public int Pid { get; set; }
    public string RiskLevel { get; set; } = "";
}

public class UnauthorizedStartupInfo
{
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public string Location { get; set; } = "";
    public string RiskLevel { get; set; } = "";
}

public class ShadowTaskInfo
{
    public string Name { get; set; } = "";
    public DateTime? NextRunTime { get; set; }
    public string Author { get; set; } = "";
    public string RiskLevel { get; set; } = "";
}
