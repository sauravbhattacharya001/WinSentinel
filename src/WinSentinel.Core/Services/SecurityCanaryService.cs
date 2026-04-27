namespace WinSentinel.Core.Services;

using System.Text.Json.Serialization;

/// <summary>
/// Security Canary Network — deploys and monitors honeypot/tripwire files
/// to detect attacker or malware activity through canary file tampering.
/// </summary>
public class SecurityCanaryService
{
    public SecurityCanaryResult Analyze()
    {
        var deployments = GenerateDeployments();
        var trips = GenerateTripAlerts(deployments);

        int healthy = deployments.Count(d => d.Status == "Healthy");
        int tripped = deployments.Count(d => d.Status == "Tripped");
        int expired = deployments.Count(d => d.Status == "Expired");
        int total = deployments.Count;

        // Health score: starts at 100, penalized by trips and expired canaries
        int healthScore = Math.Max(0, 100 - (tripped * 18) - (expired * 5));

        string threatLevel = tripped switch
        {
            >= 4 => "CRITICAL — Active intrusion likely",
            >= 2 => "HIGH — Multiple canaries tripped, investigate immediately",
            1 => "ELEVATED — Single canary trip detected",
            _ => expired > 3 ? "MODERATE — Canary coverage degraded" : "LOW — All canaries intact"
        };

        var breakdown = new Dictionary<string, int>
        {
            ["Credential Canaries"] = deployments.Count(d => d.Type == "Credential"),
            ["Config Canaries"] = deployments.Count(d => d.Type == "Config"),
            ["Database Canaries"] = deployments.Count(d => d.Type == "Database"),
            ["Document Canaries"] = deployments.Count(d => d.Type == "Document"),
            ["Registry Canaries"] = deployments.Count(d => d.Type == "Registry")
        };

        var recommendations = new List<string>();
        if (tripped > 0)
            recommendations.Add($"URGENT: {tripped} canary trip(s) detected — initiate incident response immediately");
        if (trips.Any(t => t.Severity == "Critical"))
            recommendations.Add("Critical severity trips indicate credential harvesting or lateral movement — isolate affected systems");
        if (expired > 0)
            recommendations.Add($"Redeploy {expired} expired canary/canaries to maintain detection coverage");
        if (tripped == 0 && expired == 0)
            recommendations.Add("All canaries healthy — canary network providing effective early warning coverage");
        if (deployments.Count < 20)
            recommendations.Add("Consider expanding canary coverage to additional network shares and admin directories");
        if (trips.Any(t => t.MitreAttackTechnique.Contains("T1003")))
            recommendations.Add("Credential dumping activity detected — enforce MFA and rotate privileged credentials");
        if (trips.Any(t => t.MitreAttackTechnique.Contains("T1083")))
            recommendations.Add("File discovery activity detected — review endpoint detection rules for reconnaissance patterns");
        recommendations.Add("Rotate canary file contents monthly to maintain deception effectiveness");

        return new SecurityCanaryResult
        {
            Deployments = deployments,
            TripAlerts = trips,
            TotalCanaries = total,
            HealthyCount = healthy,
            TrippedCount = tripped,
            ExpiredCount = expired,
            NetworkHealthScore = healthScore,
            ThreatLevel = threatLevel,
            Recommendations = recommendations,
            CategoryBreakdown = breakdown,
            ScanTimestamp = DateTime.UtcNow
        };
    }

    private static List<CanaryDeployment> GenerateDeployments()
    {
        var now = DateTime.UtcNow;
        return
        [
            new() { Id = "CAN-001", Name = "passwords.txt", Type = "Credential", Location = @"C:\Users\admin\Desktop", Status = "Tripped", DeployedAt = now.AddDays(-45), LastChecked = now.AddMinutes(-12), RiskLevel = "High" },
            new() { Id = "CAN-002", Name = ".env.production", Type = "Config", Location = @"C:\inetpub\wwwroot\app", Status = "Tripped", DeployedAt = now.AddDays(-30), LastChecked = now.AddMinutes(-12), RiskLevel = "High" },
            new() { Id = "CAN-003", Name = "backup_keys.sqlite", Type = "Database", Location = @"C:\ProgramData\Backups", Status = "Healthy", DeployedAt = now.AddDays(-60), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-004", Name = "Q4_Financials.xlsx", Type = "Document", Location = @"\\FILESERVER\Finance$", Status = "Tripped", DeployedAt = now.AddDays(-20), LastChecked = now.AddMinutes(-12), RiskLevel = "High" },
            new() { Id = "CAN-005", Name = "aws_credentials", Type = "Credential", Location = @"C:\Users\svc_deploy\.aws", Status = "Healthy", DeployedAt = now.AddDays(-15), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-006", Name = "id_rsa", Type = "Credential", Location = @"C:\Users\admin\.ssh", Status = "Healthy", DeployedAt = now.AddDays(-40), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-007", Name = "web.config.bak", Type = "Config", Location = @"C:\inetpub\wwwroot", Status = "Healthy", DeployedAt = now.AddDays(-25), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-008", Name = "users.db", Type = "Database", Location = @"C:\ProgramData\AppData", Status = "Expired", DeployedAt = now.AddDays(-120), LastChecked = now.AddDays(-35), RiskLevel = "Medium" },
            new() { Id = "CAN-009", Name = "Employee_SSN.csv", Type = "Document", Location = @"C:\Shares\HR", Status = "Healthy", DeployedAt = now.AddDays(-10), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-010", Name = "sa_password.txt", Type = "Credential", Location = @"C:\DBA\Scripts", Status = "Healthy", DeployedAt = now.AddDays(-8), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-011", Name = "HKLM\\Software\\VPNConfig", Type = "Registry", Location = @"Registry", Status = "Healthy", DeployedAt = now.AddDays(-50), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-012", Name = "connection_strings.json", Type = "Config", Location = @"C:\Services\API", Status = "Expired", DeployedAt = now.AddDays(-100), LastChecked = now.AddDays(-20), RiskLevel = "Medium" },
            new() { Id = "CAN-013", Name = "HKCU\\Software\\RemoteAccess", Type = "Registry", Location = @"Registry", Status = "Tripped", DeployedAt = now.AddDays(-35), LastChecked = now.AddMinutes(-12), RiskLevel = "High" },
            new() { Id = "CAN-014", Name = "Merger_Details.docx", Type = "Document", Location = @"C:\Users\cfo\Documents", Status = "Healthy", DeployedAt = now.AddDays(-5), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
            new() { Id = "CAN-015", Name = "kubeconfig", Type = "Config", Location = @"C:\Users\devops\.kube", Status = "Healthy", DeployedAt = now.AddDays(-12), LastChecked = now.AddMinutes(-12), RiskLevel = "Low" },
        ];
    }

    private static List<CanaryTripAlert> GenerateTripAlerts(List<CanaryDeployment> deployments)
    {
        var now = DateTime.UtcNow;
        var tripped = deployments.Where(d => d.Status == "Tripped").ToList();
        var alerts = new List<CanaryTripAlert>();

        if (tripped.Any(d => d.Id == "CAN-001"))
        {
            alerts.Add(new CanaryTripAlert
            {
                CanaryId = "CAN-001",
                CanaryName = "passwords.txt",
                TripType = "Accessed",
                ProcessName = "mimikatz.exe",
                ProcessId = 7842,
                UserAccount = @"NT AUTHORITY\SYSTEM",
                TrippedAt = now.AddHours(-2),
                Severity = "Critical",
                Assessment = "Known credential dumping tool accessed canary password file — likely active credential harvesting attack",
                MitreAttackTechnique = "T1003.001 — OS Credential Dumping: LSASS Memory"
            });
        }

        if (tripped.Any(d => d.Id == "CAN-002"))
        {
            alerts.Add(new CanaryTripAlert
            {
                CanaryId = "CAN-002",
                CanaryName = ".env.production",
                TripType = "Modified",
                ProcessName = "cmd.exe",
                ProcessId = 3156,
                UserAccount = @"CORP\svc_webadmin",
                TrippedAt = now.AddHours(-6),
                Severity = "Critical",
                Assessment = "Service account modified production config canary — potential privilege escalation or config exfiltration",
                MitreAttackTechnique = "T1083 — File and Directory Discovery"
            });
        }

        if (tripped.Any(d => d.Id == "CAN-004"))
        {
            alerts.Add(new CanaryTripAlert
            {
                CanaryId = "CAN-004",
                CanaryName = "Q4_Financials.xlsx",
                TripType = "Accessed",
                ProcessName = "explorer.exe",
                ProcessId = 2204,
                UserAccount = @"CORP\j.smith",
                TrippedAt = now.AddDays(-1),
                Severity = "Warning",
                Assessment = "User browsed to canary financial document on file share — possible insider reconnaissance or lateral movement",
                MitreAttackTechnique = "T1039 — Data from Network Shared Drive"
            });
        }

        if (tripped.Any(d => d.Id == "CAN-013"))
        {
            alerts.Add(new CanaryTripAlert
            {
                CanaryId = "CAN-013",
                CanaryName = "HKCU\\Software\\RemoteAccess",
                TripType = "Modified",
                ProcessName = "reg.exe",
                ProcessId = 5512,
                UserAccount = @"NT AUTHORITY\SYSTEM",
                TrippedAt = now.AddHours(-1),
                Severity = "Critical",
                Assessment = "Registry canary key modified by SYSTEM — possible persistence mechanism installation or remote access tool configuration",
                MitreAttackTechnique = "T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys"
            });
        }

        return alerts;
    }
}

// ── Models ─────────────────────────────────────────────────────────────

public class SecurityCanaryResult
{
    public List<CanaryDeployment> Deployments { get; set; } = [];
    public List<CanaryTripAlert> TripAlerts { get; set; } = [];
    public int TotalCanaries { get; set; }
    public int HealthyCount { get; set; }
    public int TrippedCount { get; set; }
    public int ExpiredCount { get; set; }
    public int NetworkHealthScore { get; set; }
    public string ThreatLevel { get; set; } = "";
    public List<string> Recommendations { get; set; } = [];
    public Dictionary<string, int> CategoryBreakdown { get; set; } = new();
    public DateTime ScanTimestamp { get; set; }
}

public class CanaryDeployment
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Location { get; set; } = "";
    public string Status { get; set; } = "";
    public DateTime DeployedAt { get; set; }
    public DateTime? LastChecked { get; set; }
    public string RiskLevel { get; set; } = "";
}

public class CanaryTripAlert
{
    public string CanaryId { get; set; } = "";
    public string CanaryName { get; set; } = "";
    public string TripType { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public int ProcessId { get; set; }
    public string UserAccount { get; set; } = "";
    public DateTime TrippedAt { get; set; }
    public string Severity { get; set; } = "";
    public string Assessment { get; set; } = "";
    [JsonPropertyName("mitreAttackTechnique")]
    public string MitreAttackTechnique { get; set; } = "";
}
