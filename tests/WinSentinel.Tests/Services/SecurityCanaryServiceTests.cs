using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class SecurityCanaryServiceTests
{
    private readonly SecurityCanaryService _svc = new();

    // ── Basic Analysis ──────────────────────────────────────────────

    [Fact]
    public void Analyze_ReturnsNonNullResult()
    {
        var result = _svc.Analyze();

        Assert.NotNull(result);
        Assert.NotNull(result.Deployments);
        Assert.NotNull(result.TripAlerts);
        Assert.NotNull(result.Recommendations);
        Assert.NotNull(result.CategoryBreakdown);
    }

    [Fact]
    public void Analyze_HasCorrectTotalCanaryCount()
    {
        var result = _svc.Analyze();

        Assert.Equal(15, result.TotalCanaries);
        Assert.Equal(result.Deployments.Count, result.TotalCanaries);
    }

    [Fact]
    public void Analyze_StatusCountsAreMutuallyExclusive()
    {
        var result = _svc.Analyze();

        // Healthy + Tripped + Expired = Total
        Assert.Equal(result.TotalCanaries, result.HealthyCount + result.TrippedCount + result.ExpiredCount);
    }

    [Fact]
    public void Analyze_ScanTimestampIsRecent()
    {
        var before = DateTime.UtcNow;
        var result = _svc.Analyze();
        var after = DateTime.UtcNow;

        Assert.InRange(result.ScanTimestamp, before, after);
    }

    // ── Deployment Status Counts ────────────────────────────────────

    [Fact]
    public void Analyze_DetectsCorrectTrippedCount()
    {
        var result = _svc.Analyze();

        // CAN-001, CAN-002, CAN-004, CAN-013 are tripped
        Assert.Equal(4, result.TrippedCount);
    }

    [Fact]
    public void Analyze_DetectsCorrectExpiredCount()
    {
        var result = _svc.Analyze();

        // CAN-008, CAN-012 are expired
        Assert.Equal(2, result.ExpiredCount);
    }

    [Fact]
    public void Analyze_DetectsCorrectHealthyCount()
    {
        var result = _svc.Analyze();

        // 15 total - 4 tripped - 2 expired = 9 healthy
        Assert.Equal(9, result.HealthyCount);
    }

    // ── Health Score Calculation ────────────────────────────────────

    [Fact]
    public void Analyze_HealthScoreCalculatedCorrectly()
    {
        var result = _svc.Analyze();

        // Formula: 100 - (tripped * 18) - (expired * 5)
        // 100 - (4 * 18) - (2 * 5) = 100 - 72 - 10 = 18
        Assert.Equal(18, result.NetworkHealthScore);
    }

    [Fact]
    public void Analyze_HealthScoreNeverNegative()
    {
        var result = _svc.Analyze();

        Assert.InRange(result.NetworkHealthScore, 0, 100);
    }

    // ── Threat Level Classification ─────────────────────────────────

    [Fact]
    public void Analyze_ThreatLevelIsCriticalWith4Trips()
    {
        var result = _svc.Analyze();

        // 4 tripped canaries → CRITICAL
        Assert.StartsWith("CRITICAL", result.ThreatLevel);
        Assert.Contains("Active intrusion likely", result.ThreatLevel);
    }

    [Fact]
    public void Analyze_ThreatLevelIsNotEmpty()
    {
        var result = _svc.Analyze();

        Assert.False(string.IsNullOrWhiteSpace(result.ThreatLevel));
    }

    // ── Category Breakdown ──────────────────────────────────────────

    [Fact]
    public void Analyze_CategoryBreakdownHasAllTypes()
    {
        var result = _svc.Analyze();

        Assert.True(result.CategoryBreakdown.ContainsKey("Credential Canaries"));
        Assert.True(result.CategoryBreakdown.ContainsKey("Config Canaries"));
        Assert.True(result.CategoryBreakdown.ContainsKey("Database Canaries"));
        Assert.True(result.CategoryBreakdown.ContainsKey("Document Canaries"));
        Assert.True(result.CategoryBreakdown.ContainsKey("Registry Canaries"));
    }

    [Fact]
    public void Analyze_CategoryBreakdownSumsToTotal()
    {
        var result = _svc.Analyze();

        int sum = result.CategoryBreakdown.Values.Sum();
        Assert.Equal(result.TotalCanaries, sum);
    }

    [Fact]
    public void Analyze_CredentialCanariesCountIsCorrect()
    {
        var result = _svc.Analyze();

        // CAN-001 (passwords.txt), CAN-005 (aws_credentials), CAN-006 (id_rsa), CAN-010 (sa_password.txt) = 4
        Assert.Equal(4, result.CategoryBreakdown["Credential Canaries"]);
    }

    [Fact]
    public void Analyze_ConfigCanariesCountIsCorrect()
    {
        var result = _svc.Analyze();

        // CAN-002 (.env.production), CAN-007 (web.config.bak), CAN-012 (connection_strings.json), CAN-015 (kubeconfig) = 4
        Assert.Equal(4, result.CategoryBreakdown["Config Canaries"]);
    }

    [Fact]
    public void Analyze_RegistryCanariesCountIsCorrect()
    {
        var result = _svc.Analyze();

        // CAN-011, CAN-013 = 2
        Assert.Equal(2, result.CategoryBreakdown["Registry Canaries"]);
    }

    // ── Trip Alerts ─────────────────────────────────────────────────

    [Fact]
    public void Analyze_GeneratesAlertsForAllTrippedCanaries()
    {
        var result = _svc.Analyze();

        Assert.Equal(4, result.TripAlerts.Count);
    }

    [Fact]
    public void Analyze_TripAlertsHaveValidCanaryIds()
    {
        var result = _svc.Analyze();

        var validIds = result.Deployments.Select(d => d.Id).ToHashSet();
        foreach (var alert in result.TripAlerts)
        {
            Assert.Contains(alert.CanaryId, validIds);
        }
    }

    [Fact]
    public void Analyze_TripAlertsHaveNonEmptyFields()
    {
        var result = _svc.Analyze();

        foreach (var alert in result.TripAlerts)
        {
            Assert.False(string.IsNullOrWhiteSpace(alert.CanaryId));
            Assert.False(string.IsNullOrWhiteSpace(alert.CanaryName));
            Assert.False(string.IsNullOrWhiteSpace(alert.TripType));
            Assert.False(string.IsNullOrWhiteSpace(alert.ProcessName));
            Assert.True(alert.ProcessId > 0);
            Assert.False(string.IsNullOrWhiteSpace(alert.UserAccount));
            Assert.False(string.IsNullOrWhiteSpace(alert.Severity));
            Assert.False(string.IsNullOrWhiteSpace(alert.Assessment));
            Assert.False(string.IsNullOrWhiteSpace(alert.MitreAttackTechnique));
        }
    }

    [Fact]
    public void Analyze_MimikatzTripIsCritical()
    {
        var result = _svc.Analyze();

        var mimikatzAlert = result.TripAlerts.First(a => a.CanaryId == "CAN-001");
        Assert.Equal("Critical", mimikatzAlert.Severity);
        Assert.Equal("mimikatz.exe", mimikatzAlert.ProcessName);
        Assert.Contains("T1003", mimikatzAlert.MitreAttackTechnique);
    }

    [Fact]
    public void Analyze_EnvFileModifiedTrip()
    {
        var result = _svc.Analyze();

        var envAlert = result.TripAlerts.First(a => a.CanaryId == "CAN-002");
        Assert.Equal("Modified", envAlert.TripType);
        Assert.Equal("cmd.exe", envAlert.ProcessName);
        Assert.Contains("T1083", envAlert.MitreAttackTechnique);
    }

    [Fact]
    public void Analyze_FileShareTripIsWarning()
    {
        var result = _svc.Analyze();

        var shareAlert = result.TripAlerts.First(a => a.CanaryId == "CAN-004");
        Assert.Equal("Warning", shareAlert.Severity);
        Assert.Equal("explorer.exe", shareAlert.ProcessName);
        Assert.Contains("T1039", shareAlert.MitreAttackTechnique);
    }

    [Fact]
    public void Analyze_RegistryTripIsCritical()
    {
        var result = _svc.Analyze();

        var regAlert = result.TripAlerts.First(a => a.CanaryId == "CAN-013");
        Assert.Equal("Critical", regAlert.Severity);
        Assert.Equal("reg.exe", regAlert.ProcessName);
        Assert.Contains("T1547", regAlert.MitreAttackTechnique);
    }

    [Fact]
    public void Analyze_TripTimestampsAreRecent()
    {
        var result = _svc.Analyze();

        var now = DateTime.UtcNow;
        foreach (var alert in result.TripAlerts)
        {
            // All trips should be within the last 2 days
            Assert.True((now - alert.TrippedAt).TotalDays <= 2,
                $"Trip alert {alert.CanaryId} has stale timestamp: {alert.TrippedAt}");
        }
    }

    [Fact]
    public void Analyze_TripTypesAreAccessedOrModified()
    {
        var result = _svc.Analyze();

        var validTypes = new[] { "Accessed", "Modified" };
        foreach (var alert in result.TripAlerts)
        {
            Assert.Contains(alert.TripType, validTypes);
        }
    }

    // ── Deployment Properties ───────────────────────────────────────

    [Fact]
    public void Analyze_AllDeploymentsHaveUniqueIds()
    {
        var result = _svc.Analyze();

        var ids = result.Deployments.Select(d => d.Id).ToList();
        Assert.Equal(ids.Distinct().Count(), ids.Count);
    }

    [Fact]
    public void Analyze_DeploymentIdsFollowNamingConvention()
    {
        var result = _svc.Analyze();

        foreach (var deployment in result.Deployments)
        {
            Assert.Matches(@"^CAN-\d{3}$", deployment.Id);
        }
    }

    [Fact]
    public void Analyze_AllDeploymentsHaveValidStatus()
    {
        var result = _svc.Analyze();

        var validStatuses = new[] { "Healthy", "Tripped", "Expired" };
        foreach (var deployment in result.Deployments)
        {
            Assert.Contains(deployment.Status, validStatuses);
        }
    }

    [Fact]
    public void Analyze_AllDeploymentsHaveValidType()
    {
        var result = _svc.Analyze();

        var validTypes = new[] { "Credential", "Config", "Database", "Document", "Registry" };
        foreach (var deployment in result.Deployments)
        {
            Assert.Contains(deployment.Type, validTypes);
        }
    }

    [Fact]
    public void Analyze_AllDeploymentsHaveValidRiskLevel()
    {
        var result = _svc.Analyze();

        var validLevels = new[] { "Low", "Medium", "High" };
        foreach (var deployment in result.Deployments)
        {
            Assert.Contains(deployment.RiskLevel, validLevels);
        }
    }

    [Fact]
    public void Analyze_TrippedCanariesHaveHighRiskLevel()
    {
        var result = _svc.Analyze();

        var tripped = result.Deployments.Where(d => d.Status == "Tripped");
        foreach (var deployment in tripped)
        {
            Assert.Equal("High", deployment.RiskLevel);
        }
    }

    [Fact]
    public void Analyze_DeployedAtIsInPast()
    {
        var result = _svc.Analyze();

        var now = DateTime.UtcNow;
        foreach (var deployment in result.Deployments)
        {
            Assert.True(deployment.DeployedAt < now,
                $"Deployment {deployment.Id} has future deploy date");
        }
    }

    [Fact]
    public void Analyze_ExpiredCanariesHaveStaleLastChecked()
    {
        var result = _svc.Analyze();

        var expired = result.Deployments.Where(d => d.Status == "Expired");
        var now = DateTime.UtcNow;
        foreach (var deployment in expired)
        {
            Assert.NotNull(deployment.LastChecked);
            // Expired canaries have been unchecked for days
            Assert.True((now - deployment.LastChecked!.Value).TotalDays > 1,
                $"Expired canary {deployment.Id} was recently checked");
        }
    }

    [Fact]
    public void Analyze_HealthyCanariesWereRecentlyChecked()
    {
        var result = _svc.Analyze();

        var healthy = result.Deployments.Where(d => d.Status == "Healthy");
        var now = DateTime.UtcNow;
        foreach (var deployment in healthy)
        {
            Assert.NotNull(deployment.LastChecked);
            // Healthy canaries should have been checked in the last hour
            Assert.True((now - deployment.LastChecked!.Value).TotalHours < 1,
                $"Healthy canary {deployment.Id} was not recently checked");
        }
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Analyze_RecommendationsAreNotEmpty()
    {
        var result = _svc.Analyze();

        Assert.NotEmpty(result.Recommendations);
        foreach (var rec in result.Recommendations)
        {
            Assert.False(string.IsNullOrWhiteSpace(rec));
        }
    }

    [Fact]
    public void Analyze_UrgentRecommendationWhenTripped()
    {
        var result = _svc.Analyze();

        // With 4 trips, should have urgent recommendation
        Assert.Contains(result.Recommendations, r => r.Contains("URGENT") && r.Contains("incident response"));
    }

    [Fact]
    public void Analyze_CredentialDumpingRecommendation()
    {
        var result = _svc.Analyze();

        // CAN-001 trip has T1003 (credential dumping)
        Assert.Contains(result.Recommendations, r => r.Contains("Credential dumping") || r.Contains("credential"));
    }

    [Fact]
    public void Analyze_FileDiscoveryRecommendation()
    {
        var result = _svc.Analyze();

        // CAN-002 trip has T1083 (file discovery)
        Assert.Contains(result.Recommendations, r => r.Contains("File discovery") || r.Contains("reconnaissance"));
    }

    [Fact]
    public void Analyze_ExpiredCanaryRedeployRecommendation()
    {
        var result = _svc.Analyze();

        // With 2 expired, should recommend redeployment
        Assert.Contains(result.Recommendations, r => r.Contains("expired") && r.Contains("edeploy"));
    }

    [Fact]
    public void Analyze_RotationRecommendationAlwaysPresent()
    {
        var result = _svc.Analyze();

        Assert.Contains(result.Recommendations, r => r.Contains("Rotate canary"));
    }

    [Fact]
    public void Analyze_CriticalSeverityRecommendation()
    {
        var result = _svc.Analyze();

        // Multiple critical alerts → should recommend isolation
        Assert.Contains(result.Recommendations, r =>
            r.Contains("Critical severity") || r.Contains("credential harvesting") || r.Contains("lateral movement"));
    }

    // ── MITRE ATT&CK Coverage ───────────────────────────────────────

    [Fact]
    public void Analyze_MitreAttackTechniquesAreMapped()
    {
        var result = _svc.Analyze();

        var techniques = result.TripAlerts.Select(a => a.MitreAttackTechnique).ToList();
        Assert.Contains(techniques, t => t.Contains("T1003")); // Credential Dumping
        Assert.Contains(techniques, t => t.Contains("T1083")); // File Discovery
        Assert.Contains(techniques, t => t.Contains("T1039")); // Data from Network Shared Drive
        Assert.Contains(techniques, t => t.Contains("T1547")); // Boot/Logon Autostart
    }

    [Fact]
    public void Analyze_MitreAttackTechniquesHaveDescriptions()
    {
        var result = _svc.Analyze();

        foreach (var alert in result.TripAlerts)
        {
            // Format: "T1234.001 — Description"
            Assert.Contains("—", alert.MitreAttackTechnique);
            Assert.Matches(@"T\d{4}", alert.MitreAttackTechnique);
        }
    }

    // ── Deployment Locations ────────────────────────────────────────

    [Fact]
    public void Analyze_DeploymentLocationsAreNonEmpty()
    {
        var result = _svc.Analyze();

        foreach (var deployment in result.Deployments)
        {
            Assert.False(string.IsNullOrWhiteSpace(deployment.Location));
        }
    }

    [Fact]
    public void Analyze_DeploymentNamesAreNonEmpty()
    {
        var result = _svc.Analyze();

        foreach (var deployment in result.Deployments)
        {
            Assert.False(string.IsNullOrWhiteSpace(deployment.Name));
        }
    }

    [Fact]
    public void Analyze_RegistryCanariesHaveRegistryLocation()
    {
        var result = _svc.Analyze();

        var registryCanaries = result.Deployments.Where(d => d.Type == "Registry");
        foreach (var canary in registryCanaries)
        {
            Assert.Equal("Registry", canary.Location);
        }
    }

    [Fact]
    public void Analyze_FileCanariesHavePathLocations()
    {
        var result = _svc.Analyze();

        var fileCanaries = result.Deployments.Where(d => d.Type != "Registry");
        foreach (var canary in fileCanaries)
        {
            // Should be a path (contains backslash or drive letter)
            Assert.True(canary.Location.Contains('\\') || canary.Location.Contains(':'),
                $"File canary {canary.Id} location '{canary.Location}' doesn't look like a path");
        }
    }

    // ── Alert-Deployment Correlation ────────────────────────────────

    [Fact]
    public void Analyze_AlertCanaryNamesMatchDeployments()
    {
        var result = _svc.Analyze();

        foreach (var alert in result.TripAlerts)
        {
            var deployment = result.Deployments.First(d => d.Id == alert.CanaryId);
            Assert.Equal(deployment.Name, alert.CanaryName);
        }
    }

    [Fact]
    public void Analyze_OnlyTrippedDeploymentsHaveAlerts()
    {
        var result = _svc.Analyze();

        var alertedIds = result.TripAlerts.Select(a => a.CanaryId).ToHashSet();
        var trippedIds = result.Deployments.Where(d => d.Status == "Tripped").Select(d => d.Id).ToHashSet();

        Assert.True(alertedIds.SetEquals(trippedIds));
    }

    // ── Service Consistency ─────────────────────────────────────────

    [Fact]
    public void Analyze_IsIdempotent()
    {
        var result1 = _svc.Analyze();
        var result2 = _svc.Analyze();

        Assert.Equal(result1.TotalCanaries, result2.TotalCanaries);
        Assert.Equal(result1.TrippedCount, result2.TrippedCount);
        Assert.Equal(result1.ExpiredCount, result2.ExpiredCount);
        Assert.Equal(result1.TripAlerts.Count, result2.TripAlerts.Count);
        Assert.Equal(result1.Recommendations.Count, result2.Recommendations.Count);
    }

    [Fact]
    public void Analyze_MultipleInstancesProduceSameStructure()
    {
        var svc2 = new SecurityCanaryService();
        var result1 = _svc.Analyze();
        var result2 = svc2.Analyze();

        Assert.Equal(result1.TotalCanaries, result2.TotalCanaries);
        Assert.Equal(result1.NetworkHealthScore, result2.NetworkHealthScore);
        Assert.Equal(result1.CategoryBreakdown.Count, result2.CategoryBreakdown.Count);
    }
}
