using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

public class ExecutionDetectorTests
{
    private static AuditHistoryService CreateHistory() => new();

    private static SecurityReport MakeReport(params (string title, string desc)[] findings)
    {
        var report = new SecurityReport();
        var result = new AuditResult { ModuleName = "TestModule", Category = "TestModule" };
        foreach (var (title, desc) in findings)
            result.Findings.Add(new Finding { Title = title, Description = desc });
        report.Results.Add(result);
        return report;
    }

    // ── Basic Behavior ──────────────────────────────────────────────

    [Fact]
    public void Detect_EmptyReport_ReturnsCleanReport()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.ExecutionsDetected);
        Assert.Equal(0, result.ThreatScore);
        Assert.Equal("Minimal", result.ThreatLevel);
        Assert.Empty(result.Executions);
        Assert.Empty(result.Campaigns);
    }

    [Fact]
    public void Detect_NoExecutionFindings_ReturnsZeroExecutions()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Firewall enabled", "Windows firewall is active and configured"));
        var result = detector.Detect(report);

        Assert.Equal(0, result.ExecutionsDetected);
        Assert.Equal("Minimal", result.ThreatLevel);
    }

    // ── Technique Detection ─────────────────────────────────────────

    [Fact]
    public void Detect_PowerShell_DetectsScriptingExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("PowerShell execution", "Invoke-Expression used to execute downloaded payload via powershell"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("PowerShell", result.Executions[0].Technique);
        Assert.Equal("T1059.001", result.Executions[0].MitreTechnique);
        Assert.Equal("Scripting", result.Executions[0].ExecutionMethod);
    }

    [Fact]
    public void Detect_CmdExe_DetectsCommandShell()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Command shell activity", "cmd.exe spawned with suspicious arguments"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Windows Command Shell", result.Executions[0].Technique);
        Assert.Equal("T1059.003", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_VBScript_DetectsVisualBasicExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("VBScript execution", "wscript.exe running suspicious vbscript from temp directory"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Visual Basic", result.Executions[0].Technique);
        Assert.Equal("T1059.005", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_Python_DetectsPythonExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Python script launched", "python.exe executing suspicious python script from downloads"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Python", result.Executions[0].Technique);
        Assert.Equal("T1059.006", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_JavaScript_DetectsJSExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("JScript payload", "jscript.encode execution detected with activexobject spawning shell"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("JavaScript", result.Executions[0].Technique);
        Assert.Equal("T1059.007", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_WMI_DetectsWMIExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("WMI process creation", "wmic process call create used for WMI execution"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Windows Management Instrumentation", result.Executions[0].Technique);
        Assert.Equal("T1047", result.Executions[0].MitreTechnique);
        Assert.Equal("WMI", result.Executions[0].ExecutionMethod);
    }

    [Fact]
    public void Detect_ScheduledTask_DetectsTaskExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Scheduled task created", "schtasks /create used to schedule malicious task execution"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Scheduled Task/Job", result.Executions[0].Technique);
        Assert.Equal("T1053.005", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_ServiceExecution_DetectsServiceAbuse()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Suspicious service creation", "sc create used for service execution with malicious binpath"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("System Services: Service Execution", result.Executions[0].Technique);
        Assert.Equal("T1569.002", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_Exploit_DetectsExploitExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Client exploitation", "Exploit for client execution via browser exploit targeting vulnerability"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Exploitation for Client Execution", result.Executions[0].Technique);
        Assert.Equal("T1203", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_MaliciousLink_DetectsUserExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Phishing alert", "User clicked malicious link leading to drive-by download"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("User Execution: Malicious Link", result.Executions[0].Technique);
        Assert.Equal("T1204.001", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_MaliciousFile_DetectsFileExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Suspicious file opened", "User executed malicious file with double extension .doc.exe"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("User Execution: Malicious File", result.Executions[0].Technique);
        Assert.Equal("T1204.002", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_DCOM_DetectsInterProcessExecution()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("DCOM lateral execution", "dcom used via mmc20.application for remote execution"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Inter-Process Communication: DCOM", result.Executions[0].Technique);
        Assert.Equal("T1559.001", result.Executions[0].MitreTechnique);
    }

    [Fact]
    public void Detect_DLLExecution_DetectsSharedModules()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("DLL side-loading", "rundll32.exe used for dll loading from suspicious path"));
        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
        Assert.Equal("Shared Modules", result.Executions[0].Technique);
        Assert.Equal("T1129", result.Executions[0].MitreTechnique);
    }

    // ── Severity Classification ─────────────────────────────────────

    [Fact]
    public void Detect_ExploitWithTool_ReturnsCriticalSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Exploit detected", "Exploit for client execution detected using metasploit framework"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.Critical, result.Executions[0].Severity);
    }

    [Fact]
    public void Detect_WMI_ReturnsHighSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("WMI activity", "wmic process create detected on endpoint for WMI execution"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.High, result.Executions[0].Severity);
    }

    [Fact]
    public void Detect_ServiceExecution_ReturnsHighSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Service abuse", "sc create for service execution with remote binpath"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.High, result.Executions[0].Severity);
    }

    [Fact]
    public void Detect_PowerShellBasic_ReturnsMediumSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("PowerShell alert", "powershell command detected in process audit"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.Medium, result.Executions[0].Severity);
    }

    [Fact]
    public void Detect_MaliciousLink_ReturnsLowSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Link alert", "User clicked suspicious url malicious link in email"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.Low, result.Executions[0].Severity);
    }

    // ── Indicator Detection ─────────────────────────────────────────

    [Fact]
    public void Detect_EncodedCommand_AddsEncodedIndicator()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Encoded PowerShell", "powershell -enc base64 encoded command detected"));
        var result = detector.Detect(report);

        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("Encoded"));
    }

    [Fact]
    public void Detect_DownloadAndExecute_AddsDownloadIndicator()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Cradle detected", "powershell invoke-webrequest download and execute payload via invoke-expression"));
        var result = detector.Detect(report);

        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("Download-and-execute"));
    }

    [Fact]
    public void Detect_FilelessExecution_AddsFilelessIndicator()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("In-memory execution", "powershell fileless in-memory execution of reflective payload"));
        var result = detector.Detect(report);

        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("Fileless"));
    }

    [Fact]
    public void Detect_WithKnownTool_AddsToolIndicator()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("PsExec detected", "psexec used for remote service execution on target"));
        var result = detector.Detect(report);

        Assert.NotNull(result.Executions[0].SourceTool);
        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("attack tool"));
    }

    [Fact]
    public void Detect_AutomatedExecution_FlagsAutomated()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Automated execution", "Automated script batch powershell execution detected"));
        var result = detector.Detect(report);

        Assert.True(result.Executions[0].IsAutomated);
        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("Automated"));
    }

    [Fact]
    public void Detect_RemoteExecution_AddsLateralIndicator()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Remote WMI execution", "wmic remote execution on lateral pivot target"));
        var result = detector.Detect(report);

        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("lateral movement"));
    }

    [Fact]
    public void Detect_ElevatedExecution_AddsPrivEscIndicator()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Elevated PowerShell", "powershell running as admin with elevated privilege"));
        var result = detector.Detect(report);

        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("privilege escalation"));
    }

    [Fact]
    public void Detect_PersistenceCombo_AddsPersistenceIndicator()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Startup execution", "powershell execution combined with registry run key for persistence startup"));
        var result = detector.Detect(report);

        Assert.Contains(result.Executions[0].Indicators, i => i.Contains("persistence"));
    }

    // ── Campaign Detection ──────────────────────────────────────────

    [Fact]
    public void Detect_MultipleMethodsSameAsset_BuildsCampaign()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("PowerShell on server:web01", "powershell execution on target: server:web01"),
            ("WMI on server:web01", "wmic process create on target: server:web01"));
        var result = detector.Detect(report);

        Assert.Single(result.Campaigns);
        Assert.Equal(2, result.Campaigns[0].Steps.Count);
    }

    [Fact]
    public void Detect_MultipleDistinctMethods_BuildsMultiMethodCampaign()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("PowerShell alert", "powershell execution detected"),
            ("WMI alert", "wmic process create detected on endpoint"));
        var result = detector.Detect(report);

        Assert.Single(result.Campaigns);
        Assert.True(result.Campaigns[0].MethodCount >= 2);
    }

    [Fact]
    public void Detect_ThreeMethodCampaign_MarkedCritical()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("PowerShell on server:db01", "powershell execution target: server:db01"),
            ("WMI on server:db01", "wmic process create target: server:db01"),
            ("Service on server:db01", "sc create service execution target: server:db01"));
        var result = detector.Detect(report);

        Assert.Single(result.Campaigns);
        Assert.Contains("CRITICAL", result.Campaigns[0].Verdict);
    }

    // ── Scoring ─────────────────────────────────────────────────────

    [Fact]
    public void Detect_SingleLowEvent_ReturnsLowScore()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Link click", "User clicked malicious link in phishing email"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore < 20);
    }

    [Fact]
    public void Detect_MultipleHighEvents_ReturnsHighScore()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("WMI execution", "wmic process create for WMI execution on endpoint"),
            ("Service execution", "sc create for service execution with malicious binpath"),
            ("DCOM execution", "dcom via mmc20.application for remote execution"),
            ("Exploit detected", "browser exploit for client execution"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 40);
    }

    [Fact]
    public void Detect_CriticalCampaignWithTools_ReturnsElevatedOrHigher()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("Cobalt Strike WMI", "wmic process create detected using cobalt strike framework"),
            ("Service execution", "psexec service execution on remote system"),
            ("PowerShell payload", "powershell encodedcommand -enc base64 download"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatScore >= 60);
        Assert.True(result.ThreatLevel is "Elevated" or "Critical");
    }

    // ── Statistics ──────────────────────────────────────────────────

    [Fact]
    public void Detect_MultipleEvents_ComputesCorrectStats()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("PowerShell activity", "powershell execution detected on endpoint"),
            ("WMI activity", "wmic process create detected for WMI execution"));
        var result = detector.Detect(report);

        Assert.Equal(2, result.Stats.TotalTechniquesUsed);
        Assert.Equal("PowerShell", result.Stats.MostCommonTechnique);
        Assert.True(result.Stats.AverageConfidence > 0);
        Assert.True(result.Stats.ExecutionMethodsUsed >= 2);
    }

    [Fact]
    public void Detect_EmptyEvents_ReturnsDefaultStats()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal(0, result.Stats.TotalTechniquesUsed);
        Assert.Equal("None", result.Stats.MostCommonTechnique);
        Assert.Equal(0, result.Stats.AverageConfidence);
    }

    // ── Recommendations ─────────────────────────────────────────────

    [Fact]
    public void Detect_EmptyReport_ReturnsMonitoringRecommendation()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Single(result.Recommendations);
        Assert.Contains("No execution indicators", result.Recommendations[0]);
    }

    [Fact]
    public void Detect_PowerShellEvent_ReturnsScriptBlockLoggingRecommendation()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("PS alert", "powershell invoke-expression execution detected"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Script Block Logging"));
    }

    [Fact]
    public void Detect_WMIEvent_ReturnsWMIRecommendation()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("WMI alert", "wmic process create for WMI execution"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("WMI"));
    }

    [Fact]
    public void Detect_ServiceExecution_ReturnsServiceRecommendation()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Service alert", "sc create for service execution with binpath"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("service creation"));
    }

    // ── Deduplication ───────────────────────────────────────────────

    [Fact]
    public void Detect_DuplicateFindings_DeduplicatesCorrectly()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = new SecurityReport();
        var result1 = new AuditResult { ModuleName = "Module1", Category = "Module1" };
        result1.Findings.Add(new Finding { Title = "PowerShell execution", Description = "powershell detected" });
        var result2 = new AuditResult { ModuleName = "Module2", Category = "Module2" };
        result2.Findings.Add(new Finding { Title = "PowerShell execution", Description = "powershell detected" });
        report.Results.Add(result1);
        report.Results.Add(result2);

        var result = detector.Detect(report);

        Assert.Equal(1, result.ExecutionsDetected);
    }

    // ── Asset Extraction ────────────────────────────────────────────

    [Fact]
    public void Detect_WithTargetAsset_ExtractsAsset()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("WMI on target", "wmic process create execution on host:workstation42 detected"));
        var result = detector.Detect(report);

        Assert.NotNull(result.Executions[0].TargetAsset);
        Assert.Contains("workstation42", result.Executions[0].TargetAsset);
    }

    // ── Threat Level Classification ─────────────────────────────────

    [Fact]
    public void Detect_ZeroScore_ReturnsMinimal()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report);

        Assert.Equal("Minimal", result.ThreatLevel);
    }

    [Fact]
    public void Detect_ModerateActivity_ReturnsModerateOrHigher()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("WMI execution", "wmic process create for WMI execution"),
            ("Service exec", "sc create for service execution binpath"),
            ("Exploit", "browser exploit for client execution"));
        var result = detector.Detect(report);

        Assert.True(result.ThreatLevel is "Moderate" or "Elevated" or "Critical");
    }

    // ── General Recommendation Always Present ───────────────────────

    [Fact]
    public void Detect_WithEvents_AlwaysIncludesGeneralRecommendation()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("PS alert", "powershell execution detected"));
        var result = detector.Detect(report);

        Assert.Contains(result.Recommendations, r => r.Contains("Event ID 4688"));
    }

    // ── DaysAnalyzed Passthrough ────────────────────────────────────

    [Fact]
    public void Detect_CustomDays_ReflectsInReport()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = new SecurityReport();
        var result = detector.Detect(report, 180);

        Assert.Equal(180, result.DaysAnalyzed);
    }

    // ── Fileless Execution Critical Severity ────────────────────────

    [Fact]
    public void Detect_FilelessExecution_ReturnsCriticalSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Fileless attack", "powershell fileless in-memory execution detected"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.Critical, result.Executions[0].Severity);
    }

    // ── Download-and-Execute Critical Severity ──────────────────────

    [Fact]
    public void Detect_DownloadAndExecute_ReturnsCriticalSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Cradle", "powershell invoke-webrequest download and invoke-expression execute payload"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.Critical, result.Executions[0].Severity);
    }

    // ── DCOM High Severity ──────────────────────────────────────────

    [Fact]
    public void Detect_DCOM_ReturnsHighSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("DCOM abuse", "dcom via mmc20.application for execution"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.High, result.Executions[0].Severity);
    }

    // ── Multiple Recommendations for Multi-Technique ────────────────

    [Fact]
    public void Detect_MultipleTechniques_GeneratesMultipleRecommendations()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(
            ("PS alert", "powershell execution detected"),
            ("VBS alert", "vbscript wscript.exe execution in temp"));
        var result = detector.Detect(report);

        Assert.True(result.Recommendations.Count >= 3); // PS + VBS + general
    }

    // ── Encoded PowerShell Gets High Severity ───────────────────────

    [Fact]
    public void Detect_EncodedPowerShell_ReturnsHighSeverity()
    {
        var detector = new ExecutionDetector(CreateHistory());
        var report = MakeReport(("Encoded PS", "powershell -enc encodedcommand base64 obfuscated execution"));
        var result = detector.Detect(report);

        Assert.Equal(ExecutionSeverity.High, result.Executions[0].Severity);
    }
}
