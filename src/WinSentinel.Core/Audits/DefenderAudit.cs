using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Windows Defender status, real-time protection, and definition freshness.
/// </summary>
public class DefenderAudit : AuditModuleBase
{
    public override string Name => "Defender Audit";
    public override string Category => "Defender";
    public override string Description => "Checks Windows Defender status, real-time protection, antivirus definition freshness, and Attack Surface Reduction (ASR) rules.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        await CheckRealTimeProtection(result, cancellationToken);
        await CheckDefinitionFreshness(result, cancellationToken);
        await CheckCloudProtection(result, cancellationToken);
        await CheckTamperProtection(result, cancellationToken);
        await CheckQuickScanAge(result, cancellationToken);
        await CheckAttackSurfaceReduction(result, cancellationToken);
    }

    private async Task CheckRealTimeProtection(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).DisableRealtimeMonitoring", ct);

        // Pure classification lives in DefenderAnalyzer; this method only collects.
        result.Findings.Add(DefenderAnalyzer.BuildRealtimeProtectionFinding(output));
    }

    private async Task CheckDefinitionFreshness(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpComputerStatus).AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm:ss')", ct);

        var finding = DefenderAnalyzer.BuildDefinitionFreshnessFinding(output, DateTime.Now);
        if (finding != null) result.Findings.Add(finding);
    }

    private async Task CheckCloudProtection(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).MAPSReporting", ct);

        var finding = DefenderAnalyzer.BuildCloudProtectionFinding(output);
        if (finding != null) result.Findings.Add(finding);
    }

    private async Task CheckTamperProtection(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpComputerStatus).IsTamperProtected", ct);

        var finding = DefenderAnalyzer.BuildTamperProtectionFinding(output);
        if (finding != null) result.Findings.Add(finding);
    }

    private async Task CheckQuickScanAge(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            "(Get-MpComputerStatus).QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss')", ct);

        var finding = DefenderAnalyzer.BuildQuickScanFinding(output, DateTime.Now);
        if (finding != null) result.Findings.Add(finding);
    }

    private async Task CheckAttackSurfaceReduction(AuditResult result, CancellationToken ct)
    {
        // Get-MpPreference exposes two parallel arrays (rule GUIDs and their
        // actions). Emit them as comma-joined lines so the pure analyzer can pair
        // them positionally. The leading marker lets us tell "Defender answered
        // with no rules configured" apart from "Defender/Get-MpPreference is not
        // available" (third-party AV) — only the latter suppresses the finding.
        var idsOutput = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).AttackSurfaceReductionRules_Ids -join ','", ct);
        var actionsOutput = await ShellHelper.RunPowerShellAsync(
            "(Get-MpPreference).AttackSurfaceReductionRules_Actions -join ','", ct);
        var managedOutput = await ShellHelper.RunPowerShellAsync(
            "if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) { 'True' } else { 'False' }", ct);

        var defenderManaged = !string.Equals(
            (managedOutput ?? string.Empty).Trim(), "False", StringComparison.OrdinalIgnoreCase);

        var finding = AttackSurfaceReductionAnalyzer.BuildAsrFinding(idsOutput, actionsOutput, defenderManaged);
        if (finding != null) result.Findings.Add(finding);
    }
}
