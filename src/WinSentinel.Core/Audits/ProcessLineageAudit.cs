using WinSentinel.Core.Helpers;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits process parent-child relationships to detect suspicious lineage chains.
/// Identifies LOLBin abuse, Office macro execution, shell injection, and living-off-the-land techniques.
///
/// This module owns only the data collection (PowerShell/WMI). All parsing, rule
/// matching, exclusion handling, and finding generation live in the pure, fully
/// unit-tested <see cref="ProcessLineageAnalyzer"/>.
/// </summary>
public class ProcessLineageAudit : AuditModuleBase
{
    public override string Name => "Process Lineage Audit";
    public override string Category => ProcessLineageAnalyzer.Category;
    public override string Description => "Analyzes parent-child process relationships to detect suspicious execution chains, LOLBin abuse, and living-off-the-land techniques.";

    protected override async Task ExecuteAuditAsync(AuditResult result, CancellationToken cancellationToken)
    {
        await CheckProcessLineage(result, cancellationToken);
        await CheckOrphanedProcesses(result, cancellationToken);
        await CheckDeepNesting(result, cancellationToken);
    }

    private async Task CheckProcessLineage(AuditResult result, CancellationToken ct)
    {
        // Get process tree with parent info via WMI
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
              Where-Object { $_.ProcessId -ne 0 } |
              ForEach-Object { 
                  $parentName = ''
                  if ($_.ParentProcessId) {
                      $parent = Get-CimInstance Win32_Process -Filter ""ProcessId = $($_.ParentProcessId)"" -EA SilentlyContinue
                      if ($parent) { $parentName = $parent.Name -replace '\.exe$','' }
                  }
                  '{0}|{1}|{2}|{3}|{4}' -f ($_.Name -replace '\.exe$',''), $_.ProcessId, $parentName, $_.ParentProcessId, ($_.CommandLine -replace '\|','_' -replace '\r?\n',' ')
              }", ct);

        var records = ProcessLineageAnalyzer.ParseProcessLines(output);
        var matches = ProcessLineageAnalyzer.MatchRecords(records);
        result.Findings.AddRange(ProcessLineageAnalyzer.BuildLineageFindings(matches));
    }

    private async Task CheckOrphanedProcesses(AuditResult result, CancellationToken ct)
    {
        // Find processes whose parent PID doesn't exist (orphaned/reparented)
        var output = await ShellHelper.RunPowerShellAsync(
            @"$allPids = (Get-CimInstance Win32_Process -EA SilentlyContinue).ProcessId
              Get-CimInstance Win32_Process -EA SilentlyContinue | 
              Where-Object { $_.ParentProcessId -ne 0 -and $_.ProcessId -ne 4 -and $allPids -notcontains $_.ParentProcessId } |
              Where-Object { $_.Name -notin @('System','Registry','Memory Compression','svchost.exe','csrss.exe','wininit.exe','winlogon.exe','services.exe','smss.exe','lsass.exe') } |
              Select-Object -First 20 |
              ForEach-Object { '{0}|{1}|{2}' -f ($_.Name -replace '\.exe$',''), $_.ProcessId, $_.ParentProcessId }", ct);

        var orphaned = ProcessLineageAnalyzer.ParseOrphanLines(output);
        result.Findings.Add(ProcessLineageAnalyzer.BuildOrphanFinding(orphaned));
    }

    private async Task CheckDeepNesting(AuditResult result, CancellationToken ct)
    {
        // Detect deeply nested process chains (>4 levels of cmd/powershell)
        var output = await ShellHelper.RunPowerShellAsync(
            @"function Get-ProcessDepth {
                  param([int]$Pid, [int]$MaxDepth = 8, [hashtable]$ProcMap)
                  $depth = 0; $current = $Pid
                  $interpreters = @('cmd','powershell','pwsh','wscript','cscript')
                  $chainNames = @()
                  while ($depth -lt $MaxDepth -and $ProcMap.ContainsKey($current)) {
                      $info = $ProcMap[$current]
                      $name = $info.Name -replace '\.exe$',''
                      if ($name -in $interpreters) { $chainNames += $name }
                      $current = $info.ParentId
                      $depth++
                  }
                  return $chainNames.Count
              }
              $procs = Get-CimInstance Win32_Process -EA SilentlyContinue
              $map = @{}
              foreach ($p in $procs) { $map[$p.ProcessId] = @{ Name=$p.Name; ParentId=$p.ParentProcessId } }
              $deep = foreach ($p in $procs) {
                  $d = Get-ProcessDepth -Pid $p.ProcessId -ProcMap $map
                  if ($d -ge 3) { '{0}|{1}|{2}' -f ($p.Name -replace '\.exe$',''), $p.ProcessId, $d }
              }
              $deep | Select-Object -First 10", ct);

        var deepChains = ProcessLineageAnalyzer.ParseDeepNestLines(output);
        result.Findings.Add(ProcessLineageAnalyzer.BuildDeepNestFinding(deepChains));
    }
}
