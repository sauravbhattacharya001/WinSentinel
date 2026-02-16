# Quick full audit runner
$env:PATH += ";C:\Program Files\dotnet"

$code = @"
using System;
using System.Threading.Tasks;
using WinSentinel.Core.Services;

class Program
{
    static async Task Main()
    {
        Console.WriteLine("=== WinSentinel Full Security Audit ===");
        Console.WriteLine("Started: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        Console.WriteLine(new string('=', 50));
        Console.WriteLine();

        var engine = new AuditEngine();
        var report = await engine.RunFullAuditAsync();

        var score = report.SecurityScore;
        var grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
        Console.WriteLine("Security Score: " + score + "/100  Grade: " + grade);
        Console.WriteLine("Findings: " + report.TotalFindings + " total | " + report.TotalCritical + " critical | " + report.TotalWarnings + " warnings | " + report.TotalPass + " pass");
        Console.WriteLine();

        foreach (var result in report.Results)
        {
            var icon = result.Score >= 90 ? "PASS" : result.Score >= 70 ? "WARN" : "FAIL";
            Console.WriteLine("[" + icon + "] " + result.ModuleName + " - Score: " + result.Score + "/100");
            
            foreach (var finding in result.Findings)
            {
                var sev = finding.Severity.ToString().ToUpper();
                Console.WriteLine("  [" + sev + "] " + finding.Title);
                if (!string.IsNullOrEmpty(finding.Description))
                    Console.WriteLine("         " + finding.Description);
                if (!string.IsNullOrEmpty(finding.Remediation))
                    Console.WriteLine("         Fix: " + finding.Remediation);
            }
            Console.WriteLine();
        }

        Console.WriteLine(new string('=', 50));
        Console.WriteLine("Completed: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
    }
}
"@

$tmpDir = "$env:TEMP\WinSentinel-Audit"
if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

$code | Set-Content "$tmpDir\Program.cs"
$csprojPath = (Resolve-Path .\src\WinSentinel.Core\WinSentinel.Core.csproj).Path
@"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <UseWPF>true</UseWPF>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="$csprojPath" />
  </ItemGroup>
</Project>
"@ | Set-Content "$tmpDir\WinSentinel.Audit.csproj"

dotnet run --project "$tmpDir\WinSentinel.Audit.csproj"
Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
