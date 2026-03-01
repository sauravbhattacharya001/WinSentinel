using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests.Services;

public class CsvReportTests
{
    private static SecurityReport CreateSampleReport()
    {
        var result = new AuditResult
        {
            ModuleName = "FirewallAudit",
            Category = "Firewall",
            Success = true,
        };
        result.Findings.Add(Finding.Critical("Firewall Disabled", "Windows Firewall is off", "Firewall",
            "Enable Windows Firewall", "netsh advfirewall set allprofiles state on"));
        result.Findings.Add(Finding.Pass("Inbound Rules", "Inbound rules are configured", "Firewall"));

        var report = new SecurityReport
        {
            SecurityScore = 65,
            GeneratedAt = DateTimeOffset.UtcNow,
        };
        report.Results.Add(result);
        return report;
    }

    [Fact]
    public void GenerateCsvReport_ContainsHeader()
    {
        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(CreateSampleReport());

        Assert.StartsWith("Module,Category,ModuleScore,ModuleGrade,Severity,Title,Description,Remediation,FixCommand,Timestamp", csv);
    }

    [Fact]
    public void GenerateCsvReport_ContainsFindings()
    {
        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(CreateSampleReport());

        Assert.Contains("Firewall Disabled", csv);
        Assert.Contains("Inbound Rules", csv);
        Assert.Contains("Critical", csv);
        Assert.Contains("Pass", csv);
    }

    [Fact]
    public void GenerateCsvReport_EscapesCommasAndQuotes()
    {
        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Test",
            Success = true,
        };
        result.Findings.Add(Finding.Warning("Title, with comma", "Desc with \"quotes\"", "Test"));

        var report = new SecurityReport { SecurityScore = 80 };
        report.Results.Add(result);

        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(report);

        Assert.Contains("\"Title, with comma\"", csv);
        Assert.Contains("\"Desc with \"\"quotes\"\"\"", csv);
    }

    [Fact]
    public void GenerateCsvReport_EmptyModule_StillEmitsRow()
    {
        var result = new AuditResult
        {
            ModuleName = "EmptyModule",
            Category = "Empty",
            Success = true,
        };

        var report = new SecurityReport { SecurityScore = 100 };
        report.Results.Add(result);

        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(report);

        Assert.Contains("EmptyModule", csv);
        Assert.Contains("No findings", csv);
    }

    [Fact]
    public void ReportFormat_Csv_GeneratesCorrectFilename()
    {
        var filename = ReportGenerator.GenerateFilename(ReportFormat.Csv);
        Assert.EndsWith(".csv", filename);
        Assert.StartsWith("WinSentinel-Report-", filename);
    }
}
