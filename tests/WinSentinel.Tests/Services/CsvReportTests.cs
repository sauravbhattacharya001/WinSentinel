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

    [Theory]
    [InlineData("=cmd|'/C calc'!A0", "Formula starting with =")]
    [InlineData("+cmd|'/C calc'!A0", "Formula starting with +")]
    [InlineData("-1+1|cmd", "Formula starting with -")]
    [InlineData("@SUM(1+1)*cmd|'/C calc'!A0", "Formula starting with @")]
    [InlineData("\tcmd", "Formula starting with tab")]
    [InlineData("\rcmd", "Formula starting with carriage return")]
    public void GenerateCsvReport_NeutralizesFormulaInjection(string maliciousTitle, string description)
    {
        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Test",
            Success = true,
        };
        result.Findings.Add(Finding.Warning(maliciousTitle, description, "Test"));

        var report = new SecurityReport { SecurityScore = 80 };
        report.Results.Add(result);

        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(report);

        // The raw malicious value should NOT appear unescaped in the CSV.
        // It should be prefixed with a single-quote to neutralize the formula.
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        // Skip header line; data is on subsequent lines
        var dataLines = lines.Skip(1).ToArray();
        Assert.True(dataLines.Length > 0, "Expected at least one data row");

        foreach (var line in dataLines)
        {
            // Ensure no cell starts with a bare formula trigger character.
            // Cells are comma-separated; within double-quoted fields the content
            // should be quote-prefixed.  Unquoted cells must not start with triggers.
            var cells = ParseCsvLine(line);
            foreach (var cell in cells)
            {
                var trimmed = cell.TrimStart('"');
                if (trimmed.Length > 0)
                {
                    Assert.False(
                        trimmed[0] == '=' || trimmed[0] == '+' || trimmed[0] == '@'
                        || trimmed[0] == '\t' || trimmed[0] == '\r',
                        $"Cell starts with formula trigger character: {cell}");
                }
            }
        }
    }

    [Fact]
    public void GenerateCsvReport_SafeValuesUnchanged()
    {
        // Ensure normal values (that don't start with formula chars) are NOT prefixed
        var result = new AuditResult
        {
            ModuleName = "SafeModule",
            Category = "Firewall",
            Success = true,
        };
        result.Findings.Add(Finding.Critical("Normal Title", "Normal description", "Firewall"));

        var report = new SecurityReport { SecurityScore = 50 };
        report.Results.Add(result);

        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(report);

        Assert.Contains("Normal Title", csv);
        Assert.Contains("Normal description", csv);
        // Should NOT have a single-quote prefix
        Assert.DoesNotContain("'Normal Title", csv);
    }

    [Fact]
    public void GenerateCsvReport_FixCommand_FormulaInjectionNeutralized()
    {
        // FixCommand is user-visible — test that formula injection is blocked there too
        var result = new AuditResult
        {
            ModuleName = "TestModule",
            Category = "Test",
            Success = true,
        };
        result.Findings.Add(Finding.Critical("Test", "Test desc", "Test",
            "Apply fix", "=HYPERLINK(\"http://evil.com\",\"Click\")"));

        var report = new SecurityReport { SecurityScore = 50 };
        report.Results.Add(result);

        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(report);

        // The fix command should be neutralized (single-quote prefixed)
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var dataLine = lines.Skip(1).First();
        // Raw "=HYPERLINK..." should not appear as a bare cell value
        Assert.DoesNotContain(",=HYPERLINK", dataLine);
    }

    /// <summary>
    /// Simple CSV line parser that handles double-quoted fields.
    /// </summary>
    private static List<string> ParseCsvLine(string line)
    {
        var cells = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++; // skip escaped quote
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    current.Append(c);
                }
            }
            else
            {
                if (c == '"') { inQuotes = true; }
                else if (c == ',') { cells.Add(current.ToString()); current.Clear(); }
                else { current.Append(c); }
            }
        }
        cells.Add(current.ToString());
        return cells;
    }
}
