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

    [Theory]
    [InlineData("   =cmd|'/C calc'!A0", "spaces before =")]
    [InlineData("  +cmd|'/C calc'!A0", "spaces before +")]
    [InlineData(" -1+1|cmd", "space before -")]
    [InlineData("\t=SUM(1+1)", "tab before =")]
    [InlineData(" \t @SUM(1+1)", "mixed whitespace before @")]
    public void GenerateCsvReport_NeutralizesWhitespacePaddedFormulaInjection(string maliciousTitle, string description)
    {
        // Regression: Excel / Sheets / LibreOffice TRIM leading whitespace before
        // evaluating a cell as a formula, so "   =HYPERLINK(...)" is still a live
        // formula. The previous guard only inspected the first character and let
        // every whitespace-padded payload through. Finding titles/descriptions
        // can carry environment-influenced text, so this is attacker-reachable.
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

        var dataLines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1).ToArray();
        Assert.True(dataLines.Length > 0, "Expected at least one data row");

        foreach (var line in dataLines)
        {
            foreach (var cell in ParseCsvLine(line))
            {
                // After the spreadsheet trims leading whitespace, the (decoded)
                // cell must NOT begin with a formula trigger. A neutralized cell
                // begins with our single-quote guard.
                var trimmed = cell.TrimStart(' ', '\t', '\r', '\n');
                if (trimmed.Length > 0)
                {
                    Assert.False(
                        trimmed[0] == '=' || trimmed[0] == '+' || trimmed[0] == '-' || trimmed[0] == '@',
                        $"Cell evaluates as a formula after whitespace-trim: <{cell}>");
                }
            }
        }
    }

    [Fact]
    public void GenerateCsvReport_AllWhitespaceValue_NotGuarded()
    {
        // An all-whitespace value has no formula to neutralize, so it must NOT be
        // prefixed with a guard quote (that would corrupt a legitimately blank-ish
        // field). A leading space alone is not a trigger.
        var result = new AuditResult
        {
            ModuleName = "Spaces Module", // contains a space but is not a formula
            Category = "Net",
            Success = true,
        };
        result.Findings.Add(Finding.Warning("  spaced title", "desc", "Net"));

        var report = new SecurityReport { SecurityScore = 70 };
        report.Results.Add(result);

        var generator = new ReportGenerator();
        var csv = generator.GenerateCsvReport(report);

        // The space-led, non-formula title keeps its leading spaces and is NOT
        // quote-guarded.
        Assert.Contains("  spaced title", csv);
        Assert.DoesNotContain("'  spaced title", csv);
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
