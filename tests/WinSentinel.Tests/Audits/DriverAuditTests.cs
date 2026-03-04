using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.DriverAudit;

namespace WinSentinel.Tests.Audits;

public class DriverAuditTests
{
    private readonly DriverAudit _audit;

    public DriverAuditTests()
    {
        _audit = new DriverAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Driver Security Audit",
        Category = "Drivers"
    };

    private static DriverState MakeCleanState() => new()
    {
        TotalDriverCount = 3,
        TestSigningEnabled = false,
        SecureBootEnabled = true,
        HvciEnabled = true,
        DriverBlockListVersion = "2026-01-15",
        Drivers = new List<DriverEntry>
        {
            new()
            {
                Name = "ntfs",
                DisplayName = "NTFS",
                FileName = @"C:\Windows\System32\drivers\ntfs.sys",
                Type = "Kernel Driver",
                Status = "Running",
                StartType = "Boot",
                IsSigned = true,
                IsMicrosoftSigned = true,
                SignerName = "Microsoft Windows"
            },
            new()
            {
                Name = "tcpip",
                DisplayName = "TCP/IP Protocol Driver",
                FileName = @"C:\Windows\System32\drivers\tcpip.sys",
                Type = "Kernel Driver",
                Status = "Running",
                StartType = "Boot",
                IsSigned = true,
                IsMicrosoftSigned = true,
                SignerName = "Microsoft Windows"
            },
            new()
            {
                Name = "nvlddmkm",
                DisplayName = "NVIDIA Display Driver",
                FileName = @"C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64\nvlddmkm.sys",
                Type = "Kernel Driver",
                Status = "Running",
                StartType = "Manual",
                IsSigned = true,
                IsMicrosoftSigned = false,
                SignerName = "NVIDIA Corporation"
            }
        }
    };

    // ── Module metadata ─────────────────────────────────────────

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("Driver Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsExpected()
    {
        Assert.Equal("Drivers", _audit.Category);
    }

    [Fact]
    public void Description_NotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(_audit.Description));
    }

    // ── Clean state ─────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_CleanState_NoWarningsOrCritical()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_CleanState_HasPassFindings()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Pass);
    }

    [Fact]
    public void AnalyzeState_CleanState_HasSummary()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Driver Summary"));
    }

    // ── Test signing ────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_TestSigningEnabled_Critical()
    {
        var state = MakeCleanState();
        state.TestSigningEnabled = true;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("Test Signing Mode Enabled"));
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.NotNull(finding.FixCommand);
    }

    [Fact]
    public void AnalyzeState_TestSigningDisabled_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Test Signing Mode Disabled") && f.Severity == Severity.Pass);
    }

    // ── Secure Boot ─────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_SecureBootDisabled_Warning()
    {
        var state = MakeCleanState();
        state.SecureBootEnabled = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("Secure Boot"));
        Assert.Equal(Severity.Warning, finding.Severity);
    }

    [Fact]
    public void AnalyzeState_SecureBootEnabled_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Secure Boot Enabled") && f.Severity == Severity.Pass);
    }

    // ── HVCI ────────────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_HvciDisabled_Warning()
    {
        var state = MakeCleanState();
        state.HvciEnabled = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("HVCI"));
        Assert.Equal(Severity.Warning, finding.Severity);
        Assert.NotNull(finding.FixCommand);
    }

    [Fact]
    public void AnalyzeState_HvciEnabled_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("HVCI") && f.Severity == Severity.Pass);
    }

    // ── Driver Block List ───────────────────────────────────────

    [Fact]
    public void AnalyzeState_NoBlockList_Warning()
    {
        var state = MakeCleanState();
        state.DriverBlockListVersion = "not found";
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Block List Not Found") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_NullBlockList_Warning()
    {
        var state = MakeCleanState();
        state.DriverBlockListVersion = null;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Block List Not Found") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_BlockListPresent_Info()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Block List Present") && f.Severity == Severity.Info);
    }

    // ── Unsigned drivers ────────────────────────────────────────

    [Fact]
    public void AnalyzeState_UnsignedDriver_Critical()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "suspdriver",
            FileName = @"C:\Windows\System32\drivers\suspdriver.sys",
            IsSigned = false,
            IsTestSigned = false
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("Unsigned Drivers"));
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains("suspdriver", finding.Description);
    }

    [Fact]
    public void AnalyzeState_MultipleUnsigned_CountCorrect()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry { Name = "bad1", FileName = @"C:\d\bad1.sys", IsSigned = false });
        state.Drivers.Add(new DriverEntry { Name = "bad2", FileName = @"C:\d\bad2.sys", IsSigned = false });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("Unsigned Drivers"));
        Assert.Contains("2", finding.Title);
    }

    [Fact]
    public void AnalyzeState_AllSigned_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No Unsigned Drivers") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AnalyzeState_UnsignedNoPath_Ignored()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry { Name = "nopath", FileName = "", IsSigned = false });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No Unsigned Drivers") && f.Severity == Severity.Pass);
    }

    // ── Test-signed drivers ─────────────────────────────────────

    [Fact]
    public void AnalyzeState_TestSignedDriver_Warning()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "devdriver",
            FileName = @"C:\dev\devdriver.sys",
            IsTestSigned = true,
            IsSigned = false
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("Test-Signed"));
        Assert.Equal(Severity.Warning, finding.Severity);
    }

    [Fact]
    public void AnalyzeState_NoTestSigned_NoWarning()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Test-Signed"));
    }

    // ── Vulnerable drivers (BYOVD) ─────────────────────────────

    [Theory]
    [InlineData("rtcore64.sys", "CVE-2019-16098")]
    [InlineData("dbutil_2_3.sys", "CVE-2021-21551")]
    [InlineData("gdrv.sys", "CVE-2018-19320")]
    [InlineData("mhyprot2.sys", "CVE-2020-36603")]
    [InlineData("iqvw64e.sys", "CVE-2015-2291")]
    public void AnalyzeState_VulnerableDriver_Critical(string driverFile, string expectedCve)
    {
        var state = MakeCleanState();
        var driverName = Path.GetFileNameWithoutExtension(driverFile);
        state.Drivers.Add(new DriverEntry
        {
            Name = driverName,
            FileName = @$"C:\Windows\System32\drivers\{driverFile}",
            IsSigned = true
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f =>
            f.Title.Contains("Known Vulnerable Driver") && f.Title.Contains(driverName));
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains(expectedCve, finding.Description);
        Assert.NotNull(finding.FixCommand);
    }

    [Fact]
    public void AnalyzeState_VulnerableDriverByName_Critical()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "winring0x64",
            FileName = @"C:\some\path\random.sys",
            IsSigned = true
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Known Vulnerable Driver") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_NoVulnerableDrivers_Pass()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("No Known Vulnerable Drivers") && f.Severity == Severity.Pass);
    }

    [Fact]
    public void AnalyzeState_MultipleVulnerableDrivers_MultipleCritical()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "rtcore64",
            FileName = @"C:\Windows\System32\drivers\rtcore64.sys",
            IsSigned = true
        });
        state.Drivers.Add(new DriverEntry
        {
            Name = "procexp152",
            FileName = @"C:\Windows\System32\drivers\procexp152.sys",
            IsSigned = true
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var vulnFindings = result.Findings.Where(f =>
            f.Title.Contains("Known Vulnerable Driver") && f.Severity == Severity.Critical).ToList();
        Assert.Equal(2, vulnFindings.Count);
    }

    // ── Suspicious paths ────────────────────────────────────────

    [Theory]
    [InlineData(@"C:\Users\admin\AppData\Local\Temp\evil.sys")]
    [InlineData(@"C:\Temp\malware.sys")]
    [InlineData(@"C:\Users\Public\driver.sys")]
    [InlineData(@"C:\Users\admin\Downloads\test.sys")]
    [InlineData(@"C:\Users\admin\Desktop\hack.sys")]
    public void AnalyzeState_SuspiciousPath_Critical(string path)
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "suspect",
            FileName = path,
            IsSigned = true
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Suspicious Paths") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_NormalPaths_NoSuspicious()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Suspicious Paths"));
    }

    // ── Non-trusted paths ───────────────────────────────────────

    [Fact]
    public void AnalyzeState_DriverOutsideTrustedPath_Info()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "vendordrv",
            FileName = @"D:\Vendor\driver.sys",
            IsSigned = true
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Outside Standard Paths") && f.Severity == Severity.Info);
    }

    [Fact]
    public void AnalyzeState_AllTrustedPaths_NoNonTrustedFinding()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Outside Standard Paths"));
    }

    // ── Driver age ──────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_OldDriver_Warning()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "ancientdrv",
            FileName = @"C:\Windows\System32\drivers\ancient.sys",
            IsSigned = true,
            DriverDate = DateTimeOffset.UtcNow.AddYears(-7)
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var finding = Assert.Single(result.Findings, f => f.Title.Contains("Old Drivers"));
        Assert.Equal(Severity.Warning, finding.Severity);
        Assert.Contains("ancientdrv", finding.Description);
    }

    [Fact]
    public void AnalyzeState_RecentDriver_NoAgeWarning()
    {
        var state = MakeCleanState();
        state.Drivers[0].DriverDate = DateTimeOffset.UtcNow.AddMonths(-6);
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Old Drivers"));
    }

    [Fact]
    public void AnalyzeState_NullDriverDate_NoAgeWarning()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.DoesNotContain(result.Findings, f => f.Title.Contains("Old Drivers"));
    }

    // ── Driver summary ──────────────────────────────────────────

    [Fact]
    public void AnalyzeState_Summary_CountsCorrect()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var summary = Assert.Single(result.Findings, f => f.Title.Contains("Driver Summary"));
        Assert.Contains("3 total", summary.Title);
        Assert.Contains("2 Microsoft-signed", summary.Title);
        Assert.Contains("1 third-party", summary.Title);
    }

    [Fact]
    public void AnalyzeState_Summary_KernelCount()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var summary = Assert.Single(result.Findings, f => f.Title.Contains("Driver Summary"));
        Assert.Contains("3 kernel", summary.Title);
    }

    [Fact]
    public void AnalyzeState_EmptyDrivers_SummaryStillWorks()
    {
        var state = new DriverState
        {
            TotalDriverCount = 0,
            SecureBootEnabled = true,
            HvciEnabled = true,
            DriverBlockListVersion = "2026-01-01"
        };
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f => f.Title.Contains("Driver Summary"));
    }

    // ── Path normalization ──────────────────────────────────────

    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\ntfs.sys", @"C:\Windows\System32\drivers\ntfs.sys")]
    [InlineData(@"\??\C:\Windows\System32\drivers\tcpip.sys", @"C:\Windows\System32\drivers\tcpip.sys")]
    [InlineData(@"system32\drivers\test.sys", @"C:\Windows\system32\drivers\test.sys")]
    [InlineData(@"C:\Normal\path.sys", @"C:\Normal\path.sys")]
    [InlineData(@"""C:\Quoted\path.sys""", @"C:\Quoted\path.sys")]
    public void NormalizePath_ConvertsCorrectly(string input, string expected)
    {
        var normalized = DriverAudit.NormalizePath(input);
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData(null)]
    public void NormalizePath_EmptyOrNull_ReturnsAsIs(string? input)
    {
        var normalized = DriverAudit.NormalizePath(input!);
        Assert.Equal(input, normalized);
    }

    // ── JSON parsing ────────────────────────────────────────────

    [Fact]
    public void ParseDrivers_ValidArray_ParsesCorrectly()
    {
        var json = "[{\"Name\":\"ntfs\",\"DisplayName\":\"NTFS\",\"PathName\":\"\\\\SystemRoot\\\\System32\\\\drivers\\\\ntfs.sys\",\"ServiceType\":\"Kernel Driver\",\"State\":\"Running\",\"StartMode\":\"Boot\"},{\"Name\":\"tcpip\",\"DisplayName\":\"TCP/IP\",\"PathName\":\"\\\\SystemRoot\\\\System32\\\\drivers\\\\tcpip.sys\",\"ServiceType\":\"Kernel Driver\",\"State\":\"Running\",\"StartMode\":\"Boot\"}]";

        var drivers = DriverAudit.ParseDrivers(json);

        Assert.Equal(2, drivers.Count);
        Assert.Equal("ntfs", drivers[0].Name);
        Assert.Equal("NTFS", drivers[0].DisplayName);
        Assert.Contains("ntfs.sys", drivers[0].FileName);
    }

    [Fact]
    public void ParseDrivers_SingleObject_ParsesCorrectly()
    {
        var json = "{\"Name\":\"ntfs\",\"DisplayName\":\"NTFS\",\"PathName\":\"\\\\SystemRoot\\\\System32\\\\drivers\\\\ntfs.sys\",\"ServiceType\":\"Kernel Driver\",\"State\":\"Running\",\"StartMode\":\"Boot\"}";

        var drivers = DriverAudit.ParseDrivers(json);

        Assert.Single(drivers);
        Assert.Equal("ntfs", drivers[0].Name);
    }

    [Fact]
    public void ParseDrivers_InvalidJson_ReturnsEmpty()
    {
        var drivers = DriverAudit.ParseDrivers("not json at all");

        Assert.Empty(drivers);
    }

    [Fact]
    public void ParseDrivers_EmptyArray_ReturnsEmpty()
    {
        var drivers = DriverAudit.ParseDrivers("[]");

        Assert.Empty(drivers);
    }

    [Fact]
    public void ParseDrivers_MissingFields_DefaultValues()
    {
        var json = @"[{""Name"":""minimal""}]";

        var drivers = DriverAudit.ParseDrivers(json);

        Assert.Single(drivers);
        Assert.Equal("minimal", drivers[0].Name);
        Assert.Equal("", drivers[0].DisplayName);
        Assert.Equal("", drivers[0].FileName);
    }

    [Fact]
    public void ParseDrivers_NormalizesSystemRootPath()
    {
        var json = "[{\"Name\":\"ntfs\",\"PathName\":\"\\\\SystemRoot\\\\System32\\\\drivers\\\\ntfs.sys\"}]";

        var drivers = DriverAudit.ParseDrivers(json);

        Assert.Contains(@"C:\Windows", drivers[0].FileName);
    }

    // ── Known vulnerable driver list ────────────────────────────

    [Fact]
    public void KnownVulnerableDrivers_ContainsExpectedEntries()
    {
        Assert.True(KnownVulnerableDrivers.Count >= 25);
        Assert.Contains("rtcore64.sys", KnownVulnerableDrivers.Keys);
        Assert.Contains("dbutil_2_3.sys", KnownVulnerableDrivers.Keys);
        Assert.Contains("mhyprot2.sys", KnownVulnerableDrivers.Keys);
    }

    [Fact]
    public void KnownVulnerableDrivers_CaseInsensitive()
    {
        Assert.True(KnownVulnerableDrivers.ContainsKey("RTCORE64.SYS"));
        Assert.True(KnownVulnerableDrivers.ContainsKey("Rtcore64.Sys"));
    }

    // ── Combined scenarios ──────────────────────────────────────

    [Fact]
    public void AnalyzeState_WorstCase_MultipleCriticals()
    {
        var state = new DriverState
        {
            TotalDriverCount = 4,
            TestSigningEnabled = true,
            SecureBootEnabled = false,
            HvciEnabled = false,
            DriverBlockListVersion = null,
            Drivers = new List<DriverEntry>
            {
                new() { Name = "ntfs", FileName = @"C:\Windows\System32\drivers\ntfs.sys", Type = "Kernel Driver", IsSigned = true, IsMicrosoftSigned = true },
                new() { Name = "unsigned", FileName = @"C:\Windows\System32\drivers\bad.sys", IsSigned = false },
                new() { Name = "rtcore64", FileName = @"C:\Windows\System32\drivers\rtcore64.sys", IsSigned = true },
                new() { Name = "tempdrv", FileName = @"C:\Temp\evil.sys", IsSigned = true },
            }
        };
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var criticals = result.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        Assert.True(criticals.Count >= 3); // test signing + unsigned + vulnerable + suspicious path
    }

    [Fact]
    public void AnalyzeState_BestCase_AllPass()
    {
        var state = MakeCleanState();
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var passes = result.Findings.Where(f => f.Severity == Severity.Pass).ToList();
        Assert.True(passes.Count >= 4); // test signing, secure boot, HVCI, no unsigned, no BYOVD
    }

    [Fact]
    public void AnalyzeState_VulnerableAndUnsigned_SameDriver()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "winring0x64",
            FileName = @"C:\Windows\System32\drivers\winring0x64.sys",
            IsSigned = false
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        // Should report both unsigned AND vulnerable
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Unsigned Drivers") && f.Severity == Severity.Critical);
        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Known Vulnerable Driver") && f.Severity == Severity.Critical);
    }

    [Fact]
    public void AnalyzeState_SuspiciousPathNotDoubleCounted()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "tempdrv",
            FileName = @"C:\Users\admin\Downloads\driver.sys",
            IsSigned = true
        });
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        // Should be in suspicious but NOT in non-trusted (avoided double reporting)
        Assert.Contains(result.Findings, f => f.Title.Contains("Suspicious Paths"));
        Assert.DoesNotContain(result.Findings, f =>
            f.Title.Contains("Outside Standard Paths") &&
            f.Description.Contains("tempdrv"));
    }

    // ── Edge cases ──────────────────────────────────────────────

    [Fact]
    public void AnalyzeState_DriverWithEmptyName_Handled()
    {
        var state = MakeCleanState();
        state.Drivers.Add(new DriverEntry
        {
            Name = "",
            FileName = @"C:\Windows\System32\drivers\test.sys",
            IsSigned = true
        });
        var result = MakeResult();

        // Should not throw
        _audit.AnalyzeState(state, result);
        Assert.True(result.Findings.Count > 0);
    }

    [Fact]
    public void AnalyzeState_AllFindingsHaveCategory()
    {
        var state = MakeCleanState();
        state.TestSigningEnabled = true;
        state.SecureBootEnabled = false;
        state.HvciEnabled = false;
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.All(result.Findings, f => Assert.Equal("Drivers", f.Category));
    }

    [Fact]
    public void AnalyzeState_DriverBlockListEmpty_Warning()
    {
        var state = MakeCleanState();
        state.DriverBlockListVersion = "";
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Title.Contains("Block List Not Found") && f.Severity == Severity.Warning);
    }

    [Fact]
    public void AnalyzeState_LargeDriverCount_Summary()
    {
        var state = MakeCleanState();
        state.TotalDriverCount = 250;
        for (int i = 0; i < 50; i++)
        {
            state.Drivers.Add(new DriverEntry
            {
                Name = $"driver{i}",
                FileName = $@"C:\Windows\System32\drivers\driver{i}.sys",
                Type = "Kernel Driver",
                IsSigned = true,
                IsMicrosoftSigned = i % 2 == 0
            });
        }
        var result = MakeResult();

        _audit.AnalyzeState(state, result);

        var summary = Assert.Single(result.Findings, f => f.Title.Contains("Driver Summary"));
        Assert.Contains("250 total", summary.Title);
    }
}
