using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using static WinSentinel.Core.Audits.ServiceAudit;

namespace WinSentinel.Tests.Audits;

public class ServiceAuditTests
{
    private readonly ServiceAudit _audit;

    public ServiceAuditTests()
    {
        _audit = new ServiceAudit();
    }

    private static AuditResult MakeResult() => new()
    {
        ModuleName = "Windows Service Security Audit",
        Category = "Services"
    };

    private static ServiceState MakeCleanState() => new()
    {
        TotalServiceCount = 3,
        Services = new List<ServiceEntry>
        {
            new()
            {
                ServiceName = "WinDefend",
                DisplayName = "Windows Defender Antivirus",
                BinaryPath = @"""C:\Program Files\Windows Defender\MsMpEng.exe""",
                StartType = "Auto",
                Status = "Running",
                Account = "LocalSystem"
            },
            new()
            {
                ServiceName = "mpssvc",
                DisplayName = "Windows Defender Firewall",
                BinaryPath = @"C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                StartType = "Auto",
                Status = "Running",
                Account = "NT AUTHORITY\\LocalService"
            },
            new()
            {
                ServiceName = "MyApp",
                DisplayName = "My Application Service",
                BinaryPath = @"""C:\Program Files\MyApp\service.exe""",
                StartType = "Auto",
                Status = "Running",
                Account = "NT SERVICE\\MyApp"
            }
        }
    };

    // ── Module metadata ─────────────────────────────────────────

    [Fact]
    public void Name_ReturnsExpected()
    {
        Assert.Equal("Windows Service Security Audit", _audit.Name);
    }

    [Fact]
    public void Category_ReturnsExpected()
    {
        Assert.Equal("Services", _audit.Category);
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

        Assert.Equal(0, result.CriticalCount);
        Assert.Equal(0, result.WarningCount);
        Assert.True(result.Findings.Any(f => f.Severity == Severity.Pass));
    }

    [Fact]
    public void AnalyzeState_EmptyState_InfoFinding()
    {
        var state = new ServiceState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("No service data"));
    }

    // ── Unquoted paths ──────────────────────────────────────────

    [Theory]
    [InlineData(@"C:\Program Files\MyApp\service.exe", true)]
    [InlineData(@"C:\Program Files (x86)\App\svc.exe", true)]
    [InlineData(@"""C:\Program Files\MyApp\service.exe""", false)]
    [InlineData(@"C:\Windows\System32\svchost.exe", false)]
    [InlineData(@"C:\NoSpaces\app.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsUnquotedPathVulnerable_DetectsCorrectly(string? path, bool expected)
    {
        Assert.Equal(expected, IsUnquotedPathVulnerable(path!));
    }

    [Fact]
    public void CheckUnquotedPaths_DetectsVulnerablePath()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "VulnSvc",
                    DisplayName = "Vulnerable Service",
                    BinaryPath = @"C:\Program Files\My App\service.exe -arg",
                    Account = "LocalSystem"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckUnquotedPaths(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Unquoted service path") &&
            f.Title.Contains("VulnSvc"));
    }

    [Fact]
    public void CheckUnquotedPaths_QuotedPath_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "SafeSvc",
                    BinaryPath = @"""C:\Program Files\My App\service.exe"" -arg"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckUnquotedPaths(state, result);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void CheckUnquotedPaths_MultipleVulnerable_FindsAll()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "Svc1", DisplayName = "S1", BinaryPath = @"C:\Program Files\App 1\s.exe" },
                new() { ServiceName = "Svc2", DisplayName = "S2", BinaryPath = @"C:\Program Files\App 2\s.exe" },
            }
        };
        var result = MakeResult();
        _audit.CheckUnquotedPaths(state, result);

        Assert.Equal(2, result.Findings.Count(f => f.Severity == Severity.Critical));
    }

    // ── Suspicious paths ────────────────────────────────────────

    [Fact]
    public void CheckSuspiciousServicePaths_TempDir_Critical()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "MalSvc",
                    DisplayName = "Malicious Service",
                    BinaryPath = @"C:\Users\Public\temp\evil.exe"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckSuspiciousServicePaths(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("suspicious location"));
    }

    [Fact]
    public void CheckSuspiciousServicePaths_DownloadsDir_Critical()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "DlSvc",
                    DisplayName = "Downloaded Service",
                    BinaryPath = @"C:\Users\John\Downloads\setup_service.exe"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckSuspiciousServicePaths(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void CheckSuspiciousServicePaths_ProgramFiles_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "GoodSvc",
                    BinaryPath = @"C:\Program Files\GoodApp\service.exe"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckSuspiciousServicePaths(state, result);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void CheckSuspiciousServicePaths_EmptyPath_Skipped()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "EmptySvc", BinaryPath = "" }
            }
        };
        var result = MakeResult();
        _audit.CheckSuspiciousServicePaths(state, result);

        Assert.Empty(result.Findings);
    }

    // ── SYSTEM account services ─────────────────────────────────

    [Fact]
    public void CheckSystemAccountServices_UntrustedPath_Warning()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "CustomSvc",
                    DisplayName = "Custom Service",
                    BinaryPath = @"D:\MyTools\service.exe",
                    Account = "LocalSystem"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckSystemAccountServices(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("SYSTEM service outside trusted path"));
    }

    [Fact]
    public void CheckSystemAccountServices_TrustedPath_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "WinSvc",
                    BinaryPath = @"C:\Windows\System32\svchost.exe -k netsvcs",
                    Account = "NT AUTHORITY\\SYSTEM"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckSystemAccountServices(state, result);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void CheckSystemAccountServices_NonSystemAccount_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "UserSvc",
                    BinaryPath = @"D:\Custom\app.exe",
                    Account = "DOMAIN\\svcaccount"
                }
            }
        };
        var result = MakeResult();
        _audit.CheckSystemAccountServices(state, result);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void CheckSystemAccountServices_EmptyAccount_Skipped()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "NoAcct", BinaryPath = @"D:\app.exe", Account = "" }
            }
        };
        var result = MakeResult();
        _audit.CheckSystemAccountServices(state, result);

        Assert.Empty(result.Findings);
    }

    // ── Security-critical services ──────────────────────────────

    [Fact]
    public void CheckSecurityCriticalServices_AllRunning_Pass()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "WinDefend", DisplayName = "Defender", StartType = "Auto", Status = "Running" },
                new() { ServiceName = "mpssvc", DisplayName = "Firewall", StartType = "Auto", Status = "Running" },
                new() { ServiceName = "EventLog", DisplayName = "Event Log", StartType = "Auto", Status = "Running" },
            }
        };
        var result = MakeResult();
        _audit.CheckSecurityCriticalServices(state, result);

        Assert.True(result.Findings.All(f => f.Severity == Severity.Pass));
        Assert.Equal(3, result.PassCount);
    }

    [Fact]
    public void CheckSecurityCriticalServices_DefenderDisabled_Critical()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "WinDefend", DisplayName = "Defender", StartType = "Disabled", Status = "Stopped" },
            }
        };
        var result = MakeResult();
        _audit.CheckSecurityCriticalServices(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Critical &&
            f.Title.Contains("Security service disabled") &&
            f.FixCommand != null);
    }

    [Fact]
    public void CheckSecurityCriticalServices_AutoButStopped_Warning()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "mpssvc", DisplayName = "Firewall", StartType = "Auto", Status = "Stopped" },
            }
        };
        var result = MakeResult();
        _audit.CheckSecurityCriticalServices(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("Security service not running"));
    }

    [Fact]
    public void CheckSecurityCriticalServices_AutomaticButStopped_Warning()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "EventLog", DisplayName = "Event Log", StartType = "Automatic", Status = "Stopped" },
            }
        };
        var result = MakeResult();
        _audit.CheckSecurityCriticalServices(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void CheckSecurityCriticalServices_NotInSnapshot_NoFinding()
    {
        var state = new ServiceState { Services = new List<ServiceEntry>() };
        var result = MakeResult();
        _audit.CheckSecurityCriticalServices(state, result);

        Assert.Empty(result.Findings);
    }

    // ── Missing binaries ────────────────────────────────────────

    [Fact]
    public void CheckMissingBinaries_AutoStartMissing_Warning()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "GhostSvc",
                    DisplayName = "Ghost Service",
                    BinaryPath = @"C:\OldApp\service.exe",
                    StartType = "Auto",
                    BinaryExists = false
                }
            }
        };
        var result = MakeResult();
        _audit.CheckMissingBinaries(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("missing binary") &&
            f.FixCommand != null);
    }

    [Fact]
    public void CheckMissingBinaries_AutomaticMissing_Warning()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "OldSvc",
                    DisplayName = "Old Service",
                    BinaryPath = @"C:\Removed\svc.exe",
                    StartType = "Automatic",
                    BinaryExists = false
                }
            }
        };
        var result = MakeResult();
        _audit.CheckMissingBinaries(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void CheckMissingBinaries_ManualMissing_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "ManualSvc",
                    BinaryPath = @"C:\OldApp\svc.exe",
                    StartType = "Manual",
                    BinaryExists = false
                }
            }
        };
        var result = MakeResult();
        _audit.CheckMissingBinaries(state, result);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void CheckMissingBinaries_ExistsNull_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new()
                {
                    ServiceName = "UnknownSvc",
                    BinaryPath = @"C:\App\svc.exe",
                    StartType = "Auto",
                    BinaryExists = null
                }
            }
        };
        var result = MakeResult();
        _audit.CheckMissingBinaries(state, result);

        Assert.Empty(result.Findings);
    }

    // ── Command wrapper services ────────────────────────────────

    [Theory]
    [InlineData(@"cmd.exe /c C:\scripts\run.bat", "cmd.exe")]
    [InlineData(@"C:\Windows\System32\cmd /c start service.exe", "cmd /c")]
    [InlineData(@"powershell.exe -File C:\svc.ps1", "powershell.exe")]
    [InlineData(@"C:\Windows\System32\wscript.exe C:\scripts\svc.vbs", "wscript.exe")]
    public void CheckWrapperCommands_DetectsWrappers(string path, string expectedPattern)
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "WrapSvc", DisplayName = "Wrapper", BinaryPath = path }
            }
        };
        var result = MakeResult();
        _audit.CheckWrapperCommands(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Warning &&
            f.Title.Contains("command wrapper"));
    }

    [Fact]
    public void CheckWrapperCommands_NormalExe_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "NormalSvc", BinaryPath = @"C:\Program Files\App\service.exe" }
            }
        };
        var result = MakeResult();
        _audit.CheckWrapperCommands(state, result);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void CheckWrapperCommands_EmptyPath_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "EmptySvc", BinaryPath = "" }
            }
        };
        var result = MakeResult();
        _audit.CheckWrapperCommands(state, result);

        Assert.Empty(result.Findings);
    }

    // ── Disabled auto-start services ────────────────────────────

    [Fact]
    public void CheckDisabledAutoStartServices_ManyDisabled_Info()
    {
        var services = new List<ServiceEntry>();
        for (int i = 0; i < 25; i++)
        {
            services.Add(new ServiceEntry
            {
                ServiceName = $"Svc{i}",
                StartType = "Disabled"
            });
        }

        var state = new ServiceState { Services = services };
        var result = MakeResult();
        _audit.CheckDisabledAutoStartServices(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("disabled services"));
    }

    [Fact]
    public void CheckDisabledAutoStartServices_FewDisabled_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "Svc1", StartType = "Disabled" },
                new() { ServiceName = "Svc2", StartType = "Disabled" },
            }
        };
        var result = MakeResult();
        _audit.CheckDisabledAutoStartServices(state, result);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void CheckDisabledAutoStartServices_SecurityCriticalNotCounted()
    {
        var services = new List<ServiceEntry>();
        // Add 21 disabled services, but make them all security-critical
        foreach (var name in SecurityCriticalServices.Keys)
        {
            services.Add(new ServiceEntry { ServiceName = name, StartType = "Disabled" });
        }
        // Only 10 security-critical, need 11+ more non-security disabled to trigger
        for (int i = 0; i < 11; i++)
        {
            services.Add(new ServiceEntry { ServiceName = $"NonSec{i}", StartType = "Disabled" });
        }

        var state = new ServiceState { Services = services };
        var result = MakeResult();
        _audit.CheckDisabledAutoStartServices(state, result);

        // 11 non-security disabled — not > 20, so no finding
        Assert.Empty(result.Findings);
    }

    // ── ExtractExecutablePath ───────────────────────────────────

    [Theory]
    [InlineData(@"""C:\Program Files\App\svc.exe"" -arg", @"C:\Program Files\App\svc.exe")]
    [InlineData(@"C:\Windows\System32\svchost.exe -k netsvcs", @"C:\Windows\System32\svchost.exe")]
    [InlineData(@"C:\Program Files\App\service.exe", @"C:\Program Files\App\service.exe")]
    [InlineData(@"C:\app.sys", @"C:\app.sys")]
    public void ExtractExecutablePath_ExtractsCorrectly(string input, string expected)
    {
        Assert.Equal(expected, ServiceAudit.ExtractExecutablePath(input));
    }

    // ── ParseServices ───────────────────────────────────────────

    [Fact]
    public void ParseServices_SingleObject_Parsed()
    {
        var json = @"{""Name"":""TestSvc"",""DisplayName"":""Test Service"",""PathName"":""C:\\test.exe"",""StartMode"":""Auto"",""State"":""Running"",""StartName"":""LocalSystem"",""Description"":""A test""}";
        var entries = ServiceAudit.ParseServices(json);

        Assert.Single(entries);
        Assert.Equal("TestSvc", entries[0].ServiceName);
        Assert.Equal("Test Service", entries[0].DisplayName);
        Assert.Contains("test.exe", entries[0].BinaryPath);
        Assert.Equal("Auto", entries[0].StartType);
        Assert.Equal("Running", entries[0].Status);
        Assert.Equal("LocalSystem", entries[0].Account);
    }

    [Fact]
    public void ParseServices_Array_ParsedAll()
    {
        var json = @"[{""Name"":""Svc1"",""DisplayName"":""S1"",""PathName"":""C:\\a.exe"",""StartMode"":""Auto"",""State"":""Running"",""StartName"":""LocalSystem"",""Description"":null},{""Name"":""Svc2"",""DisplayName"":""S2"",""PathName"":""C:\\b.exe"",""StartMode"":""Manual"",""State"":""Stopped"",""StartName"":""NT AUTHORITY\\SYSTEM"",""Description"":""svc""}]";
        var entries = ServiceAudit.ParseServices(json);

        Assert.Equal(2, entries.Count);
        Assert.Equal("Svc1", entries[0].ServiceName);
        Assert.Equal("Svc2", entries[1].ServiceName);
    }

    [Fact]
    public void ParseServices_EmptyString_EmptyList()
    {
        Assert.Empty(ServiceAudit.ParseServices(""));
    }

    [Fact]
    public void ParseServices_InvalidJson_EmptyList()
    {
        Assert.Empty(ServiceAudit.ParseServices("not json at all"));
    }

    [Fact]
    public void ParseServices_NullFields_DefaultValues()
    {
        var json = @"{""Name"":""Svc"",""DisplayName"":null,""PathName"":null,""StartMode"":null,""State"":null,""StartName"":null,""Description"":null}";
        var entries = ServiceAudit.ParseServices(json);

        Assert.Single(entries);
        Assert.Equal("Svc", entries[0].ServiceName);
        Assert.Equal("Manual", entries[0].StartType); // default
    }

    // ── Full analysis scenarios ─────────────────────────────────

    [Fact]
    public void AnalyzeState_MixedIssues_FindsAll()
    {
        var state = new ServiceState
        {
            TotalServiceCount = 4,
            Services = new List<ServiceEntry>
            {
                // Unquoted path
                new()
                {
                    ServiceName = "Unquoted",
                    DisplayName = "Unquoted Svc",
                    BinaryPath = @"C:\Program Files\Bad App\svc.exe",
                    Account = "DOMAIN\\user"
                },
                // Suspicious path + SYSTEM
                new()
                {
                    ServiceName = "TempSvc",
                    DisplayName = "Temp Service",
                    BinaryPath = @"C:\Users\Public\temp\evil.exe",
                    Account = "LocalSystem"
                },
                // Disabled defender
                new()
                {
                    ServiceName = "WinDefend",
                    DisplayName = "Defender",
                    BinaryPath = @"C:\Program Files\Windows Defender\MsMpEng.exe",
                    StartType = "Disabled",
                    Status = "Stopped",
                    Account = "LocalSystem"
                },
                // Wrapper command
                new()
                {
                    ServiceName = "ScriptSvc",
                    DisplayName = "Script Service",
                    BinaryPath = @"powershell.exe -File C:\scripts\svc.ps1",
                    Account = "NT SERVICE\\ScriptSvc"
                }
            }
        };

        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        // Should have critical findings for unquoted path, suspicious path, and disabled defender
        Assert.True(result.CriticalCount >= 3);
        // Should have warnings for SYSTEM outside trusted path and wrapper command
        Assert.True(result.WarningCount >= 1);
    }

    [Fact]
    public void AnalyzeState_AllSecure_PassSummary()
    {
        var state = MakeCleanState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Pass &&
            f.Title.Contains("looks good"));
    }

    [Fact]
    public void AnalyzeState_IncludesInventoryInfo()
    {
        var state = MakeCleanState();
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        Assert.Contains(result.Findings, f =>
            f.Severity == Severity.Info &&
            f.Title.Contains("Service inventory"));
    }

    // ── Edge cases ──────────────────────────────────────────────

    [Fact]
    public void UnquotedPath_SingleSegment_NotVulnerable()
    {
        Assert.False(IsUnquotedPathVulnerable(@"C:\service.exe"));
    }

    [Fact]
    public void UnquotedPath_NoSpacesInMiddle_NotVulnerable()
    {
        // Space only in filename, not in directory segments
        Assert.False(IsUnquotedPathVulnerable(@"C:\Apps\my service.exe"));
    }

    [Fact]
    public void UnquotedPath_SpaceInDirSegment_Vulnerable()
    {
        Assert.True(IsUnquotedPathVulnerable(@"C:\My Apps\Sub Dir\svc.exe"));
    }

    [Fact]
    public void SystemAccounts_ContainsExpectedEntries()
    {
        Assert.Contains("LocalSystem", SystemAccounts);
        Assert.Contains("NT AUTHORITY\\SYSTEM", SystemAccounts);
        Assert.Contains("SYSTEM", SystemAccounts);
    }

    [Fact]
    public void SecurityCriticalServices_ContainsDefender()
    {
        Assert.True(SecurityCriticalServices.ContainsKey("WinDefend"));
    }

    [Fact]
    public void SecurityCriticalServices_CaseInsensitive()
    {
        Assert.True(SecurityCriticalServices.ContainsKey("windefend"));
        Assert.True(SecurityCriticalServices.ContainsKey("MPSSVC"));
    }

    [Fact]
    public void AnalyzeState_OnlyServiceCount_InfoMessage()
    {
        var state = new ServiceState { TotalServiceCount = 50, Services = new List<ServiceEntry>() };
        var result = MakeResult();
        _audit.AnalyzeState(state, result);

        // Has services total but no entries — still shows inventory info
        Assert.Contains(result.Findings, f => f.Title.Contains("Service inventory"));
    }

    [Fact]
    public void CheckWrapperCommands_RundllService_Warning()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "DllSvc", DisplayName = "DLL Svc", BinaryPath = @"rundll32.exe C:\bad.dll,Entry" }
            }
        };
        var result = MakeResult();
        _audit.CheckWrapperCommands(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Warning);
    }

    [Fact]
    public void CheckSuspiciousServicePaths_RecycleBin_Critical()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "RecSvc", DisplayName = "Recycle Svc", BinaryPath = @"C:\Users\Public\temp\recycle_svc.exe" }
            }
        };
        var result = MakeResult();
        _audit.CheckSuspiciousServicePaths(state, result);

        Assert.Contains(result.Findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void CheckMissingBinaries_ExistsTrue_NoFinding()
    {
        var state = new ServiceState
        {
            Services = new List<ServiceEntry>
            {
                new() { ServiceName = "OkSvc", BinaryPath = @"C:\app.exe", StartType = "Auto", BinaryExists = true }
            }
        };
        var result = MakeResult();
        _audit.CheckMissingBinaries(state, result);

        Assert.Empty(result.Findings);
    }
}
