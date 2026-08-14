using System;
using System.Linq;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using Xunit;
using static WinSentinel.Core.Audits.PowerShellSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Regression tests for the profile-persistence/execution detection tokens added on
/// Day 84: Windows-service execution/persistence LOLBins (sc create, sc.exe create,
/// New-Service, sc config, Set-Service — MITRE T1543.003), autostart Run-key
/// persistence (reg add, CurrentVersion\Run — MITRE T1547.001), and interactive
/// remote-session lateral movement (Enter-PSSession — MITRE T1021.006). All
/// single-machine, forensic-only checks (Free tier) exercising the pure, I/O-free
/// <see cref="PowerShellSecurityAnalyzer.ScanProfileContent"/>.
/// </summary>
public class PowerShellProfileTokensDay84Tests
{
    [Theory]
    [InlineData("sc create evilsvc binPath= C:\\evil.exe", "creates a Windows service")]
    [InlineData("sc.exe create evilsvc binPath= C:\\evil.exe", "creates a Windows service")]
    [InlineData("New-Service -Name evil -BinaryPathName C:\\evil.exe", "New-Service")]
    [InlineData("sc config trustedsvc binPath= C:\\evil.exe", "reconfigures a Windows service")]
    [InlineData("Set-Service -Name spooler -StartupType Automatic", "Set-Service")]
    [InlineData("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d evil.exe", "registry write via the reg")]
    [InlineData("New-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name x -Value evil", "autostart Run key")]
    [InlineData("Enter-PSSession -ComputerName dc01", "interactive remote PowerShell session")]
    public void ScanProfileContent_Day84Tokens_AreDetected(string content, string expectReasonSubstring)
    {
        var reasons = ScanProfileContent(content);
        Assert.NotEmpty(reasons);
        Assert.Contains(reasons, r => r.Contains(expectReasonSubstring, StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    // Benign lines with none of the Day84 tokens must not trip.
    [InlineData("Get-Service | Where-Object Status -eq Running")]
    [InlineData("Write-Host 'run the build script'")]
    [InlineData("Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")]
    public void ScanProfileContent_Day84BenignLookalikes_AreNotFlagged(string content)
    {
        Assert.Empty(ScanProfileContent(content));
    }

    [Fact]
    public void CheckProfiles_MachineWideServiceCreate_IsCritical()
    {
        var state = new PowerShellState();
        state.Profiles.Add(new PowerShellProfileInfo
        {
            Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
            Scope = "AllUsersAllHosts",
            IsMachineWide = true,
            Content = "sc create backdoor binPath= C:\\evil.exe start= auto",
        });

        var f = Assert.Single(CheckProfiles(state));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("PowerShell", f.Category);
        Assert.Contains("service", f.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanProfileContent_MultipleDay84Tokens_DeDuplicatesReasons()
    {
        var reasons = ScanProfileContent(
            "reg add HKCU\\...\\CurrentVersion\\Run /v a; reg add HKCU\\...\\CurrentVersion\\Run /v b");
        Assert.NotEmpty(reasons);
        Assert.Equal(reasons.Count, reasons.Distinct().Count());
    }
}
