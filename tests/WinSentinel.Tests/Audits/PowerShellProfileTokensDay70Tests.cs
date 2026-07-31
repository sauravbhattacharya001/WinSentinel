using System;
using System.Linq;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using Xunit;
using static WinSentinel.Core.Audits.PowerShellSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Regression tests for the profile-persistence/defense-evasion detection tokens
/// added on Day 70: process-injection and execution LOLBins (mavinject, WMIC process
/// create, MSBuild inline task), firewall tampering (netsh advfirewall set), remoting
/// enablement/lateral movement (winrm quickconfig, Invoke-Command -ComputerName), and
/// file-permission tampering (takeown /f, icacls). All single-machine, forensic-only
/// checks (Free tier) exercising the pure, I/O-free
/// <see cref="PowerShellSecurityAnalyzer.ScanProfileContent"/>.
/// </summary>
public class PowerShellProfileTokensDay70Tests
{
    [Theory]
    [InlineData("mavinject 1234 /INJECTRUNNING C:\\evil.dll", "process injection")]
    [InlineData("wmic process call create \"cmd /c calc\"", "process spawn")]
    [InlineData("netsh advfirewall set allprofiles state off", "Windows Firewall tampering")]
    [InlineData("winrm quickconfig -quiet", "PowerShell remoting")]
    [InlineData("takeown /f C:\\Windows\\System32\\drivers\\etc\\hosts", "seizes file ownership")]
    [InlineData("icacls C:\\secret /grant Everyone:F", "modifies file ACLs")]
    [InlineData("msbuild evil.csproj", "MSBuild LOLBin")]
    [InlineData("Invoke-Command -ComputerName dc01 -ScriptBlock { whoami }", "remote command execution")]
    public void ScanProfileContent_Day70Tokens_AreDetected(string content, string expectReasonSubstring)
    {
        var reasons = ScanProfileContent(content);
        Assert.NotEmpty(reasons);
        Assert.Contains(reasons, r => r.Contains(expectReasonSubstring, StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    // Benign lines that must NOT trip: prose mentioning a firewall without the
    // 'netsh advfirewall set' command, 'wmic process list' (read-only, not 'call
    // create'), and a comment about msbuild is a real substring so it WOULD match -
    // so instead use lines with none of the tokens at all.
    [InlineData("Write-Host 'remember to check the firewall settings'")]
    [InlineData("wmic process list brief")]
    [InlineData("Get-ChildItem C:\\Windows\\System32")]
    public void ScanProfileContent_Day70BenignLookalikes_AreNotFlagged(string content)
    {
        Assert.Empty(ScanProfileContent(content));
    }

    [Fact]
    public void CheckProfiles_MachineWideFirewallTamper_IsCritical()
    {
        var state = new PowerShellState();
        state.Profiles.Add(new PowerShellProfileInfo
        {
            Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
            Scope = "AllUsersAllHosts",
            IsMachineWide = true,
            Content = "netsh advfirewall set allprofiles state off",
        });

        var f = Assert.Single(CheckProfiles(state));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("PowerShell", f.Category);
        Assert.Contains("Firewall", f.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanProfileContent_MultipleDay70Tokens_DeDuplicatesReasons()
    {
        var reasons = ScanProfileContent(
            "takeown /f a; takeown /f b; icacls a /grant Everyone:F; icacls b /grant Everyone:F");
        Assert.NotEmpty(reasons);
        Assert.Equal(reasons.Count, reasons.Distinct().Count());
    }
}
