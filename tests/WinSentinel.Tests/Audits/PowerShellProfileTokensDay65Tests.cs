using System;
using System.Linq;
using WinSentinel.Core.Audits;
using WinSentinel.Core.Models;
using Xunit;
using static WinSentinel.Core.Audits.PowerShellSecurityAnalyzer;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Regression tests for the profile-persistence detection tokens added on Day 65
/// (local-account/admin-group manipulation, shadow-copy deletion, event-log clearing,
/// LSASS memory dumping, in-memory injection tooling, keystroke logging, and
/// cmstp/bcdedit LOLBin abuse). These are all single-machine, forensic-only checks
/// (Free tier); they exercise <see cref="PowerShellSecurityAnalyzer.ScanProfileContent"/>
/// which is pure and I/O-free.
/// </summary>
public class PowerShellProfileTokensDay65Tests
{
    [Theory]
    [InlineData("net user backdoor P@ss1 /add", "local account manipulation")]
    [InlineData("net localgroup administrators backdoor /add", "local admin-group manipulation")]
    [InlineData("Add-LocalGroupMember -Group Administrators -Member evil", "local admin-group manipulation")]
    [InlineData("vssadmin delete shadows /all /quiet", "Volume Shadow Copy deletion")]
    [InlineData("wevtutil cl Security", "event-log clearing")]
    [InlineData("Clear-EventLog -LogName Security", "event-log clearing")]
    [InlineData("rundll32 comsvcs.dll, MiniDump 1234 lsass.dmp full", "LSASS credential dump")]
    [InlineData("Out-Minidump -Process (Get-Process lsass)", "process-memory dumping")]
    [InlineData("Invoke-DllInjection -ProcessId 1234 -Dll evil.dll", "DLL injection")]
    [InlineData("Invoke-ReflectivePEInjection -PEBytes $b", "reflective PE injection")]
    [InlineData("Get-Keystrokes -LogPath C:\\k.log", "keystroke logging")]
    [InlineData("cmstp /s evil.inf", "UAC bypass")]
    [InlineData("bcdedit /set {default} safeboot minimal", "boot-configuration tampering")]
    public void ScanProfileContent_Day65Tokens_AreDetected(string content, string expectReasonSubstring)
    {
        var reasons = ScanProfileContent(content);
        Assert.NotEmpty(reasons);
        Assert.Contains(reasons, r => r.Contains(expectReasonSubstring, StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    // Benign lines that resemble the new tokens but must NOT trip: 'net use' (drive
    // map, not 'net user '), a comment mentioning bcdedit without '/set', 'net
    // localgroup users' (not administrators), and prose containing 'cmstp' without
    // the '/s' switch.
    [InlineData("net use Z: \\\\server\\share")]
    [InlineData("# document how bcdedit works for recovery")]
    [InlineData("net localgroup users alice /add")]
    [InlineData("Write-Host 'cmstp is a connection-manager tool'")]
    public void ScanProfileContent_Day65BenignLookalikes_AreNotFlagged(string content)
    {
        Assert.Empty(ScanProfileContent(content));
    }

    [Fact]
    public void CheckProfiles_MachineWideShadowCopyDeletion_IsCritical()
    {
        var state = new PowerShellState();
        state.Profiles.Add(new PowerShellProfileInfo
        {
            Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
            Scope = "AllUsersAllHosts",
            IsMachineWide = true,
            Content = "vssadmin delete shadows /all /quiet",
        });

        var f = Assert.Single(CheckProfiles(state));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Equal("PowerShell", f.Category);
        Assert.Contains("Shadow Copy", f.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanProfileContent_MultipleDay65Tokens_DeDuplicatesReasons()
    {
        var reasons = ScanProfileContent(
            "wevtutil cl Security; wevtutil cl System; Clear-EventLog -LogName Application");
        Assert.NotEmpty(reasons);
        Assert.Equal(reasons.Count, reasons.Distinct().Count());
    }
}
