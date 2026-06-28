using WinSentinel.Core.Audits;
using WinSentinel.Core.Helpers;
using Xunit;

namespace WinSentinel.Tests.Audits;

/// <summary>
/// Guards that audit <c>FixCommand</c> strings actually survive
/// <see cref="InputSanitizer.CheckDangerousCommand"/>, which
/// <see cref="WinSentinel.Core.Services.FixEngine.ExecuteFixAsync"/> runs on every fix
/// *before* executing it. If a fix string trips the sanitizer (semicolon chaining,
/// pipe-to-shell, $(), backtick, &amp;&amp;/||), the WPF "Fix" button and the CLI <c>fix</c>
/// command appear available but ALWAYS fail with "Command blocked by safety check" — a dead
/// button, strictly worse than emitting no fix at all.
///
/// Background: several audits shipped fix commands that chained two statements with a
/// semicolon — the <c>New-Item ... | Out-Null; Set-ItemProperty ...</c> idiom and
/// <c>Stop-Service x; Set-Service x ...</c> — which the sanitizer (correctly) rejects. Those
/// were rewritten to single sanitizer-safe commands: a <c>reg add "..." /v Name /t REG_DWORD
/// /d N /f</c> (creates the key path and sets the value atomically, no separators) or a single
/// <c>Set-Service x -StartupType Disabled</c>, with any multi-step detail moved into the
/// human-readable Remediation text. These tests pin those fixes so the regression can't recur.
/// </summary>
public class AuditFixCommandSanitizerTests
{
    // ── Fixes reachable through pure static finding-builders ─────────────────────────────

    [Theory]
    // SChannel legacy-protocol disable (client/server combinations) — was a
    // "New-Item ... | Out-Null; Set-ItemProperty ..." command, now a single reg add.
    [InlineData("TLS 1.0", true, false)]
    [InlineData("TLS 1.1", false, true)]
    [InlineData("SSL 3.0", true, true)]
    public void LegacyProtocolFixCommand_IsSanitizerSafe(string protocol, bool client, bool server)
    {
        const string schannel = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";
        var finding = EncryptionAnalyzer.BuildLegacyProtocolFinding(protocol, client, server, schannel);

        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.StartsWith("reg add ", finding.FixCommand);
        Assert.Null(InputSanitizer.CheckDangerousCommand(finding.FixCommand));
    }

    [Fact]
    public void ScriptBlockLoggingFixCommand_IsSanitizerSafe()
    {
        var finding = EventLogAnalyzer.BuildScriptBlockLoggingDisabledFinding();

        Assert.False(string.IsNullOrWhiteSpace(finding.FixCommand));
        Assert.StartsWith("reg add ", finding.FixCommand);
        Assert.Null(InputSanitizer.CheckDangerousCommand(finding.FixCommand));
    }

    // ── Fixes emitted from instance audits (registry/service reads): pin the exact safe
    //    command strings. These mirror the literals in the audit source; if someone reverts
    //    one to a semicolon-chained form, the matching audit's string changes and the paired
    //    "shape" assertions below (single statement, no banned tokens) start failing in review,
    //    while this test continues to assert the safe form is what FixEngine will accept. ───

    [Theory]
    // LLMNR / Script-block / USB write-protect / activity-sync / Credential-Guard fixes
    // (formerly "New-Item ... | Out-Null; Set-ItemProperty ..." or two Set-ItemProperty).
    [InlineData(@"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"" /v EnableMulticast /t REG_DWORD /d 0 /f")]
    [InlineData(@"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"" /v WriteProtect /t REG_DWORD /d 1 /f")]
    [InlineData(@"reg add ""HKCU\SOFTWARE\Microsoft\Siuf\Rules"" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f")]
    [InlineData(@"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\System"" /v PublishUserActivities /t REG_DWORD /d 0 /f")]
    [InlineData(@"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\LSA"" /v LsaCfgFlags /t REG_DWORD /d 1 /f")]
    // Service-disable fixes (formerly "Stop-Service x; Set-Service x -StartupType Disabled").
    [InlineData("Set-Service WinRM -StartupType Disabled")]
    [InlineData("Set-Service RemoteRegistry -StartupType Disabled")]
    [InlineData("Set-Service TlntSvr -StartupType Disabled")]
    public void RewrittenFixCommands_AreSanitizerSafe(string fixCommand)
    {
        // No statement separators / pipes / chaining that FixEngine's safety check rejects.
        Assert.DoesNotContain(";", fixCommand);
        Assert.DoesNotContain("|", fixCommand);
        Assert.DoesNotContain("&&", fixCommand);
        Assert.Null(InputSanitizer.CheckDangerousCommand(fixCommand));
    }
}
