using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits remote access security configuration for risks including:
/// - RDP enabled with weak settings (no NLA, default port, weak encryption)
/// - SSH server exposure without key-only auth
/// - VNC/TeamViewer/AnyDesk/other remote tools running with weak config
/// - Remote Desktop Users group membership
/// - WinRM/PSRemoting exposure
/// - Remote Registry service enabled
/// - Remote Assistance enabled
/// </summary>
public class RemoteAccessAudit : IAuditModule
{
    public string Name => "Remote Access Security Audit";
    public string Category => "Remote Access";
    public string Description =>
        "Checks RDP configuration, SSH exposure, third-party remote tools, " +
        "WinRM, Remote Registry, and remote assistance settings for security risks.";

    /// <summary>
    /// Third-party remote access tools and their process names.
    /// </summary>
    public static readonly Dictionary<string, RemoteToolInfo> KnownRemoteTools = new(StringComparer.OrdinalIgnoreCase)
    {
        ["TeamViewer_Service"] = new("TeamViewer", "teamviewer.exe", RemoteToolRisk.Medium,
            "Commercial remote access — ensure unattended access is disabled or uses strong passwords"),
        ["TeamViewer"] = new("TeamViewer", "teamviewer.exe", RemoteToolRisk.Medium,
            "Commercial remote access — ensure unattended access is disabled or uses strong passwords"),
        ["AnyDesk"] = new("AnyDesk", "anydesk.exe", RemoteToolRisk.Medium,
            "Commercial remote access — ensure unattended access is disabled and uses 2FA"),
        ["tvnserver"] = new("TightVNC", "tvnserver.exe", RemoteToolRisk.High,
            "VNC transmits with weak encryption by default; use SSH tunnel or upgrade to encrypted VNC"),
        ["winvnc"] = new("UltraVNC", "winvnc.exe", RemoteToolRisk.High,
            "VNC transmits with weak encryption by default; use SSH tunnel or upgrade to encrypted VNC"),
        ["vncserver"] = new("RealVNC", "vncserver.exe", RemoteToolRisk.Medium,
            "Ensure VNC uses strong authentication and encryption"),
        ["ScreenConnect.ClientService"] = new("ConnectWise ScreenConnect", "screenconnect.clientservice.exe", RemoteToolRisk.Medium,
            "Managed remote access — verify only authorized administrators have access"),
        ["LogMeIn"] = new("LogMeIn", "logmein.exe", RemoteToolRisk.Medium,
            "Ensure account uses strong password and MFA"),
        ["ammyy_admin"] = new("Ammyy Admin", "ammyy_admin.exe", RemoteToolRisk.High,
            "Ammyy Admin is frequently abused by threat actors; consider removing"),
        ["SupremoService"] = new("Supremo", "supremo.exe", RemoteToolRisk.Medium,
            "Ensure unattended access uses strong credentials"),
        ["rustdesk"] = new("RustDesk", "rustdesk.exe", RemoteToolRisk.Low,
            "Open-source remote desktop — verify it's intentionally installed"),
        ["sshd"] = new("OpenSSH Server", "sshd.exe", RemoteToolRisk.Low,
            "SSH server — ensure key-based auth is preferred and password auth is restricted"),
        ["Splashtop"] = new("Splashtop", "srtsp.exe", RemoteToolRisk.Medium,
            "Ensure Splashtop account uses MFA"),
    };

    /// <summary>
    /// Well-known default ports for remote access protocols.
    /// </summary>
    public static readonly Dictionary<string, int> DefaultPorts = new()
    {
        ["RDP"] = 3389,
        ["SSH"] = 22,
        ["VNC"] = 5900,
        ["WinRM-HTTP"] = 5985,
        ["WinRM-HTTPS"] = 5986,
        ["Telnet"] = 23,
    };

    /// <summary>
    /// Remote access tools considered high risk (frequently abused by threat actors).
    /// </summary>
    public static readonly HashSet<string> HighRiskTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "ammyy_admin", "tvnserver", "winvnc",
    };

    public enum RemoteToolRisk
    {
        Low = 0,
        Medium = 1,
        High = 2
    }

    public sealed class RemoteToolInfo
    {
        public string DisplayName { get; }
        public string ExecutableName { get; }
        public RemoteToolRisk Risk { get; }
        public string Advisory { get; }

        public RemoteToolInfo(string displayName, string executableName, RemoteToolRisk risk, string advisory)
        {
            DisplayName = displayName;
            ExecutableName = executableName;
            Risk = risk;
            Advisory = advisory;
        }
    }

    /// <summary>
    /// Data transfer object for remote access environment state.
    /// All checks operate on this record for testability.
    /// </summary>
    public sealed class RemoteAccessState
    {
        /// <summary>Whether RDP is enabled (fDenyTSConnections = 0).</summary>
        public bool RdpEnabled { get; set; }

        /// <summary>Whether Network Level Authentication is required for RDP.</summary>
        public bool RdpNlaEnabled { get; set; }

        /// <summary>RDP listening port.</summary>
        public int RdpPort { get; set; } = 3389;

        /// <summary>RDP minimum encryption level (1=Low, 2=ClientCompatible, 3=High, 4=FIPSCompliant).</summary>
        public int RdpEncryptionLevel { get; set; }

        /// <summary>RDP security layer (0=RDP, 1=Negotiate, 2=TLS).</summary>
        public int RdpSecurityLayer { get; set; }

        /// <summary>Whether RDP session timeout/idle disconnect is configured.</summary>
        public bool RdpIdleTimeoutConfigured { get; set; }

        /// <summary>RDP idle timeout in minutes (0 = no timeout).</summary>
        public int RdpIdleTimeoutMinutes { get; set; }

        /// <summary>Whether RDP restricts max sessions per user.</summary>
        public bool RdpSingleSessionPerUser { get; set; }

        /// <summary>Members of the Remote Desktop Users group.</summary>
        public List<string> RemoteDesktopUsers { get; set; } = new();

        /// <summary>Whether OpenSSH server service is installed.</summary>
        public bool SshServerInstalled { get; set; }

        /// <summary>Whether OpenSSH server service is running.</summary>
        public bool SshServerRunning { get; set; }

        /// <summary>SSH listening port.</summary>
        public int SshPort { get; set; } = 22;

        /// <summary>Whether SSH allows password authentication.</summary>
        public bool SshPasswordAuthEnabled { get; set; }

        /// <summary>Whether SSH allows root/admin login.</summary>
        public bool SshRootLoginEnabled { get; set; }

        /// <summary>Running third-party remote access tool process names.</summary>
        public List<string> RunningRemoteTools { get; set; } = new();

        /// <summary>Installed (but not necessarily running) remote access tool names.</summary>
        public List<string> InstalledRemoteTools { get; set; } = new();

        /// <summary>Whether WinRM service is running.</summary>
        public bool WinRmRunning { get; set; }

        /// <summary>Whether WinRM allows unencrypted traffic.</summary>
        public bool WinRmAllowUnencrypted { get; set; }

        /// <summary>Whether WinRM uses HTTP (vs HTTPS) listener.</summary>
        public bool WinRmHttpListenerEnabled { get; set; }

        /// <summary>Whether WinRM HTTPS listener is configured.</summary>
        public bool WinRmHttpsListenerEnabled { get; set; }

        /// <summary>Whether WinRM allows basic authentication.</summary>
        public bool WinRmBasicAuthEnabled { get; set; }

        /// <summary>Whether Remote Registry service is running.</summary>
        public bool RemoteRegistryRunning { get; set; }

        /// <summary>Remote Registry service start type (Auto, Manual, Disabled).</summary>
        public string RemoteRegistryStartType { get; set; } = "Disabled";

        /// <summary>Whether Remote Assistance is enabled.</summary>
        public bool RemoteAssistanceEnabled { get; set; }

        /// <summary>Whether Telnet server is installed/running.</summary>
        public bool TelnetServerRunning { get; set; }

        /// <summary>Total count of distinct remote access vectors detected.</summary>
        public int TotalRemoteVectors =>
            (RdpEnabled ? 1 : 0) +
            (SshServerRunning ? 1 : 0) +
            RunningRemoteTools.Count +
            (WinRmRunning ? 1 : 0) +
            (RemoteRegistryRunning ? 1 : 0) +
            (TelnetServerRunning ? 1 : 0);
    }

    public async Task<AuditResult> RunAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = new AuditResult
        {
            ModuleName = Name,
            Category = Category,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            var state = await GatherStateAsync(cancellationToken);
            AnalyzeState(state, result);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    /// <summary>
    /// Gather live remote access state from the system.
    /// </summary>
    internal async Task<RemoteAccessState> GatherStateAsync(CancellationToken ct)
    {
        var state = new RemoteAccessState();

        // RDP settings from registry
        try
        {
            var rdpOutput = await ShellHelper.RunPowerShellAsync(
                "$rdp = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue; " +
                "$sec = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue; " +
                "[PSCustomObject]@{ " +
                "  Deny=$rdp.fDenyTSConnections; " +
                "  NLA=$sec.UserAuthentication; " +
                "  Port=$sec.PortNumber; " +
                "  EncLevel=$sec.MinEncryptionLevel; " +
                "  SecLayer=$sec.SecurityLayer; " +
                "  SingleSession=$rdp.fSingleSessionPerUser " +
                "} | ConvertTo-Json", ct);

            if (!string.IsNullOrWhiteSpace(rdpOutput) && rdpOutput.TrimStart().StartsWith("{"))
            {
                var json = System.Text.Json.JsonDocument.Parse(rdpOutput);
                var root = json.RootElement;
                state.RdpEnabled = root.TryGetProperty("Deny", out var deny) && deny.GetInt32() == 0;
                state.RdpNlaEnabled = root.TryGetProperty("NLA", out var nla) && nla.GetInt32() == 1;
                if (root.TryGetProperty("Port", out var port)) state.RdpPort = port.GetInt32();
                if (root.TryGetProperty("EncLevel", out var enc)) state.RdpEncryptionLevel = enc.GetInt32();
                if (root.TryGetProperty("SecLayer", out var sec)) state.RdpSecurityLayer = sec.GetInt32();
                state.RdpSingleSessionPerUser = root.TryGetProperty("SingleSession", out var ss) && ss.GetInt32() == 1;
            }
        }
        catch { /* Non-fatal */ }

        // RDP idle timeout
        try
        {
            var timeoutOutput = await ShellHelper.RunPowerShellAsync(
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'MaxIdleTime' -ErrorAction SilentlyContinue).MaxIdleTime", ct);
            if (int.TryParse(timeoutOutput?.Trim(), out var idleMs) && idleMs > 0)
            {
                state.RdpIdleTimeoutConfigured = true;
                state.RdpIdleTimeoutMinutes = idleMs / 60000;
            }
        }
        catch { /* Non-fatal */ }

        // Remote Desktop Users group
        try
        {
            var usersOutput = await ShellHelper.RunPowerShellAsync(
                "Get-LocalGroupMember 'Remote Desktop Users' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name", ct);
            if (!string.IsNullOrWhiteSpace(usersOutput))
            {
                state.RemoteDesktopUsers = usersOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
            }
        }
        catch { /* Non-fatal */ }

        // SSH Server
        try
        {
            var sshService = await ShellHelper.RunPowerShellAsync(
                "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Status, StartType | ConvertTo-Json", ct);
            if (!string.IsNullOrWhiteSpace(sshService) && sshService.TrimStart().StartsWith("{"))
            {
                var json = System.Text.Json.JsonDocument.Parse(sshService);
                var root = json.RootElement;
                state.SshServerInstalled = true;
                if (root.TryGetProperty("Status", out var status))
                    state.SshServerRunning = status.GetInt32() == 4; // Running
            }

            // SSH config
            var sshConfig = await ShellHelper.RunPowerShellAsync(
                "if (Test-Path $env:ProgramData\\ssh\\sshd_config) { Get-Content $env:ProgramData\\ssh\\sshd_config -Raw }", ct);
            if (!string.IsNullOrWhiteSpace(sshConfig))
            {
                state.SshPasswordAuthEnabled = !sshConfig.Contains("PasswordAuthentication no", StringComparison.OrdinalIgnoreCase);
                state.SshRootLoginEnabled = sshConfig.Contains("PermitRootLogin yes", StringComparison.OrdinalIgnoreCase);
                var portMatch = System.Text.RegularExpressions.Regex.Match(sshConfig, @"^\s*Port\s+(\d+)", System.Text.RegularExpressions.RegexOptions.Multiline);
                if (portMatch.Success && int.TryParse(portMatch.Groups[1].Value, out var sshPort))
                    state.SshPort = sshPort;
            }
        }
        catch { /* Non-fatal */ }

        // Running remote tools
        try
        {
            var processes = await ShellHelper.RunPowerShellAsync(
                "Get-Process | Select-Object -ExpandProperty ProcessName -Unique", ct);
            if (!string.IsNullOrWhiteSpace(processes))
            {
                var running = processes.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var tool in KnownRemoteTools.Keys)
                {
                    if (running.Contains(tool))
                        state.RunningRemoteTools.Add(tool);
                }
            }
        }
        catch { /* Non-fatal */ }

        // WinRM
        try
        {
            var winrmService = await ShellHelper.RunPowerShellAsync(
                "Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status", ct);
            state.WinRmRunning = winrmService?.Trim() == "Running" || winrmService?.Trim() == "4";

            if (state.WinRmRunning)
            {
                var winrmConfig = await ShellHelper.RunPowerShellAsync(
                    "winrm get winrm/config/service 2>$null", ct);
                if (!string.IsNullOrWhiteSpace(winrmConfig))
                {
                    state.WinRmAllowUnencrypted = winrmConfig.Contains("AllowUnencrypted = true", StringComparison.OrdinalIgnoreCase);
                    state.WinRmBasicAuthEnabled = winrmConfig.Contains("Basic = true", StringComparison.OrdinalIgnoreCase);
                }

                var listeners = await ShellHelper.RunPowerShellAsync(
                    "winrm enumerate winrm/config/listener 2>$null", ct);
                if (!string.IsNullOrWhiteSpace(listeners))
                {
                    state.WinRmHttpListenerEnabled = listeners.Contains("Transport = HTTP", StringComparison.OrdinalIgnoreCase);
                    state.WinRmHttpsListenerEnabled = listeners.Contains("Transport = HTTPS", StringComparison.OrdinalIgnoreCase);
                }
            }
        }
        catch { /* Non-fatal */ }

        // Remote Registry
        try
        {
            var remRegOutput = await ShellHelper.RunPowerShellAsync(
                "Get-Service RemoteRegistry -ErrorAction SilentlyContinue | Select-Object Status, StartType | ConvertTo-Json", ct);
            if (!string.IsNullOrWhiteSpace(remRegOutput) && remRegOutput.TrimStart().StartsWith("{"))
            {
                var json = System.Text.Json.JsonDocument.Parse(remRegOutput);
                var root = json.RootElement;
                if (root.TryGetProperty("Status", out var status))
                    state.RemoteRegistryRunning = status.GetInt32() == 4;
                if (root.TryGetProperty("StartType", out var startType))
                    state.RemoteRegistryStartType = startType.GetInt32() switch
                    {
                        2 => "Automatic",
                        3 => "Manual",
                        4 => "Disabled",
                        _ => "Unknown"
                    };
            }
        }
        catch { /* Non-fatal */ }

        // Remote Assistance
        try
        {
            var raOutput = await ShellHelper.RunPowerShellAsync(
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' -Name 'fAllowToGetHelp' -ErrorAction SilentlyContinue).fAllowToGetHelp", ct);
            state.RemoteAssistanceEnabled = raOutput?.Trim() == "1";
        }
        catch { /* Non-fatal */ }

        // Telnet server
        try
        {
            var telnetOutput = await ShellHelper.RunPowerShellAsync(
                "Get-Service TlntSvr -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status", ct);
            state.TelnetServerRunning = telnetOutput?.Trim() == "Running" || telnetOutput?.Trim() == "4";
        }
        catch { /* Non-fatal */ }

        return state;
    }

    /// <summary>
    /// Analyze remote access state and populate findings. Public for testability.
    /// </summary>
    public static void AnalyzeState(RemoteAccessState state, AuditResult result)
    {
        const string cat = "Remote Access";

        AnalyzeRdp(state, result, cat);
        AnalyzeSsh(state, result, cat);
        AnalyzeRemoteTools(state, result, cat);
        AnalyzeWinRm(state, result, cat);
        AnalyzeRemoteRegistry(state, result, cat);
        AnalyzeRemoteAssistance(state, result, cat);
        AnalyzeTelnet(state, result, cat);
        AnalyzeOverallExposure(state, result, cat);
    }

    private static void AnalyzeRdp(RemoteAccessState state, AuditResult result, string cat)
    {
        if (!state.RdpEnabled)
        {
            result.Findings.Add(Finding.Pass("RDP Disabled",
                "Remote Desktop Protocol is disabled — no RDP attack surface.", cat));
            return;
        }

        result.Findings.Add(Finding.Warning("RDP Enabled",
            "Remote Desktop is enabled. Ensure only authorized users have access and strong authentication is configured.",
            cat,
            "Disable RDP if not needed: Settings > System > Remote Desktop > Off",
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"));

        // NLA
        if (!state.RdpNlaEnabled)
        {
            result.Findings.Add(Finding.Critical("RDP: Network Level Authentication Disabled",
                "NLA is not required for RDP connections. Without NLA, attackers can reach the Windows login screen " +
                "without pre-authentication, exposing the system to brute-force and BlueKeep-style attacks.",
                cat,
                "Enable NLA: System Properties > Remote > 'Allow connections only from computers running Remote Desktop with Network Level Authentication'",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("RDP: NLA Enabled",
                "Network Level Authentication is required for RDP connections.", cat));
        }

        // Port
        if (state.RdpPort == DefaultPorts["RDP"])
        {
            result.Findings.Add(Finding.Info("RDP: Default Port (3389)",
                "RDP is listening on the default port 3389. While security-through-obscurity is limited, " +
                "changing the port reduces exposure to mass scanning and automated attacks.",
                cat,
                "Consider changing the RDP port via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber"));
        }

        // Encryption level
        if (state.RdpEncryptionLevel < 3)
        {
            result.Findings.Add(Finding.Warning("RDP: Weak Encryption Level",
                $"RDP encryption level is {state.RdpEncryptionLevel} (Low or ClientCompatible). " +
                "This allows weaker encryption negotiation with older clients.",
                cat,
                "Set minimum encryption to High (3) or FIPS Compliant (4) via Group Policy: " +
                "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Security"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("RDP: Strong Encryption Level",
                $"RDP encryption level is set to {(state.RdpEncryptionLevel == 4 ? "FIPS Compliant" : "High")}.", cat));
        }

        // Security layer
        if (state.RdpSecurityLayer == 0)
        {
            result.Findings.Add(Finding.Warning("RDP: Native RDP Security Layer",
                "RDP is using the native RDP security layer (0) instead of TLS. " +
                "This provides weaker authentication and encryption.",
                cat,
                "Set Security Layer to TLS (2) via Group Policy or registry"));
        }
        else if (state.RdpSecurityLayer == 2)
        {
            result.Findings.Add(Finding.Pass("RDP: TLS Security Layer",
                "RDP is using TLS for the security layer.", cat));
        }

        // Idle timeout
        if (!state.RdpIdleTimeoutConfigured)
        {
            result.Findings.Add(Finding.Warning("RDP: No Idle Timeout",
                "No idle session timeout is configured for RDP. Abandoned sessions remain open indefinitely, " +
                "increasing the window for session hijacking.",
                cat,
                "Configure idle timeout via Group Policy: Computer Configuration > Administrative Templates > " +
                "Windows Components > Remote Desktop Services > Session Time Limits"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("RDP: Idle Timeout Configured",
                $"RDP idle timeout is set to {state.RdpIdleTimeoutMinutes} minutes.", cat));
        }

        // Single session
        if (!state.RdpSingleSessionPerUser)
        {
            result.Findings.Add(Finding.Info("RDP: Multiple Sessions Per User Allowed",
                "Users can have multiple simultaneous RDP sessions. Consider restricting to one session per user.",
                cat,
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fSingleSessionPerUser -Value 1"));
        }

        // Remote Desktop Users group
        if (state.RemoteDesktopUsers.Count > 5)
        {
            result.Findings.Add(Finding.Warning("RDP: Large Remote Desktop Users Group",
                $"The 'Remote Desktop Users' group has {state.RemoteDesktopUsers.Count} members. " +
                "Review membership to ensure only authorized users have remote access.",
                cat,
                "Review and prune: net localgroup \"Remote Desktop Users\""));
        }
        else if (state.RemoteDesktopUsers.Count > 0 && state.RdpEnabled)
        {
            result.Findings.Add(Finding.Info("RDP: Remote Desktop Users",
                $"Remote Desktop Users group has {state.RemoteDesktopUsers.Count} member(s): " +
                string.Join(", ", state.RemoteDesktopUsers), cat));
        }
    }

    private static void AnalyzeSsh(RemoteAccessState state, AuditResult result, string cat)
    {
        if (!state.SshServerInstalled)
        {
            result.Findings.Add(Finding.Pass("SSH Server Not Installed",
                "OpenSSH Server is not installed — no SSH attack surface.", cat));
            return;
        }

        if (!state.SshServerRunning)
        {
            result.Findings.Add(Finding.Info("SSH Server Installed but Not Running",
                "OpenSSH Server is installed but the service is not running.", cat,
                "If SSH is not needed, uninstall: Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"));
            return;
        }

        result.Findings.Add(Finding.Info("SSH Server Running",
            $"OpenSSH Server is running on port {state.SshPort}.", cat));

        if (state.SshPasswordAuthEnabled)
        {
            result.Findings.Add(Finding.Warning("SSH: Password Authentication Enabled",
                "SSH allows password-based authentication. Key-based authentication is significantly more secure " +
                "and resistant to brute-force attacks.",
                cat,
                "Add 'PasswordAuthentication no' to %ProgramData%\\ssh\\sshd_config and restart sshd"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("SSH: Password Authentication Disabled",
                "SSH requires key-based authentication.", cat));
        }

        if (state.SshRootLoginEnabled)
        {
            result.Findings.Add(Finding.Critical("SSH: Root/Admin Login Allowed",
                "SSH allows direct root/administrator login. This is a high-risk configuration that " +
                "enables attackers to target the highest-privilege account directly.",
                cat,
                "Add 'PermitRootLogin no' to %ProgramData%\\ssh\\sshd_config and restart sshd"));
        }

        if (state.SshPort == DefaultPorts["SSH"])
        {
            result.Findings.Add(Finding.Info("SSH: Default Port (22)",
                "SSH is on the default port 22. Changing it reduces automated scanning noise.",
                cat,
                "Change Port in %ProgramData%\\ssh\\sshd_config"));
        }
    }

    private static void AnalyzeRemoteTools(RemoteAccessState state, AuditResult result, string cat)
    {
        if (state.RunningRemoteTools.Count == 0 && state.InstalledRemoteTools.Count == 0)
        {
            result.Findings.Add(Finding.Pass("No Third-Party Remote Tools Detected",
                "No known third-party remote access tools are running or installed.", cat));
            return;
        }

        foreach (var tool in state.RunningRemoteTools)
        {
            if (KnownRemoteTools.TryGetValue(tool, out var info))
            {
                var severity = info.Risk switch
                {
                    RemoteToolRisk.High => Severity.Critical,
                    RemoteToolRisk.Medium => Severity.Warning,
                    _ => Severity.Info
                };

                result.Findings.Add(new Finding
                {
                    Title = $"Remote Tool Running: {info.DisplayName}",
                    Description = $"{info.DisplayName} is actively running (process: {tool}). {info.Advisory}",
                    Severity = severity,
                    Category = cat,
                    Remediation = $"If {info.DisplayName} is not needed, stop and uninstall it. " +
                        "If needed, ensure strong authentication, disable unattended access when not in use, and restrict access to authorized users."
                });
            }
            else
            {
                result.Findings.Add(Finding.Info($"Unknown Remote Tool Running: {tool}",
                    $"Process '{tool}' is running and appears to be a remote access tool.", cat,
                    "Verify this is an authorized remote access tool."));
            }
        }

        foreach (var tool in state.InstalledRemoteTools.Where(t => !state.RunningRemoteTools.Contains(t)))
        {
            if (KnownRemoteTools.TryGetValue(tool, out var info))
            {
                result.Findings.Add(Finding.Info($"Remote Tool Installed (Not Running): {info.DisplayName}",
                    $"{info.DisplayName} is installed but not currently running.",
                    cat,
                    $"If {info.DisplayName} is no longer needed, uninstall it to reduce attack surface."));
            }
        }

        if (state.RunningRemoteTools.Count > 2)
        {
            result.Findings.Add(Finding.Warning("Multiple Remote Access Tools Running",
                $"{state.RunningRemoteTools.Count} different remote access tools are running simultaneously. " +
                "This significantly increases the attack surface and suggests poor remote access governance.",
                cat,
                "Standardize on a single remote access solution and remove the others."));
        }
    }

    private static void AnalyzeWinRm(RemoteAccessState state, AuditResult result, string cat)
    {
        if (!state.WinRmRunning)
        {
            result.Findings.Add(Finding.Pass("WinRM Not Running",
                "Windows Remote Management (WinRM) service is not running.", cat));
            return;
        }

        result.Findings.Add(Finding.Info("WinRM Running",
            "Windows Remote Management is running. Ensure it is needed for administration.",
            cat,
            "Disable if not needed: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"));

        if (state.WinRmAllowUnencrypted)
        {
            result.Findings.Add(Finding.Critical("WinRM: Unencrypted Traffic Allowed",
                "WinRM is configured to allow unencrypted traffic. Credentials and commands " +
                "can be intercepted on the network.",
                cat,
                "Disable: winrm set winrm/config/service @{AllowUnencrypted=\"false\"}"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("WinRM: Encrypted Traffic Required",
                "WinRM requires encrypted traffic.", cat));
        }

        if (state.WinRmBasicAuthEnabled)
        {
            result.Findings.Add(Finding.Warning("WinRM: Basic Authentication Enabled",
                "WinRM allows Basic authentication, which transmits credentials in base64 (easily decoded). " +
                "Use Kerberos or certificate-based authentication instead.",
                cat,
                "Disable: winrm set winrm/config/service/auth @{Basic=\"false\"}"));
        }

        if (state.WinRmHttpListenerEnabled && !state.WinRmHttpsListenerEnabled)
        {
            result.Findings.Add(Finding.Warning("WinRM: HTTP-Only Listener",
                "WinRM has only an HTTP listener configured (no HTTPS). " +
                "Configure an HTTPS listener with a valid certificate for encrypted management.",
                cat,
                "Configure HTTPS listener: winrm quickconfig -transport:https"));
        }
        else if (state.WinRmHttpsListenerEnabled)
        {
            result.Findings.Add(Finding.Pass("WinRM: HTTPS Listener Configured",
                "WinRM has an HTTPS listener configured.", cat));
        }
    }

    private static void AnalyzeRemoteRegistry(RemoteAccessState state, AuditResult result, string cat)
    {
        if (state.RemoteRegistryRunning)
        {
            result.Findings.Add(Finding.Warning("Remote Registry Service Running",
                "The Remote Registry service is running, allowing remote access to the Windows registry. " +
                "This can be exploited for reconnaissance and lateral movement.",
                cat,
                "Disable: Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled",
                "Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled"));
        }
        else if (state.RemoteRegistryStartType != "Disabled")
        {
            result.Findings.Add(Finding.Info("Remote Registry Not Disabled",
                $"Remote Registry service is not running but start type is '{state.RemoteRegistryStartType}'. " +
                "Set to Disabled to prevent accidental or malicious activation.",
                cat,
                "Set-Service RemoteRegistry -StartupType Disabled"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("Remote Registry Disabled",
                "Remote Registry service is disabled.", cat));
        }
    }

    private static void AnalyzeRemoteAssistance(RemoteAccessState state, AuditResult result, string cat)
    {
        if (state.RemoteAssistanceEnabled)
        {
            result.Findings.Add(Finding.Info("Remote Assistance Enabled",
                "Windows Remote Assistance is enabled. While lower risk than RDP, it allows " +
                "another user to view or control the desktop when invited.",
                cat,
                "Disable via System Properties > Remote > uncheck 'Allow Remote Assistance connections'",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' -Name fAllowToGetHelp -Value 0"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("Remote Assistance Disabled",
                "Windows Remote Assistance is disabled.", cat));
        }
    }

    private static void AnalyzeTelnet(RemoteAccessState state, AuditResult result, string cat)
    {
        if (state.TelnetServerRunning)
        {
            result.Findings.Add(Finding.Critical("Telnet Server Running",
                "The Telnet server is running. Telnet transmits everything in cleartext including credentials. " +
                "This is a critical security risk and should be disabled immediately.",
                cat,
                "Disable: Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled; " +
                "Optionally uninstall: dism /online /disable-feature /featurename:TelnetServer",
                "Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("Telnet Server Not Running",
                "Telnet server is not running.", cat));
        }
    }

    private static void AnalyzeOverallExposure(RemoteAccessState state, AuditResult result, string cat)
    {
        if (state.TotalRemoteVectors == 0)
        {
            result.Findings.Add(Finding.Pass("Minimal Remote Access Exposure",
                "No active remote access vectors detected. The system has minimal remote attack surface.", cat));
        }
        else if (state.TotalRemoteVectors >= 4)
        {
            result.Findings.Add(Finding.Critical("Excessive Remote Access Exposure",
                $"{state.TotalRemoteVectors} distinct remote access vectors are active. " +
                "This creates a very large attack surface. Review and disable unnecessary remote access methods.",
                cat,
                "Audit all remote access methods and consolidate to only what is needed."));
        }
        else if (state.TotalRemoteVectors >= 2)
        {
            result.Findings.Add(Finding.Warning("Multiple Remote Access Vectors Active",
                $"{state.TotalRemoteVectors} remote access vectors are active. " +
                "Each vector increases attack surface — ensure all are necessary and properly secured.",
                cat));
        }
        else
        {
            result.Findings.Add(Finding.Info("Single Remote Access Vector Active",
                "One remote access vector is active. Ensure it is properly secured.", cat));
        }
    }
}
