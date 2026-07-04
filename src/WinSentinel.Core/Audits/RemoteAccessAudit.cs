using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits remote access security configuration for risks including:
/// - RDP enabled with weak settings (no NLA, default port, weak encryption)
/// - RDP device redirection (client drive / clipboard / printer / COM-LPT ports / other supported PnP devices mapped into the session — exfiltration channels)
/// - RDP session shadowing allowed without user consent (silent view/control of a live session)
/// - RDP password prompt on connect disabled (saved/delegated credentials open a session with no challenge)
/// - SSH server exposure without key-only auth
/// - VNC/TeamViewer/AnyDesk/other remote tools running with weak config
/// - Remote Desktop Users group membership
/// - WinRM/PSRemoting exposure (unencrypted traffic, Basic auth, CredSSP delegation, channel binding, wildcard TrustedHosts)
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

        /// <summary>Whether RDP client DRIVE redirection is allowed (fDisableCdm != 1). When allowed, an
        /// RDP session can mount the connecting client's local drives into the session — a data
        /// exfiltration / ingress channel. Default false (= disabled/secure) so an unconfigured or
        /// non-RDP host is not flagged.</summary>
        public bool RdpDriveRedirectionAllowed { get; set; }

        /// <summary>Whether RDP CLIPBOARD redirection is allowed (fDisableClip != 1). A lower-severity
        /// data-leak path between the session and the connecting client. Default false (= disabled/secure).</summary>
        public bool RdpClipboardRedirectionAllowed { get; set; }

        /// <summary>Whether RDP PRINTER redirection is allowed (fDisableCpm != 1). The connecting client's
        /// printers are mapped into the session; print jobs can carry data off the host and the redirected
        /// spooler has historically been an attack surface. Default false (= disabled/secure).</summary>
        public bool RdpPrinterRedirectionAllowed { get; set; }

        /// <summary>Whether RDP COM/LPT PORT redirection is allowed (fDisableLPT != 1). Legacy serial/parallel
        /// ports on the client are mapped into the session — a low-level data channel rarely needed on modern
        /// hosts. Default false (= disabled/secure).</summary>
        public bool RdpPortRedirectionAllowed { get; set; }

        /// <summary>Whether RDP supported PLUG-AND-PLAY device redirection is allowed (fDisablePNPRedir != 1).
        /// This governs redirection of the "other supported RemoteFX/Plug and Play devices" class — most notably
        /// portable media players and phones/cameras exposed over MTP/PTP, plus point-of-service devices — which
        /// are mounted into the session and can carry data on or off the host, separate from the mass-storage
        /// drive channel (fDisableCdm). Rarely required on a hardened remote host and recommended to be disabled
        /// by CIS. Default false (= disabled/secure) so an unconfigured or non-RDP host is not flagged.</summary>
        public bool RdpPnpRedirectionAllowed { get; set; }

        /// <summary>RDP session-shadowing policy (the <c>Shadow</c> value under the Terminal Services policy hive),
        /// which controls whether an administrator may remotely VIEW or CONTROL another user's live RDP session:
        /// 0 = no remote control (secure), 1 = full control WITH the user's consent, 2 = full control WITHOUT
        /// consent, 3 = view WITH consent, 4 = view WITHOUT consent. The no-consent modes (2 and 4) let an admin
        /// silently observe or take over a session — a surveillance / session-hijack vector (MITRE ATT&amp;CK
        /// T1563.002). Default 0 (= secure) so an unconfigured or non-RDP host is not flagged.</summary>
        public int RdpShadowMode { get; set; }

        /// <summary>Whether the RDP <c>Shadow</c> policy is explicitly configured (the value is present in the
        /// policy hive). When false the OS default applies and no shadow-policy finding beyond the secure
        /// baseline is raised.</summary>
        public bool RdpShadowConfigured { get; set; }

        /// <summary>The RDP "Always prompt for password upon connection" policy (<c>fPromptForPassword</c> under
        /// the Terminal Services policy hive). When 1, the RD Session Host always challenges for a password at
        /// connect time even if the client supplied saved credentials. When 0, credentials passed by the client
        /// (e.g. a saved RDP password or a delegated/cached credential) are accepted without a prompt, so a stolen
        /// or reused credential can open a session silently and unattended — a lateral-movement / credential-reuse
        /// risk. Default false (secure) so an unconfigured or non-RDP host is not flagged.</summary>
        public bool RdpAlwaysPromptForPassword { get; set; }

        /// <summary>Whether the RDP <c>fPromptForPassword</c> policy is explicitly configured (present in the
        /// policy hive). When false the OS default applies and no beyond-baseline finding is raised.</summary>
        public bool RdpPromptForPasswordConfigured { get; set; }

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

        /// <summary>Whether any WinRM listener accepts connections from any source IP (IPv4Filter/IPv6Filter = "*").</summary>
        public bool WinRmListenerUnrestricted { get; set; }

        /// <summary>Raw WinRM listener IPv4Filter value when present (e.g. "*" = any source address).</summary>
        public string WinRmListenerIpv4Filter { get; set; } = string.Empty;

        /// <summary>Whether WinRM allows basic authentication.</summary>
        public bool WinRmBasicAuthEnabled { get; set; }

        /// <summary>Whether the WinRM service accepts CredSSP authentication (delegates caller credentials to this host).</summary>
        public bool WinRmServiceCredSspEnabled { get; set; }

        /// <summary>The WinRM service authentication Channel-Binding-Token / Extended-Protection-for-Authentication
        /// hardening level (<c>CbtHardeningLevel</c> under winrm/config/service/auth): <c>None</c>, <c>Relaxed</c>
        /// (the default), or <c>Strict</c>. Channel binding ties the authenticated session to the outer TLS
        /// channel; with <c>None</c> the service performs no channel-binding validation at all, so an
        /// authenticated WinRM-over-HTTPS session can be relayed/man-in-the-middled (the credential is not bound
        /// to the TLS endpoint) — an authentication-relay hardening gap. Empty string = not read/unknown; the
        /// analyzer only flags the explicit <c>None</c> value.</summary>
        public string WinRmCbtHardeningLevel { get; set; } = string.Empty;

        /// <summary>Whether the WinRM client is allowed to use CredSSP when connecting out (delegates our credentials to the remote host).</summary>
        public bool WinRmClientCredSspEnabled { get; set; }

        /// <summary>Raw WinRM client TrustedHosts value (empty = none, "*" = trust any host).</summary>
        public string WinRmTrustedHosts { get; set; } = string.Empty;

        /// <summary>Whether Remote Registry service is running.</summary>
        public bool RemoteRegistryRunning { get; set; }

        /// <summary>Remote Registry service start type (Auto, Manual, Disabled).</summary>
        public string RemoteRegistryStartType { get; set; } = "Disabled";

        /// <summary>Whether Remote Assistance is enabled.</summary>
        public bool RemoteAssistanceEnabled { get; set; }

        /// <summary>Whether UNSOLICITED Remote Assistance is enabled (fAllowUnsolicited) — a helper can
        /// offer/initiate a session without a per-session invitation from the user, driven by the
        /// "Offer Remote Assistance" policy. Materially higher risk than solicited "Ask for Help".</summary>
        public bool RemoteAssistanceUnsolicitedEnabled { get; set; }

        /// <summary>Whether unsolicited Remote Assistance helpers are granted FULL CONTROL
        /// (fAllowUnsolicitedFullControl) rather than view-only.</summary>
        public bool RemoteAssistanceUnsolicitedFullControl { get; set; }

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

        // RDP device redirection policy (drive + clipboard + printer + COM/LPT ports). These live under
        // the Terminal Services policy hive as fDisableCdm / fDisableClip / fDisableCpm / fDisableLPT where a
        // value of 1 DISABLES the redirection (i.e. secure). We record whether each is ALLOWED; the analyzer
        // only flags them when RDP is actually enabled, so an unconfigured or non-RDP host stays clean.
        // JSON-guarded + non-fatal.
        try
        {
            var redirOutput = await ShellHelper.RunPowerShellAsync(
                "$r = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -ErrorAction SilentlyContinue; " +
                "[PSCustomObject]@{ " +
                "  DisableCdm=$r.fDisableCdm; " +
                "  DisableClip=$r.fDisableClip; " +
                "  DisableCpm=$r.fDisableCpm; " +
                "  DisableLPT=$r.fDisableLPT; " +
                "  DisablePNPRedir=$r.fDisablePNPRedir; " +
                "  Shadow=$r.Shadow; " +
                "  PromptForPassword=$r.fPromptForPassword " +
                "} | ConvertTo-Json", ct);
            if (!string.IsNullOrWhiteSpace(redirOutput) && redirOutput.TrimStart().StartsWith("{"))
            {
                var json = System.Text.Json.JsonDocument.Parse(redirOutput);
                var root = json.RootElement;
                // Redirection is ALLOWED unless the policy explicitly sets the disable flag to 1.
                state.RdpDriveRedirectionAllowed =
                    !(root.TryGetProperty("DisableCdm", out var cdm) && cdm.ValueKind == System.Text.Json.JsonValueKind.Number && cdm.GetInt32() == 1);
                state.RdpClipboardRedirectionAllowed =
                    !(root.TryGetProperty("DisableClip", out var clip) && clip.ValueKind == System.Text.Json.JsonValueKind.Number && clip.GetInt32() == 1);
                state.RdpPrinterRedirectionAllowed =
                    !(root.TryGetProperty("DisableCpm", out var cpm) && cpm.ValueKind == System.Text.Json.JsonValueKind.Number && cpm.GetInt32() == 1);
                state.RdpPortRedirectionAllowed =
                    !(root.TryGetProperty("DisableLPT", out var lpt) && lpt.ValueKind == System.Text.Json.JsonValueKind.Number && lpt.GetInt32() == 1);
                state.RdpPnpRedirectionAllowed =
                    !(root.TryGetProperty("DisablePNPRedir", out var pnp) && pnp.ValueKind == System.Text.Json.JsonValueKind.Number && pnp.GetInt32() == 1);
                // Session shadowing: capture the raw Shadow mode when the policy is present. Absent => OS
                // default; we only raise a beyond-baseline finding when it is explicitly a no-consent mode.
                if (root.TryGetProperty("Shadow", out var shadow) && shadow.ValueKind == System.Text.Json.JsonValueKind.Number)
                {
                    state.RdpShadowConfigured = true;
                    state.RdpShadowMode = shadow.GetInt32();
                }
                // Always-prompt-for-password: capture only when the policy is explicitly present. Absent =>
                // OS default; the analyzer flags the value 0 (saved creds bypass the prompt) and only when RDP is on.
                if (root.TryGetProperty("PromptForPassword", out var pfp) && pfp.ValueKind == System.Text.Json.JsonValueKind.Number)
                {
                    state.RdpPromptForPasswordConfigured = true;
                    state.RdpAlwaysPromptForPassword = pfp.GetInt32() == 1;
                }
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
                    state.WinRmServiceCredSspEnabled = winrmConfig.Contains("CredSSP = true", StringComparison.OrdinalIgnoreCase);

                    // CbtHardeningLevel (channel binding / EPA) is reported inline in the service auth block,
                    // e.g. "CbtHardeningLevel = Relaxed". Capture the raw token; the analyzer only warns on None.
                    var cbt = System.Text.RegularExpressions.Regex.Match(
                        winrmConfig, @"CbtHardeningLevel\s*=\s*(?<val>\S+)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (cbt.Success)
                        state.WinRmCbtHardeningLevel = cbt.Groups["val"].Value.Trim();
                }

                // WinRM client-side auth + TrustedHosts (governs OUTBOUND connections from this host).
                var winrmClient = await ShellHelper.RunPowerShellAsync(
                    "winrm get winrm/config/client 2>$null", ct);
                if (!string.IsNullOrWhiteSpace(winrmClient))
                {
                    state.WinRmClientCredSspEnabled = winrmClient.Contains("CredSSP = true", StringComparison.OrdinalIgnoreCase);

                    // TrustedHosts appears inline in the client config, e.g. "TrustedHosts = *".
                    var thMatch = System.Text.RegularExpressions.Regex.Match(
                        winrmClient, @"TrustedHosts\s*=\s*(?<val>.*)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (thMatch.Success)
                        state.WinRmTrustedHosts = thMatch.Groups["val"].Value.Trim();
                }

                var listeners = await ShellHelper.RunPowerShellAsync(
                    "winrm enumerate winrm/config/listener 2>$null", ct);
                if (!string.IsNullOrWhiteSpace(listeners))
                {
                    state.WinRmHttpListenerEnabled = listeners.Contains("Transport = HTTP", StringComparison.OrdinalIgnoreCase);
                    state.WinRmHttpsListenerEnabled = listeners.Contains("Transport = HTTPS", StringComparison.OrdinalIgnoreCase);

                    // A listener's IPv4Filter/IPv6Filter constrains which SOURCE addresses may connect.
                    // "*" (the default) accepts from anywhere; a scoped value (e.g. "10.0.0.0-10.0.0.255")
                    // limits exposure to a management subnet. Capture the IPv4Filter for the message and
                    // flag when any listener is wide open.
                    var v4 = System.Text.RegularExpressions.Regex.Match(
                        listeners, @"IPv4Filter\s*=\s*(?<val>\S+)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (v4.Success)
                        state.WinRmListenerIpv4Filter = v4.Groups["val"].Value.Trim();
                    var v6 = System.Text.RegularExpressions.Regex.Match(
                        listeners, @"IPv6Filter\s*=\s*(?<val>\S+)",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    state.WinRmListenerUnrestricted =
                        state.WinRmListenerIpv4Filter == "*" ||
                        (v6.Success && v6.Groups["val"].Value.Trim() == "*");
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

        // Unsolicited Remote Assistance ("Offer Remote Assistance" policy). These live under the
        // Policies hive and let a listed helper initiate a session with no user invitation; full
        // control means the helper can drive the desktop, not just watch.
        try
        {
            var unsolicitedOutput = await ShellHelper.RunPowerShellAsync(
                "$ra = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -ErrorAction SilentlyContinue; " +
                "[PSCustomObject]@{ " +
                "  Unsolicited=$ra.fAllowUnsolicited; " +
                "  FullControl=$ra.fAllowUnsolicitedFullControl " +
                "} | ConvertTo-Json", ct);
            if (!string.IsNullOrWhiteSpace(unsolicitedOutput) && unsolicitedOutput.TrimStart().StartsWith("{"))
            {
                var json = System.Text.Json.JsonDocument.Parse(unsolicitedOutput);
                var root = json.RootElement;
                state.RemoteAssistanceUnsolicitedEnabled =
                    root.TryGetProperty("Unsolicited", out var uns) && uns.ValueKind == System.Text.Json.JsonValueKind.Number && uns.GetInt32() == 1;
                state.RemoteAssistanceUnsolicitedFullControl =
                    root.TryGetProperty("FullControl", out var fc) && fc.ValueKind == System.Text.Json.JsonValueKind.Number && fc.GetInt32() == 1;
            }
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

        // Drive redirection: allowing the connecting client's local drives to be mounted into the RDP
        // session is a bidirectional data channel — attacker-to-host ingress (drop tooling) and
        // host-to-attacker exfiltration. CIS Windows L1 recommends disabling it (fDisableCdm=1).
        if (state.RdpDriveRedirectionAllowed)
        {
            result.Findings.Add(Finding.Warning("RDP: Drive Redirection Allowed",
                "RDP client drive redirection is allowed, so a connecting client's local drives can be " +
                "mounted into the remote session. This is a data exfiltration and ingress channel — an " +
                "attacker with an RDP session can copy files off the host or stage tooling onto it.",
                cat,
                "Disable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                "Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection > " +
                "'Do not allow drive redirection' = Enabled.",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fDisableCdm -Value 1"));
        }
        else
        {
            result.Findings.Add(Finding.Pass("RDP: Drive Redirection Disabled",
                "RDP client drive redirection is disabled — local drives cannot be mounted into the session.", cat));
        }

        // Clipboard redirection: lower severity than drives, but still a data-leak path (copy/paste
        // of credentials or sensitive text between the session and the connecting client).
        if (state.RdpClipboardRedirectionAllowed)
        {
            result.Findings.Add(Finding.Info("RDP: Clipboard Redirection Allowed",
                "RDP clipboard redirection is allowed, permitting copy/paste of text and files between the " +
                "remote session and the connecting client. In high-security or regulated environments this " +
                "is often disabled to reduce data leakage.",
                cat,
                "Disable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                "Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection > " +
                "'Do not allow Clipboard redirection' = Enabled.",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fDisableClip -Value 1"));
        }

        // Printer redirection: the connecting client's printers are mapped into the session. Print jobs
        // are a data-egress path (anything printable leaves the host) and the redirected print spooler has
        // a history of local-privilege-escalation bugs (PrintNightmare family). CIS L1 disables it (fDisableCpm=1).
        if (state.RdpPrinterRedirectionAllowed)
        {
            result.Findings.Add(Finding.Info("RDP: Printer Redirection Allowed",
                "RDP client printer redirection is allowed, mapping the connecting client's printers into the " +
                "remote session. Redirected printing is a data-egress path and the redirected spooler has been " +
                "an attack surface for privilege escalation. Disable it where remote printing is not required.",
                cat,
                "Disable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                "Remote Desktop Services > Remote Desktop Session Host > Printer Redirection > " +
                "'Do not allow client printer redirection' = Enabled.",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fDisableCpm -Value 1"));
        }

        // COM/LPT port redirection: legacy serial/parallel ports on the client are mapped into the session.
        // Rarely needed on modern hosts and, like drive redirection, a low-level data channel between the
        // client and the session. CIS L1 disables it (fDisableLPT=1).
        if (state.RdpPortRedirectionAllowed)
        {
            result.Findings.Add(Finding.Info("RDP: COM/LPT Port Redirection Allowed",
                "RDP client COM/LPT port redirection is allowed, mapping the connecting client's serial and " +
                "parallel ports into the remote session. This is a legacy data channel that is almost never " +
                "needed on modern systems and is recommended to be disabled to shrink the redirection surface.",
                cat,
                "Disable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                "Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection > " +
                "'Do not allow LPT port redirection' = Enabled (and 'Do not allow COM port redirection').",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fDisableLPT -Value 1"));
        }

        // Plug-and-Play device redirection (the fDisablePNPRedir policy) governs the "other supported
        // Plug and Play devices" class — portable media players, phones/cameras over MTP/PTP, and point-of-
        // service devices — being mounted into the session. This is a data channel distinct from the mass-
        // storage drive redirection (fDisableCdm): a phone or media player redirected into the session can
        // still shuttle files on or off the host even when drive redirection is disabled. Rarely needed on a
        // hardened remote host; CIS L1 disables it (fDisablePNPRedir=1).
        if (state.RdpPnpRedirectionAllowed)
        {
            result.Findings.Add(Finding.Info("RDP: Plug-and-Play Device Redirection Allowed",
                "RDP supported Plug-and-Play device redirection is allowed, so a connecting client's portable " +
                "devices — media players, phones and cameras over MTP/PTP, and point-of-service hardware — can be " +
                "mounted into the remote session. This is a data on/off-ramp separate from mass-storage drive " +
                "redirection, and is recommended to be disabled where such devices are not required in-session.",
                cat,
                "Disable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                "Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection > " +
                "'Do not allow supported Plug and Play device redirection' = Enabled.",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fDisablePNPRedir -Value 1"));
        }

        // Session shadowing (the Shadow policy) lets an administrator remotely VIEW or take CONTROL of a
        // user's live RDP session. The two "without the user's consent" modes (2 = full control, 4 = view)
        // allow a silent takeover / over-the-shoulder surveillance with no prompt to the session owner — an
        // insider-threat and session-hijack vector (MITRE ATT&CK T1563.002). Modes that require consent
        // (1, 3) or disable shadowing entirely (0) are acceptable; only flag the no-consent modes, and only
        // when the policy is explicitly configured and RDP is actually enabled.
        if (state.RdpShadowConfigured && (state.RdpShadowMode == 2 || state.RdpShadowMode == 4))
        {
            var access = state.RdpShadowMode == 2 ? "take full control of" : "view";
            result.Findings.Add(Finding.Warning("RDP: Session Shadowing Without User Consent",
                $"The RDP session-shadowing policy is set to mode {state.RdpShadowMode}, which lets an administrator " +
                $"{access} a user's live session WITHOUT the user's consent and with no on-screen prompt. This enables " +
                "silent over-the-shoulder surveillance or a hands-on-keyboard session takeover — an insider-threat and " +
                "session-hijack risk. Require consent (mode 1 or 3) or disable shadowing (mode 0).",
                cat,
                "Set via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                "Remote Desktop Services > Remote Desktop Session Host > Connections > " +
                "'Set rules for remote control of Remote Desktop Services user sessions' to a consent-required " +
                "option, or disable remote control.",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name Shadow -Value 0"));
        }
        else if (state.RdpShadowConfigured)
        {
            var mode = state.RdpShadowMode switch
            {
                0 => "disabled (no remote control)",
                1 => "full control with the user's consent",
                3 => "view-only with the user's consent",
                _ => $"mode {state.RdpShadowMode}"
            };
            result.Findings.Add(Finding.Pass("RDP: Session Shadowing Requires Consent",
                $"RDP session shadowing is {mode} — an administrator cannot silently observe or control a user's " +
                "session without their permission.", cat));
        }

        // Always prompt for password on connect (the fPromptForPassword policy). When set to 0, the RD Session
        // Host accepts credentials handed over by the client — a saved RDP password, or a delegated/cached
        // credential — and opens the session with no password challenge. That lets a stolen or reused credential
        // (or an unattended machine with a saved connection) log in silently, which aids lateral movement and
        // defeats "something you know at connect time". Value 1 forces a prompt every time (secure). Only flag
        // when the policy is explicitly configured; this whole method already short-circuits unless RDP is enabled.
        if (state.RdpPromptForPasswordConfigured && !state.RdpAlwaysPromptForPassword)
        {
            result.Findings.Add(Finding.Warning("RDP: Password Prompt On Connect Disabled",
                "The RDP 'Always prompt for password upon connection' policy is disabled (fPromptForPassword = 0), " +
                "so the Remote Desktop host accepts credentials supplied by the client (a saved RDP password or a " +
                "delegated/cached credential) and opens the session with no password challenge. A stolen or reused " +
                "credential — or an unattended machine holding a saved connection — can then log in silently, aiding " +
                "lateral movement. Require a password prompt on every connection.",
                cat,
                "Set via Group Policy: Computer Configuration > Administrative Templates > Windows Components > " +
                "Remote Desktop Services > Remote Desktop Session Host > Security > 'Always prompt for password " +
                "upon connection' = Enabled.",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fPromptForPassword -Value 1"));
        }
        else if (state.RdpPromptForPasswordConfigured)
        {
            result.Findings.Add(Finding.Pass("RDP: Password Prompt On Connect Required",
                "RDP always prompts for a password on connection (fPromptForPassword = 1), so a saved or delegated " +
                "credential cannot silently open a remote session.", cat));
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

        // CredSSP: the WinRM SERVICE accepting CredSSP means callers can delegate their credentials
        // TO this host in a reusable form (they end up cached in LSASS here) — a lateral-movement /
        // credential-theft enabler (MITRE ATT&CK T1021.006). Distinct from the CredSSP encryption-
        // oracle patch level tracked by the Group Policy module.
        if (state.WinRmServiceCredSspEnabled)
        {
            result.Findings.Add(Finding.Warning("WinRM: CredSSP Authentication Accepted (Service)",
                "The WinRM service accepts CredSSP authentication. CredSSP delegates the connecting user's " +
                "credentials to this machine in a reusable form (they are exposed in memory here), which " +
                "an attacker who compromises this host can harvest for lateral movement. Prefer Kerberos.",
                cat,
                "Disable unless explicitly required (e.g. certain double-hop scenarios): " +
                "winrm set winrm/config/service/auth @{CredSSP=\"false\"}"));
        }

        // CbtHardeningLevel governs channel binding (Extended Protection for Authentication) for the WinRM
        // service. When set to "None" the service performs NO channel-binding check, so an authenticated
        // WinRM-over-HTTPS session is not bound to its TLS channel and can be relayed / man-in-the-middled
        // (a credential-relay path onto this host). "Relaxed" (the default) validates a binding when the
        // client supplies one, and "Strict" always requires it. Only flag the explicit "None" value; treat
        // Strict as a hardened pass and leave the default/unknown unflagged to avoid noise.
        var cbt = state.WinRmCbtHardeningLevel?.Trim() ?? string.Empty;
        if (string.Equals(cbt, "None", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning("WinRM: Channel Binding Disabled (CbtHardeningLevel = None)",
                "The WinRM service channel-binding hardening level is set to None, so the service does not bind " +
                "an authenticated session to its outer TLS channel (no Extended Protection for Authentication). " +
                "An authenticated WinRM-over-HTTPS session can then be relayed or man-in-the-middled onto this " +
                "host, because the credential is not tied to the TLS endpoint it was presented over. Require " +
                "channel binding.",
                cat,
                "Set the service to require channel binding: " +
                "winrm set winrm/config/service/auth @{CbtHardeningLevel=\"Strict\"} " +
                "(or 'Relaxed' to validate a binding when present)."));
        }
        else if (string.Equals(cbt, "Strict", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass("WinRM: Channel Binding Enforced",
                "The WinRM service requires channel binding (CbtHardeningLevel = Strict), binding authenticated " +
                "sessions to their TLS channel and blocking authentication-relay onto this host.", cat));
        }

        // CredSSP on the CLIENT means WE delegate OUR credentials to whatever host we connect to,
        // where they are cached — if that remote host is compromised our credentials are stolen.
        if (state.WinRmClientCredSspEnabled)
        {
            result.Findings.Add(Finding.Warning("WinRM: CredSSP Authentication Enabled (Client)",
                "The WinRM client is configured to use CredSSP for outbound connections. This delegates " +
                "your credentials to the remote host, where they are cached — if that host is compromised, " +
                "your credentials can be stolen and reused. Only enable CredSSP for specific, trusted hosts.",
                cat,
                "Disable: winrm set winrm/config/client/auth @{CredSSP=\"false\"} " +
                "(and clear delegation policy under Computer Configuration > Administrative Templates > " +
                "System > Credentials Delegation > 'Allow delegating fresh credentials')"));
        }

        // TrustedHosts governs which remote hosts this machine will connect to over WinRM when
        // Kerberos is unavailable (e.g. workgroup/IP). A wildcard means we trust ANY host, which
        // defeats server authentication and enables man-in-the-middle / credential relay.
        var trustedHosts = state.WinRmTrustedHosts?.Trim() ?? string.Empty;
        if (trustedHosts == "*")
        {
            result.Findings.Add(Finding.Warning("WinRM: TrustedHosts Set to Wildcard (*)",
                "The WinRM client TrustedHosts list is set to '*', meaning this machine will connect to " +
                "ANY remote host over WinRM without verifying its identity. This defeats server " +
                "authentication and exposes outbound sessions to man-in-the-middle and credential relay.",
                cat,
                "Restrict to an explicit, minimal list of hostnames/IPs: " +
                "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value 'host1,host2' -Force " +
                "(or clear it entirely with -Value '' if not needed)."));
        }
        else if (!string.IsNullOrEmpty(trustedHosts))
        {
            result.Findings.Add(Finding.Info("WinRM: TrustedHosts Configured",
                $"WinRM client TrustedHosts is scoped to specific host(s): {trustedHosts}. " +
                "Confirm each entry is still required.", cat));
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

        // A WinRM listener with IPv4Filter/IPv6Filter = "*" accepts management connections from ANY
        // source address. Combined with a running listener this is a broad remote attack surface —
        // credential relay / brute-force against 5985/5986 from anywhere the host is reachable.
        // Scoping the filter to a management subnet is defence-in-depth on top of the host firewall.
        if ((state.WinRmHttpListenerEnabled || state.WinRmHttpsListenerEnabled) && state.WinRmListenerUnrestricted)
        {
            result.Findings.Add(Finding.Warning("WinRM: Listener Accepts Connections From Any IP",
                "A WinRM listener has an unrestricted address filter (IPv4Filter/IPv6Filter = '*'), so it " +
                "accepts remote-management connections from any source address the host can be reached from. " +
                "Scope the listener to your management subnet(s) to shrink the remote attack surface (this is " +
                "in addition to, not a replacement for, a firewall rule on ports 5985/5986).",
                cat,
                "Restrict the listener source range, e.g.: " +
                "winrm set winrm/config/listener?Address=*+Transport=HTTP @{IPv4Filter=\"10.0.0.0-10.0.0.255\"} " +
                "(use your real management range; set IPv6Filter similarly or to an empty string to disable IPv6)."));
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
                // Single sanitizer-safe command (the semicolon-chained form was blocked by
                // InputSanitizer.CheckDangerousCommand, so the Fix button never ran). Disabling
                // startup is the durable fix; the remediation text covers stopping it now.
                "Set-Service RemoteRegistry -StartupType Disabled"));
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

        // Unsolicited Remote Assistance is the dangerous variant: a listed helper can initiate a
        // session with NO invitation from the user. Combined with full control it is a ready-made
        // lateral-movement / hands-on-keyboard channel (MITRE ATT&CK T1219 remote access software,
        // and abuse of T1021 remote services), so it warrants a Warning rather than Info.
        if (state.RemoteAssistanceUnsolicitedEnabled)
        {
            var control = state.RemoteAssistanceUnsolicitedFullControl ? "full control of" : "view-only access to";
            result.Findings.Add(Finding.Warning("Remote Assistance: Unsolicited Offers Allowed",
                $"Unsolicited Remote Assistance is enabled (fAllowUnsolicited=1), granting listed helpers {control} " +
                "this machine without the user issuing an invitation. This 'Offer Remote Assistance' policy is a common " +
                "lateral-movement and hands-on-keyboard vector — disable it unless a helpdesk tool explicitly requires it.",
                cat,
                "Disable via Group Policy: Computer Configuration > Administrative Templates > System > " +
                "Remote Assistance > 'Offer Remote Assistance' = Disabled, then remove any configured helper list.",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fAllowUnsolicited -Value 0"));
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
                // Single sanitizer-safe command (the semicolon-chained form was blocked by
                // InputSanitizer.CheckDangerousCommand, so the Fix button never ran). Disabling
                // startup is the durable fix; the remediation text covers stopping it now.
                "Set-Service TlntSvr -StartupType Disabled"));
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
