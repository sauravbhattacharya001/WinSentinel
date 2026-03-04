using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits WiFi security configuration for risks including:
/// - Saved profiles using weak/no encryption (Open, WEP, WPA-TKIP)
/// - Auto-connect to insecure or public networks
/// - Cleartext password exposure in saved profiles
/// - Hosted network / WiFi Direct exposure
/// - MAC address randomization not enabled
/// - Hidden network probing (privacy leak)
/// - Excessive saved profiles (attack surface)
/// - WiFi Sense / hotspot sharing enabled
/// </summary>
public class WifiAudit : IAuditModule
{
    public string Name => "WiFi Security Audit";
    public string Category => "WiFi";
    public string Description =>
        "Checks saved WiFi profiles for weak encryption, auto-connect risks, " +
        "password exposure, MAC randomization, and network privacy settings.";

    /// <summary>
    /// Encryption types considered insecure.
    /// </summary>
    public static readonly Dictionary<string, string> InsecureAuthTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Open"] = "No encryption — all traffic is visible to anyone nearby",
        ["WEP"] = "WEP is cryptographically broken and can be cracked in minutes",
        ["Shared"] = "Shared key authentication uses WEP and is insecure",
    };

    /// <summary>
    /// Encryption types considered weak but not critically broken.
    /// </summary>
    public static readonly Dictionary<string, string> WeakAuthTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["WPAPSK"] = "WPA1-PSK uses TKIP which has known vulnerabilities; use WPA2/WPA3",
        ["WPA"] = "WPA1-Enterprise uses TKIP which has known vulnerabilities",
    };

    /// <summary>
    /// Common public/hotel/airline network names that warrant extra caution.
    /// </summary>
    public static readonly HashSet<string> KnownPublicNetworks = new(StringComparer.OrdinalIgnoreCase)
    {
        "xfinitywifi", "attwifi", "att wi-fi", "google starbucks",
        "starbucks wifi", "mcdonalds free wifi", "boingo hotspot",
        "free wifi", "free public wifi", "guest", "hotel wifi",
        "airport wifi", "airport free wifi", "linksys", "netgear",
        "default", "dlink", "setup", "home", "open",
    };

    /// <summary>
    /// Threshold for "too many saved profiles" warning.
    /// </summary>
    public const int ExcessiveProfileThreshold = 30;

    /// <summary>
    /// Data transfer object for WiFi environment state.
    /// All checks operate on this record for testability.
    /// </summary>
    public sealed class WifiState
    {
        /// <summary>Whether a WiFi adapter is present.</summary>
        public bool AdapterPresent { get; set; }

        /// <summary>Whether WiFi is currently enabled.</summary>
        public bool WifiEnabled { get; set; }

        /// <summary>Currently connected network name (null if disconnected).</summary>
        public string? ConnectedNetwork { get; set; }

        /// <summary>Saved WiFi profiles.</summary>
        public List<WifiProfile> Profiles { get; set; } = new();

        /// <summary>Whether hosted network (virtual AP) is allowed.</summary>
        public bool? HostedNetworkAllowed { get; set; }

        /// <summary>Whether MAC address randomization is enabled globally.</summary>
        public bool? MacRandomizationEnabled { get; set; }

        /// <summary>Whether WiFi Sense (auto-connect to suggested hotspots) is enabled.</summary>
        public bool? WifiSenseEnabled { get; set; }

        /// <summary>Whether hotspot sharing (sharing saved passwords) is enabled.</summary>
        public bool? HotspotSharingEnabled { get; set; }

        /// <summary>WiFi adapter driver version.</summary>
        public string DriverVersion { get; set; } = string.Empty;

        /// <summary>Days since WiFi driver was last updated.</summary>
        public int? DriverAgeDays { get; set; }
    }

    public sealed class WifiProfile
    {
        /// <summary>Network SSID name.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Authentication type (Open, WEP, WPA2PSK, WPA3SAE, etc.).</summary>
        public string Authentication { get; set; } = string.Empty;

        /// <summary>Cipher type (None, WEP, TKIP, CCMP, GCMP256, etc.).</summary>
        public string Cipher { get; set; } = string.Empty;

        /// <summary>Whether auto-connect is enabled for this profile.</summary>
        public bool AutoConnect { get; set; }

        /// <summary>Whether this is a hidden (non-broadcast) network.</summary>
        public bool IsHidden { get; set; }

        /// <summary>Whether the password/key is stored in cleartext in the profile.</summary>
        public bool PasswordInCleartext { get; set; }

        /// <summary>Whether MAC randomization is enabled for this specific profile.</summary>
        public bool? MacRandomization { get; set; }

        /// <summary>Connection mode (auto vs manual).</summary>
        public string ConnectionMode { get; set; } = string.Empty;
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
    /// Gather live WiFi state from the system. Separated for testability.
    /// </summary>
    internal async Task<WifiState> GatherStateAsync(CancellationToken ct)
    {
        var state = new WifiState();

        // Check adapter presence and status
        var adapterOutput = await ShellHelper.RunPowerShellAsync(
            "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.InterfaceDescription -match 'Wi-Fi|Wireless|802\\.11|WLAN' } | " +
            "ForEach-Object { '{0}|{1}|{2}' -f $_.Status, $_.DriverVersion, $_.DriverDate }", ct);

        var adapterLines = adapterOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (adapterLines.Length > 0 && adapterLines[0].Contains('|'))
        {
            var parts = adapterLines[0].Split('|');
            state.AdapterPresent = true;
            state.WifiEnabled = parts[0].Equals("Up", StringComparison.OrdinalIgnoreCase);
            state.DriverVersion = parts.Length > 1 ? parts[1] : "";

            if (parts.Length > 2 && DateTimeOffset.TryParse(parts[2], out var driverDate))
            {
                state.DriverAgeDays = (int)(DateTimeOffset.UtcNow - driverDate).TotalDays;
            }
        }

        // Get connected network
        var connectedOutput = await ShellHelper.RunPowerShellAsync(
            "netsh wlan show interfaces | Select-String 'SSID' | Select-Object -First 1 | " +
            "ForEach-Object { ($_ -split ':\\s*', 2)[1] }", ct);
        var connected = connectedOutput.Trim();
        if (!string.IsNullOrWhiteSpace(connected) && connected != "")
        {
            state.ConnectedNetwork = connected;
        }

        // Get all saved profiles
        var profilesOutput = await ShellHelper.RunPowerShellAsync(
            "netsh wlan show profiles | Select-String 'All User Profile' | " +
            "ForEach-Object { ($_ -split ':\\s*', 2)[1].Trim() }", ct);

        var profileNames = profilesOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(n => !string.IsNullOrWhiteSpace(n)).ToList();

        foreach (var profileName in profileNames)
        {
            var profile = await GetProfileDetailsAsync(profileName, ct);
            if (profile != null)
            {
                state.Profiles.Add(profile);
            }
        }

        // Check hosted network
        var hostedOutput = await ShellHelper.RunPowerShellAsync(
            "netsh wlan show hostednetwork | Select-String 'Status' | " +
            "ForEach-Object { ($_ -split ':\\s*', 2)[1].Trim() }", ct);
        var hostedStatus = hostedOutput.Trim().ToLowerInvariant();
        state.HostedNetworkAllowed = hostedStatus.Contains("started") || hostedStatus.Contains("allowed");

        // Check MAC randomization (Windows 10+)
        var macRandOutput = await ShellHelper.RunPowerShellAsync(
            @"try {
                $val = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces\*' -Name 'MacRandomization' -ErrorAction SilentlyContinue
                if ($val -ne $null) { $val } else { 'unknown' }
            } catch { 'unknown' }", ct);
        var macRand = macRandOutput.Trim();
        if (macRand != "unknown")
        {
            state.MacRandomizationEnabled = macRand == "1" || macRand == "2";
        }

        // Check WiFi Sense (Windows 10 — registry)
        var wifiSenseOutput = await ShellHelper.RunPowerShellAsync(
            @"try {
                $val = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -ErrorAction SilentlyContinue
                if ($val -ne $null) { $val } else { 'unknown' }
            } catch { 'unknown' }", ct);
        var wifiSense = wifiSenseOutput.Trim();
        if (wifiSense != "unknown")
        {
            state.WifiSenseEnabled = wifiSense == "1";
        }

        // Check hotspot sharing
        var hotspotOutput = await ShellHelper.RunPowerShellAsync(
            @"try {
                $val = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'WiFiSharingState' -ErrorAction SilentlyContinue
                if ($val -ne $null) { $val } else { 'unknown' }
            } catch { 'unknown' }", ct);
        var hotspot = hotspotOutput.Trim();
        if (hotspot != "unknown")
        {
            state.HotspotSharingEnabled = hotspot == "1";
        }

        return state;
    }

    private async Task<WifiProfile?> GetProfileDetailsAsync(string profileName, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            $"netsh wlan show profile name=\"{profileName.Replace("\"", "`\"")}\" key=clear", ct);

        if (string.IsNullOrWhiteSpace(output)) return null;

        var profile = new WifiProfile { Name = profileName };

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
            {
                profile.Authentication = ExtractValue(trimmed);
            }
            else if (trimmed.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase))
            {
                profile.Cipher = ExtractValue(trimmed);
            }
            else if (trimmed.StartsWith("Connection mode", StringComparison.OrdinalIgnoreCase))
            {
                var mode = ExtractValue(trimmed);
                profile.ConnectionMode = mode;
                profile.AutoConnect = mode.Contains("auto", StringComparison.OrdinalIgnoreCase);
            }
            else if (trimmed.StartsWith("Network broadcast", StringComparison.OrdinalIgnoreCase) ||
                     trimmed.StartsWith("SSID broadcast", StringComparison.OrdinalIgnoreCase))
            {
                var val = ExtractValue(trimmed);
                profile.IsHidden = val.Contains("no", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains("connect even", StringComparison.OrdinalIgnoreCase);
            }
            else if (trimmed.StartsWith("Key Content", StringComparison.OrdinalIgnoreCase))
            {
                var keyContent = ExtractValue(trimmed);
                profile.PasswordInCleartext = !string.IsNullOrWhiteSpace(keyContent);
            }
        }

        return profile;
    }

    private static string ExtractValue(string line)
    {
        var idx = line.IndexOf(':');
        return idx >= 0 ? line[(idx + 1)..].Trim() : "";
    }

    /// <summary>
    /// Analyze WiFi state and produce findings. Public for testability.
    /// </summary>
    public void AnalyzeState(WifiState state, AuditResult result)
    {
        if (!state.AdapterPresent)
        {
            result.Findings.Add(Finding.Info(
                "No WiFi Adapter Detected",
                "No wireless network adapter found. WiFi audit skipped.",
                Category));
            return;
        }

        CheckInsecureProfiles(state, result);
        CheckWeakProfiles(state, result);
        CheckAutoConnectRisks(state, result);
        CheckHiddenNetworkProbing(state, result);
        CheckPasswordExposure(state, result);
        CheckPublicNetworks(state, result);
        CheckExcessiveProfiles(state, result);
        CheckHostedNetwork(state, result);
        CheckMacRandomization(state, result);
        CheckWifiSense(state, result);
        CheckHotspotSharing(state, result);
        CheckDriverAge(state, result);
        CheckCurrentConnection(state, result);
    }

    private void CheckInsecureProfiles(WifiState state, AuditResult result)
    {
        var insecure = state.Profiles
            .Where(p => InsecureAuthTypes.ContainsKey(p.Authentication))
            .ToList();

        if (insecure.Count > 0)
        {
            var details = insecure.Select(p =>
                $"{p.Name} ({p.Authentication}: {InsecureAuthTypes[p.Authentication]})");
            result.Findings.Add(Finding.Critical(
                $"Insecure WiFi Profiles ({insecure.Count})",
                $"Saved WiFi profiles with critically insecure or no encryption: {string.Join("; ", details)}",
                Category,
                "Remove these profiles immediately: netsh wlan delete profile name=\"<name>\"",
                string.Join(" && ", insecure.Select(p =>
                    $"netsh wlan delete profile name=\"{p.Name}\""))));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Insecure WiFi Profiles",
                "No saved profiles using Open, WEP, or Shared authentication.",
                Category));
        }
    }

    private void CheckWeakProfiles(WifiState state, AuditResult result)
    {
        var weak = state.Profiles
            .Where(p => WeakAuthTypes.ContainsKey(p.Authentication))
            .ToList();

        if (weak.Count > 0)
        {
            var details = weak.Select(p =>
                $"{p.Name} ({p.Authentication}: {WeakAuthTypes[p.Authentication]})");
            result.Findings.Add(Finding.Warning(
                $"Weak WiFi Profiles ({weak.Count})",
                $"Saved WiFi profiles using weak encryption: {string.Join("; ", details)}",
                Category,
                "Upgrade these networks to WPA2 or WPA3 if possible."));
        }
    }

    private void CheckAutoConnectRisks(WifiState state, AuditResult result)
    {
        var autoInsecure = state.Profiles
            .Where(p => p.AutoConnect && (InsecureAuthTypes.ContainsKey(p.Authentication) ||
                                           WeakAuthTypes.ContainsKey(p.Authentication)))
            .ToList();

        if (autoInsecure.Count > 0)
        {
            result.Findings.Add(Finding.Critical(
                $"Auto-Connect to Insecure Networks ({autoInsecure.Count})",
                $"Auto-connect is enabled for insecure networks: {string.Join(", ", autoInsecure.Select(p => p.Name))}. " +
                "An attacker can create a rogue access point with the same name to intercept traffic.",
                Category,
                "Disable auto-connect or remove these profiles.",
                string.Join(" && ", autoInsecure.Select(p =>
                    $"netsh wlan set profileparameter name=\"{p.Name}\" connectionmode=manual"))));
        }
    }

    private void CheckHiddenNetworkProbing(WifiState state, AuditResult result)
    {
        var hidden = state.Profiles.Where(p => p.IsHidden).ToList();

        if (hidden.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"Hidden Network Profiles ({hidden.Count})",
                $"Profiles configured for hidden networks: {string.Join(", ", hidden.Select(p => p.Name))}. " +
                "Your device actively probes for these networks, broadcasting their names and revealing your location history.",
                Category,
                "Consider using visible networks or removing hidden network profiles when not needed."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Hidden Network Probing",
                "No saved profiles are configured for hidden (non-broadcast) networks.",
                Category));
        }
    }

    private void CheckPasswordExposure(WifiState state, AuditResult result)
    {
        var exposed = state.Profiles.Where(p => p.PasswordInCleartext).ToList();

        if (exposed.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"WiFi Passwords Stored ({exposed.Count})",
                $"{exposed.Count} WiFi profiles have passwords stored and retrievable via 'netsh wlan show profile key=clear'. " +
                "Any administrator or elevated process can read these passwords.",
                Category,
                "Be aware that saved WiFi passwords are accessible to administrators. " +
                "Remove profiles for networks you no longer use."));
        }
    }

    private void CheckPublicNetworks(WifiState state, AuditResult result)
    {
        var publicNets = state.Profiles
            .Where(p => KnownPublicNetworks.Contains(p.Name) ||
                        KnownPublicNetworks.Any(k => p.Name.Contains(k, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (publicNets.Count > 0)
        {
            var autoPublic = publicNets.Where(p => p.AutoConnect).ToList();
            var severity = autoPublic.Count > 0 ? Severity.Warning : Severity.Info;

            result.Findings.Add(new Finding
            {
                Title = $"Known Public Network Profiles ({publicNets.Count})",
                Description = $"Saved profiles match known public/default networks: {string.Join(", ", publicNets.Select(p => p.Name))}. " +
                    (autoPublic.Count > 0
                        ? $"{autoPublic.Count} have auto-connect enabled — risk of evil twin attacks."
                        : "Auto-connect is disabled for these networks."),
                Severity = severity,
                Category = Category,
                Remediation = "Remove public network profiles when you're done using them. Never auto-connect to public WiFi.",
                FixCommand = autoPublic.Count > 0
                    ? string.Join(" && ", autoPublic.Select(p =>
                        $"netsh wlan delete profile name=\"{p.Name}\""))
                    : null
            });
        }
    }

    private void CheckExcessiveProfiles(WifiState state, AuditResult result)
    {
        if (state.Profiles.Count > ExcessiveProfileThreshold)
        {
            result.Findings.Add(Finding.Warning(
                $"Excessive Saved WiFi Profiles ({state.Profiles.Count})",
                $"You have {state.Profiles.Count} saved WiFi profiles (threshold: {ExcessiveProfileThreshold}). " +
                "Each saved profile increases attack surface for evil twin attacks and broadcasts probe requests.",
                Category,
                "Remove WiFi profiles for networks you no longer use.",
                "netsh wlan show profiles"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                $"Saved WiFi Profiles ({state.Profiles.Count})",
                $"You have {state.Profiles.Count} saved WiFi profiles (threshold: {ExcessiveProfileThreshold}).",
                Category));
        }
    }

    private void CheckHostedNetwork(WifiState state, AuditResult result)
    {
        if (state.HostedNetworkAllowed == true)
        {
            result.Findings.Add(Finding.Warning(
                "Hosted Network / WiFi Direct Enabled",
                "Hosted network (virtual AP) is allowed. This can be exploited to create rogue access points.",
                Category,
                "Disable hosted network if not needed.",
                "netsh wlan set hostednetwork mode=disallow"));
        }
        else if (state.HostedNetworkAllowed == false)
        {
            result.Findings.Add(Finding.Pass(
                "Hosted Network Disabled",
                "Hosted network (virtual AP) is not allowed.",
                Category));
        }
    }

    private void CheckMacRandomization(WifiState state, AuditResult result)
    {
        if (state.MacRandomizationEnabled == false)
        {
            result.Findings.Add(Finding.Warning(
                "MAC Address Randomization Disabled",
                "WiFi MAC address randomization is not enabled. Your device broadcasts its unique " +
                "hardware MAC address, allowing tracking across networks and locations.",
                Category,
                "Enable MAC address randomization in Settings > Network & Internet > WiFi > Random hardware addresses."));
        }
        else if (state.MacRandomizationEnabled == true)
        {
            result.Findings.Add(Finding.Pass(
                "MAC Address Randomization Enabled",
                "WiFi MAC address randomization is enabled, helping prevent device tracking.",
                Category));
        }

        // Check per-profile MAC randomization
        var noMacRand = state.Profiles
            .Where(p => p.MacRandomization == false)
            .ToList();

        if (noMacRand.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Per-Profile MAC Randomization Disabled ({noMacRand.Count})",
                $"MAC randomization is disabled for: {string.Join(", ", noMacRand.Select(p => p.Name))}. " +
                "These networks can track your device's hardware address.",
                Category,
                "Enable per-network random MAC in WiFi settings for each network."));
        }
    }

    private void CheckWifiSense(WifiState state, AuditResult result)
    {
        if (state.WifiSenseEnabled == true)
        {
            result.Findings.Add(Finding.Warning(
                "WiFi Sense Auto-Connect Enabled",
                "WiFi Sense automatically connects to suggested open hotspots and shared networks. " +
                "This can expose you to untrusted networks without explicit consent.",
                Category,
                "Disable WiFi Sense in Settings > Network & Internet > WiFi.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Value 0"));
        }
        else if (state.WifiSenseEnabled == false)
        {
            result.Findings.Add(Finding.Pass(
                "WiFi Sense Disabled",
                "WiFi Sense auto-connect to suggested hotspots is disabled.",
                Category));
        }
    }

    private void CheckHotspotSharing(WifiState state, AuditResult result)
    {
        if (state.HotspotSharingEnabled == true)
        {
            result.Findings.Add(Finding.Warning(
                "WiFi Password Sharing Enabled",
                "WiFi password sharing is enabled, which may share saved network credentials " +
                "with contacts without your explicit knowledge.",
                Category,
                "Disable hotspot sharing in Settings > Network & Internet > WiFi.",
                @"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'WiFiSharingState' -Value 0"));
        }
        else if (state.HotspotSharingEnabled == false)
        {
            result.Findings.Add(Finding.Pass(
                "WiFi Password Sharing Disabled",
                "WiFi password sharing with contacts is disabled.",
                Category));
        }
    }

    private void CheckDriverAge(WifiState state, AuditResult result)
    {
        if (state.DriverAgeDays is > 365)
        {
            result.Findings.Add(Finding.Warning(
                $"WiFi Driver Outdated ({state.DriverAgeDays} days)",
                $"WiFi adapter driver is {state.DriverAgeDays} days old. Outdated drivers may have " +
                "unpatched security vulnerabilities (KRACK, FragAttacks, etc.).",
                Category,
                "Update your WiFi adapter driver via Windows Update or manufacturer's website."));
        }
        else if (state.DriverAgeDays.HasValue)
        {
            result.Findings.Add(Finding.Pass(
                $"WiFi Driver Up to Date ({state.DriverAgeDays} days old)",
                "WiFi adapter driver is reasonably current.",
                Category));
        }
    }

    private void CheckCurrentConnection(WifiState state, AuditResult result)
    {
        if (state.ConnectedNetwork == null) return;

        var connectedProfile = state.Profiles
            .FirstOrDefault(p => p.Name.Equals(state.ConnectedNetwork, StringComparison.OrdinalIgnoreCase));

        if (connectedProfile != null && InsecureAuthTypes.ContainsKey(connectedProfile.Authentication))
        {
            result.Findings.Add(Finding.Critical(
                $"Currently Connected to Insecure Network",
                $"You are currently connected to '{state.ConnectedNetwork}' which uses " +
                $"{connectedProfile.Authentication} authentication. All traffic may be intercepted.",
                Category,
                "Disconnect immediately and use a VPN if you must use this network.",
                $"netsh wlan disconnect"));
        }
    }
}
