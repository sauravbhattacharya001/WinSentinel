using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits Bluetooth security configuration for risks including:
/// - Bluetooth radio left enabled when not needed (attack surface)
/// - Discoverable mode enabled (BlueBorne, BlueSmack, BlueSnarfing)
/// - Paired devices with outdated or unknown profiles
/// - Bluetooth services exposing sensitive capabilities (OBEX, PAN, serial)
/// - Missing or weak Bluetooth authentication/encryption settings
/// - Bluetooth support service running unnecessarily
/// - Devices paired via legacy (non-SSP) pairing
/// </summary>
public class BluetoothAudit : IAuditModule
{
    public string Name => "Bluetooth Security Audit";
    public string Category => "Bluetooth";
    public string Description =>
        "Checks Bluetooth radio state, discoverability, paired device trust, " +
        "exposed services, authentication settings, and legacy pairing risks.";

    /// <summary>
    /// Bluetooth profiles/services considered higher risk when exposed.
    /// </summary>
    public static readonly Dictionary<string, string> RiskyServices = new(StringComparer.OrdinalIgnoreCase)
    {
        ["OBEX Object Push"] = "Allows file transfer without explicit approval on some configurations",
        ["OBEX File Transfer"] = "Allows browsing and transferring files from the device",
        ["Serial Port"] = "Exposes serial communication channel that can be exploited",
        ["Personal Area Network"] = "Shares network access over Bluetooth",
        ["Network Access Point"] = "Acts as a network access point over Bluetooth",
        ["Dial-up Networking"] = "Exposes modem/dial-up capability over Bluetooth",
        ["Headset Gateway"] = "Audio gateway that may allow eavesdropping if misconfigured",
    };

    /// <summary>
    /// Known Bluetooth device classes that are unusual for typical enterprise use.
    /// </summary>
    public static readonly HashSet<string> SuspiciousDeviceTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Uncategorized",
        "Network",
        "Information",
    };

    /// <summary>
    /// Data transfer object for Bluetooth environment state.
    /// All checks operate on this record for testability.
    /// </summary>
    public sealed class BluetoothState
    {
        /// <summary>Whether any Bluetooth radio is present on the system.</summary>
        public bool RadioPresent { get; set; }

        /// <summary>Whether Bluetooth radio is currently enabled/powered on.</summary>
        public bool RadioEnabled { get; set; }

        /// <summary>Whether the device is discoverable to other Bluetooth devices.</summary>
        public bool Discoverable { get; set; }

        /// <summary>Whether the device is connectable (accepting incoming connections).</summary>
        public bool Connectable { get; set; } = true;

        /// <summary>Bluetooth adapter name (may reveal hostname if default).</summary>
        public string AdapterName { get; set; } = string.Empty;

        /// <summary>Whether the adapter name matches the computer hostname.</summary>
        public bool NameMatchesHostname { get; set; }

        /// <summary>Bluetooth Support Service (bthserv) running state.</summary>
        public ServiceRunState BluetoothServiceState { get; set; } = ServiceRunState.Unknown;

        /// <summary>Paired devices.</summary>
        public List<PairedDevice> PairedDevices { get; set; } = new();

        /// <summary>Exposed Bluetooth service names.</summary>
        public List<string> ExposedServices { get; set; } = new();

        /// <summary>Whether Secure Simple Pairing (SSP) is supported.</summary>
        public bool? SspSupported { get; set; }

        /// <summary>Whether encryption is enforced for connections.</summary>
        public bool? EncryptionEnforced { get; set; }

        /// <summary>Bluetooth driver version string.</summary>
        public string DriverVersion { get; set; } = string.Empty;

        /// <summary>Days since the Bluetooth driver was last updated.</summary>
        public int? DriverAgeDays { get; set; }
    }

    public enum ServiceRunState
    {
        Unknown,
        Running,
        Stopped,
        Disabled
    }

    public sealed class PairedDevice
    {
        public string Name { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public string DeviceType { get; set; } = string.Empty;
        public bool Connected { get; set; }
        public bool Authenticated { get; set; }
        public bool Remembered { get; set; } = true;
        public DateTimeOffset? LastSeen { get; set; }
        public DateTimeOffset? LastUsed { get; set; }
        /// <summary>Days since device was last seen/used. Null if unknown.</summary>
        public int? DaysSinceLastUse { get; set; }
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
    /// Gather live Bluetooth state from the system. Separated for testability.
    /// </summary>
    internal async Task<BluetoothState> GatherStateAsync(CancellationToken ct)
    {
        var state = new BluetoothState();

        // Check if Bluetooth radio exists and its state
        var radioOutput = await ShellHelper.RunPowerShellAsync(
            "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.FriendlyName -like '*Radio*' -or $_.FriendlyName -like '*Adapter*' } | " +
            "Select-Object Status, FriendlyName, DriverVersion | " +
            "ConvertTo-Json -Compress", ct);

        if (!string.IsNullOrWhiteSpace(radioOutput) && radioOutput.Trim() != "")
        {
            state.RadioPresent = true;
            if (radioOutput.Contains("\"OK\"", StringComparison.OrdinalIgnoreCase))
                state.RadioEnabled = true;
        }

        // Check Bluetooth Support Service
        var svcOutput = await ShellHelper.RunPowerShellAsync(
            "Get-Service bthserv -ErrorAction SilentlyContinue | " +
            "Select-Object Status, StartType | ConvertTo-Json -Compress", ct);

        if (!string.IsNullOrWhiteSpace(svcOutput))
        {
            if (svcOutput.Contains("\"Running\"", StringComparison.OrdinalIgnoreCase))
                state.BluetoothServiceState = ServiceRunState.Running;
            else if (svcOutput.Contains("\"Stopped\"", StringComparison.OrdinalIgnoreCase))
                state.BluetoothServiceState = ServiceRunState.Stopped;
            if (svcOutput.Contains("\"Disabled\"", StringComparison.OrdinalIgnoreCase))
                state.BluetoothServiceState = ServiceRunState.Disabled;
        }

        // Check paired devices
        var deviceOutput = await ShellHelper.RunPowerShellAsync(
            "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.FriendlyName -notlike '*Radio*' -and $_.FriendlyName -notlike '*Adapter*' } | " +
            "Select-Object FriendlyName, Status, InstanceId | " +
            "ConvertTo-Json -Compress", ct);

        if (!string.IsNullOrWhiteSpace(deviceOutput) && deviceOutput.Trim() != "[]")
        {
            // Simple parse — each device in JSON
            foreach (var line in deviceOutput.Split('{'))
            {
                if (!line.Contains("FriendlyName")) continue;
                var device = new PairedDevice();
                var nameMatch = System.Text.RegularExpressions.Regex.Match(line, "\"FriendlyName\":\"([^\"]+)\"");
                if (nameMatch.Success) device.Name = nameMatch.Groups[1].Value;
                var statusMatch = System.Text.RegularExpressions.Regex.Match(line, "\"Status\":\"([^\"]+)\"");
                if (statusMatch.Success) device.Connected = statusMatch.Groups[1].Value == "OK";
                state.PairedDevices.Add(device);
            }
        }

        // Check adapter name vs hostname
        var nameOutput = await ShellHelper.RunPowerShellAsync(
            "$bt = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | " +
            "Where-Object { $_.FriendlyName -like '*Radio*' -or $_.FriendlyName -like '*Adapter*' } | " +
            "Select-Object -First 1 -ExpandProperty FriendlyName; " +
            "$hn = $env:COMPUTERNAME; " +
            "if ($bt) { \"$bt|$hn\" }", ct);

        if (!string.IsNullOrWhiteSpace(nameOutput) && nameOutput.Contains('|'))
        {
            var parts = nameOutput.Trim().Split('|');
            state.AdapterName = parts[0];
            state.NameMatchesHostname = parts[0].Contains(parts[1], StringComparison.OrdinalIgnoreCase);
        }

        return state;
    }

    /// <summary>
    /// Analyze gathered state and populate findings. Public for testability.
    /// </summary>
    public void AnalyzeState(BluetoothState state, AuditResult result)
    {
        const string cat = "Bluetooth";

        // No Bluetooth radio
        if (!state.RadioPresent)
        {
            result.Findings.Add(Finding.Pass(
                "No Bluetooth Radio",
                "No Bluetooth adapter detected. Bluetooth attack surface is not present.",
                cat));
            return;
        }

        // Radio enabled check
        if (state.RadioEnabled)
        {
            result.Findings.Add(Finding.Info(
                "Bluetooth Radio Enabled",
                "Bluetooth radio is currently enabled. Disable when not in use to reduce attack surface (BlueBorne, BlueSmack).",
                cat,
                "Disable Bluetooth in Settings > Bluetooth & devices when not actively using it.",
                "powershell -Command \"Get-PnpDevice -Class Bluetooth | Where-Object { $_.FriendlyName -like '*Radio*' } | Disable-PnpDevice -Confirm:$false\""));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Bluetooth Radio Disabled",
                "Bluetooth radio is currently disabled, reducing wireless attack surface.",
                cat));
        }

        // Discoverable mode
        if (state.Discoverable)
        {
            result.Findings.Add(Finding.Warning(
                "Bluetooth Discoverable Mode Enabled",
                "Device is discoverable to nearby Bluetooth devices. This exposes the device to BlueSnarfing, " +
                "BlueJacking, and device enumeration attacks.",
                cat,
                "Disable discoverable mode: Settings > Bluetooth & devices > uncheck 'Allow devices to find this PC'."));
        }
        else if (state.RadioEnabled)
        {
            result.Findings.Add(Finding.Pass(
                "Bluetooth Not Discoverable",
                "Bluetooth is enabled but not in discoverable mode.",
                cat));
        }

        // Connectable when discoverable
        if (state.Discoverable && state.Connectable)
        {
            result.Findings.Add(Finding.Warning(
                "Bluetooth Connectable While Discoverable",
                "Device accepts incoming Bluetooth connections while also being discoverable. " +
                "This is the highest-risk Bluetooth configuration.",
                cat,
                "Disable discoverable mode and restrict incoming connections to paired devices only."));
        }

        // Adapter name leaks hostname
        if (state.NameMatchesHostname && state.RadioEnabled)
        {
            result.Findings.Add(Finding.Warning(
                "Bluetooth Adapter Name Reveals Hostname",
                $"The Bluetooth adapter name '{state.AdapterName}' contains the computer hostname. " +
                "This can leak device identity to nearby attackers during discovery.",
                cat,
                "Change the Bluetooth device name to a generic name in Settings > Bluetooth & devices."));
        }
        else if (state.RadioEnabled && !string.IsNullOrEmpty(state.AdapterName))
        {
            result.Findings.Add(Finding.Pass(
                "Bluetooth Name Does Not Leak Hostname",
                "Bluetooth adapter name does not appear to reveal the computer hostname.",
                cat));
        }

        // Bluetooth Support Service
        AnalyzeServiceState(state, result, cat);

        // Paired devices analysis
        AnalyzePairedDevices(state, result, cat);

        // Exposed services
        AnalyzeExposedServices(state, result, cat);

        // SSP support
        AnalyzeAuthentication(state, result, cat);

        // Driver age
        AnalyzeDriverAge(state, result, cat);
    }

    private void AnalyzeServiceState(BluetoothState state, AuditResult result, string cat)
    {
        switch (state.BluetoothServiceState)
        {
            case ServiceRunState.Running when !state.RadioEnabled:
                result.Findings.Add(Finding.Warning(
                    "Bluetooth Service Running Without Radio",
                    "The Bluetooth Support Service (bthserv) is running even though the radio is disabled. " +
                    "This service can be stopped to further reduce attack surface.",
                    cat,
                    "Stop and disable the service: Stop-Service bthserv; Set-Service bthserv -StartupType Disabled",
                    "powershell -Command \"Stop-Service bthserv; Set-Service bthserv -StartupType Disabled\""));
                break;

            case ServiceRunState.Disabled:
                result.Findings.Add(Finding.Pass(
                    "Bluetooth Service Disabled",
                    "The Bluetooth Support Service is disabled, minimizing Bluetooth attack surface.",
                    cat));
                break;

            case ServiceRunState.Running when state.RadioEnabled:
                result.Findings.Add(Finding.Info(
                    "Bluetooth Service Running",
                    "The Bluetooth Support Service is running (expected when radio is enabled).",
                    cat));
                break;
        }
    }

    private void AnalyzePairedDevices(BluetoothState state, AuditResult result, string cat)
    {
        if (state.PairedDevices.Count == 0)
        {
            if (state.RadioEnabled)
            {
                result.Findings.Add(Finding.Pass(
                    "No Paired Devices",
                    "No Bluetooth devices are currently paired. Lower risk of rogue device connections.",
                    cat));
            }
            return;
        }

        result.Findings.Add(Finding.Info(
            $"{state.PairedDevices.Count} Paired Device(s)",
            $"Found {state.PairedDevices.Count} paired Bluetooth device(s). Review regularly to remove unknown devices.",
            cat,
            "Remove unfamiliar devices: Settings > Bluetooth & devices > select device > Remove."));

        // Check for unauthenticated devices
        var unauthed = state.PairedDevices.Where(d => !d.Authenticated).ToList();
        if (unauthed.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"{unauthed.Count} Unauthenticated Paired Device(s)",
                "The following devices are paired without authentication: " +
                string.Join(", ", unauthed.Select(d => d.Name.Length > 0 ? d.Name : d.Address)) +
                ". Unauthenticated pairing is vulnerable to man-in-the-middle attacks.",
                cat,
                "Remove and re-pair these devices using Secure Simple Pairing with PIN confirmation."));
        }

        // Check for stale devices (not seen in 90+ days)
        var stale = state.PairedDevices.Where(d => d.DaysSinceLastUse.HasValue && d.DaysSinceLastUse.Value > 90).ToList();
        if (stale.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"{stale.Count} Stale Paired Device(s)",
                "The following devices haven't been used in over 90 days: " +
                string.Join(", ", stale.Select(d => $"{(d.Name.Length > 0 ? d.Name : d.Address)} ({d.DaysSinceLastUse}d)")) +
                ". Stale pairings increase risk of rogue device impersonation.",
                cat,
                "Remove stale devices: Settings > Bluetooth & devices > select device > Remove."));
        }

        // Check for suspicious device types
        var suspicious = state.PairedDevices
            .Where(d => SuspiciousDeviceTypes.Contains(d.DeviceType))
            .ToList();
        if (suspicious.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"{suspicious.Count} Suspicious Device Type(s)",
                "The following paired devices have unusual device types: " +
                string.Join(", ", suspicious.Select(d => $"{(d.Name.Length > 0 ? d.Name : d.Address)} ({d.DeviceType})")) +
                ". Verify these are legitimate devices.",
                cat,
                "Review each device and remove any unrecognized ones: Settings > Bluetooth & devices > select device > Remove."));
        }

        // Check for unnamed devices
        var unnamed = state.PairedDevices.Where(d => string.IsNullOrWhiteSpace(d.Name)).ToList();
        if (unnamed.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"{unnamed.Count} Unnamed Paired Device(s)",
                $"{unnamed.Count} paired device(s) have no name, making identification difficult. " +
                "These could be rogue devices.",
                cat,
                "Review unnamed devices by their address and remove any that are unrecognized."));
        }
    }

    private void AnalyzeExposedServices(BluetoothState state, AuditResult result, string cat)
    {
        if (state.ExposedServices.Count == 0) return;

        var risky = state.ExposedServices
            .Where(s => RiskyServices.ContainsKey(s))
            .ToList();

        if (risky.Count > 0)
        {
            var details = string.Join("\n", risky.Select(s =>
                $"  • {s}: {RiskyServices[s]}"));

            result.Findings.Add(Finding.Warning(
                $"{risky.Count} Risky Bluetooth Service(s) Exposed",
                $"The following high-risk Bluetooth services are active:\n{details}",
                cat,
                "Disable unnecessary Bluetooth services in Device Manager or via Group Policy."));
        }

        var safe = state.ExposedServices.Except(risky, StringComparer.OrdinalIgnoreCase).ToList();
        if (safe.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"{safe.Count} Bluetooth Service(s) Active",
                "Active Bluetooth services: " + string.Join(", ", safe),
                cat));
        }
    }

    private void AnalyzeAuthentication(BluetoothState state, AuditResult result, string cat)
    {
        if (!state.RadioEnabled) return;

        if (state.SspSupported.HasValue)
        {
            if (!state.SspSupported.Value)
            {
                result.Findings.Add(Finding.Critical(
                    "Secure Simple Pairing Not Supported",
                    "The Bluetooth adapter does not support Secure Simple Pairing (SSP). " +
                    "Legacy pairing uses weak PIN-based authentication vulnerable to brute force.",
                    cat,
                    "Upgrade to a Bluetooth 2.1+ adapter that supports Secure Simple Pairing."));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Secure Simple Pairing Supported",
                    "The Bluetooth adapter supports Secure Simple Pairing (SSP) for stronger authentication.",
                    cat));
            }
        }

        if (state.EncryptionEnforced.HasValue)
        {
            if (!state.EncryptionEnforced.Value)
            {
                result.Findings.Add(Finding.Critical(
                    "Bluetooth Encryption Not Enforced",
                    "Bluetooth connection encryption is not enforced. Data transmitted over Bluetooth " +
                    "may be intercepted by nearby attackers.",
                    cat,
                    "Enable mandatory encryption via Bluetooth adapter settings or Group Policy."));
            }
            else
            {
                result.Findings.Add(Finding.Pass(
                    "Bluetooth Encryption Enforced",
                    "Bluetooth connections require encryption, protecting data in transit.",
                    cat));
            }
        }
    }

    private void AnalyzeDriverAge(BluetoothState state, AuditResult result, string cat)
    {
        if (!state.RadioPresent || !state.DriverAgeDays.HasValue) return;

        if (state.DriverAgeDays.Value > 730) // > 2 years
        {
            result.Findings.Add(Finding.Warning(
                "Bluetooth Driver Outdated",
                $"The Bluetooth driver is approximately {state.DriverAgeDays.Value / 365} years old " +
                $"(version: {state.DriverVersion}). Outdated drivers may contain unpatched " +
                "vulnerabilities (e.g., BlueBorne CVE-2017-8628).",
                cat,
                "Update the Bluetooth driver via Device Manager or the manufacturer's website."));
        }
        else if (state.DriverAgeDays.Value > 365) // > 1 year
        {
            result.Findings.Add(Finding.Info(
                "Bluetooth Driver Aging",
                $"The Bluetooth driver is over a year old (version: {state.DriverVersion}). " +
                "Consider checking for updates.",
                cat,
                "Check for driver updates via Device Manager > Bluetooth > Update driver."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "Bluetooth Driver Up to Date",
                $"The Bluetooth driver (version: {state.DriverVersion}) was updated within the last year.",
                cat));
        }
    }
}
