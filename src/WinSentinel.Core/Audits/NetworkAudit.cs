using WinSentinel.Core.Helpers;
using WinSentinel.Core.Interfaces;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Audits;

/// <summary>
/// Audits network configuration: open ports, listening services, SMB/RDP exposure.
/// </summary>
public class NetworkAudit : IAuditModule
{
    public string Name => "Network Audit";
    public string Category => "Network";
    public string Description => "Checks open ports, listening services, and SMB/RDP exposure.";

    private static readonly HashSet<int> HighRiskPorts = new()
    {
        21,    // FTP
        23,    // Telnet
        135,   // RPC
        139,   // NetBIOS
        445,   // SMB
        1433,  // SQL Server
        1434,  // SQL Browser
        3389,  // RDP
        5900,  // VNC
        5985,  // WinRM HTTP
        5986,  // WinRM HTTPS
    };

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
            await CheckListeningPorts(result, cancellationToken);
            await CheckSmbExposure(result, cancellationToken);
            await CheckRdpExposure(result, cancellationToken);
            await CheckWinRm(result, cancellationToken);
            await CheckDnsSettings(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        result.EndTime = DateTimeOffset.UtcNow;
        return result;
    }

    private async Task CheckListeningPorts(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
              Select-Object LocalPort, OwningProcess | 
              Sort-Object LocalPort -Unique | 
              ForEach-Object { 
                  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                  '{0}|{1}' -f $_.LocalPort, $proc.ProcessName 
              }", ct);

        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var highRiskOpen = new List<string>();

        foreach (var line in lines)
        {
            var parts = line.Split('|');
            if (parts.Length >= 2 && int.TryParse(parts[0], out int port))
            {
                var processName = parts[1];
                if (HighRiskPorts.Contains(port))
                {
                    highRiskOpen.Add($"Port {port} ({processName})");
                }
            }
        }

        if (highRiskOpen.Count > 0)
        {
            result.Findings.Add(Finding.Warning(
                $"High-Risk Ports Listening ({highRiskOpen.Count})",
                $"The following high-risk ports are open and listening: {string.Join(", ", highRiskOpen)}",
                Category,
                "Review each listening service and disable any that are not needed. Block unused ports in the firewall."));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "No Common High-Risk Ports Exposed",
                "No commonly targeted high-risk ports were found listening.",
                Category));
        }

        result.Findings.Add(Finding.Info(
            $"Total Listening Ports: {lines.Length}",
            $"{lines.Length} TCP ports are currently in LISTEN state.",
            Category));
    }

    private async Task CheckSmbExposure(AuditResult result, CancellationToken ct)
    {
        // Check SMBv1
        var smbv1 = await ShellHelper.RunPowerShellAsync(
            @"try { (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { 'ERROR' }", ct);

        if (smbv1.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Critical(
                "SMBv1 Protocol Enabled",
                "SMBv1 is enabled. This is a critical vulnerability exploited by WannaCry, EternalBlue, and other attacks.",
                Category,
                "Disable SMBv1 immediately. It is deprecated and insecure.",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"));
        }
        else if (smbv1.Trim().Equals("False", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "SMBv1 Protocol Disabled",
                "SMBv1 is properly disabled.",
                Category));
        }

        // Check SMB signing
        var smbSigning = await ShellHelper.RunPowerShellAsync(
            @"try { (Get-SmbServerConfiguration).RequireSecuritySignature } catch { 'ERROR' }", ct);

        if (smbSigning.Trim().Equals("False", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "SMB Signing Not Required",
                "SMB packet signing is not required. This allows potential man-in-the-middle attacks on file sharing.",
                Category,
                "Enable SMB signing requirement.",
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"));
        }
        else if (smbSigning.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Pass(
                "SMB Signing Required",
                "SMB packet signing is required for all connections.",
                Category));
        }

        // Check for open shares
        var shares = await ShellHelper.RunPowerShellAsync(
            @"Get-SmbShare | Where-Object { $_.Name -notmatch '^\$' -and $_.Name -ne 'IPC$' } | Select-Object -ExpandProperty Name", ct);

        var shareList = shares.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => !string.IsNullOrWhiteSpace(s)).ToList();

        if (shareList.Count > 0)
        {
            result.Findings.Add(Finding.Info(
                $"Non-Default SMB Shares ({shareList.Count})",
                $"Custom SMB shares found: {string.Join(", ", shareList)}. Verify these shares are intentional and properly secured.",
                Category));
        }
    }

    private async Task CheckRdpExposure(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections", ct);

        if (output.Trim() == "0")
        {
            // RDP is enabled — check NLA
            var nla = await ShellHelper.RunPowerShellAsync(
                @"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication", ct);

            if (nla.Trim() == "0")
            {
                result.Findings.Add(Finding.Critical(
                    "RDP Enabled Without NLA",
                    "Remote Desktop is enabled but Network Level Authentication (NLA) is DISABLED. This allows unauthenticated users to reach the login screen.",
                    Category,
                    "Enable Network Level Authentication for RDP.",
                    @"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1"));
            }
            else
            {
                result.Findings.Add(Finding.Info(
                    "RDP Enabled with NLA",
                    "Remote Desktop is enabled with Network Level Authentication. Ensure RDP is only accessible from trusted networks.",
                    Category));
            }
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "RDP Disabled",
                "Remote Desktop Protocol is disabled.",
                Category));
        }
    }

    private async Task CheckWinRm(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"try { $status = Get-Service WinRM -ErrorAction SilentlyContinue; $status.Status } catch { 'NotFound' }", ct);

        if (output.Trim().Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(Finding.Warning(
                "WinRM Service Running",
                "Windows Remote Management (WinRM) service is running. This allows remote PowerShell sessions.",
                Category,
                "Disable WinRM if remote management is not needed.",
                "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"));
        }
        else
        {
            result.Findings.Add(Finding.Pass(
                "WinRM Service Not Running",
                "Windows Remote Management service is not running.",
                Category));
        }
    }

    private async Task CheckDnsSettings(AuditResult result, CancellationToken ct)
    {
        var output = await ShellHelper.RunPowerShellAsync(
            @"Get-DnsClientServerAddress -AddressFamily IPv4 | 
              Where-Object { $_.ServerAddresses.Count -gt 0 } | 
              Select-Object -ExpandProperty ServerAddresses -Unique", ct);

        if (!string.IsNullOrWhiteSpace(output))
        {
            var dnsServers = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            result.Findings.Add(Finding.Info(
                $"DNS Servers Configured ({dnsServers.Length})",
                $"DNS servers in use: {string.Join(", ", dnsServers)}",
                Category));
        }
    }
}
