namespace WinSentinel.Agent.Services;

/// <summary>
/// A single remediation strategy that knows how to handle a specific type of threat.
/// Strategies are evaluated in order; the first one that claims a threat handles it.
/// </summary>
public interface IRemediationStrategy
{
    /// <summary>
    /// Returns true if this strategy can handle the given threat.
    /// </summary>
    bool CanHandle(ThreatEvent threat);

    /// <summary>
    /// Execute the remediation. Only called if <see cref="CanHandle"/> returned true.
    /// </summary>
    RemediationRecord Execute(ThreatEvent threat);
}

/// <summary>
/// Re-enable Windows Defender when a "Defender Disabled" threat is detected.
/// </summary>
public class DefenderRemediationStrategy : IRemediationStrategy
{
    private readonly AutoRemediator _remediator;

    public DefenderRemediationStrategy(AutoRemediator remediator) => _remediator = remediator;

    public bool CanHandle(ThreatEvent threat) =>
        threat.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
        threat.Title.Contains("Disabled", StringComparison.OrdinalIgnoreCase);

    public RemediationRecord Execute(ThreatEvent threat) =>
        _remediator.ReEnableDefender(threat.Id);
}

/// <summary>
/// Restore the hosts file when a "Hosts File" modification threat is detected.
/// </summary>
public class HostsFileRemediationStrategy : IRemediationStrategy
{
    private readonly AutoRemediator _remediator;

    public HostsFileRemediationStrategy(AutoRemediator remediator) => _remediator = remediator;

    public bool CanHandle(ThreatEvent threat) =>
        threat.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase);

    public RemediationRecord Execute(ThreatEvent threat) =>
        _remediator.RestoreHostsFile(threat.Id);
}

/// <summary>
/// Kill a suspicious process when a ProcessMonitor threat includes a PID.
/// </summary>
public class ProcessKillRemediationStrategy : IRemediationStrategy
{
    private readonly AutoRemediator _remediator;

    public ProcessKillRemediationStrategy(AutoRemediator remediator) => _remediator = remediator;

    public bool CanHandle(ThreatEvent threat) =>
        threat.Source == "ProcessMonitor" &&
        AgentBrain.ExtractPid(threat.Description) is not null;

    public RemediationRecord Execute(ThreatEvent threat)
    {
        var pid = AgentBrain.ExtractPid(threat.Description)!.Value;
        var processName = AgentBrain.ExtractProcessName(threat.Description) ?? "unknown";
        return _remediator.KillProcess(pid, processName, threat.Id);
    }
}

/// <summary>
/// Quarantine a suspicious file when a FileSystemMonitor threat includes a file path.
/// </summary>
public class FileQuarantineRemediationStrategy : IRemediationStrategy
{
    private readonly AutoRemediator _remediator;

    public FileQuarantineRemediationStrategy(AutoRemediator remediator) => _remediator = remediator;

    public bool CanHandle(ThreatEvent threat) =>
        threat.Source == "FileSystemMonitor" &&
        AgentBrain.ExtractFilePath(threat.Description) is not null;

    public RemediationRecord Execute(ThreatEvent threat)
    {
        var filePath = AgentBrain.ExtractFilePath(threat.Description)!;
        return _remediator.QuarantineFile(filePath, threat.Id);
    }
}

/// <summary>
/// Block an IP address when a threat description contains one.
/// </summary>
public class IpBlockRemediationStrategy : IRemediationStrategy
{
    private readonly AutoRemediator _remediator;

    public IpBlockRemediationStrategy(AutoRemediator remediator) => _remediator = remediator;

    public bool CanHandle(ThreatEvent threat) =>
        AgentBrain.ExtractIpAddress(threat.Description) is not null;

    public RemediationRecord Execute(ThreatEvent threat)
    {
        var ip = AgentBrain.ExtractIpAddress(threat.Description)!;
        return _remediator.BlockIp(ip, threat.Title, threat.Id);
    }
}

/// <summary>
/// Execute a threat's FixCommand as a generic fallback.
/// </summary>
public class FixCommandRemediationStrategy : IRemediationStrategy
{
    private readonly AutoRemediator _remediator;

    public FixCommandRemediationStrategy(AutoRemediator remediator) => _remediator = remediator;

    public bool CanHandle(ThreatEvent threat) =>
        !string.IsNullOrEmpty(threat.FixCommand);

    public RemediationRecord Execute(ThreatEvent threat) =>
        _remediator.ExecuteFixCommand(threat);
}
