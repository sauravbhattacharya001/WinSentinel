using System.Text.Json;
using WinSentinel.Agent;
using WinSentinel.Agent.Ipc;

namespace WinSentinel.Tests.Agent;

/// <summary>
/// Tests for IPC message serialization/deserialization.
/// </summary>
public class IpcMessageTests
{
    [Fact]
    public void Request_Serializes_And_Deserializes()
    {
        var msg = IpcMessage.Request(IpcMessageType.GetStatus, requestId: "test123");
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        Assert.NotNull(deserialized);
        Assert.Equal(IpcMessageType.GetStatus, deserialized.Type);
        Assert.Equal("test123", deserialized.RequestId);
    }

    [Fact]
    public void Response_With_Payload_Roundtrips()
    {
        var snapshot = new AgentStatusSnapshot
        {
            StartTime = DateTimeOffset.UtcNow,
            UptimeSeconds = 3600,
            ThreatsDetectedToday = 5,
            LastScanScore = 85,
            IsScanRunning = false,
            ActiveModules = ["ScheduledAudit"],
            Version = "1.0.0"
        };

        var msg = IpcMessage.Response(IpcMessageType.StatusResponse, snapshot, "req1");
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        Assert.NotNull(deserialized);
        Assert.Equal(IpcMessageType.StatusResponse, deserialized.Type);
        Assert.Equal("req1", deserialized.RequestId);

        var payload = deserialized.GetPayload<AgentStatusSnapshot>();
        Assert.NotNull(payload);
        Assert.Equal(3600, payload.UptimeSeconds);
        Assert.Equal(5, payload.ThreatsDetectedToday);
        Assert.Equal(85, payload.LastScanScore);
        Assert.Single(payload.ActiveModules);
        Assert.Equal("ScheduledAudit", payload.ActiveModules[0]);
    }

    [Fact]
    public void ErrorResponse_Serializes_Correctly()
    {
        var msg = IpcMessage.ErrorResponse("Something went wrong", "req2");
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        Assert.NotNull(deserialized);
        Assert.Equal(IpcMessageType.Error, deserialized.Type);
        Assert.Equal("Something went wrong", deserialized.Error);
        Assert.Equal("req2", deserialized.RequestId);
    }

    [Fact]
    public void Event_Without_RequestId_Works()
    {
        var threat = new ThreatEvent
        {
            Source = "ProcessMonitor",
            Severity = ThreatSeverity.High,
            Title = "Suspicious Process",
            Description = "Unknown process detected",
            AutoFixable = true
        };

        var msg = IpcMessage.Event(IpcMessageType.ThreatDetected, threat);
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        Assert.NotNull(deserialized);
        Assert.Equal(IpcMessageType.ThreatDetected, deserialized.Type);
        Assert.Null(deserialized.RequestId);

        var payload = deserialized.GetPayload<ThreatEvent>();
        Assert.NotNull(payload);
        Assert.Equal("ProcessMonitor", payload.Source);
        Assert.Equal(ThreatSeverity.High, payload.Severity);
        Assert.True(payload.AutoFixable);
    }

    [Fact]
    public void Invalid_Json_Returns_Null()
    {
        var result = IpcMessage.Deserialize("not valid json {{{");
        Assert.Null(result);
    }

    [Fact]
    public void All_MessageTypes_Serialize_As_Strings()
    {
        // Ensure enum serialization uses string names, not numbers
        var msg = IpcMessage.Request(IpcMessageType.RunAudit);
        var json = msg.Serialize();
        Assert.Contains("\"RunAudit\"", json);
        Assert.DoesNotContain("\"type\":2", json); // Not a number
    }

    [Fact]
    public void ChatPayload_Roundtrips()
    {
        var payload = new ChatPayload { Message = "What's my security score?" };
        var msg = IpcMessage.Request(IpcMessageType.SendChat, payload, "chat1");
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        Assert.NotNull(deserialized);
        var chatPayload = deserialized.GetPayload<ChatPayload>();
        Assert.NotNull(chatPayload);
        Assert.Equal("What's my security score?", chatPayload.Message);
    }

    [Fact]
    public void RunFixPayload_Roundtrips()
    {
        var payload = new RunFixPayload
        {
            FindingTitle = "Firewall Disabled",
            FixCommand = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            DryRun = true
        };

        var msg = IpcMessage.Request(IpcMessageType.RunFix, payload, "fix1");
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        var fixPayload = deserialized!.GetPayload<RunFixPayload>();
        Assert.NotNull(fixPayload);
        Assert.Equal("Firewall Disabled", fixPayload.FindingTitle);
        Assert.True(fixPayload.DryRun);
    }

    [Fact]
    public void ScanProgressPayload_Roundtrips()
    {
        var payload = new ScanProgressPayload { Module = "Firewall", Current = 3, Total = 13 };
        var msg = IpcMessage.Event(IpcMessageType.ScanProgress, payload);
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        var progress = deserialized!.GetPayload<ScanProgressPayload>();
        Assert.NotNull(progress);
        Assert.Equal("Firewall", progress.Module);
        Assert.Equal(3, progress.Current);
        Assert.Equal(13, progress.Total);
    }

    [Fact]
    public void Config_Snapshot_Roundtrips()
    {
        var config = new AgentConfigSnapshot
        {
            ScanIntervalHours = 2.5,
            AutoFixCritical = true,
            AutoFixWarnings = false,
            RiskTolerance = "Low",
            ModuleToggles = new Dictionary<string, bool> { ["ProcessMonitor"] = false },
            MaxThreatLogSize = 500,
            NotifyOnCriticalThreats = true,
            NotifyOnScanComplete = false
        };

        var msg = IpcMessage.Response(IpcMessageType.ConfigResponse, config, "cfg1");
        var json = msg.Serialize();
        var deserialized = IpcMessage.Deserialize(json);

        var snapshot = deserialized!.GetPayload<AgentConfigSnapshot>();
        Assert.NotNull(snapshot);
        Assert.Equal(2.5, snapshot.ScanIntervalHours);
        Assert.True(snapshot.AutoFixCritical);
        Assert.Equal("Low", snapshot.RiskTolerance);
        Assert.False(snapshot.ModuleToggles["ProcessMonitor"]);
    }
}
