using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSentinel.Agent.Ipc;

/// <summary>
/// IPC message types for the WinSentinel named pipe protocol.
/// </summary>
public enum IpcMessageType
{
    // Requests (UI → Agent)
    GetStatus,
    RunAudit,
    RunFix,
    GetThreats,
    GetConfig,
    SetConfig,
    SendChat,
    Subscribe,
    Unsubscribe,
    Ping,
    GetPolicy,
    SetPolicy,

    // Responses (Agent → UI)
    StatusResponse,
    AuditStarted,
    AuditCompleted,
    FixResult,
    ThreatsResponse,
    ConfigResponse,
    ChatResponse,
    Subscribed,
    Error,
    Pong,
    PolicyResponse,

    // Events (Agent → UI, pushed)
    ThreatDetected,
    ScanProgress,
    AgentShutdown
}

/// <summary>
/// Envelope for all IPC messages. JSON-serialized, one per line over the pipe.
/// </summary>
public class IpcMessage
{
    public IpcMessageType Type { get; set; }

    /// <summary>Correlation ID for request/response matching.</summary>
    public string? RequestId { get; set; }

    /// <summary>JSON payload — interpreted based on Type.</summary>
    public JsonElement? Payload { get; set; }

    /// <summary>Error message (when Type == Error).</summary>
    public string? Error { get; set; }

    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    // ── Factory methods ──

    public static IpcMessage Request(IpcMessageType type, object? payload = null, string? requestId = null) => new()
    {
        Type = type,
        RequestId = requestId ?? Guid.NewGuid().ToString("N")[..8],
        Payload = payload != null ? JsonSerializer.SerializeToElement(payload, JsonOptions) : null
    };

    public static IpcMessage Response(IpcMessageType type, object? payload = null, string? requestId = null) => new()
    {
        Type = type,
        RequestId = requestId,
        Payload = payload != null ? JsonSerializer.SerializeToElement(payload, JsonOptions) : null
    };

    public static IpcMessage ErrorResponse(string error, string? requestId = null) => new()
    {
        Type = IpcMessageType.Error,
        RequestId = requestId,
        Error = error
    };

    public static IpcMessage Event(IpcMessageType type, object? payload = null) => new()
    {
        Type = type,
        Payload = payload != null ? JsonSerializer.SerializeToElement(payload, JsonOptions) : null
    };

    // ── Serialization ──

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string Serialize() => JsonSerializer.Serialize(this, JsonOptions);

    public static IpcMessage? Deserialize(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<IpcMessage>(json, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Deserialize the payload to a specific type.</summary>
    public T? GetPayload<T>()
    {
        if (Payload == null) return default;
        return JsonSerializer.Deserialize<T>(Payload.Value.GetRawText(), JsonOptions);
    }
}

/// <summary>Payload for RunFix requests.</summary>
public class RunFixPayload
{
    public string? FindingTitle { get; set; }
    public string? FixCommand { get; set; }
    public bool DryRun { get; set; }
}

/// <summary>Payload for SendChat requests.</summary>
public class ChatPayload
{
    public string Message { get; set; } = "";
}

/// <summary>Rich response from agent chat handler.</summary>
public class ChatResponsePayload
{
    /// <summary>Main text response.</summary>
    public string Text { get; set; } = "";

    /// <summary>Suggested follow-up actions (displayed as buttons).</summary>
    public List<SuggestedAction> SuggestedActions { get; set; } = new();

    /// <summary>Threat events included in the response (for rich display).</summary>
    public List<ChatThreatEvent> ThreatEvents { get; set; } = new();

    /// <summary>Security score (if applicable to the response).</summary>
    public int? SecurityScore { get; set; }

    /// <summary>Whether an action was performed (for undo support).</summary>
    public bool ActionPerformed { get; set; }

    /// <summary>ID of the action performed (for undo).</summary>
    public string? ActionId { get; set; }

    /// <summary>Response category for UI formatting.</summary>
    public ChatResponseCategory Category { get; set; } = ChatResponseCategory.General;
}

/// <summary>Suggested action button for chat responses.</summary>
public class SuggestedAction
{
    public string Label { get; set; } = "";
    public string Command { get; set; } = "";
}

/// <summary>Simplified threat event for chat display.</summary>
public class ChatThreatEvent
{
    public string Id { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; }
    public string Source { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Title { get; set; } = "";
    public string? ResponseTaken { get; set; }
}

/// <summary>Categories for chat response formatting.</summary>
public enum ChatResponseCategory
{
    General,
    Status,
    ThreatList,
    AuditResult,
    ActionConfirmation,
    Error,
    Help
}

/// <summary>Payload for scan progress events.</summary>
public class ScanProgressPayload
{
    public string Module { get; set; } = "";
    public int Current { get; set; }
    public int Total { get; set; }
}

/// <summary>IPC payload for response policy data.</summary>
public class PolicyPayload
{
    public List<PolicyRulePayload> Rules { get; set; } = new();
    public List<UserOverridePayload> UserOverrides { get; set; } = new();
    public string RiskTolerance { get; set; } = "Medium";
}

/// <summary>Serializable policy rule for IPC.</summary>
public class PolicyRulePayload
{
    public string? Category { get; set; }
    public string? Severity { get; set; }
    public string? TitlePattern { get; set; }
    public string Action { get; set; } = "Log";
    public bool AllowAutoFix { get; set; } = true;
    public int Priority { get; set; }
}

/// <summary>Serializable user override for IPC.</summary>
public class UserOverridePayload
{
    public string ThreatTitle { get; set; } = "";
    public string? Source { get; set; }
    public string OverrideAction { get; set; } = "AlwaysIgnore";
    public DateTimeOffset CreatedAt { get; set; }
}
