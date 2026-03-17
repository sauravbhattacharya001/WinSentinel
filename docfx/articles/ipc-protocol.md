# IPC Protocol Reference

WinSentinel uses a **JSON-over-named-pipe** protocol for communication between the Agent (Windows Service) and the Dashboard (WPF app). This document describes the wire format, message types, and interaction patterns.

## Transport

- **Pipe name:** `WinSentinel` (full path: `\\.\pipe\WinSentinel`)
- **Direction:** Bidirectional — the agent is the server, the dashboard is the client.
- **Framing:** One JSON message per line (newline-delimited JSON, aka NDJSON). Each message is a complete `IpcMessage` object followed by `\n`.
- **Encoding:** UTF-8.

## Message Envelope

Every message uses the same envelope structure:

```json
{
  "type": "StatusResponse",
  "requestId": "a1b2c3d4",
  "payload": { ... },
  "error": null,
  "timestamp": "2026-03-16T12:00:00+00:00"
}
```

| Field       | Type            | Description |
|:------------|:----------------|:------------|
| `type`      | `string` (enum) | Message type — determines how `payload` is interpreted. |
| `requestId` | `string?`       | Correlation ID for request/response matching. Requests generate an 8-char hex ID; responses echo it back. Events have no `requestId`. |
| `payload`   | `object?`       | Type-specific JSON payload. May be `null` for simple messages like `Ping`/`Pong`. |
| `error`     | `string?`       | Error description (only set when `type` is `Error`). |
| `timestamp` | `string`        | ISO 8601 timestamp (UTC). |

## Message Types

### Requests (Dashboard → Agent)

| Type | Payload | Description |
|:-----|:--------|:------------|
| `GetStatus` | *none* | Request current agent status (uptime, threat count, active modules). |
| `RunAudit` | *none* | Trigger a full security audit scan. |
| `RunFix` | `RunFixPayload` | Execute a remediation command for a specific finding. |
| `GetThreats` | *none* | Get the current list of detected threats. |
| `GetConfig` | *none* | Get the agent's configuration. |
| `SetConfig` | Config object | Update agent configuration. |
| `SendChat` | `ChatPayload` | Send a chat message to the agent's natural language handler. |
| `Subscribe` | *none* | Subscribe to real-time event push notifications. |
| `Unsubscribe` | *none* | Unsubscribe from push events. |
| `Ping` | *none* | Health check. |
| `GetPolicy` | *none* | Get the current response policy (rules + overrides). |
| `SetPolicy` | `PolicyPayload` | Update the response policy. |

### Responses (Agent → Dashboard)

| Type | Payload | Description |
|:-----|:--------|:------------|
| `StatusResponse` | Status object | Current agent status. |
| `AuditStarted` | *none* | Acknowledgment that an audit has started. |
| `AuditCompleted` | Audit results | Full audit results with findings per module. |
| `FixResult` | Fix result | Outcome of a `RunFix` request. |
| `ThreatsResponse` | Threat list | Current threat events. |
| `ConfigResponse` | Config object | Current configuration. |
| `ChatResponse` | `ChatResponsePayload` | Agent's reply to a chat message. May include suggested actions, threat events, and security score. |
| `Subscribed` | *none* | Confirmation of event subscription. |
| `Unsubscribed` | *none* | Confirmation of event unsubscription. |
| `Error` | *none* | Error response — check the `error` field. |
| `Pong` | *none* | Response to `Ping`. |
| `PolicyResponse` | `PolicyPayload` | Current response policy. |

### Pushed Events (Agent → Dashboard)

These are sent asynchronously to subscribed clients. They have no `requestId`.

| Type | Payload | Description |
|:-----|:--------|:------------|
| `ThreatDetected` | `ThreatEvent` | A new threat was detected by a real-time monitor or audit module. |
| `ScanProgress` | `ScanProgressPayload` | Audit scan progress update (module name, current/total). |
| `AgentShutdown` | *none* | The agent is shutting down. |

## Payload Types

### RunFixPayload

```json
{
  "findingTitle": "Windows Defender Real-Time Protection Disabled",
  "fixCommand": "Set-MpPreference -DisableRealtimeMonitoring $false",
  "dryRun": false
}
```

### ChatPayload

```json
{
  "message": "what threats were detected in the last hour?"
}
```

### ChatResponsePayload

```json
{
  "text": "I found 3 threats in the last hour...",
  "suggestedActions": [
    { "label": "Show details", "command": "threats detail" },
    { "label": "Auto-fix all", "command": "fix all" }
  ],
  "threatEvents": [
    {
      "id": "a1b2c3d4e5f6",
      "timestamp": "2026-03-16T11:30:00+00:00",
      "source": "ProcessMonitor",
      "severity": "High",
      "title": "Unsigned process from temp directory",
      "responseTaken": "Alert sent to UI"
    }
  ],
  "securityScore": 72,
  "actionPerformed": false,
  "actionId": null,
  "category": "ThreatList"
}
```

### ScanProgressPayload

```json
{
  "module": "NetworkAudit",
  "current": 5,
  "total": 13
}
```

### PolicyPayload

```json
{
  "rules": [
    {
      "category": "ProcessMonitor",
      "severity": "Critical",
      "titlePattern": null,
      "action": "AutoFix",
      "allowAutoFix": true,
      "priority": 100
    }
  ],
  "userOverrides": [
    {
      "threatTitle": "Remote Desktop enabled",
      "source": "RemoteAccessAudit",
      "overrideAction": "AlwaysIgnore",
      "createdAt": "2026-03-15T10:00:00+00:00"
    }
  ],
  "riskTolerance": "Medium"
}
```

## Interaction Patterns

### Request-Response

```
Dashboard                              Agent
   │                                      │
   │── GetStatus (reqId: "abc123") ──────►│
   │                                      │
   │◄── StatusResponse (reqId: "abc123") ─│
   │                                      │
```

### Subscribe + Push Events

```
Dashboard                              Agent
   │                                      │
   │── Subscribe ────────────────────────►│
   │◄── Subscribed ──────────────────────│
   │                                      │
   │     ... time passes ...              │
   │                                      │
   │◄── ThreatDetected (no reqId) ───────│
   │◄── ThreatDetected (no reqId) ───────│
   │                                      │
   │── Unsubscribe ──────────────────────►│
   │◄── Unsubscribed ───────────────────│
```

### Chat Interaction

```
Dashboard                              Agent
   │                                      │
   │── SendChat ("scan now") ────────────►│
   │◄── ChatResponse ───────────────────│
   │     (text + suggestedActions)        │
   │                                      │
   │── SendChat ("fix all critical") ────►│
   │◄── ChatResponse ───────────────────│
   │     (actionPerformed: true)          │
   │                                      │
```

## Error Handling

If the agent cannot process a request, it returns an `Error` message with the original `requestId`:

```json
{
  "type": "Error",
  "requestId": "abc123",
  "error": "Audit already in progress",
  "timestamp": "2026-03-16T12:00:00+00:00"
}
```

## Security Considerations

- The named pipe is **local-only** — no network exposure.
- Any local process can connect to the pipe. The agent validates commands against the configured response policy before executing remediation actions.
- The `RunFix` command passes through `InputSanitizer.CheckDangerousCommand()` before execution.
- User overrides and policy changes are persisted to `%LocalAppData%\WinSentinel\response-policy.json`.

## Implementation

The protocol is implemented in:
- `src/WinSentinel.Agent/Ipc/IpcMessage.cs` — Message types, envelope, serialization
- `src/WinSentinel.Agent/Services/IpcServer.cs` — Agent-side pipe server
- `src/WinSentinel.App/Services/AgentConnectionService.cs` — Dashboard-side pipe client
