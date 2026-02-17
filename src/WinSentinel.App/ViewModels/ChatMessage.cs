using System.Text.Json.Serialization;

namespace WinSentinel.App.ViewModels;

/// <summary>
/// Chat message model with support for rich agent responses.
/// Persisted in chat history JSON.
/// </summary>
public class ChatMessage
{
    public bool IsBot { get; set; }
    public string Text { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.Now;

    /// <summary>Response category for UI styling (General, Status, ThreatList, AuditResult, ActionConfirmation, Error, Help).</summary>
    public string? Category { get; set; }

    /// <summary>Security score (shown as progress bar).</summary>
    public int? SecurityScore { get; set; }

    /// <summary>Whether an action was performed (shows confirmation badge).</summary>
    public bool ActionPerformed { get; set; }

    /// <summary>Suggested follow-up actions.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ChatSuggestedAction>? SuggestedActions { get; set; }
}

/// <summary>
/// A suggested action button in a chat response.
/// </summary>
public class ChatSuggestedAction
{
    public string Label { get; set; } = "";
    public string Command { get; set; } = "";
}
