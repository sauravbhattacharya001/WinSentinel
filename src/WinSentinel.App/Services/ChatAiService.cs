using WinSentinel.Core.Services;

namespace WinSentinel.App.Services;

/// <summary>
/// Thin wrapper around WinSentinel.Core.SecurityAdvisor for the App layer.
/// Manages the singleton SecurityAdvisor instance with full audit context.
/// </summary>
public class ChatAiService
{
    private readonly SecurityAdvisor _advisor;

    public ChatAiService()
    {
        var engine = new AuditEngine();
        var history = new AuditHistoryService();
        engine.SetHistoryService(history);
        var fixEngine = new FixEngine();
        _advisor = new SecurityAdvisor(engine, fixEngine, history);
    }

    public ChatAiService(SecurityAdvisor advisor)
    {
        _advisor = advisor;
    }

    /// <summary>The underlying SecurityAdvisor.</summary>
    public SecurityAdvisor Advisor => _advisor;

    /// <summary>
    /// Get a response for a user message.
    /// </summary>
    public async Task<string> GetResponseAsync(string userMessage, CancellationToken ct = default)
    {
        var response = await _advisor.AskAsync(userMessage, ct);
        return response.Message;
    }
}
