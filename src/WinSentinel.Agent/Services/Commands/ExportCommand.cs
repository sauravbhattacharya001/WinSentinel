using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services.Commands;

public sealed class ExportCommand : ChatCommandBase
{
    public override string[] Triggers => ["export", "report", "generate report"];

    public override async Task<ChatResponsePayload> ExecuteAsync(string input, ChatContext context)
    {
        try
        {
            var engine = new AuditEngine();
            var report = await engine.RunFullAuditAsync(cancellationToken: CancellationToken.None);
            var generator = new ReportGenerator();

            var dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");
            Directory.CreateDirectory(dataDir);
            var reportPath = Path.Combine(dataDir, $"WinSentinel-Report-{DateTime.Now:yyyyMMdd-HHmmss}.html");

            var html = generator.GenerateHtmlReport(report);
            await File.WriteAllTextAsync(reportPath, html);

            return new ChatResponsePayload
            {
                Text = $"📄 **Report generated!**\nSaved to: `{reportPath}`\nScore: {report.SecurityScore}/100",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SecurityScore = report.SecurityScore,
                SuggestedActions = { new SuggestedAction { Label = "📊 Status", Command = "status" } }
            };
        }
        catch (Exception ex)
        {
            return SimpleResponse($"❌ Report generation failed: {ex.Message}", ChatResponseCategory.Error);
        }
    }
}
