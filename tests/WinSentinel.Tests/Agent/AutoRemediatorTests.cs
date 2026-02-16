using Microsoft.Extensions.Logging.Abstractions;
using WinSentinel.Agent;
using WinSentinel.Agent.Services;

namespace WinSentinel.Tests.Agent;

public class AutoRemediatorTests
{
    private AutoRemediator CreateRemediator()
    {
        var logger = new NullLogger<AutoRemediator>();
        return new AutoRemediator(logger);
    }

    // ── Kill process tests ──

    [Fact]
    public void KillProcess_NonExistentPid_ReturnsFailed()
    {
        var remediator = CreateRemediator();

        var result = remediator.KillProcess(99999, "nonexistent.exe", "threat-1");

        Assert.False(result.Success);
        Assert.Equal(RemediationAction.KillProcess, result.ActionType);
        Assert.Contains("nonexistent.exe", result.Target);
    }

    [Fact]
    public void KillProcess_RecordedInHistory()
    {
        var remediator = CreateRemediator();

        remediator.KillProcess(99999, "test.exe", "threat-1");

        var history = remediator.GetHistory();
        Assert.Single(history);
        Assert.Equal("threat-1", history[0].ThreatEventId);
    }

    // ── Quarantine file tests ──

    [Fact]
    public void QuarantineFile_NonExistentFile_ReturnsFailed()
    {
        var remediator = CreateRemediator();

        var result = remediator.QuarantineFile(@"C:\nonexistent\file.exe", "threat-2");

        Assert.False(result.Success);
        Assert.Equal(RemediationAction.QuarantineFile, result.ActionType);
        Assert.Contains("not found", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void QuarantineFile_ExistingFile_MovesToQuarantine()
    {
        var remediator = CreateRemediator();
        var tempFile = Path.GetTempFileName();

        try
        {
            File.WriteAllText(tempFile, "test content");

            var result = remediator.QuarantineFile(tempFile, "threat-3");

            Assert.True(result.Success);
            Assert.False(File.Exists(tempFile)); // Original should be gone
            Assert.NotNull(result.UndoCommand);
            Assert.True(result.UndoMetadata.ContainsKey("QuarantinePath"));

            // Verify quarantined file exists
            var quarantinePath = result.UndoMetadata["QuarantinePath"];
            Assert.True(File.Exists(quarantinePath));

            // Cleanup quarantine
            File.Delete(quarantinePath);
            var metaPath = result.UndoMetadata.GetValueOrDefault("MetadataPath", "");
            if (File.Exists(metaPath)) File.Delete(metaPath);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    // ── Undo quarantine tests ──

    [Fact]
    public void Undo_QuarantinedFile_RestoresOriginal()
    {
        var remediator = CreateRemediator();
        var tempFile = Path.Combine(Path.GetTempPath(), $"winsentinel_test_{Guid.NewGuid():N}.txt");

        try
        {
            File.WriteAllText(tempFile, "restore me");

            var quarantineResult = remediator.QuarantineFile(tempFile, "threat-4");
            Assert.True(quarantineResult.Success);
            Assert.False(File.Exists(tempFile));

            var undoResult = remediator.Undo(quarantineResult.Id);
            Assert.True(undoResult.Success);
            Assert.True(File.Exists(tempFile));
            Assert.Equal("restore me", File.ReadAllText(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void Undo_NonExistentRemediation_ReturnsFailed()
    {
        var remediator = CreateRemediator();

        var result = remediator.Undo("nonexistent-id");

        Assert.False(result.Success);
        Assert.Contains("not found", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Undo_AlreadyUndone_ReturnsFailed()
    {
        var remediator = CreateRemediator();
        var tempFile = Path.Combine(Path.GetTempPath(), $"winsentinel_test_{Guid.NewGuid():N}.txt");

        try
        {
            File.WriteAllText(tempFile, "test");

            var quarantineResult = remediator.QuarantineFile(tempFile, "threat-5");
            remediator.Undo(quarantineResult.Id);

            // Try to undo again
            var secondUndo = remediator.Undo(quarantineResult.Id);
            Assert.False(secondUndo.Success);
            Assert.Contains("already undone", secondUndo.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    // ── ExecuteFixCommand tests ──

    [Fact]
    public void ExecuteFixCommand_NoCommand_ReturnsFailed()
    {
        var remediator = CreateRemediator();
        var threat = new ThreatEvent
        {
            Title = "Test Threat",
            FixCommand = null
        };

        var result = remediator.ExecuteFixCommand(threat);
        Assert.False(result.Success);
    }

    [Fact]
    public void ExecuteFixCommand_SimpleCommand_Executes()
    {
        var remediator = CreateRemediator();
        var threat = new ThreatEvent
        {
            Title = "Test Threat",
            FixCommand = "echo hello"
        };

        var result = remediator.ExecuteFixCommand(threat);
        Assert.True(result.Success);
    }

    // ── History tests ──

    [Fact]
    public void GetRecent_ReturnsNewestFirst()
    {
        var remediator = CreateRemediator();

        remediator.KillProcess(99999, "first.exe", "t-1");
        remediator.KillProcess(99998, "second.exe", "t-2");
        remediator.KillProcess(99997, "third.exe", "t-3");

        var recent = remediator.GetRecent(2);
        Assert.Equal(2, recent.Count);
        Assert.True(recent[0].Timestamp >= recent[1].Timestamp);
    }
}
