using System.Text.Json;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using static WinSentinel.Core.Services.FileIntegrityMonitor;

namespace WinSentinel.Tests.Services;

public class FileIntegrityMonitorTests
{
    // --- Hash Computation ---

    [Fact]
    public void ComputeHash_EmptyData_ReturnsKnownSha256()
    {
        var hash = ComputeHash(Array.Empty<byte>());
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    [Fact]
    public void ComputeHash_SameData_ReturnsSameHash()
    {
        var data = "hello world"u8.ToArray();
        Assert.Equal(ComputeHash(data), ComputeHash(data));
    }

    [Fact]
    public void ComputeHash_DifferentData_ReturnsDifferentHash()
    {
        var a = ComputeHash("abc"u8.ToArray());
        var b = ComputeHash("abd"u8.ToArray());
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ComputeHash_ReturnsLowercaseHex()
    {
        var hash = ComputeHash("test"u8.ToArray());
        Assert.Equal(hash, hash.ToLowerInvariant());
        Assert.Equal(64, hash.Length);
    }

    // --- Snapshot Creation ---

    [Fact]
    public void CreateSnapshot_SetsAllFields()
    {
        var data = "file content"u8.ToArray();
        var ts = DateTimeOffset.Parse("2026-01-15T10:00:00Z");
        var snap = CreateSnapshot(@"C:\test.txt", data, ts, isReadOnly: true);

        Assert.Equal(@"C:\test.txt", snap.Path);
        Assert.Equal(ComputeHash(data), snap.Sha256);
        Assert.Equal(data.Length, snap.SizeBytes);
        Assert.Equal(ts, snap.LastModifiedUtc);
        Assert.True(snap.IsReadOnly);
        Assert.True(snap.Exists);
    }

    [Fact]
    public void CreateSnapshot_EmptyFile_Works()
    {
        var snap = CreateSnapshot(@"C:\empty.dat", Array.Empty<byte>(), DateTimeOffset.UtcNow);
        Assert.Equal(0, snap.SizeBytes);
        Assert.NotEmpty(snap.Sha256);
    }

    // --- Baseline Creation ---

    [Fact]
    public void CreateBaseline_EmptySnapshots_CreatesEmptyBaseline()
    {
        var baseline = CreateBaseline(Array.Empty<FileSnapshot>(), "TESTPC");
        Assert.Empty(baseline.Files);
        Assert.Equal("TESTPC", baseline.MachineName);
    }

    [Fact]
    public void CreateBaseline_MultipleFiles_AllPresent()
    {
        var snaps = new[]
        {
            CreateSnapshot(@"C:\a.txt", "a"u8.ToArray(), DateTimeOffset.UtcNow),
            CreateSnapshot(@"C:\b.txt", "b"u8.ToArray(), DateTimeOffset.UtcNow),
            CreateSnapshot(@"C:\c.txt", "c"u8.ToArray(), DateTimeOffset.UtcNow),
        };
        var baseline = CreateBaseline(snaps);
        Assert.Equal(3, baseline.Files.Count);
        Assert.True(baseline.Files.ContainsKey(@"C:\a.txt"));
    }

    [Fact]
    public void CreateBaseline_DuplicatePaths_LastWins()
    {
        var ts = DateTimeOffset.UtcNow;
        var snaps = new[]
        {
            CreateSnapshot(@"C:\a.txt", "v1"u8.ToArray(), ts),
            CreateSnapshot(@"C:\a.txt", "v2"u8.ToArray(), ts),
        };
        var baseline = CreateBaseline(snaps);
        Assert.Single(baseline.Files);
        Assert.Equal(ComputeHash("v2"u8.ToArray()), baseline.Files[@"C:\a.txt"].Sha256);
    }

    [Fact]
    public void CreateBaseline_CaseInsensitivePaths()
    {
        var snaps = new[]
        {
            CreateSnapshot(@"C:\Test.TXT", "data"u8.ToArray(), DateTimeOffset.UtcNow),
        };
        var baseline = CreateBaseline(snaps);
        Assert.True(baseline.Files.ContainsKey(@"c:\test.txt"));
    }

    // --- Compare: No Changes ---

    [Fact]
    public void Compare_IdenticalState_ReportsClean()
    {
        var ts = DateTimeOffset.UtcNow;
        var snap = CreateSnapshot(@"C:\test.exe", "content"u8.ToArray(), ts);
        var baseline = CreateBaseline(new[] { snap });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [snap.Path] = snap,
        };

        var report = Compare(baseline, current);
        Assert.True(report.IsClean);
        Assert.Equal(0, report.Changes.Count);
        Assert.Equal(Severity.Pass, report.OverallSeverity);
    }

    [Fact]
    public void Compare_EmptyBaseline_EmptyCurrent_Clean()
    {
        var baseline = CreateBaseline(Array.Empty<FileSnapshot>());
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);
        var report = Compare(baseline, current);
        Assert.True(report.IsClean);
    }

    // --- Compare: Modified ---

    [Fact]
    public void Compare_ModifiedFile_DetectedAsModified()
    {
        var ts = DateTimeOffset.UtcNow;
        var original = CreateSnapshot(@"C:\app.dll", "original"u8.ToArray(), ts);
        var modified = CreateSnapshot(@"C:\app.dll", "modified"u8.ToArray(), ts);
        var baseline = CreateBaseline(new[] { original });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [modified.Path] = modified,
        };

        var report = Compare(baseline, current);
        Assert.False(report.IsClean);
        Assert.Equal(1, report.ModifiedCount);
        var change = report.Changes[0];
        Assert.Equal(ChangeKind.Modified, change.Kind);
        Assert.Equal(original.Sha256, change.BaselineHash);
        Assert.Equal(modified.Sha256, change.CurrentHash);
    }

    [Fact]
    public void Compare_ModifiedCriticalFile_CriticalSeverity()
    {
        var ts = DateTimeOffset.UtcNow;
        var original = CreateSnapshot(@"C:\Windows\System32\lsass.exe", "orig"u8.ToArray(), ts);
        var modified = CreateSnapshot(@"C:\Windows\System32\lsass.exe", "hacked"u8.ToArray(), ts);
        var baseline = CreateBaseline(new[] { original });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [modified.Path] = modified,
        };

        var report = Compare(baseline, current);
        Assert.Equal(Severity.Critical, report.Changes[0].Severity);
        Assert.Equal(Severity.Critical, report.OverallSeverity);
    }

    [Fact]
    public void Compare_ModifiedNonCriticalFile_WarningSeverity()
    {
        var ts = DateTimeOffset.UtcNow;
        var original = CreateSnapshot(@"C:\Program Files\app.exe", "orig"u8.ToArray(), ts);
        var modified = CreateSnapshot(@"C:\Program Files\app.exe", "new"u8.ToArray(), ts);
        var baseline = CreateBaseline(new[] { original });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [modified.Path] = modified,
        };

        var report = Compare(baseline, current);
        Assert.Equal(Severity.Warning, report.Changes[0].Severity);
    }

    // --- Compare: Deleted ---

    [Fact]
    public void Compare_DeletedFile_DetectedAsDeleted()
    {
        var snap = CreateSnapshot(@"C:\important.sys", "data"u8.ToArray(), DateTimeOffset.UtcNow);
        var baseline = CreateBaseline(new[] { snap });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);

        var report = Compare(baseline, current);
        Assert.Equal(1, report.DeletedCount);
        Assert.Equal(ChangeKind.Deleted, report.Changes[0].Kind);
    }

    [Fact]
    public void Compare_DeletedCriticalFile_CriticalSeverity()
    {
        var snap = CreateSnapshot(@"C:\Windows\System32\ntoskrnl.exe", "kern"u8.ToArray(), DateTimeOffset.UtcNow);
        var baseline = CreateBaseline(new[] { snap });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);

        var report = Compare(baseline, current);
        Assert.Equal(Severity.Critical, report.Changes[0].Severity);
    }

    [Fact]
    public void Compare_FileMarkedNotExists_TreatedAsDeleted()
    {
        var snap = CreateSnapshot(@"C:\test.dll", "data"u8.ToArray(), DateTimeOffset.UtcNow);
        var baseline = CreateBaseline(new[] { snap });
        var gone = new FileSnapshot { Path = @"C:\test.dll", Exists = false };
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [gone.Path] = gone,
        };

        var report = Compare(baseline, current);
        Assert.Equal(1, report.DeletedCount);
    }

    // --- Compare: Added ---

    [Fact]
    public void Compare_NewFile_DetectedAsAdded()
    {
        var baseline = CreateBaseline(Array.Empty<FileSnapshot>());
        var newFile = CreateSnapshot(@"C:\suspicious.exe", "payload"u8.ToArray(), DateTimeOffset.UtcNow);
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [newFile.Path] = newFile,
        };

        var report = Compare(baseline, current);
        Assert.Equal(1, report.AddedCount);
        Assert.Equal(ChangeKind.Added, report.Changes[0].Kind);
    }

    [Fact]
    public void Compare_AddedFileNotExists_NotReported()
    {
        var baseline = CreateBaseline(Array.Empty<FileSnapshot>());
        var ghost = new FileSnapshot { Path = @"C:\ghost.exe", Exists = false };
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [ghost.Path] = ghost,
        };

        var report = Compare(baseline, current);
        Assert.True(report.IsClean);
    }

    // --- Compare: Permission Changes ---

    [Fact]
    public void Compare_PermissionChanged_Detected()
    {
        var ts = DateTimeOffset.UtcNow;
        var data = "same"u8.ToArray();
        var original = CreateSnapshot(@"C:\config.xml", data, ts, isReadOnly: true);
        var changed = CreateSnapshot(@"C:\config.xml", data, ts, isReadOnly: false);
        var baseline = CreateBaseline(new[] { original });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [changed.Path] = changed,
        };

        var report = Compare(baseline, current);
        Assert.Equal(1, report.PermissionChangedCount);
        Assert.Equal(ChangeKind.PermissionChanged, report.Changes[0].Kind);
        Assert.True(report.Changes[0].PermissionChanged);
        Assert.Equal(Severity.Info, report.Changes[0].Severity);
    }

    [Fact]
    public void Compare_HashAndPermissionBothChanged_ReportsModified()
    {
        var ts = DateTimeOffset.UtcNow;
        var original = CreateSnapshot(@"C:\app.exe", "v1"u8.ToArray(), ts, isReadOnly: true);
        var changed = CreateSnapshot(@"C:\app.exe", "v2"u8.ToArray(), ts, isReadOnly: false);
        var baseline = CreateBaseline(new[] { original });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [changed.Path] = changed,
        };

        var report = Compare(baseline, current);
        Assert.Equal(1, report.ModifiedCount);
        Assert.Equal(0, report.PermissionChangedCount);
    }

    // --- Compare: Mixed Changes ---

    [Fact]
    public void Compare_MixedChanges_AllDetected()
    {
        var ts = DateTimeOffset.UtcNow;
        var kept = CreateSnapshot(@"C:\kept.dll", "same"u8.ToArray(), ts);
        var modOrig = CreateSnapshot(@"C:\mod.exe", "old"u8.ToArray(), ts);
        var modNew = CreateSnapshot(@"C:\mod.exe", "new"u8.ToArray(), ts);
        var deleted = CreateSnapshot(@"C:\gone.sys", "bye"u8.ToArray(), ts);
        var added = CreateSnapshot(@"C:\new.bat", "hi"u8.ToArray(), ts);

        var baseline = CreateBaseline(new[] { kept, modOrig, deleted });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [kept.Path] = kept,
            [modNew.Path] = modNew,
            [added.Path] = added,
        };

        var report = Compare(baseline, current);
        Assert.Equal(3, report.Changes.Count);
        Assert.Equal(1, report.ModifiedCount);
        Assert.Equal(1, report.AddedCount);
        Assert.Equal(1, report.DeletedCount);
        Assert.Equal(3, report.TotalBaselineFiles);
        Assert.Equal(3, report.TotalFilesScanned);
    }

    // --- Compare: Report Counters ---

    [Fact]
    public void Compare_CountsCorrect()
    {
        var ts = DateTimeOffset.UtcNow;
        var baseline = CreateBaseline(new[]
        {
            CreateSnapshot(@"C:\a.exe", "a"u8.ToArray(), ts),
            CreateSnapshot(@"C:\b.exe", "b"u8.ToArray(), ts),
            CreateSnapshot(@"C:\c.exe", "c"u8.ToArray(), ts),
        });

        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [@"C:\a.exe"] = CreateSnapshot(@"C:\a.exe", "a_mod"u8.ToArray(), ts),
            [@"C:\b.exe"] = CreateSnapshot(@"C:\b.exe", "b"u8.ToArray(), ts),
            [@"C:\d.exe"] = CreateSnapshot(@"C:\d.exe", "d"u8.ToArray(), ts),
        };

        var report = Compare(baseline, current);
        Assert.Equal(1, report.ModifiedCount);
        Assert.Equal(1, report.DeletedCount);
        Assert.Equal(1, report.AddedCount);
        Assert.False(report.IsClean);
    }

    // --- ToFindings ---

    [Fact]
    public void ToFindings_CleanReport_SinglePassFinding()
    {
        var report = new IntegrityReport
        {
            TotalFilesScanned = 10,
            BaselineTimeUtc = DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
        };

        var findings = ToFindings(report);
        Assert.Single(findings);
        Assert.Equal(Severity.Pass, findings[0].Severity);
        Assert.Contains("10", findings[0].Description);
    }

    [Fact]
    public void ToFindings_WithChanges_FindingsPerChangeAndSummary()
    {
        var report = new IntegrityReport
        {
            Changes =
            {
                new IntegrityChange
                {
                    FilePath = @"C:\mod.exe", Kind = ChangeKind.Modified,
                    Severity = Severity.Warning, Description = "modified"
                },
                new IntegrityChange
                {
                    FilePath = @"C:\del.sys", Kind = ChangeKind.Deleted,
                    Severity = Severity.Critical, Description = "deleted"
                },
            }
        };

        var findings = ToFindings(report);
        Assert.Equal(3, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void ToFindings_AllWarnings_SummaryIsWarning()
    {
        var report = new IntegrityReport
        {
            Changes =
            {
                new IntegrityChange
                {
                    FilePath = @"C:\a.dll", Kind = ChangeKind.Added,
                    Severity = Severity.Warning, Description = "new"
                },
            }
        };

        var findings = ToFindings(report);
        var summary = findings.Last();
        Assert.Equal(Severity.Warning, summary.Severity);
        Assert.Contains("1 change(s)", summary.Description);
    }

    [Fact]
    public void ToFindings_CriticalChange_SummaryIsCritical()
    {
        var report = new IntegrityReport
        {
            Changes =
            {
                new IntegrityChange
                {
                    FilePath = @"C:\lsass.exe", Kind = ChangeKind.Modified,
                    Severity = Severity.Critical, Description = "critical mod"
                },
            }
        };

        var findings = ToFindings(report);
        var summary = findings.Last();
        Assert.Equal(Severity.Critical, summary.Severity);
    }

    [Fact]
    public void ToFindings_IncludesRemediation()
    {
        var report = new IntegrityReport
        {
            Changes =
            {
                new IntegrityChange
                {
                    FilePath = @"C:\test.exe", Kind = ChangeKind.Modified,
                    Severity = Severity.Warning, Description = "test"
                },
            }
        };

        var findings = ToFindings(report);
        Assert.All(findings, f => Assert.NotNull(f.Remediation));
    }

    // --- Serialization ---

    [Fact]
    public void SerializeDeserialize_Baseline_Roundtrips()
    {
        var snaps = new[]
        {
            CreateSnapshot(@"C:\a.exe", "hello"u8.ToArray(), DateTimeOffset.Parse("2026-02-01T00:00:00Z")),
            CreateSnapshot(@"C:\b.dll", "world"u8.ToArray(), DateTimeOffset.Parse("2026-02-01T00:00:00Z"), true),
        };
        var baseline = CreateBaseline(snaps, "MYPC");

        var json = SerializeBaseline(baseline);
        Assert.NotEmpty(json);

        var restored = DeserializeBaseline(json);
        Assert.NotNull(restored);
        Assert.Equal("MYPC", restored!.MachineName);
        Assert.Equal(2, restored.Files.Count);
    }

    [Fact]
    public void DeserializeBaseline_InvalidJson_Throws()
    {
        Assert.Throws<JsonException>(() => DeserializeBaseline("not json"));
    }

    [Fact]
    public void SerializeBaseline_EmptyBaseline_ValidJson()
    {
        var baseline = CreateBaseline(Array.Empty<FileSnapshot>());
        var json = SerializeBaseline(baseline);
        var restored = DeserializeBaseline(json);
        Assert.NotNull(restored);
        Assert.Empty(restored!.Files);
    }

    // --- Critical File Detection ---

    [Theory]
    [InlineData(@"C:\Windows\System32\lsass.exe", true)]
    [InlineData(@"C:\Windows\System32\csrss.exe", true)]
    [InlineData(@"C:\Windows\System32\ntoskrnl.exe", true)]
    [InlineData(@"C:\Windows\System32\config\SAM", true)]
    [InlineData(@"C:\Windows\System32\config\SYSTEM", true)]
    [InlineData(@"C:\Windows\System32\config\SECURITY", true)]
    [InlineData(@"C:\Program Files\myapp.exe", false)]
    [InlineData(@"C:\random.dll", false)]
    public void Compare_CriticalFileDetection_CorrectSeverity(string path, bool isCritical)
    {
        var ts = DateTimeOffset.UtcNow;
        var original = CreateSnapshot(path, "orig"u8.ToArray(), ts);
        var modified = CreateSnapshot(path, "mod"u8.ToArray(), ts);
        var baseline = CreateBaseline(new[] { original });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [path] = modified,
        };

        var report = Compare(baseline, current);
        var expected = isCritical ? Severity.Critical : Severity.Warning;
        Assert.Equal(expected, report.Changes[0].Severity);
    }

    // --- Edge Cases ---

    [Fact]
    public void Compare_LargeNumberOfFiles_HandledCorrectly()
    {
        var ts = DateTimeOffset.UtcNow;
        var snaps = Enumerable.Range(0, 1000)
            .Select(i => CreateSnapshot($@"C:\files\file{i}.dll", System.Text.Encoding.UTF8.GetBytes($"content{i}"), ts))
            .ToArray();
        var baseline = CreateBaseline(snaps);

        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < 1000; i++)
        {
            var content = i % 10 == 0 ? $"modified{i}" : $"content{i}";
            current[$@"C:\files\file{i}.dll"] = CreateSnapshot(
                $@"C:\files\file{i}.dll", System.Text.Encoding.UTF8.GetBytes(content), ts);
        }

        var report = Compare(baseline, current);
        Assert.Equal(100, report.ModifiedCount);
        Assert.Equal(0, report.DeletedCount);
        Assert.Equal(0, report.AddedCount);
    }

    [Fact]
    public void Compare_SameHashDifferentTimestamp_StillClean()
    {
        var data = "test"u8.ToArray();
        var snap1 = CreateSnapshot(@"C:\test.exe", data, DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var snap2 = CreateSnapshot(@"C:\test.exe", data, DateTimeOffset.Parse("2026-02-01T00:00:00Z"));

        var baseline = CreateBaseline(new[] { snap1 });
        var current = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            [snap2.Path] = snap2,
        };

        var report = Compare(baseline, current);
        Assert.True(report.IsClean);
    }

    // --- Static Constants ---

    [Fact]
    public void DefaultMonitorPaths_NotEmpty()
    {
        Assert.NotEmpty(DefaultMonitorPaths);
        Assert.All(DefaultMonitorPaths, p => Assert.NotEmpty(p));
    }

    [Fact]
    public void DefaultMonitorDirectories_NotEmpty()
    {
        Assert.NotEmpty(DefaultMonitorDirectories);
    }

    [Fact]
    public void MonitoredExtensions_ContainsCommonTypes()
    {
        Assert.Contains(".exe", MonitoredExtensions);
        Assert.Contains(".dll", MonitoredExtensions);
        Assert.Contains(".sys", MonitoredExtensions);
        Assert.Contains(".ps1", MonitoredExtensions);
    }

    [Fact]
    public void MonitorConfig_Defaults()
    {
        var config = new MonitorConfig();
        Assert.Empty(config.FilePaths);
        Assert.Empty(config.DirectoryPaths);
        Assert.True(config.Recursive);
        Assert.NotEmpty(config.Extensions);
        Assert.Empty(config.ExcludePatterns);
    }

    // --- IntegrityReport Properties ---

    [Fact]
    public void IntegrityReport_EmptyChanges_AllCountsZero()
    {
        var report = new IntegrityReport();
        Assert.Equal(0, report.ModifiedCount);
        Assert.Equal(0, report.AddedCount);
        Assert.Equal(0, report.DeletedCount);
        Assert.Equal(0, report.PermissionChangedCount);
        Assert.True(report.IsClean);
        Assert.Equal(Severity.Pass, report.OverallSeverity);
    }
}
