using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Monitors critical system files for unauthorized modifications by computing
/// SHA-256 hashes and comparing against a stored baseline.
/// Detects file additions, deletions, modifications, and permission changes.
/// </summary>
public class FileIntegrityMonitor
{
    /// <summary>
    /// Default critical system paths to monitor on Windows.
    /// </summary>
    public static readonly string[] DefaultMonitorPaths = new[]
    {
        @"C:\Windows\System32\drivers\etc\hosts",
        @"C:\Windows\System32\config\SAM",
        @"C:\Windows\System32\config\SYSTEM",
        @"C:\Windows\System32\config\SECURITY",
        @"C:\Windows\System32\cmd.exe",
        @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        @"C:\Windows\System32\svchost.exe",
        @"C:\Windows\System32\lsass.exe",
        @"C:\Windows\System32\csrss.exe",
        @"C:\Windows\System32\winlogon.exe",
        @"C:\Windows\System32\services.exe",
        @"C:\Windows\System32\ntoskrnl.exe",
    };

    /// <summary>
    /// Default directories to recursively monitor (e.g., for DLL injection detection).
    /// </summary>
    public static readonly string[] DefaultMonitorDirectories = new[]
    {
        @"C:\Windows\System32\drivers",
    };

    /// <summary>
    /// File extensions to include when scanning directories.
    /// </summary>
    public static readonly string[] MonitoredExtensions = new[]
    {
        ".sys", ".dll", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js"
    };

    /// <summary>
    /// Represents a single file's integrity snapshot.
    /// </summary>
    public sealed class FileSnapshot
    {
        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;

        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = string.Empty;

        [JsonPropertyName("sizeBytes")]
        public long SizeBytes { get; set; }

        [JsonPropertyName("lastModifiedUtc")]
        public DateTimeOffset LastModifiedUtc { get; set; }

        [JsonPropertyName("isReadOnly")]
        public bool IsReadOnly { get; set; }

        [JsonPropertyName("exists")]
        public bool Exists { get; set; } = true;
    }

    /// <summary>
    /// A complete baseline of file integrity data.
    /// </summary>
    public sealed class IntegrityBaseline
    {
        [JsonPropertyName("createdUtc")]
        public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

        [JsonPropertyName("machineName")]
        public string MachineName { get; set; } = string.Empty;

        [JsonPropertyName("files")]
        public Dictionary<string, FileSnapshot> Files { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Describes a single integrity change.
    /// </summary>
    public sealed class IntegrityChange
    {
        public string FilePath { get; set; } = string.Empty;
        public ChangeKind Kind { get; set; }
        public string? BaselineHash { get; set; }
        public string? CurrentHash { get; set; }
        public long? BaselineSize { get; set; }
        public long? CurrentSize { get; set; }
        public bool PermissionChanged { get; set; }
        public Severity Severity { get; set; } = Severity.Warning;
        public string Description { get; set; } = string.Empty;
    }

    public enum ChangeKind
    {
        Modified,
        Added,
        Deleted,
        PermissionChanged
    }

    /// <summary>
    /// Result of comparing current state against a baseline.
    /// </summary>
    public sealed class IntegrityReport
    {
        public DateTimeOffset ScanTimeUtc { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset BaselineTimeUtc { get; set; }
        public int TotalFilesScanned { get; set; }
        public int TotalBaselineFiles { get; set; }
        public List<IntegrityChange> Changes { get; set; } = new();
        public int ModifiedCount => Changes.Count(c => c.Kind == ChangeKind.Modified);
        public int AddedCount => Changes.Count(c => c.Kind == ChangeKind.Added);
        public int DeletedCount => Changes.Count(c => c.Kind == ChangeKind.Deleted);
        public int PermissionChangedCount => Changes.Count(c => c.Kind == ChangeKind.PermissionChanged);
        public bool IsClean => Changes.Count == 0;
        public Severity OverallSeverity => Changes.Count == 0
            ? Severity.Pass
            : Changes.Max(c => c.Severity);
    }

    /// <summary>
    /// Configuration for the monitor.
    /// </summary>
    public sealed class MonitorConfig
    {
        public List<string> FilePaths { get; set; } = new();
        public List<string> DirectoryPaths { get; set; } = new();
        public List<string> Extensions { get; set; } = new(MonitoredExtensions);
        public bool Recursive { get; set; } = true;
        public List<string> ExcludePatterns { get; set; } = new();
    }

    /// <summary>
    /// Well-known critical executables that should never be modified or replaced.
    /// Changes to these are Critical severity.
    /// </summary>
    private static readonly HashSet<string> CriticalFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntoskrnl.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
        "services.exe", "svchost.exe", "smss.exe", "wininit.exe",
        "SAM", "SYSTEM", "SECURITY"
    };

    // --- Core Logic (operates on data, fully testable) ---

    /// <summary>
    /// Compute SHA-256 hash of a byte array (testable without filesystem).
    /// </summary>
    public static string ComputeHash(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Create a snapshot from explicit data (for testing).
    /// </summary>
    public static FileSnapshot CreateSnapshot(string path, byte[] content,
        DateTimeOffset lastModified, bool isReadOnly = false)
    {
        return new FileSnapshot
        {
            Path = path,
            Sha256 = ComputeHash(content),
            SizeBytes = content.Length,
            LastModifiedUtc = lastModified,
            IsReadOnly = isReadOnly,
            Exists = true,
        };
    }

    /// <summary>
    /// Create a baseline from a collection of snapshots.
    /// </summary>
    public static IntegrityBaseline CreateBaseline(
        IEnumerable<FileSnapshot> snapshots, string machineName = "")
    {
        var baseline = new IntegrityBaseline
        {
            CreatedUtc = DateTimeOffset.UtcNow,
            MachineName = machineName,
        };
        foreach (var s in snapshots)
        {
            baseline.Files[s.Path] = s;
        }
        return baseline;
    }

    /// <summary>
    /// Compare current snapshots against a baseline and produce a report.
    /// This is the core analysis logic, fully testable with in-memory data.
    /// </summary>
    public static IntegrityReport Compare(
        IntegrityBaseline baseline,
        IReadOnlyDictionary<string, FileSnapshot> currentFiles)
    {
        var report = new IntegrityReport
        {
            BaselineTimeUtc = baseline.CreatedUtc,
            ScanTimeUtc = DateTimeOffset.UtcNow,
            TotalBaselineFiles = baseline.Files.Count,
            TotalFilesScanned = currentFiles.Count,
        };

        // Check each baseline file against current state
        foreach (var (path, baseSnap) in baseline.Files)
        {
            if (!currentFiles.TryGetValue(path, out var current) || !current.Exists)
            {
                var fileName = System.IO.Path.GetFileName(path);
                report.Changes.Add(new IntegrityChange
                {
                    FilePath = path,
                    Kind = ChangeKind.Deleted,
                    BaselineHash = baseSnap.Sha256,
                    BaselineSize = baseSnap.SizeBytes,
                    Severity = IsCriticalFile(fileName) ? Severity.Critical : Severity.Warning,
                    Description = $"File deleted since baseline: {path}",
                });
                continue;
            }

            // Check hash modification
            if (!string.Equals(baseSnap.Sha256, current.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                var fileName = System.IO.Path.GetFileName(path);
                report.Changes.Add(new IntegrityChange
                {
                    FilePath = path,
                    Kind = ChangeKind.Modified,
                    BaselineHash = baseSnap.Sha256,
                    CurrentHash = current.Sha256,
                    BaselineSize = baseSnap.SizeBytes,
                    CurrentSize = current.SizeBytes,
                    Severity = IsCriticalFile(fileName) ? Severity.Critical : Severity.Warning,
                    Description = $"File modified: {path} (size {baseSnap.SizeBytes} → {current.SizeBytes})",
                });
            }
            // Check permission change (hash same, but read-only flag changed)
            else if (baseSnap.IsReadOnly != current.IsReadOnly)
            {
                report.Changes.Add(new IntegrityChange
                {
                    FilePath = path,
                    Kind = ChangeKind.PermissionChanged,
                    BaselineHash = baseSnap.Sha256,
                    CurrentHash = current.Sha256,
                    PermissionChanged = true,
                    Severity = Severity.Info,
                    Description = $"Permissions changed on {path}: ReadOnly {baseSnap.IsReadOnly} → {current.IsReadOnly}",
                });
            }
        }

        // Check for new files not in baseline
        foreach (var (path, current) in currentFiles)
        {
            if (!baseline.Files.ContainsKey(path) && current.Exists)
            {
                var fileName = System.IO.Path.GetFileName(path);
                report.Changes.Add(new IntegrityChange
                {
                    FilePath = path,
                    Kind = ChangeKind.Added,
                    CurrentHash = current.Sha256,
                    CurrentSize = current.SizeBytes,
                    Severity = IsCriticalFile(fileName) ? Severity.Critical : Severity.Warning,
                    Description = $"New file detected: {path} ({current.SizeBytes} bytes)",
                });
            }
        }

        return report;
    }

    /// <summary>
    /// Convert an integrity report to audit findings.
    /// </summary>
    public static List<Finding> ToFindings(IntegrityReport report)
    {
        var findings = new List<Finding>();

        if (report.IsClean)
        {
            findings.Add(Finding.Pass(
                "File Integrity Clean",
                $"All {report.TotalFilesScanned} monitored files match baseline " +
                $"(baseline from {report.BaselineTimeUtc:yyyy-MM-dd HH:mm:ss UTC}).",
                "FileIntegrity"));
            return findings;
        }

        foreach (var change in report.Changes)
        {
            var finding = change.Severity switch
            {
                Severity.Critical => Finding.Critical(
                    $"Critical File {change.Kind}: {System.IO.Path.GetFileName(change.FilePath)}",
                    change.Description, "FileIntegrity",
                    GetRemediation(change)),
                Severity.Warning => Finding.Warning(
                    $"File {change.Kind}: {System.IO.Path.GetFileName(change.FilePath)}",
                    change.Description, "FileIntegrity",
                    GetRemediation(change)),
                _ => Finding.Info(
                    $"File {change.Kind}: {System.IO.Path.GetFileName(change.FilePath)}",
                    change.Description, "FileIntegrity",
                    GetRemediation(change)),
            };
            findings.Add(finding);
        }

        // Summary finding
        findings.Add(report.OverallSeverity == Severity.Critical
            ? Finding.Critical("File Integrity Violations",
                $"{report.Changes.Count} change(s) detected: {report.ModifiedCount} modified, " +
                $"{report.AddedCount} added, {report.DeletedCount} deleted, " +
                $"{report.PermissionChangedCount} permission changes.",
                "FileIntegrity",
                "Investigate all changes. Restore files from known-good backups if unauthorized.")
            : Finding.Warning("File Integrity Changes",
                $"{report.Changes.Count} change(s) detected: {report.ModifiedCount} modified, " +
                $"{report.AddedCount} added, {report.DeletedCount} deleted, " +
                $"{report.PermissionChangedCount} permission changes.",
                "FileIntegrity",
                "Review changes and update baseline if changes are authorized."));

        return findings;
    }

    /// <summary>
    /// Serialize baseline to JSON.
    /// </summary>
    public static string SerializeBaseline(IntegrityBaseline baseline)
    {
        return JsonSerializer.Serialize(baseline, new JsonSerializerOptions
        {
            WriteIndented = true,
        });
    }

    /// <summary>
    /// Deserialize baseline from JSON.
    /// </summary>
    public static IntegrityBaseline? DeserializeBaseline(string json)
    {
        return JsonSerializer.Deserialize<IntegrityBaseline>(json);
    }

    // --- Helpers ---

    private static bool IsCriticalFile(string fileName)
    {
        return CriticalFiles.Contains(fileName);
    }

    private static string GetRemediation(IntegrityChange change) => change.Kind switch
    {
        ChangeKind.Modified => "Verify the modification is authorized. If not, restore from a known-good backup or reinstall the affected component.",
        ChangeKind.Deleted => "Investigate why the file was removed. Restore from backup or run System File Checker (sfc /scannow).",
        ChangeKind.Added => "Investigate the origin of this file. Scan with antivirus. Remove if unauthorized.",
        ChangeKind.PermissionChanged => "Review file permissions. Ensure only authorized accounts have write access.",
        _ => "Review the change and take appropriate action.",
    };
}
