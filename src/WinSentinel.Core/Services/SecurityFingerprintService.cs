using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates a deterministic security fingerprint (hash) of the system's security posture.
/// Useful for drift detection, compliance verification, and cross-system comparison.
/// </summary>
public class SecurityFingerprintService
{
    /// <summary>
    /// Generate a security fingerprint from an audit report.
    /// </summary>
    public SecurityFingerprint Generate(SecurityReport report)
    {
        var components = new List<FingerprintComponent>();

        // Build a deterministic representation of each module's findings
        foreach (var result in report.Results.OrderBy(r => r.ModuleName))
        {
            var findingSignatures = result.Findings
                .Where(f => f.Severity is Severity.Critical or Severity.Warning)
                .OrderBy(f => f.Title)
                .Select(f => $"{f.Severity}:{f.Title}")
                .ToList();

            var moduleHash = ComputeHash(string.Join("|", findingSignatures));

            components.Add(new FingerprintComponent
            {
                Module = result.ModuleName,
                Category = result.Category,
                Score = result.Score,
                CriticalCount = result.CriticalCount,
                WarningCount = result.WarningCount,
                FindingCount = findingSignatures.Count,
                Hash = moduleHash
            });
        }

        // Build the full fingerprint string from all component hashes
        var fullInput = string.Join("|", components.Select(c => $"{c.Module}:{c.Hash}"));
        var fullHash = ComputeHash(fullInput);

        // Generate a short human-readable ID (first 12 chars of hash)
        var shortId = fullHash[..12].ToUpperInvariant();

        // Determine posture classification
        var posture = ClassifyPosture(report);

        return new SecurityFingerprint
        {
            Id = shortId,
            FullHash = fullHash,
            Algorithm = "SHA-256",
            Score = report.SecurityScore,
            Grade = SecurityScorer.GetGrade(report.SecurityScore),
            Posture = posture,
            Machine = Environment.MachineName,
            User = Environment.UserName,
            Os = Environment.OSVersion.ToString(),
            GeneratedAt = DateTimeOffset.Now,
            TotalCritical = report.TotalCritical,
            TotalWarnings = report.TotalWarnings,
            ModuleCount = components.Count,
            Components = components
        };
    }

    /// <summary>
    /// Compare two fingerprints and return the drift analysis.
    /// </summary>
    public FingerprintDrift Compare(SecurityFingerprint baseline, SecurityFingerprint current)
    {
        var drift = new FingerprintDrift
        {
            BaselineId = baseline.Id,
            CurrentId = current.Id,
            IsIdentical = baseline.FullHash == current.FullHash,
            ScoreChange = current.Score - baseline.Score,
            BaselineScore = baseline.Score,
            CurrentScore = current.Score,
            BaselineGrade = baseline.Grade,
            CurrentGrade = current.Grade,
            TimeSinceBaseline = current.GeneratedAt - baseline.GeneratedAt
        };

        // Compare module-level components
        var baselineModules = baseline.Components.ToDictionary(c => c.Module);
        var currentModules = current.Components.ToDictionary(c => c.Module);

        foreach (var mod in baselineModules.Keys.Union(currentModules.Keys).OrderBy(k => k))
        {
            baselineModules.TryGetValue(mod, out var bComp);
            currentModules.TryGetValue(mod, out var cComp);

            if (bComp == null)
            {
                drift.Changes.Add(new ModuleDriftEntry
                {
                    Module = mod,
                    Status = "added",
                    CurrentHash = cComp!.Hash,
                    ScoreChange = 0,
                    NewFindings = cComp.FindingCount
                });
            }
            else if (cComp == null)
            {
                drift.Changes.Add(new ModuleDriftEntry
                {
                    Module = mod,
                    Status = "removed",
                    BaselineHash = bComp.Hash,
                    ScoreChange = 0
                });
            }
            else if (bComp.Hash != cComp.Hash)
            {
                drift.Changes.Add(new ModuleDriftEntry
                {
                    Module = mod,
                    Status = "changed",
                    BaselineHash = bComp.Hash,
                    CurrentHash = cComp.Hash,
                    ScoreChange = cComp.Score - bComp.Score,
                    PreviousFindings = bComp.FindingCount,
                    NewFindings = cComp.FindingCount
                });
            }
            // If hashes match, module is unchanged — skip
        }

        drift.DriftLevel = drift.IsIdentical ? "none"
            : drift.Changes.Any(c => c.ScoreChange < -10) ? "high"
            : drift.Changes.Count > 3 ? "medium"
            : "low";

        return drift;
    }

    /// <summary>
    /// Render fingerprint as a compact badge-like string.
    /// </summary>
    public static string RenderBadge(SecurityFingerprint fp)
    {
        return $"🔒 {fp.Id} | {fp.Score}/100 ({fp.Grade}) | {fp.Posture}";
    }

    /// <summary>
    /// Serialize fingerprint to JSON for storage/comparison.
    /// </summary>
    public static string ToJson(SecurityFingerprint fp)
    {
        return JsonSerializer.Serialize(fp, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        });
    }

    /// <summary>
    /// Deserialize a fingerprint from JSON.
    /// </summary>
    public static SecurityFingerprint? FromJson(string json)
    {
        return JsonSerializer.Deserialize<SecurityFingerprint>(json, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        });
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string ClassifyPosture(SecurityReport report)
    {
        var score = report.SecurityScore;
        if (score >= 90 && report.TotalCritical == 0) return "Hardened";
        if (score >= 80) return "Strong";
        if (score >= 70) return "Moderate";
        if (score >= 50) return "Weak";
        return "Critical";
    }
}

// ── Models ───────────────────────────────────────────────────────────

public class SecurityFingerprint
{
    public string Id { get; set; } = "";
    public string FullHash { get; set; } = "";
    public string Algorithm { get; set; } = "SHA-256";
    public int Score { get; set; }
    public string Grade { get; set; } = "";
    public string Posture { get; set; } = "";
    public string Machine { get; set; } = "";
    public string User { get; set; } = "";
    public string Os { get; set; } = "";
    public DateTimeOffset GeneratedAt { get; set; }
    public int TotalCritical { get; set; }
    public int TotalWarnings { get; set; }
    public int ModuleCount { get; set; }
    public List<FingerprintComponent> Components { get; set; } = [];
}

public class FingerprintComponent
{
    public string Module { get; set; } = "";
    public string Category { get; set; } = "";
    public int Score { get; set; }
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int FindingCount { get; set; }
    public string Hash { get; set; } = "";
}

public class FingerprintDrift
{
    public string BaselineId { get; set; } = "";
    public string CurrentId { get; set; } = "";
    public bool IsIdentical { get; set; }
    public string DriftLevel { get; set; } = "none";
    public int ScoreChange { get; set; }
    public int BaselineScore { get; set; }
    public int CurrentScore { get; set; }
    public string BaselineGrade { get; set; } = "";
    public string CurrentGrade { get; set; } = "";
    public TimeSpan TimeSinceBaseline { get; set; }
    public List<ModuleDriftEntry> Changes { get; set; } = [];
}

public class ModuleDriftEntry
{
    public string Module { get; set; } = "";
    public string Status { get; set; } = "";
    public string? BaselineHash { get; set; }
    public string? CurrentHash { get; set; }
    public int ScoreChange { get; set; }
    public int PreviousFindings { get; set; }
    public int NewFindings { get; set; }
}
