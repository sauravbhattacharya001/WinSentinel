namespace WinSentinel.Core.Models;

/// <summary>
/// Autonomous Threat DNA Profiler — generates a unique vulnerability fingerprint
/// for a system by analyzing historical security audit findings. Tracks how the
/// system's threat DNA evolves over time and provides targeted hardening recommendations.
/// </summary>
public sealed class ThreatDnaReport
{
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public string SystemId { get; set; } = "";
    public string DnaHash { get; set; } = "";
    public int OverallResilienceScore { get; set; }
    public int GeneCount { get; set; }
    public string DominantCategory { get; set; } = "";
    public string EvolutionPhase { get; set; } = "Emerging";
    public List<ThreatGene> Genes { get; set; } = [];
    public List<DnaCategoryProfile> CategoryBreakdown { get; set; } = [];
    public List<DnaSnapshot> EvolutionTimeline { get; set; } = [];
    public List<DnaMutation> MutationAlerts { get; set; } = [];
    public List<DnaHardeningAction> HardeningPlan { get; set; } = [];
    public List<string> Recommendations { get; set; } = [];
}

/// <summary>
/// A single vulnerability pattern "gene" — a recurring finding pattern
/// that forms part of the system's threat DNA.
/// </summary>
public sealed class ThreatGene
{
    public string GeneId { get; set; } = "";
    public string Category { get; set; } = "";
    public string MitreTechnique { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public int Frequency { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public bool IsActive { get; set; }
    public double Persistence { get; set; }
    public double ResistanceScore { get; set; }
}

/// <summary>Per-category breakdown of the threat DNA.</summary>
public sealed class DnaCategoryProfile
{
    public string Category { get; set; } = "";
    public int GeneCount { get; set; }
    public int ActiveGenes { get; set; }
    public string DominantSeverity { get; set; } = "";
    public double ExposureScore { get; set; }
    public string TrendDirection { get; set; } = "Stable";
}

/// <summary>Point-in-time snapshot of the threat DNA for evolution tracking.</summary>
public sealed class DnaSnapshot
{
    public DateTimeOffset Timestamp { get; set; }
    public int GeneCount { get; set; }
    public int ActiveGenes { get; set; }
    public int ResilienceScore { get; set; }
    public string TopCategory { get; set; } = "";
    public string DnaHash { get; set; } = "";
}

/// <summary>A detected mutation (change) in the threat DNA.</summary>
public sealed class DnaMutation
{
    public DateTimeOffset Timestamp { get; set; }
    public DnaMutationType MutationType { get; set; }
    public string Description { get; set; } = "";
    public string AffectedGene { get; set; } = "";
    public string Impact { get; set; } = "";
}

/// <summary>Types of mutations in the threat DNA.</summary>
public enum DnaMutationType
{
    NewGene,
    GeneEliminated,
    Resurgence,
    SeverityEscalation,
    CategoryShift
}

/// <summary>Targeted hardening action derived from threat DNA analysis.</summary>
public sealed class DnaHardeningAction
{
    public int Priority { get; set; }
    public string Action { get; set; } = "";
    public List<string> TargetGenes { get; set; } = [];
    public string ExpectedImpact { get; set; } = "";
    public string Effort { get; set; } = "Medium";
    public int ResilienceGain { get; set; }
}
