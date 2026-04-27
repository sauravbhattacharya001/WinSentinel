using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Autonomous attack/defense war-game simulator. Runs adversary tactics
/// against the current security posture and scores the defense.
/// </summary>
public class SecurityWarGameService : IDisposable
{
    private readonly AuditHistoryService _history;
    private readonly bool _ownsHistory;
    private static readonly Random Rng = new();

    public SecurityWarGameService() : this(new AuditHistoryService()) { _ownsHistory = true; }
    public SecurityWarGameService(AuditHistoryService history) { _history = history; }

    public WarGameResult Simulate(int historyDays = 30, int rounds = 5, string? scenario = null)
    {
        var runs = _history.GetHistory(historyDays);
        runs = runs.OrderBy(r => r.Timestamp).ToList();

        var latest = runs.LastOrDefault();
        int currentScore = latest?.OverallScore ?? 50;
        var findings = latest?.Findings ?? new List<FindingRecord>();

        var selectedScenario = scenario != null
            ? AllScenarios.FirstOrDefault(s => s.Id.Equals(scenario, StringComparison.OrdinalIgnoreCase))
              ?? AllScenarios[Rng.Next(AllScenarios.Count)]
            : AllScenarios[Rng.Next(AllScenarios.Count)];

        var tactics = selectedScenario.Tactics
            .OrderBy(_ => Rng.Next())
            .Take(Math.Min(rounds, selectedScenario.Tactics.Count))
            .ToList();

        var roundResults = new List<WarGameRound>();
        int defenseScore = 100;
        int attackSuccesses = 0;
        int defenseWins = 0;

        foreach (var tactic in tactics)
        {
            var (outcome, defended, detail, recommendation) = EvaluateTactic(tactic, currentScore, findings);
            int damage = defended ? 0 : tactic.BaseDamage;
            defenseScore -= damage;

            if (defended) defenseWins++;
            else attackSuccesses++;

            roundResults.Add(new WarGameRound(
                tactic.Name, tactic.MitreId, tactic.Category,
                tactic.BaseDamage, defended, outcome, detail, recommendation));
        }

        defenseScore = Math.Max(0, defenseScore);

        var grade = defenseScore switch
        {
            >= 90 => "A",
            >= 75 => "B",
            >= 60 => "C",
            >= 40 => "D",
            _ => "F"
        };

        var verdict = defenseScore switch
        {
            >= 90 => "FORTRESS — Defenses held strong. Adversary repelled.",
            >= 75 => "RESILIENT — Minor breaches but contained quickly.",
            >= 60 => "VULNERABLE — Several tactics succeeded. Hardening needed.",
            >= 40 => "COMPROMISED — Significant damage. Immediate action required.",
            _ => "OVERRUN — Defenses collapsed. Critical remediation needed."
        };

        var recommendations = new List<string>();
        foreach (var round in roundResults.Where(r => !r.Defended))
        {
            recommendations.Add(round.Recommendation);
        }
        if (recommendations.Count == 0)
            recommendations.Add("Maintain current security posture — all tested tactics were defended.");

        var proactive = GenerateProactiveInsights(roundResults, defenseScore, selectedScenario);

        return new WarGameResult(
            selectedScenario.Id, selectedScenario.Name, selectedScenario.Description,
            roundResults, defenseScore, grade, verdict,
            attackSuccesses, defenseWins, roundResults.Count,
            recommendations, proactive, DateTime.UtcNow);
    }

    public List<WarGameScenarioInfo> ListScenarios() =>
        AllScenarios.Select(s => new WarGameScenarioInfo(s.Id, s.Name, s.Description, s.Tactics.Count)).ToList();

    private (string outcome, bool defended, string detail, string recommendation) EvaluateTactic(
        WarGameTactic tactic, int score, List<FindingRecord> findings)
    {
        // Determine defense strength based on current posture
        double defenseChance = score / 100.0;

        // Check if relevant findings weaken defense
        bool hasRelatedWeakness = findings.Any(f =>
            tactic.WeaknessKeywords.Any(k =>
                (f.Title?.Contains(k, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (f.Description?.Contains(k, StringComparison.OrdinalIgnoreCase) ?? false)));

        if (hasRelatedWeakness)
            defenseChance *= 0.5; // Weakness halves defense chance

        // Critical findings further weaken
        int criticalCount = findings.Count(f => f.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase));
        if (criticalCount > 5)
            defenseChance *= 0.8;

        bool defended = Rng.NextDouble() < defenseChance;

        if (defended)
        {
            return (
                "BLOCKED",
                true,
                $"Defense detected and neutralized {tactic.Name}. " +
                $"Score advantage ({score}/100) provided strong protection.",
                "Continue maintaining this defense layer.");
        }
        else
        {
            string weaknessNote = hasRelatedWeakness
                ? $" Existing weakness ({tactic.WeaknessKeywords.First()}) was exploited."
                : " No specific weakness found, but insufficient detection coverage.";
            return (
                "BREACHED",
                false,
                $"{tactic.Name} penetrated defenses.{weaknessNote} Damage: {tactic.BaseDamage} points.",
                tactic.Mitigation);
        }
    }

    private static List<string> GenerateProactiveInsights(
        List<WarGameRound> rounds, int defenseScore, WarGameScenario scenario)
    {
        var insights = new List<string>();

        var breachedCategories = rounds.Where(r => !r.Defended)
            .Select(r => r.Category).Distinct().ToList();

        if (breachedCategories.Count > 0)
            insights.Add($"Weak categories: {string.Join(", ", breachedCategories)} — prioritize hardening these areas.");

        int totalDamage = rounds.Where(r => !r.Defended).Sum(r => r.Damage);
        if (totalDamage > 40)
            insights.Add($"Total damage ({totalDamage} pts) exceeds critical threshold — consider emergency remediation sprint.");

        if (rounds.All(r => r.Defended))
            insights.Add("Perfect defense! Consider advancing to more aggressive scenario testing.");

        if (defenseScore < 60)
            insights.Add("Defense score below 60 — recommend running --harden to auto-fix discoverable weaknesses.");

        insights.Add($"Re-run with --wargame-scenario {scenario.Id} after remediation to verify improvement.");

        return insights;
    }

    private static readonly List<WarGameScenario> AllScenarios = new()
    {
        new("apt29", "APT29 Cozy Bear", "Sophisticated state-sponsored espionage targeting credentials and persistence", new List<WarGameTactic>
        {
            new("Spearphishing Link", "T1566.002", "Initial Access", 15, new[] { "phishing", "email", "link" }, "Deploy email filtering and user awareness training"),
            new("Credential Dumping", "T1003", "Credential Access", 20, new[] { "credential", "password", "hash", "lsass" }, "Enable Credential Guard and monitor LSASS access"),
            new("Registry Run Keys", "T1547.001", "Persistence", 12, new[] { "registry", "startup", "autorun" }, "Monitor registry run keys with --watchdog"),
            new("Scheduled Tasks", "T1053.005", "Persistence", 10, new[] { "scheduled", "task", "schtasks" }, "Audit scheduled tasks with --shadow and --inventory"),
            new("Encrypted Channel", "T1573", "C2", 18, new[] { "encrypted", "tunnel", "proxy" }, "Deploy network monitoring and TLS inspection"),
            new("Data Staging", "T1074", "Collection", 14, new[] { "staging", "collection", "archive" }, "Monitor unusual file access patterns and staging directories")
        }),
        new("ransomware", "Ransomware Blitz", "Fast-moving ransomware attack targeting encryption and lateral movement", new List<WarGameTactic>
        {
            new("Exploit Public App", "T1190", "Initial Access", 18, new[] { "exploit", "vulnerability", "cve", "patch" }, "Patch all critical CVEs — run audit and fix immediately"),
            new("Service Stop", "T1489", "Impact", 20, new[] { "service", "stop", "disable" }, "Protect critical services and enable service monitoring"),
            new("Volume Shadow Delete", "T1490", "Impact", 25, new[] { "shadow", "backup", "vss" }, "Protect VSS and maintain offline backups"),
            new("Lateral Movement SMB", "T1021.002", "Lateral", 16, new[] { "smb", "share", "lateral", "network" }, "Restrict SMB access and segment network"),
            new("Process Injection", "T1055", "Defense Evasion", 14, new[] { "injection", "process", "dll" }, "Enable code integrity policies and monitor process creation"),
            new("File Encryption", "T1486", "Impact", 22, new[] { "encrypt", "ransom", "locked" }, "Deploy anti-ransomware tools and monitor bulk file changes")
        }),
        new("insider", "Insider Threat", "Malicious insider abusing legitimate access", new List<WarGameTactic>
        {
            new("Valid Accounts", "T1078", "Initial Access", 10, new[] { "account", "privilege", "admin", "user" }, "Implement least privilege and review account permissions"),
            new("Data from Local System", "T1005", "Collection", 15, new[] { "data", "file", "access", "copy" }, "Monitor sensitive file access and enable DLP"),
            new("Exfiltration Over Web", "T1567", "Exfiltration", 20, new[] { "upload", "exfiltration", "cloud", "web" }, "Deploy DLP and monitor outbound data transfers"),
            new("Account Manipulation", "T1098", "Persistence", 18, new[] { "account", "permission", "group", "admin" }, "Monitor account changes and enable MFA everywhere"),
            new("Indicator Removal", "T1070", "Defense Evasion", 16, new[] { "log", "clear", "delete", "event" }, "Centralize logging and protect audit trails")
        }),
        new("supply-chain", "Supply Chain Attack", "Compromise through trusted third-party software", new List<WarGameTactic>
        {
            new("Trusted Relationship", "T1199", "Initial Access", 20, new[] { "trust", "vendor", "third-party" }, "Audit third-party access and segment vendor networks"),
            new("Software Supply Chain", "T1195.002", "Initial Access", 22, new[] { "update", "package", "install", "software" }, "Verify software integrity and use allowlisting"),
            new("DLL Side-Loading", "T1574.002", "Execution", 15, new[] { "dll", "sideload", "library" }, "Enable code signing enforcement and monitor DLL loads"),
            new("Masquerading", "T1036", "Defense Evasion", 12, new[] { "masquerade", "rename", "disguise" }, "Monitor file hash changes and enable path-based rules"),
            new("Compromise Infrastructure", "T1584", "Resource Dev", 18, new[] { "infrastructure", "server", "domain" }, "Monitor DNS and network connections to unusual destinations")
        }),
        new("zero-day", "Zero-Day Exploitation", "Attack leveraging unknown vulnerabilities", new List<WarGameTactic>
        {
            new("Exploit Zero-Day", "T1190", "Initial Access", 25, new[] { "zero-day", "exploit", "vulnerability", "unknown" }, "Deploy defense-in-depth — no single layer should be fatal"),
            new("Privilege Escalation", "T1068", "Priv Escalation", 20, new[] { "privilege", "escalation", "admin", "root" }, "Enforce least privilege and monitor privilege changes"),
            new("Defense Evasion Rootkit", "T1014", "Defense Evasion", 22, new[] { "rootkit", "hidden", "stealth" }, "Enable Secure Boot and kernel integrity monitoring"),
            new("Memory-Only Payload", "T1620", "Defense Evasion", 18, new[] { "memory", "fileless", "script" }, "Deploy AMSI and in-memory scan capabilities"),
            new("C2 Domain Fronting", "T1090.004", "C2", 16, new[] { "domain", "fronting", "cdn", "proxy" }, "Monitor CDN/cloud connections and deploy DNS filtering")
        })
    };

    public void Dispose()
    {
        if (_ownsHistory) _history.Dispose();
    }
}

// --- Models ---

public record WarGameResult(
    string ScenarioId,
    string ScenarioName,
    string ScenarioDescription,
    List<WarGameRound> Rounds,
    int DefenseScore,
    string Grade,
    string Verdict,
    int AttackSuccesses,
    int DefenseWins,
    int TotalRounds,
    List<string> Recommendations,
    List<string> ProactiveInsights,
    DateTime Timestamp);

public record WarGameRound(
    string TacticName,
    string MitreId,
    string Category,
    int Damage,
    bool Defended,
    string Outcome,
    string Detail,
    string Recommendation);

public record WarGameScenarioInfo(string Id, string Name, string Description, int TacticCount);

internal record WarGameScenario(string Id, string Name, string Description, List<WarGameTactic> Tactics);

internal record WarGameTactic(
    string Name, string MitreId, string Category, int BaseDamage,
    string[] WeaknessKeywords, string Mitigation);
