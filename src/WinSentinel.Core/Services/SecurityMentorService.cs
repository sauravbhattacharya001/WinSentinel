namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Autonomous security training coach that analyzes audit findings to build
/// personalized skill assessments and generate targeted learning recommendations.
/// </summary>
public sealed class SecurityMentorService
{
    private readonly AuditHistoryService _history;

    public SecurityMentorService(AuditHistoryService history) => _history = history;

    /// <summary>Analyze the current report and history to produce mentoring guidance.</summary>
    public MentorReport Analyze(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var skills = BuildSkillAssessments(report, runs);
        var overall = skills.Count > 0 ? (int)skills.Average(s => s.Score) : 0;
        var weakest = skills.MinBy(s => s.Score);
        var strongest = skills.MaxBy(s => s.Score);
        var streak = ComputeStreak(runs);

        return new MentorReport
        {
            Skills = skills,
            LearningPaths = BuildLearningPaths(skills),
            Challenges = BuildChallenges(report, skills),
            OverallScore = overall,
            OverallLevel = LevelName(overall),
            StreakDays = streak,
            WeakestDomain = weakest?.Domain ?? "N/A",
            StrongestDomain = strongest?.Domain ?? "N/A",
            Encouragement = PickEncouragement(overall, streak, weakest?.Domain)
        };
    }

    // ── Skill assessment ─────────────────────────────────────────

    List<SkillAssessment> BuildSkillAssessments(SecurityReport report, List<AuditRunRecord> runs)
    {
        var domains = new Dictionary<string, List<AuditResult>>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in report.Results)
        {
            var domain = NormalizeDomain(r.Category, r.ModuleName);
            if (!domains.ContainsKey(domain)) domains[domain] = [];
            domains[domain].Add(r);
        }

        var prevScores = GetPreviousModuleScores(runs);

        var skills = new List<SkillAssessment>();
        foreach (var (domain, results) in domains)
        {
            var totalFindings = results.Sum(r => r.Findings.Count);
            var criticals = results.Sum(r => r.CriticalCount);
            var passRate = totalFindings > 0
                ? (double)results.Sum(r => r.PassCount) / totalFindings * 100
                : 100;
            var score = Math.Clamp((int)passRate, 0, 100);

            // Penalty for critical findings
            score = Math.Max(0, score - criticals * 5);

            var trend = "→";
            if (prevScores.TryGetValue(domain, out var prev))
                trend = score > prev ? "↑" : score < prev ? "↓" : "→";

            skills.Add(new SkillAssessment
            {
                Domain = domain,
                Score = score,
                Level = LevelName(score),
                Trend = trend,
                FindingsCount = totalFindings,
                CriticalCount = criticals
            });
        }

        return skills.OrderBy(s => s.Score).ToList();
    }

    Dictionary<string, int> GetPreviousModuleScores(List<AuditRunRecord> runs)
    {
        var prev = runs.OrderByDescending(r => r.Timestamp).Skip(1).FirstOrDefault();
        if (prev is null) return [];
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var ms in prev.ModuleScores)
        {
            var domain = NormalizeDomain(ms.Category, ms.ModuleName);
            if (!result.ContainsKey(domain) || ms.Score < result[domain])
                result[domain] = ms.Score;
        }
        return result;
    }

    // ── Streak calculation ───────────────────────────────────────

    static int ComputeStreak(List<AuditRunRecord> runs)
    {
        var sorted = runs.OrderByDescending(r => r.Timestamp).ToList();
        if (sorted.Count < 2) return 0;
        int streak = 0;
        for (int i = 0; i < sorted.Count - 1; i++)
        {
            if (sorted[i].OverallScore >= sorted[i + 1].OverallScore)
                streak++;
            else
                break;
        }
        return streak;
    }

    // ── Learning paths ───────────────────────────────────────────

    static List<LearningPath> BuildLearningPaths(List<SkillAssessment> skills)
    {
        var paths = new List<LearningPath>();
        foreach (var skill in skills.Where(s => s.Score < 80))
        {
            var topics = GetTopicsForDomain(skill.Domain, skill.Score);
            paths.Add(new LearningPath
            {
                Domain = skill.Domain,
                Topics = topics,
                Priority = skill.Score < 40 ? "High" : skill.Score < 60 ? "Medium" : "Low"
            });
        }
        return paths;
    }

    static List<string> GetTopicsForDomain(string domain, int score)
    {
        var basics = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["Network"] =
            [
                "TCP/IP fundamentals and port security",
                "Network segmentation best practices",
                "DNS security and DNSSEC",
                "TLS/SSL certificate management",
                "Network monitoring and intrusion detection"
            ],
            ["Identity"] =
            [
                "Password policy enforcement",
                "Multi-factor authentication setup",
                "Least privilege principle",
                "Service account hardening",
                "Active Directory security"
            ],
            ["Encryption"] =
            [
                "BitLocker drive encryption",
                "Data-at-rest encryption strategies",
                "Certificate management basics",
                "Key rotation policies",
                "Secure communication protocols"
            ],
            ["Updates"] =
            [
                "Windows Update configuration",
                "Patch management workflow",
                "Vulnerability scanning schedules",
                "Automatic update policies",
                "Third-party software patching"
            ],
            ["Firewall"] =
            [
                "Windows Firewall rule management",
                "Inbound vs outbound filtering",
                "Application-level rules",
                "Logging and monitoring firewall events",
                "Advanced firewall profiles"
            ],
            ["Services"] =
            [
                "Unnecessary service identification",
                "Service account permissions",
                "Startup type hardening",
                "Service isolation techniques",
                "Monitoring service health"
            ],
            ["Registry"] =
            [
                "Security-related registry keys",
                "Registry permission auditing",
                "Group Policy vs registry settings",
                "Registry backup and restore",
                "Detecting unauthorized changes"
            ],
            ["Permissions"] =
            [
                "NTFS permission auditing",
                "Shared folder access control",
                "File integrity monitoring",
                "Ownership and inheritance",
                "Sensitive file protection"
            ],
            ["Logging"] =
            [
                "Windows Event Log configuration",
                "Audit policy setup",
                "Log retention and archival",
                "SIEM integration basics",
                "Detecting suspicious log entries"
            ],
            ["Applications"] =
            [
                "Application whitelisting",
                "Software restriction policies",
                "AppLocker configuration",
                "Browser security settings",
                "Removing unnecessary software"
            ]
        };

        if (!basics.TryGetValue(domain, out var topics))
            topics = ["Review general Windows security hardening guides"];

        // Return fewer topics for higher scores
        var count = score < 30 ? 5 : score < 50 ? 4 : score < 70 ? 3 : 2;
        return topics.Take(count).ToList();
    }

    // ── Challenges ───────────────────────────────────────────────

    static List<MentorChallenge> BuildChallenges(SecurityReport report, List<SkillAssessment> skills)
    {
        var challenges = new List<MentorChallenge>();
        var weakDomains = skills.Where(s => s.Score < 70).OrderBy(s => s.Score).Take(5);

        foreach (var skill in weakDomains)
        {
            var (title, desc, diff, pts) = GetChallengeForDomain(skill.Domain, skill.Score, report);
            challenges.Add(new MentorChallenge
            {
                Title = title,
                Description = desc,
                Domain = skill.Domain,
                Difficulty = diff,
                PointsReward = pts
            });
        }
        return challenges;
    }

    static (string title, string desc, string difficulty, int points) GetChallengeForDomain(
        string domain, int score, SecurityReport report)
    {
        return domain.ToLowerInvariant() switch
        {
            "network" => ("Lock Down Open Ports",
                "Review all listening ports and close any that aren't required for business operations.",
                score < 30 ? "Hard" : "Medium", score < 30 ? 50 : 30),
            "identity" => ("Enforce Strong Passwords",
                "Configure password policy: 12+ chars, complexity required, 90-day max age, 5 history.",
                score < 30 ? "Hard" : "Medium", score < 30 ? 50 : 30),
            "encryption" => ("Enable BitLocker Everywhere",
                "Enable BitLocker on all fixed drives with TPM+PIN and ensure recovery keys are backed up.",
                "Medium", 40),
            "updates" => ("Patch Sprint",
                "Install all pending Windows updates and verify no critical patches are missing.",
                "Easy", 20),
            "firewall" => ("Firewall Lockdown",
                "Set Windows Firewall to block all inbound connections by default, then whitelist only required services.",
                score < 30 ? "Hard" : "Medium", score < 30 ? 50 : 30),
            "services" => ("Service Cleanup",
                "Identify and disable at least 3 unnecessary services running on this machine.",
                "Easy", 20),
            "registry" => ("Registry Hardening",
                "Apply recommended security registry settings for SMB signing, NTLMv2, and remote access.",
                "Hard", 50),
            "permissions" => ("Permission Audit",
                "Audit file permissions on system directories and remove any overly permissive ACLs.",
                "Medium", 30),
            "logging" => ("Enable Full Audit Logging",
                "Configure advanced audit policies to capture logon, privilege use, and object access events.",
                "Medium", 30),
            "applications" => ("AppLocker Setup",
                "Configure AppLocker rules to whitelist approved applications and block unknown executables.",
                "Hard", 50),
            _ => ("General Hardening",
                $"Review and fix the {report.TotalCritical} critical findings in the latest audit.",
                "Medium", 30)
        };
    }

    // ── Helpers ──────────────────────────────────────────────────

    static string NormalizeDomain(string category, string moduleName)
    {
        if (!string.IsNullOrWhiteSpace(category) && category.Length > 1)
            return char.ToUpper(category[0]) + category[1..].ToLowerInvariant();

        // Fallback: derive from module name
        var name = moduleName.ToLowerInvariant();
        if (name.Contains("network") || name.Contains("port") || name.Contains("dns") || name.Contains("smb"))
            return "Network";
        if (name.Contains("user") || name.Contains("password") || name.Contains("account") || name.Contains("auth"))
            return "Identity";
        if (name.Contains("encrypt") || name.Contains("bitlocker") || name.Contains("tls") || name.Contains("cert"))
            return "Encryption";
        if (name.Contains("update") || name.Contains("patch") || name.Contains("wsus"))
            return "Updates";
        if (name.Contains("firewall") || name.Contains("fw"))
            return "Firewall";
        if (name.Contains("service") || name.Contains("startup"))
            return "Services";
        if (name.Contains("registry") || name.Contains("reg"))
            return "Registry";
        if (name.Contains("permission") || name.Contains("acl") || name.Contains("file"))
            return "Permissions";
        if (name.Contains("log") || name.Contains("audit") || name.Contains("event"))
            return "Logging";
        if (name.Contains("app") || name.Contains("software") || name.Contains("program"))
            return "Applications";
        return "General";
    }

    static string LevelName(int score) => score switch
    {
        >= 80 => "Expert",
        >= 60 => "Advanced",
        >= 40 => "Intermediate",
        >= 20 => "Beginner",
        _ => "Novice"
    };

    static string PickEncouragement(int overall, int streak, string? weakest)
    {
        if (overall >= 90)
            return "🏆 Outstanding! You're a security master. Keep maintaining these excellent practices!";
        if (overall >= 75)
            return $"💪 Great work! You're well above average. Focus on {weakest ?? "remaining gaps"} to reach expert level.";
        if (streak >= 3)
            return $"🔥 {streak}-run improvement streak! Your dedication is paying off. Keep pushing!";
        if (overall >= 50)
            return $"📈 Solid foundation! Tackle the {weakest ?? "weak areas"} learning path to level up quickly.";
        if (overall >= 25)
            return "🌱 Good start! Follow the learning paths below — each topic you master will boost your score.";
        return "🚀 Every expert was once a beginner. Start with the high-priority challenges and build momentum!";
    }
}

// ── Models ──────────────────────────────────────────────────────

public class MentorReport
{
    public List<SkillAssessment> Skills { get; set; } = [];
    public List<LearningPath> LearningPaths { get; set; } = [];
    public List<MentorChallenge> Challenges { get; set; } = [];
    public string OverallLevel { get; set; } = "";
    public int OverallScore { get; set; }
    public int StreakDays { get; set; }
    public string Encouragement { get; set; } = "";
    public string WeakestDomain { get; set; } = "";
    public string StrongestDomain { get; set; } = "";
}

public class SkillAssessment
{
    public string Domain { get; set; } = "";
    public int Score { get; set; }
    public string Level { get; set; } = "";
    public string Trend { get; set; } = "";
    public int FindingsCount { get; set; }
    public int CriticalCount { get; set; }
}

public class LearningPath
{
    public string Domain { get; set; } = "";
    public List<string> Topics { get; set; } = [];
    public string Priority { get; set; } = "";
}

public class MentorChallenge
{
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Difficulty { get; set; } = "";
    public int PointsReward { get; set; }
}
