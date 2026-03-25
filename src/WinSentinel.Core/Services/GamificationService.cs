using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Gamification engine that awards achievements, tracks streaks,
/// and computes a security level based on audit history.
/// </summary>
public class GamificationService
{
    /// <summary>
    /// Compute gamification profile from audit history.
    /// </summary>
    public GamificationProfile Analyze(List<AuditRunRecord> runs)
    {
        var profile = new GamificationProfile();
        if (runs.Count == 0) return profile;

        // Sort chronologically
        var sorted = runs.OrderBy(r => r.Timestamp).ToList();

        // --- Level & XP ---
        // XP = sum of scores across all runs, bonus for consecutive improvements
        int totalXp = 0;
        foreach (var run in sorted)
        {
            totalXp += run.OverallScore;
        }
        profile.TotalXp = totalXp;
        profile.Level = totalXp switch
        {
            < 500 => 1,
            < 1500 => 2,
            < 3000 => 3,
            < 5000 => 4,
            < 8000 => 5,
            < 12000 => 6,
            < 17000 => 7,
            < 23000 => 8,
            < 30000 => 9,
            _ => 10
        };

        var xpThresholds = new[] { 0, 500, 1500, 3000, 5000, 8000, 12000, 17000, 23000, 30000, int.MaxValue };
        profile.XpToNextLevel = profile.Level < 10
            ? xpThresholds[profile.Level] - totalXp
            : 0;

        // --- Streaks ---
        // Improvement streak: consecutive runs where score >= previous
        int currentStreak = 0;
        int bestStreak = 0;
        for (int i = 1; i < sorted.Count; i++)
        {
            if (sorted[i].OverallScore >= sorted[i - 1].OverallScore)
            {
                currentStreak++;
                bestStreak = Math.Max(bestStreak, currentStreak);
            }
            else
            {
                currentStreak = 0;
            }
        }
        profile.CurrentImprovementStreak = currentStreak;
        profile.BestImprovementStreak = bestStreak;

        // Perfect streak: consecutive runs with score >= 90
        int perfectStreak = 0;
        int bestPerfect = 0;
        foreach (var run in sorted)
        {
            if (run.OverallScore >= 90)
            {
                perfectStreak++;
                bestPerfect = Math.Max(bestPerfect, perfectStreak);
            }
            else
            {
                perfectStreak = 0;
            }
        }
        profile.CurrentPerfectStreak = perfectStreak;
        profile.BestPerfectStreak = bestPerfect;

        // --- Stats ---
        profile.TotalAudits = sorted.Count;
        profile.HighestScore = sorted.Max(r => r.OverallScore);
        profile.AverageScore = (int)sorted.Average(r => r.OverallScore);
        profile.TotalCriticalFixed = CountCriticalsFixed(sorted);
        profile.LatestScore = sorted.Last().OverallScore;

        // --- Achievements ---
        profile.Achievements = ComputeAchievements(sorted, profile);

        return profile;
    }

    private static int CountCriticalsFixed(List<AuditRunRecord> sorted)
    {
        int fixed_ = 0;
        for (int i = 1; i < sorted.Count; i++)
        {
            int diff = sorted[i - 1].CriticalCount - sorted[i].CriticalCount;
            if (diff > 0) fixed_ += diff;
        }
        return fixed_;
    }

    private static List<Achievement> ComputeAchievements(List<AuditRunRecord> sorted, GamificationProfile profile)
    {
        var achievements = new List<Achievement>();

        // First Audit
        achievements.Add(new Achievement("First Steps", "Run your first security audit", "🔰", true));

        // Score-based
        if (profile.HighestScore >= 50)
            achievements.Add(new Achievement("Half Way There", "Score 50+ on an audit", "⭐", true));
        if (profile.HighestScore >= 75)
            achievements.Add(new Achievement("Security Enthusiast", "Score 75+ on an audit", "🌟", true));
        if (profile.HighestScore >= 90)
            achievements.Add(new Achievement("Hardened", "Score 90+ on an audit", "🛡️", true));
        if (profile.HighestScore >= 95)
            achievements.Add(new Achievement("Fort Knox", "Score 95+ on an audit", "🏆", true));
        if (profile.HighestScore == 100)
            achievements.Add(new Achievement("Perfection", "Achieve a perfect 100 score", "💎", true));

        // Streak-based
        if (profile.BestImprovementStreak >= 3)
            achievements.Add(new Achievement("On a Roll", "3+ consecutive improvements", "🔥", true));
        if (profile.BestImprovementStreak >= 7)
            achievements.Add(new Achievement("Unstoppable", "7+ consecutive improvements", "⚡", true));
        if (profile.BestPerfectStreak >= 3)
            achievements.Add(new Achievement("Consistency", "3+ consecutive 90+ scores", "💪", true));

        // Volume-based
        if (sorted.Count >= 10)
            achievements.Add(new Achievement("Veteran", "Run 10+ audits", "🎖️", true));
        if (sorted.Count >= 50)
            achievements.Add(new Achievement("Dedicated", "Run 50+ audits", "🏅", true));
        if (sorted.Count >= 100)
            achievements.Add(new Achievement("Centurion", "Run 100+ audits", "👑", true));

        // Critical-fix based
        if (profile.TotalCriticalFixed >= 1)
            achievements.Add(new Achievement("Bug Squasher", "Fix your first critical finding", "🐛", true));
        if (profile.TotalCriticalFixed >= 10)
            achievements.Add(new Achievement("Exterminator", "Fix 10+ critical findings", "🪲", true));
        if (profile.TotalCriticalFixed >= 50)
            achievements.Add(new Achievement("Zero Day Hero", "Fix 50+ critical findings", "🦸", true));

        // Zero criticals
        if (sorted.Last().CriticalCount == 0)
            achievements.Add(new Achievement("Clean Slate", "Zero critical findings on latest audit", "✨", true));

        return achievements;
    }
}

/// <summary>
/// Gamification profile with level, XP, streaks, and achievements.
/// </summary>
public class GamificationProfile
{
    public int Level { get; set; } = 1;
    public int TotalXp { get; set; }
    public int XpToNextLevel { get; set; }
    public int TotalAudits { get; set; }
    public int HighestScore { get; set; }
    public int AverageScore { get; set; }
    public int LatestScore { get; set; }
    public int CurrentImprovementStreak { get; set; }
    public int BestImprovementStreak { get; set; }
    public int CurrentPerfectStreak { get; set; }
    public int BestPerfectStreak { get; set; }
    public int TotalCriticalFixed { get; set; }
    public List<Achievement> Achievements { get; set; } = [];
}

/// <summary>
/// A single achievement.
/// </summary>
public class Achievement
{
    public string Name { get; set; }
    public string Description { get; set; }
    public string Icon { get; set; }
    public bool Unlocked { get; set; }

    public Achievement(string name, string description, string icon, bool unlocked)
    {
        Name = name;
        Description = description;
        Icon = icon;
        Unlocked = unlocked;
    }
}
