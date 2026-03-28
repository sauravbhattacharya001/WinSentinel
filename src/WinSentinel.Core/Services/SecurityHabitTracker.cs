using System.Text.Json;

namespace WinSentinel.Core.Services;

/// <summary>
/// Tracks daily security habits (e.g., checking updates, reviewing logs)
/// with streak tracking, consistency scores, and completion history.
/// </summary>
public class SecurityHabitTracker
{
    private readonly string _dataPath;

    public SecurityHabitTracker(string? dataDir = null)
    {
        var dir = dataDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSentinel");
        Directory.CreateDirectory(dir);
        _dataPath = Path.Combine(dir, "habits.json");
    }

    public HabitData Load()
    {
        if (!File.Exists(_dataPath))
            return new HabitData();
        var json = File.ReadAllText(_dataPath);
        return JsonSerializer.Deserialize<HabitData>(json) ?? new HabitData();
    }

    public void Save(HabitData data)
    {
        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_dataPath, json);
    }

    /// <summary>Add a new habit to track.</summary>
    public void AddHabit(string name, string? category = null, string? frequency = null)
    {
        var data = Load();
        if (data.Habits.Any(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"Habit '{name}' already exists.");
        data.Habits.Add(new HabitDefinition
        {
            Name = name,
            Category = category ?? "General",
            Frequency = frequency ?? "daily",
            CreatedDate = DateTime.UtcNow.ToString("yyyy-MM-dd")
        });
        Save(data);
    }

    /// <summary>Remove a habit by name.</summary>
    public void RemoveHabit(string name)
    {
        var data = Load();
        var removed = data.Habits.RemoveAll(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (removed == 0) throw new InvalidOperationException($"Habit '{name}' not found.");
        // Also remove completions
        data.Completions.RemoveAll(c => c.Habit.Equals(name, StringComparison.OrdinalIgnoreCase));
        Save(data);
    }

    /// <summary>Check off a habit for today (or a specific date).</summary>
    public void Complete(string habitName, string? date = null)
    {
        var data = Load();
        var habit = data.Habits.FirstOrDefault(h =>
            h.Name.Equals(habitName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Habit '{habitName}' not found. Add it first with --habits add.");
        var day = date ?? DateTime.UtcNow.ToString("yyyy-MM-dd");
        if (data.Completions.Any(c => c.Habit.Equals(habitName, StringComparison.OrdinalIgnoreCase) && c.Date == day))
            throw new InvalidOperationException($"'{habitName}' already completed for {day}.");
        data.Completions.Add(new HabitCompletion { Habit = habit.Name, Date = day });
        Save(data);
    }

    /// <summary>Generate a report of all habits with streaks and consistency.</summary>
    public HabitReport GetReport(int days = 30)
    {
        var data = Load();
        var today = DateTime.UtcNow.Date;
        var startDate = today.AddDays(-(days - 1));
        var report = new HabitReport { Days = days, GeneratedAt = DateTime.UtcNow };

        foreach (var habit in data.Habits)
        {
            var completions = data.Completions
                .Where(c => c.Habit.Equals(habit.Name, StringComparison.OrdinalIgnoreCase))
                .Select(c => DateTime.Parse(c.Date).Date)
                .Where(d => d >= startDate && d <= today)
                .OrderBy(d => d)
                .ToHashSet();

            var stats = new HabitStats
            {
                Name = habit.Name,
                Category = habit.Category,
                Frequency = habit.Frequency,
                CompletedDays = completions.Count,
                TotalDays = days,
                ConsistencyPercent = Math.Round(100.0 * completions.Count / days, 1),
            };

            // Current streak
            for (var d = today; d >= startDate; d = d.AddDays(-1))
            {
                if (completions.Contains(d)) stats.CurrentStreak++;
                else break;
            }

            // Best streak
            int bestStreak = 0, runStreak = 0;
            for (var d = startDate; d <= today; d = d.AddDays(1))
            {
                if (completions.Contains(d)) { runStreak++; bestStreak = Math.Max(bestStreak, runStreak); }
                else runStreak = 0;
            }
            stats.BestStreak = bestStreak;

            // Last 7 days pattern
            var pattern = new List<bool>();
            for (int i = 6; i >= 0; i--)
                pattern.Add(completions.Contains(today.AddDays(-i)));
            stats.Last7Days = pattern;

            // Completed today?
            stats.CompletedToday = completions.Contains(today);

            report.HabitStats.Add(stats);
        }

        // Overall stats
        if (report.HabitStats.Count > 0)
        {
            report.OverallConsistency = Math.Round(report.HabitStats.Average(s => s.ConsistencyPercent), 1);
            report.CompletedToday = report.HabitStats.Count(s => s.CompletedToday);
            report.TotalHabits = report.HabitStats.Count;
        }

        return report;
    }
}

public class HabitData
{
    public List<HabitDefinition> Habits { get; set; } = new();
    public List<HabitCompletion> Completions { get; set; } = new();
}

public class HabitDefinition
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "General";
    public string Frequency { get; set; } = "daily";
    public string CreatedDate { get; set; } = "";
}

public class HabitCompletion
{
    public string Habit { get; set; } = "";
    public string Date { get; set; } = "";
}

public class HabitReport
{
    public int Days { get; set; }
    public DateTime GeneratedAt { get; set; }
    public int TotalHabits { get; set; }
    public int CompletedToday { get; set; }
    public double OverallConsistency { get; set; }
    public List<HabitStats> HabitStats { get; set; } = new();
}

public class HabitStats
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Frequency { get; set; } = "";
    public int CompletedDays { get; set; }
    public int TotalDays { get; set; }
    public double ConsistencyPercent { get; set; }
    public int CurrentStreak { get; set; }
    public int BestStreak { get; set; }
    public bool CompletedToday { get; set; }
    public List<bool> Last7Days { get; set; } = new();
}
