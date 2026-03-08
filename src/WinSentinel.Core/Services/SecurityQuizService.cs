using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Generates interactive security quizzes from audit findings.
/// Teaches users about their system's security issues through
/// multiple question types: severity classification, remediation
/// matching, true/false, and category identification.
/// </summary>
public class SecurityQuizService
{
    private readonly Random _random;

    public SecurityQuizService(int? seed = null)
    {
        _random = seed.HasValue ? new Random(seed.Value) : new Random();
    }

    /// <summary>
    /// Generate a quiz from audit findings.
    /// </summary>
    /// <param name="report">Security report with findings.</param>
    /// <param name="options">Quiz generation options.</param>
    /// <returns>A quiz with questions derived from real findings.</returns>
    public Quiz GenerateQuiz(SecurityReport report, QuizOptions? options = null)
    {
        options ??= new QuizOptions();
        var allFindings = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity != Severity.Pass)
            .ToList();

        if (allFindings.Count == 0)
        {
            return new Quiz
            {
                Title = "Security Knowledge Quiz",
                GeneratedAt = DateTimeOffset.UtcNow,
                Questions = new List<QuizQuestion>(),
                SourceFindingCount = 0
            };
        }

        var questions = new List<QuizQuestion>();
        var generators = new List<Func<List<Finding>, QuizQuestion?>>
        {
            f => GenerateSeverityQuestion(f),
            f => GenerateRemediationQuestion(f),
            f => GenerateTrueFalseQuestion(f),
            f => GenerateCategoryQuestion(f),
            f => GenerateDescriptionMatchQuestion(f),
            f => GenerateCountQuestion(f, report),
            f => GenerateWorstFindingQuestion(f),
            f => GenerateModuleQuestion(f, report)
        };

        var maxQuestions = Math.Min(options.QuestionCount, allFindings.Count * 2);
        var attempts = 0;
        var usedFindings = new HashSet<string>();

        while (questions.Count < maxQuestions && attempts < maxQuestions * 4)
        {
            attempts++;
            var genIndex = _random.Next(generators.Count);
            var question = generators[genIndex](allFindings);

            if (question != null && !usedFindings.Contains(question.Id))
            {
                // Apply difficulty filter
                if (options.Difficulty.HasValue && question.Difficulty != options.Difficulty.Value)
                    continue;

                // Apply category filter
                if (options.Categories.Count > 0 &&
                    !options.Categories.Contains(question.Category, StringComparer.OrdinalIgnoreCase))
                    continue;

                questions.Add(question);
                usedFindings.Add(question.Id);
            }
        }

        // Shuffle questions
        for (int i = questions.Count - 1; i > 0; i--)
        {
            int j = _random.Next(i + 1);
            (questions[i], questions[j]) = (questions[j], questions[i]);
        }

        return new Quiz
        {
            Title = options.Title ?? "Security Knowledge Quiz",
            GeneratedAt = DateTimeOffset.UtcNow,
            Questions = questions,
            SourceFindingCount = allFindings.Count,
            Difficulty = options.Difficulty
        };
    }

    /// <summary>
    /// Score a completed quiz.
    /// </summary>
    public QuizResult ScoreQuiz(Quiz quiz, Dictionary<int, int> answers)
    {
        var result = new QuizResult
        {
            QuizTitle = quiz.Title,
            TotalQuestions = quiz.Questions.Count,
            CompletedAt = DateTimeOffset.UtcNow
        };

        foreach (var q in quiz.Questions)
        {
            var questionIndex = quiz.Questions.IndexOf(q);
            if (answers.TryGetValue(questionIndex, out var answerIndex))
            {
                result.Answered++;
                if (answerIndex == q.CorrectAnswerIndex)
                {
                    result.Correct++;
                    result.PointsEarned += q.Points;
                }
                else
                {
                    result.Wrong++;
                    result.MissedTopics.Add(q.Category);
                }
                result.PointsPossible += q.Points;
            }
            else
            {
                result.Skipped++;
                result.PointsPossible += q.Points;
            }
        }

        result.ScorePercent = result.PointsPossible > 0
            ? (int)Math.Round(100.0 * result.PointsEarned / result.PointsPossible)
            : 0;

        result.Grade = result.ScorePercent switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };

        result.Feedback = GenerateFeedback(result);

        return result;
    }

    /// <summary>
    /// Export quiz to JSON.
    /// </summary>
    public string ExportToJson(Quiz quiz)
    {
        return JsonSerializer.Serialize(quiz, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        });
    }

    /// <summary>
    /// Get available categories from findings.
    /// </summary>
    public List<string> GetAvailableCategories(SecurityReport report)
    {
        return report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity != Severity.Pass)
            .Select(f => f.Category)
            .Where(c => !string.IsNullOrEmpty(c))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => c)
            .ToList();
    }

    // ── Question generators ─────────────────────────────────────────

    private QuizQuestion? GenerateSeverityQuestion(List<Finding> findings)
    {
        var finding = PickRandom(findings);
        if (finding == null) return null;

        var options = new List<string> { "Info", "Warning", "Critical" };

        return new QuizQuestion
        {
            Id = $"sev-{finding.Title.GetHashCode():X}",
            Type = QuestionType.SeverityClassification,
            Category = finding.Category,
            Difficulty = QuizDifficulty.Easy,
            Points = 1,
            QuestionText = $"What severity level is this finding?\n\"{finding.Title}\"",
            Options = options,
            CorrectAnswerIndex = options.IndexOf(finding.Severity.ToString()),
            Explanation = $"This finding is {finding.Severity} severity. {finding.Description}"
        };
    }

    private QuizQuestion? GenerateRemediationQuestion(List<Finding> findings)
    {
        var withRemediation = findings.Where(f => !string.IsNullOrEmpty(f.Remediation)).ToList();
        if (withRemediation.Count < 2) return null;

        var correct = PickRandom(withRemediation)!;
        var distractors = withRemediation
            .Where(f => f.Title != correct.Title && !string.IsNullOrEmpty(f.Remediation))
            .OrderBy(_ => _random.Next())
            .Take(2)
            .ToList();

        if (distractors.Count < 2) return null;

        var options = new List<string>
        {
            correct.Remediation!,
            distractors[0].Remediation!,
            distractors[1].Remediation!
        };

        // Truncate long options
        options = options.Select(o => o.Length > 120 ? o[..117] + "..." : o).ToList();

        var correctIndex = 0;
        // Shuffle options
        var indices = Enumerable.Range(0, options.Count).OrderBy(_ => _random.Next()).ToList();
        var shuffled = indices.Select(i => options[i]).ToList();
        correctIndex = indices.IndexOf(0);

        return new QuizQuestion
        {
            Id = $"rem-{correct.Title.GetHashCode():X}",
            Type = QuestionType.RemediationMatch,
            Category = correct.Category,
            Difficulty = QuizDifficulty.Medium,
            Points = 2,
            QuestionText = $"Which remediation applies to this finding?\n\"{correct.Title}\"",
            Options = shuffled,
            CorrectAnswerIndex = correctIndex,
            Explanation = $"{correct.Description}"
        };
    }

    private QuizQuestion? GenerateTrueFalseQuestion(List<Finding> findings)
    {
        var finding = PickRandom(findings);
        if (finding == null) return null;

        // Randomly decide if statement is true or false
        bool isTrue = _random.Next(2) == 0;

        string statement;
        if (isTrue)
        {
            statement = $"\"{finding.Title}\" is classified as {finding.Severity} severity.";
        }
        else
        {
            var wrongSeverity = finding.Severity == Severity.Critical ? "Info" : "Critical";
            statement = $"\"{finding.Title}\" is classified as {wrongSeverity} severity.";
        }

        return new QuizQuestion
        {
            Id = $"tf-{finding.Title.GetHashCode():X}-{isTrue}",
            Type = QuestionType.TrueFalse,
            Category = finding.Category,
            Difficulty = QuizDifficulty.Easy,
            Points = 1,
            QuestionText = $"True or False: {statement}",
            Options = new List<string> { "True", "False" },
            CorrectAnswerIndex = isTrue ? 0 : 1,
            Explanation = $"The actual severity is {finding.Severity}. {finding.Description}"
        };
    }

    private QuizQuestion? GenerateCategoryQuestion(List<Finding> findings)
    {
        var categories = findings
            .Select(f => f.Category)
            .Where(c => !string.IsNullOrEmpty(c))
            .Distinct()
            .ToList();

        if (categories.Count < 3) return null;

        var finding = PickRandom(findings.Where(f => !string.IsNullOrEmpty(f.Category)).ToList());
        if (finding == null) return null;

        var correctCat = finding.Category;
        var distractors = categories
            .Where(c => c != correctCat)
            .OrderBy(_ => _random.Next())
            .Take(2)
            .ToList();

        if (distractors.Count < 2) return null;

        var options = new List<string> { correctCat, distractors[0], distractors[1] };
        var indices = Enumerable.Range(0, options.Count).OrderBy(_ => _random.Next()).ToList();
        var shuffled = indices.Select(i => options[i]).ToList();
        var correctIndex = indices.IndexOf(0);

        return new QuizQuestion
        {
            Id = $"cat-{finding.Title.GetHashCode():X}",
            Type = QuestionType.CategoryIdentification,
            Category = finding.Category,
            Difficulty = QuizDifficulty.Medium,
            Points = 2,
            QuestionText = $"Which category does this finding belong to?\n\"{finding.Title}\"",
            Options = shuffled,
            CorrectAnswerIndex = correctIndex,
            Explanation = $"This finding belongs to the \"{correctCat}\" category."
        };
    }

    private QuizQuestion? GenerateDescriptionMatchQuestion(List<Finding> findings)
    {
        if (findings.Count < 3) return null;

        var selected = findings
            .Where(f => f.Description.Length > 20)
            .OrderBy(_ => _random.Next())
            .Take(3)
            .ToList();

        if (selected.Count < 3) return null;

        var correct = selected[0];
        var options = selected.Select(f => f.Title).ToList();
        var indices = Enumerable.Range(0, options.Count).OrderBy(_ => _random.Next()).ToList();
        var shuffled = indices.Select(i => options[i]).ToList();
        var correctIndex = indices.IndexOf(0);

        var desc = correct.Description.Length > 150
            ? correct.Description[..147] + "..."
            : correct.Description;

        return new QuizQuestion
        {
            Id = $"desc-{correct.Title.GetHashCode():X}",
            Type = QuestionType.DescriptionMatch,
            Category = correct.Category,
            Difficulty = QuizDifficulty.Hard,
            Points = 3,
            QuestionText = $"Which finding matches this description?\n\"{desc}\"",
            Options = shuffled,
            CorrectAnswerIndex = correctIndex,
            Explanation = $"The correct answer is \"{correct.Title}\"."
        };
    }

    private QuizQuestion? GenerateCountQuestion(List<Finding> findings, SecurityReport report)
    {
        var severityGroups = findings
            .GroupBy(f => f.Severity)
            .Where(g => g.Key != Severity.Pass)
            .ToList();

        if (severityGroups.Count == 0) return null;

        var group = severityGroups[_random.Next(severityGroups.Count)];
        var correctCount = group.Count();

        var options = new List<int> { correctCount };
        while (options.Count < 4)
        {
            var offset = _random.Next(1, Math.Max(5, correctCount));
            var wrong = _random.Next(2) == 0 ? correctCount + offset : Math.Max(0, correctCount - offset);
            if (!options.Contains(wrong))
                options.Add(wrong);
        }

        var sortedOptions = options.OrderBy(x => x).ToList();
        var correctIndex = sortedOptions.IndexOf(correctCount);

        return new QuizQuestion
        {
            Id = $"cnt-{group.Key}",
            Type = QuestionType.CountEstimate,
            Category = "Overview",
            Difficulty = QuizDifficulty.Medium,
            Points = 2,
            QuestionText = $"How many {group.Key} findings were detected in the latest scan?",
            Options = sortedOptions.Select(x => x.ToString()).ToList(),
            CorrectAnswerIndex = correctIndex,
            Explanation = $"There are {correctCount} {group.Key} findings in the current report."
        };
    }

    private QuizQuestion? GenerateWorstFindingQuestion(List<Finding> findings)
    {
        var criticals = findings.Where(f => f.Severity == Severity.Critical).ToList();
        var warnings = findings.Where(f => f.Severity == Severity.Warning).ToList();

        if (criticals.Count == 0 || warnings.Count == 0) return null;

        var critical = PickRandom(criticals)!;
        var warning = PickRandom(warnings)!;
        var info = findings.FirstOrDefault(f => f.Severity == Severity.Info);

        var options = new List<string> { critical.Title, warning.Title };
        if (info != null) options.Add(info.Title);

        return new QuizQuestion
        {
            Id = $"worst-{critical.Title.GetHashCode():X}",
            Type = QuestionType.HighestRisk,
            Category = "Risk Assessment",
            Difficulty = QuizDifficulty.Easy,
            Points = 1,
            QuestionText = "Which of these findings poses the highest security risk?",
            Options = options,
            CorrectAnswerIndex = 0,
            Explanation = $"\"{critical.Title}\" is Critical severity, making it the highest risk."
        };
    }

    private QuizQuestion? GenerateModuleQuestion(List<Finding> findings, SecurityReport report)
    {
        var modulesWithFindings = report.Results
            .Where(r => r.Findings.Any(f => f.Severity != Severity.Pass))
            .ToList();

        if (modulesWithFindings.Count < 2) return null;

        var target = modulesWithFindings[_random.Next(modulesWithFindings.Count)];
        var finding = PickRandom(target.Findings.Where(f => f.Severity != Severity.Pass).ToList());
        if (finding == null) return null;

        var options = modulesWithFindings
            .Select(r => r.ModuleName)
            .Distinct()
            .OrderBy(_ => _random.Next())
            .Take(3)
            .ToList();

        if (!options.Contains(target.ModuleName))
            options[0] = target.ModuleName;

        var indices = Enumerable.Range(0, options.Count).OrderBy(_ => _random.Next()).ToList();
        var shuffled = indices.Select(i => options[i]).ToList();
        var correctIndex = shuffled.IndexOf(target.ModuleName);

        return new QuizQuestion
        {
            Id = $"mod-{finding.Title.GetHashCode():X}",
            Type = QuestionType.ModuleIdentification,
            Category = finding.Category,
            Difficulty = QuizDifficulty.Hard,
            Points = 3,
            QuestionText = $"Which audit module detected this finding?\n\"{finding.Title}\"",
            Options = shuffled,
            CorrectAnswerIndex = correctIndex,
            Explanation = $"This finding was detected by the \"{target.ModuleName}\" module."
        };
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private T? PickRandom<T>(List<T> items) where T : class
    {
        if (items.Count == 0) return null;
        return items[_random.Next(items.Count)];
    }

    private string GenerateFeedback(QuizResult result)
    {
        if (result.TotalQuestions == 0)
            return "No questions were available. Run an audit first!";

        return result.Grade switch
        {
            "A" => "Excellent! You have a strong understanding of your system's security posture.",
            "B" => "Good work! You know most of your security issues well.",
            "C" => "Fair understanding. Review the findings you missed to improve.",
            "D" => "Needs improvement. Spend time reviewing your audit findings and remediations.",
            _ => "Consider reviewing the WinSentinel documentation and your audit reports."
        };
    }
}

// ── Models ──────────────────────────────────────────────────────────

public class Quiz
{
    public string Title { get; set; } = "Security Knowledge Quiz";
    public DateTimeOffset GeneratedAt { get; set; }
    public List<QuizQuestion> Questions { get; set; } = new();
    public int SourceFindingCount { get; set; }
    public QuizDifficulty? Difficulty { get; set; }
}

public class QuizQuestion
{
    public string Id { get; set; } = string.Empty;
    public QuestionType Type { get; set; }
    public string Category { get; set; } = string.Empty;
    public QuizDifficulty Difficulty { get; set; }
    public int Points { get; set; } = 1;
    public string QuestionText { get; set; } = string.Empty;
    public List<string> Options { get; set; } = new();
    public int CorrectAnswerIndex { get; set; }
    public string Explanation { get; set; } = string.Empty;
}

public class QuizOptions
{
    public int QuestionCount { get; set; } = 10;
    public string? Title { get; set; }
    public QuizDifficulty? Difficulty { get; set; }
    public List<string> Categories { get; set; } = new();
}

public class QuizResult
{
    public string QuizTitle { get; set; } = string.Empty;
    public int TotalQuestions { get; set; }
    public int Answered { get; set; }
    public int Correct { get; set; }
    public int Wrong { get; set; }
    public int Skipped { get; set; }
    public int PointsEarned { get; set; }
    public int PointsPossible { get; set; }
    public int ScorePercent { get; set; }
    public string Grade { get; set; } = "F";
    public string Feedback { get; set; } = string.Empty;
    public HashSet<string> MissedTopics { get; set; } = new();
    public DateTimeOffset CompletedAt { get; set; }
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum QuestionType
{
    SeverityClassification,
    RemediationMatch,
    TrueFalse,
    CategoryIdentification,
    DescriptionMatch,
    CountEstimate,
    HighestRisk,
    ModuleIdentification
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum QuizDifficulty
{
    Easy,
    Medium,
    Hard
}
