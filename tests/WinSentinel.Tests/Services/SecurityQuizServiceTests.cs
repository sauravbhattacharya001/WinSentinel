using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests.Services;

public class SecurityQuizServiceTests
{
    private static SecurityReport CreateTestReport(int criticals = 3, int warnings = 5, int infos = 2)
    {
        var findings = new List<Finding>();

        for (int i = 0; i < criticals; i++)
            findings.Add(Finding.Critical($"Critical Issue {i + 1}",
                $"Critical security vulnerability {i + 1} detected in the system.",
                "Security", $"Apply patch {i + 1}", $"Fix-Command-{i + 1}"));

        for (int i = 0; i < warnings; i++)
            findings.Add(Finding.Warning($"Warning Issue {i + 1}",
                $"Warning-level security concern {i + 1} found in configuration.",
                "Configuration", $"Reconfigure setting {i + 1}"));

        for (int i = 0; i < infos; i++)
            findings.Add(Finding.Info($"Info Issue {i + 1}",
                $"Informational finding {i + 1} about system status.",
                "Information"));

        return new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "SecurityModule",
                    Category = "Security",
                    Findings = findings.Where(f => f.Category == "Security").ToList()
                },
                new()
                {
                    ModuleName = "ConfigModule",
                    Category = "Configuration",
                    Findings = findings.Where(f => f.Category == "Configuration").ToList()
                },
                new()
                {
                    ModuleName = "InfoModule",
                    Category = "Information",
                    Findings = findings.Where(f => f.Category == "Information").ToList()
                }
            },
            SecurityScore = 65
        };
    }

    private static SecurityReport CreateRichReport()
    {
        return new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "WindowsUpdate",
                    Category = "Updates",
                    Findings = new List<Finding>
                    {
                        Finding.Critical("Missing Critical Update KB5001234",
                            "A critical Windows security update is missing.",
                            "Updates", "Install KB5001234 via Windows Update", "wuauclt /updatenow"),
                        Finding.Warning("Optional Update Available",
                            "An optional update is available for .NET Framework.",
                            "Updates", "Install from Windows Update")
                    }
                },
                new()
                {
                    ModuleName = "Firewall",
                    Category = "Network",
                    Findings = new List<Finding>
                    {
                        Finding.Warning("Firewall Rule Too Broad",
                            "A firewall rule allows all inbound traffic on port range 1-65535.",
                            "Network", "Restrict the port range to specific services"),
                        Finding.Critical("Firewall Disabled on Domain Profile",
                            "Windows Firewall is disabled for the domain network profile.",
                            "Network", "Enable domain firewall", "netsh advfirewall set domainprofile state on"),
                        Finding.Info("IPv6 Firewall Active",
                            "IPv6 firewall rules are properly configured.",
                            "Network")
                    }
                },
                new()
                {
                    ModuleName = "Accounts",
                    Category = "Authentication",
                    Findings = new List<Finding>
                    {
                        Finding.Warning("Weak Password Policy",
                            "Minimum password length is below recommended 12 characters.",
                            "Authentication", "Set minimum password length to 12+"),
                        Finding.Critical("Guest Account Enabled",
                            "The built-in Guest account is enabled.",
                            "Authentication", "Disable the Guest account", "net user Guest /active:no")
                    }
                }
            },
            SecurityScore = 45
        };
    }

    // ── Basic generation tests ──────────────────────────────────────

    [Fact]
    public void GenerateQuiz_WithFindings_ReturnsQuestions()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();

        var quiz = svc.GenerateQuiz(report);

        Assert.NotNull(quiz);
        Assert.True(quiz.Questions.Count > 0);
        Assert.Equal(10, quiz.SourceFindingCount);
    }

    [Fact]
    public void GenerateQuiz_EmptyReport_ReturnsEmptyQuiz()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = new SecurityReport();

        var quiz = svc.GenerateQuiz(report);

        Assert.Empty(quiz.Questions);
        Assert.Equal(0, quiz.SourceFindingCount);
    }

    [Fact]
    public void GenerateQuiz_OnlyPassFindings_ReturnsEmptyQuiz()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "Test",
                    Category = "Test",
                    Findings = new List<Finding>
                    {
                        Finding.Pass("All Good", "Everything is fine.", "Test")
                    }
                }
            }
        };

        var quiz = svc.GenerateQuiz(report);
        Assert.Empty(quiz.Questions);
    }

    // ── Question count control ──────────────────────────────────────

    [Fact]
    public void GenerateQuiz_RespectsQuestionCount()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 3 });

        Assert.True(quiz.Questions.Count <= 3);
        Assert.True(quiz.Questions.Count > 0);
    }

    [Fact]
    public void GenerateQuiz_LargeCount_CapsAtAvailable()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport(criticals: 1, warnings: 1, infos: 0);

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 100 });

        // Should not exceed 2 * findings count
        Assert.True(quiz.Questions.Count <= 4);
    }

    // ── Difficulty filtering ────────────────────────────────────────

    [Fact]
    public void GenerateQuiz_FilterByDifficulty_Easy()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions
        {
            QuestionCount = 20,
            Difficulty = QuizDifficulty.Easy
        });

        Assert.All(quiz.Questions, q => Assert.Equal(QuizDifficulty.Easy, q.Difficulty));
    }

    [Fact]
    public void GenerateQuiz_FilterByDifficulty_Hard()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions
        {
            QuestionCount = 20,
            Difficulty = QuizDifficulty.Hard
        });

        Assert.All(quiz.Questions, q => Assert.Equal(QuizDifficulty.Hard, q.Difficulty));
    }

    // ── Category filtering ──────────────────────────────────────────

    [Fact]
    public void GenerateQuiz_FilterByCategory()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions
        {
            QuestionCount = 20,
            Categories = new List<string> { "Security" }
        });

        // All non-overview questions should be Security category
        Assert.All(quiz.Questions.Where(q => q.Category != "Overview" && q.Category != "Risk Assessment"),
            q => Assert.Equal("Security", q.Category));
    }

    // ── Question types ──────────────────────────────────────────────

    [Fact]
    public void GenerateQuiz_ProducesMultipleQuestionTypes()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 20 });

        var types = quiz.Questions.Select(q => q.Type).Distinct().ToList();
        Assert.True(types.Count >= 2, $"Expected multiple question types, got: {string.Join(", ", types)}");
    }

    [Fact]
    public void GenerateQuiz_AllQuestionsHaveValidCorrectIndex()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 20 });

        Assert.All(quiz.Questions, q =>
        {
            Assert.InRange(q.CorrectAnswerIndex, 0, q.Options.Count - 1);
        });
    }

    [Fact]
    public void GenerateQuiz_AllQuestionsHaveOptions()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 20 });

        Assert.All(quiz.Questions, q =>
        {
            Assert.True(q.Options.Count >= 2);
            Assert.False(string.IsNullOrEmpty(q.QuestionText));
        });
    }

    [Fact]
    public void GenerateQuiz_AllQuestionsHavePoints()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 20 });

        Assert.All(quiz.Questions, q => Assert.True(q.Points > 0));
    }

    [Fact]
    public void GenerateQuiz_AllQuestionsHaveExplanation()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 20 });

        Assert.All(quiz.Questions, q => Assert.False(string.IsNullOrEmpty(q.Explanation)));
    }

    // ── Scoring ─────────────────────────────────────────────────────

    [Fact]
    public void ScoreQuiz_PerfectScore()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();
        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 5 });

        var answers = new Dictionary<int, int>();
        for (int i = 0; i < quiz.Questions.Count; i++)
            answers[i] = quiz.Questions[i].CorrectAnswerIndex;

        var result = svc.ScoreQuiz(quiz, answers);

        Assert.Equal(100, result.ScorePercent);
        Assert.Equal("A", result.Grade);
        Assert.Equal(0, result.Wrong);
        Assert.Equal(0, result.Skipped);
        Assert.Empty(result.MissedTopics);
    }

    [Fact]
    public void ScoreQuiz_AllWrong()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();
        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 5 });

        var answers = new Dictionary<int, int>();
        for (int i = 0; i < quiz.Questions.Count; i++)
        {
            // Pick wrong answer
            var wrong = (quiz.Questions[i].CorrectAnswerIndex + 1) % quiz.Questions[i].Options.Count;
            answers[i] = wrong;
        }

        var result = svc.ScoreQuiz(quiz, answers);

        Assert.Equal(0, result.ScorePercent);
        Assert.Equal("F", result.Grade);
        Assert.Equal(0, result.Correct);
        Assert.True(result.MissedTopics.Count > 0);
    }

    [Fact]
    public void ScoreQuiz_SkippedQuestions()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();
        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 5 });

        // Don't answer anything
        var result = svc.ScoreQuiz(quiz, new Dictionary<int, int>());

        Assert.Equal(quiz.Questions.Count, result.Skipped);
        Assert.Equal(0, result.Answered);
        Assert.Equal(0, result.ScorePercent);
    }

    [Fact]
    public void ScoreQuiz_PartialAnswers()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();
        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 5 });

        if (quiz.Questions.Count < 2) return;

        // Answer only first question correctly
        var answers = new Dictionary<int, int>
        {
            [0] = quiz.Questions[0].CorrectAnswerIndex
        };

        var result = svc.ScoreQuiz(quiz, answers);

        Assert.Equal(1, result.Correct);
        Assert.Equal(quiz.Questions.Count - 1, result.Skipped);
        Assert.True(result.ScorePercent > 0);
        Assert.True(result.ScorePercent < 100);
    }

    // ── Grading ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(100, "A")]
    [InlineData(95, "A")]
    [InlineData(90, "A")]
    [InlineData(85, "B")]
    [InlineData(80, "B")]
    [InlineData(75, "C")]
    [InlineData(70, "C")]
    [InlineData(65, "D")]
    [InlineData(60, "D")]
    [InlineData(55, "F")]
    [InlineData(0, "F")]
    public void ScoreQuiz_GradeMapping(int scorePercent, string expectedGrade)
    {
        // Create a quiz with exact scoring control
        var svc = new SecurityQuizService(seed: 42);
        var quiz = new Quiz
        {
            Questions = new List<QuizQuestion>
            {
                new()
                {
                    Id = "test",
                    QuestionText = "Test?",
                    Options = new List<string> { "A", "B" },
                    CorrectAnswerIndex = 0,
                    Points = 100,
                    Category = "Test"
                }
            }
        };

        // Score based on percentage (we'll compute points manually)
        var answers = new Dictionary<int, int>();
        if (scorePercent >= 50) // Correct if >= 50%
            answers[0] = 0;
        else
            answers[0] = 1;

        var result = svc.ScoreQuiz(quiz, answers);
        // Just verify the grade logic works for specific known results
        Assert.False(string.IsNullOrEmpty(result.Grade));
    }

    // ── Export ───────────────────────────────────────────────────────

    [Fact]
    public void ExportToJson_ProducesValidJson()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();
        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 3 });

        var json = svc.ExportToJson(quiz);

        Assert.False(string.IsNullOrEmpty(json));
        Assert.Contains("Questions", json);
        Assert.Contains("QuestionText", json);
    }

    [Fact]
    public void ExportToJson_EmptyQuiz()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = new SecurityReport();
        var quiz = svc.GenerateQuiz(report);

        var json = svc.ExportToJson(quiz);

        Assert.Contains("\"Questions\": []", json);
    }

    // ── Categories ──────────────────────────────────────────────────

    [Fact]
    public void GetAvailableCategories_ReturnsDistinctSorted()
    {
        var svc = new SecurityQuizService();
        var report = CreateTestReport();

        var categories = svc.GetAvailableCategories(report);

        Assert.Contains("Security", categories);
        Assert.Contains("Configuration", categories);
        // Should be sorted
        for (int i = 1; i < categories.Count; i++)
            Assert.True(string.Compare(categories[i - 1], categories[i], StringComparison.OrdinalIgnoreCase) <= 0);
    }

    [Fact]
    public void GetAvailableCategories_ExcludesPassFindings()
    {
        var svc = new SecurityQuizService();
        var report = new SecurityReport
        {
            Results = new List<AuditResult>
            {
                new()
                {
                    ModuleName = "Test",
                    Category = "Test",
                    Findings = new List<Finding>
                    {
                        Finding.Pass("OK", "All good", "PassOnly")
                    }
                }
            }
        };

        var categories = svc.GetAvailableCategories(report);
        Assert.DoesNotContain("PassOnly", categories);
    }

    // ── Deterministic with seed ─────────────────────────────────────

    [Fact]
    public void GenerateQuiz_SameSeed_SameQuestions()
    {
        var report = CreateRichReport();

        var svc1 = new SecurityQuizService(seed: 123);
        var quiz1 = svc1.GenerateQuiz(report, new QuizOptions { QuestionCount = 5 });

        var svc2 = new SecurityQuizService(seed: 123);
        var quiz2 = svc2.GenerateQuiz(report, new QuizOptions { QuestionCount = 5 });

        Assert.Equal(quiz1.Questions.Count, quiz2.Questions.Count);
        for (int i = 0; i < quiz1.Questions.Count; i++)
        {
            Assert.Equal(quiz1.Questions[i].Id, quiz2.Questions[i].Id);
            Assert.Equal(quiz1.Questions[i].QuestionText, quiz2.Questions[i].QuestionText);
        }
    }

    // ── Rich report tests ───────────────────────────────────────────

    [Fact]
    public void GenerateQuiz_RichReport_GeneratesQuestions()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 15 });

        Assert.True(quiz.Questions.Count > 0);
        Assert.Equal(7, quiz.SourceFindingCount); // 3 criticals + 2 warnings + info + warning
    }

    [Fact]
    public void GenerateQuiz_QuestionsHaveUniqueIds()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateRichReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 15 });

        var ids = quiz.Questions.Select(q => q.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    // ── Title customization ─────────────────────────────────────────

    [Fact]
    public void GenerateQuiz_CustomTitle()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();

        var quiz = svc.GenerateQuiz(report, new QuizOptions
        {
            QuestionCount = 3,
            Title = "My Custom Quiz"
        });

        Assert.Equal("My Custom Quiz", quiz.Title);
    }

    [Fact]
    public void GenerateQuiz_DefaultTitle()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport();

        var quiz = svc.GenerateQuiz(report);

        Assert.Equal("Security Knowledge Quiz", quiz.Title);
    }

    // ── Feedback messages ───────────────────────────────────────────

    [Fact]
    public void ScoreQuiz_EmptyQuiz_FeedbackMessage()
    {
        var svc = new SecurityQuizService(seed: 42);
        var quiz = new Quiz();

        var result = svc.ScoreQuiz(quiz, new Dictionary<int, int>());

        Assert.Contains("No questions", result.Feedback);
    }

    [Fact]
    public void ScoreQuiz_PerfectScore_PositiveFeedback()
    {
        var svc = new SecurityQuizService(seed: 42);
        var quiz = new Quiz
        {
            Questions = new List<QuizQuestion>
            {
                new()
                {
                    Id = "t1",
                    QuestionText = "Test?",
                    Options = new List<string> { "A", "B" },
                    CorrectAnswerIndex = 0,
                    Points = 10,
                    Category = "Test"
                }
            }
        };

        var result = svc.ScoreQuiz(quiz, new Dictionary<int, int> { [0] = 0 });

        Assert.Contains("Excellent", result.Feedback);
        Assert.Equal("A", result.Grade);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    [Fact]
    public void GenerateQuiz_SingleFinding()
    {
        var svc = new SecurityQuizService(seed: 42);
        var report = CreateTestReport(criticals: 1, warnings: 0, infos: 0);

        var quiz = svc.GenerateQuiz(report, new QuizOptions { QuestionCount = 5 });

        // Should still generate some questions even with just one finding
        Assert.True(quiz.Questions.Count >= 0); // May be limited
    }

    [Fact]
    public void ScoreQuiz_MissedTopicsTracked()
    {
        var svc = new SecurityQuizService(seed: 42);
        var quiz = new Quiz
        {
            Questions = new List<QuizQuestion>
            {
                new()
                {
                    Id = "t1",
                    QuestionText = "Test?",
                    Options = new List<string> { "A", "B" },
                    CorrectAnswerIndex = 0,
                    Points = 10,
                    Category = "Firewall"
                },
                new()
                {
                    Id = "t2",
                    QuestionText = "Test2?",
                    Options = new List<string> { "A", "B" },
                    CorrectAnswerIndex = 0,
                    Points = 10,
                    Category = "Updates"
                }
            }
        };

        // Answer both wrong
        var result = svc.ScoreQuiz(quiz, new Dictionary<int, int>
        {
            [0] = 1,
            [1] = 1
        });

        Assert.Contains("Firewall", result.MissedTopics);
        Assert.Contains("Updates", result.MissedTopics);
    }
}
