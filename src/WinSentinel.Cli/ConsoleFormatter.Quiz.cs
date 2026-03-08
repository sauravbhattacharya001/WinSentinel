using WinSentinel.Core.Services;

namespace WinSentinel.Cli;

public static partial class ConsoleFormatter
{
    /// <summary>
    /// Print quiz in non-interactive review mode (shows all questions with answers).
    /// </summary>
    public static void PrintQuiz(Quiz quiz, bool showAnswers = false)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored($"  ║  📝 {quiz.Title,-40} ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        WriteColored("  Questions: ", ConsoleColor.Gray);
        Console.WriteLine(quiz.Questions.Count);
        WriteColored("  Source findings: ", ConsoleColor.Gray);
        Console.WriteLine(quiz.SourceFindingCount);
        if (quiz.Difficulty.HasValue)
        {
            WriteColored("  Difficulty: ", ConsoleColor.Gray);
            Console.WriteLine(quiz.Difficulty.Value);
        }
        Console.WriteLine();

        if (quiz.Questions.Count == 0)
        {
            WriteLineColored("  No questions available. Run an audit first!", ConsoleColor.Yellow);
            return;
        }

        for (int i = 0; i < quiz.Questions.Count; i++)
        {
            var q = quiz.Questions[i];
            PrintQuestion(i + 1, q, showAnswers);
        }
    }

    private static void PrintQuestion(int number, QuizQuestion question, bool showAnswer)
    {
        var diffColor = question.Difficulty switch
        {
            QuizDifficulty.Easy => ConsoleColor.Green,
            QuizDifficulty.Medium => ConsoleColor.Yellow,
            QuizDifficulty.Hard => ConsoleColor.Red,
            _ => ConsoleColor.Gray
        };

        WriteColored($"  Q{number}. ", ConsoleColor.White);
        WriteColored($"[{question.Difficulty}] ", diffColor);
        WriteColored($"({question.Points}pt) ", ConsoleColor.DarkGray);
        Console.WriteLine();

        // Question text (may be multiline)
        foreach (var line in question.QuestionText.Split('\n'))
        {
            WriteLineColored($"      {line}", ConsoleColor.White);
        }
        Console.WriteLine();

        for (int j = 0; j < question.Options.Count; j++)
        {
            var prefix = showAnswer && j == question.CorrectAnswerIndex ? " ✓ " : "   ";
            var color = showAnswer && j == question.CorrectAnswerIndex
                ? ConsoleColor.Green
                : ConsoleColor.Gray;

            WriteColored($"      {prefix}", color);
            WriteColored($"{(char)('A' + j)}) ", ConsoleColor.DarkCyan);
            WriteLineColored(question.Options[j], color);
        }

        if (showAnswer && !string.IsNullOrEmpty(question.Explanation))
        {
            Console.WriteLine();
            WriteColored("      💡 ", ConsoleColor.Yellow);
            WriteLineColored(question.Explanation, ConsoleColor.DarkYellow);
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Print quiz results.
    /// </summary>
    public static void PrintQuizResult(QuizResult result)
    {
        Console.WriteLine();
        WriteLineColored("  ╔══════════════════════════════════════════════╗", ConsoleColor.Cyan);
        WriteLineColored("  ║  📊 Quiz Results                            ║", ConsoleColor.Cyan);
        WriteLineColored("  ╚══════════════════════════════════════════════╝", ConsoleColor.Cyan);
        Console.WriteLine();

        var gradeColor = result.Grade switch
        {
            "A" => ConsoleColor.Green,
            "B" => ConsoleColor.DarkGreen,
            "C" => ConsoleColor.Yellow,
            "D" => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };

        WriteColored("  Grade: ", ConsoleColor.Gray);
        WriteLineColored($"{result.Grade} ({result.ScorePercent}%)", gradeColor);

        WriteColored("  Score: ", ConsoleColor.Gray);
        Console.WriteLine($"{result.PointsEarned}/{result.PointsPossible} points");

        WriteColored("  Correct: ", ConsoleColor.Gray);
        WriteColored($"{result.Correct}", ConsoleColor.Green);
        WriteColored("  Wrong: ", ConsoleColor.Gray);
        WriteColored($"{result.Wrong}", ConsoleColor.Red);
        WriteColored("  Skipped: ", ConsoleColor.Gray);
        WriteLineColored($"{result.Skipped}", ConsoleColor.DarkGray);
        Console.WriteLine();

        WriteLineColored($"  {result.Feedback}", ConsoleColor.White);

        if (result.MissedTopics.Count > 0)
        {
            Console.WriteLine();
            WriteLineColored("  Topics to review:", ConsoleColor.Yellow);
            foreach (var topic in result.MissedTopics.OrderBy(t => t))
            {
                WriteLineColored($"    • {topic}", ConsoleColor.Yellow);
            }
        }

        Console.WriteLine();
    }
}
