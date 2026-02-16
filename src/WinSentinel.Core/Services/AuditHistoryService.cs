using Microsoft.Data.Sqlite;
using WinSentinel.Core.Models;

namespace WinSentinel.Core.Services;

/// <summary>
/// Service for persisting and querying audit history using SQLite.
/// Database is stored at %LocalAppData%/WinSentinel/history.db
/// </summary>
public class AuditHistoryService : IDisposable
{
    private readonly string _connectionString;
    private bool _initialized;
    private bool _disposed;
    private readonly object _initLock = new();

    /// <summary>
    /// Create an AuditHistoryService using the default database path.
    /// </summary>
    public AuditHistoryService()
        : this(GetDefaultDbPath())
    {
    }

    /// <summary>
    /// Create an AuditHistoryService with a custom database path (useful for testing).
    /// </summary>
    public AuditHistoryService(string dbPath)
    {
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        _connectionString = $"Data Source={dbPath}";
    }

    /// <summary>
    /// Get the default database file path.
    /// </summary>
    public static string GetDefaultDbPath()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(localAppData, "WinSentinel", "history.db");
    }

    /// <summary>
    /// Ensure the database schema is created.
    /// </summary>
    public void EnsureDatabase()
    {
        if (_initialized) return;
        lock (_initLock)
        {
            if (_initialized) return;

            using var conn = new SqliteConnection(_connectionString);
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS AuditRuns (
                    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp   TEXT    NOT NULL,
                    OverallScore INTEGER NOT NULL,
                    Grade       TEXT    NOT NULL,
                    TotalFindings INTEGER NOT NULL,
                    CriticalCount INTEGER NOT NULL,
                    WarningCount  INTEGER NOT NULL,
                    InfoCount    INTEGER NOT NULL DEFAULT 0,
                    PassCount    INTEGER NOT NULL DEFAULT 0,
                    IsScheduled  INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS ModuleScores (
                    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId       INTEGER NOT NULL,
                    ModuleName  TEXT    NOT NULL,
                    Category    TEXT    NOT NULL DEFAULT '',
                    Score       INTEGER NOT NULL,
                    FindingCount INTEGER NOT NULL,
                    CriticalCount INTEGER NOT NULL DEFAULT 0,
                    WarningCount  INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (RunId) REFERENCES AuditRuns(Id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS Findings (
                    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    RunId       INTEGER NOT NULL,
                    ModuleName  TEXT    NOT NULL,
                    Title       TEXT    NOT NULL,
                    Severity    TEXT    NOT NULL,
                    Description TEXT    NOT NULL,
                    Remediation TEXT,
                    FOREIGN KEY (RunId) REFERENCES AuditRuns(Id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS IX_AuditRuns_Timestamp ON AuditRuns(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_ModuleScores_RunId ON ModuleScores(RunId);
                CREATE INDEX IF NOT EXISTS IX_Findings_RunId ON Findings(RunId);
            ";
            cmd.ExecuteNonQuery();
            _initialized = true;
        }
    }

    /// <summary>
    /// Save a SecurityReport to the database.
    /// </summary>
    public long SaveAuditResult(SecurityReport report, bool isScheduled = false)
    {
        EnsureDatabase();

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var transaction = conn.BeginTransaction();

        try
        {
            // Insert AuditRun
            using var runCmd = conn.CreateCommand();
            runCmd.Transaction = transaction;
            runCmd.CommandText = @"
                INSERT INTO AuditRuns (Timestamp, OverallScore, Grade, TotalFindings, CriticalCount, WarningCount, InfoCount, PassCount, IsScheduled)
                VALUES (@ts, @score, @grade, @total, @critical, @warning, @info, @pass, @scheduled);
                SELECT last_insert_rowid();
            ";
            runCmd.Parameters.AddWithValue("@ts", report.GeneratedAt.ToString("o"));
            runCmd.Parameters.AddWithValue("@score", report.SecurityScore);
            runCmd.Parameters.AddWithValue("@grade", SecurityScorer.GetGrade(report.SecurityScore));
            runCmd.Parameters.AddWithValue("@total", report.TotalFindings);
            runCmd.Parameters.AddWithValue("@critical", report.TotalCritical);
            runCmd.Parameters.AddWithValue("@warning", report.TotalWarnings);
            runCmd.Parameters.AddWithValue("@info", report.TotalInfo);
            runCmd.Parameters.AddWithValue("@pass", report.TotalPass);
            runCmd.Parameters.AddWithValue("@scheduled", isScheduled ? 1 : 0);

            var runId = (long)runCmd.ExecuteScalar()!;

            // Insert ModuleScores
            foreach (var result in report.Results)
            {
                using var modCmd = conn.CreateCommand();
                modCmd.Transaction = transaction;
                modCmd.CommandText = @"
                    INSERT INTO ModuleScores (RunId, ModuleName, Category, Score, FindingCount, CriticalCount, WarningCount)
                    VALUES (@runId, @name, @category, @score, @findings, @critical, @warning);
                ";
                modCmd.Parameters.AddWithValue("@runId", runId);
                modCmd.Parameters.AddWithValue("@name", result.ModuleName);
                modCmd.Parameters.AddWithValue("@category", result.Category);
                modCmd.Parameters.AddWithValue("@score", result.Score);
                modCmd.Parameters.AddWithValue("@findings", result.Findings.Count);
                modCmd.Parameters.AddWithValue("@critical", result.CriticalCount);
                modCmd.Parameters.AddWithValue("@warning", result.WarningCount);
                modCmd.ExecuteNonQuery();

                // Insert Findings for this module
                foreach (var finding in result.Findings)
                {
                    using var findCmd = conn.CreateCommand();
                    findCmd.Transaction = transaction;
                    findCmd.CommandText = @"
                        INSERT INTO Findings (RunId, ModuleName, Title, Severity, Description, Remediation)
                        VALUES (@runId, @module, @title, @severity, @desc, @remediation);
                    ";
                    findCmd.Parameters.AddWithValue("@runId", runId);
                    findCmd.Parameters.AddWithValue("@module", result.ModuleName);
                    findCmd.Parameters.AddWithValue("@title", finding.Title);
                    findCmd.Parameters.AddWithValue("@severity", finding.Severity.ToString());
                    findCmd.Parameters.AddWithValue("@desc", finding.Description);
                    findCmd.Parameters.AddWithValue("@remediation", (object?)finding.Remediation ?? DBNull.Value);
                    findCmd.ExecuteNonQuery();
                }
            }

            transaction.Commit();
            return runId;
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    /// <summary>
    /// Get audit run history for the specified number of days.
    /// </summary>
    public List<AuditRunRecord> GetHistory(int days = 30)
    {
        EnsureDatabase();

        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
        var runs = new List<AuditRunRecord>();

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT Id, Timestamp, OverallScore, Grade, TotalFindings, CriticalCount, WarningCount, InfoCount, PassCount, IsScheduled
            FROM AuditRuns
            WHERE Timestamp >= @cutoff
            ORDER BY Timestamp DESC;
        ";
        cmd.Parameters.AddWithValue("@cutoff", cutoff.ToString("o"));

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            runs.Add(new AuditRunRecord
            {
                Id = reader.GetInt64(0),
                Timestamp = DateTimeOffset.Parse(reader.GetString(1)),
                OverallScore = reader.GetInt32(2),
                Grade = reader.GetString(3),
                TotalFindings = reader.GetInt32(4),
                CriticalCount = reader.GetInt32(5),
                WarningCount = reader.GetInt32(6),
                InfoCount = reader.GetInt32(7),
                PassCount = reader.GetInt32(8),
                IsScheduled = reader.GetInt32(9) == 1
            });
        }

        return runs;
    }

    /// <summary>
    /// Get the last N audit runs (lightweight, no findings loaded).
    /// </summary>
    public List<AuditRunRecord> GetRecentRuns(int count = 10)
    {
        EnsureDatabase();

        var runs = new List<AuditRunRecord>();

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT Id, Timestamp, OverallScore, Grade, TotalFindings, CriticalCount, WarningCount, InfoCount, PassCount, IsScheduled
            FROM AuditRuns
            ORDER BY Timestamp DESC
            LIMIT @limit;
        ";
        cmd.Parameters.AddWithValue("@limit", count);

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            runs.Add(new AuditRunRecord
            {
                Id = reader.GetInt64(0),
                Timestamp = DateTimeOffset.Parse(reader.GetString(1)),
                OverallScore = reader.GetInt32(2),
                Grade = reader.GetString(3),
                TotalFindings = reader.GetInt32(4),
                CriticalCount = reader.GetInt32(5),
                WarningCount = reader.GetInt32(6),
                InfoCount = reader.GetInt32(7),
                PassCount = reader.GetInt32(8),
                IsScheduled = reader.GetInt32(9) == 1
            });
        }

        return runs;
    }

    /// <summary>
    /// Get a full audit run record with module scores and findings.
    /// </summary>
    public AuditRunRecord? GetRunDetails(long runId)
    {
        EnsureDatabase();

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        // Get the run
        using var runCmd = conn.CreateCommand();
        runCmd.CommandText = @"
            SELECT Id, Timestamp, OverallScore, Grade, TotalFindings, CriticalCount, WarningCount, InfoCount, PassCount, IsScheduled
            FROM AuditRuns WHERE Id = @id;
        ";
        runCmd.Parameters.AddWithValue("@id", runId);

        AuditRunRecord? run = null;
        using (var reader = runCmd.ExecuteReader())
        {
            if (reader.Read())
            {
                run = new AuditRunRecord
                {
                    Id = reader.GetInt64(0),
                    Timestamp = DateTimeOffset.Parse(reader.GetString(1)),
                    OverallScore = reader.GetInt32(2),
                    Grade = reader.GetString(3),
                    TotalFindings = reader.GetInt32(4),
                    CriticalCount = reader.GetInt32(5),
                    WarningCount = reader.GetInt32(6),
                    InfoCount = reader.GetInt32(7),
                    PassCount = reader.GetInt32(8),
                    IsScheduled = reader.GetInt32(9) == 1
                };
            }
        }

        if (run == null) return null;

        // Get module scores
        using var modCmd = conn.CreateCommand();
        modCmd.CommandText = @"
            SELECT Id, RunId, ModuleName, Category, Score, FindingCount, CriticalCount, WarningCount
            FROM ModuleScores WHERE RunId = @runId;
        ";
        modCmd.Parameters.AddWithValue("@runId", runId);

        using (var reader = modCmd.ExecuteReader())
        {
            while (reader.Read())
            {
                run.ModuleScores.Add(new ModuleScoreRecord
                {
                    Id = reader.GetInt64(0),
                    RunId = reader.GetInt64(1),
                    ModuleName = reader.GetString(2),
                    Category = reader.GetString(3),
                    Score = reader.GetInt32(4),
                    FindingCount = reader.GetInt32(5),
                    CriticalCount = reader.GetInt32(6),
                    WarningCount = reader.GetInt32(7)
                });
            }
        }

        // Get findings
        using var findCmd = conn.CreateCommand();
        findCmd.CommandText = @"
            SELECT Id, RunId, ModuleName, Title, Severity, Description, Remediation
            FROM Findings WHERE RunId = @runId;
        ";
        findCmd.Parameters.AddWithValue("@runId", runId);

        using (var reader = findCmd.ExecuteReader())
        {
            while (reader.Read())
            {
                run.Findings.Add(new FindingRecord
                {
                    Id = reader.GetInt64(0),
                    RunId = reader.GetInt64(1),
                    ModuleName = reader.GetString(2),
                    Title = reader.GetString(3),
                    Severity = reader.GetString(4),
                    Description = reader.GetString(5),
                    Remediation = reader.IsDBNull(6) ? null : reader.GetString(6)
                });
            }
        }

        return run;
    }

    /// <summary>
    /// Get score trend summary over a period.
    /// </summary>
    public ScoreTrendSummary GetTrend(int days = 30)
    {
        var runs = GetHistory(days);
        var summary = new ScoreTrendSummary
        {
            TotalScans = runs.Count
        };

        if (runs.Count == 0) return summary;

        // Runs are ordered DESC by timestamp, so newest first
        summary.CurrentScore = runs[0].OverallScore;
        summary.PreviousScore = runs.Count > 1 ? runs[1].OverallScore : null;

        // Build trend points (oldest first for charting)
        summary.Points = runs
            .OrderBy(r => r.Timestamp)
            .Select(r => new ScoreTrendPoint
            {
                Timestamp = r.Timestamp,
                Score = r.OverallScore,
                Grade = r.Grade
            })
            .ToList();

        // Best & Worst
        var best = runs.OrderByDescending(r => r.OverallScore).First();
        summary.BestScore = best.OverallScore;
        summary.BestScoreDate = best.Timestamp;
        summary.BestScoreGrade = best.Grade;

        var worst = runs.OrderBy(r => r.OverallScore).First();
        summary.WorstScore = worst.OverallScore;
        summary.WorstScoreDate = worst.Timestamp;
        summary.WorstScoreGrade = worst.Grade;

        summary.AverageScore = runs.Average(r => (double)r.OverallScore);

        return summary;
    }

    /// <summary>
    /// Get trend information for a specific module.
    /// </summary>
    public List<ModuleTrendInfo> GetModuleHistory(string? moduleName = null, int maxRuns = 2)
    {
        EnsureDatabase();

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        // Get the last N runs
        var recentRunIds = new List<long>();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT Id FROM AuditRuns ORDER BY Timestamp DESC LIMIT @limit;";
            cmd.Parameters.AddWithValue("@limit", maxRuns);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                recentRunIds.Add(reader.GetInt64(0));
            }
        }

        if (recentRunIds.Count == 0) return [];

        var trends = new List<ModuleTrendInfo>();

        // Get module scores from latest run
        using (var cmd = conn.CreateCommand())
        {
            var whereClause = moduleName != null ? " AND ms.ModuleName = @moduleName" : "";
            cmd.CommandText = $@"
                SELECT ms.ModuleName, ms.Category, ms.Score
                FROM ModuleScores ms
                WHERE ms.RunId = @latestRunId{whereClause}
                ORDER BY ms.ModuleName;
            ";
            cmd.Parameters.AddWithValue("@latestRunId", recentRunIds[0]);
            if (moduleName != null)
                cmd.Parameters.AddWithValue("@moduleName", moduleName);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var info = new ModuleTrendInfo
                {
                    ModuleName = reader.GetString(0),
                    Category = reader.GetString(1),
                    CurrentScore = reader.GetInt32(2)
                };
                trends.Add(info);
            }
        }

        // Get previous scores if we have a previous run
        if (recentRunIds.Count > 1)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT ModuleName, Score
                FROM ModuleScores
                WHERE RunId = @prevRunId;
            ";
            cmd.Parameters.AddWithValue("@prevRunId", recentRunIds[1]);

            var prevScores = new Dictionary<string, int>();
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    prevScores[reader.GetString(0)] = reader.GetInt32(1);
                }
            }

            foreach (var trend in trends)
            {
                if (prevScores.TryGetValue(trend.ModuleName, out var prevScore))
                {
                    trend.PreviousScore = prevScore;
                }
            }
        }

        return trends;
    }

    /// <summary>
    /// Delete audit runs older than the specified number of days.
    /// </summary>
    public int PurgeOldRuns(int keepDays = 90)
    {
        EnsureDatabase();

        var cutoff = DateTimeOffset.UtcNow.AddDays(-keepDays);

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        // Enable foreign keys for CASCADE delete
        using (var fkCmd = conn.CreateCommand())
        {
            fkCmd.CommandText = "PRAGMA foreign_keys = ON;";
            fkCmd.ExecuteNonQuery();
        }

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM AuditRuns WHERE Timestamp < @cutoff;";
        cmd.Parameters.AddWithValue("@cutoff", cutoff.ToString("o"));
        return cmd.ExecuteNonQuery();
    }

    /// <summary>
    /// Get the total number of stored audit runs.
    /// </summary>
    public int GetRunCount()
    {
        EnsureDatabase();

        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM AuditRuns;";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
