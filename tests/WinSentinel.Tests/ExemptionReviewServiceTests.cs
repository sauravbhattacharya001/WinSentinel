using System.Text.Json;
using System.Text.Json.Serialization;
using WinSentinel.Cli;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;
using Xunit;

namespace WinSentinel.Tests;

/// <summary>
/// Tests for <see cref="ExemptionReviewService"/>.
/// Each test creates an isolated temp file with pre-configured rules.
/// </summary>
public class ExemptionReviewServiceTests : IDisposable
{
    private readonly List<string> _tempFiles = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public void Dispose()
    {
        foreach (var f in _tempFiles)
        {
            if (File.Exists(f)) File.Delete(f);
        }
    }

    private (IgnoreRuleService svc, ExemptionReviewService review) CreateServices(
        params IgnoreRule[] rules)
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"exemption-test-{Guid.NewGuid():N}.json");
        _tempFiles.Add(tempFile);

        if (rules.Length > 0)
        {
            File.WriteAllText(tempFile, JsonSerializer.Serialize(rules.ToList(), JsonOpts));
        }

        var svc = new IgnoreRuleService(tempFile);
        var review = new ExemptionReviewService(svc);
        return (svc, review);
    }

    // ── Construction ─────────────────────────────────────────────────

    [Fact]
    public void Constructor_NullIgnoreService_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new ExemptionReviewService(null!));
    }

    [Fact]
    public void DefaultConfiguration_SaneValues()
    {
        var (_, review) = CreateServices();
        Assert.Equal(7, review.ExpiryWarningDays);
        Assert.Equal(90, review.StaleDays);
    }

    // ── Empty review ─────────────────────────────────────────────────

    [Fact]
    public void Review_NoRules_ReturnsEmptyResult()
    {
        var (_, review) = CreateServices();
        var result = review.Review();

        Assert.Empty(result.Rules);
        Assert.Empty(result.ExpiringSoon);
        Assert.Empty(result.RecentlyExpired);
        Assert.Empty(result.Stale);
        Assert.Empty(result.Unused);
        Assert.Empty(result.Disabled);
    }

    [Fact]
    public void Review_NoRules_SummaryShowsZeroes()
    {
        var (_, review) = CreateServices();
        var result = review.Review();
        var s = result.Summary;

        Assert.Equal(0, s.TotalRules);
        Assert.Equal(0, s.ActiveRules);
        Assert.Equal(100.0, s.HealthScore);
        Assert.Equal("A", s.HealthGrade);
    }

    // ── Current rules ────────────────────────────────────────────────

    [Fact]
    public void Review_CurrentRule_ClassifiedAsCurrent()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "test", CreatedAt = now.AddDays(-5),
            ExpiresAt = now.AddDays(30), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.Rules);
        Assert.Equal(ExemptionReviewService.ReviewStatus.Current, result.Rules[0].Status);
        Assert.Empty(result.ExpiringSoon);
    }

    // ── Expiring soon ────────────────────────────────────────────────

    [Fact]
    public void Review_ExpiringWithin7Days_ClassifiedAsExpiringSoon()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "expiring", CreatedAt = now.AddDays(-10),
            ExpiresAt = now.AddDays(3), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.ExpiringSoon);
        Assert.Equal(3, result.ExpiringSoon[0].DaysUntilExpiry);
    }

    [Fact]
    public void Review_ExpiresToday_ClassifiedAsExpiringSoon()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "today", CreatedAt = now.AddDays(-10),
            ExpiresAt = now.AddHours(5), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.ExpiringSoon);
        Assert.Equal(0, result.ExpiringSoon[0].DaysUntilExpiry);
        Assert.Contains("today", result.ExpiringSoon[0].Recommendation);
    }

    [Fact]
    public void Review_ExpiresTomorrow_Recommendation()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "tomorrow", CreatedAt = now.AddDays(-10),
            ExpiresAt = now.AddDays(1).AddHours(1), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.ExpiringSoon);
        Assert.Contains("tomorrow", result.ExpiringSoon[0].Recommendation);
    }

    [Fact]
    public void Review_CustomWarningDays_Respected()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "far", CreatedAt = now.AddDays(-5),
            ExpiresAt = now.AddDays(20), Enabled = true
        });

        review.ExpiryWarningDays = 30;
        var result = review.Review(asOf: now);

        Assert.Single(result.ExpiringSoon);
    }

    [Fact]
    public void Review_ExpiringSoon_SortedByDaysLeft()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(
            new IgnoreRule { Pattern = "5d", CreatedAt = now.AddDays(-10), ExpiresAt = now.AddDays(5), Enabled = true },
            new IgnoreRule { Pattern = "1d", CreatedAt = now.AddDays(-10), ExpiresAt = now.AddDays(1), Enabled = true },
            new IgnoreRule { Pattern = "3d", CreatedAt = now.AddDays(-10), ExpiresAt = now.AddDays(3), Enabled = true }
        );

        var result = review.Review(asOf: now);

        Assert.Equal(3, result.ExpiringSoon.Count);
        Assert.True(result.ExpiringSoon[0].DaysUntilExpiry <= result.ExpiringSoon[1].DaysUntilExpiry);
        Assert.True(result.ExpiringSoon[1].DaysUntilExpiry <= result.ExpiringSoon[2].DaysUntilExpiry);
    }

    // ── Recently expired ─────────────────────────────────────────────

    [Fact]
    public void Review_RecentlyExpired_Classified()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "old", CreatedAt = now.AddDays(-30),
            ExpiresAt = now.AddDays(-5), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.RecentlyExpired);
        Assert.True(result.RecentlyExpired[0].DaysUntilExpiry < 0);
    }

    [Fact]
    public void Review_VeryOldExpired_StillClassified()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "ancient", CreatedAt = now.AddDays(-200),
            ExpiresAt = now.AddDays(-100), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.RecentlyExpired);
    }

    // ── Stale rules ──────────────────────────────────────────────────

    [Fact]
    public void Review_OldNoExpiry_ClassifiedAsStale()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "stale", CreatedAt = now.AddDays(-120), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.Stale);
        Assert.Equal(120, result.Stale[0].AgeDays);
    }

    [Fact]
    public void Review_CustomStaleDays_Respected()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "p", CreatedAt = now.AddDays(-50), Enabled = true
        });

        review.StaleDays = 30;
        var result = review.Review(asOf: now);

        Assert.Single(result.Stale);
    }

    [Fact]
    public void Review_Stale_SortedByAge()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(
            new IgnoreRule { Pattern = "newer", CreatedAt = now.AddDays(-100), Enabled = true },
            new IgnoreRule { Pattern = "oldest", CreatedAt = now.AddDays(-200), Enabled = true },
            new IgnoreRule { Pattern = "middle", CreatedAt = now.AddDays(-150), Enabled = true }
        );

        var result = review.Review(asOf: now);

        Assert.Equal(3, result.Stale.Count);
        Assert.True(result.Stale[0].AgeDays >= result.Stale[1].AgeDays);
        Assert.True(result.Stale[1].AgeDays >= result.Stale[2].AgeDays);
    }

    [Fact]
    public void Review_NotStale_UnderThreshold()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "young", CreatedAt = now.AddDays(-30), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Empty(result.Stale);
    }

    // ── Disabled rules ───────────────────────────────────────────────

    [Fact]
    public void Review_DisabledRule_ClassifiedAsDisabled()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "disabled", Enabled = false, CreatedAt = now
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.Disabled);
        Assert.Equal(ExemptionReviewService.ReviewStatus.Disabled, result.Disabled[0].Status);
    }

    [Fact]
    public void Review_DisabledRule_Recommendation()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "disabled", Enabled = false, CreatedAt = now
        });

        var result = review.Review(asOf: now);

        Assert.Contains("disabled", result.Disabled[0].Recommendation, StringComparison.OrdinalIgnoreCase);
    }

    // ── Summary / Health ─────────────────────────────────────────────

    [Fact]
    public void Summary_AllCurrent_HealthA()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(
            new IgnoreRule { Pattern = "ok1", CreatedAt = now.AddDays(-10), ExpiresAt = now.AddDays(30), Enabled = true },
            new IgnoreRule { Pattern = "ok2", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(30), Enabled = true }
        );

        var result = review.Review(asOf: now);

        Assert.Equal("A", result.Summary.HealthGrade);
        Assert.Equal(100.0, result.Summary.HealthScore);
    }

    [Fact]
    public void Summary_AllProblematic_HealthF()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(
            new IgnoreRule { Pattern = "exp1", CreatedAt = now.AddDays(-30), ExpiresAt = now.AddDays(-5), Enabled = true },
            new IgnoreRule { Pattern = "exp2", CreatedAt = now.AddDays(-30), ExpiresAt = now.AddDays(-10), Enabled = true },
            new IgnoreRule { Pattern = "dis", CreatedAt = now, Enabled = false }
        );

        var result = review.Review(asOf: now);

        Assert.Equal("F", result.Summary.HealthGrade);
        Assert.Equal(0.0, result.Summary.HealthScore);
    }

    [Fact]
    public void Summary_MixedRules_CorrectCounts()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(
            new IgnoreRule { Pattern = "current", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(30), Enabled = true },
            new IgnoreRule { Pattern = "expiring", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(3), Enabled = true },
            new IgnoreRule { Pattern = "expired", CreatedAt = now.AddDays(-30), ExpiresAt = now.AddDays(-2), Enabled = true },
            new IgnoreRule { Pattern = "disabled", CreatedAt = now, Enabled = false }
        );

        var result = review.Review(asOf: now);

        Assert.Equal(4, result.Summary.TotalRules);
        Assert.Equal(1, result.Summary.ExpiringSoon);
        Assert.Equal(1, result.Summary.RecentlyExpired);
        Assert.Equal(1, result.Summary.DisabledRules);
    }

    // ── CliParser integration ────────────────────────────────────────

    [Fact]
    public void CliParser_Exemptions_DefaultsToReview()
    {
        var opts = CliParser.Parse(new[] { "--exemptions" });

        Assert.Equal(CliCommand.Exemptions, opts.Command);
        Assert.Equal(ExemptionAction.Review, opts.ExemptionAction);
    }

    [Fact]
    public void CliParser_Exemptions_Expiring()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "expiring" });

        Assert.Equal(CliCommand.Exemptions, opts.Command);
        Assert.Equal(ExemptionAction.Expiring, opts.ExemptionAction);
    }

    [Fact]
    public void CliParser_Exemptions_Stale()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "stale" });
        Assert.Equal(ExemptionAction.Stale, opts.ExemptionAction);
    }

    [Fact]
    public void CliParser_Exemptions_Unused()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "unused" });
        Assert.Equal(ExemptionAction.Unused, opts.ExemptionAction);
    }

    [Fact]
    public void CliParser_Exemptions_Summary()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "summary" });
        Assert.Equal(ExemptionAction.Summary, opts.ExemptionAction);
    }

    [Fact]
    public void CliParser_Exemptions_InvalidAction_Error()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "bogus" });

        Assert.NotNull(opts.Error);
        Assert.Contains("bogus", opts.Error);
    }

    [Fact]
    public void CliParser_WarningDays_Parsed()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "--warning-days", "14" });
        Assert.Equal(14, opts.ExemptionWarningDays);
    }

    [Fact]
    public void CliParser_StaleDays_Parsed()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "--stale-days", "180" });
        Assert.Equal(180, opts.ExemptionStaleDays);
    }

    [Fact]
    public void CliParser_WarningDays_Invalid_Error()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "--warning-days", "abc" });
        Assert.NotNull(opts.Error);
    }

    [Fact]
    public void CliParser_StaleDays_OutOfRange_Error()
    {
        var opts = CliParser.Parse(new[] { "--exemptions", "--stale-days", "9999" });
        Assert.NotNull(opts.Error);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void Review_RuleWithNoExpiry_NotExpiringSoon()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "no expiry", CreatedAt = now.AddDays(-5), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Empty(result.ExpiringSoon);
        Assert.Empty(result.RecentlyExpired);
    }

    [Fact]
    public void Review_AgeDays_CalculatedCorrectly()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "p", CreatedAt = now.AddDays(-42),
            ExpiresAt = now.AddDays(30), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Equal(42, result.Rules[0].AgeDays);
    }

    [Fact]
    public void Review_AsOf_AffectsClassification()
    {
        var createdAt = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var expiresAt = new DateTimeOffset(2025, 2, 1, 0, 0, 0, TimeSpan.Zero);

        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "p", CreatedAt = createdAt, ExpiresAt = expiresAt, Enabled = true
        });

        // Before expiry
        var beforeResult = review.Review(asOf: new DateTimeOffset(2025, 1, 15, 0, 0, 0, TimeSpan.Zero));
        Assert.Empty(beforeResult.RecentlyExpired);

        // After expiry
        var afterResult = review.Review(asOf: new DateTimeOffset(2025, 2, 5, 0, 0, 0, TimeSpan.Zero));
        Assert.Single(afterResult.RecentlyExpired);
    }

    [Fact]
    public void Review_DisabledExpiredRule_ClassifiedAsDisabled()
    {
        // Disabled takes precedence over expired
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "both", CreatedAt = now.AddDays(-30),
            ExpiresAt = now.AddDays(-5), Enabled = false
        });

        var result = review.Review(asOf: now);

        Assert.Single(result.Disabled);
        Assert.Empty(result.RecentlyExpired);
    }

    [Fact]
    public void Review_RecommendationForCurrent_Active()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, review) = CreateServices(new IgnoreRule
        {
            Pattern = "ok", CreatedAt = now.AddDays(-5),
            ExpiresAt = now.AddDays(30), Enabled = true
        });

        var result = review.Review(asOf: now);

        Assert.Contains("No action needed", result.Rules[0].Recommendation);
    }

    [Fact]
    public void Review_HealthGrade_B()
    {
        var now = DateTimeOffset.UtcNow;
        // 5 rules, 1 problem = 80% health = B
        var (_, review) = CreateServices(
            new IgnoreRule { Pattern = "ok1", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(30), Enabled = true },
            new IgnoreRule { Pattern = "ok2", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(30), Enabled = true },
            new IgnoreRule { Pattern = "ok3", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(30), Enabled = true },
            new IgnoreRule { Pattern = "ok4", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(30), Enabled = true },
            new IgnoreRule { Pattern = "bad", CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(-1), Enabled = true }
        );

        var result = review.Review(asOf: now);

        Assert.Equal("B", result.Summary.HealthGrade);
    }
}
