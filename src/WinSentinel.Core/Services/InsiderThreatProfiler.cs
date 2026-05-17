namespace WinSentinel.Core.Services;

using WinSentinel.Core.Models;

/// <summary>
/// Insider Threat Behavioral Profiler — autonomous detection of insider threats through
/// behavioral baseline analysis, anomaly detection, and pattern recognition.
/// Monitors user activity patterns from security findings and audit history to identify:
/// off-hours activity, data hoarding, privilege abuse, pre-departure signals, and more.
/// </summary>
public sealed class InsiderThreatProfiler
{
    private readonly AuditHistoryService _history;

    // ── Configurable thresholds ──────────────────────────────────────
    private const double ZScoreWarning = 2.0;
    private const double ZScoreCritical = 3.0;
    private const int OffHoursStart = 22; // 10 PM
    private const int OffHoursEnd = 6;    // 6 AM
    private const int CriticalRiskThreshold = 85;
    private const int HighRiskThreshold = 70;
    private const int MediumRiskThreshold = 40;

    // Pre-compiled regex patterns for username extraction
    // (avoids per-call Regex interpretation — O(1) amortised vs O(pattern) per invocation)
    private static readonly System.Text.RegularExpressions.Regex[] UsernamePatterns =
    [
        new(@"user[:\s]+(\w+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled),
        new(@"account[:\s]+(\w+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled),
        new(@"logon.*?(\w+\\[\w.]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled),
        new(@"(\w+)\\(\w+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled),
        new(@"'([^']+)' account", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled),
        new(@"user '([^']+)'", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled),
    ];

    public InsiderThreatProfiler(AuditHistoryService history) => _history = history;

    /// <summary>Run a full insider threat behavioral profiling analysis.</summary>
    public InsiderThreatReport Profile(SecurityReport report, int historyDays = 90)
    {
        var runs = _history.GetHistory(historyDays);
        var findings = report.Results.SelectMany(m =>
            m.Findings.Select(f => (Finding: f, Module: m.ModuleName))).ToList();

        var result = new InsiderThreatReport
        {
            DaysAnalyzed = historyDays,
            EventsProcessed = findings.Count
        };

        // Extract user activity from findings
        var userActivities = ExtractUserActivities(findings, runs);
        result.UsersProfiled = userActivities.Count;

        // Build behavioral baselines and detect deviations
        foreach (var (username, activities) in userActivities)
        {
            var profile = BuildUserProfile(username, activities, historyDays);
            result.Profiles.Add(profile);
        }

        // Detect cross-user insider threat indicators
        result.Indicators = DetectThreatIndicators(result.Profiles, findings);

        // Build anomaly timeline
        result.AnomalyTimeline = BuildAnomalyTimeline(result.Profiles);

        // Compute overall posture
        result.Stats = ComputeStats(result);
        result.PostureScore = ComputePostureScore(result);
        result.RiskTier = ClassifyRiskTier(result.PostureScore);

        // Generate autonomous recommendations
        result.Recommendations = GenerateRecommendations(result);

        // Sort profiles by risk (highest first)
        result.Profiles = result.Profiles.OrderByDescending(p => p.RiskScore).ToList();

        return result;
    }

    // ── User Activity Extraction ─────────────────────────────────────

    private Dictionary<string, List<UserActivityEvent>> ExtractUserActivities(
        List<(Finding Finding, string Module)> findings,
        List<AuditRunRecord> historicalRuns)
    {
        var activities = new Dictionary<string, List<UserActivityEvent>>();

        // Extract from account-related findings
        foreach (var (finding, module) in findings)
        {
            var users = ExtractUsernamesFromFinding(finding, module);
            foreach (var user in users)
            {
                if (!activities.ContainsKey(user))
                    activities[user] = new List<UserActivityEvent>();

                activities[user].Add(new UserActivityEvent
                {
                    Timestamp = finding.Timestamp,
                    EventType = ClassifyEventType(finding, module),
                    Module = module,
                    Description = finding.Title,
                    Severity = finding.Severity
                });
            }
        }

        // Extract from historical runs
        foreach (var run in historicalRuns)
        {
            foreach (var fr in run.Findings)
            {
                var finding = new Finding
                {
                    Title = fr.Title,
                    Description = fr.Description,
                    Category = fr.ModuleName,
                    Severity = Enum.TryParse<Severity>(fr.Severity, true, out var sev) ? sev : Severity.Info,
                    Timestamp = run.Timestamp
                };

                var users = ExtractUsernamesFromFinding(finding, fr.ModuleName);
                foreach (var user in users)
                {
                    if (!activities.ContainsKey(user))
                        activities[user] = new List<UserActivityEvent>();

                    activities[user].Add(new UserActivityEvent
                    {
                        Timestamp = finding.Timestamp,
                        EventType = ClassifyEventType(finding, fr.ModuleName),
                        Module = fr.ModuleName,
                        Description = finding.Title,
                        Severity = finding.Severity
                    });
                }
            }
        }

        // If no real users found, synthesize from finding patterns
        if (activities.Count == 0)
        {
            activities = SynthesizeFromFindings(findings);
        }

        return activities;
    }

    private static List<string> ExtractUsernamesFromFinding(Finding finding, string module)
    {
        var users = new List<string>();
        var text = $"{finding.Title} {finding.Description}";

        // Use pre-compiled static regex patterns (avoid per-call interpretation overhead)
        foreach (var regex in UsernamePatterns)
        {
            var matches = regex.Matches(text);
            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                var user = match.Groups[match.Groups.Count > 2 ? 2 : 1].Value;
                if (!string.IsNullOrWhiteSpace(user) && user.Length > 2 &&
                    !IsSystemAccount(user))
                {
                    users.Add(user);
                }
            }
        }

        // Account audit findings typically reference accounts
        if (users.Count == 0 && module.Contains("Account", StringComparison.OrdinalIgnoreCase))
        {
            users.Add("_account_audit_");
        }

        return users.Distinct().ToList();
    }

    private static bool IsSystemAccount(string user) =>
        user.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
        user.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) ||
        user.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) ||
        user.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
        user.StartsWith("$", StringComparison.Ordinal);

    private static Dictionary<string, List<UserActivityEvent>> SynthesizeFromFindings(
        List<(Finding Finding, string Module)> findings)
    {
        // Group findings by module to create synthetic user profiles
        var activities = new Dictionary<string, List<UserActivityEvent>>();
        var moduleGroups = findings.GroupBy(f => f.Module);

        foreach (var group in moduleGroups)
        {
            var syntheticUser = $"system_{group.Key.ToLowerInvariant().Replace(" ", "_")}";
            activities[syntheticUser] = group.Select(g => new UserActivityEvent
            {
                Timestamp = g.Finding.Timestamp,
                EventType = ClassifyEventType(g.Finding, g.Module),
                Module = g.Module,
                Description = g.Finding.Title,
                Severity = g.Finding.Severity
            }).ToList();
        }

        return activities;
    }

    private static ActivityEventType ClassifyEventType(Finding finding, string module)
    {
        var title = finding.Title.ToLowerInvariant();
        var desc = finding.Description.ToLowerInvariant();
        var combined = $"{title} {desc}";

        if (combined.Contains("logon") || combined.Contains("login") || combined.Contains("authentication"))
            return ActivityEventType.Authentication;
        if (combined.Contains("privilege") || combined.Contains("admin") || combined.Contains("elevated"))
            return ActivityEventType.PrivilegeUse;
        if (combined.Contains("file") || combined.Contains("access") || combined.Contains("read") || combined.Contains("write"))
            return ActivityEventType.FileAccess;
        if (combined.Contains("network") || combined.Contains("connection") || combined.Contains("remote"))
            return ActivityEventType.NetworkActivity;
        if (combined.Contains("install") || combined.Contains("software") || combined.Contains("program"))
            return ActivityEventType.SoftwareInstall;
        if (combined.Contains("usb") || combined.Contains("removable") || combined.Contains("media"))
            return ActivityEventType.RemovableMedia;
        if (combined.Contains("log") && (combined.Contains("clear") || combined.Contains("delete") || combined.Contains("tamper")))
            return ActivityEventType.LogTampering;
        if (combined.Contains("policy") || combined.Contains("setting") || combined.Contains("config"))
            return ActivityEventType.PolicyChange;

        return ActivityEventType.Other;
    }

    // ── Profile Building ─────────────────────────────────────────────

    private UserRiskProfile BuildUserProfile(string username, List<UserActivityEvent> activities, int historyDays)
    {
        var profile = new UserRiskProfile
        {
            Username = username
        };

        // Build baseline from earlier activity
        profile.Baseline = ComputeBaseline(activities, historyDays);

        // Detect deviations from baseline
        profile.Deviations = DetectDeviations(activities, profile.Baseline);

        // Detect threat patterns
        profile.ThreatPatterns = DetectThreatPatterns(activities, profile.Deviations);

        // Check for pre-departure signals
        profile.PreDepartureSignals = DetectPreDepartureSignals(activities, profile.Deviations);

        // Compute activity trend
        profile.ActivityTrend = ComputeActivityTrend(activities);

        // Compute days since normal
        profile.DaysSinceNormalActivity = ComputeDaysSinceNormal(activities, profile.Baseline);

        // Compute composite risk score and classify into a tier.
        // (Previously this used two back-to-back assignments: an initial ternary with an
        // unreachable Critical arm — Critical was checked AFTER High, so RiskScore > 80
        // never won — followed by a corrective if/else ladder that shadowed the first
        // assignment entirely. The ladder is now the single source of truth and the
        // 85 threshold is named.)
        profile.RiskScore = ComputeUserRiskScore(profile);
        profile.RiskLevel = ClassifyInsiderRiskLevel(profile.RiskScore);

        return profile;
    }

    /// <summary>
    /// Map a 0-100 composite insider risk score to a discrete risk tier.
    /// Thresholds are evaluated highest-first so each band is reachable.
    /// </summary>
    private static InsiderRiskLevel ClassifyInsiderRiskLevel(double score) =>
        score >= CriticalRiskThreshold ? InsiderRiskLevel.Critical :
        score >= HighRiskThreshold     ? InsiderRiskLevel.High :
        score >= MediumRiskThreshold   ? InsiderRiskLevel.Medium :
                                         InsiderRiskLevel.Low;

    private static BehavioralBaseline ComputeBaseline(List<UserActivityEvent> activities, int historyDays)
    {
        var baseline = new BehavioralBaseline { BaselineDays = historyDays };

        if (activities.Count == 0) return baseline;

        // Compute typical hours
        var hourCounts = activities
            .GroupBy(a => a.Timestamp.Hour)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .Select(g => g.Key)
            .ToList();
        baseline.TypicalHours = hourCounts;

        // Compute daily logon stats
        var authEvents = activities.Where(a => a.EventType == ActivityEventType.Authentication).ToList();
        var dailyLogons = authEvents
            .GroupBy(a => a.Timestamp.Date)
            .Select(g => (double)g.Count())
            .ToList();

        if (dailyLogons.Count > 0)
        {
            var avgLogons = dailyLogons.Average();
            baseline.AvgDailyLogons = avgLogons;
            baseline.StdDevDailyLogons = dailyLogons.Count > 1
                ? Math.Sqrt(dailyLogons.Sum(x => Math.Pow(x - avgLogons, 2)) / (dailyLogons.Count - 1))
                : 0;
        }

        // Compute file access stats
        var fileEvents = activities.Where(a => a.EventType == ActivityEventType.FileAccess).ToList();
        var dailyFileOps = fileEvents
            .GroupBy(a => a.Timestamp.Date)
            .Select(g => (double)g.Count())
            .ToList();
        baseline.AvgDailyFileOps = dailyFileOps.Count > 0 ? dailyFileOps.Average() : 0;

        // Typical working days
        var workDays = activities
            .GroupBy(a => (int)a.Timestamp.DayOfWeek)
            .OrderByDescending(g => g.Count())
            .Take(5)
            .Select(g => g.Key)
            .ToList();
        baseline.WorkingDays = workDays;

        // Weekly priv esc
        var privEvents = activities.Where(a => a.EventType == ActivityEventType.PrivilegeUse).ToList();
        var weeks = Math.Max(1, historyDays / 7);
        baseline.AvgWeeklyPrivEsc = (double)privEvents.Count / weeks;

        return baseline;
    }

    private static List<BehavioralDeviation> DetectDeviations(
        List<UserActivityEvent> activities, BehavioralBaseline baseline)
    {
        var deviations = new List<BehavioralDeviation>();
        var now = DateTimeOffset.UtcNow;
        var recentWindow = now.AddDays(-7);
        var recentActivities = activities.Where(a => a.Timestamp >= recentWindow).ToList();

        // Single-pass event-type bucketing: count all event types and off-hours in one scan
        // instead of 6+ separate .Count()/. Where() passes over recentActivities
        int offHoursCount = 0;
        int authCount = 0, fileCount = 0, privCount = 0, logTamperCount = 0, removableCount = 0;
        int weekendCount = 0;
        var authByDay = new Dictionary<DateTime, int>();
        var fileByDay = new Dictionary<DateTime, int>();
        foreach (var a in recentActivities)
        {
            var hour = a.Timestamp.Hour;
            if (hour >= OffHoursStart || hour < OffHoursEnd) offHoursCount++;
            var dow = a.Timestamp.DayOfWeek;
            if (dow == DayOfWeek.Saturday || dow == DayOfWeek.Sunday) weekendCount++;
            var day = a.Timestamp.Date;
            switch (a.EventType)
            {
                case ActivityEventType.Authentication:
                    authCount++;
                    authByDay[day] = authByDay.TryGetValue(day, out var ac) ? ac + 1 : 1;
                    break;
                case ActivityEventType.FileAccess:
                    fileCount++;
                    fileByDay[day] = fileByDay.TryGetValue(day, out var fc) ? fc + 1 : 1;
                    break;
                case ActivityEventType.PrivilegeUse: privCount++; break;
                case ActivityEventType.LogTampering: logTamperCount++; break;
                case ActivityEventType.RemovableMedia: removableCount++; break;
            }
        }

        // Check off-hours activity
        if (offHoursCount > 0 && baseline.TypicalHours.Count > 0)
        {
            var typicalOffHours = baseline.TypicalHours.Count(h => h >= OffHoursStart || h < OffHoursEnd);
            if (offHoursCount > typicalOffHours + 2)
            {
                deviations.Add(new BehavioralDeviation
                {
                    Type = DeviationType.OffHoursActivity,
                    Description = $"{offHoursCount} off-hours events in last 7 days (typical: {typicalOffHours})",
                    ZScore = typicalOffHours > 0 ? (double)offHoursCount / typicalOffHours : offHoursCount,
                    Severity = offHoursCount > 10 ? Severity.Critical : Severity.Warning,
                    Expected = $"{typicalOffHours} off-hours events",
                    Actual = $"{offHoursCount} off-hours events"
                });
            }
        }

        // Check excessive logons (use pre-bucketed authByDay)
        var recentDailyLogons = authByDay.Values.Select(c => (double)c).ToList();

        if (recentDailyLogons.Count > 0 && baseline.StdDevDailyLogons > 0)
        {
            var recentAvg = recentDailyLogons.Average();
            var zScore = (recentAvg - baseline.AvgDailyLogons) / baseline.StdDevDailyLogons;
            if (zScore > ZScoreWarning)
            {
                deviations.Add(new BehavioralDeviation
                {
                    Type = DeviationType.ExcessiveLogons,
                    Description = $"Daily logons averaging {recentAvg:F1} vs baseline {baseline.AvgDailyLogons:F1}",
                    ZScore = zScore,
                    Severity = zScore > ZScoreCritical ? Severity.Critical : Severity.Warning,
                    Expected = $"{baseline.AvgDailyLogons:F1} logons/day",
                    Actual = $"{recentAvg:F1} logons/day"
                });
            }
        }

        // Check bulk data operations (use pre-bucketed fileByDay)
        var recentFileOps = fileByDay.Values.Select(c => (double)c).ToList();

        if (recentFileOps.Count > 0 && baseline.AvgDailyFileOps > 0)
        {
            var recentFileAvg = recentFileOps.Average();
            var ratio = recentFileAvg / baseline.AvgDailyFileOps;
            if (ratio > 3.0)
            {
                deviations.Add(new BehavioralDeviation
                {
                    Type = DeviationType.BulkDataOperations,
                    Description = $"File operations {ratio:F1}x above baseline ({recentFileAvg:F0}/day vs {baseline.AvgDailyFileOps:F0}/day)",
                    ZScore = ratio,
                    Severity = ratio > 5.0 ? Severity.Critical : Severity.Warning,
                    Expected = $"{baseline.AvgDailyFileOps:F0} file ops/day",
                    Actual = $"{recentFileAvg:F0} file ops/day"
                });
            }
        }

        // Check weekend activity (use pre-bucketed weekendCount)
        if (weekendCount > 0 && baseline.WorkingDays.Count > 0 &&
            !baseline.WorkingDays.Contains(0) && !baseline.WorkingDays.Contains(6))
        {
            deviations.Add(new BehavioralDeviation
            {
                Type = DeviationType.WeekendActivity,
                Description = $"{weekendCount} events on non-working days (weekends)",
                ZScore = weekendCount > 5 ? 3.0 : 2.0,
                Severity = weekendCount > 10 ? Severity.Critical : Severity.Warning,
                Expected = "No weekend activity",
                Actual = $"{weekendCount} weekend events"
            });
        }

        // Check privilege escalation spike (use pre-bucketed privCount)
        var expectedWeeklyPriv = baseline.AvgWeeklyPrivEsc;
        if (privCount > expectedWeeklyPriv * 2 && privCount > 2)
        {
            deviations.Add(new BehavioralDeviation
            {
                Type = DeviationType.PrivilegeEscalation,
                Description = $"{privCount} privilege events this week vs {expectedWeeklyPriv:F1} typical",
                ZScore = expectedWeeklyPriv > 0 ? privCount / expectedWeeklyPriv : privCount,
                Severity = privCount > expectedWeeklyPriv * 4 ? Severity.Critical : Severity.Warning,
                Expected = $"{expectedWeeklyPriv:F1} privilege events/week",
                Actual = $"{privCount} privilege events this week"
            });
        }

        // Check log tampering (use pre-bucketed logTamperCount)
        if (logTamperCount > 0)
        {
            deviations.Add(new BehavioralDeviation
            {
                Type = DeviationType.LogTampering,
                Description = $"{logTamperCount} log tampering events detected",
                ZScore = 4.0, // Always highly anomalous
                Severity = Severity.Critical,
                Expected = "0 log tampering events",
                Actual = $"{logTamperCount} events"
            });
        }

        // Check removable media / data staging (use pre-bucketed removableCount)
        if (removableCount > 2)
        {
            deviations.Add(new BehavioralDeviation
            {
                Type = DeviationType.DataStagingActivity,
                Description = $"{removableCount} removable media / data staging events",
                ZScore = 2.5,
                Severity = removableCount > 5 ? Severity.Critical : Severity.Warning,
                Expected = "Minimal removable media use",
                Actual = $"{removableCount} events"
            });
        }

        return deviations;
    }

    // ── Pattern Detection ────────────────────────────────────────────

    private static List<string> DetectThreatPatterns(
        List<UserActivityEvent> activities, List<BehavioralDeviation> deviations)
    {
        var patterns = new List<string>();

        // Data exfiltration pattern: bulk file + off-hours + network
        var hasBulkData = deviations.Any(d => d.Type == DeviationType.BulkDataOperations);
        var hasOffHours = deviations.Any(d => d.Type == DeviationType.OffHoursActivity);
        var hasNetwork = activities.Any(a => a.EventType == ActivityEventType.NetworkActivity);

        if (hasBulkData && hasOffHours)
            patterns.Add("DATA_EXFILTRATION: Bulk data operations during off-hours");
        if (hasBulkData && hasNetwork)
            patterns.Add("DATA_STAGING: Large data operations with network activity");

        // Privilege abuse pattern
        var hasPrivEsc = deviations.Any(d => d.Type == DeviationType.PrivilegeEscalation);
        if (hasPrivEsc && hasOffHours)
            patterns.Add("PRIVILEGE_ABUSE: Elevated operations during off-hours");

        // Evasion pattern
        var hasLogTamper = deviations.Any(d => d.Type == DeviationType.LogTampering);
        if (hasLogTamper)
            patterns.Add("EVASION: Audit log tampering detected");
        if (hasLogTamper && hasBulkData)
            patterns.Add("COVER_TRACKS: Log tampering combined with data operations");

        // Reconnaissance pattern
        var diverseModules = activities.Select(a => a.Module).Distinct().Count();
        if (diverseModules > 5)
            patterns.Add("RECONNAISSANCE: Activity spanning many security domains");

        // Accumulation pattern
        var criticalEvents = activities.Count(a => a.Severity == Severity.Critical);
        if (criticalEvents > 3)
            patterns.Add("ESCALATION: Accumulating critical security events");

        return patterns;
    }

    private static bool DetectPreDepartureSignals(
        List<UserActivityEvent> activities, List<BehavioralDeviation> deviations)
    {
        var signals = 0;

        // Signal 1: Bulk data operations (copying personal work)
        if (deviations.Any(d => d.Type == DeviationType.BulkDataOperations))
            signals++;

        // Signal 2: Off-hours activity spike (wrapping up or copying after hours)
        if (deviations.Any(d => d.Type == DeviationType.OffHoursActivity))
            signals++;

        // Signal 3: Removable media usage spike
        if (deviations.Any(d => d.Type == DeviationType.DataStagingActivity))
            signals++;

        // Signal 4: Accessing unusual resources (gathering contacts, documents)
        if (deviations.Any(d => d.Type == DeviationType.UnusualResourceAccess))
            signals++;

        // Signal 5: Recent increase then sudden drop in activity
        var recent = activities.Where(a => a.Timestamp >= DateTimeOffset.UtcNow.AddDays(-14)).ToList();
        var week1 = recent.Count(a => a.Timestamp >= DateTimeOffset.UtcNow.AddDays(-14) &&
                                       a.Timestamp < DateTimeOffset.UtcNow.AddDays(-7));
        var week2 = recent.Count(a => a.Timestamp >= DateTimeOffset.UtcNow.AddDays(-7));
        if (week1 > 0 && week2 < week1 * 0.3)
            signals++;

        return signals >= 3;
    }

    private static string ComputeActivityTrend(List<UserActivityEvent> activities)
    {
        if (activities.Count < 5) return "Insufficient Data";

        var midpoint = DateTimeOffset.UtcNow.AddDays(-14);
        var earlier = activities.Count(a => a.Timestamp < midpoint);
        var later = activities.Count(a => a.Timestamp >= midpoint);

        if (later == 0 && earlier > 0) return "Declining";
        if (earlier == 0) return "New Activity";

        var ratio = (double)later / earlier;
        return ratio > 1.5 ? "Increasing" :
               ratio < 0.5 ? "Declining" :
               "Stable";
    }

    private static int ComputeDaysSinceNormal(List<UserActivityEvent> activities, BehavioralBaseline baseline)
    {
        if (activities.Count == 0) return 0;

        // Find the last day where activity was within normal bounds
        var sortedDays = activities
            .GroupBy(a => a.Timestamp.Date)
            .OrderByDescending(g => g.Key)
            .ToList();

        foreach (var day in sortedDays)
        {
            var dayCount = day.Count();
            if (dayCount <= baseline.AvgDailyLogons + baseline.StdDevDailyLogons * 2)
                return (int)(DateTimeOffset.UtcNow - day.Key).TotalDays;
        }

        return sortedDays.Count > 0 ? (int)(DateTimeOffset.UtcNow - sortedDays.Last().Key).TotalDays : 0;
    }

    private static int ComputeUserRiskScore(UserRiskProfile profile)
    {
        var score = 0;

        // Base score from deviations
        foreach (var dev in profile.Deviations)
        {
            score += dev.Severity switch
            {
                Severity.Critical => 20,
                Severity.Warning => 10,
                Severity.Info => 3,
                _ => 0
            };

            // Extra weight for high z-scores
            if (dev.ZScore > ZScoreCritical)
                score += 10;
        }

        // Threat pattern multiplier
        score += profile.ThreatPatterns.Count * 8;

        // Pre-departure flag
        if (profile.PreDepartureSignals)
            score += 15;

        // Activity trend concern
        if (profile.ActivityTrend == "Increasing")
            score += 5;

        return Math.Min(100, score);
    }

    // ── Cross-User Analysis ──────────────────────────────────────────

    private static List<InsiderThreatIndicator> DetectThreatIndicators(
        List<UserRiskProfile> profiles, List<(Finding Finding, string Module)> findings)
    {
        var indicators = new List<InsiderThreatIndicator>();
        var now = DateTimeOffset.UtcNow;

        foreach (var profile in profiles.Where(p => p.RiskScore >= MediumRiskThreshold))
        {
            // Data exfiltration indicators
            if (profile.ThreatPatterns.Any(p => p.Contains("EXFILTRATION") || p.Contains("STAGING")))
            {
                indicators.Add(new InsiderThreatIndicator
                {
                    Category = InsiderIndicatorCategory.DataExfiltration,
                    Username = profile.Username,
                    Description = $"Potential data exfiltration patterns detected for {profile.Username}",
                    Confidence = Math.Min(95, profile.RiskScore),
                    MitreTechnique = "T1048 - Exfiltration Over Alternative Protocol",
                    Evidence = profile.ThreatPatterns.Where(p =>
                        p.Contains("EXFILTRATION") || p.Contains("STAGING")).ToList(),
                    FirstSeen = now.AddDays(-7),
                    LastSeen = now,
                    Severity = Severity.Critical
                });
            }

            // Privilege abuse
            if (profile.Deviations.Any(d => d.Type == DeviationType.PrivilegeEscalation))
            {
                indicators.Add(new InsiderThreatIndicator
                {
                    Category = InsiderIndicatorCategory.PrivilegeAbuse,
                    Username = profile.Username,
                    Description = $"Unusual privilege escalation activity by {profile.Username}",
                    Confidence = Math.Min(90, 50 + profile.Deviations
                        .Where(d => d.Type == DeviationType.PrivilegeEscalation)
                        .Sum(d => (int)(d.ZScore * 10))),
                    MitreTechnique = "T1078 - Valid Accounts",
                    Evidence = profile.Deviations
                        .Where(d => d.Type == DeviationType.PrivilegeEscalation)
                        .Select(d => d.Description).ToList(),
                    FirstSeen = now.AddDays(-7),
                    LastSeen = now,
                    Severity = Severity.Warning
                });
            }

            // Evasion indicators
            if (profile.ThreatPatterns.Any(p => p.Contains("EVASION") || p.Contains("COVER_TRACKS")))
            {
                indicators.Add(new InsiderThreatIndicator
                {
                    Category = InsiderIndicatorCategory.Evasion,
                    Username = profile.Username,
                    Description = $"Security evasion behavior detected for {profile.Username}",
                    Confidence = 85,
                    MitreTechnique = "T1070 - Indicator Removal",
                    Evidence = profile.ThreatPatterns.Where(p =>
                        p.Contains("EVASION") || p.Contains("COVER")).ToList(),
                    FirstSeen = now.AddDays(-3),
                    LastSeen = now,
                    Severity = Severity.Critical
                });
            }

            // Pre-departure risk
            if (profile.PreDepartureSignals)
            {
                indicators.Add(new InsiderThreatIndicator
                {
                    Category = InsiderIndicatorCategory.PreDeparture,
                    Username = profile.Username,
                    Description = $"Pre-departure behavioral signals detected for {profile.Username}",
                    Confidence = 70,
                    Evidence = new List<string>
                    {
                        "Multiple pre-departure indicators present",
                        $"Risk score: {profile.RiskScore}",
                        $"Activity trend: {profile.ActivityTrend}",
                        $"Threat patterns: {profile.ThreatPatterns.Count}"
                    },
                    FirstSeen = now.AddDays(-14),
                    LastSeen = now,
                    Severity = Severity.Warning
                });
            }

            // Sabotage indicators
            if (profile.ThreatPatterns.Any(p => p.Contains("ESCALATION")) &&
                profile.Deviations.Any(d => d.Type == DeviationType.LogTampering))
            {
                indicators.Add(new InsiderThreatIndicator
                {
                    Category = InsiderIndicatorCategory.Sabotage,
                    Username = profile.Username,
                    Description = $"Potential sabotage indicators: escalating events + evidence destruction for {profile.Username}",
                    Confidence = 75,
                    MitreTechnique = "T1485 - Data Destruction",
                    Evidence = new List<string>
                    {
                        "Critical event accumulation",
                        "Log tampering detected",
                        $"Risk score: {profile.RiskScore}"
                    },
                    FirstSeen = now.AddDays(-5),
                    LastSeen = now,
                    Severity = Severity.Critical
                });
            }
        }

        return indicators.OrderByDescending(i => i.Confidence).ToList();
    }

    // ── Timeline & Scoring ───────────────────────────────────────────

    private static List<BehavioralAnomaly> BuildAnomalyTimeline(List<UserRiskProfile> profiles)
    {
        var timeline = new List<BehavioralAnomaly>();

        foreach (var profile in profiles)
        {
            foreach (var dev in profile.Deviations)
            {
                timeline.Add(new BehavioralAnomaly
                {
                    Timestamp = dev.DetectedAt,
                    Username = profile.Username,
                    AnomalyType = dev.Type.ToString(),
                    Description = dev.Description,
                    ImpactScore = dev.Severity == Severity.Critical ? 9 :
                                  dev.Severity == Severity.Warning ? 6 : 3
                });
            }
        }

        return timeline.OrderByDescending(a => a.Timestamp).ToList();
    }

    private static InsiderThreatStats ComputeStats(InsiderThreatReport report)
    {
        return new InsiderThreatStats
        {
            HighRiskUsers = report.Profiles.Count(p => p.RiskLevel == InsiderRiskLevel.High || p.RiskLevel == InsiderRiskLevel.Critical),
            MediumRiskUsers = report.Profiles.Count(p => p.RiskLevel == InsiderRiskLevel.Medium),
            LowRiskUsers = report.Profiles.Count(p => p.RiskLevel == InsiderRiskLevel.Low),
            OffHoursEvents = report.Profiles.SelectMany(p => p.Deviations)
                .Count(d => d.Type == DeviationType.OffHoursActivity),
            ExfiltrationIndicators = report.Indicators
                .Count(i => i.Category == InsiderIndicatorCategory.DataExfiltration),
            PrivilegeAbuseIndicators = report.Indicators
                .Count(i => i.Category == InsiderIndicatorCategory.PrivilegeAbuse),
            AccountAnomalies = report.Profiles.SelectMany(p => p.Deviations)
                .Count(d => d.Type == DeviationType.ExcessiveLogons || d.Type == DeviationType.AuthenticationAnomalies),
            PreDepartureUsers = report.Profiles.Count(p => p.PreDepartureSignals)
        };
    }

    private static int ComputePostureScore(InsiderThreatReport report)
    {
        if (report.Profiles.Count == 0) return 100;

        var score = 100;

        // Deduct for high-risk users
        score -= report.Stats.HighRiskUsers * 15;
        score -= report.Stats.MediumRiskUsers * 7;

        // Deduct for indicators
        score -= report.Indicators.Count(i => i.Severity == Severity.Critical) * 10;
        score -= report.Indicators.Count(i => i.Severity == Severity.Warning) * 5;

        // Deduct for pre-departure signals
        score -= report.Stats.PreDepartureUsers * 8;

        return Math.Max(0, Math.Min(100, score));
    }

    private static string ClassifyRiskTier(int postureScore) =>
        postureScore >= 80 ? "Low" :
        postureScore >= 60 ? "Moderate" :
        postureScore >= 40 ? "Elevated" :
        postureScore >= 20 ? "High" : "Critical";

    // ── Recommendations ──────────────────────────────────────────────

    private static List<InsiderRecommendation> GenerateRecommendations(InsiderThreatReport report)
    {
        var recs = new List<InsiderRecommendation>();
        var priority = 1;

        // Critical indicators need immediate action
        if (report.Indicators.Any(i => i.Severity == Severity.Critical))
        {
            var critUsers = report.Indicators
                .Where(i => i.Severity == Severity.Critical)
                .Select(i => i.Username)
                .Distinct()
                .ToList();

            recs.Add(new InsiderRecommendation
            {
                Priority = priority++,
                Action = "Initiate formal investigation for critical-risk accounts",
                Rationale = $"{critUsers.Count} account(s) showing critical insider threat indicators",
                Target = string.Join(", ", critUsers),
                ExpectedImpact = "Immediate threat visibility and containment"
            });
        }

        // Data exfiltration recommendations
        if (report.Stats.ExfiltrationIndicators > 0)
        {
            recs.Add(new InsiderRecommendation
            {
                Priority = priority++,
                Action = "Enable DLP (Data Loss Prevention) monitoring on flagged accounts",
                Rationale = $"{report.Stats.ExfiltrationIndicators} data exfiltration indicator(s) detected",
                Target = string.Join(", ", report.Indicators
                    .Where(i => i.Category == InsiderIndicatorCategory.DataExfiltration)
                    .Select(i => i.Username).Distinct()),
                ExpectedImpact = "Block or alert on sensitive data movement"
            });
        }

        // Off-hours policy
        if (report.Stats.OffHoursEvents > 0)
        {
            recs.Add(new InsiderRecommendation
            {
                Priority = priority++,
                Action = "Implement off-hours access restrictions or enhanced monitoring",
                Rationale = $"{report.Stats.OffHoursEvents} deviations involving off-hours activity",
                Target = "All",
                ExpectedImpact = "Reduce attack window for unauthorized operations"
            });
        }

        // Privilege review
        if (report.Stats.PrivilegeAbuseIndicators > 0)
        {
            recs.Add(new InsiderRecommendation
            {
                Priority = priority++,
                Action = "Conduct privilege access review and implement least-privilege enforcement",
                Rationale = $"{report.Stats.PrivilegeAbuseIndicators} privilege abuse indicator(s)",
                Target = string.Join(", ", report.Indicators
                    .Where(i => i.Category == InsiderIndicatorCategory.PrivilegeAbuse)
                    .Select(i => i.Username).Distinct()),
                ExpectedImpact = "Limit blast radius of compromised or malicious accounts"
            });
        }

        // Pre-departure monitoring
        if (report.Stats.PreDepartureUsers > 0)
        {
            recs.Add(new InsiderRecommendation
            {
                Priority = priority++,
                Action = "Cross-reference flagged accounts with HR departure/termination lists",
                Rationale = $"{report.Stats.PreDepartureUsers} user(s) showing pre-departure behavioral patterns",
                Target = string.Join(", ", report.Profiles
                    .Where(p => p.PreDepartureSignals)
                    .Select(p => p.Username)),
                ExpectedImpact = "Prevent intellectual property theft during notice period"
            });
        }

        // General hardening
        if (report.PostureScore < 80)
        {
            recs.Add(new InsiderRecommendation
            {
                Priority = priority++,
                Action = "Deploy User and Entity Behavior Analytics (UEBA) solution",
                Rationale = $"Insider threat posture score ({report.PostureScore}/100) indicates need for continuous monitoring",
                Target = "All",
                ExpectedImpact = "Continuous automated behavioral baseline and anomaly detection"
            });
        }

        return recs;
    }

    // ── Internal Types ───────────────────────────────────────────────

    private class UserActivityEvent
    {
        public DateTimeOffset Timestamp { get; set; }
        public ActivityEventType EventType { get; set; }
        public string Module { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Severity Severity { get; set; }
    }

    private enum ActivityEventType
    {
        Authentication,
        PrivilegeUse,
        FileAccess,
        NetworkActivity,
        SoftwareInstall,
        RemovableMedia,
        LogTampering,
        PolicyChange,
        Other
    }
}
