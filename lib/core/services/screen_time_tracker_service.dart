import 'dart:convert';
import 'dart:math';
import '../../models/screen_time_entry.dart';

class CategoryBreakdownST {
  final AppCategory category;
  final int totalMinutes;
  final double percentage;
  final int entryCount;
  final String topApp;
  const CategoryBreakdownST({
    required this.category,
    required this.totalMinutes,
    required this.percentage,
    required this.entryCount,
    required this.topApp,
  });
}

class DailySummary {
  final DateTime date;
  final int totalMinutes;
  final int totalPickups;
  final int appCount;
  final List<CategoryBreakdownST> categoryBreakdown;
  final String topApp;
  final int topAppMinutes;
  final String grade;
  const DailySummary({
    required this.date,
    required this.totalMinutes,
    required this.totalPickups,
    required this.appCount,
    required this.categoryBreakdown,
    required this.topApp,
    required this.topAppMinutes,
    required this.grade,
  });
}

class LimitViolation {
  final String target;
  final int limitMinutes;
  final int actualMinutes;
  final int overageMinutes;
  const LimitViolation({
    required this.target,
    required this.limitMinutes,
    required this.actualMinutes,
    required this.overageMinutes,
  });
}

class WeeklySummary {
  final DateTime weekStart;
  final int totalMinutes;
  final double avgDailyMinutes;
  final int totalPickups;
  final double avgDailyPickups;
  final int daysTracked;
  final String busiestDay;
  final int busiestDayMinutes;
  final String grade;
  final List<CategoryBreakdownST> categoryBreakdown;
  const WeeklySummary({
    required this.weekStart,
    required this.totalMinutes,
    required this.avgDailyMinutes,
    required this.totalPickups,
    required this.avgDailyPickups,
    required this.daysTracked,
    required this.busiestDay,
    required this.busiestDayMinutes,
    required this.grade,
    required this.categoryBreakdown,
  });
}

class ScreenTimeInsight {
  final String type;
  final String message;
  final String severity; // info, warning, alert
  const ScreenTimeInsight({required this.type, required this.message, required this.severity});
}

class ScreenTimeReport {
  final int totalDaysTracked;
  final int totalMinutes;
  final double avgDailyMinutes;
  final int totalPickups;
  final double avgDailyPickups;
  final int currentStreak;
  final int longestStreak;
  final String topApp;
  final AppCategory topCategory;
  final List<CategoryBreakdownST> categoryBreakdown;
  final List<ScreenTimeInsight> insights;
  final String textSummary;
  const ScreenTimeReport({
    required this.totalDaysTracked,
    required this.totalMinutes,
    required this.avgDailyMinutes,
    required this.totalPickups,
    required this.avgDailyPickups,
    required this.currentStreak,
    required this.longestStreak,
    required this.topApp,
    required this.topCategory,
    required this.categoryBreakdown,
    required this.insights,
    required this.textSummary,
  });
}

/// Tracks daily screen time across apps and categories.
/// Supports limits, streaks, weekly summaries, and insights.
class ScreenTimeTrackerService {
  final List<ScreenTimeEntry> _entries = [];
  final List<ScreenTimeLimit> _limits = [];
  int _dailyGoalMinutes;

  List<ScreenTimeEntry> get entries => List.unmodifiable(_entries);
  List<ScreenTimeLimit> get limits => List.unmodifiable(_limits);
  int get dailyGoalMinutes => _dailyGoalMinutes;

  ScreenTimeTrackerService({int dailyGoalMinutes = 180}) : _dailyGoalMinutes = dailyGoalMinutes.clamp(1, 1440);

  // --- CRUD ---

  void addEntry(ScreenTimeEntry entry) {
    if (_entries.any((e) => e.id == entry.id)) {
      throw ArgumentError('Entry with id ${entry.id} already exists');
    }
    if (entry.durationMinutes < 0) throw ArgumentError('Duration must be non-negative');
    _entries.add(entry);
  }

  void removeEntry(String id) {
    final idx = _entries.indexWhere((e) => e.id == id);
    if (idx == -1) throw ArgumentError('Entry $id not found');
    _entries.removeAt(idx);
  }

  void updateEntry(String id, ScreenTimeEntry updated) {
    final idx = _entries.indexWhere((e) => e.id == id);
    if (idx == -1) throw ArgumentError('Entry $id not found');
    _entries[idx] = updated;
  }

  void setDailyGoal(int minutes) {
    _dailyGoalMinutes = minutes.clamp(1, 1440);
  }

  // --- Limits ---

  void addLimit(ScreenTimeLimit limit) {
    if (limit.appName == null && limit.category == null) {
      throw ArgumentError('Limit must target an app or category');
    }
    // Replace existing limit for same target
    _limits.removeWhere((l) => l.appName == limit.appName && l.category == limit.category);
    _limits.add(limit);
  }

  void removeLimit({String? appName, AppCategory? category}) {
    _limits.removeWhere((l) => l.appName == appName && l.category == category);
  }

  List<LimitViolation> checkLimits(DateTime date) {
    final dayEntries = _getEntriesForDate(date);
    final violations = <LimitViolation>[];

    for (final limit in _limits) {
      int actual;
      String target;
      if (limit.appName != null) {
        actual = dayEntries.where((e) => e.appName == limit.appName).fold(0, (sum, e) => sum + e.durationMinutes);
        target = limit.appName!;
      } else {
        actual = dayEntries.where((e) => e.category == limit.category).fold(0, (sum, e) => sum + e.durationMinutes);
        target = limit.category!.name;
      }

      if (actual > limit.dailyLimitMinutes) {
        violations.add(LimitViolation(
          target: target,
          limitMinutes: limit.dailyLimitMinutes,
          actualMinutes: actual,
          overageMinutes: actual - limit.dailyLimitMinutes,
        ));
      }
    }

    // Check daily goal
    final totalDay = dayEntries.fold(0, (sum, e) => sum + e.durationMinutes);
    if (totalDay > _dailyGoalMinutes) {
      violations.add(LimitViolation(
        target: 'Daily Total',
        limitMinutes: _dailyGoalMinutes,
        actualMinutes: totalDay,
        overageMinutes: totalDay - _dailyGoalMinutes,
      ));
    }

    return violations;
  }

  // --- Daily Summary ---

  DailySummary getDailySummary(DateTime date) {
    final dayEntries = _getEntriesForDate(date);
    final totalMin = dayEntries.fold(0, (sum, e) => sum + e.durationMinutes);
    final totalPickups = dayEntries.fold(0, (sum, e) => sum + e.pickups);
    final apps = dayEntries.map((e) => e.appName).toSet();
    final breakdown = _buildCategoryBreakdown(dayEntries, totalMin);

    String topApp = '';
    int topAppMin = 0;
    final appTotals = <String, int>{};
    for (final e in dayEntries) {
      appTotals[e.appName] = (appTotals[e.appName] ?? 0) + e.durationMinutes;
    }
    if (appTotals.isNotEmpty) {
      final top = appTotals.entries.reduce((a, b) => a.value >= b.value ? a : b);
      topApp = top.key;
      topAppMin = top.value;
    }

    return DailySummary(
      date: date,
      totalMinutes: totalMin,
      totalPickups: totalPickups,
      appCount: apps.length,
      categoryBreakdown: breakdown,
      topApp: topApp,
      topAppMinutes: topAppMin,
      grade: _gradeMinutes(totalMin),
    );
  }

  // --- Weekly Summary ---

  WeeklySummary getWeeklySummary(DateTime weekStart) {
    final days = List.generate(7, (i) => weekStart.add(Duration(days: i)));
    final dayNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    final allEntries = <ScreenTimeEntry>[];
    int daysTracked = 0;
    String busiestDay = '';
    int busiestMin = 0;

    for (int i = 0; i < 7; i++) {
      final dayEntries = _getEntriesForDate(days[i]);
      if (dayEntries.isNotEmpty) {
        daysTracked++;
        allEntries.addAll(dayEntries);
        final dayTotal = dayEntries.fold(0, (sum, e) => sum + e.durationMinutes);
        if (dayTotal > busiestMin) {
          busiestMin = dayTotal;
          busiestDay = dayNames[i];
        }
      }
    }

    final totalMin = allEntries.fold(0, (sum, e) => sum + e.durationMinutes);
    final totalPickups = allEntries.fold(0, (sum, e) => sum + e.pickups);
    final breakdown = _buildCategoryBreakdown(allEntries, totalMin);

    return WeeklySummary(
      weekStart: weekStart,
      totalMinutes: totalMin,
      avgDailyMinutes: daysTracked > 0 ? totalMin / daysTracked : 0,
      totalPickups: totalPickups,
      avgDailyPickups: daysTracked > 0 ? totalPickups / daysTracked : 0,
      daysTracked: daysTracked,
      busiestDay: busiestDay,
      busiestDayMinutes: busiestMin,
      grade: _gradeMinutes(daysTracked > 0 ? totalMin ~/ daysTracked : 0),
      categoryBreakdown: breakdown,
    );
  }

  // --- Streaks ---

  int getCurrentStreak({DateTime? asOf}) {
    final today = _normalizeDate(asOf ?? DateTime.now());
    int streak = 0;
    DateTime check = today;
    while (true) {
      final dayEntries = _getEntriesForDate(check);
      if (dayEntries.isEmpty) break;
      final total = dayEntries.fold(0, (sum, e) => sum + e.durationMinutes);
      if (total > _dailyGoalMinutes) break; // Over goal breaks streak
      streak++;
      check = check.subtract(const Duration(days: 1));
    }
    return streak;
  }

  int getLongestStreak() {
    if (_entries.isEmpty) return 0;
    final dates = _entries.map((e) => _normalizeDate(e.date)).toSet().toList()..sort();
    int longest = 0, current = 0;

    for (int i = 0; i < dates.length; i++) {
      final dayEntries = _getEntriesForDate(dates[i]);
      final total = dayEntries.fold(0, (sum, e) => sum + e.durationMinutes);
      if (total <= _dailyGoalMinutes) {
        current++;
        longest = max(longest, current);
      } else {
        current = 0;
      }
    }
    return longest;
  }

  // --- Filtering ---

  List<ScreenTimeEntry> getByApp(String appName) =>
      _entries.where((e) => e.appName == appName).toList();

  List<ScreenTimeEntry> getByCategory(AppCategory category) =>
      _entries.where((e) => e.category == category).toList();

  List<ScreenTimeEntry> getByDateRange(DateTime start, DateTime end) {
    final s = _normalizeDate(start);
    final e = _normalizeDate(end);
    return _entries.where((entry) {
      final d = _normalizeDate(entry.date);
      return !d.isBefore(s) && !d.isAfter(e);
    }).toList();
  }

  // --- App Rankings ---

  List<MapEntry<String, int>> getAppRankings({DateTime? start, DateTime? end}) {
    final filtered = (start != null && end != null) ? getByDateRange(start, end) : _entries;
    final totals = <String, int>{};
    for (final e in filtered) {
      totals[e.appName] = (totals[e.appName] ?? 0) + e.durationMinutes;
    }
    final sorted = totals.entries.toList()..sort((a, b) => b.value.compareTo(a.value));
    return sorted;
  }

  // --- Insights ---

  List<ScreenTimeInsight> generateInsights() {
    final insights = <ScreenTimeInsight>[];
    if (_entries.isEmpty) return insights;

    // Average daily usage
    final dates = _entries.map((e) => _normalizeDate(e.date)).toSet();
    final totalMin = _entries.fold(0, (sum, e) => sum + e.durationMinutes);
    final avgDaily = totalMin / dates.length;

    if (avgDaily > 360) {
      insights.add(ScreenTimeInsight(
        type: 'high_usage',
        message: 'Average daily screen time is ${avgDaily.round()} min (${(avgDaily / 60).toStringAsFixed(1)}h). Consider reducing.',
        severity: 'alert',
      ));
    } else if (avgDaily > 240) {
      insights.add(ScreenTimeInsight(
        type: 'moderate_usage',
        message: 'Average daily screen time is ${avgDaily.round()} min. Room to improve.',
        severity: 'warning',
      ));
    } else {
      insights.add(ScreenTimeInsight(
        type: 'healthy_usage',
        message: 'Average daily screen time is ${avgDaily.round()} min. Good job!',
        severity: 'info',
      ));
    }

    // Social media check
    final socialMin = _entries.where((e) => e.category == AppCategory.social).fold(0, (sum, e) => sum + e.durationMinutes);
    if (totalMin > 0 && socialMin / totalMin > 0.4) {
      insights.add(ScreenTimeInsight(
        type: 'social_heavy',
        message: 'Social media accounts for ${(socialMin / totalMin * 100).round()}% of screen time.',
        severity: 'warning',
      ));
    }

    // Gaming check
    final gamingMin = _entries.where((e) => e.category == AppCategory.gaming).fold(0, (sum, e) => sum + e.durationMinutes);
    if (totalMin > 0 && gamingMin / totalMin > 0.3) {
      insights.add(ScreenTimeInsight(
        type: 'gaming_heavy',
        message: 'Gaming accounts for ${(gamingMin / totalMin * 100).round()}% of screen time.',
        severity: 'warning',
      ));
    }

    // Productivity ratio
    final prodMin = _entries.where((e) => e.category == AppCategory.productivity || e.category == AppCategory.education).fold(0, (sum, e) => sum + e.durationMinutes);
    if (totalMin > 0) {
      final ratio = prodMin / totalMin;
      if (ratio > 0.5) {
        insights.add(ScreenTimeInsight(
          type: 'productive',
          message: '${(ratio * 100).round()}% of screen time is productive/educational.',
          severity: 'info',
        ));
      }
    }

    // Pickup frequency
    final totalPickups = _entries.fold(0, (sum, e) => sum + e.pickups);
    final avgPickups = totalPickups / dates.length;
    if (avgPickups > 80) {
      insights.add(ScreenTimeInsight(
        type: 'high_pickups',
        message: 'Averaging ${avgPickups.round()} pickups/day. Try batching your phone checks.',
        severity: 'warning',
      ));
    }

    return insights;
  }

  // --- Full Report ---

  ScreenTimeReport getReport() {
    if (_entries.isEmpty) {
      return ScreenTimeReport(
        totalDaysTracked: 0, totalMinutes: 0, avgDailyMinutes: 0,
        totalPickups: 0, avgDailyPickups: 0, currentStreak: 0, longestStreak: 0,
        topApp: '', topCategory: AppCategory.other,
        categoryBreakdown: [], insights: [],
        textSummary: 'No screen time data recorded yet.',
      );
    }

    final dates = _entries.map((e) => _normalizeDate(e.date)).toSet();
    final totalMin = _entries.fold(0, (sum, e) => sum + e.durationMinutes);
    final totalPickups = _entries.fold(0, (sum, e) => sum + e.pickups);
    final breakdown = _buildCategoryBreakdown(_entries, totalMin);
    final rankings = getAppRankings();
    final insights = generateInsights();

    final topCat = breakdown.isNotEmpty
        ? breakdown.reduce((a, b) => a.totalMinutes >= b.totalMinutes ? a : b).category
        : AppCategory.other;

    final lines = <String>[
      '=== SCREEN TIME REPORT ===',
      '',
      'Days Tracked: ${dates.length}',
      'Total Screen Time: ${_formatDuration(totalMin)}',
      'Avg Daily: ${_formatDuration(totalMin ~/ dates.length)}',
      'Total Pickups: $totalPickups (avg ${(totalPickups / dates.length).round()}/day)',
      'Daily Goal: ${_formatDuration(_dailyGoalMinutes)}',
      'Current Streak: ${getCurrentStreak()} days under goal',
      'Longest Streak: ${getLongestStreak()} days',
      '',
      'TOP APPS:',
      ...rankings.take(5).map((e) => '  ${e.key}: ${_formatDuration(e.value)}'),
      '',
      'CATEGORIES:',
      ...breakdown.map((b) => '  ${b.category.name}: ${_formatDuration(b.totalMinutes)} (${b.percentage.toStringAsFixed(1)}%)'),
      '',
      'INSIGHTS:',
      ...insights.map((i) => '  [${i.severity.toUpperCase()}] ${i.message}'),
    ];

    return ScreenTimeReport(
      totalDaysTracked: dates.length,
      totalMinutes: totalMin,
      avgDailyMinutes: totalMin / dates.length,
      totalPickups: totalPickups,
      avgDailyPickups: totalPickups / dates.length,
      currentStreak: getCurrentStreak(),
      longestStreak: getLongestStreak(),
      topApp: rankings.isNotEmpty ? rankings.first.key : '',
      topCategory: topCat,
      categoryBreakdown: breakdown,
      insights: insights,
      textSummary: lines.join('\n'),
    );
  }

  // --- Persistence ---

  String exportToJson() => jsonEncode({
    'entries': _entries.map((e) => e.toJson()).toList(),
    'limits': _limits.map((l) => l.toJson()).toList(),
    'dailyGoalMinutes': _dailyGoalMinutes,
  });

  void importFromJson(String json) {
    final data = jsonDecode(json) as Map<String, dynamic>;
    _entries.clear();
    _limits.clear();
    for (final e in (data['entries'] as List)) {
      _entries.add(ScreenTimeEntry.fromJson(e));
    }
    for (final l in (data['limits'] as List)) {
      _limits.add(ScreenTimeLimit.fromJson(l));
    }
    _dailyGoalMinutes = data['dailyGoalMinutes'] ?? 180;
  }

  // --- Private helpers ---

  List<ScreenTimeEntry> _getEntriesForDate(DateTime date) {
    final d = _normalizeDate(date);
    return _entries.where((e) => _normalizeDate(e.date) == d).toList();
  }

  DateTime _normalizeDate(DateTime dt) => DateTime(dt.year, dt.month, dt.day);

  List<CategoryBreakdownST> _buildCategoryBreakdown(List<ScreenTimeEntry> entries, int totalMin) {
    final catMap = <AppCategory, List<ScreenTimeEntry>>{};
    for (final e in entries) {
      catMap.putIfAbsent(e.category, () => []).add(e);
    }

    return catMap.entries.map((entry) {
      final catMin = entry.value.fold(0, (sum, e) => sum + e.durationMinutes);
      final appTotals = <String, int>{};
      for (final e in entry.value) {
        appTotals[e.appName] = (appTotals[e.appName] ?? 0) + e.durationMinutes;
      }
      final topApp = appTotals.entries.reduce((a, b) => a.value >= b.value ? a : b).key;

      return CategoryBreakdownST(
        category: entry.key,
        totalMinutes: catMin,
        percentage: totalMin > 0 ? catMin / totalMin * 100 : 0,
        entryCount: entry.value.length,
        topApp: topApp,
      );
    }).toList()
      ..sort((a, b) => b.totalMinutes.compareTo(a.totalMinutes));
  }

  String _gradeMinutes(int minutes) {
    if (minutes <= _dailyGoalMinutes * 0.5) return 'A';
    if (minutes <= _dailyGoalMinutes * 0.75) return 'B';
    if (minutes <= _dailyGoalMinutes) return 'C';
    if (minutes <= _dailyGoalMinutes * 1.5) return 'D';
    return 'F';
  }

  String _formatDuration(int minutes) {
    final h = minutes ~/ 60;
    final m = minutes % 60;
    if (h == 0) return '${m}m';
    if (m == 0) return '${h}h';
    return '${h}h ${m}m';
  }
}
