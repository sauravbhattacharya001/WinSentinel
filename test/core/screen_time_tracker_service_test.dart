import 'package:flutter_test/flutter_test.dart';
import 'package:everything/models/screen_time_entry.dart';
import 'package:everything/core/services/screen_time_tracker_service.dart';

void main() {
  late ScreenTimeTrackerService service;
  final today = DateTime(2026, 3, 5);
  final yesterday = DateTime(2026, 3, 4);

  ScreenTimeEntry _entry({
    String id = '1',
    DateTime? date,
    String appName = 'Instagram',
    AppCategory category = AppCategory.social,
    int duration = 30,
    int pickups = 5,
  }) => ScreenTimeEntry(
    id: id, date: date ?? today, appName: appName,
    category: category, durationMinutes: duration, pickups: pickups,
  );

  setUp(() {
    service = ScreenTimeTrackerService(dailyGoalMinutes: 180);
  });

  group('CRUD', () {
    test('addEntry adds entry', () {
      service.addEntry(_entry());
      expect(service.entries.length, 1);
    });

    test('addEntry rejects duplicate id', () {
      service.addEntry(_entry());
      expect(() => service.addEntry(_entry()), throwsArgumentError);
    });

    test('addEntry rejects negative duration', () {
      expect(() => service.addEntry(_entry(duration: -1)), throwsArgumentError);
    });

    test('removeEntry removes', () {
      service.addEntry(_entry());
      service.removeEntry('1');
      expect(service.entries.length, 0);
    });

    test('removeEntry throws for unknown id', () {
      expect(() => service.removeEntry('nope'), throwsArgumentError);
    });

    test('updateEntry replaces entry', () {
      service.addEntry(_entry(duration: 30));
      service.updateEntry('1', _entry(duration: 60));
      expect(service.entries.first.durationMinutes, 60);
    });

    test('updateEntry throws for unknown id', () {
      expect(() => service.updateEntry('nope', _entry()), throwsArgumentError);
    });

    test('setDailyGoal clamps value', () {
      service.setDailyGoal(0);
      expect(service.dailyGoalMinutes, 1);
      service.setDailyGoal(2000);
      expect(service.dailyGoalMinutes, 1440);
    });
  });

  group('Limits', () {
    test('addLimit for app', () {
      service.addLimit(ScreenTimeLimit(appName: 'Instagram', dailyLimitMinutes: 60));
      expect(service.limits.length, 1);
    });

    test('addLimit rejects no target', () {
      expect(() => service.addLimit(ScreenTimeLimit(dailyLimitMinutes: 60)), throwsArgumentError);
    });

    test('addLimit replaces existing', () {
      service.addLimit(ScreenTimeLimit(appName: 'Instagram', dailyLimitMinutes: 60));
      service.addLimit(ScreenTimeLimit(appName: 'Instagram', dailyLimitMinutes: 30));
      expect(service.limits.length, 1);
      expect(service.limits.first.dailyLimitMinutes, 30);
    });

    test('removeLimit removes', () {
      service.addLimit(ScreenTimeLimit(appName: 'Instagram', dailyLimitMinutes: 60));
      service.removeLimit(appName: 'Instagram');
      expect(service.limits.length, 0);
    });

    test('checkLimits detects app violation', () {
      service.addLimit(ScreenTimeLimit(appName: 'Instagram', dailyLimitMinutes: 20));
      service.addEntry(_entry(id: '1', duration: 25));
      final violations = service.checkLimits(today);
      expect(violations.any((v) => v.target == 'Instagram'), true);
      expect(violations.first.overageMinutes, 5);
    });

    test('checkLimits detects category violation', () {
      service.addLimit(ScreenTimeLimit(category: AppCategory.social, dailyLimitMinutes: 20));
      service.addEntry(_entry(id: '1', duration: 25));
      final violations = service.checkLimits(today);
      expect(violations.any((v) => v.target == 'social'), true);
    });

    test('checkLimits detects daily goal violation', () {
      service.addEntry(_entry(id: '1', duration: 200));
      final violations = service.checkLimits(today);
      expect(violations.any((v) => v.target == 'Daily Total'), true);
    });

    test('checkLimits no violations when under limit', () {
      service.addLimit(ScreenTimeLimit(appName: 'Instagram', dailyLimitMinutes: 60));
      service.addEntry(_entry(id: '1', duration: 30));
      expect(service.checkLimits(today).isEmpty, true);
    });
  });

  group('Daily Summary', () {
    test('returns correct totals', () {
      service.addEntry(_entry(id: '1', duration: 30, pickups: 5));
      service.addEntry(_entry(id: '2', appName: 'Twitter', duration: 20, pickups: 3));
      final summary = service.getDailySummary(today);
      expect(summary.totalMinutes, 50);
      expect(summary.totalPickups, 8);
      expect(summary.appCount, 2);
    });

    test('identifies top app', () {
      service.addEntry(_entry(id: '1', duration: 60));
      service.addEntry(_entry(id: '2', appName: 'Slack', category: AppCategory.communication, duration: 30));
      final summary = service.getDailySummary(today);
      expect(summary.topApp, 'Instagram');
      expect(summary.topAppMinutes, 60);
    });

    test('grades based on goal', () {
      service.addEntry(_entry(id: '1', duration: 50));
      expect(service.getDailySummary(today).grade, 'A');
    });

    test('empty day returns zeroes', () {
      final summary = service.getDailySummary(today);
      expect(summary.totalMinutes, 0);
      expect(summary.appCount, 0);
    });

    test('category breakdown sums correctly', () {
      service.addEntry(_entry(id: '1', duration: 30));
      service.addEntry(_entry(id: '2', appName: 'TikTok', duration: 20));
      final summary = service.getDailySummary(today);
      expect(summary.categoryBreakdown.length, 1);
      expect(summary.categoryBreakdown.first.totalMinutes, 50);
    });
  });

  group('Weekly Summary', () {
    test('returns correct stats', () {
      final monday = DateTime(2026, 3, 2);
      service.addEntry(_entry(id: '1', date: monday, duration: 60));
      service.addEntry(_entry(id: '2', date: monday.add(Duration(days: 1)), duration: 90));
      final summary = service.getWeeklySummary(monday);
      expect(summary.totalMinutes, 150);
      expect(summary.daysTracked, 2);
      expect(summary.avgDailyMinutes, 75);
    });

    test('identifies busiest day', () {
      final monday = DateTime(2026, 3, 2);
      service.addEntry(_entry(id: '1', date: monday, duration: 60));
      service.addEntry(_entry(id: '2', date: monday.add(Duration(days: 2)), duration: 120));
      final summary = service.getWeeklySummary(monday);
      expect(summary.busiestDay, 'Wed');
      expect(summary.busiestDayMinutes, 120);
    });

    test('empty week', () {
      final summary = service.getWeeklySummary(DateTime(2026, 3, 2));
      expect(summary.totalMinutes, 0);
      expect(summary.daysTracked, 0);
    });
  });

  group('Streaks', () {
    test('getCurrentStreak counts under-goal days', () {
      // 3 consecutive days under goal
      service.addEntry(_entry(id: '1', date: today, duration: 100));
      service.addEntry(_entry(id: '2', date: yesterday, duration: 100));
      service.addEntry(_entry(id: '3', date: DateTime(2026, 3, 3), duration: 100));
      expect(service.getCurrentStreak(asOf: today), 3);
    });

    test('getCurrentStreak breaks on over-goal day', () {
      service.addEntry(_entry(id: '1', date: today, duration: 100));
      service.addEntry(_entry(id: '2', date: yesterday, duration: 200)); // over goal
      expect(service.getCurrentStreak(asOf: today), 1);
    });

    test('getCurrentStreak zero when no entries', () {
      expect(service.getCurrentStreak(asOf: today), 0);
    });

    test('getLongestStreak finds max', () {
      service.addEntry(_entry(id: '1', date: DateTime(2026, 3, 1), duration: 100));
      service.addEntry(_entry(id: '2', date: DateTime(2026, 3, 2), duration: 100));
      service.addEntry(_entry(id: '3', date: DateTime(2026, 3, 3), duration: 200)); // break
      service.addEntry(_entry(id: '4', date: DateTime(2026, 3, 4), duration: 100));
      expect(service.getLongestStreak(), 2);
    });

    test('getLongestStreak zero when no entries', () {
      expect(service.getLongestStreak(), 0);
    });
  });

  group('Filtering', () {
    test('getByApp filters correctly', () {
      service.addEntry(_entry(id: '1', appName: 'Instagram'));
      service.addEntry(_entry(id: '2', appName: 'Twitter'));
      expect(service.getByApp('Instagram').length, 1);
    });

    test('getByCategory filters correctly', () {
      service.addEntry(_entry(id: '1', category: AppCategory.social));
      service.addEntry(_entry(id: '2', appName: 'VSCode', category: AppCategory.productivity));
      expect(service.getByCategory(AppCategory.social).length, 1);
    });

    test('getByDateRange returns entries in range', () {
      service.addEntry(_entry(id: '1', date: DateTime(2026, 3, 1)));
      service.addEntry(_entry(id: '2', date: DateTime(2026, 3, 5)));
      service.addEntry(_entry(id: '3', date: DateTime(2026, 3, 10)));
      final results = service.getByDateRange(DateTime(2026, 3, 1), DateTime(2026, 3, 5));
      expect(results.length, 2);
    });
  });

  group('App Rankings', () {
    test('ranks by total duration', () {
      service.addEntry(_entry(id: '1', appName: 'Instagram', duration: 30));
      service.addEntry(_entry(id: '2', appName: 'Instagram', duration: 20));
      service.addEntry(_entry(id: '3', appName: 'Twitter', duration: 60));
      final rankings = service.getAppRankings();
      expect(rankings.first.key, 'Twitter');
      expect(rankings.first.value, 60);
    });

    test('empty rankings', () {
      expect(service.getAppRankings().isEmpty, true);
    });
  });

  group('Insights', () {
    test('empty entries returns empty', () {
      expect(service.generateInsights().isEmpty, true);
    });

    test('detects high usage', () {
      service.addEntry(_entry(id: '1', duration: 400));
      final insights = service.generateInsights();
      expect(insights.any((i) => i.type == 'high_usage'), true);
    });

    test('detects social heavy', () {
      service.addEntry(_entry(id: '1', duration: 90, category: AppCategory.social));
      service.addEntry(_entry(id: '2', appName: 'Slack', duration: 10, category: AppCategory.communication));
      final insights = service.generateInsights();
      expect(insights.any((i) => i.type == 'social_heavy'), true);
    });

    test('detects productive usage', () {
      service.addEntry(_entry(id: '1', appName: 'VSCode', category: AppCategory.productivity, duration: 120));
      service.addEntry(_entry(id: '2', duration: 30));
      final insights = service.generateInsights();
      expect(insights.any((i) => i.type == 'productive'), true);
    });

    test('detects high pickups', () {
      service.addEntry(_entry(id: '1', pickups: 100));
      final insights = service.generateInsights();
      expect(insights.any((i) => i.type == 'high_pickups'), true);
    });
  });

  group('Report', () {
    test('empty report', () {
      final report = service.getReport();
      expect(report.totalDaysTracked, 0);
      expect(report.textSummary, 'No screen time data recorded yet.');
    });

    test('full report with data', () {
      service.addEntry(_entry(id: '1', duration: 60, pickups: 10));
      service.addEntry(_entry(id: '2', appName: 'Slack', category: AppCategory.communication, duration: 30, pickups: 5));
      final report = service.getReport();
      expect(report.totalMinutes, 90);
      expect(report.totalPickups, 15);
      expect(report.topApp, 'Instagram');
      expect(report.categoryBreakdown.isNotEmpty, true);
      expect(report.textSummary.contains('SCREEN TIME REPORT'), true);
    });

    test('report includes insights', () {
      service.addEntry(_entry(id: '1', duration: 400));
      final report = service.getReport();
      expect(report.insights.isNotEmpty, true);
    });
  });

  group('Persistence', () {
    test('export and import roundtrip', () {
      service.addEntry(_entry(id: '1', duration: 60));
      service.addLimit(ScreenTimeLimit(appName: 'Instagram', dailyLimitMinutes: 30));
      service.setDailyGoal(120);

      final json = service.exportToJson();
      final service2 = ScreenTimeTrackerService();
      service2.importFromJson(json);

      expect(service2.entries.length, 1);
      expect(service2.limits.length, 1);
      expect(service2.dailyGoalMinutes, 120);
    });
  });

  group('Model', () {
    test('ScreenTimeEntry copyWith', () {
      final entry = _entry();
      final copy = entry.copyWith(appName: 'Twitter');
      expect(copy.appName, 'Twitter');
      expect(copy.id, entry.id);
    });

    test('ScreenTimeEntry JSON roundtrip', () {
      final entry = _entry();
      final json = entry.toJson();
      final restored = ScreenTimeEntry.fromJson(json);
      expect(restored.id, entry.id);
      expect(restored.appName, entry.appName);
      expect(restored.category, entry.category);
    });

    test('ScreenTimeLimit JSON roundtrip', () {
      final limit = ScreenTimeLimit(appName: 'X', dailyLimitMinutes: 60);
      final json = limit.toJson();
      final restored = ScreenTimeLimit.fromJson(json);
      expect(restored.appName, 'X');
      expect(restored.dailyLimitMinutes, 60);
    });
  });
}
