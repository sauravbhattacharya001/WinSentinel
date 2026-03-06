/// Screen Time Tracker models for tracking device/app usage.

enum AppCategory {
  social,
  entertainment,
  productivity,
  communication,
  education,
  health,
  finance,
  news,
  gaming,
  utilities,
  shopping,
  travel,
  other,
}

class ScreenTimeEntry {
  final String id;
  final DateTime date;
  final String appName;
  final AppCategory category;
  final int durationMinutes;
  final int pickups;
  final String? notes;

  const ScreenTimeEntry({
    required this.id,
    required this.date,
    required this.appName,
    required this.category,
    required this.durationMinutes,
    this.pickups = 0,
    this.notes,
  });

  ScreenTimeEntry copyWith({
    String? id,
    DateTime? date,
    String? appName,
    AppCategory? category,
    int? durationMinutes,
    int? pickups,
    String? notes,
  }) {
    return ScreenTimeEntry(
      id: id ?? this.id,
      date: date ?? this.date,
      appName: appName ?? this.appName,
      category: category ?? this.category,
      durationMinutes: durationMinutes ?? this.durationMinutes,
      pickups: pickups ?? this.pickups,
      notes: notes ?? this.notes,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'date': date.toIso8601String(),
    'appName': appName,
    'category': category.name,
    'durationMinutes': durationMinutes,
    'pickups': pickups,
    'notes': notes,
  };

  factory ScreenTimeEntry.fromJson(Map<String, dynamic> json) => ScreenTimeEntry(
    id: json['id'],
    date: DateTime.parse(json['date']),
    appName: json['appName'],
    category: AppCategory.values.firstWhere((c) => c.name == json['category']),
    durationMinutes: json['durationMinutes'],
    pickups: json['pickups'] ?? 0,
    notes: json['notes'],
  );
}

class ScreenTimeLimit {
  final String? appName;
  final AppCategory? category;
  final int dailyLimitMinutes;

  const ScreenTimeLimit({
    this.appName,
    this.category,
    required this.dailyLimitMinutes,
  });

  Map<String, dynamic> toJson() => {
    'appName': appName,
    'category': category?.name,
    'dailyLimitMinutes': dailyLimitMinutes,
  };

  factory ScreenTimeLimit.fromJson(Map<String, dynamic> json) => ScreenTimeLimit(
    appName: json['appName'],
    category: json['category'] != null
        ? AppCategory.values.firstWhere((c) => c.name == json['category'])
        : null,
    dailyLimitMinutes: json['dailyLimitMinutes'],
  );
}
