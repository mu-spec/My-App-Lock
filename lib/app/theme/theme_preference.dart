import 'package:flutter/material.dart';

import '../../data/storage/preferences_store.dart';

/// Settings module: the user's appearance choice.
///
/// Stored through the existing [PreferencesStore.setThemeMode] under
/// `pref.theme.mode` as `system`, `light` or `dark`. Anything else (absent,
/// unreadable or unknown) means [system], the behaviour before this setting
/// existed. Appearance only: it never touches authentication, the native
/// shield or any security policy.
enum AppThemePreference {
  system('system', ThemeMode.system),
  light('light', ThemeMode.light),
  dark('dark', ThemeMode.dark);

  const AppThemePreference(this.id, this.themeMode);

  /// Persisted identifier.
  final String id;

  /// The [MaterialApp.themeMode] this choice applies.
  final ThemeMode themeMode;

  static AppThemePreference fromId(String? id) {
    for (final AppThemePreference p in AppThemePreference.values) {
      if (p.id == id) return p;
    }
    return AppThemePreference.system;
  }

  /// Reads the saved choice; any failure falls back to [system].
  static Future<AppThemePreference> load(PreferencesStore? store) async {
    if (store == null) return AppThemePreference.system;
    try {
      return fromId(await store.getThemeMode());
    } catch (_) {
      return AppThemePreference.system;
    }
  }
}

/// Holds the applied theme choice for the whole app and saves changes.
class ThemePreferenceController extends ValueNotifier<AppThemePreference> {
  ThemePreferenceController({
    AppThemePreference initial = AppThemePreference.system,
    this.store,
  }) : super(initial);

  /// Null in pure widget tests (the choice then applies but is not saved).
  final PreferencesStore? store;

  /// Applies [preference] at once and saves it. Returns false when it could
  /// not be saved (it still applies for this session).
  Future<bool> select(AppThemePreference preference) async {
    value = preference;
    final PreferencesStore? s = store;
    if (s == null) return false;
    try {
      await s.setThemeMode(preference.id);
      return true;
    } catch (_) {
      return false;
    }
  }
}

/// Publishes the [ThemePreferenceController] to the Settings screen.
class ThemePreferenceScope extends InheritedWidget {
  const ThemePreferenceScope({
    super.key,
    required this.controller,
    required super.child,
  });

  final ThemePreferenceController controller;

  static ThemePreferenceController? maybeOf(BuildContext context) => context
      .dependOnInheritedWidgetOfExactType<ThemePreferenceScope>()
      ?.controller;

  @override
  bool updateShouldNotify(ThemePreferenceScope oldWidget) =>
      controller != oldWidget.controller;
}
