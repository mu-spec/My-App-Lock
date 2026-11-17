// Phase 14 / M1 — notification privacy controller: per-app settings for
// PROTECTED apps, mirrored to native for the listener.
//
// Native always receives the full stored snapshot. Eligibility (protected
// + protection enabled) is decided natively at use time, so a stale entry
// for an app that is no longer protected is harmless and re-applies if the
// app is protected again (the screen shows the same value).
//
// Fail closed: when the stored record cannot be read, nothing is pushed and
// native keeps its last snapshot (it never weakens to "off").

import '../../data/models/protected_app.dart';
import '../../data/repositories/protected_apps_repository.dart';
import '../../services/notification_privacy_service.dart';
import 'notification_privacy_settings.dart';

enum NotificationPrivacyChangeOutcome {
  /// Saved and native accepted the snapshot.
  saved,

  /// Saved, but native did not confirm (retried on the next sync).
  savedNotApplied,

  unchanged,

  /// Not a protected app, or the stored record is not writable.
  refused,
}

final class NotificationPrivacyView {
  const NotificationPrivacyView({
    required this.health,
    required this.settings,
    required this.apps,
    required this.status,
  });

  final NotificationPrivacyHealth health;
  final NotificationPrivacySettings settings;

  /// Protected apps (the only apps that can be configured).
  final List<ProtectedApp> apps;

  /// Native state (null when native could not be read).
  final NotificationPrivacyStatus? status;

  bool get writable =>
      health == NotificationPrivacyHealth.ok ||
      health == NotificationPrivacyHealth.missing;
}

class NotificationPrivacyController {
  NotificationPrivacyController({
    required NotificationPrivacySettingsStore store,
    required NotificationPrivacyService service,
    required ProtectedAppsRepository protectedApps,
  })  : _store = store,
        _service = service,
        _protectedApps = protectedApps;

  final NotificationPrivacySettingsStore _store;
  final NotificationPrivacyService _service;
  final ProtectedAppsRepository _protectedApps;

  NotificationPrivacyService get service => _service;

  Future<NotificationPrivacyView> load() async {
    final NotificationPrivacyRead r = await _store.read();
    final List<ProtectedApp> apps =
        (await _protectedApps.getProtectedApps()).valueOrNull ??
            const <ProtectedApp>[];
    final NotificationPrivacyStatus? status =
        (await _service.status()).valueOrNull;
    return NotificationPrivacyView(
      health: r.health,
      settings: r.settings,
      apps: apps,
      status: status,
    );
  }

  /// Sets [packageName]'s mode. Weakening must be owner-verified by the
  /// caller first (UI responsibility).
  Future<NotificationPrivacyChangeOutcome> setMode(
      String packageName, NotificationPrivacyMode mode) async {
    if ((await _protectedApps.isProtected(packageName)).valueOrNull != true) {
      return NotificationPrivacyChangeOutcome.refused;
    }
    bool changed = false;
    final NotificationPrivacySettings? saved =
        await _store.update((NotificationPrivacySettings s) {
      changed = s.modeFor(packageName) != mode;
      return s.withMode(packageName, mode);
    });
    if (saved == null) return NotificationPrivacyChangeOutcome.refused;
    final bool applied = await sync();
    if (!changed) return NotificationPrivacyChangeOutcome.unchanged;
    return applied
        ? NotificationPrivacyChangeOutcome.saved
        : NotificationPrivacyChangeOutcome.savedNotApplied;
  }

  /// Pushes the stored snapshot to native. Returns true when native
  /// accepted it; false (nothing pushed) when the record is unreadable.
  Future<bool> sync() async {
    final NotificationPrivacyRead r = await _store.read();
    if (!r.writable) return false;
    return (await _service.configure(r.settings.apps)).valueOrNull == true;
  }
}
