// P13/M3 Batch 5 — History retention controls (F-2).
//
// Governing design: P13_M3_SECURITY_DESIGN §2. The owner picks how long
// security history is kept (7 / 30 / 90 days; default and fail-safe 30).
// The choice is the optional `hr` field of the encrypted intruder settings
// row, written through the SAME serialized settings update as the threshold
// (no second writer). It applies to the security journal and the
// failed-unlock history at startup, on append and on open; evidence photos
// keep their own fixed 30-day retention (Q-M3-D4). Every age purge is
// disclosed by the coalesced `historyExpired` marker and every change by
// `retentionChanged {old, new}`. Retention never touches `nextSeq`, `run`,
// generations, credentials, lockout, evidence or other settings fields.

import '../intruder/intruder_defense_settings.dart';
import '../intruder/intruder_monitor.dart';
import '../timeline/security_event_journal.dart';

enum RetentionChangeOutcome {
  /// The new period is saved and applied.
  changed,

  /// Already the stored period: nothing written.
  unchanged,

  /// Shortening was not confirmed: nothing written.
  needsConfirmation,

  /// Not a valid choice, or the settings record must not be overwritten
  /// (damaged / newer / unreadable): nothing written.
  refused,

  /// The owner session ended first: nothing written.
  cancelled,

  /// The settings write failed: nothing was changed.
  failed,
}

/// Effective retention of a settings read (30 unless a valid record says
/// otherwise; never the shortest).
int effectiveRetentionDays(IntruderSettingsRead read) =>
    read.health == IntruderSettingsHealth.ok
        ? read.settings.historyRetentionDays
        : IntruderDefenseSettings.defaultHistoryRetentionDays;

class HistoryRetentionService {
  HistoryRetentionService({
    required IntruderDefenseSettingsStore settings,
    required IntruderMonitor monitor,
    required SecurityEventJournal journal,
  })  : _settings = settings,
        _monitor = monitor,
        _journal = journal;

  final IntruderDefenseSettingsStore _settings;
  final IntruderMonitor _monitor;
  final SecurityEventJournal _journal;

  /// The retention in effect now (30 on any read problem). Never throws.
  Future<int> effectiveDays() async {
    try {
      return effectiveRetentionDays(await _settings.read());
    } catch (_) {
      return IntruderDefenseSettings.defaultHistoryRetentionDays;
    }
  }

  /// Startup: reads the setting, then runs the journal's startup
  /// maintenance and the failure-log purge with it. Never throws.
  Future<void> startup() async {
    final Duration keep = Duration(days: await effectiveDays());
    await Future.wait(<Future<void>>[
      _journal.startup(retention: keep).catchError((Object _) {}),
      _monitor
          .purgeExpired(retention: keep)
          .then((_) {}, onError: (Object _) {}),
    ]);
  }

  /// Changes the retention to [days]. The caller has just verified the
  /// owner freshly; [stillValid] is that session (evaluated right before
  /// the write). Shortening requires [shorteningConfirmed] ("events older
  /// than N days will be deleted now"); the check is repeated inside the
  /// serialized update against the authoritative stored value.
  Future<RetentionChangeOutcome> change(
    int days, {
    required bool Function() stillValid,
    required bool shorteningConfirmed,
  }) async {
    if (!IntruderDefenseSettings.historyRetentionChoices.contains(days)) {
      return RetentionChangeOutcome.refused;
    }
    if (!stillValid()) return RetentionChangeOutcome.cancelled;
    final IntruderSettingsRead before = await _settings.read();
    if (!before.writable) return RetentionChangeOutcome.refused;
    final int shown = before.settings.historyRetentionDays;
    if (shown == days && !before.settings.retentionInvalid) {
      return RetentionChangeOutcome.unchanged;
    }
    if (days < shown && !shorteningConfirmed) {
      return RetentionChangeOutcome.needsConfirmation;
    }
    int? old;
    _Abort? abort;
    final IntruderDefenseSettings? saved;
    try {
      saved = await _settings.update((IntruderDefenseSettings s) {
        if (!stillValid()) {
          abort = _Abort.cancelled;
          throw const _AbortChange();
        }
        if (days < s.historyRetentionDays && !shorteningConfirmed) {
          abort = _Abort.confirm;
          throw const _AbortChange();
        }
        old = s.historyRetentionDays;
        return s.copyWith(historyRetentionDays: days);
      });
    } catch (_) {
      return switch (abort) {
        _Abort.cancelled => RetentionChangeOutcome.cancelled,
        _Abort.confirm => RetentionChangeOutcome.needsConfirmation,
        null => RetentionChangeOutcome.failed,
      };
    }
    if (saved == null) return RetentionChangeOutcome.failed;
    final Duration keep = Duration(days: days);
    final int from = old ?? IntruderDefenseSettings.defaultHistoryRetentionDays;
    // Saved: apply everywhere (queue-ordered). A failed journal marker is
    // counted as lost by the journal; the new retention still applies.
    await Future.wait(<Future<void>>[
      if (from != days)
        _journal.changeRetention(from, days).then((_) {})
      else
        _journal.startup(retention: keep),
      _monitor.purgeExpired(retention: keep).then((_) {}),
    ]);
    return RetentionChangeOutcome.changed;
  }
}

enum _Abort { cancelled, confirm }

final class _AbortChange implements Exception {
  const _AbortChange();
}
