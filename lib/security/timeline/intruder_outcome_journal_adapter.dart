// Phase 13 / Milestone 2 — intruder outcome -> security journal adapter.
//
// The coordinator calls [onIntruderOutcome] synchronously after a decision.
// This adapter does O(1) work there: it captures the immutable outcome and
// schedules ONE microtask, so no journal code (not even the queue's
// synchronous prefix) runs inside the coordinator's call stack. Scheduling
// is bounded: at most [maxScheduled] microtasks are outstanding; excess
// outcomes are counted as lost in the journal, never queued. Mapping is an
// exhaustive switch over closed enums — no string ever reaches the journal.
import 'dart:async';

import '../intruder/intruder_defense_coordinator.dart';
import 'security_event_journal.dart';
import 'security_journal_event.dart';

class IntruderOutcomeJournalAdapter implements IntruderOutcomeObserver {
  IntruderOutcomeJournalAdapter(this._sink, {this.maxScheduled = 64});

  final SecurityEventFieldSink _sink;

  /// Upper bound on outstanding microtasks (equals the journal queue cap).
  final int maxScheduled;

  int _scheduled = 0;
  bool _closed = false;

  /// After [close], outcomes are ignored (including ones already scheduled).
  void close() => _closed = true;

  @override
  void onIntruderOutcome(IntruderOutcome o) {
    if (_closed) return;
    if (_scheduled >= maxScheduled) {
      _lost();
      return;
    }
    _scheduled++;
    scheduleMicrotask(() {
      _scheduled--;
      if (_closed) return;
      try {
        final (SecurityJournalEventType, SecurityEventFields) e = map(o);
        recordSecurityEventFieldsSafely(_sink, e.$1, e.$2);
      } catch (_) {
        // Never escapes into the zone.
      }
    });
  }

  void _lost() {
    try {
      _sink.recordLost(1);
    } catch (_) {
      // Never throws into the coordinator.
    }
  }

  /// Exhaustive outcome -> (type, fields) mapping.
  static (SecurityJournalEventType, SecurityEventFields) map(
          IntruderOutcome o) =>
      switch (o) {
        CaptureSavedOutcome(:final int trig) => (
            SecurityJournalEventType.captureSaved,
            CaptureSavedFields(trig),
          ),
        CaptureNotSavedOutcome(
          :final int trig,
          :final IntruderCaptureWhy why
        ) =>
          (
            SecurityJournalEventType.captureNotSaved,
            CaptureNotSavedFields(trig, captureWhy(why)),
          ),
        AlarmStartedOutcome(:final int trig) => (
            SecurityJournalEventType.alarmStarted,
            AlarmStartedFields(trig),
          ),
        AlarmNotStartedOutcome(:final int trig, :final IntruderAlarmWhy why) =>
          (
            SecurityJournalEventType.alarmNotStarted,
            AlarmNotStartedFields(trig, alarmWhy(why)),
          ),
        AlarmStoppedOutcome() => (
            SecurityJournalEventType.alarmStopped,
            const AlarmStoppedFields(),
          ),
      };

  static CaptureWhy captureWhy(IntruderCaptureWhy w) => switch (w) {
        IntruderCaptureWhy.permission => CaptureWhy.permission,
        IntruderCaptureWhy.camera => CaptureWhy.camera,
        IntruderCaptureWhy.timeout => CaptureWhy.timeout,
        IntruderCaptureWhy.busy => CaptureWhy.busy,
        IntruderCaptureWhy.cancelled => CaptureWhy.cancelled,
        IntruderCaptureWhy.duplicate => CaptureWhy.duplicate,
        IntruderCaptureWhy.storage => CaptureWhy.storage,
        IntruderCaptureWhy.encryption => CaptureWhy.encryption,
        IntruderCaptureWhy.image => CaptureWhy.image,
        IntruderCaptureWhy.superseded => CaptureWhy.superseded,
        IntruderCaptureWhy.unsupported => CaptureWhy.unsupported,
        IntruderCaptureWhy.error => CaptureWhy.error,
      };

  static AlarmWhy alarmWhy(IntruderAlarmWhy w) => switch (w) {
        IntruderAlarmWhy.alreadyPlaying => AlarmWhy.alreadyPlaying,
        IntruderAlarmWhy.dnd => AlarmWhy.dnd,
        IntruderAlarmWhy.ringer => AlarmWhy.ringer,
        IntruderAlarmWhy.focusDenied => AlarmWhy.focusDenied,
        IntruderAlarmWhy.notForeground => AlarmWhy.notForeground,
        IntruderAlarmWhy.cancelled => AlarmWhy.cancelled,
        IntruderAlarmWhy.error => AlarmWhy.error,
      };
}
