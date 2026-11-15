// Phase 13 / Milestone 2 — failed-unlock history storage observations.
//
// Records only PROVABLE facts (Q-M2-6 = A'):
// * `failing`  — the monitor reports `storageError` (set only by an observed
//                failed read, write or operation);
// * `readOnly` — the monitor reports `readOnly` (newer schema OR permanently
//                undecryptable data; the wording covers both);
// * restored   — ONLY at a timeline load whose own `snapshot()` returned a
//                log (a successful read in this load) with health `ok`; the
//                journal additionally requires a persisted non-ok state.
// A busy (rejected) read is not a storage fault and records nothing. No
// counter deltas are interpreted, the monitor is never changed or probed,
// and nothing here can throw into its caller.
import '../intruder/failed_attempt_event.dart';
import '../intruder/intruder_monitor.dart';
import 'security_event_journal.dart';
import 'security_journal_event.dart';

class StorageHealthJournalSampler {
  StorageHealthJournalSampler(this._journal);

  final SecurityEventJournal _journal;

  /// Timeline load sampling point: called right after the reader's own
  /// `snapshot()` call completed. [log] is that call's result and
  /// [rejectedThisCall] its request-local busy proof; [status] is read
  /// after the await.
  void afterFailureLogRead(
    IntruderFailureLog? log,
    bool rejectedThisCall,
    IntruderMonitorStatus status,
  ) {
    try {
      if (rejectedThisCall) {
        return; // busy: not a storage fault
      }
      if (log == null) {
        _unavailable(status.health);
        return;
      }
      if (status.health == IntruderMonitorHealth.ok) {
        _journal.recordStorageObservation(
            StorageSource.failureLog, StoreState.ok);
      } else {
        _unavailable(status.health);
      }
    } catch (_) {
      // Recording never affects the caller.
    }
  }

  /// Health-recorder sampling point: the unavailable direction ONLY. An
  /// `ok` here proves nothing (the monitor may not have loaded) and is
  /// ignored.
  void observeStatus(IntruderMonitorStatus status) {
    try {
      _unavailable(status.health);
    } catch (_) {
      // Recording never affects the caller.
    }
  }

  void _unavailable(IntruderMonitorHealth health) {
    switch (health) {
      case IntruderMonitorHealth.ok:
        return;
      case IntruderMonitorHealth.storageError:
        _journal.recordStorageObservation(
            StorageSource.failureLog, StoreState.failing);
      case IntruderMonitorHealth.readOnly:
        _journal.recordStorageObservation(
            StorageSource.failureLog, StoreState.readOnly);
    }
  }
}
