// P13/M3 Batch 4 — Clear History (owner action from the Security timeline).
//
// Governing design: P13_M3_SECURITY_DESIGN §1 as corrected by
// C_P13_M3_CRASH_SAFE_CLEAR_HISTORY_DESIGN §2–§4 (scoped pending marker with
// a fixed cut, display filter while pending, no automatic resumption,
// finish only after a fresh owner verification) and the Batch 3 identity
// model (generation-qualified attempts, outcomes and photos).
//
// Sequence (each step ONE atomic row write in its owner's queue; the
// session's stillValid() is evaluated synchronously right before each):
//   pre-check (reads only; all-or-refuse)
//   cut   : photo id high-water (photos only), then the failure log's
//           (generation, nextSeq)  — the cleared set C is now fixed
//   (a)   : journal — every event outside the kept outcomes removed, marker
//           `historyCleared {pending, cut, cg, bc, scope}` appended
//   (b)   : failure log — attempts of C removed (nextSeq, run, gen kept)
//   (c)   : photos (opt-in) — photos of C removed
//   (d)   : journal — marker flipped to `done`
// A crash or an ended session after (a) leaves the marker pending: C stays
// hidden by the read model and the owner is asked to finish (fresh
// verification), which re-runs only (b)–(d) with the marker's C. Nothing
// here touches credentials, lockout, settings, quarantine rows, the run
// counter, nextSeq or any photo outside C.

import '../intruder/intruder_evidence_store.dart';
import '../intruder/intruder_monitor.dart';
import '../timeline/security_event_journal.dart';
import '../timeline/security_journal_event.dart';

enum HistoryClearOutcome {
  /// Every step committed.
  done,

  /// The marker is pending (some later step did not run or failed): the
  /// cleared set is hidden; the owner can finish clearing.
  interrupted,

  /// Nothing was written: a store is unavailable, unreadable, damaged or
  /// from a newer version (or there is nothing to finish).
  refused,

  /// Nothing was written: the owner session ended first.
  cancelled,

  /// The first write failed and may or may not have committed; the timeline
  /// reload shows which (both states are consistent).
  failed,
}

class HistoryClearService {
  HistoryClearService({
    required IntruderMonitor monitor,
    required SecurityEventJournal journal,
    required IntruderEvidenceStore evidence,
    required String? Function() liveGen,
  })  : _monitor = monitor,
        _journal = journal,
        _evidence = evidence,
        _liveGen = liveGen;

  final IntruderMonitor _monitor;
  final SecurityEventJournal _journal;
  final IntruderEvidenceStore _evidence;
  final String? Function() _liveGen;

  /// The latest clear marker in [events] (null when none).
  static SecurityJournalEvent? markerOf(List<SecurityJournalEvent> events) {
    for (final SecurityJournalEvent e in events.reversed) {
      if (e.type == SecurityJournalEventType.historyCleared) return e;
    }
    return null;
  }

  /// A new clear. The caller has just verified the owner freshly.
  Future<HistoryClearOutcome> clear({
    required bool photos,
    required bool Function() stillValid,
  }) async {
    if (!stillValid()) return HistoryClearOutcome.cancelled;
    final SecurityJournalView view = await _journal.read();
    if (view.availability != SecurityJournalAvailability.available ||
        _journal.health == SecurityJournalHealth.readOnly) {
      return HistoryClearOutcome.refused;
    }
    int? bc;
    if (photos) {
      // Read BEFORE the log cut: any photo saved after this has bid >= bc.
      bc = await _evidence.bidCut();
      if (bc == null) return HistoryClearOutcome.refused;
    }
    if (!stillValid()) return HistoryClearOutcome.cancelled;
    final IntruderHistoryCut? cut = await _monitor.prepareHistoryClear();
    if (cut == null) return HistoryClearOutcome.refused;
    final HistoryClearedFields marker = HistoryClearedFields(
      scope:
          photos ? HistoryClearScope.historyPhotos : HistoryClearScope.history,
      state: HistoryClearState.pending,
      cut: cut.nextSeq,
      cutGen: cut.gen,
      bidCut: bc,
    );
    switch (await _journal.beginHistoryClear(marker, stillValid: stillValid)) {
      case HistoryClearJournalResult.committed:
        break;
      case HistoryClearJournalResult.refused:
        return HistoryClearOutcome.refused;
      case HistoryClearJournalResult.cancelled:
        return HistoryClearOutcome.cancelled;
      case HistoryClearJournalResult.failed:
        return HistoryClearOutcome.failed;
    }
    final SecurityJournalView after = await _journal.read();
    final SecurityJournalEvent? m = markerOf(after.events);
    if (m == null) return HistoryClearOutcome.interrupted;
    return _remaining(m, stillValid);
  }

  /// Finishes an interrupted clear with the marker's own (fixed) cleared
  /// set. The caller has just verified the owner freshly. Never invoked
  /// automatically.
  Future<HistoryClearOutcome> finish({
    required bool Function() stillValid,
  }) async {
    if (!stillValid()) return HistoryClearOutcome.cancelled;
    final SecurityJournalView view = await _journal.read();
    if (view.availability != SecurityJournalAvailability.available) {
      return HistoryClearOutcome.refused;
    }
    final SecurityJournalEvent? m = markerOf(view.events);
    final SecurityEventFields? f = m?.fields;
    if (m == null || f is! HistoryClearedFields || !f.pending) {
      return HistoryClearOutcome.refused; // nothing to finish
    }
    return _remaining(m, stillValid);
  }

  Future<HistoryClearOutcome> _remaining(
    SecurityJournalEvent m,
    bool Function() stillValid,
  ) async {
    final HistoryClearedFields f = m.fields! as HistoryClearedFields;
    if (!stillValid()) return HistoryClearOutcome.interrupted;
    final IntruderHistoryClearResult b = await _monitor.clearEventsBefore(
      IntruderHistoryCut(gen: f.cutGen, nextSeq: f.cut),
      stillValid: stillValid,
    );
    if (b != IntruderHistoryClearResult.cleared) {
      return HistoryClearOutcome.interrupted;
    }
    if (f.photos) {
      if (!stillValid()) return HistoryClearOutcome.interrupted;
      final EvidenceClearResult c = await _evidence.clearHistoryItems(
        cutGen: f.cutGen,
        cutSeq: f.cut,
        bidCut: f.bidCut!,
        liveGen: _liveGen(),
        stillValid: stillValid,
      );
      if (c != EvidenceClearResult.cleared) {
        return HistoryClearOutcome.interrupted;
      }
    }
    if (!stillValid()) return HistoryClearOutcome.interrupted;
    final HistoryClearJournalResult d =
        await _journal.completeHistoryClear(m.seq, stillValid: stillValid);
    return d == HistoryClearJournalResult.committed
        ? HistoryClearOutcome.done
        : HistoryClearOutcome.interrupted;
  }
}
