// Phase 13 / Milestone 2 — protection-health -> security journal recorder.
//
// Composition layer (manifest R2 P11 as amended, Option A): it lives in
// lib/app so that NO file under lib/security/timeline imports protection
// code (M1 source invariant).
//
// Listens to ProtectionHealthMonitor.changes (broadcast; emitted only on a
// signature change, and only when existing UI refreshes). It NEVER calls
// refresh() and never probes: no timers, no background work (TL-8).
//
// Each fresh report is mapped (exhaustively) to (HState, non-advisory
// codes) and handed to the journal's compare-and-append, which applies the
// seeding rule, rate window, `first` and quota. Neutral rule (Q-M2-5): a
// report whose ONLY non-advisory issue is `protectionNotConfigured` is
// owner configuration and is not recorded. A report that also carries any
// other actionable code IS recorded with its full code set, so the neutral
// rule can never conceal an actionable issue.
//
// Stale guard: reports flagged stale or carrying `healthSnapshotStale`, and
// reports observed before the last processed one, are ignored.
//
// On each processed emission the failed-unlock history's in-memory status
// is forwarded to the storage sampler (unavailable direction only).
//
// The handler is synchronous and wrapped in try/catch; stream errors are
// swallowed (cancelOnError: false). Nothing is ever thrown into the
// monitor.
import 'dart:async';

import '../protection/health/protection_health_engine.dart';
import '../protection/health/protection_health_monitor.dart';
import '../security/intruder/intruder_monitor.dart';
import '../security/timeline/security_event_journal.dart';
import '../security/timeline/security_journal_event.dart';
import '../security/timeline/storage_health_journal_sampler.dart';

class ProtectionHealthJournalRecorder {
  ProtectionHealthJournalRecorder({
    required SecurityEventJournal journal,
    StorageHealthJournalSampler? storageSampler,
    IntruderMonitorStatus Function()? intruderStatus,
  })  : _journal = journal,
        _sampler = storageSampler,
        _intruderStatus = intruderStatus;

  final SecurityEventJournal _journal;
  final StorageHealthJournalSampler? _sampler;
  final IntruderMonitorStatus Function()? _intruderStatus;

  StreamSubscription<ProtectionHealthReport>? _sub;
  DateTime? _lastObservedAt;

  /// Reports handed to the journal (diagnostic count only).
  int recorded = 0;

  /// Subscribes once. Never refreshes the monitor.
  void attach(ProtectionHealthMonitor monitor) {
    if (_sub != null) return;
    try {
      _sub = monitor.changes.listen(
        onReport,
        onError: (Object _, StackTrace __) {
          // Swallowed: a monitor error never reaches enforcement.
        },
        cancelOnError: false,
      );
    } catch (_) {
      // A closed monitor stream: nothing is recorded.
    }
  }

  Future<void> close() async {
    final StreamSubscription<ProtectionHealthReport>? s = _sub;
    _sub = null;
    try {
      await s?.cancel();
    } catch (_) {
      // never throws
    }
  }

  /// Synchronous handler (public for tests). Never throws.
  void onReport(ProtectionHealthReport report) {
    try {
      if (report.stale) return;
      final DateTime observedAt = report.observedAt;
      final DateTime? last = _lastObservedAt;
      if (last != null && observedAt.isBefore(last)) return; // out of order
      final List<HCode> codes = <HCode>[];
      bool staleCode = false;
      for (final HealthIssue issue in report.issues) {
        final HCode? c = journalCode(issue.code);
        if (c == HCode.healthSnapshotStale) staleCode = true;
        if (c != null && !codes.contains(c)) codes.add(c);
      }
      if (staleCode) return;
      _lastObservedAt = observedAt;
      _forwardStorageStatus();
      if (codes.length == 1 && codes.single == HCode.protectionNotConfigured) {
        return; // neutral: owner configuration, never recorded
      }
      _journal.recordHealthObservation(journalState(report.state), codes);
      recorded++;
    } catch (_) {
      // Never throws into the monitor's stream.
    }
  }

  void _forwardStorageStatus() {
    final StorageHealthJournalSampler? sampler = _sampler;
    final IntruderMonitorStatus Function()? read = _intruderStatus;
    if (sampler == null || read == null) return;
    try {
      sampler.observeStatus(read());
    } catch (_) {
      // never throws
    }
  }

  static HState journalState(ProtectionHealthState s) => switch (s) {
        ProtectionHealthState.secure => HState.secure,
        ProtectionHealthState.attentionRequired => HState.attention,
        ProtectionHealthState.protectionOffline => HState.offline,
      };

  /// Exhaustive: a new engine code is a compile error until mapped.
  /// Advisory codes are not representable (null).
  static HCode? journalCode(HealthIssueCode c) => switch (c) {
        HealthIssueCode.protectionNotConfigured =>
          HCode.protectionNotConfigured,
        HealthIssueCode.enforcementNotArmed => HCode.enforcementNotArmed,
        HealthIssueCode.overlayUnavailable => HCode.overlayUnavailable,
        HealthIssueCode.detectionOffline => HCode.detectionOffline,
        HealthIssueCode.accessibilityUnavailable =>
          HCode.accessibilityUnavailable,
        HealthIssueCode.accessibilityNotRunning =>
          HCode.accessibilityNotRunning,
        HealthIssueCode.usageAccessUnavailable => HCode.usageAccessUnavailable,
        HealthIssueCode.watcherNotRunning => HCode.watcherNotRunning,
        HealthIssueCode.shieldNotArmed => HCode.shieldNotArmed,
        HealthIssueCode.notificationsDisabled => HCode.notificationsDisabled,
        HealthIssueCode.backgroundRestricted => HCode.backgroundRestricted,
        HealthIssueCode.signalUnknown => HCode.signalUnknown,
        HealthIssueCode.healthSnapshotStale => HCode.healthSnapshotStale,
        HealthIssueCode.batterySaverOn => null,
        HealthIssueCode.biometricUnavailable => null,
      };
}
