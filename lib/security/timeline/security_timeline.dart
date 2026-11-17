// Phase 13 / Milestone 1 — chronological read model over the existing
// sources. READ-ONLY (TL-2 / TL-3 / correction E): it never writes the
// failure log, the journal's security state, credential counters, lockout
// state or evidence guards. It only calls read APIs.
//
// Honesty (corrections C / D): an unreadable source is reported as
// unavailable — never as empty — and every known gap (retention / caps,
// unrecorded events, damaged earlier history, unknown integrity) is
// reported per source.
//
// M2: one entry per source event (journal v2 types included); a busy
// failure-log read is labelled busy only on REQUEST-LOCAL proof; storage
// observations are fed to the optional sampler; reset facts and render-time
// app labels are exposed. The reader NEVER calls the evidence store or the
// evidence service (photo availability is decided only inside the verified
// evidence viewer).
import 'dart:async';

import '../../data/models/protected_app.dart';
import '../../data/repositories/protected_apps_repository.dart';
import '../../data/storage/local_database.dart';
import '../credentials/verified_attempt.dart';
import '../intruder/failed_attempt_event.dart';
import '../intruder/intruder_failure_log_store.dart';
import '../intruder/intruder_monitor.dart';
import 'security_event_journal.dart';
import 'security_event_journal_store.dart';
import 'security_journal_event.dart';
import 'storage_health_journal_sampler.dart';

/// Source of an entry. The index is the fixed tie-break rank.
enum TimelineSource { failedAttempts, journal }

enum TimelineEntryKind {
  failedUnlock,
  journalStarted,
  journalRecovered,
  journalUpgraded,
  captureSaved,
  captureNotSaved,
  alarmStarted,
  alarmNotStarted,
  alarmStopped,
  protectionHealth,
  storageUnavailable,
  storageRestored,
}

/// Metadata-only timeline row (no credential material, no pixels).
final class TimelineEntry {
  const TimelineEntry({
    required this.source,
    required this.sourceSeq,
    required this.at,
    required this.kind,
    this.method,
    this.surface,
    this.packageName,
    this.consecutiveFailures,
    this.lockoutTriggered = false,
    this.persisted = true,
    this.trig,
    this.tgen,
    this.logGen,
    this.captureWhy,
    this.alarmWhy,
    this.healthState,
    this.healthCodes = const <HCode>[],
    this.healthFirst = false,
    this.suppressed = 0,
    this.storageKind,
    this.clockBack = false,
  });

  final TimelineSource source;
  final int sourceSeq;

  /// When the app observed/recorded the event (wall clock).
  final DateTime at;
  final TimelineEntryKind kind;
  final FailedAttemptMethod? method;
  final AuthAttemptSurface? surface;

  /// Protected app (challenge surface only).
  final String? packageName;
  final int? consecutiveFailures;
  final bool lockoutTriggered;

  /// Failure-log only: false when the attempt counter write had failed.
  final bool persisted;

  /// M2 outcomes: the failed-attempt seq the outcome belongs to.
  final int? trig;

  /// Batch 3: outcomes — the failure-log generation of [trig] (null =
  /// legacy outcome). EID = (tgen, trig).
  final String? tgen;

  /// Batch 3: failed attempts — the event's generation (null = legacy).
  /// EID = (logGen, sourceSeq).
  final String? logGen;
  final CaptureWhy? captureWhy;
  final AlarmWhy? alarmWhy;
  final HState? healthState;

  /// Unmodifiable.
  final List<HCode> healthCodes;
  final bool healthFirst;
  final int suppressed;
  final StoreKind? storageKind;

  /// Recorded while the wall clock was behind the previous event.
  final bool clockBack;
}

enum TimelineSourceState {
  available,

  /// Written by a newer app version; kept untouched.
  unavailableNewerVersion,

  /// Could not be read.
  unavailableUnreadable,

  /// M2: this request was rejected because the failed-unlock history was
  /// busy (request-local proof only).
  unavailableBusy,
}

final class TimelineSourceStatus {
  const TimelineSourceStatus({
    required this.source,
    required this.state,
    required this.discarded,
    required this.lost,
    required this.damagedEarlier,
  });

  final TimelineSource source;
  final TimelineSourceState state;

  /// Events no longer kept (retention / count / size caps).
  final int discarded;

  /// Events that were never recorded (overflow / storage failures).
  final int lost;

  /// True: earlier history was damaged and replaced. Null: unknown (the
  /// integrity marker could not be read) — never assumed clean.
  final bool? damagedEarlier;

  bool get available => state == TimelineSourceState.available;
}

final class SecurityTimelineSnapshot {
  const SecurityTimelineSnapshot({
    required this.entries,
    required this.sources,
    this.resetPending = false,
    this.resetFailures = 0,
    this.suppressedHealth = 0,
    this.labels = const <String, String>{},
  });

  /// Newest first; total order (see [SecurityTimelineReader.compare]).
  final List<TimelineEntry> entries;
  final List<TimelineSourceStatus> sources;

  /// IntruderMonitor (failed-unlock history) facts from the same status
  /// read: an owner success not yet persisted to THIS history, and failed
  /// persists of such resets. They say nothing about credential or lock-out
  /// storage.
  final bool resetPending;
  final int resetFailures;

  /// Protection changes not recorded individually (rate window).
  final int suppressedHealth;

  /// Render-time protected-app labels (package -> label). Never persisted.
  final Map<String, String> labels;

  bool get allSourcesAvailable =>
      sources.every((TimelineSourceStatus s) => s.available);

  /// "No events" may only be claimed when every source was read.
  bool get confirmedEmpty => entries.isEmpty && allSourcesAvailable;

  bool get hasGaps => sources.any((TimelineSourceStatus s) =>
      !s.available ||
      s.discarded > 0 ||
      s.lost > 0 ||
      s.damagedEarlier != false);
}

class SecurityTimelineReader {
  SecurityTimelineReader({
    required IntruderMonitor monitor,
    required SecurityEventJournal journal,
    required SecurityEventJournalStore journalStore,
    required LocalDatabase database,
    StorageHealthJournalSampler? storageSampler,
    ProtectedAppsRepository? protectedApps,
  })  : _monitor = monitor,
        _journal = journal,
        _journalStore = journalStore,
        _database = database,
        _sampler = storageSampler,
        _protectedApps = protectedApps;

  static const int pageSize = 50;

  final IntruderMonitor _monitor;
  final SecurityEventJournal _journal;
  final SecurityEventJournalStore _journalStore;
  final LocalDatabase _database;
  final StorageHealthJournalSampler? _sampler;
  final ProtectedAppsRepository? _protectedApps;

  /// Newest first: (at desc, source rank desc, sourceSeq desc).
  static int compare(TimelineEntry a, TimelineEntry b) {
    final int byTime = b.at.compareTo(a.at);
    if (byTime != 0) {
      return byTime;
    }
    final int bySource = b.source.index.compareTo(a.source.index);
    if (bySource != 0) {
      return bySource;
    }
    return b.sourceSeq.compareTo(a.sourceSeq);
  }

  // Single-flight (R-P13M1-1): at most ONE timeline load — and therefore at
  // most one forced failure-log snapshot in the monitor queue and one read
  // in the journal queue — is in flight at any time, however often [load]
  // is called (repeated opens, stalled storage). Callers arriving while a
  // load runs join the NEXT load, so every caller receives a snapshot that
  // was started after its own call. Each caller gets its own completer
  // (zone-safe; no future is shared across callers).
  bool _running = false;
  List<Completer<SecurityTimelineSnapshot>> _current =
      <Completer<SecurityTimelineSnapshot>>[];
  List<Completer<SecurityTimelineSnapshot>> _next =
      <Completer<SecurityTimelineSnapshot>>[];

  /// Never throws. Coalesced: see the single-flight note above.
  Future<SecurityTimelineSnapshot> load() {
    final Completer<SecurityTimelineSnapshot> c =
        Completer<SecurityTimelineSnapshot>();
    if (_running) {
      _next.add(c);
    } else {
      _running = true;
      _current = <Completer<SecurityTimelineSnapshot>>[c];
      unawaited(_drive());
    }
    return c.future;
  }

  Future<void> _drive() async {
    while (true) {
      final List<Completer<SecurityTimelineSnapshot>> batch = _current;
      final SecurityTimelineSnapshot snap = await _loadOnce();
      for (final Completer<SecurityTimelineSnapshot> w in batch) {
        w.complete(snap);
      }
      if (_next.isEmpty) {
        _current = <Completer<SecurityTimelineSnapshot>>[];
        _running = false;
        return;
      }
      _current = _next;
      _next = <Completer<SecurityTimelineSnapshot>>[];
    }
  }

  /// One uncoalesced load. Never throws.
  Future<SecurityTimelineSnapshot> _loadOnce() async {
    final List<TimelineEntry> entries = <TimelineEntry>[];
    final (TimelineSourceStatus, IntruderMonitorStatus) f =
        await _loadFailures(entries);
    final TimelineSourceStatus failures = f.$1;
    final (TimelineSourceStatus, int) j = await _loadJournal(entries);
    final TimelineSourceStatus journal = j.$1;
    entries.sort(compare);
    return SecurityTimelineSnapshot(
      entries: List<TimelineEntry>.unmodifiable(entries),
      sources: List<TimelineSourceStatus>.unmodifiable(
          <TimelineSourceStatus>[failures, journal]),
      resetPending: f.$2.resetPending,
      resetFailures: f.$2.resetFailures,
      suppressedHealth: j.$2,
      labels: await _loadLabels(),
    );
  }

  /// Render-time labels; any failure shows package names instead.
  Future<Map<String, String>> _loadLabels() async {
    final ProtectedAppsRepository? repo = _protectedApps;
    if (repo == null) return const <String, String>{};
    try {
      final List<ProtectedApp>? apps =
          (await repo.getProtectedApps()).valueOrNull;
      if (apps == null) return const <String, String>{};
      return Map<String, String>.unmodifiable(<String, String>{
        for (final ProtectedApp a in apps) a.packageName: a.label,
      });
    } catch (_) {
      return const <String, String>{};
    }
  }

  Future<(TimelineSourceStatus, IntruderMonitorStatus)> _loadFailures(
      List<TimelineEntry> out) async {
    IntruderFailureLog? log;
    // Request-local busy proof (M2): the counter has exactly one increment
    // site, inside the synchronous rejection branch of snapshot(); these
    // three statements run with no await in between.
    bool rejectedThisCall = false;
    try {
      final int before = _monitor.status.snapshotsRejected;
      final Future<IntruderFailureLog?> pending = _monitor.snapshot();
      final int after = _monitor.status.snapshotsRejected;
      rejectedThisCall = after == before + 1;
      log = await pending;
    } catch (_) {
      log = null;
    }
    final IntruderMonitorStatus status = _monitor.status;
    try {
      _sampler?.afterFailureLogRead(log, rejectedThisCall, status);
    } catch (_) {
      // Recording never affects the read.
    }
    bool? damaged;
    try {
      damaged = status.quarantinedCorruptLog ||
          await _database.getSetting(IntruderFailureLogStore.quarantineKey) !=
              null;
    } catch (_) {
      damaged = status.quarantinedCorruptLog ? true : null;
    }
    if (log == null) {
      return (
        TimelineSourceStatus(
          source: TimelineSource.failedAttempts,
          state: rejectedThisCall
              ? TimelineSourceState.unavailableBusy
              : status.health == IntruderMonitorHealth.readOnly
                  ? TimelineSourceState.unavailableNewerVersion
                  : TimelineSourceState.unavailableUnreadable,
          discarded: 0,
          lost: status.droppedEvents,
          damagedEarlier: damaged,
        ),
        status,
      );
    }
    for (final FailedAttemptEvent e in log.events) {
      out.add(TimelineEntry(
        source: TimelineSource.failedAttempts,
        sourceSeq: e.seq,
        at: e.at,
        kind: TimelineEntryKind.failedUnlock,
        method: e.method,
        surface: e.surface,
        packageName: e.surface == AuthAttemptSurface.protectedAppChallenge
            ? e.packageName
            : null,
        consecutiveFailures: e.consecutiveFailures,
        lockoutTriggered: e.lockoutTriggered,
        persisted: e.counterPersisted,
        logGen: e.logGen,
      ));
    }
    final int discarded = log.nextSeq - log.events.length;
    return (
      TimelineSourceStatus(
        source: TimelineSource.failedAttempts,
        state: TimelineSourceState.available,
        discarded: discarded < 0 ? 0 : discarded,
        lost: status.droppedEvents,
        damagedEarlier: damaged,
      ),
      status,
    );
  }

  Future<(TimelineSourceStatus, int)> _loadJournal(
      List<TimelineEntry> out) async {
    SecurityJournalView view;
    try {
      view = await _journal.read();
    } catch (_) {
      view = const SecurityJournalView(
        availability: SecurityJournalAvailability.unreadable,
        events: <SecurityJournalEvent>[],
        discarded: 0,
        lost: 0,
      );
    }
    bool? damaged;
    try {
      damaged = _journal.quarantinedCorruptJournal ||
          await _journalStore.hasQuarantine();
    } catch (_) {
      damaged = _journal.quarantinedCorruptJournal ? true : null;
    }
    final TimelineSourceState state = switch (view.availability) {
      SecurityJournalAvailability.available => TimelineSourceState.available,
      SecurityJournalAvailability.unsupported =>
        TimelineSourceState.unavailableNewerVersion,
      SecurityJournalAvailability.unreadable =>
        TimelineSourceState.unavailableUnreadable,
    };
    if (state == TimelineSourceState.available) {
      for (final SecurityJournalEvent e in view.events) {
        out.add(journalEntry(e));
      }
    }
    return (
      TimelineSourceStatus(
        source: TimelineSource.journal,
        state: state,
        discarded: view.discarded,
        lost: view.lost,
        damagedEarlier: damaged,
      ),
      view.suppressed,
    );
  }

  /// Metadata-only entry for one journal event (exhaustive mapping).
  static TimelineEntry journalEntry(SecurityJournalEvent e) {
    final SecurityEventFields? f = e.fields;
    return TimelineEntry(
      source: TimelineSource.journal,
      sourceSeq: e.seq,
      at: e.at,
      clockBack: e.clockBack,
      kind: switch (e.type) {
        SecurityJournalEventType.journalStarted =>
          TimelineEntryKind.journalStarted,
        SecurityJournalEventType.journalRecovered =>
          TimelineEntryKind.journalRecovered,
        SecurityJournalEventType.journalUpgraded =>
          TimelineEntryKind.journalUpgraded,
        SecurityJournalEventType.captureSaved => TimelineEntryKind.captureSaved,
        SecurityJournalEventType.captureNotSaved =>
          TimelineEntryKind.captureNotSaved,
        SecurityJournalEventType.alarmStarted => TimelineEntryKind.alarmStarted,
        SecurityJournalEventType.alarmNotStarted =>
          TimelineEntryKind.alarmNotStarted,
        SecurityJournalEventType.alarmStopped => TimelineEntryKind.alarmStopped,
        SecurityJournalEventType.protectionHealth =>
          TimelineEntryKind.protectionHealth,
        SecurityJournalEventType.storageUnavailable =>
          TimelineEntryKind.storageUnavailable,
        SecurityJournalEventType.storageRestored =>
          TimelineEntryKind.storageRestored,
      },
      trig: f?.trig,
      tgen: f?.tgen,
      captureWhy: f is CaptureNotSavedFields ? f.why : null,
      alarmWhy: f is AlarmNotStartedFields ? f.why : null,
      healthState: f is ProtectionHealthFields ? f.state : null,
      healthCodes: f is ProtectionHealthFields ? f.codes : const <HCode>[],
      healthFirst: f is ProtectionHealthFields && f.first,
      suppressed: f is ProtectionHealthFields ? f.suppressed : 0,
      storageKind: f is StorageUnavailableFields ? f.kind : null,
    );
  }
}
