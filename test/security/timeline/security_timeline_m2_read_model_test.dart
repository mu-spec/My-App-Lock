// Phase 13 / M2 — T5: read model (U-25, U-25c, U-26, U-27), storage
// sampler (U-15, U-15b) and reader concurrency (C-01…C-04, C-09).
//
// SIMULATED: Dart VM; gated in-memory DB; real AES-GCM; real monitor.

import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';
import 'package:smart_app_lock/security/timeline/storage_health_journal_sampler.dart';

const String _logKey = IntruderFailureLogStore.storageKey;
const String _jKey = SecurityEventJournalStore.storageKey;
final DateTime _t0 = DateTime(2026, 10, 22, 12);

class _SpyDb extends InMemoryLocalDatabase {
  final Set<String> gatedReads = <String>{};
  final Set<String> failReads = <String>{};
  Completer<void> gate = Completer<void>();
  final List<String> reads = <String>[];
  final List<String> writes = <String>[];

  void release() {
    gatedReads.clear();
    if (!gate.isCompleted) gate.complete();
  }

  @override
  Future<String?> getSetting(String key) async {
    reads.add(key);
    if (gatedReads.contains(key)) await gate.future;
    if (failReads.contains(key)) throw StateError('read fault');
    return super.getSetting(key);
  }

  @override
  Future<void> setSetting(String key, String value) async {
    writes.add(key);
    return super.setSetting(key, value);
  }

  // P13/M3 NF-NS-1: settings writes are compare-and-set now; the same
  // interception applies to them (CAS-G2: never inherit an un-intercepted
  // CAS).
  @override
  Future<CasOutcome> compareAndSetSetting(
    String key, {
    required String? expected,
    required String next,
  }) async {
    writes.add(key);
    return super.compareAndSetSetting(key, expected: expected, next: next);
  }
}

/// Monitor whose reported status can be overridden (reset facts).
class _StatusMonitor extends IntruderMonitor {
  _StatusMonitor(
      {required super.store,
      super.now,
      super.maxPending,
      super.maxSnapshotWaiters});
  IntruderMonitorStatus? statusOverride;
  int calls = 0;

  @override
  IntruderMonitorStatus get status => statusOverride ?? super.status;

  @override
  Future<IntruderFailureLog?> snapshot() {
    calls++;
    return super.snapshot();
  }
}

int _vid = 0;
VerifiedAttempt _wrong() => VerifiedAttempt(
      verificationId: 'm2:${++_vid}',
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
        reason: AuthFailureReason.wrongCredential,
        remainingAttempts: 2,
      ),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

class _Rig {
  _Rig({int maxSnapshotWaiters = 64, int maxPending = 8}) {
    final SettingsCipher cipher = AesGcmSettingsCipher(InMemorySecretStore());
    monitor = _StatusMonitor(
      store: IntruderFailureLogStore(db, cipher: cipher),
      now: () => _t0,
      maxPending: maxPending,
      maxSnapshotWaiters: maxSnapshotWaiters,
    );
    final SecurityEventJournalStore js =
        SecurityEventJournalStore(db, cipher: cipher);
    journal = SecurityEventJournal(store: js, now: () => _t0);
    sampler = StorageHealthJournalSampler(journal);
    reader = SecurityTimelineReader(
      monitor: monitor,
      journal: journal,
      journalStore: js,
      database: db,
      storageSampler: sampler,
    );
  }

  final _SpyDb db = _SpyDb();
  late final _StatusMonitor monitor;
  late final SecurityEventJournal journal;
  late final StorageHealthJournalSampler sampler;
  late final SecurityTimelineReader reader;

  TimelineSourceStatus failures(SecurityTimelineSnapshot s) =>
      s.sources.firstWhere((TimelineSourceStatus x) =>
          x.source == TimelineSource.failedAttempts);
}

IntruderMonitorStatus st(IntruderMonitorHealth h,
        {bool resetPending = false, int resetFailures = 0}) =>
    IntruderMonitorStatus(
      health: h,
      droppedFailureRecords: 0,
      quarantinedCorruptLog: false,
      resetPending: resetPending,
      resetFailures: resetFailures,
    );

void main() {
  group('U-15 / U-15b storage sampler', () {
    late InMemoryLocalDatabase db;
    late SecurityEventJournal j;
    late StorageHealthJournalSampler s;

    Future<List<SecurityJournalEvent>> storageEvents() async {
      await j.idle();
      return (await j.read())
          .events
          .where((SecurityJournalEvent e) =>
              e.type == SecurityJournalEventType.storageUnavailable ||
              e.type == SecurityJournalEventType.storageRestored)
          .toList();
    }

    setUp(() {
      db = InMemoryLocalDatabase();
      j = SecurityEventJournal(
          store: SecurityEventJournalStore(db), now: () => _t0);
      s = StorageHealthJournalSampler(j);
    });

    test(
        'null + storageError ⇒ failing; null + readOnly ⇒ readOnly; equal '
        'state ⇒ nothing; busy ⇒ nothing', () async {
      s.afterFailureLogRead(null, true, st(IntruderMonitorHealth.storageError));
      expect(await storageEvents(), isEmpty, reason: 'busy is not a fault');
      s.afterFailureLogRead(
          null, false, st(IntruderMonitorHealth.storageError));
      s.afterFailureLogRead(
          null, false, st(IntruderMonitorHealth.storageError));
      List<SecurityJournalEvent> e = await storageEvents();
      expect(e.length, 1);
      expect((e.single.fields! as StorageUnavailableFields).kind,
          StoreKind.failing);
      s.afterFailureLogRead(null, false, st(IntruderMonitorHealth.readOnly));
      e = await storageEvents();
      expect(e.length, 2);
      expect((e.last.fields! as StorageUnavailableFields).kind,
          StoreKind.readOnly);
    });

    test(
        'U-15b restored only with a non-null snapshot AND ok AND persisted '
        'non-ok', () async {
      const IntruderFailureLog log = IntruderFailureLog.empty;
      // Fresh process, nothing persisted: ok never writes.
      s.afterFailureLogRead(log, false, st(IntruderMonitorHealth.ok));
      await j.idle();
      expect(await db.getSetting(_jKey), isNull);
      s.afterFailureLogRead(
          null, false, st(IntruderMonitorHealth.storageError));
      expect((await storageEvents()).length, 1);
      // A new process with persisted `failing`, but no successful load.
      j = SecurityEventJournal(
          store: SecurityEventJournalStore(db), now: () => _t0);
      s = StorageHealthJournalSampler(j);
      s.observeStatus(st(IntruderMonitorHealth.ok));
      s.afterFailureLogRead(null, false, st(IntruderMonitorHealth.ok));
      s.afterFailureLogRead(log, true, st(IntruderMonitorHealth.ok));
      expect((await storageEvents()).length, 1);
      // Non-null snapshot + ok + persisted failing ⇒ restored (once).
      s.afterFailureLogRead(log, false, st(IntruderMonitorHealth.ok));
      s.afterFailureLogRead(log, false, st(IntruderMonitorHealth.ok));
      final List<SecurityJournalEvent> e = await storageEvents();
      expect(
          e.map((SecurityJournalEvent x) => x.type), <SecurityJournalEventType>[
        SecurityJournalEventType.storageUnavailable,
        SecurityJournalEventType.storageRestored,
      ]);
    });
  });

  group('U-25 / U-25c / C-01 busy', () {
    test(
        'U-25c: snapshot() increments snapshotsRejected synchronously when '
        'saturated', () {
      final _Rig r = _Rig(maxSnapshotWaiters: 2);
      r.db.gatedReads.add(_logKey);
      unawaited(r.monitor.snapshot());
      unawaited(r.monitor.snapshot());
      final int before = r.monitor.status.snapshotsRejected;
      final Future<IntruderFailureLog?> f = r.monitor.snapshot();
      expect(r.monitor.status.snapshotsRejected, before + 1);
      expect(f, completion(isNull));
      r.db.release();
    });

    test(
        'U-25 / C-01: 64 held waiters then a load ⇒ unavailableBusy, '
        'confirmedEmpty false; failure recording unaffected (8 of 8)',
        () async {
      final _Rig r = _Rig();
      r.db.gatedReads.add(_logKey);
      final List<Future<IntruderFailureLog?>> held =
          <Future<IntruderFailureLog?>>[
        for (int i = 0; i < 64; i++) r.monitor.snapshot(),
      ];
      final Future<SecurityTimelineSnapshot> load = r.reader.load();
      for (int i = 0; i < 8; i++) {
        r.monitor.onVerifiedAttempt(_wrong());
      }
      final SecurityTimelineSnapshot s = await load;
      expect(r.failures(s).state, TimelineSourceState.unavailableBusy);
      expect(s.allSourcesAvailable, isFalse);
      expect(s.confirmedEmpty, isFalse);
      expect(r.monitor.status.droppedEvents, 0);
      r.db.release();
      await Future.wait(held);
      await r.monitor.idle();
      expect((await r.monitor.snapshot())!.events.length, 8);
      // Busy is not a storage fault: no storage event recorded.
      await r.journal.idle();
      expect(
          (await r.journal.read()).events.where((SecurityJournalEvent e) =>
              e.type == SecurityJournalEventType.storageUnavailable),
          isEmpty);
    });

    test(
        'C-02: the load succeeds while 10 other callers are rejected during '
        'its await ⇒ available (never busy)', () async {
      final _Rig r = _Rig(maxSnapshotWaiters: 1);
      r.db.gatedReads.add(_logKey);
      final Future<SecurityTimelineSnapshot> load = r.reader.load();
      await Future<void>.delayed(Duration.zero);
      for (int i = 0; i < 10; i++) {
        expect(await r.monitor.snapshot(), isNull);
      }
      r.db.release();
      final SecurityTimelineSnapshot s = await load;
      expect(r.failures(s).state, TimelineSourceState.available);
    });

    test(
        'C-03: the load\'s own snapshot returns null (read fault) while '
        'another caller is rejected ⇒ unreadable, NOT busy', () async {
      final _Rig r = _Rig(maxSnapshotWaiters: 1);
      r.db.gatedReads.add(_logKey);
      r.db.failReads.add(_logKey);
      final Future<SecurityTimelineSnapshot> load = r.reader.load();
      await Future<void>.delayed(Duration.zero);
      expect(await r.monitor.snapshot(), isNull); // rejected during the await
      r.db.release();
      final SecurityTimelineSnapshot s = await load;
      expect(r.failures(s).state, TimelineSourceState.unavailableUnreadable);
    });

    test(
        'C-04: 1,000 coalesced loads ⇒ 2 snapshot calls; every waiter gets '
        'the same classification', () async {
      final _Rig r = _Rig();
      r.db.gatedReads.add(_logKey);
      final List<Future<SecurityTimelineSnapshot>> loads =
          <Future<SecurityTimelineSnapshot>>[
        for (int i = 0; i < 1000; i++) r.reader.load(),
      ];
      await Future<void>.delayed(Duration.zero);
      r.db.release();
      final List<SecurityTimelineSnapshot> snaps = await Future.wait(loads);
      expect(r.monitor.calls, 2);
      expect(
          snaps
              .map((SecurityTimelineSnapshot s) => r.failures(s).state)
              .toSet(),
          <TimelineSourceState>{TimelineSourceState.available});
    });
  });

  group('U-26 / U-27', () {
    test('U-26 resetPending / resetFailures surfaced exactly from status',
        () async {
      final _Rig r = _Rig();
      r.monitor.statusOverride =
          st(IntruderMonitorHealth.ok, resetPending: true, resetFailures: 3);
      final SecurityTimelineSnapshot s = await r.reader.load();
      expect(s.resetPending, isTrue);
      expect(s.resetFailures, 3);
      r.monitor.statusOverride = st(IntruderMonitorHealth.ok);
      final SecurityTimelineSnapshot s2 = await r.reader.load();
      expect(s2.resetPending, isFalse);
      expect(s2.resetFailures, 0);
    });

    test(
        'U-27 a load writes only the journal row and never touches the '
        'evidence index or intruder settings', () async {
      final _Rig r = _Rig();
      r.monitor.onVerifiedAttempt(_wrong());
      await r.monitor.idle();
      r.db.writes.clear();
      r.db.reads.clear();
      await r.reader.load();
      await r.journal.idle();
      expect(r.db.writes.toSet().difference(<String>{_jKey}), isEmpty);
      for (final String k in <String>[
        IntruderEvidenceStore.indexKey,
        IntruderEvidenceStore.quarantineKey,
        'intruder_defense_settings',
      ]) {
        expect(r.db.reads, isNot(contains(k)));
        expect(r.db.writes, isNot(contains(k)));
      }
    });
  });

  group('C-09 load interleaved with appends', () {
    test('every event rendered exactly once; no torn document', () async {
      final _Rig r = _Rig();
      final List<Future<SecurityTimelineSnapshot>> loads =
          <Future<SecurityTimelineSnapshot>>[];
      for (int i = 0; i < 30; i++) {
        r.journal.recordEvent(
            SecurityJournalEventType.captureSaved, CaptureSavedFields(i));
        if (i % 5 == 0) loads.add(r.reader.load());
      }
      await r.journal.idle();
      loads.add(r.reader.load());
      final List<SecurityTimelineSnapshot> snaps = await Future.wait(loads);
      for (final SecurityTimelineSnapshot s in snaps) {
        final List<int> trigs = s.entries
            .where(
                (TimelineEntry e) => e.kind == TimelineEntryKind.captureSaved)
            .map((TimelineEntry e) => e.trig!)
            .toList();
        expect(trigs.toSet().length, trigs.length);
        // Prefix property: a snapshot holds 0..n-1 in full.
        if (trigs.isNotEmpty) {
          expect(
              trigs.toSet(), <int>{for (int i = 0; i < trigs.length; i++) i});
        }
      }
      expect(
          snaps.last.entries
              .where(
                  (TimelineEntry e) => e.kind == TimelineEntryKind.captureSaved)
              .length,
          30);
    });
  });
}
