// Phase 13 / M2 — T3: journal producer rules (U-11…U-19, U-18b, U-32,
// F-09, C-12) and the TERMINAL-OUTCOME EXCLUSIVITY invariants (owner
// amendment approval, security check):
//   * one capture outcome per trigger (captureSaved XOR captureNotSaved);
//   * one alarm outcome per trigger (alarmStarted XOR alarmNotStarted);
//   * alarmStopped only after a recorded, still-unmatched alarmStarted.
//
// SIMULATED: Dart VM, in-memory DB with scripted faults, injected clock.

import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/protection_health_journal_recorder.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/protection/health/protection_health_engine.dart';
import 'package:smart_app_lock/protection/health/protection_health_monitor.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';

const String _key = SecurityEventJournalStore.storageKey;

class _FaultDb extends InMemoryLocalDatabase {
  bool failWrites = false;
  int writes = 0;

  @override
  Future<void> setSetting(String key, String value) async {
    if (failWrites && key == _key) throw StateError('write fault');
    if (key == _key) writes++;
    return super.setSetting(key, value);
  }

  // E-2 (disclosed): journal / evidence rows are now written with
  // compareAndSetSetting; the same fault interception applies to it.
  @override
  Future<CasOutcome> compareAndSetSetting(String key,
      {required String? expected, required String next}) async {
    if (failWrites && key == _key) throw StateError('write fault');
    if (key == _key) writes++;
    return super.compareAndSetSetting(key, expected: expected, next: next);
  }
}

/// Monitor double: only `changes` and `refresh` are reachable.
class _FakeMonitor implements ProtectionHealthMonitor {
  final StreamController<ProtectionHealthReport> controller =
      StreamController<ProtectionHealthReport>.broadcast();
  int refreshCalls = 0;

  @override
  Stream<ProtectionHealthReport> get changes => controller.stream;

  @override
  Future<ProtectionHealthReport> refresh({bool afterChange = false}) {
    refreshCalls++;
    throw StateError('the recorder must never refresh');
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('${invocation.memberName}');
}

class _ThrowingFieldSink implements SecurityEventFieldSink {
  int calls = 0;

  @override
  void recordEvent(SecurityJournalEventType type, SecurityEventFields fields) {
    calls++;
    throw StateError('sink');
  }

  @override
  void recordLost(int count) {
    calls++;
    throw StateError('sink');
  }
}

final DateTime _t0 = DateTime(2026, 10, 22, 12);

/// A healthy report (`secure`) or one with specific signals off.
ProtectionHealthReport report(DateTime at,
        {bool overlay = true,
        bool accessibility = true,
        bool configured = true}) =>
    ProtectionHealthEngine.evaluate(
      HealthSignals(
        observedAt: at,
        protectionConfigured: configured,
        credentialConfigured: configured,
        hasProtectedApps: configured,
        nativeProtectionEnabled: configured,
        overlayGranted: overlay,
        overlayEverGranted: true,
        accessibilityEnabled: accessibility,
        accessibilityEverGranted: true,
        accessibilityConnected: accessibility,
        usageAccessGranted: true,
        usageAccessEverGranted: true,
        nativeHealthAvailable: true,
        watcherRunning: true,
        shieldArmed: true,
        notificationsGranted: true,
        backgroundRestricted: false,
        sdkInt: 34,
        powerSaveMode: false,
        ignoringBatteryOptimizations: true,
      ),
      now: at,
    );

/// Synthetic report (bypasses the engine, which never emits another code
/// together with `protectionNotConfigured`): isolates the P11 neutral rule.
class _MixedReport implements ProtectionHealthReport {
  _MixedReport(this.issues, this.state, this.observedAt);
  @override
  final List<HealthIssue> issues;
  @override
  final ProtectionHealthState state;
  @override
  final DateTime observedAt;
  @override
  bool get stale => false;
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('${invocation.memberName}');
}

HealthIssue _mixedIssue(HealthIssueCode code) => HealthIssue(
      code: code,
      component: HealthComponent.protectionConfiguration,
      cause: HealthCause.setupIncomplete,
      action: HealthRepairAction.configureProtection,
    );

void main() {
  late _FaultDb db;
  late DateTime now;

  SecurityEventJournal journal(
          {int maxPending = 64, int maxHealthEvents = 100}) =>
      SecurityEventJournal(
        store: SecurityEventJournalStore(db),
        now: () => now,
        maxPending: maxPending,
        maxHealthEvents: maxHealthEvents,
      );

  Future<SecurityJournalView> view(SecurityEventJournal j) async {
    await j.idle();
    return j.read();
  }

  List<SecurityJournalEventType> types(SecurityJournalView v) =>
      v.events.map((SecurityJournalEvent e) => e.type).toList();

  List<SecurityJournalEvent> ofType(
          SecurityJournalView v, SecurityJournalEventType t) =>
      v.events.where((SecurityJournalEvent e) => e.type == t).toList();

  setUp(() {
    db = _FaultDb();
    now = _t0;
  });

  group('terminal-outcome exclusivity (security check)', () {
    test(
        'captureSaved then captureNotSaved for one trigger: the first stands, '
        'the contradiction is lost +1', () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(5));
      j.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(5, CaptureWhy.storage));
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.captureSaved).length, 1);
      expect(ofType(v, SecurityJournalEventType.captureNotSaved), isEmpty);
      expect(v.lost, 1);
    });

    test(
        'captureNotSaved then captureSaved (reverse order): first stands, '
        'lost +1', () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(5, CaptureWhy.timeout));
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(5));
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.captureNotSaved).length, 1);
      expect(ofType(v, SecurityJournalEventType.captureSaved), isEmpty);
      expect(v.lost, 1);
    });

    test('two different captureNotSaved reasons for one trigger: one stored',
        () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(5, CaptureWhy.busy));
      j.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(5, CaptureWhy.camera));
      final SecurityJournalView v = await view(j);
      final List<SecurityJournalEvent> ns =
          ofType(v, SecurityJournalEventType.captureNotSaved);
      expect(ns.length, 1);
      expect((ns.single.fields! as CaptureNotSavedFields).why, CaptureWhy.busy);
      // Same type for the same trigger is treated as a duplicate callback.
      expect(v.lost, 0);
    });

    test('alarmStarted + alarmNotStarted for one trigger (both orders)',
        () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(1));
      j.recordEvent(SecurityJournalEventType.alarmNotStarted,
          const AlarmNotStartedFields(1, AlarmWhy.dnd));
      j.recordEvent(SecurityJournalEventType.alarmNotStarted,
          const AlarmNotStartedFields(2, AlarmWhy.ringer));
      j.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(2));
      final SecurityJournalView v = await view(j);
      expect(
          v.events
              .where(
                  (SecurityJournalEvent e) => e.type.terminalFamily == 'alarm')
              .map((SecurityJournalEvent e) =>
                  '${e.type.name}:${e.fields!.trig}')
              .toList(),
          <String>['alarmStarted:1', 'alarmNotStarted:2']);
      expect(v.lost, 2);
    });

    test(
        'a capture outcome and an alarm outcome for the same trigger are '
        'independent families (both stored)', () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(3));
      j.recordEvent(SecurityJournalEventType.alarmNotStarted,
          const AlarmNotStartedFields(3, AlarmWhy.alreadyPlaying));
      final SecurityJournalView v = await view(j);
      expect(
          types(v),
          containsAllInOrder(<SecurityJournalEventType>[
            SecurityJournalEventType.captureSaved,
            SecurityJournalEventType.alarmNotStarted,
          ]));
      expect(v.lost, 0);
    });

    test('alarmStopped with no recorded start ⇒ not stored, lost +1', () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.alarmStopped), isEmpty);
      expect(v.lost, 1);
    });

    test('alarmStopped after alarmNotStarted only ⇒ not stored, lost +1',
        () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(SecurityJournalEventType.alarmNotStarted,
          const AlarmNotStartedFields(1, AlarmWhy.cancelled));
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.alarmStopped), isEmpty);
      expect(v.lost, 1);
    });

    test('alarmStopped after a start is stored once; a second stop is lost',
        () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(1));
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.alarmStopped).length, 1);
      expect(v.lost, 1);
      // A new start re-arms exactly one stop.
      j.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(2));
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      final SecurityJournalView v2 = await view(j);
      expect(ofType(v2, SecurityJournalEventType.alarmStopped).length, 2);
      expect(v2.lost, 1);
    });

    test('alarmStopped after its start was EVICTED ⇒ not stored, lost +1',
        () async {
      final SecurityEventJournal j = SecurityEventJournal(
          store: SecurityEventJournalStore(db), now: () => now, maxEvents: 3);
      j.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(1));
      for (int t = 10; t < 14; t++) {
        j.recordEvent(
            SecurityJournalEventType.captureSaved, CaptureSavedFields(t));
      }
      SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.alarmStarted), isEmpty);
      final int lostBefore = v.lost;
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      v = await view(j);
      expect(ofType(v, SecurityJournalEventType.alarmStopped), isEmpty);
      expect(v.lost, lostBefore + 1);
    });

    test(
        'exclusivity survives a reload (persisted first outcome is the '
        'comparison base across processes)', () async {
      final SecurityEventJournal a = journal();
      a.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(8));
      a.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(8));
      await a.idle();
      final SecurityEventJournal b = journal();
      b.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(8, CaptureWhy.error));
      b.recordEvent(SecurityJournalEventType.alarmNotStarted,
          const AlarmNotStartedFields(8, AlarmWhy.error));
      b.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      final SecurityJournalView v = await view(b);
      expect(
          types(v).where((SecurityJournalEventType t) => t.isOutcome).toList(),
          <SecurityJournalEventType>[
            SecurityJournalEventType.captureSaved,
            SecurityJournalEventType.alarmStarted,
          ]);
      expect(ofType(v, SecurityJournalEventType.alarmStopped).length, 1);
      expect(v.lost, 2);
    });

    test('async ordering: interleaved queued records resolve in FIFO order',
        () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
      j.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(1));
      j.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(1, CaptureWhy.cancelled));
      final Future<SecurityJournalView> mid = j.read();
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      j.recordEvent(SecurityJournalEventType.alarmNotStarted,
          const AlarmNotStartedFields(1, AlarmWhy.cancelled));
      j.recordEvent(
          SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
      j.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(1)); // exact duplicate
      final SecurityJournalView m = await mid;
      expect(
          types(m).where((SecurityJournalEventType t) =>
              t != SecurityJournalEventType.journalStarted),
          <SecurityJournalEventType>[
            SecurityJournalEventType.captureSaved,
            SecurityJournalEventType.alarmStarted,
          ]);
      expect(m.lost, 1);
      final SecurityJournalView v = await view(j);
      expect(
          types(v).where((SecurityJournalEventType t) =>
              t != SecurityJournalEventType.journalStarted),
          <SecurityJournalEventType>[
            SecurityJournalEventType.captureSaved,
            SecurityJournalEventType.alarmStarted,
            SecurityJournalEventType.alarmStopped,
          ]);
      expect(v.lost, 3);
    });

    test(
        'a storage exception on the first outcome: lost +1, nothing stored; '
        'the retried contradictory outcome is then stored (no phantom base)',
        () async {
      final SecurityEventJournal j = journal();
      db.failWrites = true;
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(4));
      await j.idle();
      expect(j.pendingLost, greaterThanOrEqualTo(1));
      db.failWrites = false;
      j.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(4, CaptureWhy.storage));
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.captureSaved), isEmpty);
      expect(ofType(v, SecurityJournalEventType.captureNotSaved).length, 1);
      expect(v.lost, greaterThanOrEqualTo(1));
    });
  });

  group('U-16 duplicate callbacks', () {
    test('an exact (type, trig) duplicate is not stored and NOT counted lost',
        () async {
      final SecurityEventJournal j = journal();
      for (int i = 0; i < 5; i++) {
        j.recordEvent(
            SecurityJournalEventType.captureSaved, const CaptureSavedFields(9));
        j.recordEvent(
            SecurityJournalEventType.alarmStarted, const AlarmStartedFields(9));
      }
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.captureSaved).length, 1);
      expect(ofType(v, SecurityJournalEventType.alarmStarted).length, 1);
      expect(v.lost, 0);
    });
  });

  group('U-11…U-14 health', () {
    test(
        'U-11 equal (s, c) ⇒ no event and no write; same s, different c ⇒ '
        'event', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      await j.idle();
      final int w = db.writes;
      now = now.add(const Duration(minutes: 30));
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      await j.idle();
      expect(db.writes, w);
      now = now.add(const Duration(minutes: 30));
      j.recordHealthObservation(HState.attention,
          <HCode>[HCode.overlayUnavailable, HCode.notificationsDisabled]);
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.protectionHealth).length, 2);
    });

    test(
        'U-11 recorder: protectionNotConfigured alone is neutral (nothing, '
        'hs unchanged); with another actionable code it is recorded', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      final ProtectionHealthJournalRecorder r =
          ProtectionHealthJournalRecorder(journal: j);
      r.onReport(report(now, configured: false));
      await j.idle();
      final Map<String, Object?> d =
          jsonDecode((await db.getSetting(_key))!) as Map<String, Object?>;
      expect(d.containsKey('hs'), isFalse);
      expect(r.recorded, 0);
      now = now.add(const Duration(minutes: 1));
      r.onReport(report(now, configured: false, overlay: false));
      final SecurityJournalView v = await view(j);
      final List<SecurityJournalEvent> h =
          ofType(v, SecurityJournalEventType.protectionHealth);
      // Either the configuration issue suppresses the overlay code in the
      // engine (then nothing new) or it is recorded with the full set; the
      // neutral rule must never drop an actionable code by itself.
      if (r.recorded == 1) {
        expect(h.length, 1);
        expect((h.single.fields! as ProtectionHealthFields).codes,
            contains(HCode.overlayUnavailable));
      } else {
        expect(h, isEmpty);
      }
    });

    test(
        'U-11b recorder (synthetic mixed report): protectionNotConfigured + '
        'accessibilityNotRunning ⇒ recorded with both codes; the neutral '
        'code never suppresses the actionable one', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      final ProtectionHealthJournalRecorder r =
          ProtectionHealthJournalRecorder(journal: j);
      r.onReport(_MixedReport(
          <HealthIssue>[_mixedIssue(HealthIssueCode.protectionNotConfigured)],
          ProtectionHealthState.attentionRequired,
          now));
      await j.idle();
      expect(r.recorded, 0, reason: 'neutral alone');
      now = now.add(const Duration(minutes: 1));
      r.onReport(_MixedReport(<HealthIssue>[
        _mixedIssue(HealthIssueCode.protectionNotConfigured),
        _mixedIssue(HealthIssueCode.accessibilityNotRunning),
      ], ProtectionHealthState.protectionOffline, now));
      final SecurityJournalView v = await view(j);
      expect(r.recorded, 1);
      final List<SecurityJournalEvent> h =
          ofType(v, SecurityJournalEventType.protectionHealth);
      expect(h.length, 1);
      final ProtectionHealthFields f =
          h.single.fields! as ProtectionHealthFields;
      expect(f.state, HState.offline);
      expect(
          f.codes,
          containsAll(<HCode>[
            HCode.accessibilityNotRunning,
            HCode.protectionNotConfigured,
          ]));
    });

    test(
        'U-12 rate window: 3 same-state changes within 10 min ⇒ 1 recorded, '
        'sup attached to the next; backwards clock ⇒ window elapsed', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      now = now.add(const Duration(minutes: 2));
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.notificationsDisabled]);
      now = now.add(const Duration(minutes: 2));
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.shieldNotArmed]);
      SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.protectionHealth).length, 1);
      expect(v.suppressed, 2);
      now = now.add(const Duration(minutes: 11));
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      v = await view(j);
      final List<SecurityJournalEvent> h =
          ofType(v, SecurityJournalEventType.protectionHealth);
      expect(h.length, 2);
      expect((h.last.fields! as ProtectionHealthFields).suppressed, 2);
      expect(v.suppressed, 0);
      // Backwards clock: earlier than every recorded event ⇒ not limited.
      now = _t0.subtract(const Duration(days: 1));
      j.recordHealthObservation(HState.attention, <HCode>[HCode.signalUnknown]);
      v = await view(j);
      final List<SecurityJournalEvent> h2 =
          ofType(v, SecurityJournalEventType.protectionHealth);
      expect(h2.length, 3);
      expect(h2.last.clockBack, isTrue);
    });

    test(
        'U-13 quota: 150 health + 20 outcomes ⇒ health ≤ 100, all 20 '
        'outcomes kept, evictions counted', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      for (int i = 0; i < 150; i++) {
        now = now.add(const Duration(minutes: 11));
        j.recordHealthObservation(
            i.isEven ? HState.attention : HState.offline, <HCode>[
          if (i.isEven) HCode.overlayUnavailable else HCode.detectionOffline
        ]);
        if (i % 7 == 0 && i ~/ 7 < 20) {
          j.recordEvent(SecurityJournalEventType.captureSaved,
              CaptureSavedFields(1000 + i ~/ 7));
        }
        if (i % 40 == 0) await j.idle();
      }
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.protectionHealth).length,
          lessThanOrEqualTo(100));
      expect(ofType(v, SecurityJournalEventType.captureSaved).length, 20);
      expect(v.discarded, greaterThanOrEqualTo(50));
    });

    test(
        'U-14 seeding: row missing + first observation ⇒ no write; next '
        'in-process change ⇒ recorded (row created)', () async {
      final SecurityEventJournal j = journal();
      j.recordHealthObservation(
          HState.offline, <HCode>[HCode.detectionOffline]);
      await j.idle();
      expect(await db.getSetting(_key), isNull);
      expect(db.writes, 0);
      now = now.add(const Duration(minutes: 1));
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      await j.idle();
      expect(await db.getSetting(_key), isNotNull);
      final SecurityJournalView v = await view(j);
      final List<SecurityJournalEvent> h =
          ofType(v, SecurityJournalEventType.protectionHealth);
      expect(h.length, 1);
      expect((h.single.fields! as ProtectionHealthFields).first, isFalse);
    });

    test(
        'U-14 row present ⇒ first differing observation recorded with '
        'first: true, only once per process', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      j.recordHealthObservation(
          HState.offline, <HCode>[HCode.detectionOffline]);
      now = now.add(const Duration(minutes: 1));
      j.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      final SecurityJournalView v = await view(j);
      final List<SecurityJournalEvent> h =
          ofType(v, SecurityJournalEventType.protectionHealth);
      expect(
          h.map((SecurityJournalEvent e) =>
              (e.fields! as ProtectionHealthFields).first),
          <bool>[true, false]);
      // A new process over the same row: first again only if it differs.
      final SecurityEventJournal k = journal();
      now = now.add(const Duration(minutes: 30));
      k.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      final SecurityJournalView v2 = await view(k);
      expect(ofType(v2, SecurityJournalEventType.protectionHealth).length, 2);
    });
  });

  group('U-17 / F-09 clock', () {
    test(
        'now < last.at ⇒ cb: true, never re-timed or reordered; +40 days ⇒ '
        'retention drops counted', () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
      await j.idle();
      now = _t0.subtract(const Duration(days: 1));
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(2));
      SecurityJournalView v = await view(j);
      final List<SecurityJournalEvent> c =
          ofType(v, SecurityJournalEventType.captureSaved);
      expect(c.map((SecurityJournalEvent e) => e.fields!.trig), <int>[1, 2]);
      expect(c.last.clockBack, isTrue);
      expect(c.last.at, _t0.subtract(const Duration(days: 1)));
      expect(c.first.clockBack, isFalse);
      now = _t0.add(const Duration(days: 40));
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(3));
      v = await view(j);
      expect(
          ofType(v, SecurityJournalEventType.captureSaved)
              .map((SecurityJournalEvent e) => e.fields!.trig),
          <int>[3]);
      expect(v.discarded, greaterThanOrEqualTo(2));
    });
  });

  group('U-18 / U-18b invalid input never throws', () {
    test('type/fields mismatch, invalid value, 65th pending ⇒ lost', () async {
      final SecurityEventJournal j = journal();
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const AlarmStartedFields(1));
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(-1));
      j.recordEvent(
          SecurityJournalEventType.protectionHealth,
          ProtectionHealthFields(
              state: HState.secure, codes: const <HCode>[], first: false));
      expect(j.pendingLost, 3);
      final SecurityEventJournal k = journal(maxPending: 64);
      for (int i = 0; i < 65; i++) {
        k.recordEvent(
            SecurityJournalEventType.captureSaved, CaptureSavedFields(i));
      }
      expect(k.pendingLost, greaterThanOrEqualTo(1));
      final SecurityJournalView v = await view(k);
      expect(ofType(v, SecurityJournalEventType.captureSaved).length,
          lessThanOrEqualTo(64));
    });

    test(
        'U-18b a synchronously throwing sink cannot propagate through the '
        'safe wrapper', () {
      final _ThrowingFieldSink s = _ThrowingFieldSink();
      expect(
          () => recordSecurityEventFieldsSafely(
              s,
              SecurityJournalEventType.captureSaved,
              const CaptureSavedFields(1)),
          returnsNormally);
      expect(s.calls, greaterThanOrEqualTo(1));
    });
  });

  group('U-19 worst-case sizes', () {
    // Measured maxima (gate R2 §5.4 quoted 422 / 124 B; the exhaustive
    // computation below gives 423 / 128 B — health "attention" +
    // "first":false; outcome alarmNotStarted "alreadyPlaying"; disclosed in
    // the implementation addendum). The 64 KiB bound still holds with the
    // measured values (100 × 423 + 100 × 128 + 600 = 55,700 B).
    test(
        'health max 423 B, outcome max 128 B (exhaustive); 100 + 100 at max '
        '≤ 64 KiB; byte cap drops counted in a quota-bypassing fixture',
        () async {
      final DateTime maxAt =
          DateTime.fromMillisecondsSinceEpoch(securityJournalMaxAtMillis);
      final SecurityJournalEvent health = SecurityJournalEvent(
        seq: 0x7fffffff,
        at: maxAt,
        type: SecurityJournalEventType.protectionHealth,
        fields: ProtectionHealthFields(
            state: HState.attention,
            codes: HCode.values,
            first: false,
            suppressed: 0x7fffffff),
        clockBack: true,
      );
      final SecurityJournalEvent outcome = SecurityJournalEvent(
        seq: 0x7fffffff,
        at: maxAt,
        type: SecurityJournalEventType.captureNotSaved,
        fields: const CaptureNotSavedFields(
            securityJournalMaxSafeInt, CaptureWhy.unsupported),
        clockBack: true,
      );
      int len(SecurityJournalEvent e) =>
          utf8.encode(jsonEncode(e.toJson())).length;
      final int hb = len(health);
      final int ob = len(outcome);
      int hMax = 0;
      for (final HState s in HState.values) {
        for (final bool first in <bool>[true, false]) {
          final int l = len(SecurityJournalEvent(
              seq: 0x7fffffff,
              at: maxAt,
              type: SecurityJournalEventType.protectionHealth,
              fields: ProtectionHealthFields(
                  state: s,
                  codes: HCode.values,
                  first: first,
                  suppressed: 0x7fffffff),
              clockBack: true));
          if (l > hMax) hMax = l;
        }
      }
      int oMax = 0;
      final List<SecurityEventFields> outs = <SecurityEventFields>[
        for (final CaptureWhy w in CaptureWhy.values)
          CaptureNotSavedFields(securityJournalMaxSafeInt, w),
        for (final AlarmWhy w in AlarmWhy.values)
          AlarmNotStartedFields(securityJournalMaxSafeInt, w),
        const CaptureSavedFields(securityJournalMaxSafeInt),
        const AlarmStartedFields(securityJournalMaxSafeInt),
      ];
      for (final SecurityEventFields f in outs) {
        final int l = len(SecurityJournalEvent(
            seq: 0x7fffffff,
            at: maxAt,
            type: f.type,
            fields: f,
            clockBack: true));
        if (l > oMax) oMax = l;
      }
      expect(hb, 423);
      expect(hMax, 423);
      expect(ob, 125);
      expect(oMax, 128);
      expect(100 * hMax + 100 * oMax + 600, lessThan(64 * 1024));

      // Quota bypassed (maxHealthEvents 200): the byte cap binds and counts.
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal(maxHealthEvents: 200);
      final List<HCode> all = HCode.values;
      for (int i = 0; i < 200; i++) {
        now = now.add(const Duration(minutes: 11));
        j.recordHealthObservation(i.isEven ? HState.attention : HState.offline,
            i.isEven ? all : all.sublist(1));
        if (i % 40 == 0) await j.idle();
      }
      final SecurityJournalView v = await view(j);
      final int bytes = utf8.encode((await db.getSetting(_key))!).length;
      expect(bytes, lessThanOrEqualTo(64 * 1024));
      expect(v.discarded, greaterThan(0));
    });
  });

  group('U-32 recorder', () {
    test(
        'stream onError and close ⇒ no throw; stale report ignored; '
        'refresh() never called', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      final _FakeMonitor m = _FakeMonitor();
      final ProtectionHealthJournalRecorder r =
          ProtectionHealthJournalRecorder(journal: j)..attach(m);
      m.controller.addError(StateError('monitor'));
      await Future<void>.delayed(Duration.zero);
      // Stale: observed long before `now` ⇒ engine marks it stale.
      final ProtectionHealthReport stale = ProtectionHealthEngine.evaluate(
          report(now.subtract(const Duration(hours: 2)), overlay: false)
              .signals,
          now: now);
      expect(stale.stale, isTrue);
      m.controller.add(stale);
      await Future<void>.delayed(Duration.zero);
      expect(r.recorded, 0);
      m.controller.add(report(now, overlay: false));
      await Future<void>.delayed(Duration.zero);
      expect(r.recorded, 1);
      // Out of order (older than the last processed) ⇒ ignored.
      m.controller.add(report(now.subtract(const Duration(seconds: 5)),
          accessibility: false));
      await Future<void>.delayed(Duration.zero);
      expect(r.recorded, 1);
      await m.controller.close();
      await r.close();
      await r.close();
      expect(m.refreshCalls, 0);
      await j.idle();
    });
  });

  group('C-12 health / storage race', () {
    test(
        'the queue serializes interleaved health and storage observations: '
        'one event per transition, no duplicates', () async {
      await (journal()..record(SecurityJournalEventType.journalRecovered))
          .idle();
      final SecurityEventJournal j = journal();
      for (int i = 0; i < 3; i++) {
        j.recordStorageObservation(
            StorageSource.failureLog, StoreState.failing);
        j.recordHealthObservation(
            HState.offline, <HCode>[HCode.detectionOffline]);
      }
      final SecurityJournalView v = await view(j);
      expect(ofType(v, SecurityJournalEventType.storageUnavailable).length, 1);
      expect(ofType(v, SecurityJournalEventType.protectionHealth).length, 1);
      expect(v.lost, 0);
    });
  });
}
