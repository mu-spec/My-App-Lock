// Phase 13 / M2 — T6: coordinator outcome observer (U-28…U-31b, C-05…C-08,
// F-07, F-10) plus source-level exclusivity: exactly one terminal capture
// outcome per slot entry, one alarm outcome per invocation, and
// AlarmStopped only after a reported AlarmStarted.
//
// SIMULATED: Dart VM; scripted platform; real encrypted stores in memory.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_coordinator.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_settings.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_service.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/timeline/intruder_outcome_journal_adapter.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';

import '../../support/intruder_fixtures.dart';

FailedAttemptEvent ev(int seq, int run) => FailedAttemptEvent(
      seq: seq,
      verificationId: 'p:$seq',
      at: DateTime(2026, 10, 22),
      method: FailedAttemptMethod.pin,
      surface: AuthAttemptSurface.protectedAppChallenge,
      consecutiveFailures: run,
      lockoutTriggered: run == 3,
      lockoutStreak: run >= 3 ? 1 : 0,
      counterPersisted: true,
      packageName: 'com.bank',
    );

String sig(IntruderOutcome o) => switch (o) {
      CaptureSavedOutcome(:final int trig) => 'saved:$trig',
      CaptureNotSavedOutcome(:final int trig, :final IntruderCaptureWhy why) =>
        'notSaved:$trig:${why.name}',
      AlarmStartedOutcome(:final int trig) => 'started:$trig',
      AlarmNotStartedOutcome(:final int trig, :final IntruderAlarmWhy why) =>
        'notStarted:$trig:${why.name}',
      AlarmStoppedOutcome() => 'stopped',
    };

class _Spy implements IntruderOutcomeObserver {
  _Spy(this.log);
  final List<String> log;
  final List<IntruderOutcome> got = <IntruderOutcome>[];
  @override
  void onIntruderOutcome(IntruderOutcome o) {
    got.add(o);
    log.add('outcome:${sig(o)}');
  }

  List<String> get sigs => got.map(sig).toList();
}

class _ThrowingObserver implements IntruderOutcomeObserver {
  int calls = 0;
  @override
  void onIntruderOutcome(IntruderOutcome o) {
    calls++;
    throw StateError('observer bug');
  }
}

/// Evidence store with a scripted save result / throw and call log.
class _ScriptStore extends IntruderEvidenceStore {
  _ScriptStore(super.db, super.cipher, this.log);
  final List<String> log;
  EvidenceSaveResult? result;
  bool throwOnSave = false;

  @override
  Future<EvidenceSaveResult> save({
    required int seq,
    required Uint8List jpeg,
    String? packageName,
    bool Function()? stillValid,
  }) async {
    log.add('save:$seq');
    if (throwOnSave) throw StateError('store bug');
    final EvidenceSaveResult? r = result;
    if (r != null) {
      log.add('saved:$seq');
      return r;
    }
    final EvidenceSaveResult real = await super.save(
        seq: seq, jpeg: jpeg, packageName: packageName, stillValid: stillValid);
    log.add('saved:$seq');
    return real;
  }
}

/// Settings store whose Nth read throws (or returns disabled).
class _ScriptSettings extends IntruderDefenseSettingsStore {
  _ScriptSettings(super.db, super.cipher);
  int reads = 0;
  int? throwOnRead;
  int? disableOnRead;

  @override
  Future<IntruderSettingsRead> read() async {
    reads++;
    if (reads == throwOnRead) throw StateError('settings bug');
    final IntruderSettingsRead r = await super.read();
    if (reads == disableOnRead) {
      await write(const IntruderDefenseSettings(
          evidenceEnabled: false, alarmEnabled: true, threshold: 1));
      return super.read();
    }
    return r;
  }
}

class _Rig {
  _Rig({bool photo = true, bool alarm = true, int threshold = 1}) {
    final SettingsCipher cipher = AesGcmSettingsCipher(InMemorySecretStore(),
        database: InMemoryLocalDatabase());
    settings = _ScriptSettings(db, cipher);
    store = _ScriptStore(db, cipher, log);
    platform = GatedEvidenceService()
      ..permission = CameraPermissionState.granted;
    platform.onCapture = () => CaptureSucceeded(jpegWithMetadata());
    coordinator = IntruderDefenseCoordinator(
        settings: settings, evidence: store, service: platform);
    spy = _Spy(log);
    coordinator.outcomeObserver = spy;
    _init = settings.write(IntruderDefenseSettings(
        evidenceEnabled: photo, alarmEnabled: alarm, threshold: threshold));
  }

  final InMemoryLocalDatabase db = InMemoryLocalDatabase();
  final List<String> log = <String>[];
  late final _ScriptSettings settings;
  late final _ScriptStore store;
  late final GatedEvidenceService platform;
  late final IntruderDefenseCoordinator coordinator;
  late final _Spy spy;
  late final Future<void> _init;

  Future<void> ready() => _init;

  Future<void> trigger(int seq, {int run = 1}) async {
    await ready();
    settings.reads = 0; // count only reads made by the coordinator
    coordinator.onFailedAttemptRecorded(ev(seq, run));
    await coordinator.idle();
  }
}

String status(IntruderDefenseStatus s) => <Object?>[
      s.triggers,
      s.captured,
      s.captureSkipped,
      s.captureFailed,
      s.captureCancelled,
      s.saveFailed,
      s.alarmsStarted,
      s.alarmsSuppressed,
      s.alarmsCancelled,
      s.errors,
      s.lastFailure,
    ].join('|');

void main() {
  group('U-28 every branch ⇒ exactly the expected outcome', () {
    test('saved', () async {
      final _Rig r = _Rig(alarm: false);
      await r.trigger(1);
      expect(r.spy.sigs, <String>['saved:1']);
    });

    test('permission denied', () async {
      final _Rig r = _Rig(alarm: false);
      r.platform.permission = CameraPermissionState.denied;
      await r.trigger(1);
      expect(r.spy.sigs, <String>['notSaved:1:permission']);
    });

    test('CaptureFailed timeout vs camera (reason string never forwarded)',
        () async {
      final _Rig r = _Rig(alarm: false);
      r.platform.onCapture = () => const CaptureFailed('timeout');
      await r.trigger(1);
      r.platform.onCapture = () => const CaptureFailed('OEM_SECRET_123');
      await r.trigger(2);
      expect(r.spy.sigs, <String>['notSaved:1:timeout', 'notSaved:2:camera']);
    });

    test('epoch changed while waiting for permission ⇒ cancelled', () async {
      final _Rig r = _Rig(alarm: false);
      await r.ready();
      r.platform.gate = Completer<CaptureResult>();
      r.coordinator.onFailedAttemptRecorded(ev(1, 1));
      await Future<void>.delayed(Duration.zero);
      await Future<void>.delayed(Duration.zero);
      r.coordinator.onOwnerVerified();
      r.platform.gate!.complete(CaptureSucceeded(jpegWithMetadata()));
      await r.coordinator.idle();
      expect(r.spy.sigs, <String>['notSaved:1:cancelled']);
    });

    test('consent revoked at the re-check ⇒ cancelled', () async {
      final _Rig r = _Rig(alarm: false);
      r.settings.disableOnRead = 2;
      await r.trigger(1);
      expect(r.spy.sigs, <String>['notSaved:1:cancelled']);
    });

    test('every non-saved save result maps exhaustively', () async {
      const Map<EvidenceSaveResult, String> want = <EvidenceSaveResult, String>{
        EvidenceSaveResult.cancelled: 'cancelled',
        EvidenceSaveResult.superseded: 'superseded',
        EvidenceSaveResult.duplicate: 'duplicate',
        EvidenceSaveResult.storageFailed: 'storage',
        EvidenceSaveResult.encryptionFailed: 'encryption',
        EvidenceSaveResult.invalidImage: 'image',
        EvidenceSaveResult.oversized: 'image',
        EvidenceSaveResult.unsupportedSchema: 'unsupported',
      };
      expect(want.length + 1, EvidenceSaveResult.values.length);
      int seq = 1;
      for (final MapEntry<EvidenceSaveResult, String> e in want.entries) {
        final _Rig r = _Rig(alarm: false);
        r.store.result = e.key;
        await r.trigger(seq);
        expect(r.spy.sigs, <String>['notSaved:$seq:${e.value}'],
            reason: '${e.key}');
        seq++;
      }
    });

    test('busy: trigger 2 while trigger 1 holds the slot (C-06)', () async {
      final _Rig r = _Rig(alarm: false, threshold: 1);
      await r.ready();
      r.platform.gate = Completer<CaptureResult>();
      r.coordinator.onFailedAttemptRecorded(ev(1, 1));
      await Future<void>.delayed(const Duration(milliseconds: 5));
      r.coordinator.onFailedAttemptRecorded(FailedAttemptEvent(
        seq: 2,
        verificationId: 'p:2b',
        at: DateTime(2026, 10, 22),
        method: FailedAttemptMethod.pin,
        surface: AuthAttemptSurface.protectedAppChallenge,
        consecutiveFailures: 1,
        lockoutTriggered: false,
        lockoutStreak: 0,
        counterPersisted: true,
        packageName: 'com.bank',
      ));
      await Future<void>.delayed(const Duration(milliseconds: 5));
      r.platform.gate!.complete(CaptureSucceeded(jpegWithMetadata()));
      await r.coordinator.idle();
      expect(r.spy.sigs, <String>['notSaved:2:busy', 'saved:1']);
    });

    test('alarm: started / not-started reasons / throw', () async {
      final Map<AlarmStartResult, String> want = <AlarmStartResult, String>{
        AlarmStartResult.alreadyPlaying: 'alreadyPlaying',
        AlarmStartResult.suppressedByDnd: 'dnd',
        AlarmStartResult.suppressedByRinger: 'ringer',
        AlarmStartResult.focusDenied: 'focusDenied',
        AlarmStartResult.notForeground: 'notForeground',
        AlarmStartResult.error: 'error',
      };
      for (final MapEntry<AlarmStartResult, String> e in want.entries) {
        final _Rig r = _Rig(photo: false);
        r.platform.alarmResult = e.key;
        await r.trigger(4);
        expect(r.spy.sigs, <String>['notStarted:4:${e.value}'],
            reason: '${e.key}');
      }
      final _Rig ok = _Rig(photo: false);
      await ok.trigger(5);
      expect(ok.spy.sigs, <String>['started:5']);
    });

    test(
        'early returns (below threshold, both disabled, other surface) ⇒ '
        'nothing', () async {
      final _Rig r = _Rig(threshold: 3);
      await r.trigger(1, run: 1);
      await r.trigger(2, run: 2);
      final _Rig off = _Rig(photo: false, alarm: false);
      await off.trigger(1);
      await off.ready();
      off.coordinator.onFailedAttemptRecorded(FailedAttemptEvent(
        seq: 9,
        verificationId: 'p:9',
        at: DateTime(2026, 10, 22),
        method: FailedAttemptMethod.pin,
        surface: AuthAttemptSurface.values.firstWhere((AuthAttemptSurface s) =>
            s != AuthAttemptSurface.protectedAppChallenge),
        consecutiveFailures: 1,
        lockoutTriggered: false,
        lockoutStreak: 0,
        counterPersisted: true,
      ));
      await off.coordinator.idle();
      expect(r.spy.sigs, isEmpty);
      expect(off.spy.sigs, isEmpty);
    });
  });

  group('U-28b exception at each await inside _capture ⇒ exactly one outcome',
      () {
    test('permission throws', () async {
      final _Rig r = _Rig(alarm: false);
      await r.ready();
      r.coordinator.outcomeObserver = r.spy;
      final IntruderDefenseCoordinator c = IntruderDefenseCoordinator(
          settings: r.settings,
          evidence: r.store,
          service: _PermissionThrows());
      c.outcomeObserver = r.spy;
      c.onFailedAttemptRecorded(ev(1, 1));
      await c.idle();
      expect(r.spy.sigs, <String>['notSaved:1:error']);
    });

    test('captureStill throws', () async {
      final _Rig r = _Rig(alarm: false);
      r.platform.onCapture = () => throw StateError('camera bug');
      await r.trigger(1);
      expect(r.spy.sigs, <String>['notSaved:1:error']);
    });

    test('settings re-read throws', () async {
      final _Rig r = _Rig(alarm: false);
      r.settings.throwOnRead = 2;
      await r.trigger(1);
      expect(r.spy.sigs, <String>['notSaved:1:error']);
    });

    test('save throws', () async {
      final _Rig r = _Rig(alarm: false);
      r.store.throwOnSave = true;
      await r.trigger(1);
      expect(r.spy.sigs, <String>['notSaved:1:error']);
    });
  });

  group('U-29 privacy', () {
    test('a native code / reason string never reaches the decrypted journal',
        () async {
      final _Rig r = _Rig(alarm: false);
      final InMemoryLocalDatabase jdb = InMemoryLocalDatabase();
      final SettingsCipher jc = AesGcmSettingsCipher(InMemorySecretStore(),
          database: InMemoryLocalDatabase());
      final SecurityEventJournalStore js =
          SecurityEventJournalStore(jdb, cipher: jc);
      final SecurityEventJournal j = SecurityEventJournal(store: js);
      r.coordinator.outcomeObserver = IntruderOutcomeJournalAdapter(j);
      r.platform.onCapture = () => const CaptureFailed('OEM_SECRET_123');
      await r.trigger(1);
      await Future<void>.delayed(Duration.zero);
      await j.idle();
      final String stored =
          (await jdb.getSetting(SecurityEventJournalStore.storageKey))!;
      expect(stored, startsWith('enc:v1:'));
      expect(stored, isNot(contains('OEM_SECRET_123')));
      final String plain =
          await jc.decryptString(stored.substring('enc:v1:'.length));
      expect(plain, isNot(contains('OEM_SECRET_123')));
      expect(plain, contains('"why":"camera"'));
      expect(r.coordinator.status.lastFailure, 'capture:OEM_SECRET_123',
          reason: 'pre-existing in-memory status only');
    });
  });

  group('U-30 / F-07 / F-10 isolation', () {
    Future<String> run(IntruderOutcomeObserver? o,
        {bool pendingAlarm = false}) async {
      final _Rig r = _Rig();
      r.coordinator.outcomeObserver = o;
      await r.ready();
      if (pendingAlarm) r.platform.alarmGate = Completer<AlarmStartResult>();
      r.coordinator.onFailedAttemptRecorded(ev(1, 1));
      if (pendingAlarm) {
        await Future<void>.delayed(const Duration(milliseconds: 5));
        r.coordinator.onOwnerVerified();
        r.platform.alarmGate!.complete(AlarmStartResult.started);
      }
      await r.coordinator.idle();
      r.coordinator.onOwnerVerified();
      await r.coordinator.idle();
      r.platform.onCapture = () => const CaptureFailed('x');
      r.coordinator.onFailedAttemptRecorded(ev(2, 1));
      await r.coordinator.idle();
      return '${status(r.coordinator.status)} / ${r.platform.ops.join(',')}';
    }

    test(
        'U-30 always-throwing observer ⇒ status (incl. errors) and service '
        'log identical to a null observer', () async {
      final String base = await run(null);
      final _ThrowingObserver t = _ThrowingObserver();
      final String thrown = await run(t);
      expect(thrown, base);
      expect(t.calls, greaterThan(0));
    });

    test(
        'F-07 nothing escapes to the zone (observer and adapter sink both '
        'throw)', () async {
      final List<Object> zoneErrors = <Object>[];
      final List<String> results = <String>[];
      final Completer<void> done = Completer<void>();
      runZonedGuarded(() async {
        try {
          results.add(await run(null));
          results.add(await run(_ThrowingObserver()));
          results.add(await run(IntruderOutcomeJournalAdapter(_ThrowSink())));
          await Future<void>.delayed(Duration.zero);
        } finally {
          done.complete();
        }
      }, (Object e, StackTrace _) => zoneErrors.add(e));
      await done.future;
      expect(zoneErrors, isEmpty);
      expect(results.length, 3);
      expect(results[1], results[0]);
      expect(results[2], results[0]);
    });

    test(
        'F-10 throwing observer while an alarm start is pending and the '
        'owner verifies ⇒ stopped by epoch; status identical', () async {
      final String base = await run(null, pendingAlarm: true);
      final String t = await run(_ThrowingObserver(), pendingAlarm: true);
      expect(t, base);
      final _Rig r = _Rig(photo: false);
      await r.ready();
      r.platform.alarmGate = Completer<AlarmStartResult>();
      r.coordinator.onFailedAttemptRecorded(ev(1, 1));
      await Future<void>.delayed(const Duration(milliseconds: 5));
      r.coordinator.onOwnerVerified();
      r.platform.alarmGate!.complete(AlarmStartResult.started);
      await r.coordinator.idle();
      expect(r.spy.sigs, <String>['notStarted:1:cancelled']);
      expect(r.platform.alarmPlaying, isFalse);
    });
  });

  group('U-31 / U-31b ordering', () {
    test(
        'U-31 outcomes are delivered after save / startAlarm return and '
        'never inside onFailedAttemptRecorded', () async {
      final _Rig r = _Rig();
      await r.ready();
      r.coordinator.onFailedAttemptRecorded(ev(1, 1));
      expect(r.spy.got, isEmpty, reason: 'nothing synchronous');
      await r.coordinator.idle();
      final int saved = r.log.indexOf('saved:1');
      final int out = r.log.indexOf('outcome:saved:1');
      expect(saved, greaterThanOrEqualTo(0));
      expect(out, greaterThan(saved));
      expect(r.coordinator.status.captured, 1);
      expect(r.spy.sigs, containsAll(<String>['saved:1', 'started:1']));
    });

    test(
        'U-31b adapter: on return 0 DB calls and empty journal queue; after '
        'a microtask the record is enqueued in call order', () async {
      final _CountDb db = _CountDb();
      final SecurityEventJournal j =
          SecurityEventJournal(store: SecurityEventJournalStore(db));
      final IntruderOutcomeJournalAdapter a = IntruderOutcomeJournalAdapter(j);
      a.onIntruderOutcome(const AlarmStartedOutcome(1));
      a.onIntruderOutcome(const CaptureSavedOutcome(1));
      a.onIntruderOutcome(const AlarmStoppedOutcome());
      // Synchronously after the calls: no storage access and nothing queued
      // in the journal (records are only scheduled as microtasks).
      expect(db.calls, 0);
      expect(j.pendingLost, 0);
      await Future<void>.delayed(Duration.zero);
      await j.idle();
      final List<SecurityJournalEventType> t = (await j.read())
          .events
          .map((SecurityJournalEvent e) => e.type)
          .where((SecurityJournalEventType t) =>
              t != SecurityJournalEventType.journalStarted)
          .toList();
      expect(t, <SecurityJournalEventType>[
        SecurityJournalEventType.alarmStarted,
        SecurityJournalEventType.captureSaved,
        SecurityJournalEventType.alarmStopped,
      ]);
    });
  });

  group('concurrency', () {
    test(
        'C-05 one trigger, capture and alarm enabled ⇒ exactly one of each, '
        'both trig-attached', () async {
      final _Rig r = _Rig();
      await r.trigger(7);
      expect(r.spy.sigs.toSet(), <String>{'saved:7', 'started:7'});
      expect(r.spy.sigs.length, 2);
    });

    test(
        'C-07 owner success (a) while the start is pending ⇒ NotStarted('
        'cancelled), no Stopped; (b) while playing ⇒ exactly one Stopped',
        () async {
      final _Rig a = _Rig(photo: false);
      await a.ready();
      a.platform.alarmGate = Completer<AlarmStartResult>();
      a.coordinator.onFailedAttemptRecorded(ev(1, 1));
      await Future<void>.delayed(const Duration(milliseconds: 5));
      a.coordinator.onOwnerVerified();
      a.coordinator.onOwnerVerified();
      a.platform.alarmGate!.complete(AlarmStartResult.started);
      await a.coordinator.idle();
      expect(a.spy.sigs, <String>['notStarted:1:cancelled']);

      final _Rig b = _Rig(photo: false);
      await b.trigger(1);
      b.coordinator.onOwnerVerified();
      b.coordinator.onOwnerVerified();
      b.coordinator.onSettingsChanged(const IntruderDefenseSettings(
          evidenceEnabled: false, alarmEnabled: false, threshold: 1));
      await b.coordinator.idle();
      expect(b.spy.sigs, <String>['started:1', 'stopped']);
    });

    test(
        'source exclusivity under a 60-trigger interleaving: per trigger at '
        'most one capture and one alarm outcome; every stop follows a start',
        () async {
      final _Rig r = _Rig();
      await r.ready();
      r.platform.alarmResult = AlarmStartResult.started;
      for (int i = 1; i <= 60; i++) {
        r.coordinator.onFailedAttemptRecorded(ev(i, 1));
        r.coordinator.onFailedAttemptRecorded(ev(i, 1)); // duplicate
        if (i % 7 == 0) r.coordinator.onOwnerVerified();
        if (i % 11 == 0) r.platform.onCapture = () => const CaptureFailed('x');
        if (i % 13 == 0) {
          r.platform.onCapture = () => CaptureSucceeded(jpegWithMetadata());
        }
        if (i % 3 == 0) await Future<void>.delayed(Duration.zero);
      }
      await r.coordinator.idle();
      r.coordinator.onOwnerVerified();
      await r.coordinator.idle();
      final Map<String, int> perFamily = <String, int>{};
      bool playing = false;
      for (final IntruderOutcome o in r.spy.got) {
        switch (o) {
          case CaptureSavedOutcome(:final int trig) ||
                CaptureNotSavedOutcome(:final int trig):
            perFamily.update('c$trig', (int v) => v + 1, ifAbsent: () => 1);
          case AlarmStartedOutcome(:final int trig):
            perFamily.update('a$trig', (int v) => v + 1, ifAbsent: () => 1);
            playing = true;
          case AlarmNotStartedOutcome(:final int trig):
            perFamily.update('a$trig', (int v) => v + 1, ifAbsent: () => 1);
          case AlarmStoppedOutcome():
            expect(playing, isTrue, reason: 'stop without a start');
            playing = false;
        }
      }
      expect(perFamily.values.every((int v) => v == 1), isTrue,
          reason: perFamily.toString());
      // Triggers invalidated by an owner verification before handling are
      // early returns (no trigger, no outcome — Resolutions §2.3). Every
      // HANDLED trigger has exactly one capture and one alarm outcome.
      final int handled = r.coordinator.status.triggers;
      expect(handled, greaterThan(30));
      expect(perFamily.keys.where((String k) => k.startsWith('c')).length,
          handled);
      expect(perFamily.keys.where((String k) => k.startsWith('a')).length,
          handled);
    });

    test(
        'C-08 80 outcomes in one burst (pending cap 64) ⇒ lost counted; '
        'coordinator unaffected', () async {
      final SecurityEventJournal j = SecurityEventJournal(
          store: SecurityEventJournalStore(InMemoryLocalDatabase()));
      final IntruderOutcomeJournalAdapter a = IntruderOutcomeJournalAdapter(j);
      for (int i = 0; i < 80; i++) {
        a.onIntruderOutcome(CaptureSavedOutcome(i));
      }
      await Future<void>.delayed(Duration.zero);
      await j.idle();
      final SecurityJournalView v = await j.read();
      final int stored = v.events
          .where((SecurityJournalEvent e) =>
              e.type == SecurityJournalEventType.captureSaved)
          .length;
      expect(stored + v.lost, 80);
      expect(v.lost, greaterThanOrEqualTo(16));

      final String base = await _burst(null);
      final String withJ = await _burst(IntruderOutcomeJournalAdapter(
          SecurityEventJournal(
              store: SecurityEventJournalStore(InMemoryLocalDatabase()),
              maxPending: 4)));
      expect(withJ, base);
    });
  });

  test('journal JSON never contains a package name or reason text', () async {
    final _Rig r = _Rig();
    final InMemoryLocalDatabase jdb = InMemoryLocalDatabase();
    final SecurityEventJournal j =
        SecurityEventJournal(store: SecurityEventJournalStore(jdb));
    r.coordinator.outcomeObserver = IntruderOutcomeJournalAdapter(j);
    await r.trigger(1);
    await Future<void>.delayed(Duration.zero);
    await j.idle();
    final String raw =
        (await jdb.getSetting(SecurityEventJournalStore.storageKey))!;
    expect(raw, isNot(contains('com.bank')));
    expect(jsonDecode(raw), isA<Map<String, Object?>>());
  });
}

Future<String> _burst(IntruderOutcomeObserver? o) async {
  final _Rig r = _Rig(threshold: 1);
  r.coordinator.outcomeObserver = o;
  await r.ready();
  for (int i = 1; i <= 40; i++) {
    r.coordinator.onFailedAttemptRecorded(ev(i, 1));
  }
  await r.coordinator.idle();
  r.coordinator.onOwnerVerified();
  await r.coordinator.idle();
  await Future<void>.delayed(Duration.zero);
  return '${status(r.coordinator.status)} / ${r.platform.ops.join(',')}';
}

class _PermissionThrows extends GatedEvidenceService {
  @override
  Future<CameraPermissionState> cameraPermission() async =>
      throw StateError('permission bug');
}

class _ThrowSink implements SecurityEventFieldSink {
  @override
  void recordEvent(SecurityJournalEventType type, SecurityEventFields fields) =>
      throw StateError('sink');
  @override
  void recordLost(int count) => throw StateError('sink');
}

class _CountDb extends InMemoryLocalDatabase {
  int calls = 0;
  @override
  Future<String?> getSetting(String key) {
    calls++;
    return super.getSetting(key);
  }

  @override
  Future<void> setSetting(String key, String value) {
    calls++;
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
    calls++;
    return super.compareAndSetSetting(key, expected: expected, next: next);
  }
}
