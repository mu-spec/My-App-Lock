// Phase 13 / M2 — T2: lazy, atomic v1 -> v2 migration, newer-schema
// protection and storage faults (U-08…U-10, F-01…F-04, F-06).
//
// SIMULATED: Dart VM, in-memory DB with scripted faults, real AES-GCM.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
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

const String _key = SecurityEventJournalStore.storageKey;
const String _qKey = SecurityEventJournalStore.quarantineKey;

class _FaultDb extends InMemoryLocalDatabase {
  bool failReads = false;
  bool failWrites = false;
  bool failQuarantineWrites = false;
  int writes = 0;
  int reads = 0;

  @override
  Future<String?> getSetting(String key) async {
    if (key == _key) reads++;
    if (failReads && (key == _key || key == _qKey)) {
      throw StateError('read fault');
    }
    return super.getSetting(key);
  }

  @override
  Future<void> setSetting(String key, String value) async {
    if (failWrites && key == _key) throw StateError('write fault');
    if (failQuarantineWrites && key == _qKey) {
      throw StateError('quarantine fault');
    }
    if (key == _key) writes++;
    return super.setSetting(key, value);
  }
}

/// Cipher whose encryption can be made to throw.
class _FlakyCipher implements SettingsCipher {
  _FlakyCipher(this._inner);
  final SettingsCipher _inner;
  bool failEncrypt = false;

  @override
  Future<String> encryptString(String plain) {
    if (failEncrypt) throw StateError('cipher fault');
    return _inner.encryptString(plain);
  }

  @override
  Future<String> decryptString(String cipherText) =>
      _inner.decryptString(cipherText);
}

final DateTime _t0 = DateTime(2026, 10, 22, 12);

FailedAttemptEvent challengeEvent(int seq, int run) => FailedAttemptEvent(
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

Future<void> pumpMicrotasks() => Future<void>.delayed(Duration.zero);

String statusSignature(IntruderDefenseStatus s) => <Object?>[
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

String v1Row({int lost = 0, int discarded = 0}) => jsonEncode(<String, Object?>{
      'schema': SecurityJournalDocument.schema,
      'v': 1,
      'nextSeq': 3,
      'discarded': discarded,
      'lost': lost,
      'events': <Object?>[
        <String, Object?>{
          'seq': 0,
          'at': _t0.millisecondsSinceEpoch,
          'type': 'journalStarted'
        },
        <String, Object?>{
          'seq': 2,
          'at': _t0.add(const Duration(minutes: 1)).millisecondsSinceEpoch,
          'type': 'journalRecovered'
        },
      ],
    });

void main() {
  late _FaultDb db;
  late DateTime now;

  SecurityEventJournal journal({SettingsCipher? cipher}) =>
      SecurityEventJournal(
        store: SecurityEventJournalStore(db, cipher: cipher),
        now: () => now,
      );

  Future<Map<String, Object?>> rawDoc() async =>
      jsonDecode((await db.getSetting(_key))!) as Map<String, Object?>;

  setUp(() {
    db = _FaultDb();
    now = _t0.add(const Duration(hours: 1));
  });

  group('U-08 / U-09 lazy lossless migration', () {
    test('v1 decodes to an in-memory v2 losslessly (from = 1)', () {
      final SecurityJournalDocument d = SecurityJournalDocument.fromJson(
          jsonDecode(v1Row(lost: 4, discarded: 5)));
      expect(d.decodedVersion, 1);
      expect(d.from, 1);
      expect(d.nextSeq, 3);
      expect(d.lost, 4);
      expect(d.discarded, 5);
      expect(d.events.map((SecurityJournalEvent e) => e.seq), <int>[0, 2]);
      expect(
          d.events.map((SecurityJournalEvent e) => e.type),
          <SecurityJournalEventType>[
            SecurityJournalEventType.journalStarted,
            SecurityJournalEventType.journalRecovered,
          ]);
      expect(d.events.first.at, _t0);
      expect(d.events.last.at, _t0.add(const Duration(minutes: 1)));
    });

    test(
        'startup and read over v1 write nothing; the first append writes '
        'exactly once: journalUpgraded then the event, every v1 event kept',
        () async {
      await db.setSetting(_key, v1Row(lost: 1, discarded: 2));
      db.writes = 0;
      final SecurityEventJournal j = journal();
      await j.startup();
      await j.idle();
      final SecurityJournalView view = await j.read();
      expect(view.events.length, 2);
      expect(db.writes, 0, reason: 'migration alone never writes');
      expect(await db.getSetting(_key), v1Row(lost: 1, discarded: 2));
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(11));
      await j.idle();
      expect(db.writes, 1);
      final Map<String, Object?> d = await rawDoc();
      expect(d['v'], 2);
      expect(d['from'], 1);
      expect(d['lost'], 1);
      expect(d['discarded'], 2);
      final List<Object?> evs = d['events']! as List<Object?>;
      expect(
          evs.map((Object? e) => (e! as Map<String, Object?>)['type']),
          <String>[
            'journalStarted',
            'journalRecovered',
            'journalUpgraded',
            'captureSaved'
          ]);
      expect(
          (evs[0]! as Map<String, Object?>)['at'], _t0.millisecondsSinceEpoch);
      expect((evs[1]! as Map<String, Object?>)['seq'], 2);
      expect((evs[2]! as Map<String, Object?>)['seq'], 3);
      expect(
          (evs[2]! as Map<String, Object?>)['f'], <String, Object?>{'from': 1});
      expect(d['nextSeq'], 5);
      // The marker is written exactly once.
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(12));
      await j.idle();
      final List<Object?> evs2 = (await rawDoc())['events']! as List<Object?>;
      expect(
          evs2
              .where((Object? e) =>
                  (e! as Map<String, Object?>)['type'] == 'journalUpgraded')
              .length,
          1);
    });
  });

  group('U-10 newer schema (v3) is read-only for the process', () {
    test('v3 row: unsupported, 0 writes, no quarantine, outcomes lost',
        () async {
      final String v3 = jsonEncode(<String, Object?>{
        'schema': SecurityJournalDocument.schema,
        'v': 3,
        'nextSeq': 1,
        'whatever': true,
        'events': <Object?>[],
      });
      await db.setSetting(_key, v3);
      db.writes = 0;
      final SecurityEventJournal j = journal();
      await j.startup();
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
      j.record(SecurityJournalEventType.journalRecovered);
      j.recordHealthObservation(
          HState.offline, <HCode>[HCode.detectionOffline]);
      j.recordStorageObservation(StorageSource.failureLog, StoreState.failing);
      await j.idle();
      final SecurityJournalView v = await j.read();
      expect(v.availability, SecurityJournalAvailability.unsupported);
      expect(j.health, SecurityJournalHealth.readOnly);
      expect(db.writes, 0);
      expect(await db.getSetting(_key), v3);
      expect(await db.getSetting(_qKey), isNull);
      expect(j.pendingLost, greaterThanOrEqualTo(2));
    });
  });

  group('faults', () {
    test(
        'F-01 the first v2 write over v1 throws: v1 byte-identical, '
        'storageError, lost folded into the next successful write (which '
        'carries journalUpgraded)', () async {
      await db.setSetting(_key, v1Row());
      final SecurityEventJournal j = journal();
      db.failWrites = true;
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
      await j.idle();
      expect(await db.getSetting(_key), v1Row());
      expect(j.health, SecurityJournalHealth.storageError);
      expect(j.pendingLost, 1);
      db.failWrites = false;
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(2));
      await j.idle();
      final Map<String, Object?> d = await rawDoc();
      expect(d['v'], 2);
      expect(d['lost'], 1);
      final List<String> types = (d['events']! as List<Object?>)
          .map((Object? e) => (e! as Map<String, Object?>)['type']! as String)
          .toList();
      expect(types, contains('journalUpgraded'));
      expect(types.where((String t) => t == 'captureSaved').length, 1);
      expect(j.pendingLost, 0);
    });

    test(
        'F-02 cipher encryption throws on append: previous row intact, '
        'loss counted', () async {
      final _FlakyCipher cipher = _FlakyCipher(AesGcmSettingsCipher(
          InMemorySecretStore(),
          database: InMemoryLocalDatabase()));
      final SecurityEventJournal j = journal(cipher: cipher);
      j.record(SecurityJournalEventType.journalRecovered);
      await j.idle();
      final String? before = await db.getSetting(_key);
      expect(before, isNotNull);
      cipher.failEncrypt = true;
      j.recordEvent(
          SecurityJournalEventType.alarmStarted, const AlarmStartedFields(3));
      await j.idle();
      expect(await db.getSetting(_key), before);
      expect(j.pendingLost, 1);
      expect(j.health, SecurityJournalHealth.storageError);
    });

    test(
        'F-03 transient read failure: nothing written, "couldn\'t be read", '
        'retried later', () async {
      await db.setSetting(_key, v1Row());
      db.writes = 0;
      final SecurityEventJournal j = journal();
      db.failReads = true;
      final SecurityJournalView v = await j.read();
      expect(v.availability, SecurityJournalAvailability.unreadable);
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
      await j.idle();
      expect(db.writes, 0);
      db.failReads = false;
      final SecurityJournalView v2 = await j.read();
      expect(v2.availability, SecurityJournalAvailability.available);
      // The v1 events are intact and nothing is fabricated. The loss of the
      // outcome is folded by the next NEEDED write, which (Resolutions
      // §5.3 step 3) carries the one-time journalUpgraded marker.
      expect(
          v2.events.map((SecurityJournalEvent e) => e.type).toList(),
          <SecurityJournalEventType>[
            SecurityJournalEventType.journalStarted,
            SecurityJournalEventType.journalRecovered,
            SecurityJournalEventType.journalUpgraded,
          ]);
      expect(v2.lost, 1);
    });

    group('F-04 corrupt v2 (GCM tamper)', () {
      Future<(SettingsCipher, String)> tampered() async {
        final SettingsCipher c = AesGcmSettingsCipher(InMemorySecretStore(),
            database: InMemoryLocalDatabase());
        final SecurityEventJournal w = journal(cipher: c);
        w.recordEvent(
            SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
        await w.idle();
        final String raw = (await db.getSetting(_key))!;
        final String bad = '${raw.substring(0, raw.length - 4)}AAAA';
        await db.setSetting(_key, bad);
        return (c, bad);
      }

      // FLIPPED (F-KEY-1 Batch 1; previously "quarantine empty: quarantined
      // first, reinitialized with journalRecovered"): a GCM failure is
      // indistinguishable from an unavailable/wrong master key, so the row
      // is UNREADABLE and keeps its exact bytes even with an empty slot.
      test(
          'quarantine empty: GCM tamper is unreadable — neither quarantined '
          'nor reinitialized (F-KEY-1 Batch 1)', () async {
        final (SettingsCipher c, String bad) = await tampered();
        final SecurityEventJournal j = journal(cipher: c);
        await j.startup();
        await j.idle();
        expect(await db.getSetting(_key), bad);
        expect(await db.getSetting(_qKey), isNull);
        expect(j.quarantinedCorruptJournal, isFalse);
        expect(j.health, SecurityJournalHealth.storageError);
      });

      test(
          'decryptable but unparsable (key proven) with quarantine empty: '
          'quarantined first, reinitialized with journalRecovered', () async {
        final SettingsCipher c = AesGcmSettingsCipher(InMemorySecretStore(),
            database: InMemoryLocalDatabase());
        final String bad = 'enc:v1:${await c.encryptString('not json')}';
        await db.setSetting(_key, bad);
        final SecurityEventJournal j = journal(cipher: c);
        await j.startup();
        await j.idle();
        expect(await db.getSetting(_qKey), bad);
        final SecurityJournalView v = await j.read();
        expect(v.events.map((SecurityJournalEvent e) => e.type),
            contains(SecurityJournalEventType.journalRecovered));
        expect(j.quarantinedCorruptJournal, isTrue);
      });

      test('quarantine occupied: the first copy is kept', () async {
        await db.setSetting(_qKey, 'FIRST');
        final (SettingsCipher c, _) = await tampered();
        final SecurityEventJournal j = journal(cipher: c);
        await j.startup();
        await j.idle();
        expect(await db.getSetting(_qKey), 'FIRST');
      });

      test('quarantine write fails: the corrupt row is NOT overwritten',
          () async {
        final (SettingsCipher c, String bad) = await tampered();
        db.failQuarantineWrites = true;
        final SecurityEventJournal j = journal(cipher: c);
        await j.startup();
        j.recordEvent(
            SecurityJournalEventType.captureSaved, const CaptureSavedFields(9));
        await j.idle();
        expect(await db.getSetting(_key), bad);
        expect(await db.getSetting(_qKey), isNull);
      });
    });

    test(
        'F-06 journal v3 while outcomes arrive: 0 writes, pendingLost grows, '
        'capture/alarm behaviour identical to a null observer', () async {
      Future<(List<String>, String)> run({required bool withJournal}) async {
        final InMemoryLocalDatabase evDb = InMemoryLocalDatabase();
        final SettingsCipher cipher = AesGcmSettingsCipher(
            InMemorySecretStore(),
            database: InMemoryLocalDatabase());
        final IntruderDefenseSettingsStore settings =
            IntruderDefenseSettingsStore(evDb, cipher);
        await settings.write(const IntruderDefenseSettings(
            evidenceEnabled: true, alarmEnabled: true, threshold: 1));
        final GatedEvidenceService platform = GatedEvidenceService()
          ..permission = CameraPermissionState.granted;
        final IntruderDefenseCoordinator c = IntruderDefenseCoordinator(
            settings: settings,
            evidence: IntruderEvidenceStore(evDb, cipher),
            service: platform);
        SecurityEventJournal? j;
        if (withJournal) {
          await db.setSetting(
              _key,
              jsonEncode(<String, Object?>{
                'schema': SecurityJournalDocument.schema,
                'v': 3,
                'nextSeq': 0,
                'events': <Object?>[],
              }));
          db.writes = 0;
          j = journal();
          c.outcomeObserver = IntruderOutcomeJournalAdapter(j);
        }
        for (int i = 1; i <= 3; i++) {
          c.onFailedAttemptRecorded(challengeEvent(i, i));
          await c.idle();
        }
        c.onOwnerVerified();
        await c.idle();
        await pumpMicrotasks();
        if (j != null) {
          await j.idle();
          expect(db.writes, 0);
          expect(j.pendingLost, greaterThan(0));
        }
        return (platform.ops, statusSignature(c.status));
      }

      final (List<String>, String) base = await run(withJournal: false);
      final (List<String>, String) v3 = await run(withJournal: true);
      expect(v3.$1, base.$1);
      expect(v3.$2, base.$2);
    });
  });
}
