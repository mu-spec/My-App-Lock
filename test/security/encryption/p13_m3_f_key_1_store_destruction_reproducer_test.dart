// P13/M3 F-KEY-1f / F-KEY-1g — FLIPPED by Stage A (owner decisions G-3,
// G-4). Host, SIMULATED (in-memory DB + secret store; not Android).
//
// The ORIGINAL reproducers (asserting the destructive behaviour at
// 2735356 + P1) are preserved unchanged as historical evidence in
// Phase13/m3_implementation/E_feature_resumption/F_KEY_1/tests/ with their
// run log. Here the same IDs assert the repaired, preserving behaviour:
//  FK-S1  evidence: an undecryptable index (wrong key / key read throws) is
//         UNREADABLE: index + every blob byte-identical, no quarantine write,
//         no sweep; the right key recovers every photo.
//  FK-S2  failure log: occupied quarantine -> overwrite REFUSED; both rows
//         byte-identical; the record is a counted drop, never notified.
//  FK-S3  journal: occupied quarantine -> overwrite REFUSED.
//  FK-S4  control (key read throws): log not overwritten (unchanged).
//  FK-S5/S6  G-4 interrupted repair: a quarantine that already holds the
//         EXACT bytes allows the repair; a quarantine read failure refuses.
//
// F-KEY-1 key race / mint on absent key: repaired on host in Batch 2 (see
// FK-R* flips and p13_m3_b2_master_key_resolver_test.dart); device QA
// pending.
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';

import '../../support/intruder_fixtures.dart';

const String _mk = SecretKeys.settingsMasterKey;

/// Batch 2: the faulty "process-2" cipher gets its OWN commitment database,
/// so the store still receives exactly what it received before the master
/// key repair (a real AES-GCM authentication failure for "wrong key", a
/// key-read error for "throws"). With a SHARED commitment the resolver
/// refuses even earlier (KeyMismatch / storageError): see FK-S8.
InMemoryLocalDatabase _foreignDb() => InMemoryLocalDatabase();
const String _wrongKey = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=';

/// Process-2 view of the persisted secret store with one key fault.
class _KeyFault implements SecretStore {
  _KeyFault(this.inner, {this.throws = false});
  final InMemorySecretStore inner;
  final bool throws;
  int keyWrites = 0;

  @override
  Future<String?> read(String key) async {
    if (key == _mk) {
      if (throws) throw StateError('keystore unavailable');
      return _wrongKey;
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) async {
    if (key == _mk) keyWrites++;
    // Never let the fault layer replace the real key.
  }

  @override
  Future<void> delete(String key) async {}
  @override
  Future<void> clear() async {}
  @override
  Future<bool> containsKey(String key) => inner.containsKey(key);
}

/// Phase 18 / M1F (F18-9): every monitor in this file runs on this fixed
/// clock, a few minutes after [_fail]'s verdict time. The monitor's default
/// clock is the REAL clock, and its 30-day age retention then pruned the
/// fixed-date records once the real date passed 2026-11-21 12:00 (time
/// bomb). Production retention is unchanged.
DateTime _fixedNow() => DateTime(2026, 10, 22, 12, 5);

VerifiedAttempt _fail(String vid) => VerifiedAttempt(
      verificationId: vid,
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
        reason: AuthFailureReason.wrongCredential,
        remainingAttempts: 2,
      ),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: DateTime(2026, 10, 22, 12),
    );

Map<String, String> _blobs(Map<String, String> all) => <String, String>{
      for (final MapEntry<String, String> e in all.entries)
        if (e.key.startsWith(IntruderEvidenceStore.blobPrefix)) e.key: e.value,
    };

class _RecordingListener implements IntruderEventListener {
  final List<String> vids = <String>[];
  @override
  void onFailedAttemptRecorded(FailedAttemptEvent event) =>
      vids.add(event.verificationId);
  @override
  void onOwnerVerified() {}
}

/// Quarantine reads throw (G-4: refuse when preservation can't be proven).
class _QuarantineReadFaultDb extends InMemoryLocalDatabase {
  @override
  Future<String?> getSetting(String key) async {
    if (key == IntruderFailureLogStore.quarantineKey ||
        key == SecurityEventJournalStore.quarantineKey) {
      throw StateError('quarantine read fault');
    }
    return super.getSetting(key);
  }
}

Future<(InMemoryLocalDatabase, InMemorySecretStore, String)> _seedLog(
    [InMemoryLocalDatabase? database]) async {
  final InMemoryLocalDatabase db = database ?? InMemoryLocalDatabase();
  final InMemorySecretStore secrets = InMemorySecretStore();
  final IntruderMonitor m1 = IntruderMonitor(
      now: _fixedNow,
      store:
          IntruderFailureLogStore(db, cipher: AesGcmSettingsCipher(secrets, database: db)));
  m1.onVerifiedAttempt(_fail('a'));
  m1.onVerifiedAttempt(_fail('b'));
  await m1.idle();
  return (db, secrets, (await db.getSetting(IntruderFailureLogStore.storageKey))!);
}

void main() {
  for (final bool throws in <bool>[true, false]) {
    final String mode = throws ? 'key read throws' : 'wrong key';
    test('FK-S1 FLIPPED F-KEY-1f ($mode): startup maintenance keeps the '
        'evidence index and every blob byte-identical; the right key '
        'recovers all evidence', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final InMemorySecretStore secrets = InMemorySecretStore();
      final IntruderEvidenceStore p1 =
          IntruderEvidenceStore(db, AesGcmSettingsCipher(secrets, database: db));
      final Uint8List jpeg = jpegWithMetadata();
      expect(await p1.save(seq: 1, jpeg: jpeg), EvidenceSaveResult.saved);
      expect(await p1.save(seq: 2, jpeg: jpeg), EvidenceSaveResult.saved);
      final Map<String, String> blobsBefore = _blobs(await db.getAllSettings());
      expect(blobsBefore, hasLength(2));
      final String indexBefore =
          (await db.getSetting(IntruderEvidenceStore.indexKey))!;

      final _KeyFault fault = _KeyFault(secrets, throws: throws);
      final IntruderEvidenceStore p2 =
          IntruderEvidenceStore(db, AesGcmSettingsCipher(fault, database: _foreignDb()));
      await p2.startupMaintenance();
      expect(await p2.health(), EvidenceIndexHealth.unreadable);
      expect(await p2.list(), isEmpty, reason: 'unreadable, never trusted');
      expect(await p2.sweepOrphans(), 0);
      expect(await p2.enforceRetention(), 0);
      expect(await p2.save(seq: 3, jpeg: jpeg),
          EvidenceSaveResult.storageFailed);
      expect(await p2.delete(1), EvidenceDeleteResult.storageFailed);

      expect(await db.getSetting(IntruderEvidenceStore.indexKey), indexBefore);
      expect(_blobs(await db.getAllSettings()), blobsBefore);
      expect(await db.getSetting(IntruderEvidenceStore.quarantineKey), isNull);
      expect(fault.keyWrites, 0);

      final IntruderEvidenceStore p3 =
          IntruderEvidenceStore(db, AesGcmSettingsCipher(secrets, database: db));
      expect((await p3.list()).map((EvidenceItem e) => e.seq), <int>[1, 2]);
      expect(await p3.readImage(1), isNotNull);
      expect(await p3.readImage(2), isNotNull);
    });
  }

  test('FK-S2 FLIPPED F-KEY-1g (wrong key): occupied quarantine -> the '
      'failure-log overwrite is refused; nothing claimed persisted', () async {
    final (InMemoryLocalDatabase db, InMemorySecretStore secrets, String good) =
        await _seedLog();
    await db.setSetting(IntruderFailureLogStore.quarantineKey, 'earlier');

    final _RecordingListener l = _RecordingListener();
    final IntruderMonitor m2 = IntruderMonitor(
        now: _fixedNow,
        store: IntruderFailureLogStore(db,
            cipher: AesGcmSettingsCipher(_KeyFault(secrets), database: _foreignDb())))
      ..listener = l;
    m2.onVerifiedAttempt(_fail('c'));
    await m2.idle();

    expect(await db.getSetting(IntruderFailureLogStore.storageKey), good);
    expect(
        await db.getSetting(IntruderFailureLogStore.quarantineKey), 'earlier');
    expect(l.vids, isEmpty, reason: 'never notified');
    expect(m2.status.droppedFailureRecords, 1);
    // Batch 1: an undecryptable log is UNREADABLE (never corrupt), so the
    // corrupt/quarantine path is not even reached.
    expect(m2.status.corruptUnpreserved, 0);
    expect(m2.status.health, IntruderMonitorHealth.storageError);
    expect(await m2.snapshot(), isNull, reason: 'unavailable, not empty');
    final IntruderLogRead r = await IntruderFailureLogStore(db,
            cipher: AesGcmSettingsCipher(secrets, database: db))
        .read();
    expect((r as IntruderLogLoaded).log.events.map((e) => e.verificationId),
        <String>['a', 'b'], reason: 'right key recovers the history');
  });

  test('FK-S3 FLIPPED F-KEY-1g (wrong key): occupied quarantine -> the '
      'journal overwrite is refused', () async {
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    final InMemorySecretStore secrets = InMemorySecretStore();
    final SecurityEventJournal j1 = SecurityEventJournal(
        store: SecurityEventJournalStore(db,
            cipher: AesGcmSettingsCipher(secrets, database: db)));
    j1.record(SecurityJournalEventType.journalRecovered);
    await j1.idle();
    final String good =
        (await db.getSetting(SecurityEventJournalStore.storageKey))!;
    await db.setSetting(SecurityEventJournalStore.quarantineKey, 'earlier');

    final SecurityEventJournal j2 = SecurityEventJournal(
        store: SecurityEventJournalStore(db,
            cipher: AesGcmSettingsCipher(_KeyFault(secrets), database: _foreignDb())));
    await j2.startup();
    j2.record(SecurityJournalEventType.journalRecovered);
    await j2.idle();

    expect(await db.getSetting(SecurityEventJournalStore.storageKey), good);
    expect(await db.getSetting(SecurityEventJournalStore.quarantineKey),
        'earlier');
    expect(j2.corruptUnpreserved, 0, reason: 'unreadable, never corrupt');
    expect(j2.health, SecurityJournalHealth.storageError);
    expect(j2.quarantinedCorruptJournal, isFalse);
  });

  // R9 FLIPPED (Batch 1). The ORIGINAL FK-S4 asserted that the intact bytes
  // were quarantined as corrupt; it is preserved verbatim in the sealed
  // Phase13/.../F_KEY_1/tests/ copy as historical evidence.
  test('FK-S4 FLIPPED R9 (key read throws): the failure log is NOT '
      'overwritten and the intact bytes are NOT quarantined', () async {
    final (InMemoryLocalDatabase db, InMemorySecretStore secrets, String good) =
        await _seedLog();
    final IntruderMonitor m2 = IntruderMonitor(
        now: _fixedNow,
        store: IntruderFailureLogStore(db,
            cipher: AesGcmSettingsCipher(_KeyFault(secrets, throws: true), database: _foreignDb())));
    m2.onVerifiedAttempt(_fail('c'));
    await m2.idle();
    expect(await db.getSetting(IntruderFailureLogStore.storageKey), good);
    expect(await db.getSetting(IntruderFailureLogStore.quarantineKey), isNull);
    expect(m2.status.health, IntruderMonitorHealth.storageError);
  });

  for (final bool throws in <bool>[true, false]) {
    final String mode = throws ? 'key read throws' : 'wrong key';
    test('FK-S7 Batch 1 empty-quarantine fix ($mode): with an EMPTY '
        'quarantine slot the log and journal are neither quarantined nor '
        'replaced; the right key recovers both', () async {
      final (InMemoryLocalDatabase db, InMemorySecretStore secrets, String good) =
          await _seedLog();
      final SecurityEventJournal j1 = SecurityEventJournal(
          store: SecurityEventJournalStore(db,
              cipher: AesGcmSettingsCipher(secrets, database: db)));
      j1.record(SecurityJournalEventType.journalRecovered);
      await j1.idle();
      final String goodJ =
          (await db.getSetting(SecurityEventJournalStore.storageKey))!;
      expect(await db.getSetting(IntruderFailureLogStore.quarantineKey), isNull);
      expect(
          await db.getSetting(SecurityEventJournalStore.quarantineKey), isNull);

      final _KeyFault fault = _KeyFault(secrets, throws: throws);
      final _RecordingListener l = _RecordingListener();
      final IntruderMonitor m2 = IntruderMonitor(
          now: _fixedNow,
          store: IntruderFailureLogStore(db,
              cipher: AesGcmSettingsCipher(fault, database: _foreignDb())))
        ..listener = l;
      m2.onVerifiedAttempt(_fail('c'));
      await m2.idle();
      final SecurityEventJournal j2 = SecurityEventJournal(
          store: SecurityEventJournalStore(db,
              cipher: AesGcmSettingsCipher(fault, database: _foreignDb())));
      await j2.startup();
      j2.record(SecurityJournalEventType.journalRecovered);
      await j2.idle();

      expect(await db.getSetting(IntruderFailureLogStore.storageKey), good);
      expect(await db.getSetting(IntruderFailureLogStore.quarantineKey), isNull);
      expect(await db.getSetting(SecurityEventJournalStore.storageKey), goodJ);
      expect(
          await db.getSetting(SecurityEventJournalStore.quarantineKey), isNull);
      expect(fault.keyWrites, 0);
      expect(l.vids, isEmpty, reason: 'nothing claimed persisted');
      expect(m2.status.droppedFailureRecords, 1);
      expect(m2.status.corruptUnpreserved, 0);
      expect(m2.status.health, IntruderMonitorHealth.storageError);
      expect(await m2.snapshot(), isNull, reason: 'unavailable, not empty');
      expect(j2.health, SecurityJournalHealth.storageError);
      expect(j2.quarantinedCorruptJournal, isFalse);

      // The right key recovers both histories, byte-for-byte.
      final IntruderLogRead r = await IntruderFailureLogStore(db,
              cipher: AesGcmSettingsCipher(secrets, database: db))
          .read();
      expect((r as IntruderLogLoaded).log.events.map((e) => e.verificationId),
          <String>['a', 'b']);
      expect(
          await SecurityEventJournalStore(db,
                  cipher: AesGcmSettingsCipher(secrets, database: db))
              .read(),
          isA<SecurityJournalLoaded>());
    });
  }

  test('FK-S5 G-4 interrupted repair: a quarantine already holding the EXACT '
      'bytes lets the log and journal repair proceed (bytes preserved)',
      () async {
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    await db.setSetting(IntruderFailureLogStore.storageKey, 'damaged-log');
    await db.setSetting(IntruderFailureLogStore.quarantineKey, 'damaged-log');
    final IntruderMonitor m = IntruderMonitor(now: _fixedNow, store: IntruderFailureLogStore(db));
    m.onVerifiedAttempt(_fail('x'));
    await m.idle();
    expect(m.status.corruptUnpreserved, 0);
    expect(m.status.droppedFailureRecords, 0);
    expect(await db.getSetting(IntruderFailureLogStore.quarantineKey),
        'damaged-log');
    expect(await db.getSetting(IntruderFailureLogStore.storageKey),
        isNot('damaged-log'));

    await db.setSetting(SecurityEventJournalStore.storageKey, 'damaged-j');
    await db.setSetting(SecurityEventJournalStore.quarantineKey, 'damaged-j');
    final SecurityEventJournal j =
        SecurityEventJournal(store: SecurityEventJournalStore(db));
    j.record(SecurityJournalEventType.journalRecovered);
    await j.idle();
    expect(j.corruptUnpreserved, 0);
    expect(j.health, SecurityJournalHealth.ok);
    expect(await db.getSetting(SecurityEventJournalStore.quarantineKey),
        'damaged-j');
    expect(await db.getSetting(SecurityEventJournalStore.storageKey),
        isNot('damaged-j'));
  });

  test('FK-S6 G-4 quarantine read failure (slot occupied) refuses the '
      'overwrite for log and journal', () async {
    final _QuarantineReadFaultDb db = _QuarantineReadFaultDb();
    await db.setSetting(IntruderFailureLogStore.storageKey, 'damaged-log');
    await db.setSetting(IntruderFailureLogStore.quarantineKey, 'other');
    final IntruderMonitor m = IntruderMonitor(now: _fixedNow, store: IntruderFailureLogStore(db));
    m.onVerifiedAttempt(_fail('x'));
    await m.idle();
    expect(m.status.corruptUnpreserved, 1);
    expect((await db.getAllSettings())[IntruderFailureLogStore.storageKey],
        'damaged-log');
    // Health must report the refusal (never a neutral/ok state) and the
    // record is a counted drop, never claimed persisted.
    expect(m.status.health, IntruderMonitorHealth.storageError);
    expect(m.status.droppedFailureRecords, 1);
    expect(await m.snapshot(), isNull, reason: 'unavailable, not empty');

    await db.setSetting(SecurityEventJournalStore.storageKey, 'damaged-j');
    final SecurityEventJournal j =
        SecurityEventJournal(store: SecurityEventJournalStore(db));
    j.record(SecurityJournalEventType.journalRecovered);
    await j.idle();
    expect(j.corruptUnpreserved, 1);
    expect((await db.getAllSettings())[SecurityEventJournalStore.storageKey],
        'damaged-j');
    expect(j.health, SecurityJournalHealth.storageError);
  });

  // Batch 2: the same faults with the SHARED key commitment. The resolver
  // refuses before any decrypt (wrong key = KeyMismatch, read throws =
  // storageError); every store still preserves every byte, writes no key,
  // and the right key recovers everything.
  for (final bool throws in <bool>[true, false]) {
    final String mode = throws ? 'key read throws' : 'wrong key';
    test('FK-S8 Batch 2 shared commitment ($mode): evidence, log and journal '
        'are preserved; no key is written; the right key recovers', () async {
      final (InMemoryLocalDatabase db, InMemorySecretStore secrets, String good) =
          await _seedLog();
      final IntruderEvidenceStore e1 =
          IntruderEvidenceStore(db, AesGcmSettingsCipher(secrets, database: db));
      expect(await e1.save(seq: 1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      final SecurityEventJournal j1 = SecurityEventJournal(
          store: SecurityEventJournalStore(db,
              cipher: AesGcmSettingsCipher(secrets, database: db)));
      j1.record(SecurityJournalEventType.journalRecovered);
      await j1.idle();
      final Map<String, String> before =
          Map<String, String>.of(await db.getAllSettings());

      final _KeyFault fault = _KeyFault(secrets, throws: throws);
      final AesGcmSettingsCipher fc =
          AesGcmSettingsCipher(fault, database: db);
      final IntruderMonitor m2 =
          IntruderMonitor(now: _fixedNow, store: IntruderFailureLogStore(db, cipher: fc));
      m2.onVerifiedAttempt(_fail('c'));
      await m2.idle();
      final IntruderEvidenceStore e2 = IntruderEvidenceStore(db, fc);
      await e2.startupMaintenance();
      expect(await e2.health(), EvidenceIndexHealth.unreadable);
      expect(await e2.sweepOrphans(), 0);
      final SecurityEventJournal j2 = SecurityEventJournal(
          store: SecurityEventJournalStore(db, cipher: fc));
      await j2.startup();
      j2.record(SecurityJournalEventType.journalRecovered);
      await j2.idle();

      expect(await db.getAllSettings(), before, reason: 'nothing changed');
      expect(fault.keyWrites, 0);
      expect(m2.status.health, IntruderMonitorHealth.storageError);
      expect(j2.health, SecurityJournalHealth.storageError);
      expect(await db.getSetting(IntruderFailureLogStore.storageKey), good);

      final AesGcmSettingsCipher ok = AesGcmSettingsCipher(secrets, database: db);
      final IntruderLogRead r =
          await IntruderFailureLogStore(db, cipher: ok).read();
      expect((r as IntruderLogLoaded).log.events.map((e) => e.verificationId),
          <String>['a', 'b']);
      expect((await IntruderEvidenceStore(db, ok).list()).single.seq, 1);
    });
  }
}
