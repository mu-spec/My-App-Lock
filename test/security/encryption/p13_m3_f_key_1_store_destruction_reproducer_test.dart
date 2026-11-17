// P13/M3 F-KEY-1 — NEW findings F-KEY-1f / F-KEY-1g (OPEN). Host,
// SIMULATED: in-memory DB + in-memory secret store; not Android, not device
// QA. These tests assert the CURRENT UNSAFE behaviour and must FLIP (never be
// deleted) once the repair is approved and implemented.
//
// Every encrypted store maps "the cipher could not decrypt" (wrong key, or
// the key read THROWING) to CORRUPT, not to "unreadable". The corrupt paths
// were designed for genuinely damaged bytes; under F-KEY-1 the bytes are
// intact and would decrypt once the right key is back.
//
//  F-KEY-1f: evidence index corrupt -> quarantine (only if the slot is
//            empty) + index REMOVED + health reported OK/empty; the startup
//            sweep (AppContainer L174, unawaited) then deletes EVERY evidence
//            blob as an orphan. A transient key failure at startup destroys
//            all evidence photos permanently.
//  F-KEY-1g: failure log / journal corrupt -> quarantine is insert-if-absent;
//            when a quarantine already exists the intact ciphertext is
//            OVERWRITTEN by a fresh document (nothing preserves it).
//
// The key is pre-initialized here ON PURPOSE (process 1 wrote data); the
// first-launch race itself is reproduced in
// p13_m3_f_key_1_open_reproducer_test.dart (FK-R1..R4).
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
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

void main() {
  for (final bool throws in <bool>[true, false]) {
    final String mode = throws ? 'key read throws' : 'wrong key';
    test(
        'FK-S1 OPEN F-KEY-1f ($mode): startup maintenance deletes the '
        'evidence index and EVERY evidence blob; unrecoverable even after '
        'the right key is back', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final InMemorySecretStore secrets = InMemorySecretStore();
      final IntruderEvidenceStore p1 =
          IntruderEvidenceStore(db, AesGcmSettingsCipher(secrets));
      final Uint8List jpeg = jpegWithMetadata();
      expect(await p1.save(seq: 1, jpeg: jpeg), EvidenceSaveResult.saved);
      expect(await p1.save(seq: 2, jpeg: jpeg), EvidenceSaveResult.saved);
      final Map<String, String> blobsBefore = _blobs(await db.getAllSettings());
      expect(blobsBefore, hasLength(2));
      final String indexBefore =
          (await db.getSetting(IntruderEvidenceStore.indexKey))!;

      // Process 2: master key unavailable / wrong at startup.
      final _KeyFault fault = _KeyFault(secrets, throws: throws);
      final IntruderEvidenceStore p2 =
          IntruderEvidenceStore(db, AesGcmSettingsCipher(fault));
      await p2.startupMaintenance();

      // CURRENT UNSAFE behaviour (must flip after the repair):
      expect(await db.getSetting(IntruderEvidenceStore.indexKey), isNull,
          reason: 'index removed');
      expect(_blobs(await db.getAllSettings()), isEmpty,
          reason: 'every evidence blob swept as an orphan');
      expect(
          await db.getSetting(IntruderEvidenceStore.quarantineKey), indexBefore,
          reason: 'only the index bytes survive (slot was empty)');
      expect(fault.keyWrites, 0);

      // The right key is back: the photos are gone for good.
      final IntruderEvidenceStore p3 =
          IntruderEvidenceStore(db, AesGcmSettingsCipher(secrets));
      expect(await p3.list(), isEmpty);
      expect(await p3.readImage(1), isNull);
      expect(await p3.readImage(2), isNull);
    });
  }

  test(
      'FK-S2 OPEN F-KEY-1g (wrong key): with a quarantine already present, '
      'the intact failure-log ciphertext is overwritten', () async {
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    final InMemorySecretStore secrets = InMemorySecretStore();
    final IntruderMonitor m1 = IntruderMonitor(
        store:
            IntruderFailureLogStore(db, cipher: AesGcmSettingsCipher(secrets)));
    m1.onVerifiedAttempt(_fail('a'));
    m1.onVerifiedAttempt(_fail('b'));
    await m1.idle();
    final String good =
        (await db.getSetting(IntruderFailureLogStore.storageKey))!;
    await db.setSetting(IntruderFailureLogStore.quarantineKey, 'earlier');

    final IntruderMonitor m2 = IntruderMonitor(
        store: IntruderFailureLogStore(db,
            cipher: AesGcmSettingsCipher(_KeyFault(secrets))));
    m2.onVerifiedAttempt(_fail('c'));
    await m2.idle();

    expect(
        await db.getSetting(IntruderFailureLogStore.quarantineKey), 'earlier',
        reason: 'insert-if-absent: the good bytes were NOT kept');
    final String now =
        (await db.getSetting(IntruderFailureLogStore.storageKey))!;
    expect(now, isNot(good), reason: 'intact ciphertext overwritten');
    final Map<String, String> all = await db.getAllSettings();
    expect(all.values.where((String v) => v == good), isEmpty,
        reason: 'the original bytes exist nowhere any more');
    // Right key back: events a/b are lost.
    final IntruderLogRead r =
        await IntruderFailureLogStore(db, cipher: AesGcmSettingsCipher(secrets))
            .read();
    expect(r, isA<IntruderLogCorrupt>(),
        reason: 'the replacement is under the wrong key; a/b unrecoverable');
  });

  test(
      'FK-S3 OPEN F-KEY-1g (wrong key): with a quarantine already present, '
      'journal startup overwrites the intact journal ciphertext', () async {
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    final InMemorySecretStore secrets = InMemorySecretStore();
    final SecurityEventJournal j1 = SecurityEventJournal(
        store: SecurityEventJournalStore(db,
            cipher: AesGcmSettingsCipher(secrets)));
    j1.record(SecurityJournalEventType.protectionHealth);
    await j1.idle();
    final String good =
        (await db.getSetting(SecurityEventJournalStore.storageKey))!;
    await db.setSetting(SecurityEventJournalStore.quarantineKey, 'earlier');

    final SecurityEventJournal j2 = SecurityEventJournal(
        store: SecurityEventJournalStore(db,
            cipher: AesGcmSettingsCipher(_KeyFault(secrets))));
    await j2.startup();
    j2.record(SecurityJournalEventType.protectionHealth);
    await j2.idle();

    expect(await db.getSetting(SecurityEventJournalStore.quarantineKey),
        'earlier');
    final Map<String, String> all = await db.getAllSettings();
    expect(all.values.where((String v) => v == good), isEmpty,
        reason: 'intact journal ciphertext overwritten, preserved nowhere');
  });

  test(
      'FK-S4 control (key read throws): failure log and journal are NOT '
      'overwritten (re-encryption also fails); evidence is (FK-S1)', () async {
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    final InMemorySecretStore secrets = InMemorySecretStore();
    final IntruderMonitor m1 = IntruderMonitor(
        store:
            IntruderFailureLogStore(db, cipher: AesGcmSettingsCipher(secrets)));
    m1.onVerifiedAttempt(_fail('a'));
    await m1.idle();
    final String good =
        (await db.getSetting(IntruderFailureLogStore.storageKey))!;
    final IntruderMonitor m2 = IntruderMonitor(
        store: IntruderFailureLogStore(db,
            cipher: AesGcmSettingsCipher(_KeyFault(secrets, throws: true))));
    m2.onVerifiedAttempt(_fail('b'));
    await m2.idle();
    expect(await db.getSetting(IntruderFailureLogStore.storageKey), good);
    // Misclassification (documented): the transient key failure was
    // reported as CORRUPT and the intact bytes were quarantined.
    expect(await db.getSetting(IntruderFailureLogStore.quarantineKey), good);
  });
}
