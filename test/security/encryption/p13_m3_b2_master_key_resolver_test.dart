// P13/M3 Batch 2 — F-KEY-1 master-key repair (K-2+B-compat).
//
// SIMULATED: host VM, in-memory database, in-memory secret store and an
// in-memory KEK double (InMemoryKeyWrapper). NOT Android: AndroidKeyStore,
// flutter_secure_storage persistence, process death and real isolates are
// DEVICE BLOCKED here. FIRST-LAUNCH tests unless a test says otherwise; no
// test pre-initializes the key to hide the race.
//
//  KB-*  one test per Stage B transition T1..T12 (+ decrypt-never-mints).
//  KC-*  crash / interrupted-init recovery (fault-injecting stores).
//  CC-*  concurrency: many resolver/cipher instances, one DB + secret store.
//  KD-*  downgrade: the VERBATIM pre-Batch-2 cipher (test/support fixture)
//        against data written by the repaired build, and re-upgrade.
//  CF-*  credential fail-closed through AppContainer for every non-Ready
//        outcome.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/encryption/key_wrapper.dart';
import 'package:smart_app_lock/security/encryption/master_key_resolver.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_settings.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';

import '../../support/legacy_settings_cipher_ac894ec.dart';

const String _mk = SecretKeys.settingsMasterKey;
const String _commit = MasterKeyResolver.commitKey;
const String _pin = '482915';

/// Yields on every call (as the platform channel does) and injects faults.
class _Secrets implements SecretStore {
  final InMemorySecretStore inner = InMemorySecretStore();
  int keyWrites = 0;
  bool readThrows = false;
  bool writeThrows = false; // "crash" before the write lands
  bool dropWrites = false; // write acknowledged but never persisted
  int nullReads = 0;
  String? overrideRead; // e.g. "Data has been reset"

  @override
  Future<String?> read(String key) async {
    await Future<void>.delayed(Duration.zero);
    if (key == _mk) {
      if (readThrows) throw StateError('keystore unavailable');
      if (nullReads > 0) {
        nullReads--;
        return null;
      }
      if (overrideRead != null) return overrideRead;
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) async {
    await Future<void>.delayed(Duration.zero);
    if (key == _mk) {
      if (writeThrows) throw StateError('process died');
      keyWrites++;
      if (dropWrites) return;
    }
    return inner.write(key, value);
  }

  @override
  Future<void> delete(String key) async => throw StateError('never deletes');
  @override
  Future<void> clear() async => throw StateError('never clears');
  @override
  Future<bool> containsKey(String key) => inner.containsKey(key);
}

/// Database whose reads can fail; CAS can report an unknown outcome AFTER
/// committing (SQLITE_BUSY on commit acknowledgement).
class _Db extends InMemoryLocalDatabase {
  bool readsThrow = false;
  int casUnknownAfterCommit = 0;
  int casCalls = 0;

  @override
  Future<String?> getSetting(String key) async {
    await Future<void>.delayed(Duration.zero);
    if (readsThrow) throw StateError('db unreadable');
    return super.getSetting(key);
  }

  @override
  Future<Map<String, String>> getAllSettings() async {
    await Future<void>.delayed(Duration.zero);
    if (readsThrow) throw StateError('db unreadable');
    return super.getAllSettings();
  }

  @override
  Future<CasOutcome> compareAndSetSetting(String key,
      {required String? expected, required String next}) async {
    casCalls++;
    await Future<void>.delayed(Duration.zero);
    final CasOutcome o =
        await super.compareAndSetSetting(key, expected: expected, next: next);
    if (casUnknownAfterCommit > 0 && o == CasOutcome.committed) {
      casUnknownAfterCommit--;
      throw const CasUnknownOutcome(CasUnknownCode.busy);
    }
    return o;
  }
}

MasterKeyResolver _resolver(SecretStore s, LocalDatabase db,
        {KeyWrapper wrapper = const NoKeyWrapper(), List<Duration>? waits}) =>
    MasterKeyResolver(
      secrets: s,
      database: db,
      wrapper: wrapper,
      pendingPollInterval: const Duration(milliseconds: 5),
      delay: waits == null
          ? null
          : (Duration d) async {
              waits.add(d);
              await Future<void>.delayed(Duration.zero);
            },
    );

AesGcmSettingsCipher _cipher(SecretStore s, LocalDatabase db,
        {KeyWrapper wrapper = const NoKeyWrapper()}) =>
    AesGcmSettingsCipher.withResolver(_resolver(s, db, wrapper: wrapper));

Map<String, Object?> _row(String? raw) =>
    (jsonDecode(raw!) as Map<Object?, Object?>).cast<String, Object?>();

Uint8List _key(int b) => Uint8List.fromList(List<int>.filled(32, b));

Future<String> _kid(int b) => MasterKeyResolver.kidOf(_key(b));

Future<String> _pendingRow(int b, {WrappedKey? w}) async =>
    jsonEncode(<String, Object?>{
      'v': 1,
      'state': 'pending',
      'kid': await _kid(b),
      if (w != null) 'alias': w.alias,
      if (w != null) 'wrapped': w.blob,
      'at': 1,
    });

Future<String> _activeRow(int b, {WrappedKey? w}) async =>
    (await _pendingRow(b, w: w)).replaceFirst('"pending"', '"active"');

T _unavailable<T extends Object>(MasterKeyState s, MasterKeyIssue issue) {
  expect(s, isA<MasterKeyUnavailable>());
  expect((s as MasterKeyUnavailable).issue, issue);
  return s as T;
}

void main() {
  group('KB transitions (Stage B T1..T12)', () {
    test(
        'KB-01 T1 adopts an existing legacy key: no key write, ciphertext '
        'written by the OLD build still decrypts', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String oldCt =
          await LegacyAesGcmSettingsCipherAc894ec(s).encryptString('old');
      await db.setSetting('security_settings', 'enc:v1:$oldCt');
      final String legacy = (await s.inner.read(_mk))!;
      s.keyWrites = 0;
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final AesGcmSettingsCipher c = _cipher(s, db, wrapper: w);
      expect(await c.decryptString(oldCt), 'old');
      expect(s.keyWrites, 0);
      expect(await s.inner.read(_mk), legacy);
      final Map<String, Object?> row = _row(await db.getSetting(_commit));
      expect(row['state'], 'active');
      expect(row['kid'], await MasterKeyResolver.kidOf(base64Decode(legacy)));
      expect(row['alias'], isA<String>(), reason: 'verified wrapped copy');
    });

    test('KB-02 T2 genesis: commit first, exactly one key write, active',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final MasterKeyResolver r =
          _resolver(s, db, wrapper: InMemoryKeyWrapper());
      final MasterKeyState st = await r.resolve();
      expect(st, isA<MasterKeyReady>());
      expect(s.keyWrites, 1);
      expect(r.legacyWrites, 1);
      final Map<String, Object?> row = _row(await db.getSetting(_commit));
      expect(row['state'], 'active');
      expect(
          row['kid'],
          await MasterKeyResolver.kidOf(
              base64Decode((await s.inner.read(_mk))!)));
    });

    test('KB-03 T3 encrypted data with no key anywhere: KeyLost, never mints',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await db.setSetting('intruder_failure_log', 'enc:v1:AAAA');
      final MasterKeyResolver r =
          _resolver(s, db, wrapper: InMemoryKeyWrapper());
      _unavailable<MasterKeyUnavailable>(
          await r.resolve(), MasterKeyIssue.keyLost);
      expect(s.keyWrites, 0);
      expect(await s.inner.read(_mk), isNull);
      expect(await db.getSetting(_commit), isNull);
    });

    test(
        'KB-04 T4 legacy slot holds garbage ("Data has been reset"): never '
        'overwritten, never minted', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await s.inner.write(_mk, 'Data has been reset');
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db).resolve(), MasterKeyIssue.legacyKeyInvalid);
      expect(await s.inner.read(_mk), 'Data has been reset');
      expect(s.keyWrites, 0);
      expect(await db.getSetting(_commit), isNull);
    });

    test('KB-05a T5 pending{k} with L=k activates the same key', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await s.inner.write(_mk, base64Encode(_key(3)));
      await db.setSetting(_commit, await _pendingRow(3));
      final MasterKeyState st = await _resolver(s, db).resolve();
      expect((st as MasterKeyReady).kid, await _kid(3));
      expect(_row(await db.getSetting(_commit))['state'], 'active');
      expect(s.keyWrites, 0);
    });

    test(
        'KB-05b T5 pending{k} with a different valid L: L wins (pending '
        'never encrypted); L untouched', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await s.inner.write(_mk, base64Encode(_key(4)));
      await db.setSetting(_commit, await _pendingRow(3));
      final MasterKeyState st = await _resolver(s, db).resolve();
      expect((st as MasterKeyReady).kid, await _kid(4));
      expect(await s.inner.read(_mk), base64Encode(_key(4)));
      expect(s.keyWrites, 0);
    });

    test(
        'KB-05c T5 pending{k}, L absent, E false: completes the SAME key '
        'from the verified wrapped copy', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final WrappedKey wk = await w.wrapNew(_key(5));
      await db.setSetting(_commit, await _pendingRow(5, w: wk));
      final MasterKeyState st = await _resolver(s, db, wrapper: w).resolve();
      expect((st as MasterKeyReady).kid, await _kid(5));
      expect(await s.inner.read(_mk), base64Encode(_key(5)));
    });

    test('KB-05d T5 pending, L absent, E true: KeyLost; nothing written',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      await db.setSetting(
          _commit, await _pendingRow(5, w: await w.wrapNew(_key(5))));
      await db.setSetting('x', 'enc:v1:AAAA');
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db, wrapper: w).resolve(), MasterKeyIssue.keyLost);
      expect(s.keyWrites, 0);
    });

    test(
        'KB-05e T5 pending without a usable wrapped copy and L absent: '
        'bounded wait, then `initializing`; never mints (B2-PEND-1)', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String pending = await _pendingRow(6);
      await db.setSetting(_commit, pending);
      final List<Duration> waits = <Duration>[];
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db, waits: waits).resolve(),
          MasterKeyIssue.initializing);
      expect(waits, hasLength(10), reason: 'design §4: 10 x 100 ms bound');
      expect(s.keyWrites, 0);
      expect(await db.getSetting(_commit), pending);
    });

    test(
        'KB-06 T6 normal start: Ready, no writes; a missing wrapped copy is '
        'added only after unwrap verification', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await s.inner.write(_mk, base64Encode(_key(7)));
      await db.setSetting(_commit, await _activeRow(7));
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      expect(
          await _resolver(s, db, wrapper: w).resolve(), isA<MasterKeyReady>());
      expect(s.keyWrites, 0);
      expect(w.unwraps, 1, reason: 'verified before commit');
      expect(_row(await db.getSetting(_commit))['alias'], w.aliases.single);
    });

    test(
        'KB-07a T7 active, L absent: restore L from the verified wrapped '
        'copy', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      await db.setSetting(
          _commit, await _activeRow(8, w: await w.wrapNew(_key(8))));
      final MasterKeyState st = await _resolver(s, db, wrapper: w).resolve();
      expect((st as MasterKeyReady).readOnly, isFalse);
      expect(await s.inner.read(_mk), base64Encode(_key(8)));
      expect(s.keyWrites, 1);
    });

    test(
        'KB-07b T7 active, L garbage: the verified copy is used; the garbage '
        'is NOT overwritten (I4)', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      await s.inner.write(_mk, 'Data has been reset');
      await db.setSetting(
          _commit, await _activeRow(8, w: await w.wrapNew(_key(8))));
      expect(
          await _resolver(s, db, wrapper: w).resolve(), isA<MasterKeyReady>());
      expect(await s.inner.read(_mk), 'Data has been reset');
      expect(s.keyWrites, 0);
    });

    test(
        'KB-08 T8 active{k}, L holds another valid key: KeyMismatch; both '
        'keys and the row untouched (DB-3 ring NOT implemented)', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final String row = await _activeRow(9, w: await w.wrapNew(_key(9)));
      await db.setSetting(_commit, row);
      await s.inner.write(_mk, base64Encode(_key(10)));
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db, wrapper: w).resolve(),
          MasterKeyIssue.keyMismatch);
      expect(await s.inner.read(_mk), base64Encode(_key(10)));
      expect(await db.getSetting(_commit), row);
      expect(s.keyWrites, 0);
    });

    test(
        'KB-09 T9 active, L read error: Ready read-only from the wrapped '
        'copy; the cipher decrypts but refuses to encrypt', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final AesGcmSettingsCipher c1 = _cipher(s, db, wrapper: w);
      final String ct = await c1.encryptString('row');
      s.readThrows = true;
      final AesGcmSettingsCipher c2 = _cipher(s, db, wrapper: w);
      expect(await c2.decryptString(ct), 'row');
      await expectLater(
          c2.encryptString('x'), throwsA(isA<MasterKeyUnavailableException>()));
      expect(s.keyWrites, 1, reason: 'genesis only');
    });

    test(
        'KB-10 T10 both copies gone: KeyLost (KEK absent) / storageError '
        '(KEK error); nothing minted', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      await db.setSetting(
          _commit, await _activeRow(11, w: await w.wrapNew(_key(11))));
      w.failNext = const KeyWrapUnavailable('busy');
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db, wrapper: w).resolve(),
          MasterKeyIssue.storageError);
      w.loseAllKeks(); // backup/D2D restore (L5)
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db, wrapper: w).resolve(), MasterKeyIssue.keyLost);
      expect(s.keyWrites, 0);
      expect(await s.inner.read(_mk), isNull);
    });

    test('KB-11 T11 unsupported commitment (newer build): never rewritten',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      const String newer = '{"v":2,"state":"active","kid":"x"}';
      await db.setSetting(_commit, newer);
      await s.inner.write(_mk, base64Encode(_key(12)));
      _unavailable<MasterKeyUnavailable>(await _resolver(s, db).resolve(),
          MasterKeyIssue.unsupportedCommitment);
      expect(await db.getSetting(_commit), newer);
      expect(s.keyWrites, 0);
    });

    test('KB-12 T12 database unreadable: storageError, nothing written',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db()..readsThrow = true;
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db).resolve(), MasterKeyIssue.storageError);
      expect(s.keyWrites, 0);
      expect(db.casCalls, 0);
    });

    test('KB-13 a DECRYPT on a fresh store never creates a key', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await expectLater(
          _cipher(s, db).decryptString(base64Encode(List<int>.filled(40, 1))),
          throwsA(isA<MasterKeyUnavailableException>()));
      expect(s.keyWrites, 0);
      expect(await db.getSetting(_commit), isNull);
    });

    test(
        'KB-14 a wrapped copy that cannot be verified at activation is '
        'dropped (alias recorded in `retired`, never deleted)', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final WrappedKey wk = await w.wrapNew(_key(13));
      await s.inner.write(_mk, base64Encode(_key(13)));
      await db.setSetting(_commit, await _pendingRow(13, w: wk));
      w.failNext = const KeyWrapUnavailable('busy');
      expect(
          await _resolver(s, db, wrapper: w).resolve(), isA<MasterKeyReady>());
      final Map<String, Object?> row = _row(await db.getSetting(_commit));
      expect(row['state'], 'active');
      expect(row['retired'], <String>[wk.alias]);
      expect(w.aliases, contains(wk.alias), reason: 'KEK never deleted');
    });
  });

  test(
      'KB-15 a wrapped copy holding a DIFFERENT key (stale/forged) is never '
      'used and never restored into the legacy slot', () async {
    final _Secrets s = _Secrets();
    final _Db db = _Db();
    final InMemoryKeyWrapper w = InMemoryKeyWrapper();
    // Commitment says kid(14) but the wrapped blob holds key 15.
    await db.setSetting(
        _commit, await _activeRow(14, w: await w.wrapNew(_key(15))));
    _unavailable<MasterKeyUnavailable>(
        await _resolver(s, db, wrapper: w).resolve(),
        MasterKeyIssue.storageError);
    expect(await s.inner.read(_mk), isNull);
    expect(s.keyWrites, 0);
  });

  group('KC crash / interrupted-init recovery', () {
    test(
        'KC-01 death after CAS->pending, before the L write (wrapper '
        'present): the next start completes the SAME key', () async {
      final _Secrets s = _Secrets()..writeThrows = true;
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      _unavailable<MasterKeyUnavailable>(
          await _resolver(s, db, wrapper: w).resolve(),
          MasterKeyIssue.storageError);
      final Map<String, Object?> pending = _row(await db.getSetting(_commit));
      expect(pending['state'], 'pending');
      expect(await s.inner.read(_mk), isNull);
      s.writeThrows = false;
      final MasterKeyState st = await _resolver(s, db, wrapper: w).resolve();
      expect((st as MasterKeyReady).kid, pending['kid']);
      expect(s.keyWrites, 1);
    });

    test(
        'KC-02 same crash WITHOUT a wrapped copy: fail-closed '
        '`initializing`, no mint, no encryption (B2-PEND-1, disclosed)',
        () async {
      final _Secrets s = _Secrets()..writeThrows = true;
      final _Db db = _Db();
      await _resolver(s, db).resolve();
      s.writeThrows = false;
      final AesGcmSettingsCipher c = _cipher(s, db);
      await expectLater(
          c.encryptString('x'), throwsA(isA<MasterKeyUnavailableException>()));
      expect(s.keyWrites, 0);
      expect(_row(await db.getSetting(_commit))['state'], 'pending');
    });

    test(
        'KC-03 death after the L write, before activation: the next start '
        'activates the same key', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await s.inner.write(_mk, base64Encode(_key(20)));
      await db.setSetting(_commit, await _pendingRow(20));
      final MasterKeyState st = await _resolver(s, db).resolve();
      expect((st as MasterKeyReady).kid, await _kid(20));
    });

    test(
        'KC-04 L write acknowledged but never persisted (apply() lost): '
        'never activated on an unverified write', () async {
      final _Secrets s = _Secrets()..dropWrites = true;
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final MasterKeyState st = await _resolver(s, db, wrapper: w).resolve();
      expect(st, isA<MasterKeyUnavailable>());
      expect(_row(await db.getSetting(_commit))['state'], 'pending',
          reason: 'activation requires reading L back');
      s.dropWrites = false;
      final MasterKeyState again = await _resolver(s, db, wrapper: w).resolve();
      expect((again as MasterKeyReady).kid,
          _row(await db.getSetting(_commit))['kid']);
    });

    test(
        'KC-05 CAS reports an unknown outcome after committing: the re-read '
        'decides; one key', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db()..casUnknownAfterCommit = 1;
      final MasterKeyState st = await _resolver(s, db).resolve();
      expect(st, isA<MasterKeyReady>());
      expect(s.keyWrites, 1);
    });

    test(
        'KC-06 T7 restore write fails: read-only this session; restored on '
        'the next start', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      await db.setSetting(
          _commit, await _activeRow(21, w: await w.wrapNew(_key(21))));
      s.writeThrows = true;
      final MasterKeyState st = await _resolver(s, db, wrapper: w).resolve();
      expect((st as MasterKeyReady).readOnly, isTrue);
      expect(await s.inner.read(_mk), isNull);
      s.writeThrows = false;
      final MasterKeyState st2 = await _resolver(s, db, wrapper: w).resolve();
      expect((st2 as MasterKeyReady).readOnly, isFalse);
      expect(await s.inner.read(_mk), base64Encode(_key(21)));
    });
  });

  group('CC concurrency (first launch, many instances, one DB + store)', () {
    for (final bool withWrap in <bool>[true, false]) {
      test(
          'CC-01 8 cipher instances race the first encrypt (wrap: $withWrap)'
          ' x 50 rounds: one key write, every ciphertext decrypts everywhere',
          () async {
        for (int round = 0; round < 50; round++) {
          final _Secrets s = _Secrets();
          final _Db db = _Db();
          final InMemoryKeyWrapper w = InMemoryKeyWrapper();
          final List<AesGcmSettingsCipher> cs = <AesGcmSettingsCipher>[
            for (int i = 0; i < 8; i++)
              _cipher(s, db, wrapper: withWrap ? w : const NoKeyWrapper()),
          ];
          final List<String> cts = await Future.wait(<Future<String>>[
            for (int i = 0; i < 8; i++) cs[i].encryptString('row-$i'),
          ]);
          expect(s.keyWrites, 1, reason: 'round $round');
          final AesGcmSettingsCipher fresh =
              _cipher(s, db, wrapper: withWrap ? w : const NoKeyWrapper());
          for (int i = 0; i < 8; i++) {
            expect(await fresh.decryptString(cts[i]), 'row-$i');
          }
          expect(_row(await db.getSetting(_commit))['state'], 'active');
        }
      });
    }

    test(
        'CC-02 8 instances adopt an existing legacy key concurrently: one '
        'active row, zero key writes, old data readable', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String oldCt =
          await LegacyAesGcmSettingsCipherAc894ec(s).encryptString('legacy');
      await db.setSetting('security_settings', 'enc:v1:$oldCt');
      s.keyWrites = 0;
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final List<String> out = await Future.wait(<Future<String>>[
        for (int i = 0; i < 8; i++)
          _cipher(s, db, wrapper: w).decryptString(oldCt),
      ]);
      expect(out, everyElement('legacy'));
      expect(s.keyWrites, 0);
      expect(_row(await db.getSetting(_commit))['state'], 'active');
    });

    test(
        'CC-03 two AppContainers (two engines) over one DB + store race '
        'first-launch writes: the credential and the intruder settings are '
        'both readable by a third container', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final AppContainer c1 =
          AppContainer.inMemory(database: db, secretStore: s);
      final AppContainer c2 =
          AppContainer.inMemory(database: db, secretStore: s);
      final List<Object> r = await Future.wait(<Future<Object>>[
        c1.auth.enrollPin(_pin),
        IntruderDefenseSettingsStore(db, c2.settingsCipher).write(
            const IntruderDefenseSettings(evidenceEnabled: true, threshold: 3)),
      ]);
      expect(r[1], isTrue);
      expect(s.keyWrites, 1);
      final AppContainer c3 =
          AppContainer.inMemory(database: db, secretStore: s);
      final CredentialState st = (await c3.auth.status()).valueOrNull!;
      expect(st.hasAnyCredential, isTrue);
      expect((await c3.auth.authenticatePin(_pin)).valueOrNull,
          isA<AuthSuccess>());
      final IntruderSettingsRead ir =
          await IntruderDefenseSettingsStore(db, c3.settingsCipher).read();
      expect(ir.health, IntruderSettingsHealth.ok);
      expect(ir.settings.evidenceEnabled, isTrue);
    });
  });

  group('KD downgrade / re-upgrade (old = verbatim ac894ec cipher)', () {
    test(
        'KD-01 N writes; O (old build) decrypts everything; O ignores the '
        'commitment row', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String ct = await _cipher(s, db, wrapper: InMemoryKeyWrapper())
          .encryptString('written-by-N');
      final String row = (await db.getSetting(_commit))!;
      expect(await LegacyAesGcmSettingsCipherAc894ec(s).decryptString(ct),
          'written-by-N');
      expect(await db.getSetting(_commit), row);
    });

    test('KD-02 N -> O writes -> N re-upgrade reads O\'s writes (T6)',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      await _cipher(s, db, wrapper: w).encryptString('n1');
      final String oCt =
          await LegacyAesGcmSettingsCipherAc894ec(s).encryptString('o1');
      expect(await _cipher(s, db, wrapper: w).decryptString(oCt), 'o1');
    });

    test(
        'KD-03 N -> O loses L and mints Z (L1) -> N: KeyMismatch fail-closed;'
        ' X still recoverable from the wrapped copy; nothing deleted',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final String xCt = await _cipher(s, db, wrapper: w).encryptString('x');
      final String x = (await s.inner.read(_mk))!;
      final String row = (await db.getSetting(_commit))!;
      await s.inner.delete(_mk); // plugin wipe while O runs
      final String zCt =
          await LegacyAesGcmSettingsCipherAc894ec(s).encryptString('z');
      final String z = (await s.inner.read(_mk))!;
      expect(z, isNot(x));
      final AesGcmSettingsCipher n = _cipher(s, db, wrapper: w);
      await expectLater(
          n.decryptString(xCt), throwsA(isA<MasterKeyUnavailableException>()));
      await expectLater(
          n.decryptString(zCt), throwsA(isA<MasterKeyUnavailableException>()));
      expect(await s.inner.read(_mk), z, reason: 'Z never overwritten');
      expect(await db.getSetting(_commit), row, reason: 'commitment kept');
      final Map<String, Object?> r = _row(row);
      final Uint8List recovered = await w.unwrap(WrappedKey(
          alias: r['alias']! as String, blob: r['wrapped']! as String));
      expect(base64Encode(recovered), x, reason: 'X recoverable (wrap)');
    });

    test(
        'KD-04 N -> O-era plugin wipe of L (no O write) -> N restores L '
        'from the wrapped copy -> O reads again', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper w = InMemoryKeyWrapper();
      final String ct = await _cipher(s, db, wrapper: w).encryptString('kept');
      final String x = (await s.inner.read(_mk))!;
      await s.inner.delete(_mk);
      expect(await _cipher(s, db, wrapper: w).decryptString(ct), 'kept');
      expect(await s.inner.read(_mk), x);
      expect(
          await LegacyAesGcmSettingsCipherAc894ec(s).decryptString(ct), 'kept');
    });

    test(
        'KD-05 the ciphertext format is unchanged (no enc:v2, raw '
        'nonce||ct||mac) and the data key is the legacy slot value', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String ct = await _cipher(s, db).encryptString('fmt');
      expect(base64Decode(ct).length, 12 + utf8.encode('fmt').length + 16);
      final AppContainer c =
          AppContainer.inMemory(database: db, secretStore: s);
      expect((await c.auth.enrollPin(_pin)).isSuccess, isTrue);
      final String raw = (await db.getSetting('security_settings'))!;
      expect(raw, startsWith('enc:v1:'));
      expect(raw, isNot(contains('enc:v2')));
    });
  });

  group('CF credential fail-closed for every non-Ready outcome', () {
    Future<(_Db, _Secrets, String, String)> enrolled() async {
      final _Db db = _Db();
      final _Secrets s = _Secrets();
      final AppContainer c1 =
          AppContainer.inMemory(database: db, secretStore: s);
      expect((await c1.auth.enrollPin(_pin)).isSuccess, isTrue);
      for (int i = 0; i < 3; i++) {
        await c1.auth.authenticatePin('000000');
      }
      expect((await c1.auth.status()).valueOrNull!.lockedOutUntil, isNotNull);
      await c1.intruderMonitor.idle();
      return (
        db,
        s,
        (await db.getSetting('security_settings'))!,
        (await s.inner.read(_mk))!
      );
    }

    Future<void> failClosed(AppContainer c, _Db db, String raw) async {
      expect((await c.auth.status()).isFailure, isTrue);
      final r = await c.auth.authenticatePin(_pin);
      expect(r.valueOrNull, isNot(isA<AuthSuccess>()));
      expect((await c.auth.enrollPin('135790')).isFailure, isTrue);
      expect((await c.auth.clearAll()).isFailure, isTrue);
      expect(await db.getSetting('security_settings'), raw);
    }

    Future<void> recovers(_Db db, _Secrets s) async {
      final CredentialState st =
          (await AppContainer.inMemory(database: db, secretStore: s)
                  .auth
                  .status())
              .valueOrNull!;
      expect(st.hasAnyCredential, isTrue);
      expect(st.lockedOutUntil, isNotNull, reason: 'lockout not cleared');
    }

    test('CF-01 KeyLost (L deleted, no wrapped copy)', () async {
      final (_Db db, _Secrets s, String raw, String good) = await enrolled();
      await s.inner.delete(_mk);
      await failClosed(
          AppContainer.inMemory(database: db, secretStore: s), db, raw);
      expect(await s.inner.read(_mk), isNull);
      await s.inner.write(_mk, good);
      await recovers(db, s);
    });

    test('CF-02 KeyMismatch (L replaced by another valid key)', () async {
      final (_Db db, _Secrets s, String raw, String good) = await enrolled();
      await s.inner.write(_mk, base64Encode(_key(42)));
      await failClosed(
          AppContainer.inMemory(database: db, secretStore: s), db, raw);
      expect(await s.inner.read(_mk), base64Encode(_key(42)));
      await s.inner.write(_mk, good);
      await recovers(db, s);
    });

    test('CF-03 unsupported commitment / DB-read of the commitment fails',
        () async {
      final (_Db db, _Secrets s, String raw, _) = await enrolled();
      final String row = (await db.getSetting(_commit))!;
      await db.setSetting(_commit, '{"v":9}');
      await failClosed(
          AppContainer.inMemory(database: db, secretStore: s), db, raw);
      expect(await db.getSetting(_commit), '{"v":9}');
      await db.setSetting(_commit, row);
      await recovers(db, s);
    });

    test(
        'CF-05 intruder defense settings with the key unavailable read '
        'UNREADABLE (not corrupt); never overwritten', () async {
      final (_Db db, _Secrets s, _, String good) = await enrolled();
      final AppContainer c1 =
          AppContainer.inMemory(database: db, secretStore: s);
      expect(
          await IntruderDefenseSettingsStore(db, c1.settingsCipher).write(
              const IntruderDefenseSettings(
                  evidenceEnabled: true, threshold: 3)),
          isTrue);
      final String row =
          (await db.getSetting(IntruderDefenseSettingsStore.storageKey))!;
      await s.inner.delete(_mk);
      final IntruderDefenseSettingsStore st = IntruderDefenseSettingsStore(db,
          AppContainer.inMemory(database: db, secretStore: s).settingsCipher);
      final IntruderSettingsRead r = await st.read();
      expect(r.health, IntruderSettingsHealth.unreadable);
      expect(r.settings.evidenceEnabled, isFalse, reason: 'privacy fail-safe');
      expect(await st.write(IntruderDefenseSettings.disabled), isFalse);
      expect(await db.getSetting(IntruderDefenseSettingsStore.storageKey), row);
      await s.inner.write(_mk, good);
      expect(
          (await IntruderDefenseSettingsStore(
                      db,
                      AppContainer.inMemory(database: db, secretStore: s)
                          .settingsCipher)
                  .read())
              .settings
              .evidenceEnabled,
          isTrue);
    });

    test(
        'CF-06 intruder defense settings under a WRONG key (GCM '
        'authentication failure) read UNREADABLE, not corrupt', () async {
      final _Db db = _Db();
      final _Secrets s = _Secrets();
      final IntruderDefenseSettingsStore st1 =
          IntruderDefenseSettingsStore(db, _cipher(s, db));
      expect(
          await st1.write(const IntruderDefenseSettings(evidenceEnabled: true)),
          isTrue);
      final _Secrets other = _Secrets();
      await other.inner.write(_mk, base64Encode(_key(77)));
      // Own commitment DB: the cipher holds a verified (wrong) key, so the
      // store sees a real AES-GCM authentication failure.
      final IntruderSettingsRead r =
          await IntruderDefenseSettingsStore(db, _cipher(other, _Db())).read();
      expect(r.health, IntruderSettingsHealth.unreadable);
      expect(r.writable, isFalse);
    });

    test('CF-04 legacy slot garbage ("Data has been reset")', () async {
      final (_Db db, _Secrets s, String raw, _) = await enrolled();
      s.overrideRead = 'Data has been reset';
      await failClosed(
          AppContainer.inMemory(database: db, secretStore: s), db, raw);
      expect(s.keyWrites, 1, reason: 'genesis only; never overwritten');
      s.overrideRead = null;
      await recovers(db, s);
    });
  });
}
