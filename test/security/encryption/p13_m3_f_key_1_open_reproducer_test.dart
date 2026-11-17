// P13/M3 F-KEY-1: reproducer (FK-R*, FLIPPED by the Batch 2 repair) and
// credential fail-closed characterization (FK-C*, unchanged).
//
// FK-R* tests asserted the UNSAFE master-key behaviour of
// AesGcmSettingsCipher, on purpose. Batch 2 (K-2+B-compat repair) made each
// FK-R* fail; they are now deliberately FLIPPED (never deleted or
// weakened) and the originals are preserved as sealed historical evidence.
//
// FK-C* tests assert what must hold now AND after the repair: unreadable or
// missing credential state fails closed (no access, no silent reset, no
// lockout clear, no fresh enrollment, no overwrite of the ciphertext).
//
// SIMULATED: host VM, in-memory database and secret store. These are
// FIRST-LAUNCH tests: the master key is NOT pre-initialized unless a test
// says so explicitly.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/encryption/master_key_resolver.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';

const String _settingsKey = 'security_settings';
const String _mk = SecretKeys.settingsMasterKey;

/// Delegating secret store. Every call yields once, as the platform channel
/// always does. It can simulate one transient null read.
class _Secrets implements SecretStore {
  final InMemorySecretStore inner = InMemorySecretStore();
  int writes = 0;
  int nullReadsRemaining = 0;

  @override
  Future<String?> read(String key) async {
    await Future<void>.delayed(Duration.zero);
    if (nullReadsRemaining > 0) {
      nullReadsRemaining--;
      return null; // transient "absent" although a value exists
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) async {
    writes++;
    await Future<void>.delayed(Duration.zero);
    return inner.write(key, value);
  }

  @override
  Future<void> delete(String key) => inner.delete(key);

  @override
  Future<void> clear() => inner.clear();

  @override
  Future<bool> containsKey(String key) => inner.containsKey(key);
}

const String _pin = '482915';

void main() {
  // FLIPPED by Batch 2 (owner-approved K-2+B-compat repair). The ORIGINAL
  // FK-R1..R4 (asserting two keys / replacement / overwrite) are preserved
  // verbatim as historical evidence in the sealed
  // Phase13/m3_implementation/E_feature_resumption/F_KEY_1/tests/ copy and
  // in the Batch 2 evidence folder. Same IDs, same FIRST-LAUNCH setup (no
  // pre-initialized key); every cipher over one secret store shares one
  // commitment database, as AppContainer wires it.
  group('FK-R FLIPPED F-KEY-1 (Batch 2: assert REPAIRED behaviour)', () {
    test('FK-R1 FLIPPED two concurrent first uses of ONE cipher create ONE '
        'master key; every first-session ciphertext decrypts after restart',
        () async {
      final _Secrets secrets = _Secrets();
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final AesGcmSettingsCipher p1 =
          AesGcmSettingsCipher(secrets, database: db);
      final List<String> cts = await Future.wait(<Future<String>>[
        p1.encryptString('row-A'),
        p1.encryptString('row-B'),
      ]);
      final AesGcmSettingsCipher p2 =
          AesGcmSettingsCipher(secrets, database: db);
      int bad = 0;
      for (final String ct in cts) {
        try {
          await p2.decryptString(ct);
        } catch (_) {
          bad++;
        }
      }
      expect(secrets.writes, 1, reason: 'FIXED: single key creation');
      expect(bad, 0, reason: 'FIXED: no losing-key ciphertext');
    });

    test('FK-R2 FLIPPED two cipher INSTANCES (two engines) over one secret '
        'store create ONE key (SQLite CAS commitment)', () async {
      final _Secrets secrets = _Secrets();
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final List<String> cts = await Future.wait(<Future<String>>[
        AesGcmSettingsCipher(secrets, database: db).encryptString('engine-1'),
        AesGcmSettingsCipher(secrets, database: db).encryptString('engine-2'),
      ]);
      final AesGcmSettingsCipher after =
          AesGcmSettingsCipher(secrets, database: db);
      int bad = 0;
      for (final String ct in cts) {
        try {
          await after.decryptString(ct);
        } catch (_) {
          bad++;
        }
      }
      expect(secrets.writes, 1);
      expect(bad, 0, reason: 'FIXED: cross-instance commitment');
    });

    test('FK-R3 FLIPPED a DECRYPT with the key missing NEVER generates a '
        'replacement key while encrypted data exists', () async {
      final _Secrets secrets = _Secrets();
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final String ct = await AesGcmSettingsCipher(secrets, database: db)
          .encryptString('existing');
      await db.setSetting('probe_row', 'enc:v1:$ct');
      await secrets.inner.delete(_mk); // key lost (e.g. backend reset)
      secrets.writes = 0;
      await expectLater(
          AesGcmSettingsCipher(secrets, database: db).decryptString(ct),
          throwsA(isA<MasterKeyUnavailableException>()));
      await expectLater(
          AesGcmSettingsCipher(secrets, database: db).encryptString('new'),
          throwsA(isA<MasterKeyUnavailableException>()));
      expect(secrets.writes, 0, reason: 'FIXED: no replacement key');
      expect(await secrets.inner.read(_mk), isNull);
    });

    test('FK-R4 FLIPPED ONE transient null read never overwrites the good '
        'key; the next healthy read decrypts', () async {
      final _Secrets secrets = _Secrets();
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final String ct = await AesGcmSettingsCipher(secrets, database: db)
          .encryptString('existing');
      final String? original = await secrets.inner.read(_mk);
      secrets.writes = 0;
      secrets.nullReadsRemaining = 1;
      final AesGcmSettingsCipher c2 =
          AesGcmSettingsCipher(secrets, database: db);
      await expectLater(
          c2.decryptString(ct), throwsA(isA<MasterKeyUnavailableException>()));
      expect(await secrets.inner.read(_mk), original,
          reason: 'FIXED: good key preserved');
      expect(secrets.writes, 0);
      // Not cached as a failure: the SAME instance recovers.
      expect(await c2.decryptString(ct), 'existing');
    });
  });

  group('FK-C credential state fails closed (must hold before and after the '
      'repair)', () {
    /// Process 1 enrolls a PIN, records a lockout and returns the exact
    /// stored ciphertext and key.
    Future<(InMemoryLocalDatabase, _Secrets, String, String)> enrolled({
      bool lockOut = false,
    }) async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final _Secrets secrets = _Secrets();
      final AppContainer c1 =
          AppContainer.inMemory(database: db, secretStore: secrets);
      expect((await c1.auth.enrollPin(_pin)).isSuccess, isTrue);
      if (lockOut) {
        for (int i = 0; i < 3; i++) {
          await c1.auth.authenticatePin('000000');
        }
        final CredentialState s = (await c1.auth.status()).valueOrNull!;
        expect(s.lockedOutUntil, isNotNull, reason: 'lockout precondition');
      }
      await c1.intruderMonitor.idle();
      final String raw = (await db.getSetting(_settingsKey))!;
      expect(raw, startsWith('enc:v1:'));
      return (db, secrets, raw, (await secrets.inner.read(_mk))!);
    }

    Future<void> expectFailClosed(
        AppContainer c, InMemoryLocalDatabase db, String raw) async {
      // No state: never "no credential" and never defaults.
      expect((await c.auth.status()).isFailure, isTrue);
      // Never grants access, even with the CORRECT PIN.
      final r = await c.auth.authenticatePin(_pin);
      expect(r.isFailure, isTrue);
      expect(r.valueOrNull, isNot(isA<AuthSuccess>()));
      final p = await c.auth.authenticatePattern(<int>[1, 2, 3, 6, 9]);
      expect(p.valueOrNull, isNot(isA<AuthSuccess>()));
      final b = await c.auth.authenticateBiometric();
      expect(b.valueOrNull, isNot(isA<AuthSuccess>()));
      // Never a fresh enrollment, and never a silent reset.
      expect((await c.auth.enrollPin('135790')).isFailure, isTrue);
      expect((await c.auth.enrollPattern(<int>[1, 2, 3, 6, 9])).isFailure,
          isTrue);
      expect((await c.auth.clearAll()).isFailure, isTrue);
      expect((await c.auth.setRandomizedKeypadEnabled(true)).isFailure,
          isTrue);
      // The ciphertext is never overwritten (lockout/counters inside it).
      expect(await db.getSetting(_settingsKey), raw);
    }

    test('FK-C1 race-loser key (wrong key persisted): fails closed; the row '
        'and the lockout inside it survive', () async {
      final (InMemoryLocalDatabase db, _Secrets secrets, String raw,
          String good) = await enrolled(lockOut: true);
      // A different key is persisted (FK-R1/R2 outcome).
      await secrets.inner.write(_mk, base64Encode(List<int>.filled(32, 7)));
      final AppContainer c2 =
          AppContainer.inMemory(database: db, secretStore: secrets);
      await expectFailClosed(c2, db, raw);
      // Recovery evidence: with the original key, the SAME state returns,
      // lockout included (nothing was reset or re-enrolled).
      await secrets.inner.write(_mk, good);
      final AppContainer c3 =
          AppContainer.inMemory(database: db, secretStore: secrets);
      final CredentialState s = (await c3.auth.status()).valueOrNull!;
      expect(s.hasAnyCredential, isTrue);
      expect(s.lockedOutUntil, isNotNull, reason: 'lockout not cleared');
    });

    // FK-C2 FLIPPED (Batch 2): the original asserted that a replacement key
    // IS generated (FK-R3 characterization); preserved in the sealed copy.
    test('FK-C2 FLIPPED key missing with encrypted settings present: fails '
        'closed; NO replacement key is generated and the row is never '
        'overwritten', () async {
      final (InMemoryLocalDatabase db, _Secrets secrets, String raw,
          String good) = await enrolled(lockOut: true);
      await secrets.inner.delete(_mk);
      final AppContainer c2 =
          AppContainer.inMemory(database: db, secretStore: secrets);
      await expectFailClosed(c2, db, raw);
      expect(await secrets.inner.read(_mk), isNull,
          reason: 'FIXED (Batch 2): no replacement key');
      expect(secrets.writes, 1, reason: 'only the original creation');
      await secrets.inner.write(_mk, good);
      final CredentialState s = (await AppContainer.inMemory(
                  database: db, secretStore: secrets)
              .auth
              .status())
          .valueOrNull!;
      expect(s.lockedOutUntil, isNotNull);
      expect(s.hasAnyCredential, isTrue);
    });

    test('FK-C3 secure storage throws (unreadable): fails closed and no key '
        'is generated', () async {
      final (InMemoryLocalDatabase db, _Secrets secrets, String raw, _) =
          await enrolled();
      final _ThrowingSecrets broken = _ThrowingSecrets();
      final AppContainer c2 =
          AppContainer.inMemory(database: db, secretStore: broken);
      await expectFailClosed(c2, db, raw);
      expect(broken.writes, 0);
      expect(secrets.writes, 1, reason: 'only the original creation');
    });

    test('FK-C4 a fresh install (no row, no key) is the ONLY state treated as '
        'unenrolled', () async {
      final AppContainer c = AppContainer.inMemory(
          database: InMemoryLocalDatabase(), secretStore: _Secrets());
      final CredentialState s = (await c.auth.status()).valueOrNull!;
      expect(s.hasAnyCredential, isFalse);
    });
  });
}

class _ThrowingSecrets implements SecretStore {
  int writes = 0;
  @override
  Future<String?> read(String key) async =>
      throw StateError('keystore unavailable');
  @override
  Future<void> write(String key, String value) async {
    writes++;
    throw StateError('keystore unavailable');
  }

  @override
  Future<void> delete(String key) async {}
  @override
  Future<void> clear() async {}
  @override
  Future<bool> containsKey(String key) async =>
      throw StateError('keystore unavailable');
}
