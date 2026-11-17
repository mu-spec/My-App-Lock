// P13/M3 F-KEY-1: OPEN-defect reproducer and credential fail-closed
// characterization. NOT a fix, and no production code is changed.
//
// FK-R* tests assert the CURRENT, UNSAFE master-key behaviour of
// AesGcmSettingsCipher, on purpose. When the owner-approved K-2+ repair
// lands, each FK-R* test MUST fail and be deliberately flipped (never
// deleted or weakened): that flip is the regression proof.
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
  group('FK-R OPEN F-KEY-1 reproducers (assert CURRENT unsafe behaviour)', () {
    test('FK-R1 two concurrent first uses of ONE cipher create two master '
        'keys; one first-session ciphertext is undecryptable after restart',
        () async {
      final _Secrets secrets = _Secrets();
      final AesGcmSettingsCipher p1 = AesGcmSettingsCipher(secrets);
      final List<String> cts = await Future.wait(<Future<String>>[
        p1.encryptString('row-A'),
        p1.encryptString('row-B'),
      ]);
      final AesGcmSettingsCipher p2 = AesGcmSettingsCipher(secrets);
      int bad = 0;
      for (final String ct in cts) {
        try {
          await p2.decryptString(ct);
        } catch (_) {
          bad++;
        }
      }
      expect(secrets.writes, 2, reason: 'OPEN: no single-flight creation');
      expect(bad, 1, reason: 'OPEN: a losing-key ciphertext was produced');
    });

    test('FK-R2 two cipher INSTANCES (two engines) over one secret store '
        'also create two keys', () async {
      final _Secrets secrets = _Secrets();
      final List<String> cts = await Future.wait(<Future<String>>[
        AesGcmSettingsCipher(secrets).encryptString('engine-1'),
        AesGcmSettingsCipher(secrets).encryptString('engine-2'),
      ]);
      final AesGcmSettingsCipher after = AesGcmSettingsCipher(secrets);
      int bad = 0;
      for (final String ct in cts) {
        try {
          await after.decryptString(ct);
        } catch (_) {
          bad++;
        }
      }
      expect(secrets.writes, 2);
      expect(bad, 1, reason: 'OPEN: a per-instance mutex cannot fix this');
    });

    test('FK-R3 a DECRYPT with the key missing generates and persists a '
        'replacement key although encrypted data exists', () async {
      final _Secrets secrets = _Secrets();
      final String ct =
          await AesGcmSettingsCipher(secrets).encryptString('existing');
      await secrets.inner.delete(_mk); // key lost (e.g. backend reset)
      secrets.writes = 0;
      await expectLater(
          AesGcmSettingsCipher(secrets).decryptString(ct), throwsA(anything));
      expect(secrets.writes, 1, reason: 'OPEN: replacement key written');
      expect(await secrets.inner.read(_mk), isNotNull);
    });

    test('FK-R4 ONE transient null read OVERWRITES the existing good key '
        '(the original key is destroyed)', () async {
      final _Secrets secrets = _Secrets();
      final String ct =
          await AesGcmSettingsCipher(secrets).encryptString('existing');
      final String? original = await secrets.inner.read(_mk);
      secrets.nullReadsRemaining = 1;
      await expectLater(
          AesGcmSettingsCipher(secrets).decryptString(ct), throwsA(anything));
      final String? now = await secrets.inner.read(_mk);
      expect(now, isNot(original), reason: 'OPEN: good key overwritten');
      // Unrecoverable: even a healthy store can no longer decrypt.
      await expectLater(
          AesGcmSettingsCipher(secrets).decryptString(ct), throwsA(anything));
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

    test('FK-C2 key missing with encrypted settings present: fails closed; '
        'a replacement key IS generated today (FK-R3, OPEN) but the row is '
        'never overwritten', () async {
      final (InMemoryLocalDatabase db, _Secrets secrets, String raw,
          String good) = await enrolled(lockOut: true);
      await secrets.inner.delete(_mk);
      final AppContainer c2 =
          AppContainer.inMemory(database: db, secretStore: secrets);
      await expectFailClosed(c2, db, raw);
      final String? replacement = await secrets.inner.read(_mk);
      expect(replacement, isNotNull, reason: 'OPEN FK-R3 characterization');
      expect(replacement, isNot(good));
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
