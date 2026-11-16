// P13/M3 NF-NS-1 — PinCredentialStore.saveOnto coverage (owner item 5).
//
// `saveOnto` is the conditional PIN write the manager uses for T5: it is
// bound to the exact document the change was decided on. Host tests only.
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/repositories/security_settings_repository.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/credential_hash_policy.dart';
import 'package:smart_app_lock/security/credentials/impl/default_pin_credential_store.dart';
import 'package:smart_app_lock/security/credentials/pin_storage.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/utilities/result.dart';

void main() {
  late InMemoryLocalDatabase db;
  late SecuritySettingsRepository settings;
  late PinCredentialStore store;
  final Pbkdf2PinHasher hasher = Pbkdf2PinHasher(iterations: 500);

  setUp(() {
    db = InMemoryLocalDatabase();
    settings = SecuritySettingsRepositoryImpl(db);
    store = DefaultPinCredentialStore(
      settings,
      policy: CredentialHashPolicy.lenient,
    );
  });

  Future<SecuritySettings> read() async =>
      (await settings.getSettings()).valueOrNull!;

  test('PS-1 saveOnto on the current basis commits the hash and metadata',
      () async {
    final PinHash h = await hasher.hash('2468');
    final Result<void> r = await store.saveOnto(
      await read(),
      h,
      pinLength: 4,
      makePrimary: true,
    );
    expect(r.isSuccess, isTrue);
    final SecuritySettings s = await read();
    expect(s.pinHash!.digest, h.digest);
    expect(s.pinLength, 4);
    expect(s.primaryAuthType, AuthType.pin);
    expect(s.secretEpoch, 1);
  });

  test('PS-2 saveOnto on a STALE basis is a conflict and writes nothing: an '
      'old PIN can never be restored over a newer one', () async {
    expect((await store.save(await hasher.hash('1111'))).isSuccess, isTrue);
    final SecuritySettings stale = await read();
    // Another writer replaces the PIN.
    expect((await store.saveOnto(await read(), await hasher.hash('2222')))
        .isSuccess, isTrue);
    final String? before = await db.getSetting('security_settings');
    final Result<void> late =
        await store.saveOnto(stale, await hasher.hash('1111'));
    expect(late.isFailure, isTrue);
    expect(late.errorOrNull, isA<SettingsWriteConflict>());
    expect(await db.getSetting('security_settings'), before);
    expect(await hasher.verify('2222', (await read()).pinHash!), isTrue);
  });

  test('PS-3 saveOnto with a value never read from storage cannot replace an '
      'existing document', () async {
    expect((await store.save(await hasher.hash('1111'))).isSuccess, isTrue);
    final String? before = await db.getSetting('security_settings');
    final Result<void> r = await store.saveOnto(
      SecuritySettings.defaults,
      await hasher.hash('9999'),
    );
    expect(r.errorOrNull, isA<SettingsWriteConflict>());
    expect(await db.getSetting('security_settings'), before);
  });

  test('PS-4 saveOnto refuses a policy-violating hash before any write',
      () async {
    final PinCredentialStore strict = DefaultPinCredentialStore(
      settings,
      policy: CredentialHashPolicy.strict,
    );
    final String? before = await db.getSetting('security_settings');
    final Result<void> r = await strict.saveOnto(
      await read(),
      await Pbkdf2PinHasher(iterations: 100).hash('1234'),
    );
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull.toString(), contains('iterationsBelowMinimum'));
    expect(await db.getSetting('security_settings'), before);
  });

  test('PS-5 resetAttemptState clears counters only when asked; otherwise '
      'the basis counters are kept (lockout never dropped by a PIN write)',
      () async {
    expect((await store.save(await hasher.hash('1111'))).isSuccess, isTrue);
    final DateTime until = DateTime(2030);
    expect((await settings.saveSettings((await read()).copyWith(
      failedAttempts: 2,
      lockoutStreak: 1,
      lockedOutUntil: until,
    )))
        .isSuccess, isTrue);
    expect((await store.saveOnto(await read(), await hasher.hash('2222')))
        .isSuccess, isTrue);
    SecuritySettings s = await read();
    expect(s.failedAttempts, 2);
    expect(s.lockoutStreak, 1);
    expect(s.lockedOutUntil, until);
    expect((await store.saveOnto(
      await read(),
      await hasher.hash('3333'),
      resetAttemptState: true,
    ))
        .isSuccess, isTrue);
    s = await read();
    expect(s.failedAttempts, 0);
    expect(s.lockoutStreak, 0);
    expect(s.lockedOutUntil, isNull);
  });
}
