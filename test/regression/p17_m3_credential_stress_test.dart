import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/repositories/security_settings_repository.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/utilities/result.dart';

/// Phase 17 / M3 — repeated PIN/pattern authentication, repeated wrong
/// attempts and lockouts, process recreation during a lockout, and
/// temporarily unavailable credential storage.
///
/// SIMULATED (evidence B): in-memory database, injected clock, the
/// production lockout policy (3 attempts, 30 s base, escalating to 10 min).
const String _pin = '4829';
const String _wrong = '0000';
const List<int> _pattern = <int>[1, 2, 3, 6, 9];
const List<int> _wrongPattern = <int>[7, 8, 9, 6, 3];

/// Read/write faults that can be switched on and off between attempts.
class _FlakyRepo implements SecuritySettingsRepository {
  _FlakyRepo(this._inner);
  final SecuritySettingsRepository _inner;
  bool failReads = false;
  bool failWrites = false;
  int reads = 0;

  @override
  Future<Result<SecuritySettings>> getSettings() async {
    reads++;
    if (failReads) {
      return Result.failure(StateError('injected: storage unavailable'));
    }
    return _inner.getSettings();
  }

  @override
  Future<Result<void>> saveSettings(SecuritySettings settings) async {
    if (failWrites) {
      return Result.failure(StateError('injected: write unavailable'));
    }
    return _inner.saveSettings(settings);
  }

  @override
  Future<Result<bool>> hasPin() async {
    if (failReads) {
      return Result.failure(StateError('injected: storage unavailable'));
    }
    return _inner.hasPin();
  }
}

void main() {
  late InMemoryLocalDatabase db;
  late DateTime now;
  late _FlakyRepo repo;

  /// A fresh manager over the SAME database: a process recreation.
  DefaultCredentialManager process() => DefaultCredentialManager(
        settings: repo,
        pinHasher: Pbkdf2PinHasher(iterations: 200),
        patternHasher: Pbkdf2PatternHasher(iterations: 200),
        // Production policy (app_container.dart).
        stateMachine: CredentialStateMachine(
          maxFailedAttempts: 3,
          lockoutDuration: const Duration(seconds: 30),
        ),
        now: () => now,
      );

  setUp(() {
    db = InMemoryLocalDatabase();
    now = DateTime(2026, 10, 22, 9);
    repo = _FlakyRepo(SecuritySettingsRepositoryImpl(db));
  });

  bool isSuccess(Result<AuthAttemptResult> r) =>
      r.isSuccess && r.valueOrNull is AuthSuccess;

  test(
      'S-AUTH-1: 100 repeated correct PIN authentications all succeed and '
      'never accumulate failure state', () async {
    final DefaultCredentialManager m = process();
    expect((await m.enrollPin(_pin)).isSuccess, isTrue);
    for (int i = 0; i < 100; i++) {
      expect(isSuccess(await m.authenticatePin(_pin)), isTrue, reason: '#$i');
      now = now.add(const Duration(seconds: 1));
    }
    final SecuritySettings s = (await repo.getSettings()).valueOrNull!;
    expect(s.failedAttempts, 0);
    expect(s.lockedOutUntil, isNull);
    expect(s.lockoutStreak, 0);
  });

  test(
      'S-AUTH-2: 20 consecutive lockout rounds — a correct PIN is refused '
      'during every lockout, the cooldown escalates and caps at 10 min',
      () async {
    final DefaultCredentialManager m = process();
    await m.enrollPin(_pin);
    Duration previous = Duration.zero;
    for (int round = 1; round <= 20; round++) {
      final Result<AuthAttemptResult> a = await m.authenticatePin(_wrong);
      final Result<AuthAttemptResult> b = await m.authenticatePin(_wrong);
      expect(a.valueOrNull, isA<AuthFailure>());
      expect(b.valueOrNull, isA<AuthFailure>());
      final AuthAttemptResult third =
          (await m.authenticatePin(_wrong)).valueOrNull!;
      expect(third, isA<AuthLockedOut>(), reason: 'round $round');
      final AuthLockedOut lock = third as AuthLockedOut;
      expect(lock.lockoutStreak, round);
      final Duration cooldown = lock.retryAt.difference(now);
      expect(cooldown, greaterThanOrEqualTo(previous));
      expect(cooldown, lessThanOrEqualTo(const Duration(minutes: 10)));
      previous = cooldown;
      // Repeated correct PINs during the lockout: never a success.
      for (int i = 0; i < 5; i++) {
        final AuthAttemptResult r =
            (await m.authenticatePin(_pin)).valueOrNull!;
        expect(r, isA<AuthLockedOut>(), reason: 'round $round try $i');
      }
      // One millisecond before expiry is still locked.
      now = lock.retryAt.subtract(const Duration(milliseconds: 1));
      expect((await m.authenticatePin(_pin)).valueOrNull, isA<AuthLockedOut>());
      now = lock.retryAt;
    }
    expect(previous, const Duration(minutes: 10));
    // After the last expiry a correct PIN succeeds and resets the streak.
    expect(isSuccess(await m.authenticatePin(_pin)), isTrue);
    final SecuritySettings s = (await repo.getSettings()).valueOrNull!;
    expect(s.lockoutStreak, 0);
    expect(s.failedAttempts, 0);
  });

  test(
      'S-AUTH-3: process recreation during an active lockout (20 restarts) '
      'never clears the lockout or the attempt counter', () async {
    await process().enrollPin(_pin);
    final DefaultCredentialManager first = process();
    await first.authenticatePin(_wrong);
    await first.authenticatePin(_wrong);
    final AuthLockedOut lock =
        (await first.authenticatePin(_wrong)).valueOrNull! as AuthLockedOut;
    for (int i = 0; i < 20; i++) {
      now = now.add(const Duration(seconds: 1));
      final DefaultCredentialManager restarted = process();
      final AuthAttemptResult r =
          (await restarted.authenticatePin(_pin)).valueOrNull!;
      expect(r, isA<AuthLockedOut>(), reason: 'restart $i');
      expect((r as AuthLockedOut).retryAt, lock.retryAt);
    }
    // Partial failures also survive a restart (no reset by recreation).
    now = lock.retryAt;
    await process().authenticatePin(_wrong);
    await process().authenticatePin(_wrong);
    final AuthAttemptResult third =
        (await process().authenticatePin(_wrong)).valueOrNull!;
    expect(third, isA<AuthLockedOut>());
    expect((third as AuthLockedOut).lockoutStreak, 2);
  });

  test(
      'S-AUTH-4: 50 repeated pattern authentications plus wrong-pattern '
      'lockout; the correct pattern is refused while locked and after a '
      'process recreation', () async {
    final DefaultCredentialManager m = process();
    expect((await m.enrollPattern(_pattern)).isSuccess, isTrue);
    for (int i = 0; i < 50; i++) {
      expect(isSuccess(await m.authenticatePattern(_pattern)), isTrue);
    }
    await m.authenticatePattern(_wrongPattern);
    await m.authenticatePattern(_wrongPattern);
    expect((await m.authenticatePattern(_wrongPattern)).valueOrNull,
        isA<AuthLockedOut>());
    for (int i = 0; i < 10; i++) {
      expect((await m.authenticatePattern(_pattern)).valueOrNull,
          isA<AuthLockedOut>());
      expect((await process().authenticatePattern(_pattern)).valueOrNull,
          isA<AuthLockedOut>());
    }
  });

  test(
      'S-AUTH-5: storage toggling unavailable/available 40 times — an '
      'unreadable store never yields success, recovery needs a real match',
      () async {
    final DefaultCredentialManager m = process();
    await m.enrollPin(_pin);
    int successes = 0;
    for (int i = 0; i < 40; i++) {
      repo.failReads = i.isEven;
      final Result<AuthAttemptResult> r = await m.authenticatePin(_pin);
      if (repo.failReads) {
        expect(r.isFailure, isTrue, reason: 'unknown storage is not ALLOW');
      } else {
        expect(isSuccess(r), isTrue);
        successes++;
      }
      // A wrong PIN is never a success in either state.
      expect(isSuccess(await m.authenticatePin(_wrong)), isFalse);
      repo.failReads = false;
      // Reset the counter with a genuine success so no lockout interferes.
      await m.authenticatePin(_pin);
    }
    expect(successes, 20);
  });

  test(
      'S-AUTH-6: an unpersistable verdict fails closed — correct and '
      'wrong PINs both fail while writes fail (no success, no oracle)',
      () async {
    final DefaultCredentialManager m = process();
    await m.enrollPin(_pin);
    for (int i = 0; i < 20; i++) {
      repo.failWrites = true;
      final Result<AuthAttemptResult> right = await m.authenticatePin(_pin);
      final Result<AuthAttemptResult> wrong = await m.authenticatePin(_wrong);
      expect(right.isFailure, isTrue, reason: '#$i');
      expect(wrong.isFailure, isTrue, reason: '#$i');
      expect(right.errorOrNull.runtimeType, wrong.errorOrNull.runtimeType);
      repo.failWrites = false;
    }
    // Nothing was persisted during the outage: no counter drift either way.
    final SecuritySettings s = (await repo.getSettings()).valueOrNull!;
    expect(s.failedAttempts, 0);
    // Once writes work, the policy applies from the persisted state.
    await m.authenticatePin(_wrong);
    await m.authenticatePin(_wrong);
    expect((await m.authenticatePin(_wrong)).valueOrNull, isA<AuthLockedOut>());
  });
}
