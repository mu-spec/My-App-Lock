// Phase 18 / M1F — F18-2: credential lockout timing cannot be shortened by
// changing the wall clock (owner-approved design D2-a / D2-b).
//
// SIMULATED (evidence B): the production DefaultCredentialManager over the
// production SecuritySettingsRepositoryImpl and an in-memory database, an
// injected wall clock and a fake monotonic clock ({elapsedMs, bootCount}).
// Real reboots, SystemClock/BOOT_COUNT behaviour and OEM differences are
// DEVICE PENDING.
//
//  ML1  PIN: wall clock +440 min during a lockout -> still locked out
//  ML1b pattern: the same
//  ML2  status() reports the lockout after a wall-clock jump
//  ML3  monotonic expiry: unlock after the cooldown even if the wall clock
//       went back
//  ML4  a new lockout persists its anchor in the stored JSON
//  ML5  reboot (lower elapsed, new BOOT_COUNT): the full cooldown restarts,
//       re-anchored and persisted
//  ML6  lower elapsed with an unchanged BOOT_COUNT is still another boot
//  ML7  BOOT_COUNT mismatch with a HIGHER elapsed is another boot
//  ML8  unknown BOOT_COUNT: > 10 s wall/monotonic drift = another boot
//  ML9  a lockout already served is not restarted by a later reboot
//  ML10 legacy lockout (no anchor) is re-anchored once with the full streak
//       cooldown; an expired legacy lockout is not
//  ML11 no native reading: the in-process fallback clock keeps the lockout
//       (was D2-a wall-clock rule; changed by the M1F final corrections,
//       see p18_m1f_monotonic_fallback_test.dart)
//  ML12 commit-time (T3) check uses the monotonic view and writes nothing
//  ML13 CR-3 change gate uses the monotonic view
//  ML14 regression guards protect the anchor
//  ML15 channel reply parsing; missing plugin = no reading
//  ML16 anchor JSON round trip; malformed = legacy; clearLockout clears it
//  ML17 policy contract of LockoutClockPolicy.effectiveUntil
//  ML18 a re-anchor write that does not land still fails closed
//  (ML17/ML18 added after mutation run 1: MM8/MM4 survived.)
import 'dart:async';
import 'dart:math';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/repositories/security_settings_repository.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_change_authorization.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/lockout_clock.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '739154';
const String _wrong = '111999';
const List<int> _pattern = <int>[1, 2, 3, 6, 9];
const List<int> _wrongPattern = <int>[7, 4, 1, 2];
const Duration _cooldown = Duration(seconds: 30);

class _Clock implements MonotonicClock {
  int elapsed = 1000000;
  int boot = 5;
  bool fail = false;

  @override
  Future<MonotonicReading?> read() async {
    if (fail) throw StateError('no clock');
    return MonotonicReading(elapsedMs: elapsed, bootCount: boot);
  }
}

/// Holds `verify` until [open] completes (interleaves two instances).
class _GatedPinHasher implements PinHasher {
  _GatedPinHasher(this._inner);
  final PinHasher _inner;
  Completer<void>? gate;

  @override
  Future<PinHash> hash(String pin) => _inner.hash(pin);

  @override
  Future<bool> verify(String pin, PinHash stored) async {
    final Completer<void>? g = gate;
    if (g != null) await g.future;
    return _inner.verify(pin, stored);
  }
}

/// Delegates to the production repository; writes can be made to fail
/// (unconfirmed) on demand. Not a database fake (CAS-G2 unchanged).
class _FlakyWrites implements SecuritySettingsRepository {
  _FlakyWrites(this._inner);
  final SecuritySettingsRepository _inner;
  bool fail = false;

  @override
  Future<Result<SecuritySettings>> getSettings() => _inner.getSettings();

  @override
  Future<Result<void>> saveSettings(SecuritySettings settings) async => fail
      ? Result<void>.failure(const SettingsWriteUnknown('test'))
      : _inner.saveSettings(settings);

  @override
  Future<Result<bool>> hasPin() => _inner.hasPin();
}

CredentialStateMachine _machine() => CredentialStateMachine(
      maxFailedAttempts: 3,
      lockoutDuration: _cooldown,
    );

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late InMemoryLocalDatabase db;
  late DateTime now;
  late _Clock clock;

  DefaultCredentialManager manager({
    MonotonicClock? lockoutClock,
    bool noClock = false,
    PinHasher? pinHasher,
  }) =>
      DefaultCredentialManager(
        settings: SecuritySettingsRepositoryImpl(db),
        pinHasher:
            pinHasher ?? Pbkdf2PinHasher(iterations: 200, random: Random(18)),
        patternHasher: Pbkdf2PatternHasher(iterations: 200, random: Random(81)),
        stateMachine: _machine(),
        now: () => now,
        lockoutClock: noClock ? null : (lockoutClock ?? clock),
      );

  Future<SecuritySettings> stored() async =>
      (await SecuritySettingsRepositoryImpl(db).getSettings()).valueOrNull!;

  void advanceBoth(Duration d) {
    now = now.add(d);
    clock.elapsed += d.inMilliseconds;
  }

  Future<AuthAttemptResult> pin(DefaultCredentialManager m, String p) async =>
      (await m.authenticatePin(p)).valueOrNull!;

  Future<void> lockOut(DefaultCredentialManager m) async {
    for (int i = 0; i < 3; i++) {
      await pin(m, _wrong);
    }
    expect(await pin(m, _wrong), isA<AuthLockedOut>());
  }

  setUp(() {
    db = InMemoryLocalDatabase();
    now = DateTime(2026, 10, 22, 9);
    clock = _Clock();
  });

  group('F18-2 wall-clock manipulation', () {
    test('ML1 PIN: wall clock +440 min during a lockout keeps it', () async {
      final DefaultCredentialManager m = manager();
      expect((await m.enrollPin(_pin)).isSuccess, isTrue);
      await lockOut(m);
      now = now.add(const Duration(minutes: 440)); // monotonic unchanged
      for (int i = 0; i < 5; i++) {
        expect(await pin(m, _wrong), isA<AuthLockedOut>());
      }
      expect(await pin(m, _pin), isA<AuthLockedOut>());
      // A new process sees the same.
      expect(await pin(manager(), _pin), isA<AuthLockedOut>());
    });

    test('ML1b pattern: wall clock jump keeps the lockout', () async {
      final DefaultCredentialManager m = manager();
      expect((await m.enrollPattern(_pattern)).isSuccess, isTrue);
      for (int i = 0; i < 3; i++) {
        await m.authenticatePattern(_wrongPattern);
      }
      now = now.add(const Duration(hours: 6));
      expect(
        (await m.authenticatePattern(_pattern)).valueOrNull,
        isA<AuthLockedOut>(),
      );
    });

    test('ML2 status() reports the lockout after a wall-clock jump', () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      now = now.add(const Duration(hours: 1));
      final CredentialState s = (await m.status()).valueOrNull!;
      expect(s.lockedOutUntil, isNotNull);
      expect(s.lockedOutUntil!.isAfter(now), isTrue);
    });

    test(
        'ML3 the monotonic cooldown ends the lockout even if the wall '
        'clock went back', () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      clock.elapsed += _cooldown.inMilliseconds + 1000;
      now = now.subtract(const Duration(hours: 1));
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });

    test('ML4 a new lockout persists its anchor in the stored JSON', () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      final LockoutAnchor? a = (await stored()).lockoutAnchor;
      expect(a, isNotNull);
      expect(a!.elapsedMs, 1000000);
      expect(a.bootCount, 5);
      expect(a.durationMs, _cooldown.inMilliseconds);
      expect(a.served, isFalse);
      final String rows = (await db.getAllSettings()).values.join('\n');
      expect(rows, contains('lockoutAnchor'));
    });
  });

  group('F18-2 reboot handling (D2-b)', () {
    test('ML5 reboot: the full cooldown restarts, re-anchored', () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      advanceBoth(const Duration(seconds: 25));
      // Reboot: elapsed restarts, BOOT_COUNT increments.
      clock
        ..elapsed = 2000
        ..boot = 6;
      now = now.add(const Duration(seconds: 5));
      final DefaultCredentialManager after = manager();
      expect(await pin(after, _pin), isA<AuthLockedOut>());
      final LockoutAnchor a = (await stored()).lockoutAnchor!;
      expect(a.bootCount, 6);
      expect(a.elapsedMs, 2000);
      expect(a.durationMs, _cooldown.inMilliseconds);
      advanceBoth(const Duration(seconds: 28));
      expect(await pin(after, _pin), isA<AuthLockedOut>());
      advanceBoth(const Duration(seconds: 3));
      expect(await pin(after, _pin), isA<AuthSuccess>());
    });

    test('ML6 lower elapsed with an unchanged BOOT_COUNT is another boot',
        () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      clock.elapsed = 10000; // same boot count reported (unreliable OEM)
      now = now.add(const Duration(seconds: 5));
      expect(await pin(manager(), _pin), isA<AuthLockedOut>());
      advanceBoth(const Duration(seconds: 31));
      expect(await pin(manager(), _pin), isA<AuthSuccess>());
    });

    test('ML7 BOOT_COUNT mismatch with a HIGHER elapsed is another boot',
        () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      advanceBoth(const Duration(seconds: 20));
      clock.boot = 6;
      expect(await pin(m, _pin), isA<AuthLockedOut>()); // re-anchored here
      advanceBoth(const Duration(seconds: 15)); // 35 s after the start
      expect(await pin(m, _pin), isA<AuthLockedOut>());
      advanceBoth(const Duration(seconds: 16));
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });

    test('ML8 unknown BOOT_COUNT: > 10 s drift is another boot', () async {
      clock
        ..boot = -1
        ..elapsed = 5000;
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      // Reboot without BOOT_COUNT: elapsed is higher than the anchor's, but
      // the wall clock moved 10 min while elapsed moved 55 s.
      clock.elapsed = 60000;
      now = now.add(const Duration(minutes: 10));
      expect(await pin(manager(), _pin), isA<AuthLockedOut>());
      // Within the drift tolerance the monotonic clock rules.
      advanceBoth(const Duration(seconds: 31));
      expect(await pin(manager(), _pin), isA<AuthSuccess>());
    });

    test('ML9 a served lockout is not restarted by a later reboot', () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      advanceBoth(const Duration(seconds: 31));
      await m.status(); // observes the end: recorded as served
      expect((await stored()).lockoutAnchor!.served, isTrue);
      clock
        ..elapsed = 1000
        ..boot = 6;
      now = now.add(const Duration(seconds: 40));
      final CredentialState s = (await manager().status()).valueOrNull!;
      expect(
          s.lockedOutUntil == null || !s.lockedOutUntil!.isAfter(now), isTrue);
      expect(await pin(manager(), _pin), isA<AuthSuccess>());
    });

    test('ML10 legacy lockout is re-anchored once with the streak cooldown',
        () async {
      // Lockouts written by a build without the anchor (no clock).
      final DefaultCredentialManager legacy = manager(noClock: true);
      await legacy.enrollPin(_pin);
      await lockOut(legacy);
      now = now.add(const Duration(seconds: 31));
      await lockOut(legacy); // streak 2
      final SecuritySettings s0 = await stored();
      expect(s0.lockoutAnchor, isNull);
      expect(s0.lockoutStreak, 2);
      final Duration cd2 = _machine().cooldownForStreak(2);
      now = now.add(cd2 - const Duration(seconds: 5)); // 5 s left by wall
      final DefaultCredentialManager m = manager();
      expect(await pin(m, _pin), isA<AuthLockedOut>());
      final LockoutAnchor a = (await stored()).lockoutAnchor!;
      expect(a.durationMs, cd2.inMilliseconds);
      expect(a.elapsedMs, clock.elapsed);
      // Re-anchored ONCE: the next observation keeps the same anchor.
      advanceBoth(const Duration(seconds: 3));
      expect(await pin(m, _pin), isA<AuthLockedOut>());
      expect((await stored()).lockoutAnchor, a);

      // An already-expired legacy lockout is not re-anchored.
      db = InMemoryLocalDatabase();
      final DefaultCredentialManager legacy2 = manager(noClock: true);
      await legacy2.enrollPin(_pin);
      await lockOut(legacy2);
      now = now.add(const Duration(seconds: 31));
      expect(await pin(manager(), _pin), isA<AuthSuccess>());
    });

    test('ML11 no native reading: the fallback clock keeps the lockout',
        () async {
      clock.fail = true;
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      await lockOut(m);
      // Anchored on the in-process fallback clock (never the wall clock).
      expect((await stored()).lockoutAnchor!.processScope, isNotNull);
      expect(await pin(m, _pin), isA<AuthLockedOut>());
      now = now.add(const Duration(seconds: 31)); // wall clock only
      expect(await pin(m, _pin), isA<AuthLockedOut>());
    });
  });

  group('F18-2 consumers and guards', () {
    test('ML12 commit-time (T3) check uses the monotonic view, no write',
        () async {
      final _GatedPinHasher gated =
          _GatedPinHasher(Pbkdf2PinHasher(iterations: 200, random: Random(18)));
      final DefaultCredentialManager a = manager(pinHasher: gated);
      final DefaultCredentialManager b = manager();
      await b.enrollPin(_pin);
      gated.gate = Completer<void>();
      final Future<Result<AuthAttemptResult>> pending = a.authenticatePin(_pin);
      await pumpEventQueue();
      await lockOut(b); // lockout starts while A verifies
      now = now.add(const Duration(hours: 1)); // monotonic unchanged
      final Map<String, String> before = await db.getAllSettings();
      gated.gate!.complete();
      expect((await pending).valueOrNull, isA<AuthLockedOut>());
      expect(await db.getAllSettings(), before);
    });

    test('ML13 CR-3 change gate uses the monotonic view', () async {
      final DefaultCredentialManager a = manager();
      final DefaultCredentialManager b = manager();
      await a.enrollPin(_pin);
      final CredentialChangeAttempt attempt =
          (await a.verifyPinForCredentialChange(_pin)).valueOrNull!;
      expect(attempt.result, isA<AuthSuccess>());
      await lockOut(b);
      now = now.add(const Duration(seconds: 31)); // wall only; TTL is 2 min
      final Result<void> r =
          await a.enrollPin('582607', authorization: attempt.authorization);
      expect(r.isFailure, isTrue);
      expect(
        (r.errorOrNull! as CredentialChangeNotAuthorized).denial,
        CredentialChangeDenial.lockedOut,
      );
    });

    test('ML14 regression guards protect the anchor', () {
      final DateTime t = DateTime(2026, 10, 22, 9);
      const LockoutAnchor a = LockoutAnchor(
          elapsedMs: 1000, bootCount: 5, wallMs: 1, durationMs: 30000);
      final SecuritySettings locked = SecuritySettings(
        failedAttempts: 3,
        lockoutStreak: 1,
        lockedOutUntil: t.add(_cooldown),
        lockoutAnchor: a,
      );
      String? upd(SecuritySettings n) =>
          DefaultCredentialManager.updateRegression(locked, n,
              allowCounterReset: false);
      expect(upd(locked.copyWith(randomizedKeypadEnabled: true)), isNull);
      expect(upd(locked.copyWith(clearLockoutAnchor: true)), 'anchor');
      expect(
          upd(locked.copyWith(
              lockoutAnchor: const LockoutAnchor(
                  elapsedMs: 9, bootCount: 6, wallMs: 2, durationMs: 1000))),
          'anchor'); // shortened
      expect(
          upd(locked.copyWith(
              lockoutAnchor: const LockoutAnchor(
                  elapsedMs: 9, bootCount: 6, wallMs: 2, durationMs: 30000))),
          isNull); // reboot re-anchor
      expect(upd(locked.copyWith(lockoutAnchor: a.asServed())), isNull);
      expect(
          upd(locked.copyWith(
              lockoutAnchor: const LockoutAnchor(
                  elapsedMs: 0,
                  bootCount: 5,
                  wallMs: 1,
                  durationMs: 30000,
                  served: true))),
          'anchor'); // served + moved
      const SecuritySettings free = SecuritySettings();
      expect(
          DefaultCredentialManager.updateRegression(
              free, free.copyWith(lockoutAnchor: a),
              allowCounterReset: false),
          'anchor'); // no anchor without a lockout
      expect(
          DefaultCredentialManager.updateRegression(
              locked, locked.copyWith(clearLockoutAnchor: true),
              allowCounterReset: true),
          isNull); // Clear All

      // Verdicts: nothing changes during an active lockout (anchor too).
      expect(
          DefaultCredentialManager.verdictRegression(
              locked, locked.copyWith(lockoutAnchor: a.asServed()),
              matches: false, now: t),
          'lockout');
      // A new lockout's anchor starts now, unserved, for the new cooldown.
      const SecuritySettings two = SecuritySettings(failedAttempts: 2);
      const MonotonicReading r = MonotonicReading(elapsedMs: 50, bootCount: 5);
      SecuritySettings start(LockoutAnchor x) => two.copyWith(
          failedAttempts: 3,
          lockoutStreak: 1,
          lockedOutUntil: t.add(_cooldown),
          lockoutAnchor: x);
      String? v(LockoutAnchor x) =>
          DefaultCredentialManager.verdictRegression(two, start(x),
              matches: false, now: t);
      expect(v(LockoutAnchor.start(r, t, _cooldown)), isNull);
      expect(v(LockoutAnchor.start(r, t, _cooldown).asServed()), 'anchor');
      expect(
          v(LockoutAnchor.start(r, t, const Duration(seconds: 1))), 'anchor');
      expect(
          v(LockoutAnchor.start(
              r, t.subtract(const Duration(minutes: 5)), _cooldown)),
          'anchor');
    });
  });

  group('F18-2 plumbing', () {
    test('ML15 channel reply parsing; missing plugin = no reading', () async {
      expect(
          MonotonicReading.fromMap(<Object?, Object?>{
            'elapsedMs': 7,
            'bootCount': 3,
          })?.bootCount,
          3);
      expect(
          MonotonicReading.fromMap(<Object?, Object?>{'elapsedMs': 7})
              ?.bootCount,
          -1);
      expect(MonotonicReading.fromMap(<Object?, Object?>{'elapsedMs': -1}),
          isNull);
      expect(MonotonicReading.fromMap(<Object?, Object?>{'elapsedMs': '7'}),
          isNull);
      expect(MonotonicReading.fromMap(null), isNull);

      const MethodChannel ch =
          MethodChannel(MethodChannelMonotonicClock.channelName);
      const MethodChannelMonotonicClock c = MethodChannelMonotonicClock();
      expect(await c.read(), isNull); // no native handler
      final TestDefaultBinaryMessenger m =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      m.setMockMethodCallHandler(ch, (MethodCall call) async {
        expect(call.method, 'read');
        return <String, Object>{'elapsedMs': 42, 'bootCount': 9};
      });
      final MonotonicReading? got = await c.read();
      expect(got?.elapsedMs, 42);
      expect(got?.bootCount, 9);
      m.setMockMethodCallHandler(ch, (MethodCall call) async {
        throw PlatformException(code: 'unavailable');
      });
      expect(await c.read(), isNull);
      m.setMockMethodCallHandler(ch, null);
    });

    test('ML16 anchor JSON round trip; malformed = legacy', () {
      const LockoutAnchor a = LockoutAnchor(
          elapsedMs: 10, bootCount: -1, wallMs: 99, durationMs: 30000);
      expect(LockoutAnchor.fromJson(a.toJson()), a);
      expect(LockoutAnchor.fromJson(a.asServed().toJson())!.served, isTrue);
      expect(LockoutAnchor.fromJson(<String, Object>{'elapsedMs': 1}), isNull);
      expect(
          LockoutAnchor.fromJson(<String, Object>{
            'elapsedMs': 1,
            'bootCount': 1,
            'wallMs': 1,
            'durationMs': 0,
          }),
          isNull);
      expect(LockoutAnchor.fromJson('x'), isNull);
      final SecuritySettings s = SecuritySettings(
        lockedOutUntil: DateTime(2026, 10, 22, 9),
        lockoutAnchor: a,
      );
      expect(SecuritySettings.fromJson(s.toJson()).lockoutAnchor, a);
      expect(s.copyWith(clearLockout: true).lockoutAnchor, isNull);
      expect(
          SecuritySettings.fromJson(const SecuritySettings().toJson())
              .lockoutAnchor,
          isNull);
    });
  });

  group('F18-2 fail-closed edges', () {
    test('ML17 policy contract of effectiveUntil', () {
      final DateTime t = DateTime(2026, 10, 22, 9);
      final DateTime until = t.add(_cooldown);
      const LockoutAnchor a = LockoutAnchor(
          elapsedMs: 1000, bootCount: 5, wallMs: 0, durationMs: 30000);
      const MonotonicReading same =
          MonotonicReading(elapsedMs: 11000, bootCount: 5);
      const MonotonicReading other =
          MonotonicReading(elapsedMs: 500, bootCount: 6);
      DateTime? eff(LockoutAnchor? x, MonotonicReading? r, DateTime n) =>
          LockoutClockPolicy.effectiveUntil(
              storedUntil: until, anchor: x, reading: r, now: n);
      // D2-a: no reading, or no anchor = the stored wall-clock end.
      expect(eff(a, null, t), until);
      expect(eff(null, same, t), until);
      expect(
          LockoutClockPolicy.effectiveUntil(
              storedUntil: null, anchor: a, reading: same, now: t),
          isNull);
      // Same boot: 10 s of 30 s elapsed -> 20 s left, whatever the wall says.
      final DateTime later = t.add(const Duration(hours: 5));
      expect(eff(a, same, later), later.add(const Duration(seconds: 20)));
      // Another boot not yet re-anchored: the FULL cooldown from now.
      expect(eff(a, other, later), later.add(_cooldown));
      // Served: expired.
      expect(eff(a.asServed(), other, later)!.isAfter(later), isFalse);
    });

    test('ML18 a re-anchor write that does not land still fails closed',
        () async {
      final _FlakyWrites repo =
          _FlakyWrites(SecuritySettingsRepositoryImpl(db));
      DefaultCredentialManager flaky() => DefaultCredentialManager(
            settings: repo,
            pinHasher: Pbkdf2PinHasher(iterations: 200, random: Random(18)),
            patternHasher:
                Pbkdf2PatternHasher(iterations: 200, random: Random(81)),
            stateMachine: _machine(),
            now: () => now,
            lockoutClock: clock,
          );
      final DefaultCredentialManager m = flaky();
      await m.enrollPin(_pin);
      await lockOut(m);
      advanceBoth(const Duration(seconds: 25));
      clock
        ..elapsed = 2000
        ..boot = 6; // reboot; the stored anchor is from boot 5
      now = now.add(const Duration(minutes: 10));
      repo.fail = true; // the re-anchor cannot be persisted
      final DefaultCredentialManager after = flaky();
      final CredentialState s = (await after.status()).valueOrNull!;
      expect(s.lockedOutUntil!.isAfter(now), isTrue);
      expect((await after.authenticatePin(_pin)).valueOrNull,
          isA<AuthLockedOut>());
      expect((await stored()).lockoutAnchor!.bootCount, 5); // not re-anchored
    });
  });
}
