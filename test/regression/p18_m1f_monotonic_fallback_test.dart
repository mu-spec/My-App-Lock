// Phase 18 / M1F final corrections — F18-2b: with the native monotonic
// clock unavailable or malformed, an active lockout can NOT be bypassed by
// moving the device wall clock (the replaced D2-a wall-clock fallback could:
// Phase18/M1F/impl2/repro, R1-R3 BYPASS). The fallback is an in-process
// monotonic clock (FailClosedLockoutClock -> ProcessMonotonicClock); a new
// process / boot restarts the full cooldown; bounded recovery = the cooldown
// served on a monotonic clock.
//
// SIMULATED (evidence B): production DefaultCredentialManager over the
// production SecuritySettingsRepositoryImpl; injected wall clock, fake native
// clock and fake in-process clock (scope = one simulated process). Real
// process death, reboots and OEM clock behaviour are DEVICE PENDING.
//
//  MF1  native unavailable for the whole lockout: wall +1 h keeps it (R1);
//       30 s on the in-process clock ends it (bounded recovery)
//  MF2  wall clock moved BACK: neither extends nor shortens the cooldown
//  MF3  native-anchored lockout, native unavailable at the check (R2):
//       full cooldown on the fallback, re-anchored and persisted
//  MF4  malformed native replies (negative, non-int, non-map, throwing,
//       spoofed scope) are never trusted and never fall back to the wall
//  MF5  lockout started while unavailable, native recovered later (R3):
//       full cooldown on the native clock, re-anchored
//  MF6  process recreation while unavailable: full cooldown again
//  MF7  reboot with native unavailable afterwards: full cooldown
//  MF8  legacy lockout (no anchor) migrated while native unavailable
//  MF9  concurrent attempts (two instances) after a wall jump: all refused
//  MF10 failed re-anchor persistence: fails closed; recovers once writes land
//  MF11 latch: a flapping native clock cannot restart the cooldown forever
//  MF12 FailClosedLockoutClock / ProcessMonotonicClock contract
import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/repositories/security_settings_repository.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/lockout_clock.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '739154';
const String _wrong = '111999';
const Duration _cooldown = Duration(seconds: 30);

/// Fake native clock.
class _Native implements MonotonicClock {
  int elapsed = 1000000;
  int boot = 5;
  bool fail = false;
  MonotonicReading? Function()? reply;

  @override
  Future<MonotonicReading?> read() async {
    final MonotonicReading? Function()? o = reply;
    if (o != null) return o();
    if (fail) throw StateError('no native clock');
    return MonotonicReading(elapsedMs: elapsed, bootCount: boot);
  }
}

/// Fake in-process monotonic clock: one instance per simulated process.
class _Proc implements MonotonicClock {
  _Proc(this.scope, [this.elapsed = 500]);
  final String scope;
  int elapsed;

  @override
  Future<MonotonicReading?> read() async =>
      MonotonicReading(elapsedMs: elapsed, bootCount: -1, processScope: scope);
}

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

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late InMemoryLocalDatabase db;
  late DateTime now;
  late _Native native;

  /// One simulated process: its own fallback clock and latch.
  DefaultCredentialManager process(
    _Proc proc, {
    SecuritySettingsRepository? repo,
    bool noClock = false,
  }) =>
      DefaultCredentialManager(
        settings: repo ?? SecuritySettingsRepositoryImpl(db),
        pinHasher: Pbkdf2PinHasher(iterations: 200, random: Random(18)),
        patternHasher: Pbkdf2PatternHasher(iterations: 200, random: Random(81)),
        stateMachine: CredentialStateMachine(
          maxFailedAttempts: 3,
          lockoutDuration: _cooldown,
        ),
        now: () => now,
        lockoutClock: noClock ? null : native,
        lockoutFallbackClock: proc,
        lockoutClockLatch: LockoutClockLatch(),
      );

  Future<SecuritySettings> stored() async =>
      (await SecuritySettingsRepositoryImpl(db).getSettings()).valueOrNull!;

  Future<AuthAttemptResult> pin(DefaultCredentialManager m, String p) async =>
      (await m.authenticatePin(p)).valueOrNull!;

  Future<void> lockOut(DefaultCredentialManager m) async {
    for (int i = 0; i < 3; i++) {
      await pin(m, _wrong);
    }
    expect(await pin(m, _wrong), isA<AuthLockedOut>());
  }

  Future<void> expectLocked(DefaultCredentialManager m) async {
    final CredentialState s = (await m.status()).valueOrNull!;
    expect(s.lockedOutUntil, isNotNull);
    expect(s.lockedOutUntil!.isAfter(now), isTrue);
    expect(await pin(m, _pin), isA<AuthLockedOut>());
  }

  setUp(() {
    db = InMemoryLocalDatabase();
    now = DateTime(2026, 10, 22, 9);
    native = _Native();
  });

  group('F18-2b native clock unavailable', () {
    test('MF1 wall +1 h keeps the lockout; 30 s monotonic ends it', () async {
      native.fail = true;
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager m = process(p1);
      expect((await m.enrollPin(_pin)).isSuccess, isTrue);
      await lockOut(m);
      expect((await stored()).lockoutAnchor!.processScope, 'p1');
      now = now.add(const Duration(hours: 1)); // wall clock only
      await expectLocked(m);
      p1.elapsed += 29000;
      await expectLocked(m);
      p1.elapsed += 1500; // the cooldown served on a monotonic clock
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });

    test('MF2 wall clock moved back neither extends nor shortens', () async {
      native.fail = true;
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager m = process(p1);
      await m.enrollPin(_pin);
      await lockOut(m);
      now = now.subtract(const Duration(hours: 3));
      p1.elapsed += 10000;
      await expectLocked(m);
      p1.elapsed += 21000;
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });

    test('MF3 native-anchored lockout, native gone at the check', () async {
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager m = process(p1);
      await m.enrollPin(_pin);
      await lockOut(m);
      expect((await stored()).lockoutAnchor!.processScope, isNull);
      native.fail = true;
      now = now.add(const Duration(hours: 1));
      await expectLocked(m);
      // Re-anchored on the fallback clock, full cooldown, persisted.
      final LockoutAnchor a = (await stored()).lockoutAnchor!;
      expect(a.processScope, 'p1');
      expect(a.durationMs, _cooldown.inMilliseconds);
      expect(a.served, isFalse);
      p1.elapsed += 31000;
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });

    test('MF4 malformed native replies are never trusted', () async {
      final List<MonotonicReading? Function()> bad =
          <MonotonicReading? Function()>[
        () => null,
        () => const MonotonicReading(elapsedMs: -5, bootCount: 5),
        () => const MonotonicReading(elapsedMs: 9, bootCount: -7),
        // A primary may not impersonate the fallback (spoofed scope).
        () => const MonotonicReading(
            elapsedMs: 9, bootCount: 5, processScope: 'p1'),
        () => throw const FormatException('garbage'),
      ];
      for (final MonotonicReading? Function() reply in bad) {
        db = InMemoryLocalDatabase();
        now = DateTime(2026, 10, 22, 9);
        native = _Native()..reply = reply;
        final _Proc p1 = _Proc('p1');
        final DefaultCredentialManager m = process(p1);
        await m.enrollPin(_pin);
        await lockOut(m);
        // Anchored on the fallback clock's reading, not the bad reply.
        expect((await stored()).lockoutAnchor!.processScope, 'p1');
        expect((await stored()).lockoutAnchor!.elapsedMs, 500);
        now = now.add(const Duration(days: 2));
        await expectLocked(m);
      }
      // Channel level: malformed maps / non-map replies parse to nothing.
      const MethodChannel ch =
          MethodChannel(MethodChannelMonotonicClock.channelName);
      final TestDefaultBinaryMessenger messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      const MethodChannelMonotonicClock c = MethodChannelMonotonicClock();
      for (final Object? reply in <Object?>[
        <String, Object>{'elapsedMs': -1, 'bootCount': 3},
        <String, Object>{'elapsedMs': '42', 'bootCount': 3},
        <String, Object>{'elapsedMs': 4.2, 'bootCount': 3},
        <String, Object>{'bootCount': 3},
        <Object>[1, 2],
        'garbage',
      ]) {
        messenger.setMockMethodCallHandler(
            ch, (MethodCall call) async => reply);
        expect(await c.read(), isNull, reason: '$reply');
      }
      messenger.setMockMethodCallHandler(ch, null);
    });

    test('MF5 started while unavailable, native recovered later', () async {
      native.fail = true;
      final DefaultCredentialManager m1 = process(_Proc('p1'));
      await m1.enrollPin(_pin);
      await lockOut(m1);
      // New process; the native clock works again.
      native.fail = false;
      now = now.add(const Duration(hours: 1));
      final DefaultCredentialManager m2 = process(_Proc('p2'));
      await expectLocked(m2);
      final LockoutAnchor a = (await stored()).lockoutAnchor!;
      expect(a.processScope, isNull); // re-anchored on the native clock
      expect(a.elapsedMs, native.elapsed);
      native.elapsed += 29000;
      await expectLocked(m2);
      native.elapsed += 1500;
      expect(await pin(m2, _pin), isA<AuthSuccess>());
    });

    test('MF6 process recreation while unavailable: full cooldown', () async {
      native.fail = true;
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager m1 = process(p1);
      await m1.enrollPin(_pin);
      await lockOut(m1);
      p1.elapsed += 25000; // 25 s served in process 1
      final _Proc p2 = _Proc('p2', 100); // new process, stopwatch restarted
      now = now.add(const Duration(hours: 1));
      final DefaultCredentialManager m2 = process(p2);
      await expectLocked(m2);
      expect((await stored()).lockoutAnchor!.processScope, 'p2');
      p2.elapsed += 29000;
      await expectLocked(m2);
      p2.elapsed += 1500;
      expect(await pin(m2, _pin), isA<AuthSuccess>());
    });

    test('MF7 reboot, native unavailable afterwards: full cooldown', () async {
      final DefaultCredentialManager m1 = process(_Proc('p1'));
      await m1.enrollPin(_pin);
      await lockOut(m1);
      native
        ..elapsed = 2000
        ..boot = 6
        ..fail = true; // after the reboot the native clock is broken
      now = now.add(const Duration(minutes: 20));
      final _Proc p2 = _Proc('p2', 50);
      final DefaultCredentialManager m2 = process(p2);
      await expectLocked(m2);
      p2.elapsed += 31000;
      expect(await pin(m2, _pin), isA<AuthSuccess>());
    });

    test('MF8 legacy lockout migrated while native unavailable', () async {
      final DefaultCredentialManager legacy =
          process(_Proc('p0'), noClock: true);
      await legacy.enrollPin(_pin);
      await lockOut(legacy);
      expect((await stored()).lockoutAnchor, isNull);
      now = now.add(const Duration(seconds: 10)); // still active by wall
      native.fail = true;
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager m = process(p1);
      await expectLocked(m);
      final LockoutAnchor a = (await stored()).lockoutAnchor!;
      expect(a.processScope, 'p1');
      expect(a.durationMs, _cooldown.inMilliseconds);
      now = now.add(const Duration(hours: 1));
      await expectLocked(m);
      p1.elapsed += 31000;
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });

    test('MF9 concurrent attempts after a wall jump are all refused', () async {
      native.fail = true;
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager a = process(p1);
      final DefaultCredentialManager b = process(p1);
      await a.enrollPin(_pin);
      await lockOut(a);
      now = now.add(const Duration(hours: 1));
      final List<Result<AuthAttemptResult>> results =
          await Future.wait(<Future<Result<AuthAttemptResult>>>[
        for (int i = 0; i < 4; i++) a.authenticatePin(_pin),
        for (int i = 0; i < 4; i++) b.authenticatePin(_pin),
        a.status().then((_) => b.authenticatePin(_pin)),
      ]);
      for (final Result<AuthAttemptResult> r in results) {
        expect(r.valueOrNull, isA<AuthLockedOut>());
      }
      expect((await stored()).lockoutAnchor!.processScope, 'p1');
    });

    test('MF10 failed re-anchor persistence fails closed, then recovers',
        () async {
      final _FlakyWrites repo =
          _FlakyWrites(SecuritySettingsRepositoryImpl(db));
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager m = process(p1, repo: repo);
      await m.enrollPin(_pin);
      await lockOut(m);
      native.fail = true;
      repo.fail = true; // the fallback re-anchor cannot be persisted
      now = now.add(const Duration(hours: 1));
      await expectLocked(m);
      p1.elapsed += 60000;
      await expectLocked(m); // never credited without a persisted anchor
      expect((await stored()).lockoutAnchor!.processScope, isNull);
      repo.fail = false; // writes land again: bounded recovery
      await expectLocked(m);
      expect((await stored()).lockoutAnchor!.processScope, 'p1');
      p1.elapsed += 31000;
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });

    test('MF11 a flapping native clock cannot restart the cooldown', () async {
      final _Proc p1 = _Proc('p1');
      final DefaultCredentialManager m = process(p1);
      await m.enrollPin(_pin);
      await lockOut(m);
      native.fail = true;
      await expectLocked(m); // fallback latched, re-anchored on p1
      native.fail = false; // native back in the same process
      p1.elapsed += 15000;
      native.elapsed += 15000;
      await expectLocked(m);
      expect((await stored()).lockoutAnchor!.processScope, 'p1');
      p1.elapsed += 16000;
      native.elapsed += 16000;
      expect(await pin(m, _pin), isA<AuthSuccess>());
    });
  });

  group('F18-2b clock contracts', () {
    test('MF12 FailClosedLockoutClock and ProcessMonotonicClock', () async {
      final _Proc p = _Proc('px', 7);
      final LockoutClockLatch latch = LockoutClockLatch();
      final FailClosedLockoutClock c =
          FailClosedLockoutClock(native, fallback: p, latch: latch);
      expect((await c.read())!.processScope, isNull);
      expect(latch.fellBack, isFalse);
      native.fail = true;
      expect((await c.read())!.processScope, 'px');
      expect(latch.fellBack, isTrue);
      native.fail = false;
      expect((await c.read())!.processScope, 'px'); // latched
      // A fallback that is not scoped / is negative is refused.
      final FailClosedLockoutClock bad = FailClosedLockoutClock(
        _Native()..fail = true,
        fallback: _Native(),
        latch: LockoutClockLatch(),
      );
      expect(await bad.read(), isNull);

      final MonotonicReading r1 =
          (await ProcessMonotonicClock.instance.read())!;
      await Future<void>.delayed(const Duration(milliseconds: 20));
      final MonotonicReading r2 =
          (await ProcessMonotonicClock.instance.read())!;
      expect(r1.processScope, isNotNull);
      expect(r1.processScope!.length, 32);
      expect(r2.processScope, r1.processScope);
      expect(r1.bootCount, -1);
      expect(r2.elapsedMs, greaterThanOrEqualTo(r1.elapsedMs + 15));
      // Default fallback is the in-process clock.
      final MonotonicReading? d =
          await FailClosedLockoutClock(_Native()..fail = true).read();
      expect(d!.processScope, r1.processScope);
    });

    test('MF12b the anchor scope survives JSON; a non-string is malformed', () {
      final LockoutAnchor a = LockoutAnchor.start(
        const MonotonicReading(elapsedMs: 5, bootCount: -1, processScope: 'p9'),
        DateTime(2026, 10, 22, 9),
        _cooldown,
      );
      expect(LockoutAnchor.fromJson(a.toJson()), a);
      expect(LockoutAnchor.fromJson(a.toJson())!.processScope, 'p9');
      final Map<String, Object?> j = Map<String, Object?>.of(a.toJson())
        ..['processScope'] = 7;
      expect(LockoutAnchor.fromJson(j), isNull);
      final LockoutAnchor n = LockoutAnchor.start(
        const MonotonicReading(elapsedMs: 5, bootCount: 2),
        DateTime(2026, 10, 22, 9),
        _cooldown,
      );
      expect(n.toJson().containsKey('processScope'), isFalse);
      // Different time bases are never the same boot.
      expect(
        LockoutClockPolicy.sameBoot(
          a,
          const MonotonicReading(elapsedMs: 9, bootCount: -1),
          DateTime(2026, 10, 22, 9),
        ),
        isFalse,
      );
      expect(
        LockoutClockPolicy.sameBoot(
          a,
          const MonotonicReading(
              elapsedMs: 9, bootCount: -1, processScope: 'p8'),
          DateTime(2026, 10, 22, 9),
        ),
        isFalse,
      );
      expect(
        LockoutClockPolicy.sameBoot(
          a,
          const MonotonicReading(
              elapsedMs: 9, bootCount: -1, processScope: 'p9'),
          DateTime(2027, 1, 1), // wall drift is irrelevant in-process
        ),
        isTrue,
      );
      // Static: the fallback clock never reads the wall clock (its only
      // DateTime.now use seeds the scope id when no secure RNG exists).
      final String src = File('lib/security/credentials/lockout_clock.dart')
          .readAsStringSync();
      expect('DateTime.now'.allMatches(src).length, 1);
      expect(src,
          contains('random = Random(DateTime.now().microsecondsSinceEpoch);'));
      expect(src, contains('elapsedMs: _stopwatch.elapsedMilliseconds,'));
    });
  });
}
