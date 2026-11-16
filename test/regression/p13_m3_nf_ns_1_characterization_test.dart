// P13/M3 Track C — NF-NS-1 credential/lockout concurrency characterization.
//
// WORKSPACE-ONLY host test (never committed without approval). It changes
// no production code: it builds TWO production DefaultCredentialManager
// instances (what two Flutter engines would each construct in their own
// AppContainer) over ONE shared InMemoryLocalDatabase, each with its own
// SecuritySettingsRepositoryImpl, and interleaves them deterministically by
// holding one manager's PIN verification (the slow KDF step) on a gate.
//
// Every test asserts the SECURE expectation. A failing test is therefore a
// DEMONSTRATION of the defect on host. Each test also prints one line
//   NS1-RESULT id=<id> secure=<bool> <observed facts>
// so the outcome is recorded whether it passes or fails.
//
// SIMULATED: Dart VM, in-memory storage, deterministic clock. Not device QA.
// Two managers over one store is the HOST model of two engines; whether two
// engines can coexist on a device is DQ-ENG-1a (open).

import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/repositories/security_settings_repository.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_change_authorization.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '4829';
const String _newPin = '7391';
const String _wrong = '0000';

/// Real PBKDF2 (low work factor) whose verify can be held on a gate AFTER
/// the manager has loaded its settings snapshot (the real race window).
class _GatedPinHasher implements PinHasher {
  final Pbkdf2PinHasher _inner = Pbkdf2PinHasher(iterations: 200);
  Completer<void>? gate;
  Completer<void>? entered;

  void hold() {
    gate = Completer<void>();
    entered = Completer<void>();
  }

  void release() => gate?.complete();

  @override
  Future<PinHash> hash(String pin) => _inner.hash(pin);

  @override
  Future<bool> verify(String pin, PinHash stored) async {
    final Completer<void>? g = gate;
    if (g != null) {
      entered?.complete();
      await g.future;
      gate = null;
    }
    return _inner.verify(pin, stored);
  }
}

/// Repository whose next save can be held (verdict-visibility test) or
/// made to fail after writing (ambiguous persistence).
class _ControlledRepo implements SecuritySettingsRepository {
  _ControlledRepo(this._inner);
  final SecuritySettingsRepository _inner;
  Completer<void>? holdSave;
  bool failAfterWrite = false;
  bool failBeforeWrite = false;

  @override
  Future<Result<SecuritySettings>> getSettings() => _inner.getSettings();

  @override
  Future<Result<void>> saveSettings(SecuritySettings settings) async {
    final Completer<void>? h = holdSave;
    if (h != null) {
      await h.future;
      holdSave = null;
    }
    if (failBeforeWrite) {
      failBeforeWrite = false;
      return Result.failure(StateError('injected pre-write fault'));
    }
    final Result<void> r = await _inner.saveSettings(settings);
    if (failAfterWrite) {
      failAfterWrite = false;
      return Result.failure(StateError('injected post-write fault'));
    }
    return r;
  }

  @override
  Future<Result<bool>> hasPin() => _inner.hasPin();
}

void main() {
  late InMemoryLocalDatabase db;
  late DateTime now;
  late _GatedPinHasher hA;
  late _GatedPinHasher hB;
  late _ControlledRepo repoA;
  late DefaultCredentialManager a;
  late DefaultCredentialManager b;

  DefaultCredentialManager build(
    SecuritySettingsRepository repo,
    PinHasher hasher,
  ) =>
      DefaultCredentialManager(
        settings: repo,
        pinHasher: hasher,
        patternHasher: Pbkdf2PatternHasher(iterations: 200),
        // Production policy (app_container.dart L215-222).
        stateMachine: CredentialStateMachine(
          maxFailedAttempts: 3,
          lockoutDuration: const Duration(seconds: 30),
        ),
        now: () => now,
      );

  Future<SecuritySettings> persisted() async =>
      (await SecuritySettingsRepositoryImpl(db).getSettings()).valueOrNull!;

  void record(String id, bool secure, String facts) {
    // ignore: avoid_print
    print('NS1-RESULT id=$id secure=$secure $facts');
  }

  setUp(() async {
    db = InMemoryLocalDatabase();
    now = DateTime(2026, 11, 15, 10);
    hA = _GatedPinHasher();
    hB = _GatedPinHasher();
    repoA = _ControlledRepo(SecuritySettingsRepositoryImpl(db));
    // Engine A and engine B: separate repository + manager instances.
    a = build(repoA, hA);
    b = build(SecuritySettingsRepositoryImpl(db), hB);
    expect((await a.enrollPin(_pin)).isSuccess, isTrue);
  });

  /// B starts a wrong-PIN attempt and is parked inside verify (its settings
  /// snapshot is already loaded). Returns B's pending result.
  Future<Future<Result<AuthAttemptResult>>> parkB(String pin) async {
    hB.hold();
    final Future<Result<AuthAttemptResult>> f = b.authenticatePin(pin);
    await hB.entered!.future;
    return f;
  }

  group('NF-NS-1 two-instance characterization', () {
    test('K-1 CONTROL: one manager, two concurrent wrong PINs both counted',
        () async {
      hA.hold();
      final Future<Result<AuthAttemptResult>> f1 = a.authenticatePin(_wrong);
      final Future<Result<AuthAttemptResult>> f2 = a.authenticatePin(_wrong);
      await hA.entered!.future;
      hA.release();
      await f1;
      await f2;
      final int n = (await persisted()).failedAttempts;
      record('K-1', n == 2, 'failedAttempts=$n expected=2 (single instance)');
      expect(n, 2);
    });

    test('C-1 lost failed-attempt increment across instances', () async {
      final Future<Result<AuthAttemptResult>> fb = await parkB(_wrong);
      await a.authenticatePin(_wrong); // A: 0 -> 1, persisted
      hB.release();
      await fb; // B: stale snapshot 0 -> 1, persisted over A
      final int n = (await persisted()).failedAttempts;
      record('C-1', n == 2, 'wrong_submitted=2 failedAttempts=$n expected=2');
      expect(n, 2, reason: 'SECURITY: a failed attempt was lost');
    });

    test('C-2 lockout threshold (policy 3) under pairwise concurrency',
        () async {
      int submitted = 0;
      int? lockedAt;
      for (int round = 0; round < 5 && lockedAt == null; round++) {
        final Future<Result<AuthAttemptResult>> fb = await parkB(_wrong);
        final AuthAttemptResult ra =
            (await a.authenticatePin(_wrong)).valueOrNull!;
        submitted++;
        if (ra is AuthLockedOut) lockedAt = submitted;
        hB.release();
        final AuthAttemptResult rb = (await fb).valueOrNull!;
        submitted++;
        if (lockedAt == null && rb is AuthLockedOut) lockedAt = submitted;
      }
      final SecuritySettings s = await persisted();
      final bool secure = lockedAt != null && lockedAt <= 3;
      record(
        'C-2',
        secure,
        'wrong_submitted_until_lockout=${lockedAt ?? ">$submitted"} '
            'policy=3 persisted_locked=${s.lockedOutUntil != null}',
      );
      expect(lockedAt, isNotNull);
      expect(lockedAt, lessThanOrEqualTo(3),
          reason: 'SECURITY: lockout threshold exceeded');
    });

    test('C-3 active lockout erased by a stale concurrent write', () async {
      await a.authenticatePin(_wrong); // persisted failed=1
      final Future<Result<AuthAttemptResult>> fb = await parkB(_wrong);
      await a.authenticatePin(_wrong); // 2
      final AuthAttemptResult third =
          (await a.authenticatePin(_wrong)).valueOrNull!; // 3 -> lockout
      final bool trippedInA = third is AuthLockedOut;
      final int streakBefore = (await persisted()).lockoutStreak;
      hB.release();
      await fb; // B writes its stale (unlocked) snapshot
      final SecuritySettings s = await persisted();
      // During the 30 s cooldown, is a further attempt still refused?
      final AuthAttemptResult next =
          (await a.authenticatePin(_wrong)).valueOrNull!;
      final bool secure =
          trippedInA && s.lockedOutUntil != null && next is AuthLockedOut;
      record(
        'C-3',
        secure,
        'lockout_tripped_in_A=$trippedInA persisted_locked_after_B='
            '${s.lockedOutUntil != null} streak_before=$streakBefore '
            'streak_after=${s.lockoutStreak} '
            'next_attempt_during_cooldown=${next.runtimeType}',
      );
      expect(trippedInA, isTrue);
      expect(s.lockedOutUntil, isNotNull,
          reason: 'SECURITY: an active lockout was erased');
      expect(next, isA<AuthLockedOut>());
    });

    test('C-4 PIN change reverted by a stale verification write', () async {
      final CredentialChangeAttempt grant =
          (await a.verifyPinForCredentialChange(_pin)).valueOrNull!;
      final Future<Result<AuthAttemptResult>> fb = await parkB(_wrong);
      final bool changed = (await a.enrollPin(
        _newPin,
        authorization: grant.authorization,
      ))
          .isSuccess;
      hB.release();
      await fb;
      // A fresh instance (e.g. after restart) checks which PIN is stored.
      final DefaultCredentialManager c =
          build(SecuritySettingsRepositoryImpl(db), _GatedPinHasher());
      final AuthAttemptResult withNew =
          (await c.authenticatePin(_newPin)).valueOrNull!;
      final bool secure = changed && withNew is AuthSuccess;
      record(
        'C-4',
        secure,
        'change_reported_success=$changed new_pin_accepted_after_race='
            '${withNew is AuthSuccess} (${withNew.runtimeType})',
      );
      expect(changed, isTrue);
      expect(withNew, isA<AuthSuccess>(),
          reason: 'SECURITY: the changed PIN was overwritten');
    });

    test('C-5 clearAll resurrected by a stale verification write', () async {
      final Future<Result<AuthAttemptResult>> fb = await parkB(_wrong);
      final bool cleared = (await a.clearAll()).isSuccess;
      hB.release();
      await fb;
      final SecuritySettings s = await persisted();
      final bool secure = cleared && s.pinHash == null;
      record('C-5', secure,
          'clear_reported_success=$cleared pin_present_after_race=${s.pinHash != null}');
      expect(cleared, isTrue);
      expect(s.pinHash, isNull,
          reason: 'SECURITY: cleared credential was resurrected');
    });

    test('C-6 change grant from B survives a PIN change made in A', () async {
      final CredentialChangeAttempt grantB =
          (await b.verifyPinForCredentialChange(_pin)).valueOrNull!;
      final CredentialChangeAttempt grantA =
          (await a.verifyPinForCredentialChange(_pin)).valueOrNull!;
      expect((await a.enrollPin(_newPin, authorization: grantA.authorization))
          .isSuccess, isTrue);
      // B's grant was earned against the OLD PIN, before A's change.
      final Result<void> late =
          await b.enrollPin('5555', authorization: grantB.authorization);
      final bool secure = late.isFailure;
      record('C-6', secure,
          'stale_grant_change_accepted=${late.isSuccess} (per-instance epoch)');
      expect(late.isFailure, isTrue,
          reason: 'SECURITY: stale cross-instance grant replaced a credential');
    });

    test('C-7 process death during slow verification: uncounted, no verdict',
        () async {
      hA.hold();
      bool completed = false;
      unawaited(a.authenticatePin(_wrong).then((_) => completed = true));
      await hA.entered!.future;
      // "Process death": A is abandoned while parked; a new instance starts.
      final DefaultCredentialManager c =
          build(SecuritySettingsRepositoryImpl(db), _GatedPinHasher());
      final int before = (await persisted()).failedAttempts;
      final AuthAttemptResult r = (await c.authenticatePin(_wrong)).valueOrNull!;
      final int after = (await persisted()).failedAttempts;
      record('C-7', !completed,
          'abandoned_attempt_counted=${before != 0} verdict_delivered=$completed '
          'next_attempt=${r.runtimeType} failed_after=$after');
      expect(completed, isFalse);
      expect(before, 0); // characterization: the abandoned attempt is uncounted
    });

    test('C-8a verdict is not observable before the counter write', () async {
      repoA.holdSave = Completer<void>();
      bool done = false;
      final Future<Result<AuthAttemptResult>> f =
          a.authenticatePin(_wrong)..then((_) => done = true);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final bool earlyVerdict = done;
      repoA.holdSave!.complete();
      await f;
      record('C-8a', !earlyVerdict, 'verdict_before_persist=$earlyVerdict');
      expect(earlyVerdict, isFalse);
    });

    test('C-8b failed / ambiguous persistence never grants access', () async {
      repoA.failBeforeWrite = true;
      final Result<AuthAttemptResult> pre = await a.authenticatePin(_pin);
      repoA.failAfterWrite = true;
      final Result<AuthAttemptResult> post = await a.authenticatePin(_pin);
      repoA.failAfterWrite = true;
      final Result<AuthAttemptResult> wrongAmb = await a.authenticatePin(_wrong);
      final int counted = (await persisted()).failedAttempts;
      final bool secure = pre.isFailure && post.isFailure && wrongAmb.isFailure;
      record('C-8b', secure,
          'correct_pin_prewrite_fault_access=${pre.isSuccess} '
          'correct_pin_postwrite_fault_access=${post.isSuccess} '
          'wrong_pin_ambiguous_counted=${counted == 1}');
      expect(pre.isFailure, isTrue);
      expect(post.isFailure, isTrue);
      expect(wrongAmb.isFailure, isTrue);
    });
  });
}
