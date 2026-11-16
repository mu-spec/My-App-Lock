// P13/M3 NF-NS-1 — credential state transitions (design A,
// Phase13/m3_security_response/A_NF_NS_1_CREDENTIAL_STATE_TRANSITION_DESIGN.md
// §2–§4, §8). Host evidence only: not Android, not device QA.
//
// Every scenario uses SEPARATE repository + manager instances over ONE
// store ("engines"), gated hashers / prompts to park an attempt at a known
// point, and the production lockout policy (3 attempts / 30 s).
//
// Groups:
//   P-1..P-6   pattern twins of the sealed C-1..C-6
//   B-1..B-6   biometric verdicts racing writes from another manager
//   T-NS-*     transitions, grants, monotone guard, migration, T4, faults,
//              destroyed-engine write, restart / recovery
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/repositories/security_settings_repository.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/biometric_options.dart';
import 'package:smart_app_lock/security/credentials/credential_change_authorization.dart';
import 'package:smart_app_lock/security/credentials/credential_hash.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/credentials/credential_state_errors.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/services/biometric_service.dart';
import 'package:smart_app_lock/utilities/result.dart';

// Disposable test credentials only.
const String _pin = '4829';
const String _newPin = '7391';
const String _wrong = '0000';
const List<int> _pat = <int>[1, 2, 3, 6, 9];
const List<int> _newPat = <int>[7, 4, 1, 2, 3];
const List<int> _wrongPat = <int>[9, 8, 7, 4];
const String _key = 'security_settings';

// ------------------------------------------------------------------ gates
class _Gate {
  Completer<void>? _gate;
  Completer<void>? _entered;

  void hold() {
    _gate = Completer<void>();
    _entered = Completer<void>();
  }

  Future<void> get entered => _entered!.future;

  void release() => _gate?.complete();

  Future<void> pass() async {
    final Completer<void>? g = _gate;
    if (g != null) {
      _entered?.complete();
      await g.future;
      _gate = null;
    }
  }
}

class _GatedPinHasher implements PinHasher {
  final Pbkdf2PinHasher _inner = Pbkdf2PinHasher(iterations: 200);
  final _Gate gate = _Gate();

  @override
  Future<PinHash> hash(String pin) => _inner.hash(pin);

  @override
  Future<bool> verify(String pin, PinHash stored) async {
    await gate.pass();
    return _inner.verify(pin, stored);
  }
}

class _GatedPatternHasher implements PatternHasher {
  final Pbkdf2PatternHasher _inner = Pbkdf2PatternHasher(iterations: 200);
  final _Gate gate = _Gate();

  @override
  Future<CredentialHash> hash(List<int> nodes) => _inner.hash(nodes);

  @override
  Future<bool> verify(List<int> nodes, CredentialHash stored) async {
    await gate.pass();
    return _inner.verify(nodes, stored);
  }
}

/// Biometric prompt that can be parked while "open".
class _GatedBiometric implements BiometricService {
  final _Gate gate = _Gate();
  Result<bool> outcome = Result.success(true);

  @override
  Future<Result<bool>> isSupported() async => Result.success(true);

  @override
  Future<Result<Set<BiometricKind>>> availableKinds() async =>
      Result.success(const <BiometricKind>{BiometricKind.strong});

  @override
  Future<Result<bool>> authenticate({
    required String reason,
    BiometricOptions? options,
  }) async {
    await gate.pass();
    return outcome;
  }
}

// ------------------------------------------------------------- fault store
enum _Fault {
  none,

  /// A competing writer commits right before every compare-and-set.
  conflictAlways,

  /// The statement lands, then the outcome is reported UNKNOWN.
  unknownLanded,

  /// UNKNOWN without landing.
  unknownNotLanded,

  /// UNKNOWN without landing, and the reconciliation read fails too.
  unknownUnreadable,
}

class _FaultDb extends InMemoryLocalDatabase {
  _Fault fault = _Fault.none;
  int casCalls = 0;
  int blindSettingsWrites = 0;

  /// Owner item 4 (M-NS-14): an unbounded retry loop under [_Fault.conflictAlways]
  /// never yields to the timer queue, so a test [Timeout] cannot preempt it.
  /// This deterministic ceiling ends such a loop (far above the bound of 3,
  /// never reached by a correct manager) and is asserted by T-NS-11a.
  static const int runawayCeiling = 50;
  bool runawayRetry = false;
  bool failReads = false;

  @override
  Future<String?> getSetting(String key) {
    if (failReads) {
      throw StateError('injected read fault');
    }
    return super.getSetting(key);
  }

  @override
  Future<void> setSetting(String key, String value) {
    if (key == _key) {
      blindSettingsWrites++;
    }
    return super.setSetting(key, value);
  }

  /// A foreign committed write: same document, revision + 1.
  Future<void> competingCommit() async {
    final Map<String, dynamic> doc = (jsonDecode((await super.getSetting(_key))!)
            as Map<String, dynamic>)
        .cast<String, dynamic>();
    doc['_rev'] = (doc['_rev'] as int? ?? 0) + 1;
    await super.setSetting(_key, jsonEncode(doc));
  }

  @override
  Future<CasOutcome> compareAndSetSetting(
    String key, {
    required String? expected,
    required String next,
  }) async {
    casCalls++;
    switch (fault) {
      case _Fault.none:
        return super.compareAndSetSetting(key, expected: expected, next: next);
      case _Fault.conflictAlways:
        if (casCalls > runawayCeiling) {
          runawayRetry = true;
          throw StateError('runaway compare-and-set retry (M-NS-14)');
        }
        await competingCommit();
        return super.compareAndSetSetting(key, expected: expected, next: next);
      case _Fault.unknownLanded:
        await super.compareAndSetSetting(key, expected: expected, next: next);
        throw const CasUnknownOutcome(CasUnknownCode.io);
      case _Fault.unknownNotLanded:
        throw const CasUnknownOutcome(CasUnknownCode.busy);
      case _Fault.unknownUnreadable:
        failReads = true;
        throw const CasUnknownOutcome(CasUnknownCode.closed);
    }
  }
}

/// Repository wrapper that parks the N-th call of one operation.
class _ParkingRepo implements SecuritySettingsRepository {
  _ParkingRepo(this._inner);

  final SecuritySettingsRepository _inner;
  String? parkOp; // 'get' | 'save'
  int parkAt = 0;
  int _gets = 0;
  int _saves = 0;
  final _Gate gate = _Gate();

  void parkOn(String op, int n) {
    parkOp = op;
    parkAt = n;
    _gets = 0;
    _saves = 0;
    gate.hold();
  }

  @override
  Future<Result<SecuritySettings>> getSettings() async {
    _gets++;
    final Result<SecuritySettings> r = await _inner.getSettings();
    if (parkOp == 'get' && _gets == parkAt) {
      await gate.pass();
    }
    return r;
  }

  @override
  Future<Result<void>> saveSettings(SecuritySettings settings) async {
    _saves++;
    if (parkOp == 'save' && _saves == parkAt) {
      await gate.pass();
    }
    return _inner.saveSettings(settings);
  }

  @override
  Future<Result<bool>> hasPin() => _inner.hasPin();
}

/// Policy machine that returns a WEAKER next state (T-NS-8 only).
class _RegressingMachine extends CredentialStateMachine {
  _RegressingMachine()
      : super(
          maxFailedAttempts: 3,
          lockoutDuration: const Duration(seconds: 30),
        );

  @override
  (CredentialState, AuthAttemptResult) evaluate({
    required CredentialState state,
    required bool credentialMatches,
    required AuthType attemptType,
    required DateTime now,
  }) {
    final (CredentialState next, AuthAttemptResult r) = super.evaluate(
      state: state,
      credentialMatches: credentialMatches,
      attemptType: attemptType,
      now: now,
    );
    return credentialMatches
        ? (next, r)
        : (next.copyWith(failedAttempts: 0), r); // drops the count
  }
}

class _Observer implements VerifiedAttemptObserver {
  final List<VerifiedAttempt> attempts = <VerifiedAttempt>[];

  @override
  void onVerifiedAttempt(VerifiedAttempt attempt) => attempts.add(attempt);
}

void main() {
  late _FaultDb db;
  late DateTime now;

  DefaultCredentialManager build(
    SecuritySettingsRepository repo, {
    PinHasher? pinHasher,
    PatternHasher? patternHasher,
    BiometricService? biometric,
    CredentialStateMachine? machine,
    VerifiedAttemptObserver? observer,
  }) =>
      DefaultCredentialManager(
        settings: repo,
        pinHasher: pinHasher ?? Pbkdf2PinHasher(iterations: 200),
        patternHasher: patternHasher ?? Pbkdf2PatternHasher(iterations: 200),
        stateMachine: machine ??
            CredentialStateMachine(
              maxFailedAttempts: 3,
              lockoutDuration: const Duration(seconds: 30),
            ),
        biometricService: biometric,
        now: () => now,
        attemptObserver: observer,
      );

  SecuritySettingsRepository repo() => SecuritySettingsRepositoryImpl(db);

  Future<SecuritySettings> persisted() async =>
      (await SecuritySettingsRepositoryImpl(db).getSettings()).valueOrNull!;

  Future<Map<String, dynamic>> rawDoc() async =>
      (jsonDecode((await db.getSetting(_key))!) as Map<String, dynamic>)
          .cast<String, dynamic>();

  Future<CredentialChangeAuthorization> pinGrant(
    DefaultCredentialManager m, [
    String pin = _pin,
  ]) async =>
      (await m.verifyPinForCredentialChange(pin)).valueOrNull!.authorization!;

  Future<CredentialChangeAuthorization> patGrant(
    DefaultCredentialManager m, [
    List<int> nodes = _pat,
  ]) async =>
      (await m.verifyPatternForCredentialChange(nodes))
          .valueOrNull!
          .authorization!;

  setUp(() {
    db = _FaultDb();
    now = DateTime(2026, 11, 16, 10);
  });

  // ======================================================== pattern twins
  group('P-1..P-6 pattern twins of C-1..C-6', () {
    late _GatedPatternHasher hA;
    late _GatedPatternHasher hB;
    late DefaultCredentialManager a;
    late DefaultCredentialManager b;

    setUp(() async {
      hA = _GatedPatternHasher();
      hB = _GatedPatternHasher();
      a = build(repo(), patternHasher: hA);
      b = build(repo(), patternHasher: hB);
      expect((await a.enrollPattern(_pat)).isSuccess, isTrue);
    });

    Future<Future<Result<AuthAttemptResult>>> parkB(List<int> nodes) async {
      hB.gate.hold();
      final Future<Result<AuthAttemptResult>> f = b.authenticatePattern(nodes);
      await hB.gate.entered;
      return f;
    }

    test('P-1 no lost failed-attempt increment across instances', () async {
      final Future<Result<AuthAttemptResult>> fb = await parkB(_wrongPat);
      await a.authenticatePattern(_wrongPat);
      hB.gate.release();
      expect((await fb).valueOrNull, isA<AuthFailure>());
      expect((await persisted()).failedAttempts, 2);
    });

    test('P-2 lockout trips at the 3rd wrong pattern under concurrency',
        () async {
      int submitted = 0;
      int? lockedAt;
      for (int round = 0; round < 5 && lockedAt == null; round++) {
        final Future<Result<AuthAttemptResult>> fb = await parkB(_wrongPat);
        final AuthAttemptResult ra =
            (await a.authenticatePattern(_wrongPat)).valueOrNull!;
        submitted++;
        if (ra is AuthLockedOut) lockedAt = submitted;
        hB.gate.release();
        final AuthAttemptResult rb = (await fb).valueOrNull!;
        submitted++;
        if (lockedAt == null && rb is AuthLockedOut) lockedAt = submitted;
      }
      expect(lockedAt, 3);
    });

    test('P-3 an active lockout is never erased by a stale write', () async {
      await a.authenticatePattern(_wrongPat);
      final Future<Result<AuthAttemptResult>> fb = await parkB(_wrongPat);
      await a.authenticatePattern(_wrongPat);
      expect((await a.authenticatePattern(_wrongPat)).valueOrNull,
          isA<AuthLockedOut>());
      final SecuritySettings locked = await persisted();
      hB.gate.release();
      expect((await fb).valueOrNull, isA<AuthLockedOut>());
      final SecuritySettings s = await persisted();
      expect(s.lockedOutUntil, locked.lockedOutUntil);
      expect(s.lockoutStreak, locked.lockoutStreak);
      expect((await a.authenticatePattern(_pat)).valueOrNull,
          isA<AuthLockedOut>());
    });

    test('P-4 a pattern change is never reverted by a stale verification',
        () async {
      final CredentialChangeAuthorization g = await patGrant(a);
      final Future<Result<AuthAttemptResult>> fb = await parkB(_pat);
      expect((await a.enrollPattern(_newPat, authorization: g)).isSuccess,
          isTrue);
      hB.gate.release();
      final Result<AuthAttemptResult> late = await fb;
      // T4: the OLD pattern matched in B but the credential changed.
      expect(late.isFailure, isTrue);
      expect(late.errorOrNull, isA<CredentialChangedDuringVerification>());
      final DefaultCredentialManager c = build(repo());
      expect((await c.authenticatePattern(_newPat)).valueOrNull,
          isA<AuthSuccess>());
      expect((await c.authenticatePattern(_pat)).valueOrNull,
          isA<AuthFailure>());
    });

    test('P-5 Clear All is never undone by a stale verification', () async {
      final Future<Result<AuthAttemptResult>> fb = await parkB(_pat);
      expect((await a.clearAll()).isSuccess, isTrue);
      hB.gate.release();
      expect((await fb).isFailure, isTrue);
      final SecuritySettings s = await persisted();
      expect(s.patternHash, isNull);
      expect(s.pinHash, isNull);
    });

    test('P-6 a grant from B is stale after A changed the pattern', () async {
      final CredentialChangeAuthorization gB = await patGrant(b);
      final CredentialChangeAuthorization gA = await patGrant(a);
      expect((await a.enrollPattern(_newPat, authorization: gA)).isSuccess,
          isTrue);
      final Result<void> late =
          await b.enrollPattern(_wrongPat + <int>[5], authorization: gB);
      expect(late.isFailure, isTrue);
      expect(
        (late.errorOrNull! as CredentialChangeNotAuthorized).denial,
        CredentialChangeDenial.stale,
      );
      expect((await build(repo()).authenticatePattern(_newPat)).valueOrNull,
          isA<AuthSuccess>());
    });
  });

  // ============================================================ biometric
  group('B-1..B-6 biometric verdicts vs writes from another manager', () {
    late _GatedBiometric bio;
    late DefaultCredentialManager a;
    late DefaultCredentialManager b;

    setUp(() async {
      bio = _GatedBiometric();
      a = build(repo(), biometric: bio);
      b = build(repo(), biometric: _GatedBiometric());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      expect((await a.updateBiometricOptions(BiometricOptions.defaults))
          .isSuccess, isTrue);
      // One prior failure: a discarded success must not reset it.
      await a.authenticatePin(_wrong);
    });

    Future<Future<Result<AuthAttemptResult>>> openPrompt() async {
      bio.gate.hold();
      final Future<Result<AuthAttemptResult>> f = a.authenticateBiometric();
      await bio.gate.entered;
      return f;
    }

    test('B-1 success after a PIN change in B never authorizes', () async {
      final Future<Result<AuthAttemptResult>> f = await openPrompt();
      expect((await b.enrollPin(_newPin, authorization: await pinGrant(b)))
          .isSuccess, isTrue);
      await b.authenticatePin(_wrong); // counters after the change: 1
      bio.gate.release();
      final AuthAttemptResult r = (await f).valueOrNull!;
      expect(r, isNot(isA<AuthSuccess>()));
      expect((r as AuthFailure).reason, AuthFailureReason.cancelled);
      expect((await persisted()).failedAttempts, 1);
    });

    test('B-2 success after Clear All in B never authorizes', () async {
      final Future<Result<AuthAttemptResult>> f = await openPrompt();
      expect((await b.clearAll()).isSuccess, isTrue);
      bio.gate.release();
      final AuthAttemptResult r = (await f).valueOrNull!;
      expect((r as AuthFailure).reason, AuthFailureReason.notConfigured);
      final SecuritySettings s = await persisted();
      expect(s.pinHash, isNull);
      expect(s.biometricOptions, isNull);
    });

    test('B-3 success after biometric was turned off in B', () async {
      final Future<Result<AuthAttemptResult>> f = await openPrompt();
      expect((await b.updateBiometricOptions(null)).isSuccess, isTrue);
      bio.gate.release();
      final AuthAttemptResult r = (await f).valueOrNull!;
      expect((r as AuthFailure).reason, AuthFailureReason.notConfigured);
      expect((await persisted()).failedAttempts, 1);
    });

    test('B-4 success during a lockout begun meanwhile in B', () async {
      final Future<Result<AuthAttemptResult>> f = await openPrompt();
      await b.authenticatePin(_wrong);
      expect((await b.authenticatePin(_wrong)).valueOrNull,
          isA<AuthLockedOut>());
      final SecuritySettings locked = await persisted();
      bio.gate.release();
      expect((await f).valueOrNull, isA<AuthLockedOut>());
      final SecuritySettings s = await persisted();
      expect(s.lockedOutUntil, locked.lockedOutUntil);
      expect(s.failedAttempts, locked.failedAttempts);
      expect(s.lockoutStreak, locked.lockoutStreak);
    });

    test('B-5 options re-written to the SAME value in B: only the durable '
        'credential epoch differs -> stale prompt never authorizes', () async {
      final Future<Result<AuthAttemptResult>> f = await openPrompt();
      expect((await b.updateBiometricOptions(null)).isSuccess, isTrue);
      expect((await b.updateBiometricOptions(BiometricOptions.defaults))
          .isSuccess, isTrue);
      bio.gate.release();
      final AuthAttemptResult r = (await f).valueOrNull!;
      expect(r, isNot(isA<AuthSuccess>()));
      expect((r as AuthFailure).reason, AuthFailureReason.cancelled);
      expect((await persisted()).failedAttempts, 1);
    });

    test('B-6 a counted biometric rejection is never lost to a concurrent '
        'wrong PIN in B', () async {
      bio.outcome = Result.failure(
        const BiometricAuthException(code: 'x', message: 'x'),
      );
      final Future<Result<AuthAttemptResult>> f = await openPrompt();
      await b.authenticatePin(_wrong); // 1 -> 2 in B
      bio.gate.release();
      final AuthAttemptResult r = (await f).valueOrNull!;
      expect(r, isA<AuthLockedOut>()); // 3rd failure trips the lockout
      expect((await persisted()).lockoutStreak, 1);
    });

    test('B-7 CONTROL: an unraced biometric success still authorizes',
        () async {
      final Future<Result<AuthAttemptResult>> f = await openPrompt();
      bio.gate.release();
      expect((await f).valueOrNull, isA<AuthSuccess>());
      expect((await persisted()).failedAttempts, 0);
    });
  });

  // ============================================================== T-NS-*
  group('T-NS transitions', () {
    test('T-NS-2 threshold 3 and escalation streak equal the serial model',
        () async {
      // Serial reference on its own store.
      final _FaultDb serialDb = _FaultDb();
      final DefaultCredentialManager serial = build(
        SecuritySettingsRepositoryImpl(serialDb),
      );
      expect((await serial.enrollPin(_pin)).isSuccess, isTrue);
      final DateTime t0 = now;
      final List<String> serialTrace = <String>[];
      for (int cycle = 0; cycle < 3; cycle++) {
        for (int i = 0; i < 3; i++) {
          final AuthAttemptResult r =
              (await serial.authenticatePin(_wrong)).valueOrNull!;
          serialTrace.add(r is AuthLockedOut
              ? 'L${r.lockoutStreak}:${r.retryAt.difference(now).inSeconds}'
              : 'F');
        }
        now = now.add(const Duration(minutes: 11));
      }

      now = t0;
      final _GatedPinHasher hB = _GatedPinHasher();
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(repo(), pinHasher: hB);
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final List<String> trace = <String>[];
      String fmt(AuthAttemptResult r) => r is AuthLockedOut
          ? 'L${r.lockoutStreak}:${r.retryAt.difference(now).inSeconds}'
          : 'F';
      for (int cycle = 0; cycle < 3; cycle++) {
        // B parked across A's first attempt of every cycle.
        hB.gate.hold();
        final Future<Result<AuthAttemptResult>> fb = b.authenticatePin(_wrong);
        await hB.gate.entered;
        trace.add(fmt((await a.authenticatePin(_wrong)).valueOrNull!));
        hB.gate.release();
        trace.add(fmt((await fb).valueOrNull!));
        trace.add(fmt((await a.authenticatePin(_wrong)).valueOrNull!));
        now = now.add(const Duration(minutes: 11));
      }
      expect(trace, serialTrace);
      expect(serialTrace, <String>[
        'F', 'F', 'L1:30', //
        'F', 'F', 'L2:60', //
        'F', 'F', 'L3:120',
      ]);
    });

    test('T-NS-5 PIN replace vs stale verify/save at every await point: the '
        'old PIN never comes back', () async {
      // B (stale) parks at: its read, its KDF, its save; A changes the PIN.
      for (final (String op, int n) in <(String, int)>[
        ('get', 1),
        ('kdf', 0),
        ('save', 1),
      ]) {
        db = _FaultDb();
        final _GatedPinHasher hB = _GatedPinHasher();
        final _ParkingRepo pB = _ParkingRepo(repo());
        final DefaultCredentialManager a = build(repo());
        final DefaultCredentialManager b = build(pB, pinHasher: hB);
        expect((await a.enrollPin(_pin)).isSuccess, isTrue);
        for (final String input in <String>[_pin, _wrong]) {
          final Future<void> parked;
          if (op == 'kdf') {
            hB.gate.hold();
            parked = hB.gate.entered;
          } else {
            pB.parkOn(op, n);
            parked = pB.gate.entered;
          }
          final Future<Result<AuthAttemptResult>> fb = b.authenticatePin(input);
          await parked;
          final CredentialChangeAuthorization g = await pinGrant(a);
          final String next = '${op.length}${input.length}93';
          expect((await a.enrollPin(next, authorization: g)).isSuccess, isTrue,
              reason: '$op/$input');
          hB.gate.release();
          pB.gate.release();
          final Result<AuthAttemptResult> rb = await fb;
          expect(rb.valueOrNull, isNot(isA<AuthSuccess>()),
              reason: 'stale verification succeeded ($op/$input)');
          final DefaultCredentialManager c = build(repo());
          expect((await c.authenticatePin(next)).valueOrNull,
              isA<AuthSuccess>(),
              reason: 'changed PIN lost ($op/$input)');
          expect((await c.authenticatePin(_pin)).valueOrNull,
              isNot(isA<AuthSuccess>()),
              reason: 'old PIN restored ($op/$input)');
          // Re-enroll the base PIN for the second input.
          expect(
            (await a.enrollPin(_pin,
                    authorization: await pinGrant(a, next)))
                .isSuccess,
            isTrue,
          );
        }
      }
    });

    test('T-NS-5b a stale credential CHANGE parked at its save never lands '
        'over a newer change', () async {
      final _ParkingRepo pB = _ParkingRepo(repo());
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(pB);
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final CredentialChangeAuthorization gB = await pinGrant(b);
      final CredentialChangeAuthorization gA = await pinGrant(a);
      pB.parkOn('save', 1);
      final Future<Result<void>> fb = b.enrollPin('5555', authorization: gB);
      await pB.gate.entered;
      expect((await a.enrollPin(_newPin, authorization: gA)).isSuccess, isTrue);
      pB.gate.release();
      final Result<void> rb = await fb;
      expect(rb.isFailure, isTrue);
      expect((rb.errorOrNull! as CredentialChangeNotAuthorized).denial,
          CredentialChangeDenial.stale);
      final DefaultCredentialManager c = build(repo());
      expect((await c.authenticatePin(_newPin)).valueOrNull, isA<AuthSuccess>());
      expect((await c.authenticatePin('5555')).valueOrNull,
          isNot(isA<AuthSuccess>()));
    });

    test('T-NS-5c two concurrent INITIAL enrollments: exactly one wins',
        () async {
      final _ParkingRepo pB = _ParkingRepo(repo());
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(pB);
      pB.parkOn('save', 1);
      final Future<Result<void>> fb = b.enrollPin('5555');
      await pB.gate.entered;
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      pB.gate.release();
      final Result<void> rb = await fb;
      expect(rb.isFailure, isTrue);
      expect((await build(repo()).authenticatePin(_pin)).valueOrNull,
          isA<AuthSuccess>());
    });

    test('T-NS-6 Clear All vs a stale save: nothing resurrects; rev and '
        'credEpoch strictly increase', () async {
      final _ParkingRepo pB = _ParkingRepo(repo());
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(pB);
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final Map<String, dynamic> d0 = await rawDoc();
      pB.parkOn('save', 1);
      final Future<Result<AuthAttemptResult>> fb = b.authenticatePin(_pin);
      await pB.gate.entered;
      expect((await a.clearAll()).isSuccess, isTrue);
      final Map<String, dynamic> d1 = await rawDoc();
      pB.gate.release();
      expect((await fb).valueOrNull, isNot(isA<AuthSuccess>()));
      final Map<String, dynamic> d2 = await rawDoc();
      expect((await persisted()).pinHash, isNull);
      expect(d1['_rev'] as int, greaterThan(d0['_rev'] as int));
      expect(d1['_credEpoch'] as int, greaterThan(d0['_credEpoch'] as int));
      expect(d2['_rev'], d1['_rev']); // the stale write never landed
      // Clear All of an already-clear document still moves the epoch (T6).
      expect((await a.clearAll()).isSuccess, isTrue);
      final Map<String, dynamic> d3 = await rawDoc();
      expect(d3['_rev'] as int, greaterThan(d2['_rev'] as int));
      expect(d3['_credEpoch'] as int, greaterThan(d2['_credEpoch'] as int));
      expect(d3['_schema'], 2);
    });

    test('T-NS-7 a grant earned in A is stale after B changes the credential, '
        'even though A\'s in-memory epoch never moved', () async {
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final CredentialChangeAuthorization gA = await pinGrant(a);
      expect((await b.enrollPin(_newPin, authorization: await pinGrant(b)))
          .isSuccess, isTrue);
      final Result<void> late = await a.enrollPin('5555', authorization: gA);
      expect((late.errorOrNull! as CredentialChangeNotAuthorized).denial,
          CredentialChangeDenial.stale);
      expect((await build(repo()).authenticatePin(_newPin)).valueOrNull,
          isA<AuthSuccess>());
      // Owner decision 1b (CR-3): a biometric-options change in B moves the
      // credential epoch but NOT the secret epoch, so A's fresh grant stays
      // usable — exactly once (see CR-1b-*).
      final CredentialChangeAuthorization gA2 = await pinGrant(a, _newPin);
      expect((await b.updateBiometricOptions(BiometricOptions.defaults))
          .isSuccess, isTrue);
      expect((await a.enrollPin('5555', authorization: gA2)).isSuccess,
          isTrue);
      final Result<void> replay = await a.enrollPin('6666', authorization: gA2);
      expect((replay.errorOrNull! as CredentialChangeNotAuthorized).denial,
          CredentialChangeDenial.unknown);
      expect((await build(repo()).authenticatePin('5555')).valueOrNull,
          isA<AuthSuccess>());
    });

    test('T-NS-7b a grant is still usable after unrelated counter / '
        'cosmetic writes (no over-invalidation)', () async {
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final CredentialChangeAuthorization g = await pinGrant(a);
      await b.authenticatePin(_wrong);
      expect((await b.setRandomizedKeypadEnabled(true)).isSuccess, isTrue);
      expect((await a.enrollPin(_newPin, authorization: g)).isSuccess, isTrue);
    });

    test('T-NS-8 monotone guard: a next state with a lower counter fails '
        'closed and writes nothing', () async {
      final DefaultCredentialManager a = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      await a.authenticatePin(_wrong); // failed = 1 (honest machine)
      final String before = (await db.getSetting(_key))!;
      final _Observer obs = _Observer();
      final DefaultCredentialManager bad =
          build(repo(), machine: _RegressingMachine(), observer: obs);
      final Result<AuthAttemptResult> r = await bad.authenticatePin(_wrong);
      expect(r.isFailure, isTrue);
      expect(r.errorOrNull, isA<CredentialStateRegression>());
      expect(await db.getSetting(_key), before);
      expect(obs.attempts, isEmpty);
      // Unit form.
      final SecuritySettings s = await persisted();
      expect(
        DefaultCredentialManager.verdictRegression(
          s,
          s.copyWith(failedAttempts: 0),
          matches: false,
          now: now,
        ),
        'count',
      );
      expect(
        DefaultCredentialManager.verdictRegression(
          s,
          s.copyWith(failedAttempts: 2),
          matches: false,
          now: now,
        ),
        isNull,
      );
      expect(
        DefaultCredentialManager.updateRegression(
          s,
          s.copyWith(failedAttempts: 0),
          allowCounterReset: false,
        ),
        'counters',
      );
    });

    test('T-NS-9 lazy atomic migration; a newer schema is never overwritten',
        () async {
      // Legacy (pre-NF-NS-1) document: no envelope keys.
      final DefaultCredentialManager seed = build(repo());
      expect((await seed.enrollPin(_pin)).isSuccess, isTrue);
      final Map<String, dynamic> legacy = await rawDoc()
        ..remove('_rev')
        ..remove('_credEpoch')
        ..remove('_schema');
      await db.setSetting(_key, jsonEncode(legacy));
      final SecuritySettings read = await persisted();
      expect(read.revision, 0);
      expect(read.credentialEpoch, 0);
      expect(await db.getSetting(_key), jsonEncode(legacy)); // no write on read
      final DefaultCredentialManager a = build(repo());
      await a.authenticatePin(_wrong);
      final Map<String, dynamic> migrated = await rawDoc();
      expect(migrated['_schema'], 2);
      expect(migrated['_rev'], 1);
      expect(migrated['_credEpoch'], 0);
      expect(migrated['failedAttempts'], 1);

      // schema 3: fail closed, never written by any path.
      final String future = jsonEncode(<String, dynamic>{
        ...migrated,
        '_schema': 3,
        '_rev': 9,
      });
      await db.setSetting(_key, future);
      final int blind = db.blindSettingsWrites;
      final Result<SecuritySettings> r = await repo().getSettings();
      expect(r.errorOrNull, isA<UnsupportedSettingsSchema>());
      expect((await a.authenticatePin(_pin)).isFailure, isTrue);
      expect((await a.authenticatePin(_wrong)).isFailure, isTrue);
      expect((await a.clearAll()).isFailure, isTrue);
      expect((await a.enrollPin(_newPin)).isFailure, isTrue);
      expect((await a.setRandomizedKeypadEnabled(true)).isFailure, isTrue);
      expect(await db.getSetting(_key), future);
      expect(db.blindSettingsWrites, blind);
    });

    test('T-NS-10 slow KDF overlapping T5 / T6 / T10 -> T4: not counted, '
        'never a success, identical for matching and wrong input', () async {
      for (final String change in <String>['T5', 'T6', 'T10']) {
        final List<String> shapes = <String>[];
        for (final String input in <String>[_pin, _wrong]) {
          db = _FaultDb();
          final _GatedPinHasher hB = _GatedPinHasher();
          final DefaultCredentialManager a = build(repo());
          final _Observer obs = _Observer();
          final DefaultCredentialManager b =
              build(repo(), pinHasher: hB, observer: obs);
          expect((await a.enrollPin(_pin)).isSuccess, isTrue);
          await a.authenticatePin(_wrong); // failed = 1
          hB.gate.hold();
          final Future<Result<AuthAttemptResult>> fb = b.authenticatePin(input);
          await hB.gate.entered;
          switch (change) {
            case 'T5':
              expect((await a.enrollPin(_newPin,
                      authorization: await pinGrant(a)))
                  .isSuccess, isTrue);
            case 'T6':
              expect((await a.clearAll()).isSuccess, isTrue);
            case 'T10':
              expect((await a.updateBiometricOptions(BiometricOptions.defaults))
                  .isSuccess, isTrue);
          }
          final int failedBefore = (await persisted()).failedAttempts;
          final String before = (await db.getSetting(_key))!;
          hB.gate.release();
          final Result<AuthAttemptResult> rb = await fb;
          expect(rb.isFailure, isTrue, reason: '$change/$input');
          expect(rb.errorOrNull, isA<CredentialChangedDuringVerification>(),
              reason: '$change/$input');
          expect((await persisted()).failedAttempts, failedBefore,
              reason: 'T4 counted ($change/$input)');
          expect(await db.getSetting(_key), before,
              reason: 'T4 wrote ($change/$input)');
          expect(obs.attempts, isEmpty);
          shapes.add('${rb.isFailure}:${rb.errorOrNull.runtimeType}');
        }
        expect(shapes[0], shapes[1], reason: 'T4 response differs ($change)');
      }
    });

    test('T-NS-11a conflict x3 -> failure, no verdict, exactly 3 CAS attempts',
        () async {
      final _Observer obs = _Observer();
      final DefaultCredentialManager a = build(repo(), observer: obs);
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      db.fault = _Fault.conflictAlways;
      db.casCalls = 0;
      final Result<AuthAttemptResult> r = await a.authenticatePin(_pin);
      expect(r.isFailure, isTrue);
      expect(r.errorOrNull, isA<CredentialStateConflict>());
      expect(db.casCalls, DefaultCredentialManager.maxCommitAttempts);
      expect(DefaultCredentialManager.maxCommitAttempts, 3);
      expect(obs.attempts.single.counterPersisted, isFalse);
      // Same bound for a credential change and a cosmetic write.
      db.fault = _Fault.none;
      final CredentialChangeAuthorization g = await pinGrant(a);
      db.fault = _Fault.conflictAlways;
      db.casCalls = 0;
      expect((await a.enrollPin(_newPin, authorization: g)).errorOrNull,
          isA<CredentialStateConflict>());
      expect(db.casCalls, 3);
      db.casCalls = 0;
      expect((await a.setRandomizedKeypadEnabled(true)).errorOrNull,
          isA<CredentialStateConflict>());
      expect(db.casCalls, 3);
      expect(db.runawayRetry, isFalse);
      db.fault = _Fault.none;
      expect((await build(repo()).authenticatePin(_pin)).valueOrNull,
          isA<AuthSuccess>());
    },
        // Owner item 4: an unbounded retry loop (M-NS-14) must fail here
        // promptly, not hang the harness. The Timeout covers loops that do
        // yield; [_FaultDb.runawayCeiling] covers loops that never do.
        timeout: const Timeout(Duration(seconds: 20)));

    test('T-NS-11b UNKNOWN + landed -> verdict; UNKNOWN + not landed / '
        'unreadable -> no verdict', () async {
      final DefaultCredentialManager a = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);

      db.fault = _Fault.unknownLanded;
      expect((await a.authenticatePin(_wrong)).valueOrNull, isA<AuthFailure>());
      db.fault = _Fault.none;
      expect((await persisted()).failedAttempts, 1);

      db.fault = _Fault.unknownNotLanded;
      final Result<AuthAttemptResult> notLanded = await a.authenticatePin(_pin);
      expect(notLanded.isFailure, isTrue);
      expect(notLanded.errorOrNull, isA<CredentialStateUnknown>());
      db.fault = _Fault.none;
      expect((await persisted()).failedAttempts, 1);

      db.fault = _Fault.unknownUnreadable;
      final Result<AuthAttemptResult> unreadable =
          await a.authenticatePin(_pin);
      expect(unreadable.isFailure, isTrue);
      expect(unreadable.valueOrNull, isNull);
      db
        ..fault = _Fault.none
        ..failReads = false;
      expect((await persisted()).failedAttempts, 1);

      // A grant is never issued from an unconfirmed verification.
      db.fault = _Fault.unknownNotLanded;
      expect((await a.verifyPinForCredentialChange(_pin)).isFailure, isTrue);
      db.fault = _Fault.none;
    });

    test('T-NS-12b destroyed-engine queued write never lands over newer state',
        () async {
      final SecuritySettingsRepository engineA = repo();
      final DefaultCredentialManager b = build(repo());
      expect((await b.enrollPin(_pin)).isSuccess, isTrue);
      final SecuritySettings stale = (await engineA.getSettings()).valueOrNull!;
      await b.authenticatePin(_wrong);
      await b.authenticatePin(_wrong);
      final String newer = (await db.getSetting(_key))!;
      // The dead engine's queued write (counters from its old read).
      final Result<void> late = await engineA.saveSettings(
        stale.copyWith(failedAttempts: 0, clearLockout: true),
      );
      expect(late.errorOrNull, isA<SettingsWriteConflict>());
      expect(await db.getSetting(_key), newer);
      // A value never read from storage cannot overwrite either.
      final Result<void> blind =
          await engineA.saveSettings(SecuritySettings.defaults);
      expect(blind.errorOrNull, isA<SettingsWriteConflict>());
      expect(await db.getSetting(_key), newer);
      expect((await persisted()).failedAttempts, 2);
    });

    test('T-NS-13 restart / recovery: a new instance continues from the '
        'durable revision; old grants die with their instance', () async {
      final DefaultCredentialManager a = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      await a.authenticatePin(_wrong);
      db.fault = _Fault.unknownNotLanded;
      expect((await a.authenticatePin(_wrong)).isFailure, isTrue);
      db.fault = _Fault.none;
      final CredentialChangeAuthorization old = await pinGrant(a);
      final Map<String, dynamic> d0 = await rawDoc();
      // "Restart": a fresh repository + manager over the same store.
      final DefaultCredentialManager c = build(repo());
      expect((await c.enrollPin(_newPin, authorization: old)).errorOrNull,
          isA<CredentialChangeNotAuthorized>());
      expect((await c.authenticatePin(_wrong)).valueOrNull, isA<AuthFailure>());
      final Map<String, dynamic> d1 = await rawDoc();
      expect(d1['_rev'], (d0['_rev'] as int) + 1);
      expect(d1['_credEpoch'], d0['_credEpoch']);
      expect(d1['failedAttempts'], 1); // reset by the grant's success, +1
    });

    test('T-NS-14 cosmetic toggle racing a verdict in another manager: both '
        'land, nothing lost', () async {
      final _GatedPinHasher hB = _GatedPinHasher();
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(repo(), pinHasher: hB);
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      hB.gate.hold();
      final Future<Result<AuthAttemptResult>> fb = b.authenticatePin(_wrong);
      await hB.gate.entered;
      expect((await a.setPatternVisibilityEnabled(false)).isSuccess, isTrue);
      hB.gate.release();
      expect((await fb).valueOrNull, isA<AuthFailure>());
      final SecuritySettings s = await persisted();
      expect(s.failedAttempts, 1);
      expect(s.patternVisibilityEnabled, isFalse);
    });
  });
  // ======================================================== static guard
  group('T-NS-4 static guard: no blind writer of security_settings', () {
    List<File> libFiles() => Directory('lib')
        .listSync(recursive: true)
        .whereType<File>()
        .where((File f) => f.path.endsWith('.dart'))
        .toList();
    String norm(File f) => f.path.replaceAll(r'\', '/');
    const String repoImpl =
        'lib/data/repositories/impl/security_settings_repository_impl.dart';

    test('only the repository names the security_settings key outside '
        'storage; it never writes blindly and always uses CAS', () {
      final List<String> namers = <String>[
        for (final File f in libFiles())
          if (!norm(f).startsWith('lib/data/storage/') &&
              f.readAsStringSync().contains("'security_settings'"))
            norm(f),
      ];
      expect(namers, <String>[repoImpl]);
      final String src = File(repoImpl).readAsStringSync();
      expect(src, isNot(contains('setSetting(')));
      expect(src, isNot(contains('removeSetting(')));
      expect(src, contains('compareAndSetSetting('));
    });

    test('saveSettings is called only by the credential commit paths', () {
      final List<String> callers = <String>[
        for (final File f in libFiles())
          if (!norm(f).startsWith('lib/data/repositories/') &&
              f.readAsStringSync().contains('saveSettings('))
            norm(f),
      ]..sort();
      expect(callers, <String>[
        'lib/security/credentials/impl/default_credential_manager.dart',
        'lib/security/credentials/impl/default_pin_credential_store.dart',
      ]);
    });
  });

  // ===================================================== owner decision 1b
  group('CR-1b credential-secret epoch (owner decision 1: CR-3 preserved)',
      () {
    Future<(int, int, int)> epochs() async {
      final Map<String, dynamic> d = await rawDoc();
      return (
        d['_rev'] as int,
        d['_credEpoch'] as int,
        d['_secEpoch'] as int,
      );
    }

    test('CR-1b-1 a pending grant survives biometric enable / disable in the '
        'same AND in another manager, and stays single-use', () async {
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final CredentialChangeAuthorization g = await pinGrant(a);
      final (int _, int cred0, int sec0) = await epochs();
      expect((await a.updateBiometricOptions(BiometricOptions.defaults))
          .isSuccess, isTrue);
      expect((await b.updateBiometricOptions(null)).isSuccess, isTrue);
      expect((await b.updateBiometricOptions(
        const BiometricOptions(requireConfirmation: false),
      ))
          .isSuccess, isTrue);
      final (int _, int cred1, int sec1) = await epochs();
      expect(cred1, cred0 + 3, reason: 'biometric basis must still move');
      expect(sec1, sec0, reason: 'secret epoch must not move');
      expect((await a.enrollPin(_newPin, authorization: g)).isSuccess, isTrue);
      final Result<void> replay = await a.enrollPin('5555', authorization: g);
      expect((replay.errorOrNull! as CredentialChangeNotAuthorized).denial,
          CredentialChangeDenial.unknown);
      final DefaultCredentialManager fresh = build(repo());
      expect((await fresh.authenticatePin(_newPin)).valueOrNull,
          isA<AuthSuccess>());
      expect((await fresh.authenticatePin(_pin)).valueOrNull,
          isA<AuthFailure>());
    });

    test('CR-1b-2 grant expiry is preserved across a biometric-options change',
        () async {
      final DefaultCredentialManager a = build(repo());
      final DefaultCredentialManager b = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final CredentialChangeAuthorization g = await pinGrant(a);
      expect((await b.updateBiometricOptions(BiometricOptions.defaults))
          .isSuccess, isTrue);
      now = now.add(DefaultCredentialManager.credentialChangeAuthorizationTtl +
          const Duration(seconds: 1));
      final Result<void> late = await a.enrollPin(_newPin, authorization: g);
      expect((late.errorOrNull! as CredentialChangeNotAuthorized).denial,
          CredentialChangeDenial.expired);
      expect((await build(repo()).authenticatePin(_pin)).valueOrNull,
          isA<AuthSuccess>());
    });

    test('CR-1b-3 secret changes in another manager still make a grant stale: '
        'PIN replacement, pattern enrollment (primary change), Clear All',
        () async {
      for (final String change in <String>['pin', 'pattern', 'clear']) {
        db = _FaultDb();
        final DefaultCredentialManager a = build(repo());
        final DefaultCredentialManager b = build(repo());
        expect((await a.enrollPin(_pin)).isSuccess, isTrue);
        final CredentialChangeAuthorization g = await pinGrant(a);
        switch (change) {
          case 'pin':
            expect((await b.enrollPin(_newPin,
                    authorization: await pinGrant(b)))
                .isSuccess, isTrue, reason: change);
          case 'pattern':
            expect((await b.enrollPattern(_pat,
                    authorization: await pinGrant(b)))
                .isSuccess, isTrue, reason: change);
          case 'clear':
            expect((await b.clearAll()).isSuccess, isTrue);
            expect((await b.enrollPin(_newPin)).isSuccess, isTrue,
                reason: 'initial enrollment after Clear All');
        }
        final String before = (await db.getSetting(_key))!;
        final Result<void> late = await a.enrollPin('5555', authorization: g);
        expect(late.isFailure, isTrue, reason: change);
        expect((late.errorOrNull! as CredentialChangeNotAuthorized).denial,
            CredentialChangeDenial.stale, reason: change);
        expect(await db.getSetting(_key), before, reason: '$change wrote');
      }
    });

    test('CR-1b-4 durable epochs: _secEpoch moves only on secret / policy '
        'changes and Clear All; _credEpoch also on biometric options; rev on '
        'every commit; none ever decreases', () async {
      final DefaultCredentialManager a = build(repo());
      final List<(String, int, int, int)> trace = <(String, int, int, int)>[];
      Future<void> step(String name, Future<Object?> Function() op) async {
        await op();
        final (int r, int c, int e) = await epochs();
        trace.add((name, r, c, e));
      }

      await step('enrollPin', () => a.enrollPin(_pin));
      await step('wrong', () => a.authenticatePin(_wrong));
      await step('keypad', () => a.setRandomizedKeypadEnabled(true));
      await step('bioOn',
          () => a.updateBiometricOptions(BiometricOptions.defaults));
      await step('bioOff', () => a.updateBiometricOptions(null));
      await step('pattern', () async => a.enrollPattern(_pat,
          authorization: await pinGrant(a)));
      await step('policy', () async {
        final SecuritySettings s = await persisted();
        return repo().saveSettings(
          s.copyWith(maxFailedAttempts: s.maxFailedAttempts + 1),
        );
      });
      await step('clearAll', () => a.clearAll());

      // (credEpoch delta, secEpoch delta) per step after the first.
      const Map<String, (int, int)> expected = <String, (int, int)>{
        'wrong': (0, 0),
        'keypad': (0, 0),
        'bioOn': (1, 0),
        'bioOff': (1, 0),
        // The grant's own verification commits a verdict (+1 rev only).
        'pattern': (1, 1),
        'policy': (0, 1),
        'clearAll': (1, 1),
      };
      for (int i = 1; i < trace.length; i++) {
        final (String name, int r, int c, int e) = trace[i];
        final (String _, int r0, int c0, int e0) = trace[i - 1];
        expect(r, greaterThan(r0), reason: '$name rev');
        expect(c - c0, expected[name]!.$1, reason: '$name credEpoch');
        expect(e - e0, expected[name]!.$2, reason: '$name secEpoch');
      }
    });

    test('CR-1b-5 legacy / corrupt _secEpoch: a missing key reads 0, a '
        'negative value fails closed and is never overwritten', () async {
      final DefaultCredentialManager a = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      final Map<String, dynamic> d = await rawDoc();
      await db.setSetting(_key, jsonEncode(d..remove('_secEpoch')));
      expect((await persisted()).secretEpoch, 0);
      expect((await a.enrollPin(_newPin, authorization: await pinGrant(a)))
          .isSuccess, isTrue);
      expect((await rawDoc())['_secEpoch'], 1);

      final Map<String, dynamic> bad = await rawDoc();
      final String corrupt = jsonEncode(bad..['_secEpoch'] = -1);
      await db.setSetting(_key, corrupt);
      expect((await repo().getSettings()).isFailure, isTrue);
      final Result<AuthAttemptResult> r =
          await build(repo()).authenticatePin(_newPin);
      expect(r.isFailure, isTrue);
      expect(await db.getSetting(_key), corrupt);
    });

    test('CR-1b-6 fresh owner verification is still required: no grant, a '
        'failed verification or a superseded grant never authorizes',
        () async {
      final DefaultCredentialManager a = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      expect((await a.updateBiometricOptions(BiometricOptions.defaults))
          .isSuccess, isTrue);
      final Result<void> none = await a.enrollPin(_newPin);
      expect((none.errorOrNull! as CredentialChangeNotAuthorized).denial,
          CredentialChangeDenial.missing);
      expect((await a.verifyPinForCredentialChange(_wrong))
          .valueOrNull!
          .authorization, isNull);
      final CredentialChangeAuthorization g1 = await pinGrant(a);
      final CredentialChangeAuthorization g2 = await pinGrant(a);
      final Result<void> superseded =
          await a.enrollPin(_newPin, authorization: g1);
      expect((superseded.errorOrNull! as CredentialChangeNotAuthorized).denial,
          CredentialChangeDenial.unknown);
      expect((await a.enrollPin(_newPin, authorization: g2)).isSuccess, isTrue);
    });

    test('CR-1b-7 biometric keeps validating its FULL basis: a pending success '
        'is discarded after an options change to a different value',
        () async {
      final _GatedBiometric bio = _GatedBiometric();
      final _Observer obs = _Observer();
      final DefaultCredentialManager a =
          build(repo(), biometric: bio, observer: obs);
      final DefaultCredentialManager b = build(repo());
      expect((await a.enrollPin(_pin)).isSuccess, isTrue);
      expect((await a.updateBiometricOptions(BiometricOptions.defaults))
          .isSuccess, isTrue);
      await a.authenticatePin(_wrong); // failed = 1
      obs.attempts.clear();
      bio.gate.hold();
      final Future<Result<AuthAttemptResult>> f = a.authenticateBiometric();
      await bio.gate.entered;
      expect((await b.updateBiometricOptions(
        const BiometricOptions(requireConfirmation: false),
      ))
          .isSuccess, isTrue);
      final String before = (await db.getSetting(_key))!;
      bio.gate.release();
      final AuthAttemptResult r = (await f).valueOrNull!;
      expect(r, isNot(isA<AuthSuccess>()));
      expect((r as AuthFailure).reason, AuthFailureReason.cancelled);
      expect(await db.getSetting(_key), before);
      expect((await persisted()).failedAttempts, 1);
      expect(obs.attempts, isEmpty);
    });
  });

  // ====================================================== owner decision 3
  group('T4 credential changed during verification (owner decision 3)', () {
    test('T4-1 PIN: neutral failure, never access, uncounted, no intruder '
        'evidence (no verified attempt), no write — vs PIN change, Clear All',
        () async {
      for (final String change in <String>['pin', 'clear']) {
        for (final String input in <String>[_pin, _wrong]) {
          db = _FaultDb();
          final _GatedPinHasher hB = _GatedPinHasher();
          final _Observer obs = _Observer();
          final DefaultCredentialManager a = build(repo());
          final DefaultCredentialManager b =
              build(repo(), pinHasher: hB, observer: obs);
          expect((await a.enrollPin(_pin)).isSuccess, isTrue);
          await a.authenticatePin(_wrong); // failed = 1
          hB.gate.hold();
          final Future<Result<AuthAttemptResult>> fb = b.authenticatePin(input);
          await hB.gate.entered;
          if (change == 'pin') {
            expect((await a.enrollPin(_newPin,
                    authorization: await pinGrant(a)))
                .isSuccess, isTrue);
          } else {
            expect((await a.clearAll()).isSuccess, isTrue);
          }
          final String before = (await db.getSetting(_key))!;
          hB.gate.release();
          final Result<AuthAttemptResult> r = await fb;
          expect(r.isFailure, isTrue, reason: '$change/$input');
          expect(r.valueOrNull, isNull, reason: 'no verdict ($change/$input)');
          expect(r.errorOrNull, isA<CredentialChangedDuringVerification>());
          expect(r.errorOrNull.toString(), 'CredentialChangedDuringVerification',
              reason: 'neutral, data-free');
          expect(await db.getSetting(_key), before, reason: '$change/$input');
          expect(obs.attempts, isEmpty, reason: '$change/$input');
        }
      }
    });

    test('T4-2 pattern: neutral failure, never access, uncounted, no intruder '
        'evidence, no write — vs pattern change, Clear All, options change',
        () async {
      for (final String change in <String>['pattern', 'clear', 'options']) {
        for (final List<int> input in <List<int>>[_pat, _wrongPat]) {
          db = _FaultDb();
          final _GatedPatternHasher hB = _GatedPatternHasher();
          final _Observer obs = _Observer();
          final DefaultCredentialManager a = build(repo());
          final DefaultCredentialManager b =
              build(repo(), patternHasher: hB, observer: obs);
          expect((await a.enrollPattern(_pat)).isSuccess, isTrue);
          await a.authenticatePattern(_wrongPat); // failed = 1
          hB.gate.hold();
          final Future<Result<AuthAttemptResult>> fb =
              b.authenticatePattern(input);
          await hB.gate.entered;
          switch (change) {
            case 'pattern':
              expect((await a.enrollPattern(_newPat,
                      authorization: await patGrant(a)))
                  .isSuccess, isTrue);
            case 'clear':
              expect((await a.clearAll()).isSuccess, isTrue);
            case 'options':
              expect((await a.updateBiometricOptions(
                BiometricOptions.defaults,
              ))
                  .isSuccess, isTrue);
          }
          final int failedBefore = (await persisted()).failedAttempts;
          final String before = (await db.getSetting(_key))!;
          hB.gate.release();
          final Result<AuthAttemptResult> r = await fb;
          expect(r.isFailure, isTrue, reason: '$change/$input');
          expect(r.valueOrNull, isNull);
          expect(r.errorOrNull, isA<CredentialChangedDuringVerification>(),
              reason: '$change/$input');
          expect((await persisted()).failedAttempts, failedBefore);
          expect(await db.getSetting(_key), before, reason: '$change/$input');
          expect(obs.attempts, isEmpty, reason: '$change/$input');
        }
      }
    });

    test('T4-3 biometric: a success whose basis moved is discarded as an '
        'uncounted neutral failure (Gate B representation kept), never '
        'access, no intruder evidence, no write', () async {
      for (final String change in <String>['pin', 'clear', 'options']) {
        db = _FaultDb();
        final _GatedBiometric bio = _GatedBiometric();
        final _Observer obs = _Observer();
        final DefaultCredentialManager a =
            build(repo(), biometric: bio, observer: obs);
        final DefaultCredentialManager b = build(repo());
        expect((await a.enrollPin(_pin)).isSuccess, isTrue);
        expect((await a.updateBiometricOptions(BiometricOptions.defaults))
            .isSuccess, isTrue);
        await a.authenticatePin(_wrong); // failed = 1
        obs.attempts.clear();
        bio.gate.hold();
        final Future<Result<AuthAttemptResult>> f = a.authenticateBiometric();
        await bio.gate.entered;
        switch (change) {
          case 'pin':
            expect((await b.enrollPin(_newPin,
                    authorization: await pinGrant(b)))
                .isSuccess, isTrue);
          case 'clear':
            expect((await b.clearAll()).isSuccess, isTrue);
          case 'options':
            expect((await b.updateBiometricOptions(null)).isSuccess, isTrue);
            expect((await b.updateBiometricOptions(BiometricOptions.defaults))
                .isSuccess, isTrue);
        }
        final String before = (await db.getSetting(_key))!;
        final int failedBefore = (await persisted()).failedAttempts;
        bio.gate.release();
        final AuthAttemptResult r = (await f).valueOrNull!;
        expect(r, isNot(isA<AuthSuccess>()), reason: change);
        expect((r as AuthFailure).reason,
            change == 'clear'
                ? AuthFailureReason.notConfigured
                : AuthFailureReason.cancelled,
            reason: change);
        expect(r.reason, isNot(AuthFailureReason.wrongCredential));
        expect((await persisted()).failedAttempts, failedBefore);
        expect(await db.getSetting(_key), before, reason: change);
        expect(obs.attempts, isEmpty, reason: change);
      }
    });
  });
}
