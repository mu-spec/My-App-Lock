import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';

import '../../../data/models/security_settings.dart';
import '../../../data/repositories/security_settings_repository.dart';
import '../../../services/biometric_service.dart';
import '../../../utilities/result.dart';
import '../../pin_hasher.dart';
import '../../pin_policy.dart';
import '../auth_result.dart';
import '../auth_type.dart';
import '../biometric_binding.dart';
import '../biometric_options.dart';
import '../credential_change_authorization.dart';
import '../credential_hash.dart';
import '../credential_state.dart';
import '../credential_state_errors.dart';
import '../lockout_clock.dart';
import '../credential_state_machine.dart';
import '../credential_manager.dart';
import '../credential_hash_policy.dart';
import '../pattern_hasher.dart';
import '../pattern_policy.dart';
import '../verified_attempt.dart';
import '../pin_storage.dart';
import 'default_pin_credential_store.dart';

/// Production [CredentialManager].
///
/// Pure Dart end-to-end: hashes credentials with PBKDF2, persists them
/// through the (encrypted) [SecuritySettingsRepository], and routes every
/// attempt through the [CredentialStateMachine] so lockouts survive app
/// restarts. Biometric authentication is delegated to a platform service
/// (wired in a later phase; until then attempts fail with
/// [AuthFailureReason.notAvailable]).
///
/// PIN credential material flows exclusively through the [PinCredentialStore]
/// (Phase 2D): the raw PIN is hashed in memory and only the derived hash
/// reaches persistence — never the PIN itself.
///
/// P13/M3 NF-NS-1: every write is a CONDITIONAL save of a next document
/// derived from a FRESH read (see [SecuritySettingsRepository.saveSettings]).
/// A conflict re-reads the durable state and re-evaluates from scratch — at
/// most [maxCommitAttempts] attempts, then the operation fails closed — so a
/// writer holding stale state (another manager, engine or process) can never
/// lose a failed attempt, lift a lockout, restore a replaced PIN or undo
/// Clear All. Change grants and biometric prompts are bound to the durable
/// credential epoch, which no instance can reuse. Slow PBKDF2 work runs
/// before the single compare-and-set statement: no database transaction is
/// held across it. The in-process [_SerialLock] is kept as a per-instance
/// optimisation only; correctness never depends on it.
class DefaultCredentialManager implements CredentialManager {
  DefaultCredentialManager({
    required SecuritySettingsRepository settings,
    PinHasher? pinHasher,
    PatternHasher? patternHasher,
    CredentialStateMachine? stateMachine,
    PinCredentialStore? pinStore,
    CredentialHashPolicy patternHashPolicy = CredentialHashPolicy.lenient,
    BiometricService? biometricService,
    DateTime Function()? now,
    VerifiedAttemptObserver? attemptObserver,
    MonotonicClock? lockoutClock,
    MonotonicClock? lockoutFallbackClock,
    LockoutClockLatch? lockoutClockLatch,
  })  : _settings = settings,
        _pinHasher = pinHasher ?? Pbkdf2PinHasher(),
        _patternHasher = patternHasher ?? Pbkdf2PatternHasher(),
        _machine = stateMachine ?? CredentialStateMachine(),
        _pinStore = pinStore ?? DefaultPinCredentialStore(settings),
        _patternHashPolicy = patternHashPolicy,
        _biometrics = biometricService,
        _now = now ?? DateTime.now,
        _observer = attemptObserver,
        _lockoutClock = lockoutClock == null
            ? null
            : FailClosedLockoutClock(
                lockoutClock,
                fallback: lockoutFallbackClock,
                latch: lockoutClockLatch,
              ),
        _instanceNonce = _newInstanceNonce();

  final SecuritySettingsRepository _settings;
  final PinHasher _pinHasher;
  final PatternHasher _patternHasher;
  final CredentialStateMachine _machine;
  final PinCredentialStore _pinStore;
  final CredentialHashPolicy _patternHashPolicy;

  /// Platform biometric service; null = not wired (attempts fail with
  /// [AuthFailureReason.notAvailable] — never a fabricated success).
  final BiometricService? _biometrics;

  /// Clock seam (Phase 2L QA): lockout timestamps come from here so tests
  /// can drive time deterministically; defaults to [DateTime.now].
  final DateTime Function() _now;

  /// Phase 18 / M1F (F18-2): monotonic clock for lockout timing, wrapped in
  /// [FailClosedLockoutClock]: an unavailable or malformed native clock
  /// falls back to the in-process monotonic clock, never to the wall clock
  /// (final corrections; replaces D2-a). Null only when no clock is
  /// configured (non-production constructors): the wall-clock rule.
  final MonotonicClock? _lockoutClock;

  /// Phase 12 / M1: observe-only sink for completed, counted verifications
  /// (the intruder monitor). Never awaited; exceptions are swallowed; it can
  /// never change a verdict.
  final VerifiedAttemptObserver? _observer;

  /// Phase 12 / M1: random per-instance prefix of every verification id, so
  /// ids stay unique across process recreation without using the clock.
  final String _instanceNonce;
  int _verificationSequence = 0;

  /// Phase 12 / M1 defect fix: every read-modify-write of the settings
  /// document (authentication counters, enrollment, preferences, clearAll)
  /// runs under ONE FIFO lock. Without it, concurrent verifications each
  /// loaded the same counters and overwrote one another — three concurrent
  /// wrong PINs persisted one failure and never tripped the lockout. A
  /// biometric system prompt is NEVER held under this lock (a stuck prompt
  /// must not block PIN entry); only its verdict is applied under it.
  final _SerialLock _lock = _SerialLock();

  /// P13/M3 NF-NS-1: bounded compare-and-set attempts per operation. After
  /// the last conflict the operation fails ([CredentialStateConflict]); no
  /// verdict is released and nothing is unlocked.
  static const int maxCommitAttempts = 3;

  /// Phase 12 / M1 gate B: the biometric "basis" epoch. Bumped (under
  /// [_lock], immediately before the write) by every credential-set or
  /// biometric-option write — enrollPin, enrollPattern, clearAll,
  /// updateBiometricOptions — whether or not the write lands. A biometric
  /// prompt captures it before it starts; a SUCCESS delivered after the
  /// epoch moved is stale and never authorizes. Separate from the CR-3
  /// [_credentialEpoch] so CR-3 grant semantics are untouched.
  int _biometricBasisEpoch = 0;

  static String _newInstanceNonce() {
    Random random;
    try {
      random = Random.secure();
    } on UnsupportedError {
      random = Random();
    }
    String part() => random.nextInt(1 << 32).toRadixString(16).padLeft(8, '0');
    return '${part()}${part()}';
  }

  // -- status -------------------------------------------------------------

  @override
  Future<Result<CredentialState>> status() async {
    // F18-2: lockout expiry follows the monotonic clock.
    final MonotonicReading? reading = await _reconcileLockout();
    final Result<SecuritySettings> loaded = await _settings.getSettings();
    return loaded.fold(
      (SecuritySettings s) =>
          Result.success(_stateFrom(_lockoutView(s, reading, _now()))),
      Result.failure,
    );
  }

  // -- enrollment ---------------------------------------------------------

  @override
  Future<Result<void>> enrollPin(
    String pin, {
    PinPolicy policy = PinPolicy.defaults,
    CredentialChangeAuthorization? authorization,
  }) =>
      _lock.run(() => _enrollPinLocked(pin, policy, authorization));

  Future<Result<void>> _enrollPinLocked(
    String pin,
    PinPolicy policy,
    CredentialChangeAuthorization? authorization,
  ) async {
    final PinValidation validation = policy.validate(pin);
    if (validation != PinValidation.valid) {
      return Result.failure(
        FormatException(policy.messageFor(validation)),
      );
    }
    // CR-3 write gate: runs before hashing and before any write.
    final Result<SecuritySettings> loaded = await _settings.getSettings();
    if (loaded.isFailure) {
      return Result.failure(loaded.errorOrNull!); // fail closed
    }
    final SecuritySettings s0 = loaded.valueOrNull!;
    // F18-2: the change gate's lockout check uses the monotonic view.
    final MonotonicReading? changeReading = await _readClock();
    final _ChangeGate gate =
        _consumeChangeAuthorization(s0, authorization, changeReading);
    final CredentialChangeNotAuthorized? denied = gate.denied;
    if (denied != null) {
      return Result.failure(denied);
    }
    // Slow KDF: no database transaction is open (the commit below is one
    // compare-and-set statement).
    final PinHash hash = await _pinHasher.hash(pin);

    // The hash and all metadata that describes it must land in ONE settings
    // write. Two writes can leave an old hash paired with a new length or
    // primary method when the second write fails.
    _biometricBasisEpoch++;
    final Result<void> saved = await _commitCredentialChange(
      s0,
      gate,
      (SecuritySettings basis) => _pinStore.saveOnto(
        basis,
        hash,
        pinLength: pin.length,
        makePrimary: true,
        resetAttemptState: true,
      ),
    );
    _credentialSetChanged();
    return saved;
  }

  @override
  Future<Result<void>> enrollPattern(
    List<int> nodes, {
    PatternPolicy policy = PatternPolicy.defaults,
    CredentialChangeAuthorization? authorization,
  }) =>
      _lock.run(() => _enrollPatternLocked(nodes, policy, authorization));

  Future<Result<void>> _enrollPatternLocked(
    List<int> nodes,
    PatternPolicy policy,
    CredentialChangeAuthorization? authorization,
  ) async {
    final PatternValidation validation = policy.validate(nodes);
    if (validation != PatternValidation.valid) {
      return Result.failure(
        FormatException(policy.messageFor(validation)),
      );
    }
    // CR-3 write gate: runs before hashing and before any write.
    final Result<SecuritySettings> gateLoaded = await _settings.getSettings();
    if (gateLoaded.isFailure) {
      return Result.failure(gateLoaded.errorOrNull!); // fail closed
    }
    final SecuritySettings s0 = gateLoaded.valueOrNull!;
    // F18-2: the change gate's lockout check uses the monotonic view.
    final MonotonicReading? changeReading = await _readClock();
    final _ChangeGate gate =
        _consumeChangeAuthorization(s0, authorization, changeReading);
    final CredentialChangeNotAuthorized? denied = gate.denied;
    if (denied != null) {
      return Result.failure(denied);
    }
    final CredentialHash hash = await _patternHasher.hash(nodes);
    _biometricBasisEpoch++;
    final Result<void> saved = await _commitCredentialChange(
      s0,
      gate,
      (SecuritySettings basis) => _settings.saveSettings(
        basis.copyWith(
          patternHash: hash,
          primaryAuthType: AuthType.pattern,
          failedAttempts: 0,
          clearLockout: true,
        ),
      ),
    );
    _credentialSetChanged();
    return saved;
  }

  @override
  Future<Result<void>> updateBiometricOptions(BiometricOptions? options) =>
      _lock.run(() {
        _biometricBasisEpoch++;
        return _conditionalUpdate(
          (SecuritySettings s) => options == null
              ? s.copyWith(clearBiometricOptions: true)
              : s.copyWith(biometricOptions: options),
        );
      });

  @override
  Future<Result<void>> setRandomizedKeypadEnabled(bool enabled) =>
      _lock.run(
        () => _conditionalUpdate(
          (SecuritySettings s) => s.copyWith(randomizedKeypadEnabled: enabled),
        ),
      );

  @override
  Future<Result<void>> setPatternVisibilityEnabled(bool enabled) =>
      _lock.run(
        () => _conditionalUpdate(
          (SecuritySettings s) =>
              s.copyWith(patternVisibilityEnabled: enabled),
        ),
      );

  // -- authentication -----------------------------------------------------

  @override
  Future<Result<AuthAttemptResult>> authenticatePin(String pin) {
    // Attribution is captured when the call STARTS (Phase 12 / M1).
    final AuthAttemptContext context = AuthAttemptContext.current;
    return _lock.run(() => _authenticatePinLocked(pin, context));
  }

  Future<Result<AuthAttemptResult>> _authenticatePinLocked(
    String pin,
    AuthAttemptContext context, [
    void Function(int secretEpoch)? onCommitted,
  ]) async {
    final MonotonicReading? reading = await _readClock();
    if (reading != null) await _writeLockoutAnchor(reading);
    final Result<PinHash?> loadedHash = await _pinStore.load();
    if (loadedHash.isFailure) {
      // Fail closed: corrupted/weakened stored credential.
      return Result.failure(loadedHash.errorOrNull!);
    }
    final PinHash? stored = loadedHash.valueOrNull;
    if (stored == null) {
      return Result.success(
        const AuthFailure(
          reason: AuthFailureReason.noCredentialEnrolled,
          remainingAttempts: 0,
        ),
      );
    }

    final Result<SecuritySettings> loaded = await _settings.getSettings();
    if (loaded.isFailure) {
      return Result.failure(loaded.errorOrNull!);
    }
    final SecuritySettings s = loaded.valueOrNull!;
    // The verification basis V: the hash verified below must be the one in
    // this document (two reads; a change in between is a T4 race).
    if (!_sameJson(s.pinHash?.toJson(), stored.toJson())) {
      return Result.failure(const CredentialChangedDuringVerification());
    }

    final DateTime checkedAt = _now();
    final CredentialState state =
        _stateFrom(_lockoutView(s, reading, checkedAt));
    final AuthLockedOut? activeLockout = _activeLockout(state, checkedAt);
    if (activeLockout != null) {
      return Result.success(activeLockout);
    }

    // Slow KDF outside any database transaction.
    final bool matches = await _pinHasher.verify(pin, stored);
    return _commitVerdict(
      first: s,
      matches: matches,
      type: AuthType.pin,
      context: context,
      onCommitted: onCommitted,
      // T4: the verified credential must still be the stored one on EVERY
      // attempt (fresh state after a conflict included).
      revalidate: (SecuritySettings fresh) => fresh.credentialEpoch !=
                  s.credentialEpoch ||
              !_sameJson(fresh.pinHash?.toJson(), stored.toJson())
          ? Result<AuthAttemptResult>.failure(
              const CredentialChangedDuringVerification(),
            )
          : null,
    );
  }

  @override
  Future<Result<AuthAttemptResult>> authenticatePattern(List<int> nodes) {
    final AuthAttemptContext context = AuthAttemptContext.current;
    return _lock.run(() => _authenticatePatternLocked(nodes, context));
  }

  Future<Result<AuthAttemptResult>> _authenticatePatternLocked(
    List<int> nodes,
    AuthAttemptContext context, [
    void Function(int secretEpoch)? onCommitted,
  ]) async {
    final MonotonicReading? reading = await _readClock();
    if (reading != null) await _writeLockoutAnchor(reading);
    final Result<SecuritySettings> loaded = await _settings.getSettings();
    if (loaded.isFailure) {
      return Result.failure(loaded.errorOrNull!);
    }
    final SecuritySettings s = loaded.valueOrNull!;
    final CredentialHash? patternHash = s.patternHash;
    // Fail closed: legacy (direction-insensitive) hashes are ambiguous and
    // must be re-enrolled — they are treated as not enrolled, never
    // verified against both orientations.
    if (patternHash == null || Pbkdf2PatternHasher.isLegacyHash(patternHash)) {
      return Result.success(
        const AuthFailure(
          reason: AuthFailureReason.noCredentialEnrolled,
          remainingAttempts: 0,
        ),
      );
    }
    final HashPolicyViolation? patternViolation =
        _patternHashPolicy.validate(patternHash);
    if (patternViolation != null) {
      return Result.failure(
        StateError(
          'Stored pattern credential failed the storage security policy '
          '(${patternViolation.name}). Re-enrollment required.',
        ),
      );
    }

    final DateTime checkedAt = _now();
    final CredentialState state =
        _stateFrom(_lockoutView(s, reading, checkedAt));
    final AuthLockedOut? activeLockout = _activeLockout(state, checkedAt);
    if (activeLockout != null) {
      return Result.success(activeLockout);
    }

    // Slow KDF outside any database transaction.
    final bool matches = await _patternHasher.verify(nodes, patternHash);
    return _commitVerdict(
      first: s,
      matches: matches,
      type: AuthType.pattern,
      context: context,
      onCommitted: onCommitted,
      revalidate: (SecuritySettings fresh) => fresh.credentialEpoch !=
                  s.credentialEpoch ||
              !_sameJson(fresh.patternHash?.toJson(), patternHash.toJson())
          ? Result<AuthAttemptResult>.failure(
              const CredentialChangedDuringVerification(),
            )
          : null,
    );
  }

  @override
  Future<Result<AuthAttemptResult>> authenticateBiometric({
    String reason = 'Unlock Smart App Lock',
  }) async {
    final AuthAttemptContext context = AuthAttemptContext.current;
    // Gate B: captured BEFORE the pre-prompt read, so any credential or
    // biometric-option write that could race the read is still detected.
    final int basisEpoch = _biometricBasisEpoch;
    final MonotonicReading? reading = await _reconcileLockout();
    // 1. Configuration gates: biometric is an accelerator — it needs the
    //    user's explicit opt-in AND an enrolled primary credential.
    final Result<SecuritySettings> loaded = await _settings.getSettings();
    if (loaded.isFailure) {
      return Result.failure(loaded.errorOrNull!);
    }
    final SecuritySettings s = loaded.valueOrNull!;
    final BiometricOptions? options = s.biometricOptions;
    if (options == null || !s.hasAnyCredential) {
      return Result.success(
        const AuthFailure(
          reason: AuthFailureReason.notConfigured,
          remainingAttempts: 0,
        ),
      );
    }

    final BiometricService? service = _biometrics;
    if (service == null) {
      return Result.success(
        const AuthFailure(
          reason: AuthFailureReason.notAvailable,
          remainingAttempts: 0,
        ),
      );
    }

    // 2. Lockout gates everything — even the correct biometric.
    final DateTime checkedAt = _now();
    final CredentialState state =
        _stateFrom(_lockoutView(s, reading, checkedAt));
    final AuthLockedOut? activeLockout = _activeLockout(state, checkedAt);
    if (activeLockout != null) {
      return Result.success(activeLockout);
    }

    // 2b. Phase 18 / M1F (F18-3): the Keystore binding key must still be
    //     valid. Android invalidates it when a biometric is enrolled after
    //     biometric unlock was enabled; a missing key (older builds, owner
    //     decision D3-b) is treated the same. Either turns biometric unlock
    //     off — re-enabling needs the app PIN/pattern. A keystore error
    //     only makes biometrics unavailable for this attempt.
    final BiometricBinding? binding =
        service is BiometricBinding ? service as BiometricBinding : null;
    if (binding != null) {
      switch (await binding.checkKey()) {
        case BiometricKeyState.valid:
          break;
        case BiometricKeyState.invalidated:
        case BiometricKeyState.missing:
          return Result.success(await _disableAfterEnrollmentChange(binding));
        case BiometricKeyState.error:
          return Result.success(
            const AuthFailure(
              reason: AuthFailureReason.notAvailable,
              remainingAttempts: 0,
            ),
          );
      }
    }

    // 3. Capability check (BiometricManager).
    final Result<bool> supported = await service.isSupported();
    if (supported.isFailure || supported.valueOrNull != true) {
      return Result.success(
        const AuthFailure(
          reason: AuthFailureReason.notAvailable,
          remainingAttempts: 0,
        ),
      );
    }

    // 4. Prompt (BiometricPrompt). The OS owns verification.
    final Result<bool> outcome =
        await service.authenticate(reason: reason, options: options);
    if (outcome.isFailure) {
      final Object? error = outcome.errorOrNull;
      // F18-3: the key was invalidated between the check and the prompt.
      if (binding != null &&
          error is BiometricAuthException &&
          error.code == BiometricAuthException.keyInvalidatedCode) {
        return Result.success(await _disableAfterEnrollmentChange(binding));
      }
      // Availability problems (no hardware, nothing enrolled, lockouts, ...)
      // are NOT authentication rejections — surface them without counting.
      if (error is BiometricAuthException && error.isAvailabilityError) {
        return Result.success(
          const AuthFailure(
            reason: AuthFailureReason.notAvailable,
            remainingAttempts: 0,
          ),
        );
      }
      // H-3: cancellation (Back, the prompt's Cancel button), system
      // cancellation and timeout end the prompt without a verdict. They
      // never grant access, and they are neither counted as a failed app
      // credential attempt nor allowed to reset existing counters or a
      // lockout: nothing is persisted. Cancelling reveals nothing about the
      // app PIN or pattern, and an active lockout still blocks the prompt
      // (step 2).
      if (error is BiometricAuthException && error.isCancellation) {
        return Result.success(
          AuthFailure(
            reason: AuthFailureReason.cancelled,
            remainingAttempts: _remainingAttempts(state),
          ),
        );
      }
      // Any other platform error is treated as a rejection and counts, so
      // a failing prompt can never be used to dodge the escalating lockout.
      return _evaluateLatestAndPersist(
        false,
        AuthType.biometric,
        context,
        promptBasis: s,
        basisEpoch: basisEpoch,
      );
    }

    // Phase 12 / M1: the verdict is applied to the CURRENT counters (re-read
    // under the lock), not the pre-prompt snapshot — a lockout that started
    // while the prompt was open still blocks, and a stale write can never
    // revert newer counters or credentials. H-3 branches above are unchanged.
    return _evaluateLatestAndPersist(
      outcome.valueOrNull == true,
      AuthType.biometric,
      context,
      promptBasis: s,
      basisEpoch: basisEpoch,
    );
  }

  // -- lifecycle ----------------------------------------------------------

  @override
  Future<Result<void>> clearAll() => _lock.run(_clearAllLocked);

  Future<Result<void>> _clearAllLocked() async {
    _biometricBasisEpoch++;
    _credentialSetChanged();
    // NF-NS-1 T6: defaults replace the document the clear was decided on;
    // the credential epoch moves (repository), so no stale writer can CAS
    // its old document back. An unreadable document is NOT overwritten
    // (fail closed; no blind write).
    final Result<void> saved = await _conditionalUpdate(
      (SecuritySettings s) =>
          SecuritySettings.defaults.rebasedOn(s, newCredentialEpoch: true),
      allowCounterReset: true,
    );
    _credentialSetChanged();
    return saved;
  }

  // -- CR-3: credential-change authorization ------------------------------

  /// How long a credential-change grant stays valid after verification.
  static const Duration credentialChangeAuthorizationTtl =
      Duration(minutes: 2);

  /// Live grants, keyed by handle identity. Memory only: a recreated
  /// process starts empty, so no grant survives process death.
  final Map<CredentialChangeAuthorization, _ChangeGrant> _changeGrants =
      Map<CredentialChangeAuthorization, _ChangeGrant>.identity();

  /// Bumped on every credential-set write (successful or not, because a
  /// failed write may still have partly landed). A grant is bound to the
  /// epoch it was issued in.
  int _credentialEpoch = 0;

  @override
  Future<Result<CredentialChangeAttempt>> verifyPinForCredentialChange(
    String pin,
  ) async {
    final AuthAttemptContext context = AuthAttemptContext.current;
    // The grant binds to the secret epoch of THE commit that released this
    // verdict (captured inside the lock, issued after it).
    int? committedEpoch;
    void sink(int epoch) => committedEpoch = epoch;
    final Result<AuthAttemptResult> attempt =
        await _lock.run(() => _authenticatePinLocked(pin, context, sink));
    return _issueOnSuccess(attempt, AuthType.pin, committedEpoch);
  }

  @override
  Future<Result<CredentialChangeAttempt>> verifyPatternForCredentialChange(
    List<int> nodes,
  ) async {
    final AuthAttemptContext context = AuthAttemptContext.current;
    // The grant binds to the secret epoch of THE commit that released this
    // verdict (captured inside the lock, issued after it).
    int? committedEpoch;
    void sink(int epoch) => committedEpoch = epoch;
    final Result<AuthAttemptResult> attempt =
        await _lock.run(() => _authenticatePatternLocked(nodes, context, sink));
    return _issueOnSuccess(attempt, AuthType.pattern, committedEpoch);
  }

  @override
  void revokeCredentialChangeAuthorization(
    CredentialChangeAuthorization authorization,
  ) {
    _changeGrants.remove(authorization);
  }

  Result<CredentialChangeAttempt> _issueOnSuccess(
    Result<AuthAttemptResult> attempt,
    AuthType method,
    int? durableEpoch,
  ) {
    if (attempt.isFailure) {
      return Result.failure(attempt.errorOrNull!);
    }
    final AuthAttemptResult result = attempt.valueOrNull!;
    if (result is! AuthSuccess || result.type != method) {
      return Result.success(CredentialChangeAttempt(result));
    }
    if (durableEpoch == null) {
      // A success is only ever released after its commit; without the
      // committed epoch no grant is issued (fail closed).
      return Result.success(CredentialChangeAttempt(result));
    }
    // At most one live grant: a new verification supersedes older ones.
    _changeGrants.clear();
    final CredentialChangeAuthorization handle =
        CredentialChangeAuthorization.handle(method: method);
    _changeGrants[handle] = _ChangeGrant(
      issuedAt: _now(),
      epoch: _credentialEpoch,
      secretEpoch: durableEpoch,
    );
    return Result.success(CredentialChangeAttempt(result, handle));
  }

  /// The CR-3 write gate. Its [_ChangeGate.denied] is null if the write
  /// may go ahead; the gate then records what every commit attempt must
  /// re-validate against FRESH state ([_revalidateChange]).
  ///
  /// When a usable app credential exists, the supplied grant is removed
  /// from the registry (consumed) BEFORE it is validated, so it can never be
  /// replayed, even after a denied or failed write.
  ///
  /// NF-NS-1: a grant is bound to the DURABLE credential-SECRET epoch it
  /// was earned under (never reused, valid across instances and processes;
  /// owner decision 1b: unaffected by biometric-options changes), in
  /// addition to this instance's epoch.
  _ChangeGate _consumeChangeAuthorization(
    SecuritySettings s,
    CredentialChangeAuthorization? authorization,
    MonotonicReading? reading,
  ) {
    final CredentialState state = _stateFrom(s);
    final bool hasExistingCredential =
        state.hasEnrolled(AuthType.pin) || state.hasEnrolled(AuthType.pattern);
    if (!hasExistingCredential) {
      // Initial enrollment: valid only while no credential appears.
      return _ChangeGate(epoch: s.secretEpoch, replacement: false);
    }
    if (authorization == null) {
      return _ChangeGate.denied(CredentialChangeDenial.missing);
    }
    final _ChangeGrant? grant = _changeGrants.remove(authorization);
    if (grant == null) {
      return _ChangeGate.denied(CredentialChangeDenial.unknown);
    }
    if (grant.epoch != _credentialEpoch ||
        grant.secretEpoch != s.secretEpoch) {
      return _ChangeGate.denied(CredentialChangeDenial.stale);
    }
    final DateTime now = _now();
    final Duration age = now.difference(grant.issuedAt);
    if (age.isNegative || age > credentialChangeAuthorizationTtl) {
      return _ChangeGate.denied(CredentialChangeDenial.expired);
    }
    if (_activeLockout(_stateFrom(_lockoutView(s, reading, now)), now) !=
        null) {
      return _ChangeGate.denied(CredentialChangeDenial.lockedOut);
    }
    return _ChangeGate(epoch: grant.secretEpoch, replacement: true);
  }

  /// Re-validates an admitted credential change against [fresh] durable
  /// state before EVERY commit attempt (never trusts the first read).
  CredentialChangeNotAuthorized? _revalidateChange(
    SecuritySettings fresh,
    _ChangeGate gate,
    MonotonicReading? reading,
  ) {
    // Any committed credential-secret change (any instance or process) since
    // the change was admitted makes it stale — also for initial enrollment,
    // where another enrollment would otherwise be silently replaced.
    if (fresh.secretEpoch != gate.epoch) {
      return const CredentialChangeNotAuthorized(CredentialChangeDenial.stale);
    }
    final DateTime now = _now();
    if (gate.replacement &&
        _activeLockout(_stateFrom(_lockoutView(fresh, reading, now)), now) !=
            null) {
      return const CredentialChangeNotAuthorized(
        CredentialChangeDenial.lockedOut,
      );
    }
    return null;
  }

  /// Commits an admitted credential change: [write] is applied to the
  /// re-validated basis; a conflict re-reads, re-validates and retries (at
  /// most [maxCommitAttempts]); a stale change is denied, never re-applied.
  Future<Result<void>> _commitCredentialChange(
    SecuritySettings first,
    _ChangeGate gate,
    Future<Result<void>> Function(SecuritySettings basis) write,
  ) async {
    SecuritySettings basis = first;
    for (int attempt = 1;; attempt++) {
      if (attempt > 1) {
        final Result<SecuritySettings> loaded = await _settings.getSettings();
        if (loaded.isFailure) {
          return Result.failure(loaded.errorOrNull!); // fail closed
        }
        basis = loaded.valueOrNull!;
      }
      final CredentialChangeNotAuthorized? denied =
          _revalidateChange(basis, gate, await _readClock());
      if (denied != null) {
        return Result.failure(denied);
      }
      final Result<void> saved = await write(basis);
      if (saved.isSuccess || saved.errorOrNull is! SettingsWriteConflict) {
        return _mapUnknown(saved);
      }
      if (attempt >= maxCommitAttempts) {
        return Result.failure(const CredentialStateConflict());
      }
    }
  }

  /// Read-modify-write of a document field set that carries no verdict
  /// ([change] is re-applied to FRESH state after a conflict; at most
  /// [maxCommitAttempts]; an unreadable document is never overwritten).
  Future<Result<void>> _conditionalUpdate(
    SecuritySettings Function(SecuritySettings s) change, {
    bool allowCounterReset = false,
  }) async {
    for (int attempt = 1;; attempt++) {
      final Result<SecuritySettings> loaded = await _settings.getSettings();
      if (loaded.isFailure) {
        return Result.failure(loaded.errorOrNull!); // fail closed
      }
      final SecuritySettings s = loaded.valueOrNull!;
      final SecuritySettings next = change(s);
      final String? regression =
          updateRegression(s, next, allowCounterReset: allowCounterReset);
      if (regression != null) {
        return Result.failure(CredentialStateRegression(regression));
      }
      final Result<void> saved = await _settings.saveSettings(next);
      if (saved.isSuccess || saved.errorOrNull is! SettingsWriteConflict) {
        return _mapUnknown(saved);
      }
      if (attempt >= maxCommitAttempts) {
        return Result.failure(const CredentialStateConflict());
      }
    }
  }

  void _credentialSetChanged() {
    _credentialEpoch++;
    _changeGrants.clear();
  }

  // -- internals ----------------------------------------------------------

  /// Projects persisted settings onto a [CredentialState] snapshot.
  ///
  /// Legacy (direction-insensitive) pattern hashes are excluded from the
  /// enrolled set so flows treat them as "set up the pattern again" —
  /// re-enrollment overwrites the record with the ordered scheme.
  CredentialState _stateFrom(SecuritySettings s) {
    final bool patternUsable = s.patternHash != null &&
        !Pbkdf2PatternHasher.isLegacyHash(s.patternHash!) &&
        _patternHashPolicy.validate(s.patternHash!) == null;
    final Set<AuthType> enrolled = <AuthType>{
      if (s.pinHash != null) AuthType.pin,
      if (patternUsable) AuthType.pattern,
      if (s.biometricOptions != null) AuthType.biometric,
    };
    final AuthType? primary = s.primaryAuthType ??
        (s.pinHash != null
            ? AuthType.pin
            : patternUsable
                ? AuthType.pattern
                : null);
    // A legacy primary falls back to PIN (or none).
    final AuthType? effectivePrimary =
        primary == AuthType.pattern && !patternUsable
            ? (s.pinHash != null ? AuthType.pin : null)
            : primary;
    return CredentialState(
      enrolled: enrolled,
      primary: effectivePrimary,
      failedAttempts: s.failedAttempts,
      lockedOutUntil: s.lockedOutUntil,
      pinLength: s.pinLength,
      lockoutStreak: s.lockoutStreak,
      randomizedKeypadEnabled: s.randomizedKeypadEnabled,
      patternVisibilityEnabled: s.patternVisibilityEnabled,
    );
  }

  /// Returns the active lockout (if any) — used to skip hashing while
  /// authentication is blocked.
  AuthLockedOut? _activeLockout(CredentialState state, DateTime now) {
    final DateTime? until = state.lockedOutUntil;
    if (until != null && now.isBefore(until)) {
      return AuthLockedOut(retryAt: until, lockoutStreak: state.lockoutStreak);
    }
    return null;
  }

  /// Phase 18 / M1F (F18-2): [s] with its lockout end translated into the
  /// wall-clock frame of [now] by [LockoutClockPolicy.effectiveUntil]. For
  /// decisions only; the document it returns is never written as-is except
  /// through a verdict that replaces the lockout fields.
  SecuritySettings _lockoutView(
    SecuritySettings s,
    MonotonicReading? reading,
    DateTime now,
  ) {
    final DateTime? until = LockoutClockPolicy.effectiveUntil(
      storedUntil: s.lockedOutUntil,
      anchor: s.lockoutAnchor,
      reading: reading,
      now: now,
    );
    return until == s.lockedOutUntil ? s : s.copyWith(lockedOutUntil: until);
  }

  Future<MonotonicReading?> _readClock() async {
    final MonotonicClock? clock = _lockoutClock;
    if (clock == null) return null;
    try {
      return await clock.read();
    } on Object {
      return null; // unreachable: FailClosedLockoutClock never throws
    }
  }

  /// Phase 18 / M1F (F18-2): the anchor the stored document needs for this
  /// boot (re-anchor after a reboot, legacy lockout anchored once, served
  /// lockout recorded), or null when the stored one is already right.
  LockoutAnchor? _anchorNeeded(SecuritySettings d, MonotonicReading reading) =>
      LockoutClockPolicy.reconcile(
        storedUntil: d.lockedOutUntil,
        anchor: d.lockoutAnchor,
        lockoutStreak: d.lockoutStreak,
        reading: reading,
        now: _now(),
        cooldownForStreak: _machine.cooldownForStreak,
      );

  /// Phase 18 / M1F (F18-2), for the unlocked paths (status, biometric):
  /// reads the clock and, only when the stored anchor is stale, takes the
  /// lock once to persist the fix. Best effort: when the write does not
  /// land, [_lockoutView] still fails closed (another boot reads as a full
  /// cooldown; a legacy lockout keeps the wall-clock rule).
  Future<MonotonicReading?> _reconcileLockout() async {
    final MonotonicReading? reading = await _readClock();
    if (reading == null) return null;
    final Result<SecuritySettings> loaded = await _settings.getSettings();
    if (loaded.isFailure) return reading;
    if (_anchorNeeded(loaded.valueOrNull!, reading) == null) return reading;
    await _lock.run(() => _writeLockoutAnchor(reading));
    return reading;
  }

  /// Phase 18 / M1F (F18-2): lock-held anchor write (NF-NS-1: called only
  /// from lock-held code). Re-evaluated against the fresh document inside
  /// the CAS; only the anchor changes (the [updateRegression] counter guard
  /// holds).
  Future<void> _writeLockoutAnchor(MonotonicReading reading) async {
    await _conditionalUpdate((SecuritySettings d) {
      final LockoutAnchor? anchor = _anchorNeeded(d, reading);
      return anchor == null ? d : d.copyWith(lockoutAnchor: anchor);
    });
  }

  /// Phase 18 / M1F (F18-3): biometric unlock is turned off after Android
  /// invalidated (or never had) the binding key. Same write as the Security
  /// screen's "disable" (basis epoch moves, so an in-flight prompt can never
  /// authorize); counters untouched. Nothing is counted and nothing is
  /// granted. If the write does not land, the next attempt detects the same
  /// key state again (still no biometric unlock).
  Future<AuthFailure> _disableAfterEnrollmentChange(
    BiometricBinding binding,
  ) async {
    await updateBiometricOptions(null);
    await binding.deleteKey();
    return const AuthFailure(
      reason: AuthFailureReason.notConfigured,
      remainingAttempts: 0,
    );
  }

  /// Attempts left before a lockout, without recording an attempt. Callers
  /// have already handled an ACTIVE lockout, so a non-null
  /// [CredentialState.lockedOutUntil] here is an expired one, which the
  /// state machine treats as a fresh count.
  int _remainingAttempts(CredentialState state) {
    final int used = state.lockedOutUntil != null ? 0 : state.failedAttempts;
    final int remaining = _machine.maxFailedAttempts - used;
    return remaining < 0 ? 0 : remaining;
  }

  /// Biometric verdicts: re-reads the settings under the lock and applies
  /// the verdict to the current counters (fails closed on a read failure).
  ///
  /// Gate B: a SUCCESS is discarded — no grant, no counter reset, nothing
  /// persisted, nothing reported — when, while the prompt was open,
  ///  * biometric unlock was disabled or every credential was cleared
  ///    (-> notConfigured, as the pre-prompt gate would answer), or
  ///  * the credential set / biometric options were written (basis epoch
  ///    moved — this instance's, or the DURABLE credential epoch, which
  ///    catches writes from any manager, engine or process) or now differ
  ///    from what the prompt started against (-> cancelled: the prompt
  ///    ended without a usable verdict).
  /// A REJECTION is always counted against the current counters, so a
  /// stale prompt can never reduce counting either. NF-NS-1: the checks
  /// are repeated on the fresh state of every commit attempt.
  Future<Result<AuthAttemptResult>> _evaluateLatestAndPersist(
    bool matches,
    AuthType type,
    AuthAttemptContext context, {
    required SecuritySettings promptBasis,
    required int basisEpoch,
  }) =>
      _lock.run(
        () => _commitVerdict(
          first: null, // re-read under the lock
          matches: matches,
          type: type,
          context: context,
          revalidate: (SecuritySettings s) {
            if (!matches) {
              return null;
            }
            if (s.biometricOptions == null || !s.hasAnyCredential) {
              return Result<AuthAttemptResult>.success(
                const AuthFailure(
                  reason: AuthFailureReason.notConfigured,
                  remainingAttempts: 0,
                ),
              );
            }
            if (basisEpoch != _biometricBasisEpoch ||
                s.credentialEpoch != promptBasis.credentialEpoch ||
                _biometricBasisOf(promptBasis) != _biometricBasisOf(s)) {
              return Result<AuthAttemptResult>.success(
                AuthFailure(
                  reason: AuthFailureReason.cancelled,
                  remainingAttempts: _remainingAttempts(_stateFrom(s)),
                ),
              );
            }
            return null;
          },
        ),
      );

  /// What a biometric prompt authorizes against: the enrolled credential
  /// material, the biometric options and the primary method. Compared as
  /// canonical JSON (catches writes from any manager instance).
  static String _biometricBasisOf(SecuritySettings s) {
    final Map<String, dynamic> j = s.toJson();
    return jsonEncode(<String, dynamic>{
      'pinHash': j['pinHash'],
      'patternHash': j['patternHash'],
      'biometricOptions': j['biometricOptions'],
      'primaryAuthType': j['primaryAuthType'],
    });
  }

  static bool _sameJson(Object? a, Object? b) =>
      jsonEncode(a) == jsonEncode(b);

  /// Runs the state machine and persists the resulting counters. Always
  /// called under [_lock]. This is the ONE place a counted verdict exists,
  /// so it is the one place the [_observer] hears about it — after the
  /// counter write, so a lost event can never mean a lost counter.
  ///
  /// NF-NS-1 (T1/T2/T7/T8): [first] is the state the verification started
  /// from (null = read now). Every write is a conditional save of a next
  /// state derived from that exact document. A conflict means another
  /// writer committed in between: the state is re-read, [revalidate]
  /// re-checked (T4: credential changed -> no verdict) and the verdict
  /// re-evaluated from scratch, so a concurrent failure is never lost and
  /// escalation is computed from the newest counters. At most
  /// [maxCommitAttempts]; after that, or on any other save failure
  /// (including an unconfirmed outcome), NO verdict is released.
  /// [verdictRegression] refuses any next state that would weaken the
  /// state it was derived from.
  Future<Result<AuthAttemptResult>> _commitVerdict({
    required SecuritySettings? first,
    required bool matches,
    required AuthType type,
    required AuthAttemptContext context,
    required Result<AuthAttemptResult>? Function(SecuritySettings s)
        revalidate,
    void Function(int secretEpoch)? onCommitted,
  }) async {
    SecuritySettings? current = first;
    for (int attempt = 1;; attempt++) {
      if (current == null) {
        final Result<SecuritySettings> loaded = await _settings.getSettings();
        if (loaded.isFailure) {
          return Result<AuthAttemptResult>.failure(loaded.errorOrNull!);
        }
        current = loaded.valueOrNull!;
      }
      final SecuritySettings s = current;
      final Result<AuthAttemptResult>? stop = revalidate(s);
      if (stop != null) {
        return stop;
      }
      // F18-2: every lockout decision below uses the monotonic view of the
      // fresh document (wall-clock rule only when no reading exists).
      final MonotonicReading? reading = await _readClock();
      final DateTime now = _now();
      final SecuritySettings view = _lockoutView(s, reading, now);
      // T3: a lockout that started meanwhile (fresh state) refuses the
      // attempt, as the pre-verification check would: no write.
      final AuthLockedOut? lockedNow = _activeLockout(_stateFrom(view), now);
      if (lockedNow != null) {
        return Result<AuthAttemptResult>.success(lockedNow);
      }
      final (CredentialState next, AuthAttemptResult result) =
          _machine.evaluate(
        state: _stateFrom(view),
        credentialMatches: matches,
        attemptType: type,
        now: now,
      );
      final DateTime? newUntil = next.lockedOutUntil;
      final bool startsLockout =
          newUntil != null && newUntil != view.lockedOutUntil;
      final SecuritySettings nextDoc = view.copyWith(
        failedAttempts: next.failedAttempts,
        lockedOutUntil: newUntil,
        clearLockout: newUntil == null,
        lockoutStreak: next.lockoutStreak,
        // F18-2: a new lockout is anchored on the monotonic clock in the
        // same compare-and-set write (no reading only without a clock).
        lockoutAnchor: startsLockout && reading != null
            ? LockoutAnchor.start(reading, now, newUntil.difference(now))
            : null,
        clearLockoutAnchor: startsLockout && reading == null,
      );
      final String? regression =
          verdictRegression(view, nextDoc, matches: matches, now: now);
      if (regression != null) {
        return Result<AuthAttemptResult>.failure(
          CredentialStateRegression(regression),
        );
      }
      final Result<void> saved = await _settings.saveSettings(nextDoc);
      if (saved.isFailure &&
          saved.errorOrNull is SettingsWriteConflict &&
          attempt < maxCommitAttempts) {
        current = null; // re-read and re-evaluate from scratch
        continue;
      }
      _notifyObserver(
        VerifiedAttempt(
          verificationId: '$_instanceNonce:${++_verificationSequence}',
          type: type,
          matched: matches,
          result: result,
          counterPersisted: saved.isSuccess,
          lockoutStreak: next.lockoutStreak,
          context: context,
          at: now,
        ),
      );
      if (saved.isFailure) {
        final Object error = saved.errorOrNull!;
        return Result<AuthAttemptResult>.failure(
          switch (error) {
            SettingsWriteConflict() => const CredentialStateConflict(),
            SettingsWriteUnknown() => const CredentialStateUnknown(),
            _ => error,
          },
        );
      }
      onCommitted?.call(s.secretEpoch);
      return Result<AuthAttemptResult>.success(result);
    }
  }

  /// Maps an unconfirmed write to [CredentialStateUnknown] (fail closed).
  static Result<void> _mapUnknown(Result<void> saved) =>
      saved.errorOrNull is SettingsWriteUnknown
          ? Result<void>.failure(const CredentialStateUnknown())
          : saved;

  /// NF-NS-1 monotonicity guard for writes that carry no verdict: the
  /// basis is kept and, unless [allowCounterReset] (Clear All: defaults by
  /// definition), the lockout counters are untouched.
  static String? updateRegression(
    SecuritySettings basis,
    SecuritySettings next, {
    required bool allowCounterReset,
  }) {
    if (!identical(next.storedBasis, basis.storedBasis)) {
      return 'basis';
    }
    if (allowCounterReset) {
      return null;
    }
    if (next.failedAttempts != basis.failedAttempts ||
        next.lockoutStreak != basis.lockoutStreak ||
        next.lockedOutUntil != basis.lockedOutUntil) {
      return 'counters';
    }
    return anchorUpdateRegression(basis, next);
  }

  /// Phase 18 / M1F (F18-2): the only anchor changes a write without a
  /// verdict may make are the manager's reconcile results — never removing
  /// an anchor (that would fall back to the wall clock), never creating one
  /// without a stored lockout, never shortening an unserved lockout, and
  /// marking a lockout served only by flipping that one flag. (Whether the
  /// cooldown really elapsed needs a clock reading; that is the policy's
  /// job — this is defence in depth against a weakened write.)
  static String? anchorUpdateRegression(
    SecuritySettings basis,
    SecuritySettings next,
  ) {
    final LockoutAnchor? was = basis.lockoutAnchor;
    final LockoutAnchor? now = next.lockoutAnchor;
    if (now == was) return null;
    if (basis.lockedOutUntil == null || now == null) return 'anchor';
    if (was != null && was.served) return 'anchor';
    if (now.served) {
      return was != null && now == was.asServed() ? null : 'anchor';
    }
    if (was != null && now.durationMs < was.durationMs) return 'anchor';
    return null;
  }

  /// NF-NS-1 monotonicity guard (defence in depth): returns the violated
  /// rule, or null when [next] — derived from [basis] for ONE verdict at
  /// [now] — never weakens it.
  ///
  ///  * a verdict keeps the basis and never touches the credential set;
  ///  * during an active lockout nothing changes (the attempt is refused);
  ///  * a rejection counts: the streak never drops, the attempt counter
  ///    strictly grows from its effective value (an expired lockout starts
  ///    a fresh count, as the established policy defines) and any new
  ///    lockout ends in the future;
  ///  * only a match may reset counters (outside an active lockout).
  static String? verdictRegression(
    SecuritySettings basis,
    SecuritySettings next, {
    required bool matches,
    required DateTime now,
  }) {
    if (!identical(next.storedBasis, basis.storedBasis)) {
      return 'basis';
    }
    if (basis.credentialFingerprint != next.credentialFingerprint) {
      return 'credential';
    }
    final DateTime? until = basis.lockedOutUntil;
    if (until != null && now.isBefore(until)) {
      return next.failedAttempts == basis.failedAttempts &&
              next.lockedOutUntil == until &&
              next.lockoutStreak == basis.lockoutStreak &&
              next.lockoutAnchor == basis.lockoutAnchor
          ? null
          : 'lockout';
    }
    if (matches) {
      return null;
    }
    if (next.lockoutStreak < basis.lockoutStreak) {
      return 'streak';
    }
    final int effective = until != null ? 0 : basis.failedAttempts;
    if (next.failedAttempts <= effective) {
      return 'count';
    }
    final DateTime? newUntil = next.lockedOutUntil;
    if (newUntil != null && !newUntil.isAfter(now)) {
      return 'lockout';
    }
    // F18-2: a new lockout's anchor (absent only when no clock is
    // configured) starts now, unserved, for exactly the new cooldown.
    final LockoutAnchor? anchor = next.lockoutAnchor;
    if (newUntil != null &&
        newUntil != until &&
        anchor != null &&
        (anchor.served ||
            anchor.wallMs != now.millisecondsSinceEpoch ||
            anchor.durationMs != newUntil.difference(now).inMilliseconds)) {
      return 'anchor';
    }
    return null;
  }

  /// Observe-only: synchronous, never awaited, never allowed to throw into
  /// the authentication path (monitoring can never override enforcement).
  void _notifyObserver(VerifiedAttempt attempt) {
    final VerifiedAttemptObserver? observer = _observer;
    if (observer == null) {
      return;
    }
    try {
      observer.onVerifiedAttempt(attempt);
    } catch (_) {
      // Deliberately ignored: a failing monitor must not affect the verdict.
    }
  }
}

/// Phase 12 / M1: minimal FIFO async mutex. Actions run one at a time in
/// call order; an action's failure never wedges the queue.
///
/// Zone-safe by construction: an uncontended action starts immediately in
/// the caller's zone, and each waiter parks on a [Completer] created in ITS
/// OWN zone, handed the lock directly on release. No future is ever shared
/// across callers (a completed future schedules its listeners in the zone
/// that created it, which can stall callers from another zone).
final class _SerialLock {
  bool _held = false;
  final Queue<Completer<void>> _waiters = Queue<Completer<void>>();

  Future<T> run<T>(Future<T> Function() action) async {
    if (_held) {
      final Completer<void> turn = Completer<void>();
      _waiters.add(turn);
      await turn.future; // ownership is handed over; _held stays true
    } else {
      _held = true;
    }
    try {
      return await action();
    } finally {
      if (_waiters.isEmpty) {
        _held = false;
      } else {
        _waiters.removeFirst().complete();
      }
    }
  }
}

/// CR-3: registry entry backing a live [CredentialChangeAuthorization].
final class _ChangeGrant {
  const _ChangeGrant({
    required this.issuedAt,
    required this.epoch,
    required this.secretEpoch,
  });

  final DateTime issuedAt;

  /// This instance's in-memory epoch at issue.
  final int epoch;

  /// NF-NS-1 / owner decision 1b: the DURABLE credential-SECRET epoch the
  /// verification committed under. Never reused, so it can never match
  /// again once it has moved; a biometric-options change does not move it
  /// (CR-3: a pending grant survives the F4 flow).
  final int secretEpoch;
}

/// CR-3 / NF-NS-1: outcome of admitting a credential change.
final class _ChangeGate {
  const _ChangeGate({required this.epoch, required this.replacement})
      : denied = null;

  _ChangeGate.denied(CredentialChangeDenial denial)
      : denied = CredentialChangeNotAuthorized(denial),
        epoch = -1,
        replacement = true;

  /// Non-null when the change is refused.
  final CredentialChangeNotAuthorized? denied;

  /// Durable credential-SECRET epoch every commit attempt must still see.
  final int epoch;

  /// True when an existing credential is being replaced (lockout gates it).
  final bool replacement;
}
