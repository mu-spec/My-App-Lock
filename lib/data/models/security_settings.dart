import 'dart:convert';

import '../../security/credentials/auth_type.dart';
import '../../security/credentials/biometric_options.dart';
import '../../security/credentials/credential_hash.dart';
import '../../security/credentials/lockout_clock.dart';

/// All user-configurable security settings, persisted as one JSON document
/// in the local database (`security_settings` key-value table, encrypted at
/// rest — see Phase 1F).
///
/// Phase 2A adds the credential-state surface: enrolled credential hashes
/// (PIN + pattern), biometric configuration, the primary credential type,
/// and the attempt/lockout counters. This model only *stores* state — the
/// logic lives in the security module (`CredentialStateMachine`,
/// `CredentialManager`).
class SecuritySettings {
  const SecuritySettings({
    this.pinHash,
    this.patternHash,
    this.biometricOptions,
    this.primaryAuthType,
    this.intruderSelfieEnabled = false,
    this.breakInAlertsEnabled = false,
    this.stealthModeEnabled = false,
    this.uninstallProtectionEnabled = false,
    this.maxFailedAttempts = 5,
    this.lockoutDuration = const Duration(seconds: 30),
    this.unlockSessionWindow = const Duration(minutes: 2),
    this.failedAttempts = 0,
    this.lockedOutUntil,
    this.pinLength,
    this.lockoutStreak = 0,
    this.randomizedKeypadEnabled = false,
    this.patternVisibilityEnabled = true,
    this.lockoutAnchor,
    this.storedBasis,
    this.startsNewCredentialEpoch = false,
  });

  /// Factory-default settings (nothing configured yet).
  static const SecuritySettings defaults = SecuritySettings();

  /// Stored PIN credential (PBKDF2 hash) — null until a PIN is enrolled.
  final PinHash? pinHash;

  /// Stored pattern credential (PBKDF2 hash over the exact ordered node
  /// sequence — direction-sensitive).
  final CredentialHash? patternHash;

  /// Biometric accelerator configuration; null = biometric not configured.
  /// (The app never stores biometric secrets — the OS owns them.)
  final BiometricOptions? biometricOptions;

  /// Which credential acts as the primary fallback secret
  /// ([AuthType.pin] or [AuthType.pattern]).
  final AuthType? primaryAuthType;

  /// Snap a photo after repeated wrong-credential attempts.
  final bool intruderSelfieEnabled;

  /// Notify the owner about blocked attempts.
  final bool breakInAlertsEnabled;

  /// Hide the app from the launcher while protection is active.
  final bool stealthModeEnabled;

  /// Block casual uninstall while locks are active.
  final bool uninstallProtectionEnabled;

  /// Wrong attempts before the challenge locks out for a cooldown.
  final int maxFailedAttempts;

  /// Cooldown after too many failed attempts.
  final Duration lockoutDuration;

  /// How long a successful unlock keeps re-opening the same app free.
  final Duration unlockSessionWindow;

  /// Consecutive failed attempts since the last success.
  final int failedAttempts;

  /// When the current lockout expires (null = not locked out).
  final DateTime? lockedOutUntil;

  /// Length of the enrolled PIN (4 or 6). Recorded at enrollment so the
  /// unlock screen knows how many digits to expect without inspecting the
  /// stored hash.
  final int? pinLength;

  /// Consecutive lockout count (0 = none). Drives the escalating cooldown
  /// schedule (Phase 2F); persists so restarts do not reset it.
  final int lockoutStreak;

  /// Randomizes the unlock-screen keypad layout (Phase 2G). Off by default
  /// so the standard 1-9 layout stays the accessible baseline.
  final bool randomizedKeypadEnabled;

  /// Shows the pattern drawing trail while unlocking (Phase 2K). Default
  /// true (visible); turning it off hides the trail + node highlights for
  /// privacy (anti-shoulder-surfing).
  final bool patternVisibilityEnabled;

  /// Phase 18 / M1F (F18-2): monotonic-clock anchor of the current lockout
  /// (null = none, or a legacy document). Optional in the JSON document;
  /// older builds ignore it. See [LockoutClockPolicy].
  final LockoutAnchor? lockoutAnchor;

  /// P13/M3 NF-NS-1: the durable document this value was read from (null =
  /// not read from storage, e.g. [defaults] or a freshly built value).
  ///
  /// Never serialized by [toJson]: the repository keeps the revision fields
  /// in its own envelope and uses this basis to make every save a
  /// compare-and-set against the exact document the caller read. Preserved
  /// by [copyWith], so a read-modify-write keeps its basis.
  final StoredSettingsBasis? storedBasis;

  /// Transient (never serialized, not kept by [copyWith]): the next save
  /// moves the durable credential epoch even if the credential set looks
  /// unchanged (Clear All, design A T6). Moves [secretEpoch] too.
  final bool startsNewCredentialEpoch;

  /// Durable document revision of [storedBasis] (0 = absent or legacy).
  int get revision => storedBasis?.revision ?? 0;

  /// Durable credential-set epoch of [storedBasis] (0 = absent or legacy).
  /// Strictly increases whenever the stored credential set changes; it is
  /// never reset, so a grant or prompt bound to an older epoch can never
  /// match again.
  int get credentialEpoch => storedBasis?.credentialEpoch ?? 0;

  /// Canonical form of the credential set (hashes, biometric options,
  /// primary method, PIN length): a committed change of it moves the
  /// durable [credentialEpoch]. Never logged.
  String get credentialFingerprint {
    final Map<String, dynamic> j = toJson();
    return jsonEncode(<String, dynamic>{
      'pinHash': j['pinHash'],
      'patternHash': j['patternHash'],
      'biometricOptions': j['biometricOptions'],
      'primaryAuthType': j['primaryAuthType'],
      'pinLength': j['pinLength'],
    });
  }

  /// Durable credential-SECRET epoch of [storedBasis] (0 = absent or
  /// legacy). Owner decision 1b (CR-3): strictly increases whenever the
  /// credential secret or its authorization policy changes (PIN hash,
  /// pattern hash, primary method, PIN length, attempt policy) and on Clear
  /// All — but NOT on a biometric-options change. Credential-change grants
  /// are bound to it; biometric verdicts keep validating the full
  /// [credentialEpoch] basis. Never reset, so it can never match again once
  /// it has moved.
  int get secretEpoch => storedBasis?.secretEpoch ?? 0;

  /// Canonical form of the credential secret and its authorization policy:
  /// a committed change of it moves the durable [secretEpoch]. Never logged.
  String get secretFingerprint {
    final Map<String, dynamic> j = toJson();
    return jsonEncode(<String, dynamic>{
      'pinHash': j['pinHash'],
      'patternHash': j['patternHash'],
      'primaryAuthType': j['primaryAuthType'],
      'pinLength': j['pinLength'],
      'maxFailedAttempts': j['maxFailedAttempts'],
      'lockoutDurationSeconds': j['lockoutDurationSeconds'],
    });
  }

  /// This value with [basis]'s [storedBasis]: used to REPLACE a document
  /// wholesale (Clear All) while still conditioning the write on the exact
  /// document that was read. [newCredentialEpoch] forces the epoch move.
  SecuritySettings rebasedOn(
    SecuritySettings basis, {
    bool newCredentialEpoch = false,
  }) =>
      _withBasis(basis.storedBasis, newCredentialEpoch: newCredentialEpoch);

  /// Attaches the storage basis (repository use only).
  SecuritySettings withStoredBasis(StoredSettingsBasis basis) =>
      _withBasis(basis);

  SecuritySettings _withBasis(
    StoredSettingsBasis? basis, {
    bool newCredentialEpoch = false,
  }) =>
      SecuritySettings(
        pinHash: pinHash,
        patternHash: patternHash,
        biometricOptions: biometricOptions,
        primaryAuthType: primaryAuthType,
        intruderSelfieEnabled: intruderSelfieEnabled,
        breakInAlertsEnabled: breakInAlertsEnabled,
        stealthModeEnabled: stealthModeEnabled,
        uninstallProtectionEnabled: uninstallProtectionEnabled,
        maxFailedAttempts: maxFailedAttempts,
        lockoutDuration: lockoutDuration,
        unlockSessionWindow: unlockSessionWindow,
        failedAttempts: failedAttempts,
        lockedOutUntil: lockedOutUntil,
        pinLength: pinLength,
        lockoutStreak: lockoutStreak,
        randomizedKeypadEnabled: randomizedKeypadEnabled,
        patternVisibilityEnabled: patternVisibilityEnabled,
        lockoutAnchor: lockoutAnchor,
        storedBasis: basis,
        startsNewCredentialEpoch: newCredentialEpoch,
      );

  /// True once a PIN credential exists (the original primary secret).
  bool get hasPin => pinHash != null;

  /// True once a pattern credential exists.
  bool get hasPattern => patternHash != null;

  /// True when any credential is enrolled.
  bool get hasAnyCredential => hasPin || hasPattern;

  SecuritySettings copyWith({
    PinHash? pinHash,
    bool clearPin = false,
    CredentialHash? patternHash,
    bool clearPattern = false,
    BiometricOptions? biometricOptions,
    bool clearBiometricOptions = false,
    AuthType? primaryAuthType,
    bool clearPrimaryAuthType = false,
    bool? intruderSelfieEnabled,
    bool? breakInAlertsEnabled,
    bool? stealthModeEnabled,
    bool? uninstallProtectionEnabled,
    int? maxFailedAttempts,
    Duration? lockoutDuration,
    Duration? unlockSessionWindow,
    int? failedAttempts,
    DateTime? lockedOutUntil,
    bool clearLockout = false,
    int? pinLength,
    bool clearPinLength = false,
    int? lockoutStreak,
    bool? randomizedKeypadEnabled,
    bool? patternVisibilityEnabled,
    LockoutAnchor? lockoutAnchor,
    bool clearLockoutAnchor = false,
  }) {
    return SecuritySettings(
      pinHash: clearPin ? null : (pinHash ?? this.pinHash),
      patternHash: clearPattern ? null : (patternHash ?? this.patternHash),
      biometricOptions: clearBiometricOptions
          ? null
          : (biometricOptions ?? this.biometricOptions),
      primaryAuthType: clearPrimaryAuthType
          ? null
          : (primaryAuthType ?? this.primaryAuthType),
      intruderSelfieEnabled: intruderSelfieEnabled ?? this.intruderSelfieEnabled,
      breakInAlertsEnabled: breakInAlertsEnabled ?? this.breakInAlertsEnabled,
      stealthModeEnabled: stealthModeEnabled ?? this.stealthModeEnabled,
      uninstallProtectionEnabled:
          uninstallProtectionEnabled ?? this.uninstallProtectionEnabled,
      maxFailedAttempts: maxFailedAttempts ?? this.maxFailedAttempts,
      lockoutDuration: lockoutDuration ?? this.lockoutDuration,
      unlockSessionWindow: unlockSessionWindow ?? this.unlockSessionWindow,
      failedAttempts: failedAttempts ?? this.failedAttempts,
      lockedOutUntil:
          clearLockout ? null : (lockedOutUntil ?? this.lockedOutUntil),
      pinLength:
          clearPinLength ? null : (pinLength ?? this.pinLength),
      lockoutStreak: lockoutStreak ?? this.lockoutStreak,
      randomizedKeypadEnabled:
          randomizedKeypadEnabled ?? this.randomizedKeypadEnabled,
      patternVisibilityEnabled:
          patternVisibilityEnabled ?? this.patternVisibilityEnabled,
      // F18-2: an anchor never outlives its lockout.
      lockoutAnchor: clearLockout || clearLockoutAnchor
          ? null
          : (lockoutAnchor ?? this.lockoutAnchor),
      storedBasis: storedBasis,
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'pinHash': pinHash?.toJson(),
        'patternHash': patternHash?.toJson(),
        'biometricOptions': biometricOptions?.toJson(),
        'primaryAuthType': primaryAuthType?.storageName,
        'intruderSelfieEnabled': intruderSelfieEnabled,
        'breakInAlertsEnabled': breakInAlertsEnabled,
        'stealthModeEnabled': stealthModeEnabled,
        'uninstallProtectionEnabled': uninstallProtectionEnabled,
        'maxFailedAttempts': maxFailedAttempts,
        'lockoutDurationSeconds': lockoutDuration.inSeconds,
        'unlockSessionWindowSeconds': unlockSessionWindow.inSeconds,
        'failedAttempts': failedAttempts,
        'lockedOutUntilEpochMs': lockedOutUntil?.millisecondsSinceEpoch,
        'pinLength': pinLength,
        'lockoutStreak': lockoutStreak,
        'randomizedKeypadEnabled': randomizedKeypadEnabled,
        'patternVisibilityEnabled': patternVisibilityEnabled,
        // F18-2: written only while a lockout is anchored, so documents
        // without a lockout keep their existing shape.
        if (lockoutAnchor != null) 'lockoutAnchor': lockoutAnchor!.toJson(),
      };

  factory SecuritySettings.fromJson(Map<String, dynamic> json) =>
      SecuritySettings(
        pinHash: json['pinHash'] == null
            ? null
            : PinHash.fromJson(
                (json['pinHash'] as Map<String, dynamic>).cast<String, dynamic>(),
              ),
        patternHash: json['patternHash'] == null
            ? null
            : CredentialHash.fromJson(
                (json['patternHash'] as Map<String, dynamic>)
                    .cast<String, dynamic>(),
              ),
        biometricOptions: json['biometricOptions'] == null
            ? null
            : BiometricOptions.fromJson(
                (json['biometricOptions'] as Map<String, dynamic>)
                    .cast<String, dynamic>(),
              ),
        primaryAuthType: json['primaryAuthType'] == null
            ? null
            : AuthType.fromStorageName(json['primaryAuthType'] as String),
        intruderSelfieEnabled: json['intruderSelfieEnabled'] as bool? ?? false,
        breakInAlertsEnabled: json['breakInAlertsEnabled'] as bool? ?? false,
        stealthModeEnabled: json['stealthModeEnabled'] as bool? ?? false,
        uninstallProtectionEnabled:
            json['uninstallProtectionEnabled'] as bool? ?? false,
        maxFailedAttempts: json['maxFailedAttempts'] as int? ?? 5,
        lockoutDuration: Duration(
          seconds: json['lockoutDurationSeconds'] as int? ?? 30,
        ),
        unlockSessionWindow: Duration(
          seconds: json['unlockSessionWindowSeconds'] as int? ?? 120,
        ),
        failedAttempts: json['failedAttempts'] as int? ?? 0,
        lockedOutUntil: json['lockedOutUntilEpochMs'] == null
            ? null
            : DateTime.fromMillisecondsSinceEpoch(
                json['lockedOutUntilEpochMs'] as int,
              ),
        pinLength: json['pinLength'] as int?,
        lockoutStreak: json['lockoutStreak'] as int? ?? 0,
        randomizedKeypadEnabled:
            json['randomizedKeypadEnabled'] as bool? ?? false,
        patternVisibilityEnabled:
            json['patternVisibilityEnabled'] as bool? ?? true,
        lockoutAnchor: LockoutAnchor.fromJson(json['lockoutAnchor']),
      );

  @override
  String toString() => 'SecuritySettings(pin=${hasPin ? 'set' : 'not set'}, '
      'pattern=${hasPattern ? 'set' : 'not set'}, '
      'primary=${primaryAuthType?.name ?? 'none'}, '
      'intruderSelfie=$intruderSelfieEnabled, stealth=$stealthModeEnabled)';
}

/// P13/M3 NF-NS-1: identity of one durable settings document.
///
/// [raw] is the exact stored string (ciphertext in production) the value
/// was decoded from; the repository's compare-and-set uses it as the
/// expected value. [revision] strictly increases on every committed write
/// and [credentialEpoch] on every committed credential-set change; neither
/// is ever reset. Never persisted on its own and never logged.
final class StoredSettingsBasis {
  const StoredSettingsBasis({
    required this.raw,
    required this.revision,
    required this.credentialEpoch,
    required this.credentialFingerprint,
    required this.secretEpoch,
    required this.secretFingerprint,
  });

  final String raw;
  final int revision;
  final int credentialEpoch;

  /// Owner decision 1b: epoch of the credential secret + authorization
  /// policy only (see [SecuritySettings.secretEpoch]).
  final int secretEpoch;

  /// Canonical form of the stored credential secret + policy.
  final String secretFingerprint;

  /// Canonical form of the stored credential set (hashes, biometric
  /// options, primary method, PIN length); a change bumps the epoch.
  final String credentialFingerprint;

  @override
  String toString() => 'StoredSettingsBasis(rev=$revision, '
      'credEpoch=$credentialEpoch, secEpoch=$secretEpoch)';
}
