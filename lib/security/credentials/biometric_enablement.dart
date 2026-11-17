import '../../services/biometric_service.dart';
import '../../utilities/result.dart';
import 'auth_type.dart';
import 'biometric_options.dart';
import 'credential_manager.dart';
import 'credential_state.dart';

/// Result of [enableBiometricUnlock].
enum BiometricEnableOutcome {
  /// Biometric unlock is now enabled (biometric-only options saved).
  enabled,

  /// No PIN or pattern is set up yet.
  noCredential,

  /// The credential state could not be read (secure storage unavailable).
  storageUnavailable,

  /// No biometric hardware, or the capability query failed.
  unsupported,

  /// Hardware exists but no usable biometric is enrolled (a device screen
  /// lock alone never counts).
  notEnrolled,

  /// The primary app credential was not verified, or the credential state
  /// changed (or a lockout started) while verifying.
  notVerified,

  /// Saving the options failed.
  couldNotSave,

  /// The caller went away mid-flow ([stillActive] returned false). Nothing
  /// was saved by this call after that point.
  aborted,
}

/// H-3 biometric enablement, shared by the Security screen (Phase 2J/H-3)
/// and onboarding (Phase 15 / M1). Behaviour is unchanged from the Security
/// screen implementation it was extracted from:
///  1. a PIN or pattern must exist (state readable);
///  2. biometric hardware must be present;
///  3. a genuinely ENROLLED biometric is required
///     ([BiometricKind.strong]); [BiometricKind.deviceCredential] (a device
///     screen lock) never enables biometric unlock;
///  4. the configured PRIMARY app credential must be verified through
///     [verifyPrimary] (normal authentication; no CR-3 grant). It returns
///     the verified method, or null when not verified;
///  5. immediately before saving, the state is re-read: the primary must
///     still be the verified, enrolled method, with no active lockout, and
///     the biometric must still be enrolled;
///  6. options are biometric-only (`allowDeviceCredential: false`).
/// [stillActive] is checked after every await (widget `mounted`).
Future<BiometricEnableOutcome> enableBiometricUnlock({
  required CredentialManager auth,
  required BiometricService service,
  required Future<AuthType?> Function() verifyPrimary,
  required bool Function() stillActive,
  DateTime Function() now = DateTime.now,
}) async {
  final Result<CredentialState> statusResult = await auth.status();
  final CredentialState? state = statusResult.valueOrNull;
  if (!stillActive()) return BiometricEnableOutcome.aborted;
  if (state == null || !state.hasAnyCredential) {
    return statusResult.isFailure
        ? BiometricEnableOutcome.storageUnavailable
        : BiometricEnableOutcome.noCredential;
  }

  final Result<bool> supported = await service.isSupported();
  if (!stillActive()) return BiometricEnableOutcome.aborted;
  // `isSupported` = biometric HARDWARE present (true even with nothing
  // enrolled), so it is necessary but not sufficient.
  if (supported.isFailure || supported.valueOrNull != true) {
    return BiometricEnableOutcome.unsupported;
  }

  final Result<Set<BiometricKind>> available = await service.availableKinds();
  if (!stillActive()) return BiometricEnableOutcome.aborted;
  if (available.isFailure) {
    return BiometricEnableOutcome.unsupported;
  }
  if (!available.valueOrNull!.contains(BiometricKind.strong)) {
    return BiometricEnableOutcome.notEnrolled;
  }

  final AuthType? verifiedMethod = await verifyPrimary();
  if (!stillActive()) return BiometricEnableOutcome.aborted;
  if (verifiedMethod == null) {
    return BiometricEnableOutcome.notVerified;
  }

  // Re-check immediately before saving: the credential set or the device's
  // biometric enrollment may have changed while verification was open.
  final CredentialState? fresh = (await auth.status()).valueOrNull;
  if (!stillActive()) return BiometricEnableOutcome.aborted;
  final DateTime? lockedUntil = fresh?.lockedOutUntil;
  if (fresh == null ||
      fresh.primary != verifiedMethod ||
      !fresh.hasEnrolled(verifiedMethod) ||
      (lockedUntil != null && now().isBefore(lockedUntil))) {
    return BiometricEnableOutcome.notVerified;
  }
  final Result<Set<BiometricKind>> stillEnrolled =
      await service.availableKinds();
  if (!stillActive()) return BiometricEnableOutcome.aborted;
  if (stillEnrolled.isFailure ||
      !stillEnrolled.valueOrNull!.contains(BiometricKind.strong)) {
    return BiometricEnableOutcome.notEnrolled;
  }

  const BiometricOptions options = BiometricOptions(
    allowStrongBiometrics: true,
    // H-3: the device credential is never a substitute.
    allowDeviceCredential: false,
    requireConfirmation: true,
  );
  final Result<void> saved = await auth.updateBiometricOptions(options);
  if (!stillActive()) return BiometricEnableOutcome.aborted;
  return saved.isFailure
      ? BiometricEnableOutcome.couldNotSave
      : BiometricEnableOutcome.enabled;
}
