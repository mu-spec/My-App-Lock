/// Phase 18 / M1F (F18-3, owner-approved Option B): the Android Keystore key
/// that ties biometric unlock to the biometrics enrolled when it was enabled.
///
/// The key requires user authentication for every use and Android
/// invalidates it permanently when a new biometric is enrolled (and when
/// the device screen lock is removed). Biometric unlock is offered only
/// while the key is [BiometricKeyState.valid]; otherwise it is turned off
/// and can be re-enabled only through the Smart App Lock PIN/pattern
/// (`enableBiometricUnlock`). No device-credential fallback exists.
enum BiometricKeyState {
  /// The key exists and can be used (a prompt may be shown).
  valid,

  /// Android invalidated the key (new enrollment, screen lock removed, …).
  invalidated,

  /// No key (never created, or created by a build before this fix —
  /// owner decision D3-b: treated like [invalidated]).
  missing,

  /// The keystore could not be queried right now: biometrics unavailable
  /// for this attempt, nothing is changed and nothing is counted.
  error,
}

abstract interface class BiometricBinding {
  /// Replaces any existing key with a new one bound to the CURRENT
  /// enrollment. False when Android refuses (no secure lock screen, no
  /// Class 3 biometric, keystore error).
  Future<bool> createKey();

  Future<BiometricKeyState> checkKey();

  /// Best effort.
  Future<void> deleteKey();
}
