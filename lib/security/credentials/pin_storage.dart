import '../../data/models/security_settings.dart';
import '../../utilities/result.dart';
import '../pin_hasher.dart';

/// Secure PIN storage boundary.
///
/// **The raw PIN never crosses this boundary.** Callers hash first
/// ([PinHasher]) and hand over only the derived, verifiable [PinHash].
/// Implementations must:
///
///  * persist only the hash (salt + digest + parameters);
///  * validate the stored record against a [CredentialHashPolicy] on load
///    and fail closed when it is corrupted or weakened;
///  * never log or return raw credential material.
///
/// The production implementation stores the hash inside the encrypted
/// security settings document (Phase 1F chain: AES-256-GCM with a
/// Keystore-backed master key).
abstract interface class PinCredentialStore {
  /// Persists ONLY the derived [PinHash]. A hash that violates the storage
  /// policy is refused with a [Failure].
  /// Persists a PIN replacement atomically with the credential metadata
  /// needed by authentication. Implementations must not expose an
  /// intermediate state where the new PIN length/primary method is saved
  /// while the old hash is still active (or vice versa).
  Future<Result<void>> save(
    PinHash hash, {
    int? pinLength,
    bool makePrimary = false,
    bool resetAttemptState = false,
  });

  /// P13/M3 NF-NS-1: like [save], but applied to [basis] — the settings
  /// document the caller has ALREADY validated (authorization, lockout,
  /// credential epoch). The write is conditional on [basis] still being
  /// the durable document; a conflict is reported, never retried or
  /// re-based here, so the caller re-validates against fresh state.
  Future<Result<void>> saveOnto(
    SecuritySettings basis,
    PinHash hash, {
    int? pinLength,
    bool makePrimary = false,
    bool resetAttemptState = false,
  });

  /// Loads the stored hash for verification.
  ///
  /// Resolves to null when no PIN is enrolled; resolves to a [Failure] when
  /// the stored record fails the security policy (corrupted/weakened).
  Future<Result<PinHash?>> load();

  /// Removes the stored PIN credential.
  Future<Result<void>> delete();
}
