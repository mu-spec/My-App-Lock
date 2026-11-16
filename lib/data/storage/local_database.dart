import '../models/app_security_level.dart';
import '../models/protected_app.dart';
import '../../profiles/lock_profile.dart';
import '../../rules/lock_rule.dart';

/// Local database boundary — the single on-device store for everything the
/// app persists beyond lightweight preferences:
///
///  * protected applications (`protected_apps` table)
///  * security settings (`security_settings` key-value table)
///  * lock profiles (`profiles` table)
///  * lock rules (`lock_rules` table)
///
/// The production implementation is SQLite (`SqfliteLocalDatabase`); tests
/// use `InMemoryLocalDatabase`. No protection logic lives here — this layer
/// only stores and retrieves.
abstract interface class LocalDatabase {
  /// Version of the on-disk schema (drives migrations in the SQLite impl).
  int get schemaVersion;

  /// Opens/prepares the store. Must be called once before use.
  Future<void> init();

  Future<void> close();

  // -- protected applications ---------------------------------------------

  /// All protected apps, ordered by [ProtectedApp.sortOrder] then label.
  Future<List<ProtectedApp>> getProtectedApps();

  /// Upsert by package name (one record per package). A new record is
  /// stored with [ProtectedApp.securityLevel]. For an existing record the
  /// label, addedAt and sortOrder are replaced but the stored security
  /// level is KEPT (Phase 8 / M1): a repeated protect never resets a level;
  /// only [updateProtectedAppSecurityLevel] changes it. Atomic.
  Future<void> saveProtectedApp(ProtectedApp app);

  /// Sets the security level of an existing protected app, atomically.
  /// Returns false (and stores nothing) when [packageName] is not
  /// protected: a level change never protects or unprotects an app.
  Future<bool> updateProtectedAppSecurityLevel(
    String packageName,
    AppSecurityLevel level,
  );

  Future<void> removeProtectedApp(String packageName);

  // -- security settings (key-value) ---------------------------------------

  Future<String?> getSetting(String key);

  Future<Map<String, String>> getAllSettings();

  Future<void> setSetting(String key, String value);

  Future<void> removeSetting(String key);

  /// P13/M3 F-1: atomic compare-and-set of ONE settings row.
  ///
  ///  * [expected] == null: succeeds iff NO row exists for [key]; inserts
  ///    [next].
  ///  * [expected] != null: succeeds iff the row's current value is exactly
  ///    (byte-for-byte, BINARY collation) [expected]; replaces it with
  ///    [next]. An absent row is a conflict, never an insert.
  ///
  /// Returns [CasOutcome.committed] iff THIS call changed exactly one row and
  /// [CasOutcome.conflict] iff the statement completed and changed none.
  /// Throws [CasUnknownOutcome] (never returns) when completion cannot be
  /// confirmed (busy, closed database, I/O or platform error); callers MUST
  /// treat that as UNKNOWN and may resolve it with [reconcileCompareAndSet].
  ///
  /// One statement per call: it never opens, joins or holds a transaction,
  /// never retries internally and performs no encryption. Fails with
  /// [ArgumentError], before any I/O, when [next] == [expected].
  ///
  /// ABA: the comparison is over the WHOLE stored value. Callers must store
  /// whole documents (so byte equality implies state equality) and should
  /// make every [next] unique (the AES-GCM settings cipher does, via a fresh
  /// random nonce) so that [reconcileCompareAndSet] is meaningful.
  Future<CasOutcome> compareAndSetSetting(
    String key, {
    required String? expected,
    required String next,
  });

  // -- lock profiles -------------------------------------------------------

  Future<List<LockProfile>> getProfiles();

  /// Upserts a profile. When [profile.isActive] is true, all other profiles
  /// are deactivated first — exactly one profile stays active.
  Future<void> saveProfile(LockProfile profile);

  Future<void> deleteProfile(String profileId);

  // -- lock rules ----------------------------------------------------------

  Future<List<LockRule>> getRules();

  /// Replaces the entire rule set (rules are edited as a whole).
  Future<void> saveRules(List<LockRule> rules);
}

/// P13/M3 F-1: definite outcomes of [LocalDatabase.compareAndSetSetting].
enum CasOutcome {
  /// This call's statement changed exactly one row.
  committed,

  /// The statement completed and changed no row (the expectation was stale).
  conflict,
}

/// Why a compare-and-set outcome is unknown. Fixed codes only: exception
/// text is never carried (it can contain stored values or paths).
enum CasUnknownCode { busy, closed, io, other }

/// Thrown by [LocalDatabase.compareAndSetSetting] when it cannot confirm
/// whether its statement completed. Never treat as success or as conflict.
final class CasUnknownOutcome implements Exception {
  const CasUnknownOutcome(this.code);

  final CasUnknownCode code;

  @override
  String toString() => 'CasUnknownOutcome(${code.name})';
}

/// Result of [reconcileCompareAndSet].
enum CasReconciliation {
  /// The durable value equals the attempted `next`: this write landed (sound
  /// only when `next` was unique, e.g. fresh-nonce ciphertext).
  confirmedCommitted,

  /// The durable value is not `next`: the write did not land OR was already
  /// superseded. NEVER report success from this result.
  notConfirmed,

  /// The durable value could not be read: still unknown.
  unreadable,
}

/// Resolves an UNKNOWN compare-and-set by one durable read. Never writes.
Future<CasReconciliation> reconcileCompareAndSet(
  LocalDatabase database,
  String key,
  String next,
) async {
  final String? current;
  try {
    current = await database.getSetting(key);
  } catch (_) {
    return CasReconciliation.unreadable;
  }
  return current == next
      ? CasReconciliation.confirmedCommitted
      : CasReconciliation.notConfirmed;
}

/// Shared argument contract for [LocalDatabase.compareAndSetSetting]
/// implementations.
void checkCompareAndSetArguments(String? expected, String next) {
  if (expected == next) {
    // Values are never echoed: they may be credential ciphertext.
    throw ArgumentError('next must differ from expected');
  }
}
