import '../../utilities/result.dart';
import '../models/security_settings.dart';

/// Source of truth for the security configuration (PIN credential, intruder
/// selfie, stealth mode, lockout policy, ...).
///
/// Stored as a single JSON document in the local database's key-value table.
/// No protection logic here — enforcement phases *read* these settings and
/// act on them elsewhere.
abstract interface class SecuritySettingsRepository {
  /// Current settings, or [SecuritySettings.defaults] when nothing was saved.
  ///
  /// A stored value carries its [SecuritySettings.storedBasis] (the exact
  /// durable document it was decoded from). A document written by a newer
  /// schema fails with [UnsupportedSettingsSchema] (never downgraded).
  Future<Result<SecuritySettings>> getSettings();

  /// P13/M3 NF-NS-1: CONDITIONAL save. The write lands only if the durable
  /// document is still exactly the one [settings] was read from (its
  /// [SecuritySettings.storedBasis]); a value without a basis (never read
  /// from storage) may only create the document when none exists.
  ///
  ///  * success: committed (revision + 1; credential epoch + 1 iff the
  ///    credential set changed; secret epoch + 1 iff the credential secret
  ///    or its authorization policy changed — owner decision 1b);
  ///  * failure [SettingsWriteConflict]: another writer committed first —
  ///    nothing was written; re-read and re-evaluate, never re-apply;
  ///  * failure [SettingsWriteUnknown]: the outcome could not be confirmed
  ///    (callers must fail closed);
  ///  * any other failure: not written or unknown — fail closed.
  ///
  /// There is no blind (unconditional) write.
  Future<Result<void>> saveSettings(SecuritySettings settings);

  /// Convenience: true once a PIN credential is stored.
  Future<Result<bool>> hasPin();
}

/// The durable settings document changed since it was read: nothing was
/// written. Carries no settings data.
final class SettingsWriteConflict implements Exception {
  const SettingsWriteConflict();

  @override
  String toString() => 'SettingsWriteConflict';
}

/// A settings write whose outcome could not be confirmed (busy, closed or
/// failed storage, and the reconciliation read did not show it landed).
/// Callers must treat it as NOT saved and must not release any verdict.
final class SettingsWriteUnknown implements Exception {
  const SettingsWriteUnknown(this.code);

  /// Fixed storage code only (never exception text or settings data).
  final String code;

  @override
  String toString() => 'SettingsWriteUnknown($code)';
}

/// The stored document was written by a newer schema: it is never read as
/// defaults and never overwritten by this build (fail closed).
final class UnsupportedSettingsSchema implements Exception {
  const UnsupportedSettingsSchema(this.schema);

  final int schema;

  @override
  String toString() => 'UnsupportedSettingsSchema($schema)';
}
