import 'dart:convert';

import '../../../security/encryption/settings_cipher.dart';
import '../../../utilities/result.dart';
import '../../models/security_settings.dart';
import '../../storage/local_database.dart';
import '../security_settings_repository.dart';

/// [SecuritySettingsRepository] over the [LocalDatabase] with
/// **authenticated encryption at rest**.
///
/// Storage format in the `security_settings` key-value table:
///  * encrypted (default, since Phase 1F):
///    `enc:v1:<base64(nonce || AES-256-GCM ciphertext || auth tag)>`
///  * legacy plaintext JSON (written by Phase 1E) is still *readable* so
///    existing installs upgrade seamlessly — and is re-encrypted on the
///    next save.
///
/// **No raw PIN or password is ever stored.** The settings document holds
/// only the PBKDF2 [PinHash] (see `security/pin_hasher.dart`), and that
/// document is encrypted with a master key that lives exclusively in the
/// Android Keystore-backed [SecretStore].
///
/// P13/M3 NF-NS-1: every save is a compare-and-set
/// ([LocalDatabase.compareAndSetSetting]) against the exact stored string the
/// caller's value was read from ([SecuritySettings.storedBasis]), so a writer
/// holding an older document — another manager, engine or process — can
/// never overwrite a newer one. The document envelope adds three keys next
/// to [SecuritySettings.toJson]: `_schema` (2), `_rev` (strictly increasing
/// per committed write) and `_credEpoch` (strictly increasing per committed
/// credential-set change). Neither counter is ever reset, so equal stored
/// strings imply the same committed write (anti-ABA, even in plaintext test
/// mode). Older builds ignore the extra keys; a document without them reads
/// as revision 0 / epoch 0 / schema 1 and is migrated by its next commit
/// (lazy, in the same atomic write). Encryption happens before the single
/// compare-and-set statement: no transaction or lock is held across it.
class SecuritySettingsRepositoryImpl implements SecuritySettingsRepository {
  SecuritySettingsRepositoryImpl(
    this._database, {
    SettingsCipher? cipher,
  }) : _cipher = cipher;

  static const String _storageKey = 'security_settings';
  static const String _encryptedPrefix = 'enc:v1:';

  /// Envelope keys (never produced by [SecuritySettings.toJson]).
  static const String revisionKey = '_rev';
  static const String credentialEpochKey = '_credEpoch';

  /// Owner decision 1b: durable credential-SECRET epoch (grant binding).
  static const String secretEpochKey = '_secEpoch';
  static const String schemaKey = '_schema';

  /// Schema written by this build. A stored document with a higher schema
  /// is never decoded as defaults and never overwritten.
  static const int schemaVersion = 2;

  final LocalDatabase _database;
  final SettingsCipher? _cipher;

  @override
  Future<Result<SecuritySettings>> getSettings() async {
    try {
      final String? raw = await _database.getSetting(_storageKey);
      if (raw == null) {
        return Result.success(SecuritySettings.defaults);
      }

      final String jsonText;
      if (raw.startsWith(_encryptedPrefix)) {
        final SettingsCipher? cipher = _cipher;
        if (cipher == null) {
          // Encrypted data but no secure storage available — refuse to
          // return anything (fails closed, never falls back to guessing).
          return Result.failure(
            StateError('Secure storage unavailable; cannot decrypt settings.'),
          );
        }
        jsonText = await cipher.decryptString(
          raw.substring(_encryptedPrefix.length),
        );
      } else {
        // Legacy plaintext document from Phase 1E.
        jsonText = raw;
      }

      final Map<String, dynamic> json =
          (jsonDecode(jsonText) as Map<String, dynamic>).cast<String, dynamic>();
      final int schema = json[schemaKey] as int? ?? 1;
      if (schema > schemaVersion) {
        return Result.failure(UnsupportedSettingsSchema(schema));
      }
      final int revision = json[revisionKey] as int? ?? 0;
      final int epoch = json[credentialEpochKey] as int? ?? 0;
      final int secretEpoch = json[secretEpochKey] as int? ?? 0;
      if (revision < 0 || epoch < 0 || secretEpoch < 0 || schema < 1) {
        return Result.failure(
          const FormatException('Corrupt settings revision fields.'),
        );
      }
      final SecuritySettings settings = SecuritySettings.fromJson(json);
      return Result.success(
        settings.withStoredBasis(
          StoredSettingsBasis(
            raw: raw,
            revision: revision,
            credentialEpoch: epoch,
            credentialFingerprint: settings.credentialFingerprint,
            secretEpoch: secretEpoch,
            secretFingerprint: settings.secretFingerprint,
          ),
        ),
      );
    } catch (e) {
      // Includes tamper-detection failures from the cipher (GCM auth).
      return Result.failure(e);
    }
  }

  @override
  Future<Result<void>> saveSettings(SecuritySettings settings) async {
    final StoredSettingsBasis? basis = settings.storedBasis;
    final String stored;
    try {
      final String fingerprint = settings.credentialFingerprint;
      final String basisFingerprint = basis?.credentialFingerprint ??
          SecuritySettings.defaults.credentialFingerprint;
      final Map<String, dynamic> document = <String, dynamic>{
        ...settings.toJson(),
        schemaKey: schemaVersion,
        revisionKey: (basis?.revision ?? 0) + 1,
        credentialEpochKey: (basis?.credentialEpoch ?? 0) +
            (fingerprint == basisFingerprint &&
                    !settings.startsNewCredentialEpoch
                ? 0
                : 1),
        secretEpochKey: (basis?.secretEpoch ?? 0) +
            (settings.secretFingerprint ==
                        (basis?.secretFingerprint ??
                            SecuritySettings.defaults.secretFingerprint) &&
                    !settings.startsNewCredentialEpoch
                ? 0
                : 1),
      };
      final String json = jsonEncode(document);
      final SettingsCipher? cipher = _cipher;
      stored = cipher == null
          ? json // only used by legacy/plaintext tests — production always encrypts
          : '$_encryptedPrefix${await cipher.encryptString(json)}';
    } catch (e) {
      return Result.failure(e); // nothing was written
    }

    final CasOutcome outcome;
    try {
      // ONE statement; a value never read from storage (no basis) may only
      // create the document (insert-if-absent), never replace one.
      outcome = await _database.compareAndSetSetting(
        _storageKey,
        expected: basis?.raw,
        next: stored,
      );
    } on CasUnknownOutcome catch (unknown) {
      return _reconcile(stored, SettingsWriteUnknown(unknown.code.name));
    } catch (e) {
      // Any other storage error is ambiguous too: confirm by one read.
      return _reconcile(stored, e);
    }
    return outcome == CasOutcome.committed
        ? Result.success(null)
        : Result.failure(const SettingsWriteConflict());
  }

  /// [stored] is unique (strictly increasing revision, fresh cipher nonce),
  /// so finding it durable proves THIS write landed; anything else stays a
  /// failure (never reported as saved).
  Future<Result<void>> _reconcile(String stored, Object error) async {
    final CasReconciliation r =
        await reconcileCompareAndSet(_database, _storageKey, stored);
    return r == CasReconciliation.confirmedCommitted
        ? Result.success(null)
        : Result.failure(error);
  }

  @override
  Future<Result<bool>> hasPin() async {
    final Result<SecuritySettings> settings = await getSettings();
    return settings.fold(
      (SecuritySettings s) => Result.success(s.hasPin),
      Result.failure,
    );
  }
}
