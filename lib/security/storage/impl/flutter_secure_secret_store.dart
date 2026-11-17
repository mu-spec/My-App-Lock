import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../secret_store.dart';

/// Production [SecretStore] backed by the Android Keystore.
///
/// flutter_secure_storage v11 dropped the legacy
/// `encryptedSharedPreferences` flag together with the deprecated
/// EncryptedSharedPreferences backend (removed upstream by androidx).
/// Its current Android implementation is **Keystore-backed by default**:
///
///  * secret key protection: RSA/ECB/OAEPWithSHA-256AndMGF1Padding key
///    wrapping in the Android Keystore (hardware-backed where the device
///    provides TEE/StrongBox);
///  * data encryption: AES/GCM/NoPadding;
///  * supported from API 23+.
///
/// Every value is encrypted with a device-bound key that never leaves the
/// OS keystore, and nothing is written to disk in plaintext.
///
/// F-KEY-1 owner decision G-2: `resetOnError` is explicitly **false**. The
/// Dart-side default (true) makes the plugin delete the entry (read/write
/// failure), all entries (any method failure, or a failed key migration
/// via `deleteAllDataAndKeys`) and report success or "absent" — which let
/// the settings cipher mint a replacement master key over recoverable
/// ciphertext. With false, every such failure surfaces as an exception
/// and nothing is deleted. `migrateOnAlgorithmChange` stays at its default
/// (true): it only runs when the stored algorithm markers differ from the
/// current ones, and with resetOnError=false a failed migration reports an
/// error instead of deleting.
class FlutterSecureSecretStore implements SecretStore {
  FlutterSecureSecretStore()
      : _storage = const FlutterSecureStorage(
          aOptions: androidOptions,
        );

  /// The exact options sent with every call (pinned by tests).
  static const AndroidOptions androidOptions = AndroidOptions(
    resetOnError: false,
  );

  final FlutterSecureStorage _storage;

  @override
  Future<bool> containsKey(String key) => _storage.containsKey(key: key);

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);

  @override
  Future<void> clear() => _storage.deleteAll();
}
