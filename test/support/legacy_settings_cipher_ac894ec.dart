// P13/M3 Batch 2 DOWNGRADE FIXTURE (test-only). The class below is the
// pre-Batch-2 AesGcmSettingsCipher from ac894ec
// (lib/security/encryption/settings_cipher_impl.dart), copied VERBATIM
// except for the class name, so tests can run "old build" code against data
// written by the repaired build. Includes its defects (mint on null read,
// no CAS) on purpose: that is what an older installed binary does.
import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';

/// AES-256-GCM cipher for the security settings document.
///
/// Key management:
///  * on first use, a random 256-bit master key is generated and written to
///    the [SecretStore] (Android Keystore-backed in production);
///  * every later use reads that same key — the key itself never leaves the
///    secret store, and only ever exists in memory while encrypting;
///  * each encryption uses a fresh random 96-bit nonce, and the GCM auth tag
///    makes the stored document tamper-evident.
class LegacyAesGcmSettingsCipherAc894ec implements SettingsCipher {
  LegacyAesGcmSettingsCipherAc894ec(this._secrets, {Random? random})
      : _random = random ?? Random.secure();

  static const int _keyLengthBytes = 32; // AES-256
  static const int _nonceLengthBytes = 12; // GCM standard

  final SecretStore _secrets;
  final Random _random;
  final AesGcm _algorithm = AesGcm.with256bits();

  SecretKey? _cachedKey;

  /// Loads the master key, creating it on first use.
  Future<SecretKey> _masterKey() async {
    final SecretKey? cached = _cachedKey;
    if (cached != null) {
      return cached;
    }

    final String? stored = await _secrets.read(SecretKeys.settingsMasterKey);
    final SecretKey key;
    if (stored == null) {
      final List<int> fresh = _randomBytes(_keyLengthBytes);
      await _secrets.write(
        SecretKeys.settingsMasterKey,
        base64Encode(fresh),
      );
      key = SecretKey(fresh);
    } else {
      key = SecretKey(base64Decode(stored));
    }

    _cachedKey = key;
    return key;
  }

  List<int> _randomBytes(int length) {
    final List<int> bytes = List<int>.filled(length, 0);
    for (int i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }

  @override
  Future<String> encryptString(String plaintext) async {
    final SecretKey key = await _masterKey();
    final SecretBox box = await _algorithm.encrypt(
      utf8.encode(plaintext),
      secretKey: key,
      nonce: _randomBytes(_nonceLengthBytes),
    );
    // nonce || ciphertext || mac — everything needed to decrypt later.
    return base64Encode(
      box.concatenation(nonce: true, mac: true),
    );
  }

  @override
  Future<String> decryptString(String ciphertext) async {
    final SecretKey key = await _masterKey();
    final SecretBox box = SecretBox.fromConcatenation(
      base64Decode(ciphertext),
      nonceLength: _nonceLengthBytes,
      macLength: 16,
    );
    // Throws SecretBoxAuthenticationError on tampering — intentional.
    final List<int> clear = await _algorithm.decrypt(box, secretKey: key);
    return utf8.decode(clear);
  }
}
