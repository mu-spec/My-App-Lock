import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

import '../../data/storage/local_database.dart';
import '../storage/secret_store.dart';
import 'key_wrapper.dart';
import 'master_key_resolver.dart';
import 'settings_cipher.dart';

/// AES-256-GCM cipher for the security settings document.
///
/// Key management (F-KEY-1 / K-2+B-compat, Batch 2):
///  * the master key comes from [MasterKeyResolver], which commits it with
///    an atomic SQLite compare-and-set (`sec.key_commit`) before it is ever
///    used, so concurrent first launches (isolates, engines, instances) all
///    converge on ONE key;
///  * nothing is encrypted unless the key is verified ACTIVE and writable;
///    nothing is decrypted unless a verified key is available;
///  * decryption never creates a key, and no key is ever created while
///    encrypted data exists: an unavailable key raises
///    [MasterKeyUnavailableException] (stores treat that as unreadable);
///  * the key bytes, the legacy secret slot and the ciphertext format
///    (`base64(nonce || ct || mac)`) are unchanged, so older builds keep
///    reading everything this build writes;
///  * each encryption uses a fresh random 96-bit nonce, and the GCM auth tag
///    makes the stored document tamper-evident.
class AesGcmSettingsCipher implements SettingsCipher {
  /// [database] holds the key commitment and is probed for existing
  /// ciphertext. Every cipher sharing one secret store MUST share it.
  AesGcmSettingsCipher(
    SecretStore secrets, {
    required LocalDatabase database,
    KeyWrapper keyWrapper = const NoKeyWrapper(),
    Random? random,
  }) : this.withResolver(
          MasterKeyResolver(
              secrets: secrets, database: database, wrapper: keyWrapper),
          random: random,
        );

  AesGcmSettingsCipher.withResolver(this.resolver, {Random? random})
      : _random = random ?? Random.secure();

  static const int _nonceLengthBytes = 12; // GCM standard

  final MasterKeyResolver resolver;
  final Random _random;
  final AesGcm _algorithm = AesGcm.with256bits();

  Future<SecretKey> _key({required bool forWrite}) async {
    final MasterKeyState s = await resolver.resolve(allowGenesis: forWrite);
    switch (s) {
      case MasterKeyReady(:final List<int> key, :final bool readOnly):
        if (forWrite && readOnly) {
          // T9: the legacy slot is unreadable; no writes that could diverge.
          throw const MasterKeyUnavailableException(
              MasterKeyIssue.storageError);
        }
        return SecretKey(key);
      case MasterKeyUnavailable(:final MasterKeyIssue issue):
        throw MasterKeyUnavailableException(issue);
    }
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
    final SecretKey key = await _key(forWrite: true);
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
    // Structure first (no key needed): bytes that no key could ever open
    // fail as malformed (FormatException/ArgumentError), independent of the
    // key state.
    final SecretBox box = SecretBox.fromConcatenation(
      base64Decode(ciphertext),
      nonceLength: _nonceLengthBytes,
      macLength: 16,
    );
    final SecretKey key = await _key(forWrite: false);
    // Throws SecretBoxAuthenticationError on tampering — intentional.
    final List<int> clear = await _algorithm.decrypt(box, secretKey: key);
    return utf8.decode(clear);
  }
}
