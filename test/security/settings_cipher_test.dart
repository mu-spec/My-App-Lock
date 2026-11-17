import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';

void main() {
  group('AesGcmSettingsCipher', () {
    test('encrypt/decrypt round-trip', () async {
      final SettingsCipher cipher =
          AesGcmSettingsCipher(InMemorySecretStore(),
          database: InMemoryLocalDatabase());
      const String secret = '{"pinHash":"...","stealthModeEnabled":true}';
      final String encrypted = await cipher.encryptString(secret);
      expect(encrypted, isNot(secret));
      expect(await cipher.decryptString(encrypted), secret);
    });

    test('each encryption uses a fresh nonce (no reuse)', () async {
      final SettingsCipher cipher =
          AesGcmSettingsCipher(InMemorySecretStore(),
          database: InMemoryLocalDatabase());
      const String plain = 'same plaintext twice';
      final String a = await cipher.encryptString(plain);
      final String b = await cipher.encryptString(plain);
      expect(a, isNot(b));
    });

    test('tampering with the ciphertext fails decryption', () async {
      final SettingsCipher cipher =
          AesGcmSettingsCipher(InMemorySecretStore(),
          database: InMemoryLocalDatabase());
      final String encrypted = await cipher.encryptString('sensitive data');

      // Flip a byte in the middle of the payload.
      final List<int> bytes = base64Decode(encrypted);
      bytes[bytes.length ~/ 2] ^= 0xFF;
      final String tampered = base64Encode(bytes);

      expect(
        () => cipher.decryptString(tampered),
        throwsA(isA<Object>()),
      );
    });

    test('master key is created once and reused across instances', () async {
      final InMemorySecretStore store = InMemorySecretStore();
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();

      final SettingsCipher writer = AesGcmSettingsCipher(store, database: db);
      final String encrypted = await writer.encryptString('persisted secret');

      // A brand-new cipher instance (e.g. after app restart) reads the same
      // key from the store and can still decrypt.
      final SettingsCipher reader = AesGcmSettingsCipher(store, database: db);
      expect(await reader.decryptString(encrypted), 'persisted secret');
    });

    test('master key stored in the secret store is a 256-bit key', () async {
      final InMemorySecretStore store = InMemorySecretStore();
      final SettingsCipher cipher =
          AesGcmSettingsCipher(store, database: InMemoryLocalDatabase());
      await cipher.encryptString('trigger key creation');

      final String? raw = await store.read(SecretKeys.settingsMasterKey);
      expect(raw, isNotNull);
      expect(base64Decode(raw!), hasLength(32)); // AES-256
    });

    test('decrypting garbage throws instead of returning data', () async {
      final SettingsCipher cipher =
          AesGcmSettingsCipher(InMemorySecretStore(),
          database: InMemoryLocalDatabase());
      await cipher.encryptString('init');
      expect(
        () => cipher.decryptString('bm90LWEtY2lwaGVydGV4dA=='), // "not-a-ciphertext"
        throwsA(isA<Object>()),
      );
    });
  });
}
