// F-KEY-1 owner decision G-2: flutter_secure_storage resetOnError=false.
//
// Host evidence of the DART side only: the exact options map the plugin
// receives on every call, and that a failing platform read surfaces as an
// error that neither deletes nor replaces the master key. The plugin's
// Android behaviour for resetOnError=false (read -> onError, no delete;
// catch-all -> handleException, no deleteAll; key mismatch -> migrate or
// error, never deleteAllDataAndKeys) is CODE-READ from 11.2.0 sources, not
// executed here (no Android runtime / device: DEVICE BLOCKED).
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
// The platform seam is the plugin's own federated interface.
// ignore: depend_on_referenced_packages
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/storage/impl/flutter_secure_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';

class _CapturePlatform extends FlutterSecureStoragePlatform {
  final Map<String, String> data = <String, String>{};
  final List<(String, Map<String, String>)> calls =
      <(String, Map<String, String>)>[];
  bool failReads = false;
  int writes = 0;
  int deletes = 0;

  @override
  Future<bool> containsKey(
      {required String key, required Map<String, String> options}) async {
    calls.add(('containsKey', options));
    return data.containsKey(key);
  }

  @override
  Future<void> delete(
      {required String key, required Map<String, String> options}) async {
    calls.add(('delete', options));
    deletes++;
    data.remove(key);
  }

  @override
  Future<void> deleteAll({required Map<String, String> options}) async {
    calls.add(('deleteAll', options));
    deletes++;
    data.clear();
  }

  @override
  Future<String?> read(
      {required String key, required Map<String, String> options}) async {
    calls.add(('read', options));
    if (failReads) {
      throw PlatformException(code: 'Exception', message: 'keystore busy');
    }
    return data[key];
  }

  @override
  Future<Map<String, String>> readAll(
      {required Map<String, String> options}) async {
    calls.add(('readAll', options));
    return Map<String, String>.of(data);
  }

  @override
  Future<void> write(
      {required String key,
      required String value,
      required Map<String, String> options}) async {
    calls.add(('write', options));
    writes++;
    data[key] = value;
  }
}

void main() {
  late _CapturePlatform platform;

  setUp(() {
    platform = _CapturePlatform();
    FlutterSecureStoragePlatform.instance = platform;
  });

  test('G2-1 the pinned options: resetOnError=false, '
      'migrateOnAlgorithmChange=true (unchanged), migrateWithBackup=false '
      '(unchanged)', () {
    final Map<String, String> m =
        FlutterSecureSecretStore.androidOptions.toMap();
    expect(m['resetOnError'], 'false');
    expect(m['migrateOnAlgorithmChange'], 'true');
    expect(m['migrateWithBackup'], 'false');
    // Everything else equals the former AndroidOptions() defaults, so the
    // algorithm markers (and hence the plugin migration trigger) are
    // unchanged by G-2.
    final Map<String, String> before = const AndroidOptions().toMap();
    for (final String k in before.keys) {
      if (k == 'resetOnError') continue;
      expect(m[k], before[k], reason: 'option $k unchanged');
    }
    expect(before['resetOnError'], 'true', reason: 'the old default');
  });

  test('G2-2 every call carries resetOnError=false', () async {
    final FlutterSecureSecretStore s = FlutterSecureSecretStore();
    await s.write('k', 'v');
    await s.read('k');
    await s.containsKey('k');
    await s.delete('k');
    await s.clear();
    expect(platform.calls.map(((String, Map<String, String>) c) => c.$1),
        <String>['write', 'read', 'containsKey', 'delete', 'deleteAll']);
    for (final (String op, Map<String, String> o) in platform.calls) {
      expect(o['resetOnError'], 'false', reason: op);
    }
  });

  test('G2-3 a failing platform read surfaces as an error: the master key is '
      'neither deleted nor replaced, ciphertext stays decryptable', () async {
    final AesGcmSettingsCipher c1 =
        AesGcmSettingsCipher(FlutterSecureSecretStore());
    final String ct = await c1.encryptString('credential-row');
    final String key = platform.data[SecretKeys.settingsMasterKey]!;
    final int writesBefore = platform.writes;

    platform.failReads = true;
    final AesGcmSettingsCipher c2 =
        AesGcmSettingsCipher(FlutterSecureSecretStore());
    await expectLater(c2.decryptString(ct), throwsA(anything));
    await expectLater(c2.encryptString('x'), throwsA(anything));
    expect(platform.writes, writesBefore, reason: 'no replacement key');
    expect(platform.deletes, 0);
    expect(platform.data[SecretKeys.settingsMasterKey], key);

    platform.failReads = false;
    final AesGcmSettingsCipher c3 =
        AesGcmSettingsCipher(FlutterSecureSecretStore());
    expect(await c3.decryptString(ct), 'credential-row');
  });
}
