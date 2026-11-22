// Phase 18 / M2 (M2-A, M2-B) — local storage inventory and classification.
//
// Every persistent store the app writes is listed here and in
// docs/storage_logging_network_audit.md. A store, key, table, Keystore
// alias or file API that is not classified fails these tests until it is
// audited and added to both. Static source invariants (host test); on-device
// inspection of the real files is physical-device QA.
//
//  ST-01 Dart preferences tier (shared_preferences): exact key set, one
//        writer (PreferencesStoreImpl), plugin imported only by its adapter
//        and the app container.
//  ST-02 Secret tier (flutter_secure_storage): exact key set, one writer
//        (MasterKeyResolver).
//  ST-03 SQLite: one database file, schema v2, exact tables and columns,
//        opened only by SqfliteLocalDatabase.
//  ST-04 `security_settings` rows: every reader/writer file is classified
//        and every row key constant matches the inventory (encrypted vs
//        plaintext recorded).
//  ST-05 Native SharedPreferences: exactly two files, exact key sets.
//  ST-06 Android Keystore: used only by the two classified native files,
//        aliases `sal_bio_binding_v1` and the `sal_kek_` prefix.
//  ST-07 No other storage: no dart:io / path_provider in lib/, no file,
//        media or external-storage API in native sources.
//  ST-08 D-M2-1 Option A: the plaintext stores reference no credential,
//        cipher, key, biometric or intruder-evidence code.
//  ST-09 Backup and device transfer exclude every storage domain used.
//  ST-10 The audit document names every classified store and key.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

const String _k = 'android/app/src/main/kotlin/com/smartapplock/app';
const String _doc = 'docs/storage_logging_network_audit.md';

/// ST-01: `AppPrefKeys` (all plaintext, non-secret UI/app preferences;
/// `dismissed` holds `package@level` lines — a plaintext package list).
const Set<String> _prefKeys = <String>{
  'pref.onboarding.completed',
  'pref.theme.mode',
  'pref.language.code',
  'pref.notifications.enabled',
  'pref.profile.last_active_id',
  'pref.capability.ever_granted.',
  'pref.security_recommendation.dismissed',
};

/// ST-02: secret tier (Keystore/Tink-encrypted by flutter_secure_storage).
const Set<String> _secretKeys = <String>{'sec.settings_master_key'};

/// ST-03: SQLite tables -> columns.
const Map<String, List<String>> _tables = <String, List<String>>{
  'protected_apps': <String>[
    'package_name', 'label', 'added_at', 'sort_order', 'security_level', //
  ],
  'security_settings': <String>['key', 'value', 'updated_at'],
  'profiles': <String>[
    'id', 'name', 'description', 'is_active', 'locked_packages', //
  ],
  'lock_rules': <String>[
    'id', 'type', 'package_name', 'start_minute', 'end_minute',
    'max_launches', 'enabled', //
  ],
};

/// ST-04: `security_settings` row keys -> true when the value is
/// `enc:v1:` AES-256-GCM ciphertext (quarantine rows keep an unreadable
/// copy of their encrypted row), false when it is plaintext.
const Map<String, bool> _settingRows = <String, bool>{
  'security_settings': true,
  'sec.key_commit': false, // key metadata; data key only Keystore-wrapped
  'intruder_evidence_index': true,
  'intruder_evidence_index.quarantine': true,
  'intruder_evidence_blob_': true,
  'intruder_defense_settings': true,
  'intruder_failure_log': true,
  'intruder_failure_log.quarantine': true,
  'notification_privacy_settings': true,
  'security_event_journal': true,
  'security_event_journal.quarantine': true,
  'smart_rules': false, // D-M2-1 Option A
  'security_profiles': false, // D-M2-1 Option A
  'lock.grace_period_seconds': false,
};

/// ST-04: files that read or write `security_settings` rows.
const Set<String> _settingFiles = <String>{
  'lib/data/repositories/impl/lock_settings_repository_impl.dart',
  'lib/data/repositories/impl/security_profile_repository_impl.dart',
  'lib/data/repositories/impl/security_settings_repository_impl.dart',
  'lib/data/repositories/impl/smart_rule_repository_impl.dart',
  'lib/data/storage/local_database.dart',
  'lib/security/encryption/master_key_resolver.dart',
  'lib/security/intruder/intruder_defense_settings.dart',
  'lib/security/intruder/intruder_evidence_store.dart',
  'lib/security/intruder/intruder_failure_log_store.dart',
  'lib/security/notification_privacy/notification_privacy_settings.dart',
  'lib/security/timeline/security_event_journal_store.dart',
  'lib/security/timeline/security_timeline.dart',
};

/// ST-05: native SharedPreferences file -> (defining file, keys). All
/// plaintext, app-private (MODE_PRIVATE), excluded from backup/transfer.
const Map<String, (String, Set<String>)> _nativePrefs =
    <String, (String, Set<String>)>{
  'smart_app_lock_protection_bootstrap': (
    'ProtectionStateStore.kt',
    <String>{
      'enabled', 'protected_packages', 'pending_challenge',
      'pending_challenge_generation', 'next_challenge_generation',
      'wake_reauth_package', 'wake_reauth_boot_count',
      'wake_reauth_stamp_elapsed', 'wake_reauth_stamp_wall', 'last_error',
      'last_error_code', 'security_levels', 'security_levels_version',
      'smart_rules', 'smart_rules_version', //
    },
  ),
  'smart_app_lock_notification_privacy': (
    'NotificationPrivacyStore.kt',
    <String>{'version', 'modes', 'placeholder_salt'},
  ),
};

/// ST-06: Keystore users and aliases.
const Set<String> _keystoreFiles = <String>{
  'BiometricBindingChannel.kt',
  'KeyWrapChannel.kt',
};
const Set<String> _keystoreAliases = <String>{'sal_bio_binding_v1', 'sal_kek_'};

/// ST-08: the D-M2-1 plaintext stores.
const List<String> _plaintextDart = <String>[
  'lib/data/storage/impl/sqflite_local_database.dart',
  'lib/data/storage/impl/preferences_store_impl.dart',
  'lib/data/repositories/impl/protected_apps_repository_impl.dart',
  'lib/data/repositories/impl/lock_settings_repository_impl.dart',
  'lib/data/repositories/impl/smart_rule_repository_impl.dart',
  'lib/data/repositories/impl/security_profile_repository_impl.dart',
  'lib/rules/smart_rule_document.dart',
  'lib/profiles/security_profile_document.dart',
  'lib/data/models/protected_app.dart',
];
const List<String> _plaintextNative = <String>[
  'ProtectionStateStore.kt',
  'NotificationPrivacyStore.kt',
];

String _norm(String p) => p.replaceAll(r'\', '/');

String _code(String src) => src
    .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
    .split('\n')
    .map((String l) {
      final int i = l.indexOf('//');
      return i < 0 ? l : l.substring(0, i);
    })
    .join('\n');

List<File> _dart() => Directory('lib')
    .listSync(recursive: true)
    .whereType<File>()
    .where((File f) => f.path.endsWith('.dart'))
    .toList()
  ..sort((File a, File b) => a.path.compareTo(b.path));

List<File> _kotlin() => Directory(_k)
    .listSync()
    .whereType<File>()
    .where((File f) => f.path.endsWith('.kt'))
    .toList()
  ..sort((File a, File b) => a.path.compareTo(b.path));

String _read(String p) => _code(File(p).readAsStringSync());

Set<String> _filesMatching(RegExp r) => <String>{
      for (final File f in _dart())
        if (r.hasMatch(_code(f.readAsStringSync()))) _norm(f.path),
    };

Set<String> _stringConsts(String src) => <String>{
      for (final RegExpMatch m in RegExp(
              r"static const String \w+\s*=\s*'([^']*)'(?:\s*;)?",
              multiLine: true)
          .allMatches(src))
        m[1]!,
    };

void main() {
  test('ST-01 preferences tier: exact keys, single writer', () {
    final String keys = _read('lib/data/storage/preferences_store.dart');
    final String block =
        keys.substring(keys.indexOf('abstract final class AppPrefKeys'));
    final String body = block.substring(0, block.indexOf('\n}'));
    expect(
        <String>{
          for (final RegExpMatch m in RegExp(
                  r"static const String \w+\s*=\s*'([^']*)';")
              .allMatches(body))
            m[1]!,
        },
        _prefKeys);
    expect(_filesMatching(RegExp(r'\bAppPrefKeys\b')), <String>{
      'lib/data/storage/preferences_store.dart',
      'lib/data/storage/impl/preferences_store_impl.dart',
    });
    expect(_filesMatching(RegExp(r'\bKeyValueStore\b')), <String>{
      'lib/app/app_container.dart',
      'lib/data/storage/key_value_store.dart',
      'lib/data/storage/impl/in_memory_key_value_store.dart',
      'lib/data/storage/impl/preferences_store_impl.dart',
      'lib/data/storage/impl/shared_prefs_key_value_store.dart',
    });
    expect(_filesMatching(RegExp(r"package:shared_preferences/")), <String>{
      'lib/app/app_container.dart',
      'lib/data/storage/impl/shared_prefs_key_value_store.dart',
    });
  });

  test('ST-02 secret tier: exact keys, single writer', () {
    final String src = _read('lib/security/storage/secret_store.dart');
    expect(_stringConsts(src), _secretKeys);
    expect(_filesMatching(RegExp(r'package:flutter_secure_storage/')),
        <String>{'lib/security/storage/impl/flutter_secure_secret_store.dart'});
    expect(
        _filesMatching(RegExp(r'_secrets\.(write|delete|clear)\s*\(|'
            r'secretStore\.(write|delete|clear)\s*\(')),
        <String>{'lib/security/encryption/master_key_resolver.dart'});
  });

  test('ST-03 SQLite: one file, exact tables and columns', () {
    const String p = 'lib/data/storage/impl/sqflite_local_database.dart';
    final String s = File(p).readAsStringSync();
    expect(s.contains("_dbName = 'smart_app_lock.db'"), isTrue);
    expect(s.contains('_schemaVersion = 2'), isTrue);
    final Map<String, List<String>> found = <String, List<String>>{};
    for (final RegExpMatch m in RegExp(r'CREATE TABLE (\w+) \(([\s\S]*?)\n\s*\)')
        .allMatches(s)) {
      found[m[1]!] = <String>[
        for (final String l in m[2]!.split('\n'))
          if (l.trim().isNotEmpty) l.trim().split(RegExp(r'\s+')).first,
      ];
    }
    expect(found, _tables);
    expect(_filesMatching(RegExp(r'\bopenDatabase\s*\(')), <String>{p});
    expect(_filesMatching(RegExp(r'package:sqflite/')), <String>{p});
  });

  test('ST-04 security_settings rows are classified', () {
    expect(
        _filesMatching(RegExp(r'\.(getSetting|setSetting|compareAndSetSetting|'
            r'removeSetting|getAllSettings)\s*\(')),
        _settingFiles);
    final Set<String> keys = <String>{};
    for (final String f in _settingFiles) {
      final String src = _read(f);
      for (final RegExpMatch m in RegExp(
              r"static const String (?:_?storageKey|indexKey|quarantineKey|"
              r"blobPrefix|commitKey|gracePeriodKey)\s*=\s*'([^']*)'")
          .allMatches(src)) {
        keys.add(m[1]!);
      }
    }
    expect(keys, _settingRows.keys.toSet());
    // Encrypted rows are written with the enc:v1: prefix by their store.
    for (final String f in <String>[
      'lib/security/intruder/intruder_defense_settings.dart',
      'lib/security/intruder/intruder_failure_log_store.dart',
      'lib/security/intruder/intruder_evidence_store.dart',
      'lib/security/notification_privacy/notification_privacy_settings.dart',
      'lib/security/timeline/security_event_journal_store.dart',
      'lib/data/repositories/impl/security_settings_repository_impl.dart',
    ]) {
      expect(File(f).readAsStringSync().contains('enc:v1:'), isTrue,
          reason: '$f must write ciphertext');
    }
  });

  test('ST-05 native SharedPreferences: two files, exact keys', () {
    final Set<String> users = <String>{};
    for (final File f in _kotlin()) {
      if (_code(f.readAsStringSync()).contains('getSharedPreferences(')) {
        users.add(_norm(f.path).split('/').last);
      }
    }
    expect(users, <String>{
      for (final (String, Set<String>) v in _nativePrefs.values) v.$1,
    });
    _nativePrefs.forEach((String name, (String, Set<String>) v) {
      final String s = _read('$_k/${v.$1}');
      expect(s.contains('private const val PREFS = "$name"'), isTrue);
      final Set<String> keys = <String>{
        for (final RegExpMatch m
            in RegExp(r'const val KEY_\w+\s*=\s*"([^"]*)"').allMatches(s))
          m[1]!,
      };
      expect(keys, v.$2, reason: '${v.$1} keys');
      expect(RegExp(r'getSharedPreferences\((?!PREFS\b)').hasMatch(s), isFalse);
    });
  });

  test('ST-06 Android Keystore: classified files and aliases only', () {
    final Set<String> users = <String>{};
    final Set<String> aliases = <String>{};
    for (final File f in _kotlin()) {
      final String s = _code(f.readAsStringSync());
      if (RegExp(r'KeyStore\.getInstance|KeyGenParameterSpec\.Builder')
          .hasMatch(s)) {
        users.add(_norm(f.path).split('/').last);
      }
      for (final RegExpMatch m
          in RegExp(r'const val (?:ALIAS|ALIAS_PREFIX)\s*=\s*"([^"]*)"')
              .allMatches(s)) {
        aliases.add(m[1]!);
      }
    }
    expect(users, _keystoreFiles);
    expect(aliases, _keystoreAliases);
  });

  test('ST-07 no file, media or external storage', () {
    expect(
        _filesMatching(RegExp(r"import\s+'(dart:io|package:path_provider)")),
        isEmpty);
    final List<String> offenders = <String>[];
    final RegExp banned = RegExp(
        r'FileOutputStream|FileWriter|RandomAccessFile|openFileOutput|'
        r'\bFile\s*\(|filesDir|cacheDir|getExternal|MediaStore|'
        r'createTempFile|Files\.write|getDatabasePath|openOrCreateDatabase|'
        r'DataStore|Environment\.getExternal');
    for (final File f in _kotlin()) {
      for (final RegExpMatch m
          in banned.allMatches(_code(f.readAsStringSync()))) {
        offenders.add('${_norm(f.path)}: ${m[0]}');
      }
    }
    expect(offenders, isEmpty);
  });

  test('ST-08 D-M2-1 plaintext stores reference no secret material', () {
    final RegExp dartBanned = RegExp(
        r"import\s+'[^']*(security/credentials|security/encryption|"
        r"security/intruder|security/storage|pin_hasher|biometric)[^']*'|"
        r'\b(SettingsCipher|SecretStore|PinHasher|PatternHasher|'
        r'CredentialHash|IntruderEvidence\w*)\b');
    for (final String p in _plaintextDart) {
      final List<String> hits = <String>[
        for (final RegExpMatch m in dartBanned.allMatches(_read(p))) m[0]!,
      ];
      expect(hits, isEmpty, reason: '$p is a plaintext store');
    }
    final RegExp ktBanned = RegExp(
        r'\b(KeyStore|Cipher|SecretKey|KeyWrap\w*|BiometricBinding\w*|'
        r'Intruder\w*|StillCapture\w*|pinHash|patternHash|credential)\b',
        caseSensitive: false);
    for (final String p in _plaintextNative) {
      final List<String> hits = <String>[
        for (final RegExpMatch m in ktBanned.allMatches(_read('$_k/$p'))) m[0]!,
      ];
      expect(hits, isEmpty, reason: '$p is a plaintext store');
    }
  });

  test('ST-09 backup and transfer exclude every used storage domain', () {
    final String manifest =
        File('android/app/src/main/AndroidManifest.xml').readAsStringSync();
    expect(manifest.contains('android:allowBackup="false"'), isTrue);
    expect(manifest.contains('android:fullBackupContent="@xml/backup_rules"'),
        isTrue);
    expect(
        manifest.contains(
            'android:dataExtractionRules="@xml/data_extraction_rules"'),
        isTrue);
    final String rules =
        File('android/app/src/main/res/xml/data_extraction_rules.xml')
            .readAsStringSync();
    expect(rules.contains('<include'), isFalse);
    for (final String section in <String>['cloud-backup', 'device-transfer']) {
      final String body = rules.substring(rules.indexOf('<$section>'),
          rules.indexOf('</$section>'));
      for (final String domain in <String>[
        'database', 'sharedpref', 'file', 'root', //
        'device_database', 'device_sharedpref', 'device_file', 'device_root',
      ]) {
        expect(body.contains('<exclude domain="$domain" path="." />'), isTrue,
            reason: '$section must exclude $domain');
      }
    }
    final String legacy =
        File('android/app/src/main/res/xml/backup_rules.xml').readAsStringSync();
    expect(legacy.contains('<include'), isFalse);
    for (final String domain in <String>['database', 'sharedpref', 'file']) {
      expect(legacy.contains('<exclude domain="$domain" path="." />'), isTrue);
    }
  });

  test('ST-10 the audit document names every classified store and key', () {
    final String doc = File(_doc).readAsStringSync();
    final List<String> missing = <String>[
      for (final String k in <String>[
        ..._prefKeys,
        ..._secretKeys,
        'smart_app_lock.db',
        ..._tables.keys,
        ..._settingRows.keys,
        ..._nativePrefs.keys,
        for (final (String, Set<String>) v in _nativePrefs.values) ...v.$2,
        ..._keystoreAliases,
      ])
        if (!doc.contains('`$k`')) k,
    ];
    expect(missing, isEmpty);
    expect(doc.contains('Residual privacy risk'), isTrue);
  });
}
