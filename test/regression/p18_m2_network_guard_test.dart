// Phase 18 / M2 (M2-D) — network audit guards.
//
// Core protection is local-only: the release manifest has no network
// permission and neither the app nor any plugin it ships asks for one, so a
// release build cannot open a socket. These are static invariants (host
// test). The merged release manifest (processReleaseManifest), airplane-mode
// protection and on-device traffic checks are physical-device / CI QA.
//
//  NW-01 main manifest: no network permission, no cleartext / network
//        security config; debug and profile manifests add only INTERNET
//        (Flutter tooling for hot reload / debugger).
//  NW-02 lib/: no network API or networking package.
//  NW-03 native sources: no network API, socket, WebView or HTTP client.
//  NW-04 pubspec: direct dependencies are exactly the audited set.
//  NW-05 pubspec.lock: no networking, analytics or crash-reporting package.
//  NW-06 Gradle: app dependencies are exactly the audited set; no
//        Firebase / Google services / Crashlytics plugin.
//  NW-07 no resolved plugin's Android manifest requests a network
//        permission (so the merged release manifest stays offline).

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

const String _k = 'android/app/src/main/kotlin/com/smartapplock/app';

const Set<String> _networkPermissions = <String>{
  'android.permission.INTERNET',
  'android.permission.ACCESS_NETWORK_STATE',
  'android.permission.ACCESS_WIFI_STATE',
  'android.permission.CHANGE_NETWORK_STATE',
  'android.permission.CHANGE_WIFI_STATE',
  'android.permission.NEARBY_WIFI_DEVICES',
  'android.permission.BLUETOOTH',
  'android.permission.BLUETOOTH_CONNECT',
  'android.permission.BLUETOOTH_ADMIN',
  'com.google.android.c2dm.permission.RECEIVE',
};

/// NW-04: audited direct dependencies (none performs network I/O).
const Set<String> _deps = <String>{
  'flutter', 'cupertino_icons', 'crypto', 'shared_preferences', 'sqflite',
  'path', 'flutter_secure_storage', 'cryptography', 'local_auth', //
};
const Set<String> _devDeps = <String>{
  'flutter_test', 'flutter_lints', 'sqflite_common_ffi', //
};

final RegExp _bannedPackage = RegExp(
    r'^(http|http2|dio|web_socket|web_socket_channel|grpc|graphql\w*|'
    r'firebase\w*|cloud_\w+|sentry\w*|url_launcher\w*|webview\w*|'
    r'flutter_inappwebview\w*|connectivity\w*|google_\w+|amplitude\w*|'
    r'mixpanel\w*|appsflyer\w*|datadog\w*|posthog\w*|onesignal\w*|'
    r'flutter_local_notifications|chopper|retrofit|socket_io\w*)$');

String _norm(String p) => p.replaceAll(r'\', '/');

String _code(String src) => src
    .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
    .split('\n')
    .map((String l) {
      final int i = l.indexOf('//');
      return i < 0 ? l : l.substring(0, i);
    })
    .join('\n');

String _xml(String src) => src.replaceAll(RegExp(r'<!--[\s\S]*?-->'), '');

Set<String> _permissions(String manifest) => <String>{
      for (final RegExpMatch m in RegExp(
              r'<uses-permission(?:-sdk-23)?[^>]*android:name="([^"]+)"')
          .allMatches(_xml(manifest)))
        m[1]!,
    };

/// Names under a top-level YAML section (two-space indented keys).
Set<String> _section(String yaml, String name) {
  final int start = yaml.indexOf('\n$name:\n');
  if (start < 0) return <String>{};
  final String rest = yaml.substring(start + name.length + 3);
  final int end = rest.indexOf(RegExp(r'^\S', multiLine: true));
  final String body = end < 0 ? rest : rest.substring(0, end);
  return <String>{
    for (final RegExpMatch m
        in RegExp(r'^  ([a-z0-9_]+):', multiLine: true).allMatches(body))
      m[1]!,
  };
}

void main() {
  test('NW-01 release manifest is offline; debug/profile add only INTERNET',
      () {
    final String main =
        File('android/app/src/main/AndroidManifest.xml').readAsStringSync();
    expect(_permissions(main).intersection(_networkPermissions), isEmpty);
    final String code = _xml(main);
    expect(code.contains('usesCleartextTraffic'), isFalse);
    expect(code.contains('networkSecurityConfig'), isFalse);
    for (final String v in <String>['debug', 'profile']) {
      final String m = File('android/app/src/$v/AndroidManifest.xml')
          .readAsStringSync();
      expect(_permissions(m), <String>{'android.permission.INTERNET'},
          reason: '$v manifest');
      expect(_xml(m).contains('<application'), isFalse, reason: v);
    }
    expect(Directory('android/app/src/release').existsSync(), isFalse,
        reason: 'no release overlay may add permissions');
  });

  test('NW-02 lib/ has no network API or networking package', () {
    final RegExp banned = RegExp(
        r"import\s+'(dart:io|dart:html|dart:js\w*|package:web/)|"
        r"import\s+'package:([a-z0-9_]+)/|"
        r'\b(HttpClient|HttpRequest|WebSocket|RawSocket|SecureSocket|'
        r'Socket|Uri\.https?|NetworkImage|Image\.network)\b');
    final List<String> offenders = <String>[];
    for (final File f in Directory('lib')
        .listSync(recursive: true)
        .whereType<File>()
        .where((File f) => f.path.endsWith('.dart'))) {
      for (final RegExpMatch m
          in banned.allMatches(_code(f.readAsStringSync()))) {
        final String? pkg = m[2];
        if (pkg != null) {
          if (pkg == 'smart_app_lock' || _deps.contains(pkg)) continue;
        }
        offenders.add('${_norm(f.path)}: ${m[0]}');
      }
    }
    expect(offenders, isEmpty);
  });

  test('NW-03 native sources have no network API', () {
    final RegExp banned = RegExp(
        r'\b(java\.net|javax\.net|okhttp3?|HttpURLConnection|'
        r'HttpsURLConnection|URLConnection|Socket|DatagramSocket|WebView|'
        r'ConnectivityManager|DownloadManager|android\.net\.http|'
        r'Volley|retrofit2?|com\.google\.firebase|com\.google\.android\.gms|'
        r'URL\s*\()');
    final List<String> offenders = <String>[];
    for (final File f in Directory('android/app/src/main')
        .listSync(recursive: true)
        .whereType<File>()
        .where((File f) => f.path.endsWith('.kt'))) {
      for (final RegExpMatch m
          in banned.allMatches(_code(f.readAsStringSync()))) {
        offenders.add('${_norm(f.path)}: ${m[0]}');
      }
    }
    expect(Directory(_k).existsSync(), isTrue);
    expect(offenders, isEmpty);
  });

  test('NW-04 direct dependencies are exactly the audited set', () {
    final String pubspec = File('pubspec.yaml').readAsStringSync();
    expect(_section(pubspec, 'dependencies'), _deps);
    expect(_section(pubspec, 'dev_dependencies'), _devDeps);
  });

  test('NW-05 resolved packages include no network or telemetry package', () {
    final Set<String> resolved =
        _section(File('pubspec.lock').readAsStringSync(), 'packages');
    expect(resolved, containsAll(_deps.difference(<String>{'flutter'})));
    expect(resolved.where(_bannedPackage.hasMatch).toList(), isEmpty);
  });

  test('NW-06 Gradle adds no network, analytics or crash-reporting code', () {
    final String app =
        _code(File('android/app/build.gradle.kts').readAsStringSync());
    final String deps = app.substring(app.lastIndexOf('dependencies {'));
    expect(
        <String>{
          for (final RegExpMatch m in RegExp(
                  r'(implementation|api|testImplementation|runtimeOnly|'
                  r'compileOnly)\("([^"]+)"\)')
              .allMatches(deps))
            '${m[1]} ${m[2]}',
        },
        <String>{
          'testImplementation junit:junit:4.13.2',
          'implementation androidx.biometric:biometric:1.1.0',
        });
    for (final String p in <String>[
      'android/app/build.gradle.kts',
      'android/build.gradle.kts',
      'android/settings.gradle.kts',
    ]) {
      final String s = _code(File(p).readAsStringSync());
      expect(
          RegExp(r'google-services|firebase|crashlytics|okhttp|sentry')
              .hasMatch(s),
          isFalse,
          reason: p);
    }
  });

  test('NW-07 no resolved plugin manifest requests a network permission',
      () {
    final Map<String, Object?> config = jsonDecode(
            File('.dart_tool/package_config.json').readAsStringSync())
        as Map<String, Object?>;
    final Uri base = File('.dart_tool/package_config.json').absolute.uri;
    final List<String> offenders = <String>[];
    int manifests = 0;
    for (final Object? p in config['packages']! as List<Object?>) {
      final Map<String, Object?> pkg = p! as Map<String, Object?>;
      final String root =
          base.resolve(pkg['rootUri']! as String).toFilePath();
      final File m = File('${root.endsWith('/') ? root : '$root/'}'
          'android/src/main/AndroidManifest.xml');
      if (!m.existsSync()) continue;
      manifests++;
      final Set<String> hits = _permissions(m.readAsStringSync())
          .intersection(_networkPermissions);
      if (hits.isNotEmpty) offenders.add('${pkg['name']}: $hits');
    }
    expect(manifests, greaterThanOrEqualTo(4),
        reason: 'plugin manifests must be found (pub get done)');
    expect(offenders, isEmpty);
  });
}
