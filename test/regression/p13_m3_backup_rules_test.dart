// Phase 13 / M3 Stage 1 remediation (Q-P13-6): no security data may leave
// the device through Android backup or device-to-device transfer.
//
// Static manifest/resource invariants (host test; real backup/D2D
// behaviour is physical-device QA):
//  BR-01 <application> keeps allowBackup="false" and references the
//        exclude-all rules for Android 12+ and for Android 6-11; no
//        backupAgent.
//  BR-02 data_extraction_rules.xml: exactly <cloud-backup> and
//        <device-transfer>, each excluding all nine domains at "." and
//        including nothing.
//  BR-03 backup_rules.xml (legacy full-backup-content): all nine domains
//        excluded at ".", nothing included.
//  BR-04 debug/profile manifests do not override any backup attribute and
//        use no tools:replace/remove/node on <application>.
//  BR-05 each rules file is defined exactly once (no qualified override
//        such as res/xml-v31, no copy in another source set).
//  BR-06 no resolved plugin manifest declares backup attributes or merge
//        directives on <application> (approximation of the merged release
//        manifest; the real merge needs an APK build).

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

const String _src = 'android/app/src';
const String _mainManifest = '$_src/main/AndroidManifest.xml';
const String _derPath = '$_src/main/res/xml/data_extraction_rules.xml';
const String _fbcPath = '$_src/main/res/xml/backup_rules.xml';

const Set<String> _allDomains = <String>{
  'root',
  'file',
  'database',
  'sharedpref',
  'external',
  'device_root',
  'device_file',
  'device_database',
  'device_sharedpref',
};

String _noComments(String xml) =>
    xml.replaceAll(RegExp(r'<!--[\s\S]*?-->'), '');

/// Attributes of the first start tag named [tag] (null if absent).
Map<String, String>? _attrs(String xml, String tag) {
  final Match? m = RegExp('<$tag\\b([^>]*)>').firstMatch(xml);
  if (m == null) return null;
  return <String, String>{
    for (final Match a
        in RegExp(r'([\w:.-]+)\s*=\s*"([^"]*)"').allMatches(m.group(1)!))
      a.group(1)!: a.group(2)!,
  };
}

/// Inner text of the single element [tag]; fails if absent or repeated.
String _section(String xml, String tag) {
  final List<Match> ms =
      RegExp('<$tag\\b[^>]*>([\\s\\S]*?)</$tag>').allMatches(xml).toList();
  expect(ms.length, 1, reason: 'expected exactly one <$tag>');
  return ms.single.group(1)!;
}

/// Checks a rules body: only `<exclude domain=X path="."/>`, all nine
/// domains, each once, and no `<include>`.
void _expectExcludeAll(String body, String where) {
  expect(RegExp(r'<include\b').hasMatch(body), isFalse,
      reason: '$where declares an include rule');
  final List<String> elements = RegExp(r'<([\w-]+)\b')
      .allMatches(body)
      .map((Match m) => m.group(1)!)
      .toList();
  expect(elements.toSet(), <String>{'exclude'},
      reason: '$where must contain only <exclude> elements');
  final List<String> domains = <String>[];
  for (final Match m in RegExp(r'<exclude\b([^>]*)/>').allMatches(body)) {
    final Map<String, String> a = <String, String>{
      for (final Match x
          in RegExp(r'([\w:.-]+)\s*=\s*"([^"]*)"').allMatches(m.group(1)!))
        x.group(1)!: x.group(2)!,
    };
    expect(a.keys.toSet(), <String>{'domain', 'path'},
        reason: '$where exclude has unexpected attributes: $a');
    expect(a['path'], '.', reason: '$where narrows ${a['domain']}');
    domains.add(a['domain']!);
  }
  expect(domains.length, elements.length,
      reason: '$where has a non-self-closing or malformed exclude');
  expect(domains.toSet(), _allDomains, reason: '$where domain set');
  expect(domains.length, _allDomains.length,
      reason: '$where repeats a domain');
}

void main() {
  test('BR-01 application keeps allowBackup=false and wires exclude-all rules',
      () {
    final String xml = _noComments(File(_mainManifest).readAsStringSync());
    final Map<String, String>? app = _attrs(xml, 'application');
    expect(app, isNotNull);
    expect(app!['android:allowBackup'], 'false');
    expect(app['android:dataExtractionRules'], '@xml/data_extraction_rules');
    expect(app['android:fullBackupContent'], '@xml/backup_rules');
    expect(app.containsKey('android:backupAgent'), isFalse);
    expect(app.containsKey('android:fullBackupOnly'), isFalse);
    expect(app.containsKey('android:restoreAnyVersion'), isFalse);
    expect(RegExp(r'<application\b').allMatches(xml).length, 1);
  });

  test('BR-02 data extraction rules exclude every domain from cloud backup '
      'and device transfer', () {
    final String xml = _noComments(File(_derPath).readAsStringSync());
    final Map<String, String>? root = _attrs(xml, 'data-extraction-rules');
    expect(root, isNotNull);
    expect(root, isEmpty, reason: 'no attributes on the root element');
    final String body = _section(xml, 'data-extraction-rules');
    // Exactly the two sections, no cross-platform-transfer, nothing else.
    final List<String> top = <String>[];
    int depth = 0;
    for (final Match m in RegExp(r'<(/?)([\w-]+)\b[^>]*?(/?)>').allMatches(body)) {
      final bool closing = m.group(1) == '/';
      final bool selfClosing = m.group(3) == '/';
      if (!closing && depth == 0) top.add(m.group(2)!);
      if (!closing && !selfClosing) depth++;
      if (closing) depth--;
    }
    expect(top, <String>['cloud-backup', 'device-transfer']);
    final Map<String, String>? cloud = _attrs(body, 'cloud-backup');
    expect(cloud, isEmpty,
        reason: 'no attributes that could relax cloud-backup rules');
    expect(_attrs(body, 'device-transfer'), isEmpty);
    _expectExcludeAll(_section(body, 'cloud-backup'), 'cloud-backup');
    _expectExcludeAll(_section(body, 'device-transfer'), 'device-transfer');
  });

  test('BR-03 legacy full-backup-content excludes every domain', () {
    final String xml = _noComments(File(_fbcPath).readAsStringSync());
    expect(_attrs(xml, 'full-backup-content'), isEmpty);
    _expectExcludeAll(_section(xml, 'full-backup-content'),
        'full-backup-content');
  });

  test('BR-04 debug/profile manifests do not override backup attributes', () {
    for (final String set in <String>['debug', 'profile']) {
      final File f = File('$_src/$set/AndroidManifest.xml');
      if (!f.existsSync()) continue;
      final String xml = _noComments(f.readAsStringSync());
      for (final String banned in <String>[
        'allowBackup',
        'dataExtractionRules',
        'fullBackupContent',
        'backupAgent',
        'tools:replace',
        'tools:remove',
        'tools:node',
      ]) {
        expect(xml.contains(banned), isFalse,
            reason: '$set manifest must not set $banned');
      }
    }
    // The main manifest uses no merge directives either.
    final String main = _noComments(File(_mainManifest).readAsStringSync());
    expect(RegExp(r'tools:(replace|remove|node)').hasMatch(main), isFalse);
  });

  test('BR-05 each rules file is defined exactly once', () {
    final List<String> found = <String>[];
    for (final FileSystemEntity e
        in Directory(_src).listSync(recursive: true)) {
      if (e is! File) continue;
      final String p = e.path.replaceAll(r'\', '/');
      if (p.endsWith('/data_extraction_rules.xml') ||
          p.endsWith('/backup_rules.xml')) {
        found.add(p);
      }
    }
    found.sort();
    expect(found, <String>[_fbcPath, _derPath]..sort());
  });

  test('BR-06 no plugin manifest sets backup attributes on <application>',
      () {
    final File cfg = File('.dart_tool/package_config.json');
    expect(cfg.existsSync(), isTrue, reason: 'run after pub get');
    final Map<String, dynamic> json =
        jsonDecode(cfg.readAsStringSync()) as Map<String, dynamic>;
    final Uri base = cfg.absolute.uri;
    int inspected = 0;
    final List<String> bad = <String>[];
    for (final dynamic p in json['packages'] as List<dynamic>) {
      final Map<String, dynamic> pkg = p as Map<String, dynamic>;
      final Uri root = base.resolve(pkg['rootUri'] as String);
      final String dir = root.toFilePath();
      final File m = File(
          '${dir.endsWith('/') ? dir : '$dir/'}android/src/main/AndroidManifest.xml');
      if (!m.existsSync()) continue;
      inspected++;
      final String xml = _noComments(m.readAsStringSync());
      final Map<String, String>? app = _attrs(xml, 'application');
      if (app == null) continue;
      for (final String k in app.keys) {
        if (RegExp(r'allowBackup|dataExtractionRules|fullBackupContent|'
                r'backupAgent|fullBackupOnly|tools:(replace|remove|node)')
            .hasMatch(k)) {
          bad.add('${pkg['name']}: $k=${app[k]}');
        }
      }
    }
    expect(inspected, greaterThan(0), reason: 'no plugin manifests resolved');
    expect(bad, isEmpty, reason: bad.join('\n'));
  });
}
