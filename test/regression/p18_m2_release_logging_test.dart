// Phase 18 / M2 (M2-C) — Dart release-logging guards and the G3 gate.
//
// Static source invariants over lib/ (host test). Real release logcat is
// physical-device QA. The native side is covered by RL-01..05
// (p13_m3_release_logging_test.dart) and ReleaseLogPolicyTest.kt.
//
//  LG-01 every print / debugPrint / debugPrintStack in lib/ sits inside an
//        `assert(() {...}())` block or an `if (kDebugMode ...)` block —
//        both are compiled out of release builds — except the single
//        `[SAL_QA]` line, which must sit inside `if (_kQaDiagnostics)`.
//  LG-02 G3: `_kQaDiagnostics` is the release-gated constant; the only
//        `bool.fromEnvironment('SAL_QA_DIAG')` read is in
//        qa_diagnostics_policy.dart, and the gate is
//        `kQaDiagnosticsRequested && !kQaReleaseMode`.
//  LG-03 G3 truth table: a release build is never enabled, with or without
//        SAL_QA_DIAG=true; debug/profile + SAL_QA_DIAG=true stays enabled
//        (approved internal QA). kQaReleaseMode equals Flutter's
//        kReleaseMode.
//  LG-04 no other console/log sink: no dart:developer, stdout, stderr or
//        debugPrintSynchronously in lib/; the `[SAL_QA]` prefix appears
//        only in lock_challenge_host.dart.
//  LG-05 G5 (audit only): lib/ installs no global error handler or error
//        zone (FlutterError.onError / presentError, PlatformDispatcher
//        onError, runZonedGuarded, Isolate error listeners, ErrorWidget).
//        Adding one changes exception propagation and needs owner approval.
//  LG-06 G5: every Dart exception/error constructed with a package name in
//        its text is one of the audited sites below, each returned as a
//        Result failure or caught (never thrown to the framework's default
//        handler, which prints `exception.toString()` in release builds).
//  LG-07 G5 native: Kotlin `throw` messages are constant (no string
//        templates), and native-to-Dart error texts never interpolate a
//        package variable.

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/qa_diagnostics_policy.dart';

const String _host = 'lib/app/lock_challenge_host.dart';
const String _policy = 'lib/app/qa_diagnostics_policy.dart';
const String _nativeDir = 'android/app/src/main/kotlin/com/smartapplock/app';

List<File> _dart(String root) => Directory(root)
    .listSync(recursive: true)
    .whereType<File>()
    .where((File f) => f.path.endsWith('.dart'))
    .toList()
  ..sort((File a, File b) => a.path.compareTo(b.path));

List<File> _kotlin() => Directory(_nativeDir)
    .listSync()
    .whereType<File>()
    .where((File f) => f.path.endsWith('.kt'))
    .toList()
  ..sort((File a, File b) => a.path.compareTo(b.path));

String _norm(String p) => p.replaceAll(r'\', '/');

/// Strips block and line comments so documentation may mention the APIs.
String _code(String src) => src
    .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
    .split('\n')
    .map((String l) {
      final int i = l.indexOf('//');
      return i < 0 ? l : l.substring(0, i);
    })
    .join('\n');

/// Headers (text before `{`) of every block enclosing [pos], innermost first.
List<String> _enclosingHeaders(String s, int pos) {
  final List<String> headers = <String>[];
  int depth = 0;
  for (int i = pos - 1; i >= 0; i--) {
    final String c = s[i];
    if (c == '}') depth++;
    if (c == '{') {
      if (depth == 0) {
        final int from = i - 120 < 0 ? 0 : i - 120;
        headers.add(s.substring(from, i));
      } else {
        depth--;
      }
    }
  }
  return headers;
}

int _closeParen(String s, int open) {
  int depth = 0;
  for (int i = open; i < s.length; i++) {
    if (s[i] == '(') depth++;
    if (s[i] == ')') {
      depth--;
      if (depth == 0) return i;
    }
  }
  throw StateError('unbalanced parens at $open');
}

final RegExp _assertHeader = RegExp(r'assert\s*\(\s*\(\s*\)\s*$');
final RegExp _debugHeader = RegExp(r'if\s*\(\s*kDebugMode\b[^{;]*\)\s*$');
final RegExp _qaHeader = RegExp(r'if\s*\(\s*_kQaDiagnostics\s*\)\s*$');

/// Audited G5 sites (file -> number of package-bearing error texts).
/// Each is returned as `Result.failure` or caught by its caller:
///  * unprotect_gate.dart: 2 x StateError -> Result.failure (Phase 8/M2).
///  * protected_apps_repository_impl.dart: ArgumentError.value + StateError
///    -> Result.failure.
///  * security_profile.dart: 'Invalid package' SecurityProfileFormatException,
///    caught by SecurityProfileDocument.decode (-> store exception ->
///    Result.failure) and by the profile editor (on-screen message).
const Map<String, int> _auditedPackageErrors = <String, int>{
  'lib/ui/screens/apps/unprotect_gate.dart': 2,
  'lib/data/repositories/impl/protected_apps_repository_impl.dart': 2,
  'lib/profiles/security_profile.dart': 1,
};

/// Removes string-literal text but keeps `${...}` / `$id` interpolations.
String _withoutLiteralText(String s) {
  final StringBuffer out = StringBuffer();
  final RegExp lit =
      RegExp(r"'(?:[^'\\]|\\.)*'" r'|"(?:[^"\\]|\\.)*"');
  int last = 0;
  for (final RegExpMatch m in lit.allMatches(s)) {
    out.write(s.substring(last, m.start));
    for (final RegExpMatch i
        in RegExp(r'\$\{([^}]*)\}|\$([A-Za-z_]\w*)').allMatches(m[0]!)) {
      out.write(' ${i[1] ?? i[2]} ');
    }
    last = m.end;
  }
  out.write(s.substring(last));
  return out.toString();
}

void main() {
  test('LG-01 every Dart console print is compiled out of release builds',
      () {
    final RegExp call = RegExp(
        r'(?<![\w.])(print|debugPrint|debugPrintStack)\s*\(');
    final List<String> offenders = <String>[];
    int checked = 0;
    for (final File f in _dart('lib')) {
      final String path = _norm(f.path);
      final String s = _code(f.readAsStringSync());
      for (final RegExpMatch m in call.allMatches(s)) {
        checked++;
        final List<String> headers = _enclosingHeaders(s, m.start);
        final bool guarded = headers.any((String h) =>
            _assertHeader.hasMatch(h) ||
            _debugHeader.hasMatch(h) ||
            (path == _host && _qaHeader.hasMatch(h)));
        if (!guarded) {
          final int line = '\n'.allMatches(s.substring(0, m.start)).length + 1;
          offenders.add('$path:$line ${m[1]}');
        }
      }
    }
    expect(checked, greaterThanOrEqualTo(14),
        reason: 'the scan must see the known diagnostic prints');
    expect(offenders, isEmpty,
        reason: 'unguarded console output reaches release logcat');
  });

  test('LG-02 G3: SAL_QA_DIAG is read once, through the release gate', () {
    final List<String> readers = <String>[];
    for (final File f in _dart('lib')) {
      if (_code(f.readAsStringSync()).contains("'SAL_QA_DIAG'")) {
        readers.add(_norm(f.path));
      }
    }
    expect(readers, <String>[_policy]);

    final String policy = _code(File(_policy).readAsStringSync());
    expect(policy, isNot(contains('package:flutter')),
        reason: 'pure Dart so an AOT product compile can check it');
    expect(
        RegExp(r"const bool kQaReleaseMode\s*=\s*"
                r"bool\.fromEnvironment\('dart\.vm\.product'\);")
            .hasMatch(policy),
        isTrue);
    expect(
        RegExp(r"const bool kQaDiagnosticsRequested\s*=\s*"
                r"bool\.fromEnvironment\('SAL_QA_DIAG'\);")
            .hasMatch(policy),
        isTrue);
    expect(
        RegExp(r'const bool kQaDiagnosticsEnabled\s*=\s*'
                r'kQaDiagnosticsRequested\s*&&\s*!kQaReleaseMode;')
            .hasMatch(policy),
        isTrue);

    final String host = _code(File(_host).readAsStringSync());
    expect(
        RegExp(r'const bool _kQaDiagnostics\s*=\s*kQaDiagnosticsEnabled;')
            .hasMatch(host),
        isTrue,
        reason: 'the host must use the release-gated constant');
    expect(RegExp(r'\bkQaDiagnosticsRequested\b').hasMatch(host), isFalse);
    // The [SAL_QA] print is reachable only through _kQaDiagnostics.
    final int qa = host.indexOf("print('[SAL_QA]");
    expect(qa, greaterThan(0));
    expect(_qaHeader.hasMatch(_enclosingHeaders(host, qa).first), isTrue);
  });

  test('LG-03 G3: release is never enabled; debug/profile QA is preserved',
      () {
    // Negative: release with and without the define.
    expect(qaDiagnosticsAllowed(requested: true, releaseMode: true), isFalse);
    expect(qaDiagnosticsAllowed(requested: false, releaseMode: true), isFalse);
    // Positive: approved internal QA (debug/profile + define).
    expect(qaDiagnosticsAllowed(requested: true, releaseMode: false), isTrue);
    expect(
        qaDiagnosticsAllowed(requested: false, releaseMode: false), isFalse);
    // The compiled constants agree with Flutter and with the function.
    expect(kQaReleaseMode, kReleaseMode);
    expect(
        kQaDiagnosticsEnabled,
        qaDiagnosticsAllowed(
            requested: kQaDiagnosticsRequested, releaseMode: kReleaseMode));
    // Tests run in debug mode: the define alone decides (run once with
    // --dart-define=SAL_QA_DIAG=true for the positive compiled case).
    expect(kQaDiagnosticsEnabled, kQaDiagnosticsRequested);
  });

  test('LG-04 no other console or log sink in lib/', () {
    final RegExp banned = RegExp(
        r"import\s+'dart:developer'|(?<![\w.])(stdout|stderr)\b|"
        r'debugPrintSynchronously|developer\.log\s*\(');
    final List<String> offenders = <String>[];
    for (final File f in _dart('lib')) {
      final String s = _code(f.readAsStringSync());
      for (final RegExpMatch m in banned.allMatches(s)) {
        offenders.add('${_norm(f.path)}: ${m[0]}');
      }
      if (_norm(f.path) != _host && s.contains('[SAL_QA]')) {
        offenders.add('${_norm(f.path)}: [SAL_QA]');
      }
    }
    expect(offenders, isEmpty);
  });

  test('LG-05 G5: no global error handler or error zone is installed', () {
    final RegExp handler = RegExp(
        r'FlutterError\.(onError|presentError)\s*=|'
        r'PlatformDispatcher\.instance\.onError\s*=|'
        r'\.onError\s*=\s*\(|runZonedGuarded\s*[<(]|'
        r'addErrorListener\s*\(|ErrorWidget\.builder\s*=');
    final List<String> offenders = <String>[];
    for (final File f in _dart('lib')) {
      for (final RegExpMatch m
          in handler.allMatches(_code(f.readAsStringSync()))) {
        offenders.add('${_norm(f.path)}: ${m[0]}');
      }
    }
    expect(offenders, isEmpty,
        reason: 'a global handler changes exception propagation; it needs '
            'separate owner approval (G5 audit-only decision)');
  });

  test('LG-06 G5: package names appear only in audited error texts', () {
    final RegExp ctor = RegExp(
        r'(?<![\w.])([A-Z]\w*(?:Exception|Error))(\.\w+)?\s*\(');
    final RegExp pkg = RegExp(r'\b\w*(?:[Pp]ackage|[Pp]kg)\w*\b');
    final Map<String, int> found = <String, int>{};
    for (final File f in _dart('lib')) {
      final String s = _code(f.readAsStringSync());
      for (final RegExpMatch m in ctor.allMatches(s)) {
        final String before =
            s.substring(m.start < 40 ? 0 : m.start - 40, m.start);
        // Declarations (`class X`, `on X catch`, ...) are not uses.
        if (RegExp(r'\b(class|on|extends|implements|with)\s+$')
            .hasMatch(before)) {
          continue;
        }
        final int open = m.end - 1;
        final String args =
            _withoutLiteralText(s.substring(open + 1, _closeParen(s, open)));
        if (pkg.hasMatch(args)) {
          final String path = _norm(f.path);
          found[path] = (found[path] ?? 0) + 1;
        }
      }
    }
    expect(found, _auditedPackageErrors,
        reason: 'a new error text carrying a package name must be audited '
            '(returned as a Result failure or caught) before it is listed');
  });

  test('LG-07 G5 native: constant throw messages, no package in error texts',
      () {
    final List<String> offenders = <String>[];
    for (final File f in _kotlin()) {
      final String s = _code(f.readAsStringSync());
      for (final RegExpMatch m
          in RegExp(r'\bthrow\s+[A-Za-z_.]+\s*\(').allMatches(s)) {
        final int open = m.end - 1;
        final String args = s.substring(open + 1, _closeParen(s, open));
        if (args.contains(r'$')) offenders.add('${_norm(f.path)}: ${m[0]}');
      }
      for (final RegExpMatch m
          in RegExp(r'\.error\s*\(').allMatches(s)) {
        final int open = m.end - 1;
        final String args = s.substring(open + 1, _closeParen(s, open));
        if (RegExp(r'\$\{?[\w.]*(?:[Pp]ackage|[Pp]kg)').hasMatch(args)) {
          offenders.add('${_norm(f.path)}: result.error($args)');
        }
      }
    }
    expect(offenders, isEmpty);
  });
}
