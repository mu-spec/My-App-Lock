// Phase 18 / M3 (M3-A) — Accessibility use stays narrowly scoped.
//
// PRD v2.1 Phase 18 / M3: "Verify Accessibility use, if any, remains narrowly
// scoped." Static source invariants (evidence C; host test). Device behaviour
// is physical-device QA. Lifecycle revocation (A11Y-1) is covered by
// P17M3StressRecoveryTest.kt and P18M3AccessibilityInvariantsTest.kt.
//
//  AX-01 the service configuration requests window-state events only, with
//        window content retrieval disabled and no capability flags
//        (gestures, key filtering, touch exploration, screenshots,
//        magnification, fingerprint gestures, accessibility-tool claim).
//  AX-02 the manifest declares exactly one AccessibilityService: not
//        exported, bound only by the system (BIND_ACCESSIBILITY_SERVICE),
//        configured by that resource; the user-facing description says no
//        screen content is read.
//  AX-03 the service never reads window content or acts for the user (no
//        node tree, event text, window list, global action, gesture,
//        screenshot or runtime re-configuration).
//  AX-04 data minimisation: only TYPE_WINDOW_STATE_CHANGED is handled, the
//        own package is skipped, Dart receives the package name only, and
//        the window class goes only to native enforcement (never to Dart,
//        a log, the last-error slot or storage). The service persists
//        nothing.
//  AX-05 the service never grants: no authorize / grant / ticket
//        acknowledgement anywhere in it; both disconnect callbacks keep the
//        A11Y-1 revocation.
//  AX-06 no other component in the app is an AccessibilityService.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

const String _k = 'android/app/src/main/kotlin/com/smartapplock/app';
const String _service = '$_k/AccessibilityLockService.kt';
const String _config = 'android/app/src/main/res/xml/accessibility_service_config.xml';
const String _manifest = 'android/app/src/main/AndroidManifest.xml';

String _xml(String s) => s.replaceAll(RegExp(r'<!--[\s\S]*?-->'), '');

String _code(String src) => src
    .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
    .split('\n')
    .map((String l) {
      final int i = l.indexOf('//');
      return i < 0 ? l : l.substring(0, i);
    })
    .join('\n');

String _body(String s, String start) {
  final int a = s.indexOf(start);
  expect(a, greaterThanOrEqualTo(0), reason: 'missing $start');
  final int open = s.indexOf('{', a);
  int depth = 0;
  for (int i = open; i < s.length; i++) {
    if (s[i] == '{') depth++;
    if (s[i] == '}' && --depth == 0) return s.substring(open + 1, i);
  }
  throw StateError('unbalanced $start');
}

void main() {
  test('AX-01 configuration: window-state events only, no capabilities', () {
    final String x = _xml(File(_config).readAsStringSync());
    final Map<String, String> attrs = <String, String>{
      for (final RegExpMatch m
          in RegExp(r'android:(\w+)="([^"]*)"').allMatches(x))
        m[1]!: m[2]!,
    };
    expect(attrs, <String, String>{
      'accessibilityEventTypes': 'typeWindowStateChanged',
      'accessibilityFeedbackType': 'feedbackGeneric',
      'canRetrieveWindowContent': 'false',
      'description': '@string/accessibility_service_description',
      'notificationTimeout': '0',
    });
    // Not even present as false: a capability attribute needs an audit.
    for (final String banned in <String>[
      'accessibilityFlags', 'packageNames', 'canPerformGestures',
      'canRequestFilterKeyEvents', 'canRequestTouchExplorationMode',
      'canRequestEnhancedWebAccessibility', 'canTakeScreenshot',
      'canControlMagnification', 'canRequestFingerprintGestures',
      'isAccessibilityTool', 'settingsActivity', //
    ]) {
      expect(x.contains(banned), isFalse, reason: banned);
    }
  });

  test('AX-02 manifest: one private, system-bound accessibility service', () {
    final String m = _xml(File(_manifest).readAsStringSync());
    final List<RegExpMatch> services =
        RegExp(r'<service\b[\s\S]*?</service>').allMatches(m).toList();
    final List<String> a11y = <String>[
      for (final RegExpMatch s in services)
        if (s[0]!.contains('android.accessibilityservice.AccessibilityService'))
          s[0]!,
    ];
    expect(a11y, hasLength(1));
    final String s = a11y.single;
    expect(s.contains('android:name=".AccessibilityLockService"'), isTrue);
    expect(s.contains('android:exported="false"'), isTrue);
    expect(
        s.contains(
            'android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"'),
        isTrue);
    expect(s.contains('android:resource="@xml/accessibility_service_config"'),
        isTrue);
    expect('BIND_ACCESSIBILITY_SERVICE'.allMatches(m), hasLength(1));
    final String strings =
        File('android/app/src/main/res/values/strings.xml').readAsStringSync();
    expect(
        RegExp(r'name="accessibility_service_description">[^<]*'
                r'No screen content is read')
            .hasMatch(strings),
        isTrue);
  });

  test('AX-03 the service never reads content or acts for the user', () {
    final String s = _code(File(_service).readAsStringSync());
    for (final String banned in <String>[
      'rootInActiveWindow', 'getRootInActiveWindow', 'AccessibilityNodeInfo',
      'event.source', '.getSource(', 'event.text', '.contentDescription',
      'beforeText', 'windows', 'getWindows', 'findFocus',
      'performGlobalAction', 'performAction', 'dispatchGesture',
      'GestureDescription', 'takeScreenshot', 'serviceInfo', 'setServiceInfo',
      'softKeyboardController', 'magnificationController',
      'fingerprintGestureController', 'onKeyEvent', 'onGesture', //
    ]) {
      expect(s.contains(banned), isFalse, reason: banned);
    }
  });

  test('AX-04 package name only to Dart; class only to native; no storage',
      () {
    final String s = _code(File(_service).readAsStringSync());
    final String onEvent = _body(s, 'override fun onAccessibilityEvent(');
    expect(
        onEvent.contains(
            'if (type != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {'),
        isTrue);
    expect(
        onEvent.contains('if (packageName == applicationContext.packageName)'),
        isTrue);
    expect(RegExp(r'sink\.success\(([^)]*)\)').allMatches(onEvent).map(
          (RegExpMatch m) => m[1],
        ), <String>['packageName']);
    // The window class is read once and passed only to native enforcement.
    expect('event.className'.allMatches(s), hasLength(1));
    final int cls = onEvent.indexOf('event.className');
    final int report = onEvent.lastIndexOf('WatcherService.reportForeground(', cls);
    expect(report, greaterThanOrEqualTo(0));
    expect(onEvent.substring(report, cls).contains(')'), isFalse,
        reason: 'className must be an argument of reportForeground');
    for (final RegExpMatch m
        in RegExp(r'DiagLog\.\w\([^\n]*').allMatches(s)) {
      expect(m[0]!.contains('className'), isFalse);
    }
    for (final String banned in <String>[
      'setLastError', 'getSharedPreferences', 'edit()', 'putString',
      'configure(', 'rememberWakeReauthPackage', 'openFileOutput', //
    ]) {
      expect(s.contains(banned), isFalse, reason: banned);
    }
  });

  test('AX-05 the service never grants; both disconnects revoke', () {
    final String s = _code(File(_service).readAsStringSync());
    for (final String banned in <String>[
      'authorize(', 'grant', 'acknowledge', 'consumeChallengeHandoff',
      'markReady', 'clearPendingChallenge', //
    ]) {
      expect(s.toLowerCase().contains(banned.toLowerCase()), isFalse,
          reason: banned);
    }
    for (final String cb in <String>[
      'override fun onUnbind(',
      'override fun onDestroy()', //
    ]) {
      final String b = _body(s, cb);
      expect(b.contains('AccessibilityConnection.onDisconnected()'), isTrue);
      expect(b.contains('revokeOnDisconnect()'), isTrue);
    }
    final String helper = _body(s, 'private fun revokeOnDisconnect()');
    expect(helper.contains('ProtectionAccessState.revokeAll()'), isTrue);
  });

  test('AX-06 no other AccessibilityService in native sources', () {
    final List<String> subclasses = <String>[
      for (final File f in Directory('android/app/src/main')
          .listSync(recursive: true)
          .whereType<File>()
          .where((File f) => f.path.endsWith('.kt') || f.path.endsWith('.java')))
        if (RegExp(r':\s*AccessibilityService\s*\(')
            .hasMatch(_code(f.readAsStringSync())))
          f.path.replaceAll(r'\', '/').split('/').last,
    ];
    expect(subclasses, <String>['AccessibilityLockService.kt']);
  });
}
