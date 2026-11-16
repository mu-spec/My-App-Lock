// P13/M3 NF-RG-1 — Flutter-side validation of the native last-error code.
// IDs follow m3_security_decisions/D section 7 (DE-1..3) plus DE-4..6.
// Host evidence only (SIMULATED platform channel), not device QA.
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/protection/health/protection_health_engine.dart';
import 'package:smart_app_lock/services/impl/method_channel_watcher_service.dart';
import 'package:smart_app_lock/services/watcher_last_error_code.dart';
import 'package:smart_app_lock/services/watcher_service.dart';

const List<String> canaries = <String>[
  'com.canary.protected.pkg',
  'challenge-7f3a',
  'at com.smartapplock.X(X.kt:1)',
  '\n\tat ',
  'enc:v1:AAAA',
  '%s%n',
  '\u202Eטקסט عربي 中文',
];

final DateTime t0 = DateTime.utc(2026, 11, 15, 12);

HealthSignals down(WatcherLastErrorCode? code) => HealthSignals(
      observedAt: t0,
      protectionConfigured: true,
      overlayGranted: true,
      accessibilityEnabled: true,
      usageAccessGranted: true,
      nativeHealthAvailable: true,
      watcherRunning: false,
      watcherLastError: code,
    );

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('DE-1 raw native text never survives', () {
    test('canary in lastError with no code -> unknown; detail is neutral', () {
      for (final String c in <String>[
        ...canaries,
        'Watcher start failed: com.canary.protected.pkg',
        'x' * 4096,
      ]) {
        final ProtectionEngineHealth h = ProtectionEngineHealth.fromMap(
            <String, Object?>{'serviceRunning': false, 'lastError': c});
        expect(h.lastErrorCode, WatcherLastErrorCode.unknown);
        expect(h.lastError, WatcherLastErrorCode.unknown.neutralText);
        final ProtectionHealthReport r =
            ProtectionHealthEngine.evaluate(down(h.lastErrorCode), now: t0);
        final HealthIssue issue = r.issues.firstWhere(
            (HealthIssue i) => i.code == HealthIssueCode.watcherNotRunning);
        for (final String v in issue.detail.values) {
          expect(v.contains(c), isFalse);
        }
        expect(issue.detail['lastErrorCode'], 'unknown');
      }
    });

    test('valid code with canary text: the platform text is ignored', () {
      final ProtectionEngineHealth h =
          ProtectionEngineHealth.fromMap(<String, Object?>{
        'lastErrorCode': 'overlay_unavailable',
        'lastError': 'com.canary.protected.pkg',
      });
      expect(h.lastErrorCode, WatcherLastErrorCode.overlayUnavailable);
      expect(h.lastError, WatcherLastErrorCode.overlayUnavailable.neutralText);
    });

    test('through the real MethodChannel decode path', () async {
      const MethodChannel channel = MethodChannel('smart_app_lock/watcher');
      final TestDefaultBinaryMessenger messenger = TestDefaultBinaryMessengerBinding
          .instance.defaultBinaryMessenger;
      messenger.setMockMethodCallHandler(channel, (MethodCall call) async {
        return <String, dynamic>{
          'protectionConfigured': true,
          'serviceRunning': false,
          'engineState': 'unavailable',
          'notificationPermissionGranted': true,
          'lastError': 'Watcher start failed: challenge-7f3a',
          'lastErrorCode': '../../challenge-7f3a',
        };
      });
      addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
      final ProtectionEngineHealth h =
          (await MethodChannelWatcherService().getHealth()).valueOrNull!;
      expect(h.lastErrorCode, WatcherLastErrorCode.unknown);
      expect(h.lastError!.contains('challenge-7f3a'), isFalse);
    });
  });

  group('DE-2 native / Dart allowlist parity (parsed from Kotlin source)', () {
    String src(String name) {
      for (final String d in <String>[
        'android/app/src/main/kotlin/com/smartapplock/app',
      ]) {
        final File f = File('$d/$name');
        if (f.existsSync()) return f.readAsStringSync();
      }
      fail('source $name not found');
    }

    test('same codes, same wire names, same neutral sentences', () {
      final String kt = src('LastErrorCode.kt');
      final String gate = src('WakeRecoveryGate.kt');
      final RegExpMatch? im = RegExp(
              r'const val INTERRUPTED_MESSAGE =\s*((?:"[^"]*"\s*\+?\s*)+)')
          .firstMatch(gate);
      expect(im, isNotNull);
      final String interrupted = RegExp(r'"([^"]*)"')
          .allMatches(im!.group(1)!)
          .map((RegExpMatch m) => m.group(1))
          .join();
      final Map<String, String> native = <String, String>{};
      for (final RegExpMatch m in RegExp(
              r'([A-Z_]+)\(\s*"([a-z_]+)",\s*("(?:[^"\\]|\\.)*"|WatcherTeardownPolicy\.INTERRUPTED_MESSAGE),?\s*\)')
          .allMatches(kt)) {
        final String raw = m.group(3)!;
        native[m.group(2)!] = raw.startsWith('"')
            ? raw.substring(1, raw.length - 1)
            : interrupted;
      }
      expect(native.length, 10);
      expect(<String, String>{
        for (final WatcherLastErrorCode c in WatcherLastErrorCode.values)
          c.wire: c.neutralText,
      }, native);
    });
  });

  group('DE-3 malformed or unknown codes -> unknown', () {
    test('never echoes, never trusts', () {
      for (final Object? bad in <Object?>[
        'v1:../../x',
        'v1:watcher_interrupted', // the persisted form is never sent
        'WATCHER_INTERRUPTED',
        'watcher_interrupted ',
        'not_a_code',
        '',
        'a' * 41,
        42,
        true,
        <String>['watcher_interrupted'],
        ...canaries,
      ]) {
        final WatcherLastErrorCode? c = WatcherLastErrorCode.fromNative(
            <String, Object?>{'lastErrorCode': bad});
        expect(c, WatcherLastErrorCode.unknown, reason: '$bad');
      }
    });
  });

  group('DE-4..6 compatibility', () {
    test('DE-4 nothing recorded -> null (no fabricated error)', () {
      expect(WatcherLastErrorCode.fromNative(<String, Object?>{}), isNull);
      expect(
          WatcherLastErrorCode.fromNative(
              <String, Object?>{'lastErrorCode': null, 'lastError': null}),
          isNull);
      expect(const ProtectionEngineHealth.inactive().lastError, isNull);
    });

    test('DE-5 older native build (text only): exact neutral sentence only',
        () {
      for (final WatcherLastErrorCode c in WatcherLastErrorCode.values) {
        if (c == WatcherLastErrorCode.unknown) continue;
        expect(
            WatcherLastErrorCode.fromNative(
                <String, Object?>{'lastError': c.neutralText}),
            c);
        expect(
            WatcherLastErrorCode.fromNative(
                <String, Object?>{'lastError': '${c.neutralText} '}),
            WatcherLastErrorCode.unknown);
      }
      expect(
          WatcherLastErrorCode.fromNative(
              <String, Object?>{'lastError': 'security_levels_invalid'}),
          WatcherLastErrorCode.securityLevelsInvalid);
    });

    test('DE-6 a down watcher is never neutral: attention with any code',
        () {
      for (final WatcherLastErrorCode? c in <WatcherLastErrorCode?>[
        null,
        ...WatcherLastErrorCode.values,
      ]) {
        final ProtectionHealthReport r =
            ProtectionHealthEngine.evaluate(down(c), now: t0);
        expect(r.state, isNot(ProtectionHealthState.secure), reason: '$c');
        expect(
            r.issues.any(
                (HealthIssue i) => i.code == HealthIssueCode.watcherNotRunning),
            isTrue);
      }
    });
  });
}
