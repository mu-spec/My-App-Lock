// Phase 18 / M1 — permission status is read from Android and never assumed.
//
// SIMULATED (host tests over the production MethodChannel bridges, the
// native-health parser, the capability evaluation and the onboarding
// notification reading, with mocked platform channels). No Android device.
//
//  PS  F18-1: the notification-permission field of native health. An
//      absent or malformed value (older/garbled native reply) must never be
//      reported as granted (was `?? true`, watcher_service.dart L48).
//  PB  Core permission bridges (overlay, Accessibility, Usage Access):
//      granted / denied / null (unknown) / PlatformException (failed) /
//      MissingPlugin (unavailable) / never-answering (timed out). Only an
//      explicit Android `true` is granted.
//  RV  Revocation: a later Android `false` replaces an earlier `true`; no
//      status is cached by the bridges.
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/protection/protection_health.dart';
import 'package:smart_app_lock/services/impl/method_channel_accessibility_lock_service.dart';
import 'package:smart_app_lock/services/impl/method_channel_installed_apps_service.dart';
import 'package:smart_app_lock/services/impl/method_channel_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/method_channel_watcher_service.dart';
import 'package:smart_app_lock/services/watcher_service.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_permissions_step.dart';
import 'package:smart_app_lock/utilities/result.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final TestDefaultBinaryMessenger messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  Map<String, Object?> healthyBase() => <String, Object?>{
        'protectionConfigured': true,
        'serviceRunning': true,
        'engineState': 'healthy',
        'sdkInt': 34,
      };

  group('PS F18-1 notification permission from native health', () {
    test('PS1 absent key is never granted', () {
      final ProtectionEngineHealth h =
          ProtectionEngineHealth.fromMap(healthyBase());
      expect(h.notificationPermissionGranted, isFalse);
    });

    test('PS2 malformed values are never granted', () {
      for (final Object? v in <Object?>[
        null,
        'true',
        1,
        'yes',
        <int>[1]
      ]) {
        final ProtectionEngineHealth h = ProtectionEngineHealth.fromMap(
          <String, Object?>{
            ...healthyBase(),
            'notificationPermissionGranted': v,
          },
        );
        expect(h.notificationPermissionGranted, isFalse, reason: '$v');
      }
    });

    test('PS3 explicit Android booleans are kept as reported', () {
      expect(
        ProtectionEngineHealth.fromMap(<String, Object?>{
          ...healthyBase(),
          'notificationPermissionGranted': true,
        }).notificationPermissionGranted,
        isTrue,
      );
      expect(
        ProtectionEngineHealth.fromMap(<String, Object?>{
          ...healthyBase(),
          'notificationPermissionGranted': false,
        }).notificationPermissionGranted,
        isFalse,
      );
    });

    test(
        'PS4 through the real watcher MethodChannel: absent key -> '
        'onboarding never shows Enabled; capability never Healthy', () async {
      const MethodChannel channel = MethodChannel('p18/watcher_health');
      messenger.setMockMethodCallHandler(channel, (MethodCall call) async {
        expect(call.method, 'getHealth');
        return healthyBase();
      });
      addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
      final MethodChannelWatcherService svc =
          MethodChannelWatcherService(channel: channel);

      final Result<ProtectionEngineHealth> r = await svc.getHealth();
      expect(r.isSuccess, isTrue);
      expect(r.valueOrNull!.notificationPermissionGranted, isFalse);

      final OnboardingNotificationReading reading =
          await readOnboardingNotifications(svc.getHealth);
      expect(reading.status, isNot(OnboardingPermissionStatus.enabled));

      final ProtectionCapabilityEvaluation e =
          ProtectionCapabilityEvaluation.evaluate(
        protectionConfigured: true,
        usageAccess: true,
        accessibility: true,
        overlay: true,
        engine: r.valueOrNull!,
      );
      expect(e.notificationVisible, isFalse);
      expect(e.status, isNot(ProtectionHealthStatus.healthy));
    });

    test('PS5 failed / unavailable / null health -> onboarding unknown',
        () async {
      const MethodChannel channel = MethodChannel('p18/watcher_health_fail');
      Object? Function() reply = () => null;
      messenger.setMockMethodCallHandler(channel, (MethodCall call) async {
        final Object? v = reply();
        if (v is Exception) throw v;
        return v;
      });
      addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
      final MethodChannelWatcherService svc =
          MethodChannelWatcherService(channel: channel);

      for (final Object? Function() r in <Object? Function()>[
        () => null,
        () => PlatformException(code: 'boom'),
      ]) {
        reply = r;
        final OnboardingNotificationReading reading =
            await readOnboardingNotifications(svc.getHealth);
        expect(reading.status, OnboardingPermissionStatus.unknown);
      }
      // MissingPlugin (no handler at all).
      messenger.setMockMethodCallHandler(channel, null);
      final OnboardingNotificationReading missing =
          await readOnboardingNotifications(svc.getHealth);
      expect(missing.status, OnboardingPermissionStatus.unknown);
    });
  });

  group('PB core permission bridges', () {
    // (name, channel, method, read)
    final List<
        (
          String,
          MethodChannel,
          String,
          Future<Result<bool>> Function(MethodChannel)
        )> bridges = <(
      String,
      MethodChannel,
      String,
      Future<Result<bool>> Function(MethodChannel)
    )>[
      (
        'overlay',
        const MethodChannel('p18/overlay'),
        'isOverlayGranted',
        (MethodChannel c) =>
            MethodChannelOverlayLockService(channel: c).canDrawOverlays(),
      ),
      (
        'accessibility',
        const MethodChannel('p18/accessibility'),
        'isAccessibilityEnabled',
        (MethodChannel c) => MethodChannelAccessibilityLockService(channel: c)
            .isServiceEnabled(),
      ),
      (
        'usageAccess',
        const MethodChannel('p18/apps'),
        'hasUsageAccess',
        (MethodChannel c) =>
            MethodChannelInstalledAppsService(channel: c).hasUsageAccess(),
      ),
    ];

    for (final (
          String name,
          MethodChannel channel,
          String method,
          Future<Result<bool>> Function(MethodChannel) read
        ) in bridges) {
      test('PB-$name granted / denied / unknown / failed / unavailable',
          () async {
        Object? Function() reply = () => true;
        messenger.setMockMethodCallHandler(channel, (MethodCall call) async {
          expect(call.method, method);
          final Object? v = reply();
          if (v is Exception) throw v;
          return v;
        });
        addTearDown(() => messenger.setMockMethodCallHandler(channel, null));

        Result<bool> r = await read(channel);
        expect(r.valueOrNull, isTrue, reason: 'granted');

        reply = () => false;
        r = await read(channel);
        expect(r.valueOrNull, isFalse, reason: 'denied');

        reply = () => null;
        r = await read(channel);
        expect(r.valueOrNull == true, isFalse, reason: 'unknown');

        reply = () => PlatformException(code: 'failed');
        r = await read(channel);
        expect(r.isFailure, isTrue, reason: 'failed');
        expect(r.valueOrNull == true, isFalse);

        messenger.setMockMethodCallHandler(channel, null);
        r = await read(channel);
        expect(r.isFailure, isTrue, reason: 'unavailable (MissingPlugin)');
        expect(r.valueOrNull == true, isFalse);
      });

      test('PB-$name timed out (no reply) never resolves as granted', () async {
        final Completer<Object?> never = Completer<Object?>();
        messenger.setMockMethodCallHandler(
            channel, (MethodCall call) => never.future);
        addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
        bool? granted;
        final Future<void> pending =
            read(channel).then((Result<bool> r) => granted = r.valueOrNull);
        await Future<void>.delayed(const Duration(milliseconds: 50));
        expect(granted, isNull, reason: 'no answer is not a grant');
        never.complete(null);
        await pending;
        expect(granted == true, isFalse);
      });

      test('RV-$name revocation: a later false replaces an earlier true',
          () async {
        bool android = true;
        messenger.setMockMethodCallHandler(
            channel, (MethodCall call) async => android);
        addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
        expect((await read(channel)).valueOrNull, isTrue);
        android = false;
        expect((await read(channel)).valueOrNull, isFalse);
      });
    }
  });
}
