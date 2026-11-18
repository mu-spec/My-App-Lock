import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/lock_challenge_host.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/protection/impl/default_access_controller.dart';
import 'package:smart_app_lock/services/impl/static_accessibility_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_native_challenge_contract.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_screen_state_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/services/pending_lock_challenge.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';

/// Phase 17 / M1 shared SIMULATED device harness (fake clock +
/// [StaticNativeChallengeContract]). Not device evidence.
///
/// The simulated before/after series is split over separate test files
/// because long single-file widget runs slow down cumulatively in this
/// harness (reproduced with the HEAD dd97c20 host as well; see
/// Phase17/M1 evidence), which is unrelated to the code under test.
const String p17Pkg = 'com.whatsapp';
const String p17Pin = '1234';

class P17Device {
  P17Device(this.tester, this.container, this.native);

  final WidgetTester tester;
  final AppContainer container;
  final StaticNativeChallengeContract native;
  AppLifecycleState _lifecycle = AppLifecycleState.resumed;

  static const List<AppLifecycleState> _ladder = <AppLifecycleState>[
    AppLifecycleState.resumed,
    AppLifecycleState.inactive,
    AppLifecycleState.hidden,
    AppLifecycleState.paused,
  ];

  StaticScreenStateService get screen =>
      container.screenState as StaticScreenStateService;
  StaticOverlayLockService get overlay =>
      container.overlay as StaticOverlayLockService;

  Future<void> lifecycle(AppLifecycleState target) async {
    int index = _ladder.indexOf(_lifecycle);
    final int goal = _ladder.indexOf(target);
    while (index != goal) {
      index += goal > index ? 1 : -1;
      _lifecycle = _ladder[index];
      tester.binding.handleAppLifecycleStateChanged(_lifecycle);
      await tester.pump();
    }
  }

  Future<void> openProtectedApp() async {
    native.reportForeground(p17Pkg);
    (container.accessibility as StaticAccessibilityLockService)
        .emitForegroundPackage(p17Pkg);
    await tester.pumpAndSettle();
  }

  Future<void> screenOff() async {
    native.screenOff();
    screen.emitScreenOff();
    await tester.pump();
    native.onActivityPaused();
    await lifecycle(AppLifecycleState.paused);
  }

  Future<void> screenOnBehindKeyguard() async {
    native.lockKeyguard();
    native.screenOn();
    screen.emitScreenOn();
    await tester.pump();
    native.onActivityResumed();
    await lifecycle(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
  }

  Future<void> enterPin(String pin) async {
    for (final String digit in pin.split('')) {
      await tester.tap(find.byKey(Key('pin_key_$digit')));
      await tester.pumpAndSettle();
    }
  }

  Object? dartSession() =>
      (container.accessController as DefaultAccessController)
          .sessionFor(p17Pkg);

  /// Nothing is usable: no Dart session and no native authorization.
  void expectNoAccess() {
    expect(dartSession(), isNull, reason: 'no Dart session before auth');
    expect(native.authorizedPackages, isEmpty,
        reason: 'no native authorization before auth');
  }

  /// Simulation resolution (fake-clock ms per pump).
  static const int stepMs = 5;

  /// Advances the fake clock in [stepMs] steps until the next ready
  /// rejection (the retry timer just fired and re-armed). False if none.
  Future<bool> alignToRetryTick() async {
    final int before = native.readyRejections.length;
    for (int i = 0; i < 2500 ~/ stepMs; i++) {
      await tester.pump(const Duration(milliseconds: stepMs));
      if (native.readyRejections.length > before) return true;
    }
    return false;
  }

  /// Fake-clock ms (resolution [stepMs]) until the shield is released, or
  /// -1 after [limitMs]. 0 means released without any clock advance.
  Future<int> msUntilShieldReleased({int limitMs = 3000}) async {
    await tester.pump();
    if (!native.shieldVisible) return 0;
    for (int ms = stepMs; ms <= limitMs; ms += stepMs) {
      await tester.pump(const Duration(milliseconds: stepMs));
      if (!native.shieldVisible) return ms;
    }
    return -1;
  }
}

Future<P17Device> p17Launch(
  WidgetTester tester, {
  bool nativeTicketBeforeMount = false,
}) async {
  tester.view.physicalSize = const Size(800, 1600);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);
  LockChallengeHost.latencyRecorder.reset();
  final AppContainer container = AppContainer.inMemory();
  final StaticNativeChallengeContract native =
      StaticNativeChallengeContract.bind(
    overlay: container.overlay as StaticOverlayLockService,
    watcher: container.watcher as StaticWatcherService,
  );
  await container.auth.enrollPin(p17Pin);
  await container.protectedApps.add(
    ProtectedApp(
      packageName: p17Pkg,
      label: 'WhatsApp',
      addedAt: DateTime(2026, 10, 22),
    ),
  );
  await container.protectionBootstrap.synchronize();
  expect(native.isProtected(p17Pkg), isTrue);
  if (nativeTicketBeforeMount) {
    // Cold start / process restore: native detected the app and persisted a
    // ticket behind the shield before any Flutter UI existed.
    native.reportForeground(p17Pkg);
    expect(native.pending?.packageName, p17Pkg);
    expect(native.shieldVisible, isTrue);
  }
  await tester.pumpWidget(SmartAppLockApp(container: container));
  await tester.pumpAndSettle();
  return P17Device(tester, container, native);
}

/// Opens the app, completes the first hand-off, sleeps, and wakes behind
/// the keyguard so that the ready acknowledgement is rejected and the
/// bounded one-second retry is armed. Returns the wake ticket.
Future<PendingLockChallenge> p17WakeBehindKeyguard(P17Device d) async {
  await d.openProtectedApp();
  expect(find.byType(PinUnlockScreen), findsOneWidget);
  expect(d.native.shieldVisible, isFalse);
  await d.screenOff();
  final PendingLockChallenge wake = d.native.pending!;
  expect(d.native.shieldVisible, isTrue);
  await d.screenOnBehindKeyguard();
  expect(d.native.readyRejections, isNotEmpty);
  expect(d.native.readyRejections.last,
      <NativeReadyRejection>{NativeReadyRejection.keyguardLocked});
  expect(d.native.shieldVisible, isTrue);
  d.expectNoAccess();
  return wake;
}
