import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/challenge_latency_recorder.dart';
import 'package:smart_app_lock/app/lock_challenge_host.dart';
import 'package:smart_app_lock/data/models/app_entry.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/protection/foreground_app_monitor.dart';
import 'package:smart_app_lock/protection/lock_trigger.dart';
import 'package:smart_app_lock/services/accessibility_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_accessibility_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_installed_apps_service.dart';
import 'package:smart_app_lock/services/impl/static_screen_state_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/services/screen_state_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/utilities/result.dart';

import '../support/p17_latency_device.dart';

/// Phase 17 / M2 — memory, CPU and battery: listener/timer lifecycle,
/// bounded state, fail-closed behaviour under repeated cycles, and the
/// static wiring contracts of the three native resource fixes (R1-R3).
///
/// SIMULATED / STATIC: no device RAM, CPU or battery is measured here.
void main() {
  // ------------------------------------------------------ native contracts
  group('native resource fixes (static source contracts)', () {
    const String dir = 'android/app/src/main/kotlin/com/smartapplock/app';
    String read(String f) => File('$dir/$f').readAsStringSync();
    String body(String src, String signature) {
      final int start = src.indexOf(signature);
      expect(start, isNonNegative, reason: 'missing $signature');
      int depth = 0;
      for (int i = src.indexOf('{', start); i < src.length; i++) {
        if (src[i] == '{') depth++;
        if (src[i] == '}' && --depth == 0) return src.substring(start, i + 1);
      }
      fail('unbalanced $signature');
    }

    test('R1: the heartbeat refresh posts only through the refresher', () {
      final String src = read('WatcherService.kt');
      final String refresh = body(src, 'private fun refreshNotification()');
      final int gate = refresh.indexOf('notificationRefresher.take(');
      final int skip = refresh.indexOf('if (!post) return');
      final int notify = refresh.indexOf('.notify(NOTIFICATION_ID');
      expect(gate, isNonNegative);
      expect(skip, greaterThan(gate));
      expect(notify, greaterThan(skip));
      // The health text is still derived from the engine lease, and the
      // startForeground post is recorded so the first heartbeat is not a
      // duplicate post.
      final String text = src.substring(
        src.indexOf('private fun notificationText()'),
        src.indexOf('private fun buildNotification('),
      );
      expect(text, contains('ProtectionRuntime.isEngineHealthy()'));
      expect(text, contains('"Protection engine active"'));
      expect(text, contains('"Protection recovery active"'));
      final String start = body(src, 'override fun onStartCommand(');
      expect(start.indexOf('notificationRefresher.markPosted('),
          greaterThan(start.indexOf('startForeground(')));
      // Exactly one notify() call site in the service.
      expect('.notify('.allMatches(src), hasLength(1));
      expect(body(src, 'fun heartbeat()'), contains('refreshNotification()'));
      expect(body(src, 'fun markEngineUnavailable()'),
          contains('refreshNotification()'));
    });

    test('R2: only hide() consults the standby policy; show() is untouched',
        () {
      final String src = read('ProtectionOverlayController.kt');
      final String hide = body(src, 'fun hide(): Boolean');
      final int policy = hide.indexOf('ShieldStandbyPolicy.relayoutNeeded(');
      expect(policy, isNonNegative);
      expect(hide.indexOf('manager.updateViewLayout('), greaterThan(policy));
      expect(hide.indexOf('showMultiWindowNotice(false)'), lessThan(policy));
      for (final String input in <String>[
        'showing = showing',
        'active.isAttachedToWindow',
        'active.visibility == View.INVISIBLE',
        'params.flags == standbyFlags()',
        'params.alpha == 0f',
      ]) {
        expect(hide, contains(input));
      }
      expect(body(src, 'fun show(context: Context): Boolean'),
          isNot(contains('ShieldStandbyPolicy')));
      expect(body(src, 'fun arm(context: Context): Boolean'),
          isNot(contains('ShieldStandbyPolicy')));
    });

    test('R3: the Accessibility sink is owner-checked everywhere', () {
      final String all = Directory(dir)
          .listSync()
          .whereType<File>()
          .where((File f) => f.path.endsWith('.kt'))
          .map((File f) => f.readAsStringSync())
          .join('\n');
      expect(RegExp(r'eventSink\s*=').hasMatch(all), isFalse,
          reason: 'no unchecked assignment of the static sink');
      final String channel = read('AccessibilityStatusChannel.kt');
      expect(channel, contains('attachEventSink(engine, events)'));
      expect(channel, contains('releaseEventSink(engine)'));
      final String activity = read('MainActivity.kt');
      final String cleanUp =
          body(activity, 'override fun cleanUpFlutterEngine(');
      expect(cleanUp, contains('releaseEventSink(flutterEngine)'));
      expect(cleanUp, contains('super.cleanUpFlutterEngine(flutterEngine)'));
    });

    test('R3: native enforcement never depends on the Dart sink', () {
      final String service = read('AccessibilityLockService.kt');
      final String onEvent =
          body(service, 'override fun onAccessibilityEvent(');
      expect(onEvent.indexOf('WatcherService.reportForeground('),
          lessThan(onEvent.indexOf('val sink = eventSink ?: return')));
      expect(read('WatcherService.kt'), isNot(contains('eventSink')));
    });

    test('resource policies are pure JVM code with no logging', () {
      final String src = read('ResourcePolicies.kt');
      expect(src, isNot(contains('import android')));
      for (final String token in <String>[
        'Log.',
        'println(',
        'print(',
        'System.out',
        'printStackTrace',
      ]) {
        expect(src, isNot(contains(token)), reason: token);
      }
    });
  });

  // -------------------------------------------------- listener lifecycle
  group('listener and timer lifecycle', () {
    test(
        'ForegroundAppMonitor: 50 start/stop cycles never hold more than one '
        'Accessibility subscription or poll timer', () async {
      final _CountingAccessibility a11y = _CountingAccessibility();
      final _TimerTracker timers = _TimerTracker();
      await timers.run(() async {
        final ForegroundAppMonitor monitor = ForegroundAppMonitor(
          installedApps: StaticInstalledAppsService(const <AppEntry>[]),
          accessibility: a11y,
        );
        for (int i = 0; i < 50; i++) {
          await monitor.start();
          await monitor.start(); // idempotent: no second timer/subscription
          expect(a11y.listeners, 1, reason: 'cycle $i');
          expect(timers.activePeriodic, 1, reason: 'cycle $i');
          await monitor.stop();
          await Future<void>.delayed(Duration.zero);
          expect(a11y.listeners, 0, reason: 'cycle $i');
          expect(timers.activePeriodic, 0, reason: 'cycle $i');
        }
        await monitor.dispose();
      });
      expect(a11y.maxListeners, 1);
    });

    test(
        'LockTrigger: 50 start/stop cycles keep exactly one screen-state and '
        'one Accessibility subscription, and none after dispose', () async {
      final _CountingAccessibility a11y = _CountingAccessibility();
      final _CountingScreenState screen = _CountingScreenState();
      final _TimerTracker timers = _TimerTracker();
      final AppContainer container = AppContainer.inMemory();
      await timers.run(() async {
        final ForegroundAppMonitor monitor = ForegroundAppMonitor(
          installedApps: StaticInstalledAppsService(const <AppEntry>[]),
          accessibility: a11y,
        );
        final LockTrigger trigger = LockTrigger(
          monitor: monitor,
          controller: container.accessController,
          screenState: screen,
          watcher: container.watcher,
        );
        bool lockDone = false;
        bool keyguardDone = false;
        trigger.lockRequired.listen(null, onDone: () => lockDone = true);
        trigger.keyguardDismissed
            .listen(null, onDone: () => keyguardDone = true);
        for (int i = 0; i < 50; i++) {
          await trigger.start();
          expect(screen.listeners, 1, reason: 'cycle $i');
          expect(a11y.listeners, 1, reason: 'cycle $i');
          expect(timers.activePeriodic, 1, reason: 'cycle $i');
          await trigger.stop();
          await Future<void>.delayed(Duration.zero);
          expect(screen.listeners, 0, reason: 'cycle $i');
          expect(a11y.listeners, 0, reason: 'cycle $i');
          expect(timers.activePeriodic, 0, reason: 'cycle $i');
        }
        await trigger.start();
        await trigger.dispose();
        await monitor.dispose();
        await Future<void>.delayed(Duration.zero);
        expect(screen.listeners, 0);
        expect(a11y.listeners, 0);
        expect(timers.activePeriodic, 0);
        expect(lockDone, isTrue, reason: 'lockRequired closed');
        expect(keyguardDone, isTrue, reason: 'keyguardDismissed closed');
      });
      expect(screen.maxListeners, 1);
      expect(a11y.maxListeners, 1);
    });
  });

  // ---------------------------------------------- repeated cycles (Dart)
  group('repeated cycles stay bounded and fail closed', () {
    late AppContainer container;
    late LockTrigger trigger;
    late List<LockRequired> required;

    setUp(() async {
      container = AppContainer.inMemory();
      trigger = container.lockTrigger;
      required = <LockRequired>[];
      trigger.lockRequired.listen(required.add);
      await container.protectedApps.add(ProtectedApp(
        packageName: 'com.whatsapp',
        label: 'WhatsApp',
        addedAt: DateTime(2026, 10, 22),
      ));
    });

    tearDown(() async => trigger.dispose());

    StaticAccessibilityLockService a11y() =>
        container.accessibility as StaticAccessibilityLockService;

    test(
        '300 app switches: every protected entry requires authentication, '
        'one poll timer, no extra subscriptions', () async {
      final _TimerTracker timers = _TimerTracker();
      await timers.run(() async {
        await trigger.start();
        for (int i = 0; i < 300; i++) {
          a11y().emitForegroundPackage(
              i.isEven ? 'com.whatsapp' : 'com.example.notes');
          await Future<void>.delayed(Duration.zero);
          await Future<void>.delayed(Duration.zero);
        }
        expect(timers.activePeriodic, 1);
        await trigger.stop();
        expect(timers.activePeriodic, 0);
      });
      expect(required.where((r) => r.packageName == 'com.whatsapp'),
          hasLength(150));
      expect(required.where((r) => r.packageName != 'com.whatsapp'), isEmpty);
    });

    test(
        '100 unlock/leave cycles: every return to the protected app requires '
        'authentication again (no session survives a leave)', () async {
      await trigger.start();
      for (int i = 0; i < 100; i++) {
        a11y().emitForegroundPackage('com.whatsapp');
        await Future<void>.delayed(Duration.zero);
        await Future<void>.delayed(Duration.zero);
        expect(required, hasLength(i + 1), reason: 'cycle $i');
        await container.accessController.grantAccess('com.whatsapp');
        a11y().emitForegroundPackage('com.example.notes');
        await Future<void>.delayed(Duration.zero);
        await Future<void>.delayed(Duration.zero);
      }
      expect(required, hasLength(100));
    });

    test(
        '100 screen off/on cycles: one screen-state subscription, sessions '
        'revoked on every screen-off, wake re-lock every cycle', () async {
      final StaticWatcherService watcher =
          container.watcher as StaticWatcherService;
      (container.installedAppsService as StaticInstalledAppsService)
          .foregroundPackage = 'com.whatsapp';
      await trigger.start();
      required.clear();
      for (int i = 0; i < 100; i++) {
        await container.accessController.grantAccess('com.whatsapp');
        (container.screenState as StaticScreenStateService).emitScreenOff();
        await Future<void>.delayed(Duration.zero);
        await Future<void>.delayed(Duration.zero);
        (container.screenState as StaticScreenStateService).emitScreenOn();
        for (int k = 0; k < 4; k++) {
          await Future<void>.delayed(Duration.zero);
        }
        expect(required, hasLength(i + 1), reason: 'cycle $i');
        trigger.takeScreenOffPending();
      }
      expect(watcher.revokeAllAuthorizationsCalls, 100);
    });

    test(
        'probe failures under pressure never stop detection or allow a '
        'protected app', () async {
      final _FailingInstalledApps failing = _FailingInstalledApps();
      final StaticAccessibilityLockService accessibility =
          StaticAccessibilityLockService();
      final ForegroundAppMonitor monitor = ForegroundAppMonitor(
        installedApps: failing,
        accessibility: accessibility,
      );
      final LockTrigger t = LockTrigger(
        monitor: monitor,
        controller: container.accessController,
        screenState: container.screenState,
        watcher: container.watcher,
      );
      final List<LockRequired> got = <LockRequired>[];
      t.lockRequired.listen(got.add);
      await t.start();
      for (int i = 0; i < 200; i++) {
        await monitor.probe();
      }
      expect(monitor.failureCount, greaterThanOrEqualTo(200));
      accessibility.emitForegroundPackage('com.whatsapp');
      await Future<void>.delayed(Duration.zero);
      await Future<void>.delayed(Duration.zero);
      expect(got.map((r) => r.packageName), <String>['com.whatsapp']);
      await t.dispose();
      await monitor.dispose();
    });

    test('latency recorder stays bounded over 10,000 lock cycles', () {
      int now = 0;
      final ChallengeLatencyRecorder r =
          ChallengeLatencyRecorder(nowMicros: () => now += 7);
      for (int i = 0; i < 10000; i++) {
        r.begin(ChallengeLatencySource.lockTrigger);
        for (final ChallengeLatencyStage s in ChallengeLatencyStage.values) {
          r.mark(s);
        }
      }
      expect(r.samples.length, lessThanOrEqualTo(r.capacity));
      expect(r.samples.length, r.capacity);
    });
  });

  // ------------------------------------------- host lock/unlock (widget)
  group('challenge host repeated lock/unlock (simulated)', () {
    testWidgets(
        '8 lock/unlock/leave cycles: PIN required every time, shield '
        'released only for the challenge, no timers left after unmount',
        (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      for (int i = 0; i < 8; i++) {
        await d.openProtectedApp();
        expect(find.byType(PinUnlockScreen), findsOneWidget,
            reason: 'cycle $i');
        d.expectNoAccess();
        await d.enterPin(p17Pin);
        expect(d.native.authorizedPackages, contains(p17Pkg),
            reason: 'cycle $i');
        // Leave: the screen turns off; every authorization is revoked.
        await d.screenOff();
        expect(d.native.authorizedPackages, isEmpty, reason: 'cycle $i');
        expect(d.native.shieldVisible, isTrue, reason: 'cycle $i');
        d.native.screenOn();
        d.screen.emitScreenOn();
        d.native.onActivityResumed();
        await d.lifecycle(AppLifecycleState.resumed);
        await tester.pumpAndSettle();
        await d.enterPin(p17Pin);
        expect(d.native.authorizedPackages, contains(p17Pkg),
            reason: 'wake cycle $i');
        d.native.reportForeground('com.example.notes');
        (d.container.accessibility as StaticAccessibilityLockService)
            .emitForegroundPackage('com.example.notes');
        await tester.pumpAndSettle();
      }
      expect(LockChallengeHost.latencyRecorder.samples.length,
          lessThanOrEqualTo(LockChallengeHost.latencyRecorder.capacity));
      // Unmount: flutter_test fails the test if any Timer (heartbeat, ready
      // retry, settle, poll) is still pending after the tree is disposed.
      await tester.pumpWidget(const SizedBox());
      await tester.pump(const Duration(seconds: 5));
    });
  });
}

// ------------------------------------------------------------- test doubles

class _CountingAccessibility implements AccessibilityLockService {
  int listeners = 0;
  int maxListeners = 0;
  late final StreamController<Result<String>> _c =
      StreamController<Result<String>>.broadcast(
    onListen: () {},
    onCancel: () {},
  );

  @override
  Stream<Result<String>> get foregroundPackages =>
      _CountingStream<Result<String>>(_c.stream, (int delta) {
        listeners += delta;
        if (listeners > maxListeners) maxListeners = listeners;
      });

  @override
  Future<Result<bool>> isServiceEnabled() async => Result.success(true);

  @override
  Future<Result<void>> requestServiceEnable() async => Result.success(null);
}

class _CountingScreenState implements ScreenStateService {
  int listeners = 0;
  int maxListeners = 0;
  final StreamController<Result<ScreenStateEvent>> _c =
      StreamController<Result<ScreenStateEvent>>.broadcast();

  @override
  Stream<Result<ScreenStateEvent>> get events =>
      _CountingStream<Result<ScreenStateEvent>>(_c.stream, (int delta) {
        listeners += delta;
        if (listeners > maxListeners) maxListeners = listeners;
      });
}

/// Counts live subscriptions made through it (+1 on listen, -1 on cancel).
class _CountingStream<T> extends Stream<T> {
  _CountingStream(this._inner, this._onDelta);

  final Stream<T> _inner;
  final void Function(int) _onDelta;

  @override
  bool get isBroadcast => true;

  @override
  StreamSubscription<T> listen(
    void Function(T event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    _onDelta(1);
    final StreamSubscription<T> sub = _inner.listen(onData,
        onError: onError, onDone: onDone, cancelOnError: cancelOnError);
    return _CountedSubscription<T>(sub, () => _onDelta(-1));
  }
}

class _CountedSubscription<T> implements StreamSubscription<T> {
  _CountedSubscription(this._sub, this._onCancel);

  final StreamSubscription<T> _sub;
  final void Function() _onCancel;
  bool _cancelled = false;

  @override
  Future<void> cancel() {
    if (!_cancelled) {
      _cancelled = true;
      _onCancel();
    }
    return _sub.cancel();
  }

  @override
  void onData(void Function(T data)? handleData) => _sub.onData(handleData);
  @override
  void onError(Function? handleError) => _sub.onError(handleError);
  @override
  void onDone(void Function()? handleDone) => _sub.onDone(handleDone);
  @override
  void pause([Future<void>? resumeSignal]) => _sub.pause(resumeSignal);
  @override
  void resume() => _sub.resume();
  @override
  bool get isPaused => _sub.isPaused;
  @override
  Future<E> asFuture<E>([E? futureValue]) => _sub.asFuture<E>(futureValue);
}

/// Tracks periodic timers created inside [run].
class _TimerTracker {
  final List<Timer> _periodic = <Timer>[];

  int get activePeriodic => _periodic.where((Timer t) => t.isActive).length;

  Future<void> run(Future<void> Function() body) {
    return runZoned(
      body,
      zoneSpecification: ZoneSpecification(
        createPeriodicTimer: (Zone self, ZoneDelegate parent, Zone zone,
            Duration period, void Function(Timer) f) {
          final Timer t = parent.createPeriodicTimer(zone, period, f);
          _periodic.add(t);
          return t;
        },
      ),
    );
  }
}

class _FailingInstalledApps extends StaticInstalledAppsService {
  _FailingInstalledApps() : super(const <AppEntry>[]);

  @override
  Future<Result<String?>> getForegroundPackage() async =>
      Result.failure(StateError('usage backend unavailable'));
}
