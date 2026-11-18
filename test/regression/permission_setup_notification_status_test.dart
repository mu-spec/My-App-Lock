// Pre-Phase-16 fix — Permissions screen notification status (NS-FIX).
//
// Bug: permission_setup_screen.dart showed the optional "Protection
// notification" row as "Enabled" when Android had NOT confirmed it:
//  * a failed health read (`health.isFailure || ...`) counted as granted;
//  * the row started as granted (`'notification': true`), so it read
//    "Enabled" before the first read, with no AppScope, and whenever the
//    read threw or hung (the refresh never reached setState).
//
// Fixed contract: "Enabled" only on an explicit Android grant; denied ->
// "Not enabled"; failure / exception / timeout / no platform ->
// "Couldn't check". Re-read on resume (return from Android Settings). The
// row never affects the core (Accessibility + shield) readiness.
//
// SIMULATED: widget tests over the static watcher fake (its getHealthError
// / getHealthGate seams model a failed, thrown or slow platform channel).

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/theme/app_theme.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/ui/screens/permissions/permission_setup_screen.dart';

const String _row = 'perm_row_notification';
const String _enabled = PermissionSetupScreen.enabledLabel;
const String _notEnabled = PermissionSetupScreen.notificationNotEnabledLabel;
const String _couldNotCheck =
    PermissionSetupScreen.notificationCouldNotCheckLabel;

void main() {
  StaticWatcherService watcherOf(AppContainer c) =>
      c.watcher as StaticWatcherService;

  AppContainer container({
    bool accessibility = true,
    bool overlay = true,
  }) =>
      AppContainer.inMemory(
        accessibilityEnabled: accessibility,
        overlayGranted: overlay,
      );

  Future<void> pumpScreen(WidgetTester tester, AppContainer c,
      {bool settle = true}) async {
    await tester.pumpWidget(
      AppScope(
        container: c,
        child: MaterialApp(
          theme: AppTheme.dark,
          home: const PermissionSetupScreen(),
        ),
      ),
    );
    if (settle) {
      await tester.pumpAndSettle();
    }
  }

  /// The notification row's status text (exactly one label is shown).
  String statusOf(WidgetTester tester) {
    for (final String label in <String>[
      _enabled,
      _notEnabled,
      _couldNotCheck,
      PermissionSetupScreen.checkingLabel,
    ]) {
      if (find
          .descendant(
              of: find.byKey(const Key(_row)), matching: find.text(label))
          .evaluate()
          .isNotEmpty) {
        return label;
      }
    }
    fail('notification row shows no known status');
  }

  void expectNeverEnabled(WidgetTester tester) => expect(
        find.descendant(
            of: find.byKey(const Key(_row)), matching: find.text(_enabled)),
        findsNothing,
        reason: 'Android did not confirm the grant',
      );

  /// The user leaves for Android Settings and comes back.
  Future<void> returnFromSettings(WidgetTester tester) async {
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
  }

  group('NS-FIX states', () {
    testWidgets('S1 granted by Android: "Enabled"',
        (WidgetTester tester) async {
      final AppContainer c = container();
      watcherOf(c).notificationPermissionGranted = true;
      await pumpScreen(tester, c);
      expect(statusOf(tester), _enabled);
    });

    testWidgets('S2 denied by Android: "Not enabled"',
        (WidgetTester tester) async {
      final AppContainer c = container();
      watcherOf(c).notificationPermissionGranted = false;
      await pumpScreen(tester, c);
      expect(statusOf(tester), _notEnabled);
      expectNeverEnabled(tester);
    });

    testWidgets(
        'S3 failed health check (the old bug): "Couldn\'t check", never '
        '"Enabled"', (WidgetTester tester) async {
      final AppContainer c = container();
      watcherOf(c)
        ..notificationPermissionGranted = true
        ..getHealthError = StateError('bridge failure');
      await pumpScreen(tester, c);
      expect(statusOf(tester), _couldNotCheck);
      expectNeverEnabled(tester);
    });

    testWidgets(
        'S4 timeout: "Checking…" while waiting, then "Couldn\'t check"; a '
        'late grant is ignored', (WidgetTester tester) async {
      final AppContainer c = container();
      final Completer<void> gate = Completer<void>();
      watcherOf(c)
        ..notificationPermissionGranted = true
        ..getHealthGate = gate;
      await pumpScreen(tester, c, settle: false);
      await tester.pump();
      expect(statusOf(tester), PermissionSetupScreen.checkingLabel);
      expectNeverEnabled(tester);

      await tester.pump(PermissionSetupScreen.notificationCheckTimeout -
          const Duration(milliseconds: 100));
      expect(statusOf(tester), PermissionSetupScreen.checkingLabel);
      await tester.pump(const Duration(milliseconds: 200));
      await tester.pumpAndSettle();
      expect(statusOf(tester), _couldNotCheck);

      // Android finally answers "granted" after the timeout: not trusted.
      gate.complete();
      await tester.pumpAndSettle();
      expect(statusOf(tester), _couldNotCheck);
      expectNeverEnabled(tester);
    });

    testWidgets('S4b an answer inside the timeout is used',
        (WidgetTester tester) async {
      final AppContainer c = container();
      final Completer<void> gate = Completer<void>();
      watcherOf(c)
        ..notificationPermissionGranted = true
        ..getHealthGate = gate;
      await pumpScreen(tester, c, settle: false);
      await tester.pump(const Duration(seconds: 2));
      gate.complete();
      await tester.pumpAndSettle();
      expect(statusOf(tester), _enabled);
    });

    testWidgets(
        'S5 exception thrown by the health read: "Couldn\'t check"; the '
        'other rows still update', (WidgetTester tester) async {
      final AppContainer c = container();
      final Completer<void> gate = Completer<void>();
      watcherOf(c)
        ..notificationPermissionGranted = true
        ..getHealthGate = gate;
      await pumpScreen(tester, c, settle: false);
      gate.completeError(StateError('platform threw'));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      expect(statusOf(tester), _couldNotCheck);
      expectNeverEnabled(tester);
      // Before the fix a throw aborted the whole refresh.
      expect(find.text(PermissionSetupScreen.coreReadyLabel), findsOneWidget);
    });

    testWidgets('S6 no platform container: "Couldn\'t check", never "Enabled"',
        (WidgetTester tester) async {
      await tester.pumpWidget(MaterialApp(
        theme: AppTheme.dark,
        home: const PermissionSetupScreen(),
      ));
      await tester.pumpAndSettle();
      expect(statusOf(tester), _couldNotCheck);
      expectNeverEnabled(tester);
    });
  });

  group('NS-FIX re-check on return from Android Settings', () {
    testWidgets('R1 revoked in Settings: "Enabled" -> "Not enabled"',
        (WidgetTester tester) async {
      final AppContainer c = container();
      watcherOf(c).notificationPermissionGranted = true;
      await pumpScreen(tester, c);
      expect(statusOf(tester), _enabled);
      watcherOf(c).notificationPermissionGranted = false;
      await returnFromSettings(tester);
      expect(statusOf(tester), _notEnabled);
    });

    testWidgets('R2 allowed in Settings: "Not enabled" -> "Enabled"',
        (WidgetTester tester) async {
      final AppContainer c = container();
      watcherOf(c).notificationPermissionGranted = false;
      await pumpScreen(tester, c);
      expect(statusOf(tester), _notEnabled);
      watcherOf(c).notificationPermissionGranted = true;
      await returnFromSettings(tester);
      expect(statusOf(tester), _enabled);
    });

    testWidgets(
        'R3 the check fails on return: the earlier "Enabled" is not kept',
        (WidgetTester tester) async {
      final AppContainer c = container();
      watcherOf(c).notificationPermissionGranted = true;
      await pumpScreen(tester, c);
      expect(statusOf(tester), _enabled);
      watcherOf(c).getHealthError = StateError('bridge failure');
      await returnFromSettings(tester);
      expect(statusOf(tester), _couldNotCheck);
      expectNeverEnabled(tester);
    });

    testWidgets(
        'R4 an older, slower read cannot overwrite a newer one (stale '
        '"Enabled" after a revocation)', (WidgetTester tester) async {
      final AppContainer c = container();
      final Completer<void> gate = Completer<void>();
      watcherOf(c)
        ..notificationPermissionGranted = false
        ..getHealthGate = gate;
      await pumpScreen(tester, c, settle: false);
      await tester.pump(); // first read is now waiting on the slow channel
      watcherOf(c).getHealthGate = null;
      await returnFromSettings(tester); // newer read: denied
      expect(statusOf(tester), _notEnabled);
      // The older read now completes reporting "granted".
      watcherOf(c).notificationPermissionGranted = true;
      gate.complete();
      await tester.pumpAndSettle();
      expect(statusOf(tester), _notEnabled);
      expectNeverEnabled(tester);
    });
  });

  group('NS-FIX separation from core app locking', () {
    testWidgets(
        'C1 notifications denied or unknown do not affect core readiness',
        (WidgetTester tester) async {
      final AppContainer c = container();
      watcherOf(c).notificationPermissionGranted = false;
      await pumpScreen(tester, c);
      expect(find.text(PermissionSetupScreen.coreReadyLabel), findsOneWidget);

      watcherOf(c).getHealthError = StateError('bridge failure');
      await returnFromSettings(tester);
      expect(statusOf(tester), _couldNotCheck);
      expect(find.text(PermissionSetupScreen.coreReadyLabel), findsOneWidget);
    });

    testWidgets('C2 notifications granted cannot make core setup ready',
        (WidgetTester tester) async {
      final AppContainer c = container(accessibility: false, overlay: false);
      watcherOf(c).notificationPermissionGranted = true;
      await pumpScreen(tester, c);
      expect(statusOf(tester), _enabled);
      expect(find.text(PermissionSetupScreen.coreMissingLabel), findsOneWidget);
    });
  });
}
