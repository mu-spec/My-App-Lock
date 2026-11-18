// Phase 15 final — Android 13+ notification permission in onboarding and
// "Review setup" routing from the completion screen.
//
// SIMULATED (host widget tests over the production onboarding, the Phase 7
// health engine/monitor and the in-memory container's static platform
// services). Android's notification permission state comes from
// `StaticWatcherService.notificationPermissionGranted` / `sdkInt` (native:
// `checkSelfPermission(POST_NOTIFICATIONS)` in WatcherChannel.getHealth).
// No Android Settings screen is observed. Not device QA.
//
//  N  permissions step: optional, separately explained row on Android 13+;
//     status only from Android; failure → "Couldn't check"; skippable; never
//     counted as core; tap opens Android notification settings through the
//     existing hand-off; nothing granted by onboarding.
//  R  completion screen: notifications-only gap is Setup Incomplete (never
//     active) with its own explanation; "Review setup" leads to the place
//     that fixes the first issue; nothing opens on its own.
//  F  end-to-end: notifications off → Setup Incomplete → Review setup →
//     allow in Android settings → resume → Protection Active.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/router.dart';
import 'package:smart_app_lock/app/theme/app_theme.dart';
import 'package:smart_app_lock/data/models/app_entry.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/security/credentials/biometric_options.dart';
import 'package:smart_app_lock/services/biometric_service.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/services/watcher_service.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_apps_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_decision.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_health_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_permissions_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_screen.dart';
import 'package:smart_app_lock/ui/shell/main_shell.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '482916';
const AppEntry _whatsapp =
    AppEntry(packageName: 'com.whatsapp', label: 'WhatsApp');

class _NoBiometrics implements BiometricService {
  @override
  Future<Result<bool>> isSupported() async => Result.success(false);
  @override
  Future<Result<Set<BiometricKind>>> availableKinds() async =>
      Result.success(<BiometricKind>{});
  @override
  Future<Result<bool>> authenticate({
    required String reason,
    BiometricOptions? options,
  }) async =>
      Result.success(false);
}

void main() {
  AppContainer newContainer({
    List<AppEntry> apps = const <AppEntry>[],
    bool granted = false,
  }) =>
      AppContainer.inMemory(
        biometrics: _NoBiometrics(),
        apps: apps,
        accessibilityEnabled: granted,
        overlayGranted: granted,
        usageAccessGranted: granted,
      );

  StaticWatcherService watcherOf(AppContainer c) =>
      c.watcher as StaticWatcherService;

  void nativeHealthy(AppContainer c, {bool? configured}) {
    final StaticWatcherService w = watcherOf(c);
    if (configured != null) w.protectionConfigured = configured;
    w
      ..running = true
      ..accessibilityServiceConnected = true
      ..shieldArmed = true
      ..challengePending = false
      ..backgroundRestricted = false
      ..powerSaveMode = false
      ..ignoringBatteryOptimizations = false
      ..sdkInt = 34;
  }

  Future<AppContainer> healthyContainer() async {
    final AppContainer c = newContainer(granted: true);
    await c.auth.enrollPin(_pin);
    await c.protectedApps.add(
      ProtectedApp(
        packageName: _whatsapp.packageName,
        label: _whatsapp.label,
        addedAt: DateTime(2026, 10, 1),
      ),
    );
    nativeHealthy(c, configured: true);
    return c;
  }

  void tallView(WidgetTester tester) {
    tester.view.physicalSize = const Size(800, 2000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
  }

  Future<void> tapFinder(WidgetTester tester, Finder f) async {
    await tester.ensureVisible(f);
    await tester.pumpAndSettle();
    await tester.tap(f);
    await tester.pumpAndSettle();
  }

  Future<void> tapText(WidgetTester tester, String text) =>
      tapFinder(tester, find.text(text));

  Future<void> tapDigits(WidgetTester tester, String digits) async {
    await tester.pump(const Duration(milliseconds: 250));
    for (final String d in digits.split('')) {
      await tester.tap(find.byKey(Key('pin_key_$d')));
      await tester.pump(const Duration(milliseconds: 50));
    }
    await tester.pumpAndSettle();
  }

  String statusOf(WidgetTester tester, String id) {
    final Finder pill = find.descendant(
      of: find.byKey(Key('onboarding_perm_${id}_status')),
      matching: find.byType(Text),
    );
    return tester.widget<Text>(pill.first).data!;
  }

  Future<void> resume(WidgetTester tester) async {
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
  }

  /// The permissions step alone, reading Android through [c].
  Future<int> pumpPermissions(WidgetTester tester, AppContainer c) async {
    tallView(tester);
    int continued = 0;
    await tester.pumpWidget(AppScope(
      container: c,
      child: MaterialApp(
        theme: AppTheme.light,
        onGenerateRoute: AppRouter.onGenerateRoute,
        home: Scaffold(
          body: OnboardingPermissionsStep(onContinue: () => continued++),
        ),
      ),
    ));
    await tester.pumpAndSettle();
    return continued;
  }

  int finished = 0;
  int reviewedPermissions = 0;
  int reviewedApps = 0;

  Future<void> pumpHealth(WidgetTester tester, AppContainer c) async {
    tallView(tester);
    finished = 0;
    reviewedPermissions = 0;
    reviewedApps = 0;
    await tester.pumpWidget(AppScope(
      container: c,
      child: MaterialApp(
        theme: AppTheme.light,
        home: Scaffold(
          body: OnboardingHealthStep(
            onFinish: () => finished++,
            onReviewSetup: () => reviewedPermissions++,
            onReviewApps: () => reviewedApps++,
          ),
        ),
      ),
    ));
    await tester.pumpAndSettle();
  }

  Finder outcome(OnboardingCompletion o) =>
      find.byKey(ValueKey<String>('onboarding_health_${o.name}'));

  // -------------------------------------------------------------------------
  // N: permissions step
  // -------------------------------------------------------------------------
  group('N notification permission in the permissions step', () {
    test('N1 readOnboardingNotifications maps only an Android read', () async {
      ProtectionEngineHealth h({required bool granted, int? sdk}) =>
          ProtectionEngineHealth(
            protectionConfigured: false,
            serviceRunning: false,
            engineState: ProtectionEngineState.inactive,
            notificationPermissionGranted: granted,
            sdkInt: sdk,
          );
      Future<OnboardingNotificationReading> read(
              Future<Result<ProtectionEngineHealth>> Function() p) =>
          readOnboardingNotifications(p);

      OnboardingNotificationReading r =
          await read(() async => Result.success(h(granted: true, sdk: 34)));
      expect(r.applicable, isTrue);
      expect(r.status, OnboardingPermissionStatus.enabled);
      r = await read(() async => Result.success(h(granted: false, sdk: 33)));
      expect(r.applicable, isTrue);
      expect(r.status, OnboardingPermissionStatus.notEnabled);
      r = await read(() async => Result.success(h(granted: true, sdk: 32)));
      expect(r.applicable, isFalse, reason: 'no runtime permission < 13');
      r = await read(() async => Result.success(h(granted: false)));
      expect(r.applicable, isTrue, reason: 'unknown SDK is shown');
      expect(r.status, OnboardingPermissionStatus.notEnabled);
      r = await read(() async => Result.failure(StateError('bridge')));
      expect(r.applicable, isTrue);
      expect(r.status, OnboardingPermissionStatus.unknown);
      r = await read(() async => throw StateError('channel'));
      expect(r.status, OnboardingPermissionStatus.unknown);
    });

    testWidgets(
        'N2 Android 13+, not granted: a separate optional row with its own '
        'explanation; core status and Continue are unaffected',
        (WidgetTester tester) async {
      final AppContainer c = newContainer(granted: true);
      watcherOf(c)
        ..sdkInt = 34
        ..notificationPermissionGranted = false;
      await pumpPermissions(tester, c);
      expect(
          find.text(OnboardingPermissionsStep.optionalHeading), findsOneWidget);
      expect(find.text(OnboardingPermissionsStep.notificationsWhy),
          findsOneWidget);
      expect(statusOf(tester, 'notifications'), 'Optional');
      for (final String id in <String>['accessibility', 'overlay', 'usage']) {
        expect(statusOf(tester, id), 'Enabled', reason: id);
      }
      expect(find.text(OnboardingPermissionsStep.continueLabel), findsOneWidget,
          reason: 'notifications never count toward the core set');
      expect(find.text(OnboardingPermissionsStep.incompleteNote), findsNothing);
      expect(watcherOf(c).openedSettings, isEmpty,
          reason: 'nothing opens without a tap');
    });

    testWidgets('N3 granted by Android: "Enabled"',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      watcherOf(c)
        ..sdkInt = 33
        ..notificationPermissionGranted = true;
      await pumpPermissions(tester, c);
      expect(statusOf(tester, 'notifications'), 'Enabled');
    });

    testWidgets(
        'N4 health read fails: "Couldn\'t check", never "Enabled"; '
        'continuing is still possible', (WidgetTester tester) async {
      final AppContainer c = newContainer(granted: true);
      watcherOf(c)
        ..notificationPermissionGranted = true
        ..getHealthError = StateError('bridge down');
      await pumpPermissions(tester, c);
      expect(statusOf(tester, 'notifications'), "Couldn't check");
      expect(find.textContaining('bridge down'), findsNothing);
      await tapText(tester, OnboardingPermissionsStep.continueLabel);
    });

    testWidgets('N5 below Android 13 the row is not shown',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      watcherOf(c).sdkInt = 32;
      await pumpPermissions(tester, c);
      expect(
          find.byKey(const Key('onboarding_perm_notifications')), findsNothing);
      expect(
          find.text(OnboardingPermissionsStep.optionalHeading), findsNothing);
    });

    testWidgets(
        'N6 tapping opens Android notification settings (existing hand-off); '
        'the tap grants nothing; the status changes only after Android '
        'reports it on return', (WidgetTester tester) async {
      final AppContainer c = newContainer();
      watcherOf(c)
        ..sdkInt = 34
        ..notificationPermissionGranted = false;
      await pumpPermissions(tester, c);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_perm_notifications')));
      expect(watcherOf(c).openedSettings,
          <ProtectionSettingsTarget>[ProtectionSettingsTarget.notifications]);
      expect(statusOf(tester, 'notifications'), 'Optional',
          reason: 'opening settings is not a grant');
      expect(
          find.text(OnboardingPermissionsStep.openFailedMessage), findsNothing);

      // The user allows notifications in Android settings and returns.
      watcherOf(c).notificationPermissionGranted = true;
      await resume(tester);
      expect(statusOf(tester, 'notifications'), 'Enabled');
    });

    testWidgets(
        'N7 Android cannot open the settings screen: an error is shown and '
        'the status is unchanged', (WidgetTester tester) async {
      final AppContainer c = newContainer();
      watcherOf(c)
        ..sdkInt = 34
        ..notificationPermissionGranted = false
        ..settingsOpenResult = false;
      await pumpPermissions(tester, c);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_perm_notifications')));
      expect(find.text(OnboardingPermissionsStep.openFailedMessage),
          findsOneWidget);
      expect(statusOf(tester, 'notifications'), 'Optional');
    });

    testWidgets('N8 skippable: Skip for now proceeds with notifications off',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      watcherOf(c)
        ..sdkInt = 34
        ..notificationPermissionGranted = false;
      tallView(tester);
      int continued = 0;
      await tester.pumpWidget(AppScope(
        container: c,
        child: MaterialApp(
          home: Scaffold(
            body: OnboardingPermissionsStep(onContinue: () => continued++),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      await tapText(tester, OnboardingPermissionsStep.skipLabel);
      expect(continued, 1);
      expect(watcherOf(c).openedSettings, isEmpty);
    });
  });

  // -------------------------------------------------------------------------
  // R: completion screen
  // -------------------------------------------------------------------------
  group('R completion screen and Review setup', () {
    testWidgets(
        'R1 everything working except notifications: Setup Incomplete '
        '(never active) with the notifications explanation; Review setup '
        'opens the permissions step', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      watcherOf(c).notificationPermissionGranted = false;
      await pumpHealth(tester, c);
      expect(outcome(OnboardingCompletion.setupIncomplete), findsOneWidget);
      expect(find.text(OnboardingHealthStep.activeTitle), findsNothing);
      expect(find.text(OnboardingHealthStep.notificationsOnlyMessage),
          findsOneWidget);
      expect(find.text(OnboardingHealthStep.incompleteMessage), findsNothing);
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(reviewedPermissions, 1);
      expect(reviewedApps, 0);
      expect(watcherOf(c).openedSettings, isEmpty);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'R2 a core permission missing as well: the general message, not the '
        'notifications-only one; Review setup opens permissions',
        (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      watcherOf(c).notificationPermissionGranted = false;
      (c.overlay as StaticOverlayLockService).overlayGranted = false;
      await pumpHealth(tester, c);
      expect(outcome(OnboardingCompletion.setupIncomplete), findsOneWidget);
      expect(find.text(OnboardingHealthStep.incompleteMessage), findsOneWidget);
      expect(find.text(OnboardingHealthStep.notificationsOnlyMessage),
          findsNothing);
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(reviewedPermissions, 1);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets('R3 no protected app: Review setup opens the apps step',
        (WidgetTester tester) async {
      final AppContainer c = newContainer(granted: true);
      await tester.runAsync(() => c.auth.enrollPin(_pin));
      nativeHealthy(c, configured: false);
      await pumpHealth(tester, c);
      expect(outcome(OnboardingCompletion.setupIncomplete), findsOneWidget);
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(reviewedApps, 1);
      expect(reviewedPermissions, 0);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'R4 background restricted: Review setup opens Android app settings '
        '(existing hand-off), not an onboarding step',
        (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      watcherOf(c).backgroundRestricted = true;
      await pumpHealth(tester, c);
      expect(outcome(OnboardingCompletion.setupIncomplete), findsOneWidget);
      expect(watcherOf(c).openedSettings, isEmpty,
          reason: 'nothing opens on its own');
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(watcherOf(c).openedSettings,
          <ProtectionSettingsTarget>[ProtectionSettingsTarget.appDetails]);
      expect(reviewedPermissions + reviewedApps, 0);
      expect(find.byKey(const Key('onboarding_health_message')), findsNothing);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'R5 Android cannot open the settings screen: an error is shown, '
        'still Setup Incomplete', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      watcherOf(c)
        ..backgroundRestricted = true
        ..settingsOpenResult = false;
      await pumpHealth(tester, c);
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(find.text(OnboardingHealthStep.openSettingsFailedMessage),
          findsOneWidget);
      expect(outcome(OnboardingCompletion.setupIncomplete), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    });
  });

  // -------------------------------------------------------------------------
  // F: end-to-end
  // -------------------------------------------------------------------------
  group('F end-to-end', () {
    testWidgets(
        'F1 fresh install, core granted, app protected, notifications off: '
        'Setup Incomplete → Review setup → allow in Android settings → '
        'Protection Active → shell', (WidgetTester tester) async {
      final AppContainer c =
          newContainer(apps: const <AppEntry>[_whatsapp], granted: true);
      nativeHealthy(c);
      watcherOf(c).notificationPermissionGranted = false;
      tallView(tester);
      final bool start =
          await tester.runAsync(() => shouldStartOnboarding(c.auth)) ?? false;
      await tester.pumpWidget(
          SmartAppLockApp(container: c, startWithOnboarding: start));
      await tester.pumpAndSettle();

      await tapText(tester, OnboardingScreen.getStartedLabel);
      await tapText(tester, OnboardingScreen.pinOptionTitle);
      await tapText(tester, '6-digit PIN');
      await tapDigits(tester, _pin);
      await tapDigits(tester, _pin);
      await tapText(tester, 'Done');
      await tapText(tester, OnboardingScreen.continueLabel);
      expect(statusOf(tester, 'notifications'), 'Optional');
      await tapText(tester, OnboardingPermissionsStep.continueLabel);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapText(tester, OnboardingAppsStep.protectLabel(1));
      await tester.pumpAndSettle();

      expect(outcome(OnboardingCompletion.setupIncomplete), findsOneWidget);
      expect(find.text(OnboardingHealthStep.notificationsOnlyMessage),
          findsOneWidget);
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_perm_notifications')));
      expect(watcherOf(c).openedSettings,
          <ProtectionSettingsTarget>[ProtectionSettingsTarget.notifications]);
      watcherOf(c).notificationPermissionGranted = true;
      await resume(tester);
      expect(statusOf(tester, 'notifications'), 'Enabled');
      await tapText(tester, OnboardingPermissionsStep.continueLabel);
      await tapText(tester, OnboardingAppsStep.continueLabel);
      await tester.pumpAndSettle();
      expect(outcome(OnboardingCompletion.protectionActive), findsOneWidget);
      await tapText(tester, OnboardingHealthStep.finishLabel);
      expect(find.byType(MainShell), findsOneWidget);
    });
  });
}
