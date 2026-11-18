// Phase 15 / Milestone 2 — Permission Guidance & App Selection.
//
// SIMULATED (host widget tests over the production app root, onboarding,
// existing permission setup screens, repositories and bootstrap; Android
// capability state comes from the static platform services, the biometric
// OS layer is a fake). Not device QA.
//
//  P  permission education + guided setup: status only from Android reads;
//     "Enabled" only on a confirmed grant; failures shown as "Couldn't
//     check"; existing setup flows reused; denial/cancel leave state as-is;
//     nothing is granted by onboarding.
//  A  suggested apps: reviewed catalog only, unselected by default, only an
//     explicit "Protect" adds protection, never resets an existing record,
//     unreadable protection set fails closed, nothing logged.
//  I  integration: continues from M1; interrupted onboarding never forces
//     an existing user through it again; credential-less restart restarts.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/router.dart';
import 'package:smart_app_lock/data/models/app_entry.dart';
import 'package:smart_app_lock/data/models/app_security_level.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/models/security_recommendation.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_key_value_store.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/biometric_options.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/services/biometric_service.dart';
import 'package:smart_app_lock/services/impl/static_accessibility_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_installed_apps_service.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_apps_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_decision.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_permissions_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_screen.dart';
import 'package:smart_app_lock/ui/screens/permissions/accessibility_setup_screen.dart';
import 'package:smart_app_lock/ui/screens/permissions/overlay_setup_screen.dart';
import 'package:smart_app_lock/ui/screens/permissions/usage_access_screen.dart';
import 'package:smart_app_lock/ui/shell/main_shell.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '482916';

const AppEntry _whatsapp =
    AppEntry(packageName: 'com.whatsapp', label: 'WhatsApp');
const AppEntry _bitwarden =
    AppEntry(packageName: 'com.x8bit.bitwarden', label: 'Bitwarden');
const AppEntry _easypaisa =
    AppEntry(packageName: 'pk.com.telenor.phoenix', label: 'Easypaisa');
const AppEntry _game =
    AppEntry(packageName: 'com.example.game', label: 'Some Game');

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

/// Database double: optionally fails protection reads or specific writes.
class _Db extends InMemoryLocalDatabase {
  bool failReads = false;
  Set<String> failWritesFor = <String>{};
  int writes = 0;

  @override
  Future<List<ProtectedApp>> getProtectedApps() async {
    if (failReads) throw StateError('db unavailable');
    return super.getProtectedApps();
  }

  @override
  Future<void> saveProtectedApp(ProtectedApp app) async {
    writes++;
    if (failWritesFor.contains(app.packageName)) {
      throw StateError('write failed');
    }
    return super.saveProtectedApp(app);
  }
}

void main() {
  AppContainer newContainer({
    List<AppEntry> apps = const <AppEntry>[],
    bool accessibility = false,
    bool overlay = false,
    bool usage = false,
    _Db? db,
    InMemorySecretStore? secrets,
    InMemoryKeyValueStore? kv,
  }) =>
      AppContainer.inMemory(
        biometrics: _NoBiometrics(),
        apps: apps,
        accessibilityEnabled: accessibility,
        overlayGranted: overlay,
        usageAccessGranted: usage,
        database: db,
        secretStore: secrets,
        keyValueStore: kv,
      );

  StaticAccessibilityLockService a11y(AppContainer c) =>
      c.accessibility as StaticAccessibilityLockService;
  StaticOverlayLockService overlayOf(AppContainer c) =>
      c.overlay as StaticOverlayLockService;
  StaticInstalledAppsService usageOf(AppContainer c) =>
      c.installedAppsService as StaticInstalledAppsService;

  Future<Set<String>> protectedSet(AppContainer c) async =>
      (await c.protectedApps.getProtectedApps())
          .valueOrNull!
          .map((ProtectedApp p) => p.packageName)
          .toSet();

  Future<void> pumpApp(WidgetTester tester, AppContainer c) async {
    tester.view.physicalSize = const Size(800, 1800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    final bool start =
        await tester.runAsync(() => shouldStartOnboarding(c.auth)) ?? false;
    await tester.pumpWidget(
      SmartAppLockApp(container: c, startWithOnboarding: start),
    );
    await tester.pumpAndSettle();
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

  /// M1: Welcome → PIN → (no biometric hardware) Continue → permissions.
  Future<void> throughM1(WidgetTester tester) async {
    await tapText(tester, OnboardingScreen.getStartedLabel);
    await tapText(tester, OnboardingScreen.pinOptionTitle);
    await tapText(tester, '6-digit PIN');
    await tapDigits(tester, _pin);
    await tapDigits(tester, _pin);
    await tapText(tester, 'Done');
    await tapText(tester, OnboardingScreen.continueLabel);
    expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
  }

  Future<void> toApps(WidgetTester tester) async {
    await throughM1(tester);
    final Finder skip = find.text(OnboardingPermissionsStep.skipLabel);
    await tapFinder(
      tester,
      skip.evaluate().isNotEmpty
          ? skip
          : find.text(OnboardingPermissionsStep.continueLabel),
    );
    expect(find.text(OnboardingAppsStep.title), findsOneWidget);
  }

  String statusOf(WidgetTester tester, String id) {
    final Finder pill = find.descendant(
      of: find.byKey(Key('onboarding_perm_${id}_status')),
      matching: find.byType(Text),
    );
    return tester.widget<Text>(pill.first).data!;
  }

  Finder shell() => find.byType(MainShell);

  // -------------------------------------------------------------------------
  // P: permissions
  // -------------------------------------------------------------------------
  group('P permission education and guided setup', () {
    test('P1 only a confirmed Android grant is "enabled"', () async {
      expect(
        await readOnboardingPermission(() async => Result.success(true)),
        OnboardingPermissionStatus.enabled,
      );
      expect(
        await readOnboardingPermission(() async => Result.success(false)),
        OnboardingPermissionStatus.notEnabled,
      );
      expect(
        await readOnboardingPermission(
            () async => Result.failure(StateError('x'))),
        OnboardingPermissionStatus.unknown,
      );
      expect(
        await readOnboardingPermission(() async => throw StateError('boom')),
        OnboardingPermissionStatus.unknown,
      );
    });

    test(
        'P2 every capability has a plain explanation and an existing '
        'setup route', () {
      final Set<String> routes = <String>{
        RouteNames.accessibilitySetup,
        RouteNames.overlaySetup,
        RouteNames.usageAccess,
      };
      expect(OnboardingPermissionsStep.permissions.map((p) => p.route).toSet(),
          routes);
      for (final OnboardingPermission p
          in OnboardingPermissionsStep.permissions) {
        expect(p.why.length, greaterThan(40), reason: p.id);
        expect(
          AppRouter.onGenerateRoute(RouteSettings(name: p.route)),
          isNotNull,
          reason: p.route,
        );
      }
    });

    testWidgets(
        'P3 nothing granted: no "Enabled" claim, skip is explicit '
        'and the incomplete note is shown', (WidgetTester tester) async {
      await pumpApp(tester, newContainer());
      await throughM1(tester);
      expect(statusOf(tester, 'accessibility'), 'Required');
      expect(statusOf(tester, 'overlay'), 'Required');
      expect(statusOf(tester, 'usage'), 'Recommended');
      expect(find.text(OnboardingPermissionsStep.enabledLabel), findsNothing);
      expect(
          find.text(OnboardingPermissionsStep.incompleteNote), findsOneWidget);
      expect(find.text(OnboardingPermissionsStep.skipLabel), findsOneWidget);
      expect(find.text(OnboardingPermissionsStep.continueLabel), findsNothing);
    });

    testWidgets('P4 all granted by Android: all "Enabled", Continue',
        (WidgetTester tester) async {
      await pumpApp(
        tester,
        newContainer(accessibility: true, overlay: true, usage: true),
      );
      await throughM1(tester);
      for (final String id in <String>['accessibility', 'overlay', 'usage']) {
        expect(statusOf(tester, id), 'Enabled', reason: id);
      }
      expect(find.text(OnboardingPermissionsStep.incompleteNote), findsNothing);
      expect(
          find.text(OnboardingPermissionsStep.continueLabel), findsOneWidget);
    });

    testWidgets(
        'P5 unreadable capability state is "Couldn\'t check", '
        'never "Enabled"', (WidgetTester tester) async {
      final AppContainer c = newContainer();
      tester.view.physicalSize = const Size(800, 1800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(AppScope(
        container: c,
        child: MaterialApp(
          onGenerateRoute: AppRouter.onGenerateRoute,
          home: Scaffold(
            body: OnboardingPermissionsStep(
              onContinue: () {},
              probes: <String, OnboardingPermissionProbe>{
                'accessibility': () async => Result.failure(StateError('x')),
                'overlay': () async => throw StateError('channel'),
                // 'usage' missing entirely -> unknown
              },
            ),
          ),
        ),
      ));
      await tester.pumpAndSettle();
      for (final String id in <String>['accessibility', 'overlay', 'usage']) {
        expect(statusOf(tester, id), "Couldn't check", reason: id);
      }
      expect(find.text(OnboardingPermissionsStep.enabledLabel), findsNothing);
      expect(find.text(OnboardingPermissionsStep.skipLabel), findsOneWidget);
    });

    testWidgets(
        'P6 guided setup reuses the existing flows; denial/cancel changes '
        'nothing; a real grant is picked up on return and on resume',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await throughM1(tester);

      // Accessibility: existing disclosure screen; user opens Android
      // settings but does not enable (denial), then comes back.
      await tapFinder(
          tester, find.byKey(const Key('onboarding_perm_accessibility')));
      expect(find.byType(AccessibilitySetupScreen), findsOneWidget);
      expect(
          find.text(AccessibilitySetupScreen.disclosureTitle), findsOneWidget);
      await tapText(tester, AccessibilitySetupScreen.openSettingsLabel);
      expect(a11y(c).requestServiceEnableCalls, 1);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.byType(AccessibilitySetupScreen), findsNothing);
      expect(statusOf(tester, 'accessibility'), 'Required');
      expect(a11y(c).enabled, isFalse, reason: 'onboarding never grants');

      // Overlay: cancelled straight away (no settings opened).
      await tapFinder(tester, find.byKey(const Key('onboarding_perm_overlay')));
      expect(find.byType(OverlaySetupScreen), findsOneWidget);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(statusOf(tester, 'overlay'), 'Required');
      expect(overlayOf(c).requestCalls, 0);

      // Usage: the user really grants it in Android, then returns.
      await tapFinder(tester, find.byKey(const Key('onboarding_perm_usage')));
      expect(find.byType(UsageAccessScreen), findsOneWidget);
      usageOf(c).usageAccessGranted = true;
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(statusOf(tester, 'usage'), 'Enabled');

      // Accessibility and overlay granted in Android settings directly,
      // picked up when the app resumes.
      a11y(c).enabled = true;
      overlayOf(c).overlayGranted = true;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(statusOf(tester, 'accessibility'), 'Enabled');
      expect(statusOf(tester, 'overlay'), 'Enabled');
      expect(
          find.text(OnboardingPermissionsStep.continueLabel), findsOneWidget);
    });

    testWidgets('P7 a revoked grant is reported again on resume',
        (WidgetTester tester) async {
      final AppContainer c =
          newContainer(accessibility: true, overlay: true, usage: true);
      await pumpApp(tester, c);
      await throughM1(tester);
      expect(statusOf(tester, 'accessibility'), 'Enabled');
      a11y(c).enabled = false;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(statusOf(tester, 'accessibility'), 'Required');
      expect(find.text(OnboardingPermissionsStep.skipLabel), findsOneWidget);
    });
  });

  // -------------------------------------------------------------------------
  // A: suggested apps
  // -------------------------------------------------------------------------
  group('A suggested apps', () {
    test(
        'A1 suggestions come only from the reviewed catalog, ordered by '
        'category then label', () {
      final List<OnboardingAppSuggestion> s = onboardingSuggestions(
        const <AppEntry>[_game, _whatsapp, _bitwarden, _easypaisa, _whatsapp],
      );
      expect(s.map((x) => x.app.packageName).toList(), <String>[
        'pk.com.telenor.phoenix', // finance
        'com.x8bit.bitwarden', // password manager
        'com.whatsapp', // privacy
      ]);
      expect(s.first.category, SensitiveAppCategory.finance);
      expect(onboardingSuggestions(const <AppEntry>[_game]), isEmpty);
    });

    testWidgets('A2 suggestions start unselected; Skip protects nothing',
        (WidgetTester tester) async {
      final AppContainer c =
          newContainer(apps: const <AppEntry>[_whatsapp, _bitwarden, _game]);
      await pumpApp(tester, c);
      await toApps(tester);
      expect(find.text('WhatsApp'), findsOneWidget);
      expect(find.text('Bitwarden'), findsOneWidget);
      expect(find.text('Some Game'), findsNothing);
      expect(find.byIcon(Icons.check_box), findsNothing);
      final DsButtonFinder protect = DsButtonFinder(tester);
      expect(protect.enabled, isFalse, reason: 'nothing selected');

      await tapText(tester, OnboardingAppsStep.skipLabel);
      expect(shell(), findsOneWidget);
      expect(await tester.runAsync(() => protectedSet(c)), isEmpty);
    });

    testWidgets(
        'A3 only the explicitly selected apps are protected, at the '
        'default level', (WidgetTester tester) async {
      final AppContainer c = newContainer(
          apps: const <AppEntry>[_whatsapp, _bitwarden, _easypaisa]);
      await pumpApp(tester, c);
      await toApps(tester);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapFinder(tester,
          find.byKey(const Key('onboarding_app_pk.com.telenor.phoenix')));
      // Changing one's mind: select then deselect Bitwarden.
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.x8bit.bitwarden')));
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.x8bit.bitwarden')));
      expect(await tester.runAsync(() => protectedSet(c)), isEmpty,
          reason: 'selection alone writes nothing');

      await tapText(tester, OnboardingAppsStep.protectLabel(2));
      expect(shell(), findsOneWidget);
      final List<ProtectedApp> saved =
          (await tester.runAsync(() => c.protectedApps.getProtectedApps()))!
              .valueOrNull!;
      expect(saved.map((p) => p.packageName).toSet(),
          <String>{'com.whatsapp', 'pk.com.telenor.phoenix'});
      for (final ProtectedApp p in saved) {
        expect(p.securityLevel, AppSecurityLevel.standard, reason: p.label);
      }
    });

    testWidgets(
        'A4 an already-protected app is shown as Protected, cannot be '
        'toggled and keeps its stricter level', (WidgetTester tester) async {
      final AppContainer c =
          newContainer(apps: const <AppEntry>[_whatsapp, _bitwarden]);
      await tester.runAsync(() async {
        await c.protectedApps.add(ProtectedApp(
            packageName: 'com.x8bit.bitwarden',
            label: 'Bitwarden',
            addedAt: DateTime(2026)));
        await c.protectedApps
            .setSecurityLevel('com.x8bit.bitwarden', AppSecurityLevel.critical);
      });
      await pumpApp(tester, c);
      await toApps(tester);
      expect(
        find.descendant(
          of: find.byKey(const Key('onboarding_app_com.x8bit.bitwarden')),
          matching: find.text(OnboardingAppsStep.alreadyProtectedLabel),
        ),
        findsOneWidget,
      );
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.x8bit.bitwarden')));
      expect(find.text(OnboardingAppsStep.protectLabel(1)), findsNothing);

      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapText(tester, OnboardingAppsStep.protectLabel(1));
      final List<ProtectedApp> saved =
          (await tester.runAsync(() => c.protectedApps.getProtectedApps()))!
              .valueOrNull!;
      final ProtectedApp bw =
          saved.firstWhere((p) => p.packageName == 'com.x8bit.bitwarden');
      expect(bw.securityLevel, AppSecurityLevel.critical);
      expect(bw.addedAt, DateTime(2026), reason: 'record never re-added');
    });

    testWidgets(
        'A5 unreadable protection set fails closed: no suggestions, nothing '
        'written', (WidgetTester tester) async {
      final _Db db = _Db()..failReads = true;
      final AppContainer c =
          newContainer(apps: const <AppEntry>[_whatsapp], db: db);
      await pumpApp(tester, c);
      await toApps(tester);
      expect(find.text(OnboardingAppsStep.loadFailedText), findsOneWidget);
      expect(find.text('WhatsApp'), findsNothing);
      expect(
          find.byKey(const Key('onboarding_protect_selected')), findsNothing);

      // Retry recovers once storage is readable again.
      db.failReads = false;
      await tapText(tester, OnboardingAppsStep.retryLabel);
      expect(find.text('WhatsApp'), findsOneWidget);
      db.failReads = true;
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapText(tester, OnboardingAppsStep.protectLabel(1));
      // The pre-write re-read failed: nothing written, error shown.
      expect(find.text(OnboardingAppsStep.loadFailedText), findsOneWidget);
      expect(db.writes, 0);
      await tapText(tester, OnboardingAppsStep.continueLabel);
      expect(shell(), findsOneWidget);
      expect(db.writes, 0);
    });

    testWidgets('A6 a failed write is reported and stays selected',
        (WidgetTester tester) async {
      final _Db db = _Db()..failWritesFor = <String>{'com.whatsapp'};
      final AppContainer c =
          newContainer(apps: const <AppEntry>[_whatsapp, _bitwarden], db: db);
      await pumpApp(tester, c);
      await toApps(tester);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.x8bit.bitwarden')));
      await tapText(tester, OnboardingAppsStep.protectLabel(2));
      expect(find.text(OnboardingAppsStep.partialFailure(1)), findsOneWidget);
      expect(shell(), findsNothing);
      expect(await tester.runAsync(() => protectedSet(c)),
          <String>{'com.x8bit.bitwarden'});
      expect(find.text(OnboardingAppsStep.protectLabel(1)), findsOneWidget);
    });

    testWidgets('A7 no installed app list or package name is logged',
        (WidgetTester tester) async {
      final List<String> logs = <String>[];
      final void Function(String?, {int? wrapWidth}) original = debugPrint;
      debugPrint = (String? m, {int? wrapWidth}) => logs.add(m ?? '');
      addTearDown(() => debugPrint = original);
      final AppContainer c =
          newContainer(apps: const <AppEntry>[_whatsapp, _bitwarden, _game]);
      await pumpApp(tester, c);
      await toApps(tester);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapText(tester, OnboardingAppsStep.protectLabel(1));
      debugPrint = original;
      for (final String pkg in <String>[
        'com.whatsapp',
        'com.x8bit.bitwarden',
        'com.example.game',
      ]) {
        expect(logs.where((String l) => l.contains(pkg)), isEmpty, reason: pkg);
      }
    });

    testWidgets(
        'A9 an app protected elsewhere after the list loaded is not '
        're-added: its record and stricter level are kept',
        (WidgetTester tester) async {
      final AppContainer c = newContainer(apps: const <AppEntry>[_whatsapp]);
      await pumpApp(tester, c);
      await toApps(tester);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      // Race: WhatsApp becomes protected (Critical) by another path while
      // the step still shows it as selectable.
      await tester.runAsync(() async {
        await c.protectedApps.add(ProtectedApp(
            packageName: 'com.whatsapp',
            label: 'WhatsApp',
            addedAt: DateTime(2026)));
        await c.protectedApps
            .setSecurityLevel('com.whatsapp', AppSecurityLevel.critical);
      });
      await tapText(tester, OnboardingAppsStep.protectLabel(1));
      expect(shell(), findsOneWidget);
      final ProtectedApp wa =
          (await tester.runAsync(() => c.protectedApps.getProtectedApps()))!
              .valueOrNull!
              .single;
      expect(wa.securityLevel, AppSecurityLevel.critical);
      expect(wa.addedAt, DateTime(2026), reason: 'record never re-added');
    });

    test('A8 onboarding sources contain no logging, network or export calls',
        () {
      final Directory dir = Directory('lib/ui/screens/onboarding');
      final RegExp banned = RegExp(
        r'\bprint\(|debugPrint|developer\.log|HttpClient|http\.|'
        r'Share\.|MethodChannel|File\(|writeAsString|Clipboard',
      );
      int scanned = 0;
      for (final FileSystemEntity f in dir.listSync()) {
        if (f is! File || !f.path.endsWith('.dart')) continue;
        scanned++;
        final List<String> hits = f
            .readAsLinesSync()
            .where((String l) => !l.trimLeft().startsWith('//'))
            .where(banned.hasMatch)
            .toList();
        expect(hits, isEmpty, reason: f.path);
      }
      expect(scanned, greaterThanOrEqualTo(4));
    });
  });

  // -------------------------------------------------------------------------
  // I: integration and interruption
  // -------------------------------------------------------------------------
  group('I integration and interrupted onboarding', () {
    testWidgets(
        'I1 back from apps returns to permissions; back on '
        'permissions stays', (WidgetTester tester) async {
      await pumpApp(tester, newContainer(apps: const <AppEntry>[_whatsapp]));
      await toApps(tester);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
      expect(find.byType(OnboardingScreen), findsOneWidget);
    });

    testWidgets(
        'I2 interrupted after the credential (at permissions/apps): the '
        'restarted app opens the shell, nothing was protected, onboarding '
        'is never forced again', (WidgetTester tester) async {
      final _Db db = _Db();
      final InMemorySecretStore secrets = InMemorySecretStore();
      final InMemoryKeyValueStore kv = InMemoryKeyValueStore();
      final AppContainer first = newContainer(
          apps: const <AppEntry>[_whatsapp], db: db, secrets: secrets, kv: kv);
      await pumpApp(tester, first);
      await toApps(tester);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      // Process death before "Protect" is tapped.
      await tester.pumpWidget(const SizedBox());
      await tester.pumpAndSettle();

      final AppContainer second = newContainer(
          apps: const <AppEntry>[_whatsapp], db: db, secrets: secrets, kv: kv);
      expect(await tester.runAsync(() => shouldStartOnboarding(second.auth)),
          isFalse);
      await pumpApp(tester, second);
      expect(shell(), findsOneWidget);
      expect(find.byType(OnboardingScreen), findsNothing);
      expect(await tester.runAsync(() => protectedSet(second)), isEmpty);
      expect(db.writes, 0);
    });

    testWidgets(
        'I3 interrupted before the credential: the restarted app starts '
        'onboarding again from Welcome', (WidgetTester tester) async {
      final _Db db = _Db();
      final InMemorySecretStore secrets = InMemorySecretStore();
      final InMemoryKeyValueStore kv = InMemoryKeyValueStore();
      final AppContainer first = newContainer(db: db, secrets: secrets, kv: kv);
      await pumpApp(tester, first);
      await tapText(tester, OnboardingScreen.getStartedLabel);
      await tapText(tester, OnboardingScreen.pinOptionTitle);
      await tester.pumpWidget(const SizedBox());
      await tester.pumpAndSettle();

      final AppContainer second =
          newContainer(db: db, secrets: secrets, kv: kv);
      await pumpApp(tester, second);
      expect(find.text(OnboardingScreen.welcomeTitle), findsOneWidget);
      expect(shell(), findsNothing);
    });

    testWidgets(
        'I4 the completed flow ends at the shell with the flag '
        'recorded and onboarding off the stack', (WidgetTester tester) async {
      final AppContainer c = newContainer(
          apps: const <AppEntry>[_whatsapp],
          accessibility: true,
          overlay: true);
      await pumpApp(tester, c);
      await throughM1(tester);
      await tapText(tester, OnboardingPermissionsStep.continueLabel);
      await tapText(tester, OnboardingAppsStep.skipLabel);
      expect(shell(), findsOneWidget);
      expect(await tester.runAsync(() => c.preferences.isOnboardingCompleted()),
          isTrue);
      final NavigatorState nav = tester.state(find.byType(Navigator).first);
      expect(nav.canPop(), isFalse);
      expect(
          await tester.runAsync(() => shouldStartOnboarding(c.auth)), isFalse);
    });
  });
}

/// Reads the enabled state of the "Protect N apps" button.
class DsButtonFinder {
  DsButtonFinder(this.tester);
  final WidgetTester tester;

  bool get enabled {
    final Finder f = find.byKey(const Key('onboarding_protect_selected'));
    final Widget w = tester.widget(f);
    return (w as dynamic).onPressed != null;
  }
}
