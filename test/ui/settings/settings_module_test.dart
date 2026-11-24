// Settings module (functional Settings tab): targeted widget, theme,
// persistence, notification-status and About tests. Host/widget tests
// (simulated); Android behaviour itself is device QA.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/theme/theme_preference.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_key_value_store.dart';
import 'package:smart_app_lock/data/storage/impl/preferences_store_impl.dart';
import 'package:smart_app_lock/data/storage/preferences_store.dart';
import 'package:smart_app_lock/services/impl/static_notification_privacy_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/services/watcher_service.dart';
import 'package:smart_app_lock/ui/screens/security/notification_privacy_screen.dart';
import 'package:smart_app_lock/ui/screens/settings/about_screen.dart';
import 'package:smart_app_lock/ui/screens/settings/notification_settings_screen.dart';
import 'package:smart_app_lock/ui/screens/settings/settings_notification_status.dart';
import 'package:smart_app_lock/ui/screens/settings/settings_screen.dart';

class _ThrowingKv extends InMemoryKeyValueStore {
  bool failReads = false;
  bool failWrites = false;

  @override
  Future<String?> getString(String key) async {
    if (failReads) throw StateError('read failed');
    return super.getString(key);
  }

  @override
  Future<void> setString(String key, String value) async {
    if (failWrites) throw StateError('write failed');
    return super.setString(key, value);
  }
}

class _Fx {
  _Fx({AppContainer? container, StaticNotificationPrivacyService? privacy})
      : privacy = privacy ?? StaticNotificationPrivacyService(),
        kv = _ThrowingKv() {
    c = container ??
        AppContainer.inMemory(keyValueStore: kv, notificationPrivacy: this.privacy);
  }

  final StaticNotificationPrivacyService privacy;
  final _ThrowingKv kv;
  late final AppContainer c;

  StaticWatcherService get watcher => c.watcher as StaticWatcherService;
}

Future<void> _pumpApp(
  WidgetTester tester,
  AppContainer? c, {
  AppThemePreference initial = AppThemePreference.system,
}) async {
  tester.view.physicalSize = const Size(1080, 2600);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);
  if (c != null) addTearDown(c.capabilityMonitor.dispose);
  await tester.pumpWidget(
    SmartAppLockApp(container: c, initialThemePreference: initial),
  );
  await tester.pumpAndSettle();
}

Future<void> _openSettings(WidgetTester tester) async {
  await tester.tap(find.byKey(const Key('nav_settings')));
  await tester.pumpAndSettle();
}

MaterialApp _app(WidgetTester tester) =>
    tester.widget<MaterialApp>(find.byType(MaterialApp));

Brightness _shownBrightness(WidgetTester tester) =>
    Theme.of(tester.element(find.byKey(const Key('settings_list')))).brightness;

void main() {
  group('Settings screen', () {
    testWidgets('S1 placeholder replaced by the three functional sections',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await _pumpApp(tester, fx.c);
      await _openSettings(tester);

      expect(find.text(SettingsScreen.description), findsOneWidget);
      expect(find.text('Appearance & theme'), findsOneWidget);
      expect(find.text('Notifications'), findsWidgets);
      expect(find.text('About & support'), findsOneWidget);
      // Old placeholder feature list and postponed features are gone.
      expect(find.text('Appearance & theme options'), findsNothing);
      expect(find.text('Backup & restore your locks'), findsNothing);
      expect(find.text('Language & notifications'), findsNothing);
      expect(find.textContaining('Coming'), findsNothing);
      expect(find.textContaining('Backup'), findsNothing);
      expect(find.textContaining('Language'), findsNothing);
    });

    testWidgets('S2 opening the Settings tab reads nothing from Android',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await _pumpApp(tester, fx.c);
      final int health = fx.watcher.getHealthCalls;
      await _openSettings(tester);
      expect(fx.watcher.getHealthCalls, health);
      expect(fx.watcher.openedSettings, isEmpty);
      expect(fx.privacy.accessSettingsOpened, 0);
    });

    testWidgets('S3 without a container the Notifications entry is disabled',
        (WidgetTester tester) async {
      await _pumpApp(tester, null);
      await _openSettings(tester);
      await tester.tap(find.byKey(const Key('settings_notifications')));
      await tester.pumpAndSettle();
      expect(find.byType(NotificationSettingsScreen), findsNothing);
      expect(find.text('Not available'), findsOneWidget);
    });
  });

  group('Theme switching and persistence', () {
    testWidgets('T1 Light / Dark / System default apply app-wide',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.light;
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      await _pumpApp(tester, fx.c);
      await _openSettings(tester);
      expect(_app(tester).themeMode, ThemeMode.system);
      expect(_shownBrightness(tester), Brightness.light);

      await tester.tap(find.text('Dark'));
      await tester.pumpAndSettle();
      expect(_app(tester).themeMode, ThemeMode.dark);
      expect(_shownBrightness(tester), Brightness.dark);
      // App-wide: another tab is rendered dark too.
      await tester.tap(find.byKey(const Key('nav_home')));
      await tester.pumpAndSettle();
      expect(Theme.of(tester.element(find.byType(NavigationBar))).brightness,
          Brightness.dark);
      await _openSettings(tester);

      await tester.tap(find.text('Light'));
      await tester.pumpAndSettle();
      expect(_app(tester).themeMode, ThemeMode.light);
      expect(_shownBrightness(tester), Brightness.light);

      await tester.tap(find.text('System default'));
      await tester.pumpAndSettle();
      expect(_app(tester).themeMode, ThemeMode.system);
      // System default follows Android's appearance setting.
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
      await tester.pumpAndSettle();
      expect(_shownBrightness(tester), Brightness.dark);
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.light;
      await tester.pumpAndSettle();
      expect(_shownBrightness(tester), Brightness.light);
    });

    testWidgets('T2 the choice is saved and restored after a restart',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await _pumpApp(tester, fx.c);
      await _openSettings(tester);
      await tester.tap(find.text('Dark'));
      await tester.pumpAndSettle();
      expect(await fx.c.preferences.getThemeMode(), 'dark');

      // Restart: a new container over the same preferences tier, loaded the
      // way main() does before the first frame.
      final AppContainer restarted = AppContainer.inMemory(keyValueStore: fx.kv);
      final AppThemePreference loaded =
          await AppThemePreference.load(restarted.preferences);
      expect(loaded, AppThemePreference.dark);
      await tester.pumpWidget(const SizedBox());
      await _pumpApp(tester, restarted, initial: loaded);
      expect(_app(tester).themeMode, ThemeMode.dark);
      await _openSettings(tester);
      final Finder selector = find.byKey(const Key('settings_theme_selector'));
      final SegmentedButton<AppThemePreference> button =
          tester.widget<SegmentedButton<AppThemePreference>>(find.descendant(
        of: selector,
        matching: find.byType(SegmentedButton<AppThemePreference>),
      ));
      expect(button.selected, <AppThemePreference>{AppThemePreference.dark});
    });

    test('T3 stored values: known ids, unknown/absent/failed read -> system',
        () async {
      final _ThrowingKv kv = _ThrowingKv();
      final PreferencesStore store = PreferencesStoreImpl(kv);
      expect(await AppThemePreference.load(store), AppThemePreference.system);
      for (final AppThemePreference p in AppThemePreference.values) {
        await store.setThemeMode(p.id);
        expect(await AppThemePreference.load(store), p);
      }
      await store.setThemeMode('sepia');
      expect(await AppThemePreference.load(store), AppThemePreference.system);
      kv.failReads = true;
      expect(await AppThemePreference.load(store), AppThemePreference.system);
      expect(await AppThemePreference.load(null), AppThemePreference.system);
      expect(
        AppThemePreference.values.map((AppThemePreference p) => p.id),
        <String>['system', 'light', 'dark'],
      );
    });

    testWidgets('T4 a failed save still applies and says it was not saved',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await _pumpApp(tester, fx.c);
      await _openSettings(tester);
      fx.kv.failWrites = true;
      await tester.tap(find.text('Dark'));
      await tester.pumpAndSettle();
      expect(_app(tester).themeMode, ThemeMode.dark);
      expect(find.text('Theme applied, but it could not be saved.'),
          findsOneWidget);
      fx.kv.failWrites = false;
      expect(await fx.c.preferences.getThemeMode(), isNull);
    });
  });

  group('Notification status mapping', () {
    test('N1 app notification permission', () async {
      final StaticWatcherService w = StaticWatcherService();
      w.sdkInt = 34;
      w.notificationPermissionGranted = true;
      expect(await readSettingsNotificationPermission(w.getHealth),
          SettingsPermissionState.granted);
      w.notificationPermissionGranted = false;
      expect(await readSettingsNotificationPermission(w.getHealth),
          SettingsPermissionState.notGranted);
      // Below Android 13 native reports granted (no runtime permission);
      // it is never shown as Allowed.
      w.sdkInt = 30;
      w.notificationPermissionGranted = true;
      expect(await readSettingsNotificationPermission(w.getHealth),
          SettingsPermissionState.notRequired);
      w.getHealthError = StateError('bridge down');
      expect(await readSettingsNotificationPermission(w.getHealth),
          SettingsPermissionState.unknown);
      expect(
        await readSettingsNotificationPermission(
            () => throw StateError('thrown')),
        SettingsPermissionState.unknown,
      );
    });

    test('N2 notification access', () async {
      final StaticNotificationPrivacyService s =
          StaticNotificationPrivacyService(accessGranted: true);
      expect(await readSettingsNotificationAccess(s),
          SettingsPermissionState.granted);
      s.accessGranted = false;
      expect(await readSettingsNotificationAccess(s),
          SettingsPermissionState.notGranted);
      s.failStatus = true;
      expect(await readSettingsNotificationAccess(s),
          SettingsPermissionState.unknown);
      expect(SettingsPermissionState.unknown.label, isNot('Allowed'));
    });
  });

  group('Notifications screen', () {
    Future<void> openNotifications(WidgetTester tester, _Fx fx) async {
      await _pumpApp(tester, fx.c);
      await _openSettings(tester);
      await tester.tap(find.byKey(const Key('settings_notifications')));
      await tester.pumpAndSettle();
    }

    String pill(WidgetTester tester, String key) => tester
        .widget<Text>(find.descendant(
            of: find.byKey(Key(key)), matching: find.byType(Text)))
        .data!;

    testWidgets('NS1 shows the real states and re-reads them on resume',
        (WidgetTester tester) async {
      final _Fx fx = _Fx(
          privacy: StaticNotificationPrivacyService(accessGranted: false));
      fx.watcher
        ..sdkInt = 34
        ..notificationPermissionGranted = true;
      await openNotifications(tester, fx);
      expect(find.byType(NotificationSettingsScreen), findsOneWidget);
      expect(pill(tester, 'notif_settings_permission_status'), 'Allowed');
      expect(pill(tester, 'notif_settings_access_status'), 'Not allowed');

      fx.privacy.accessGranted = true;
      fx.watcher.getHealthError = StateError('bridge down');
      for (final AppLifecycleState st in const <AppLifecycleState>[
        AppLifecycleState.inactive,
        AppLifecycleState.hidden,
        AppLifecycleState.paused,
        AppLifecycleState.hidden,
        AppLifecycleState.inactive,
        AppLifecycleState.resumed,
      ]) {
        tester.binding.handleAppLifecycleStateChanged(st);
      }
      await tester.pumpAndSettle();
      expect(pill(tester, 'notif_settings_permission_status'), 'Unknown');
      expect(pill(tester, 'notif_settings_access_status'), 'Allowed');
    });

    testWidgets('NS2 opens Android notification settings via the existing '
        'hand-off; an unavailable destination shows a message',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await openNotifications(tester, fx);
      await tester.tap(find.byKey(const Key('notif_settings_open_android')));
      await tester.pumpAndSettle();
      expect(fx.watcher.openedSettings,
          <ProtectionSettingsTarget>[ProtectionSettingsTarget.notifications]);
      expect(find.text(NotificationSettingsScreen.openFailedMessage),
          findsNothing);

      fx.watcher.settingsOpenResult = false;
      await tester.tap(find.byKey(const Key('notif_settings_open_android')));
      await tester.pumpAndSettle();
      expect(find.text(NotificationSettingsScreen.openFailedMessage),
          findsOneWidget);
    });

    testWidgets('NS3 opens Android Notification access settings',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await openNotifications(tester, fx);
      final int configured = fx.privacy.configured.length;
      await tester.tap(find.byKey(const Key('notif_settings_open_access')));
      await tester.pumpAndSettle();
      expect(fx.privacy.accessSettingsOpened, 1);
      expect(fx.privacy.configured.length, configured,
          reason: 'nothing configured');
    });

    testWidgets('NS4 opens the existing Notification Privacy screen',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await openNotifications(tester, fx);
      final int configured = fx.privacy.configured.length;
      await tester.tap(find.byKey(const Key('notif_settings_privacy')));
      await tester.pumpAndSettle();
      expect(find.byType(NotificationPrivacyScreen), findsOneWidget);
      final ModalRoute<dynamic>? route = ModalRoute.of(
          tester.element(find.byType(NotificationPrivacyScreen)));
      expect(route?.settings.name, notificationPrivacyRouteName);
      expect(fx.privacy.configured.length, configured,
          reason: 'opening changes nothing');
      await tester.pageBack();
      await tester.pumpAndSettle();
      expect(find.byType(NotificationSettingsScreen), findsOneWidget);
    });
  });

  group('About', () {
    testWidgets('A1 reachable from Settings; shows name and build values',
        (WidgetTester tester) async {
      final _Fx fx = _Fx();
      await _pumpApp(tester, fx.c);
      await _openSettings(tester);
      await tester.tap(find.byKey(const Key('settings_about')));
      await tester.pumpAndSettle();
      expect(find.byType(AboutScreen), findsOneWidget);
      expect(find.text(AboutScreen.appName), findsWidgets);
      // The compiled values (or "Not available" when a build has none).
      final AboutScreen about = tester.widget<AboutScreen>(find.byType(AboutScreen));
      expect(about.version, appBuildNameForTest);
    });

    testWidgets('A2 version / build number shown; missing -> Not available',
        (WidgetTester tester) async {
      await tester.pumpWidget(const MaterialApp(
        home: AboutScreen(version: '0.36.12', buildNumber: '99'),
      ));
      expect(find.text('0.36.12'), findsOneWidget);
      expect(find.text('99'), findsOneWidget);

      await tester.pumpWidget(const MaterialApp(
        home: AboutScreen(version: null, buildNumber: ''),
      ));
      expect(find.text(AboutScreen.notAvailable), findsNWidgets(2));
      // No invented links.
      expect(find.textContaining('Privacy Policy'), findsNothing);
      expect(find.textContaining('@'), findsNothing);
      expect(find.textContaining('http'), findsNothing);
    });

    testWidgets('A3 open-source licenses open the Flutter license page',
        (WidgetTester tester) async {
      await tester.pumpWidget(const MaterialApp(
        home: AboutScreen(version: '0.36.12', buildNumber: '99'),
      ));
      await tester.tap(find.byKey(const Key('about_licenses')));
      await tester.pumpAndSettle();
      expect(find.byType(LicensePage), findsOneWidget);
    });
  });
}

/// The value the About screen defaults to in this test build.
const String? appBuildNameForTest =
    bool.hasEnvironment('FLUTTER_BUILD_NAME')
        ? String.fromEnvironment('FLUTTER_BUILD_NAME')
        : null;
