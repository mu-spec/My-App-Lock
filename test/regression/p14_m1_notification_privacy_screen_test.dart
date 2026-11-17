// Phase 14 / M1 — per-app notification privacy screen: entry point,
// Notification access status + fallback, strengthening without
// verification, weakening only with a fresh PIN (cancel / lockout refuse),
// unreadable settings read-only.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/router.dart';
import 'package:smart_app_lock/app/theme/app_theme.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/notification_privacy/notification_privacy_settings.dart';
import 'package:smart_app_lock/services/impl/static_notification_privacy_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/security/notification_privacy_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_screen.dart';

const String _pin = '482916';
const String _bank = 'com.bank.app';
const String _chat = 'org.chat.app';

void main() {
  late InMemoryLocalDatabase db;
  late StaticNotificationPrivacyService native;
  late AppContainer c;

  setUp(() async {
    db = InMemoryLocalDatabase();
    native = StaticNotificationPrivacyService();
    c = AppContainer.inMemory(database: db, notificationPrivacy: native);
    await c.intruderStartup;
    await c.notificationPrivacyStartup;
    await c.auth.enrollPin(_pin);
    await c.protectedApps.add(ProtectedApp(
        packageName: _bank, label: 'Bank', addedAt: DateTime(2026, 10, 1)));
    await c.protectedApps.add(ProtectedApp(
        packageName: _chat,
        label: 'Chat',
        addedAt: DateTime(2026, 10, 2),
        sortOrder: 1));
  });

  Future<void> pump(WidgetTester tester, Widget home) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(AppScope(
      container: c,
      child: MaterialApp(
        theme: AppTheme.dark,
        onGenerateRoute: AppRouter.onGenerateRoute,
        home: home,
      ),
    ));
    await tester.pumpAndSettle();
  }

  Future<void> pumpScreen(WidgetTester tester) =>
      pump(tester, NotificationPrivacyScreen(container: c));

  Future<void> typePin(WidgetTester tester, String pin) async {
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    await tester.pump(const Duration(milliseconds: 250));
    for (final String d in pin.split('')) {
      await tester.tap(find.byKey(Key('pin_key_$d')));
      await tester.pump(const Duration(milliseconds: 50));
    }
    await tester.pumpAndSettle();
  }

  Future<void> cancelVerification(WidgetTester tester) async {
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    tester.state<NavigatorState>(find.byType(Navigator).last).pop();
    await tester.pumpAndSettle();
  }

  Future<void> choose(
      WidgetTester tester, String pkg, NotificationPrivacyMode m) async {
    await tester.tap(find.byKey(Key('np_app_$pkg')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(Key('np_mode_${m.id}')));
    await tester.pumpAndSettle();
  }

  Future<NotificationPrivacyMode> stored(String pkg) async =>
      (await c.notificationPrivacySettings.read()).settings.modeFor(pkg);

  String subtitleOf(WidgetTester tester, String pkg) {
    final ListTile t = tester.widget(find.byKey(Key('np_app_$pkg')));
    return (t.subtitle! as Text).data!;
  }

  testWidgets(
      'W-1 Security screen row opens the screen without verification; both '
      'protected apps listed as Off', (WidgetTester tester) async {
    await pump(tester, const SecurityScreen());
    await tester.scrollUntilVisible(
        find.byKey(const ValueKey<String>('notification_privacy_row')), 200,
        scrollable: find.byType(Scrollable).first);
    await tester.pumpAndSettle();
    await tester
        .tap(find.byKey(const ValueKey<String>('notification_privacy_row')));
    await tester.pumpAndSettle();
    expect(find.byType(NotificationPrivacyScreen), findsOneWidget);
    expect(find.byType(PinUnlockScreen), findsNothing);
    expect(find.text(NotificationPrivacyText.intro), findsOneWidget);
    expect(subtitleOf(tester, _bank), 'Off');
    expect(subtitleOf(tester, _chat), 'Off');
  });

  testWidgets(
      'W-2 access not granted: status, hint and the Android-settings fallback '
      'per app; buttons call the native links', (WidgetTester tester) async {
    await pumpScreen(tester);
    final ListTile status =
        tester.widget(find.byKey(const Key('np_access_status')));
    expect(
        (status.trailing! as Text).data, NotificationPrivacyText.accessMissing);
    expect(find.text(NotificationPrivacyText.accessHint), findsOneWidget);
    await tester.tap(find.byKey(const Key('np_open_access')));
    await tester.pumpAndSettle();
    expect(native.accessSettingsOpened, 1);
    await tester.tap(find.byKey(const Key('np_android_settings_$_chat')));
    await tester.pumpAndSettle();
    expect(native.appSettingsOpened, <String>[_chat]);
  });

  testWidgets('W-3 access granted: "Allowed", no fallback links',
      (WidgetTester tester) async {
    native.accessGranted = true;
    await pumpScreen(tester);
    final ListTile status =
        tester.widget(find.byKey(const Key('np_access_status')));
    expect(
        (status.trailing! as Text).data, NotificationPrivacyText.accessGranted);
    expect(find.text(NotificationPrivacyText.accessHint), findsNothing);
    expect(find.byKey(const Key('np_android_settings_$_bank')), findsNothing);
  });

  testWidgets(
      'W-4 more privacy needs no verification: saved, shown and pushed to '
      'native; the other app is unchanged', (WidgetTester tester) async {
    await pumpScreen(tester);
    await choose(tester, _bank, NotificationPrivacyMode.hideContent);
    expect(find.byType(PinUnlockScreen), findsNothing);
    expect(await stored(_bank), NotificationPrivacyMode.hideContent);
    expect(subtitleOf(tester, _bank), 'Hide content');
    expect(find.text('Bank: Hide content'), findsOneWidget);
    await choose(tester, _bank, NotificationPrivacyMode.maximum);
    expect(find.byType(PinUnlockScreen), findsNothing);
    expect(native.native, <String, NotificationPrivacyMode>{
      _bank: NotificationPrivacyMode.maximum,
    });
    expect(await stored(_chat), NotificationPrivacyMode.off);
  });

  testWidgets(
      'W-5 less privacy needs a fresh PIN: cancel changes nothing; the '
      'correct PIN saves', (WidgetTester tester) async {
    await c.notificationPrivacy.setMode(_bank, NotificationPrivacyMode.maximum);
    await pumpScreen(tester);
    final int pushes = native.configured.length;
    await choose(tester, _bank, NotificationPrivacyMode.off);
    await cancelVerification(tester);
    expect(await stored(_bank), NotificationPrivacyMode.maximum);
    expect(native.configured.length, pushes, reason: 'nothing pushed');
    expect(find.text(NotificationPrivacyText.notChanged), findsOneWidget);
    expect(subtitleOf(tester, _bank), 'Maximum privacy');

    await choose(tester, _bank, NotificationPrivacyMode.hideContent);
    await typePin(tester, _pin);
    expect(await stored(_bank), NotificationPrivacyMode.hideContent);
    expect(native.native, <String, NotificationPrivacyMode>{
      _bank: NotificationPrivacyMode.hideContent,
    });
    expect(subtitleOf(tester, _bank), 'Hide content');
  });

  testWidgets(
      'W-6 a wrong PIN counts normally and changes nothing; during lockout '
      'the correct PIN cannot weaken; lockout unchanged',
      (WidgetTester tester) async {
    await c.notificationPrivacy.setMode(_bank, NotificationPrivacyMode.maximum);
    await pumpScreen(tester);
    final int failed = (await c.auth.status()).valueOrNull!.failedAttempts;
    await choose(tester, _bank, NotificationPrivacyMode.off);
    await typePin(tester, '000000');
    expect((await c.auth.status()).valueOrNull!.failedAttempts, failed + 1);
    if (find.byType(PinUnlockScreen).evaluate().isNotEmpty) {
      await cancelVerification(tester);
    }
    expect(await stored(_bank), NotificationPrivacyMode.maximum);

    for (int i = 0; i < 5; i++) {
      await c.auth.authenticatePin('000000');
    }
    final CredentialState before = (await c.auth.status()).valueOrNull!;
    expect(before.lockedOutUntil, isNotNull);
    await choose(tester, _bank, NotificationPrivacyMode.off);
    if (find.byType(PinUnlockScreen).evaluate().isNotEmpty) {
      await typePin(tester, _pin);
      if (find.byType(PinUnlockScreen).evaluate().isNotEmpty) {
        await cancelVerification(tester);
      }
    }
    expect(await stored(_bank), NotificationPrivacyMode.maximum);
    final CredentialState after = (await c.auth.status()).valueOrNull!;
    expect(after.lockedOutUntil, before.lockedOutUntil);
    expect(after.lockoutStreak, before.lockoutStreak);
  });

  testWidgets(
      'W-7 unreadable settings: notice shown, rows disabled, nothing written',
      (WidgetTester tester) async {
    await db.setSetting(NotificationPrivacySettingsStore.storageKey,
        'enc:v1:${await c.settingsCipher.encryptString('{"v":9}')}');
    final String stored0 =
        (await db.getSetting(NotificationPrivacySettingsStore.storageKey))!;
    await pumpScreen(tester);
    expect(find.byKey(const Key('np_unavailable')), findsOneWidget);
    await tester.tap(find.byKey(const Key('np_app_$_bank')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('np_mode_off')), findsNothing,
        reason: 'no picker for a read-only record');
    expect(await db.getSetting(NotificationPrivacySettingsStore.storageKey),
        stored0);
  });

  testWidgets('W-8 no protected apps: explains that an app must be protected',
      (WidgetTester tester) async {
    await c.protectedApps.remove(_bank);
    await c.protectedApps.remove(_chat);
    await pumpScreen(tester);
    expect(find.byKey(const Key('np_no_apps')), findsOneWidget);
  });
}
