// Phase 14 / M2 — privacy modes, Flutter side: placeholder-permission status
// (fail-safe parsing), the own-notification-settings link, the stated
// Android limits and the "removed without a placeholder" warning.
// The removal / placeholder behaviour itself is native
// (NotificationPrivacyEngineTest).
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/router.dart';
import 'package:smart_app_lock/app/theme/app_theme.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/notification_privacy/notification_privacy_settings.dart';
import 'package:smart_app_lock/services/impl/method_channel_notification_privacy_service.dart';
import 'package:smart_app_lock/services/impl/static_notification_privacy_service.dart';
import 'package:smart_app_lock/services/notification_privacy_service.dart';
import 'package:smart_app_lock/ui/screens/security/notification_privacy_screen.dart';

const String _bank = 'com.bank.app';

void main() {
  group('P status and channel', () {
    const MethodChannel channel =
        MethodChannel('smart_app_lock/notification_privacy');
    final List<MethodCall> calls = <MethodCall>[];
    Object? Function(MethodCall) reply = (_) => null;

    setUp(() {
      calls.clear();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        calls.add(call);
        return reply(call);
      });
    });
    tearDown(() => TestDefaultBinaryMessengerBinding
        .instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null));

    test(
        'P-1 placeholdersAllowed is true only when native says exactly true '
        '(missing, wrong type or unknown = not allowed)', () {
      expect(
          NotificationPrivacyStatus.fromMap(
                  <String, Object?>{'placeholdersAllowed': true})
              .placeholdersAllowed,
          isTrue);
      for (final Object? v in <Object?>[null, false, 'true', 1]) {
        expect(
            NotificationPrivacyStatus.fromMap(
                    <String, Object?>{'placeholdersAllowed': v})
                .placeholdersAllowed,
            isFalse,
            reason: '$v');
      }
      expect(
          NotificationPrivacyStatus.fromMap(<String, Object?>{})
              .placeholdersAllowed,
          isFalse);
      expect(NotificationPrivacyStatus.unknown.placeholdersAllowed, isFalse);
    });

    test('P-2 status over the channel; own-settings link; errors fail closed',
        () async {
      final NotificationPrivacyService s =
          MethodChannelNotificationPrivacyService();
      reply = (MethodCall c) => switch (c.method) {
            'getStatus' => <String, Object?>{
                'accessGranted': true,
                'listenerConnected': true,
                'storeInvalid': false,
                'configuredCount': 1,
                'placeholdersAllowed': false,
              },
            'openOwnNotificationSettings' => true,
            _ => null,
          };
      final NotificationPrivacyStatus st = (await s.status()).valueOrNull!;
      expect(st.accessGranted, isTrue);
      expect(st.placeholdersAllowed, isFalse);
      expect((await s.openOwnNotificationSettings()).valueOrNull, isTrue);
      expect(calls.last.method, 'openOwnNotificationSettings');
      expect(calls.last.arguments, isNull, reason: 'no package is sent');
      reply = (_) => throw PlatformException(code: 'x');
      expect((await s.openOwnNotificationSettings()).isFailure, isTrue);
      reply = (_) => null;
      expect((await s.openOwnNotificationSettings()).valueOrNull, isFalse);
    });
  });

  group('S screen', () {
    late StaticNotificationPrivacyService native;
    late AppContainer c;

    setUp(() async {
      native = StaticNotificationPrivacyService(accessGranted: true);
      c = AppContainer.inMemory(
          database: InMemoryLocalDatabase(), notificationPrivacy: native);
      await c.intruderStartup;
      await c.notificationPrivacyStartup;
      await c.protectedApps.add(ProtectedApp(
          packageName: _bank, label: 'Bank', addedAt: DateTime(2026, 10, 1)));
    });

    Future<void> pumpScreen(WidgetTester tester) async {
      tester.view.physicalSize = const Size(800, 2400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(AppScope(
        container: c,
        child: MaterialApp(
          theme: AppTheme.dark,
          onGenerateRoute: AppRouter.onGenerateRoute,
          // A fresh key per pump: the screen reloads its status each time.
          home: NotificationPrivacyScreen(key: UniqueKey(), container: c),
        ),
      ));
      await tester.pumpAndSettle();
    }

    testWidgets(
        'S-1 Android limits are always stated (no guarantee of hiding before '
        'display)', (WidgetTester tester) async {
      await pumpScreen(tester);
      expect(find.byKey(const Key('np_limits')), findsOneWidget);
      expect(find.text(NotificationPrivacyText.limits), findsOneWidget);
      expect(NotificationPrivacyText.limits, contains('briefly appear'));
      expect(NotificationPrivacyText.limits, contains('can\u2019t be hidden'));
      for (final String s in <String>[
        NotificationPrivacyText.intro,
        NotificationPrivacyText.limits,
        for (final NotificationPrivacyMode m in NotificationPrivacyMode.values)
          NotificationPrivacyText.modeHint(m),
      ]) {
        expect(s.toLowerCase(), isNot(contains('guarantee')));
        expect(s.toLowerCase(), isNot(contains('never appear')));
      }
    });

    testWidgets(
        'S-2 placeholders not allowed + an app with privacy on: warning; the '
        'button opens Smart App Lock\u2019s own notification settings',
        (WidgetTester tester) async {
      native.placeholdersAllowed = false;
      await c.notificationPrivacy
          .setMode(_bank, NotificationPrivacyMode.maximum);
      await pumpScreen(tester);
      expect(find.byKey(const Key('np_placeholders_blocked')), findsOneWidget);
      expect(find.text(NotificationPrivacyText.placeholdersBlocked),
          findsOneWidget);
      await tester.tap(find.byKey(const Key('np_allow_placeholders')));
      await tester.pumpAndSettle();
      expect(native.ownSettingsOpened, 1);
      expect(native.appSettingsOpened, isEmpty);
    });

    testWidgets(
        'S-3 no warning when every app is Off, when placeholders are allowed, '
        'or when Notification access is missing (its own hint applies)',
        (WidgetTester tester) async {
      native.placeholdersAllowed = false;
      await pumpScreen(tester);
      expect(find.byKey(const Key('np_placeholders_blocked')), findsNothing);

      await c.notificationPrivacy
          .setMode(_bank, NotificationPrivacyMode.hideContent);
      native.placeholdersAllowed = true;
      await pumpScreen(tester);
      expect(find.byKey(const Key('np_placeholders_blocked')), findsNothing);

      native
        ..placeholdersAllowed = false
        ..accessGranted = false;
      await pumpScreen(tester);
      expect(find.byKey(const Key('np_placeholders_blocked')), findsNothing);
      expect(find.text(NotificationPrivacyText.accessHint), findsOneWidget);
    });

    testWidgets('S-4 status unavailable: no warning, nothing claimed',
        (WidgetTester tester) async {
      native.failStatus = true;
      await c.notificationPrivacy
          .setMode(_bank, NotificationPrivacyMode.maximum);
      await pumpScreen(tester);
      expect(find.byKey(const Key('np_placeholders_blocked')), findsNothing);
      final ListTile status =
          tester.widget(find.byKey(const Key('np_access_status')));
      expect((status.trailing! as Text).data,
          NotificationPrivacyText.accessUnknown);
    });
  });
}
