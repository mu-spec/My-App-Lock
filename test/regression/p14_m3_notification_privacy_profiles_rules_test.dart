// Phase 14 / M3 — profiles and rules, Flutter side.
//
// Owner decision ("linked to levels"): an active Security Profile or Smart
// Rule that raises a protected app to Critical gives Maximum privacy, and
// Sensitive gives Hide content. It is never weaker than the per-app mode.
// Native applies it (NotificationPrivacyM3Test executes the shared vectors).
// This file proves:
//  * V: each profile vector's transport is EXACTLY what
//    SecurityProfilePolicy.nativeTransport sends, so the native floors are
//    the ones for the real Guest/Kids profiles;
//  * R: `raisedNow` status parsing is fail-safe, and the screen states that
//    profiles/rules can only make privacy stricter;
//  * W: the native wiring (profile switch -> immediate refresh; rule window
//    timer; no profile type and no content in native).
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/router.dart';
import 'package:smart_app_lock/app/theme/app_theme.dart';
import 'package:smart_app_lock/data/models/app_security_level.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/profiles/security_profile.dart';
import 'package:smart_app_lock/profiles/security_profile_policy.dart';
import 'package:smart_app_lock/rules/smart_rule.dart';
import 'package:smart_app_lock/security/notification_privacy/notification_privacy_settings.dart';
import 'package:smart_app_lock/services/impl/method_channel_notification_privacy_service.dart';
import 'package:smart_app_lock/services/impl/static_notification_privacy_service.dart';
import 'package:smart_app_lock/services/notification_privacy_service.dart';
import 'package:smart_app_lock/ui/screens/security/notification_privacy_screen.dart';

const String _kotlinDir = 'android/app/src/main/kotlin/com/smartapplock/app';

String _kt(String name) => File('$_kotlinDir/$name').readAsStringSync();

/// Source lines without imports/comments, for wiring scans.
String _code(String name) => _kt(name).split('\n').where((String l) {
      final String t = l.trimLeft();
      return !t.startsWith('import ') &&
          !t.startsWith('//') &&
          !t.startsWith('*') &&
          !t.startsWith('/*');
    }).join('\n');

void main() {
  group('V shared profile/rule vectors', () {
    final Map<String, Object?> v = jsonDecode(
        File('test/fixtures/notification_privacy/m3_profile_rule_vectors.json')
            .readAsStringSync()) as Map<String, Object?>;
    final Set<String> protectedPackages =
        (v['protected']! as List<Object?>).cast<String>().toSet();
    final List<Map<String, Object?>> vectors =
        (v['vectors']! as List<Object?>).cast<Map<String, Object?>>();

    test(
        'V-1 the fixture covers Normal, Guest, Kids, activation, expiry, '
        'overnight and conflicting rules', () {
      final Set<String> kinds = <String>{
        for (final Map<String, Object?> x in vectors)
          if (x['profile'] case final Map<String, Object?> p)
            p['kind']! as String,
      };
      expect(kinds, containsAll(<String>['normal', 'guest', 'kids']));
      final String names =
          vectors.map((Map<String, Object?> x) => x['name']).join('|');
      for (final String w in <String>[
        'activation',
        'expiry',
        'overnight',
        'conflicting',
        'never weakens'
      ]) {
        expect(names, contains(w));
      }
    });

    for (final Map<String, Object?> x in vectors) {
      final Map<String, Object?>? p = x['profile'] as Map<String, Object?>?;
      if (p == null) continue;
      test(
          'V-2 ${x['name']}: transport == SecurityProfilePolicy.nativeTransport',
          () {
        final SecurityProfileKind kind = SecurityProfileKind.fromId(p['kind'])!;
        final Map<String, AppSecurityLevel> appLevels =
            <String, AppSecurityLevel>{
          for (final MapEntry<String, Object?> e
              in ((p['appLevels'] as Map<String, Object?>?) ??
                      const <String, Object?>{})
                  .entries)
            e.key: AppSecurityLevel.values
                .firstWhere((AppSecurityLevel l) => l.storageId == e.value),
        };
        final SecurityProfile profile = SecurityProfile(
          kind: kind,
          allProtectedLevel: kind == SecurityProfileKind.guest
              ? AppSecurityLevel.critical
              : null,
          appLevels: appLevels,
        );
        final List<Map<String, Object?>> sent =
            SecurityProfilePolicy.nativeTransport(
                const <SmartRule>[], profile, protectedPackages);
        String canon(List<Object?> l) => jsonEncode(<Object?>[
              for (final Object? e in l)
                <String, Object?>{
                  for (final MapEntry<String, Object?> f
                      in ((e! as Map<String, Object?>).entries.toList()
                        ..sort((MapEntry<String, Object?> a,
                                MapEntry<String, Object?> b) =>
                            a.key.compareTo(b.key))))
                    f.key: f.value,
                },
            ]..sort((Object? a, Object? b) =>
                jsonEncode(a).compareTo(jsonEncode(b))));
        expect(canon(sent), canon(x['transport']! as List<Object?>));
      });
    }
  });

  group('R raisedNow status and screen', () {
    const MethodChannel channel =
        MethodChannel('smart_app_lock/notification_privacy');
    tearDown(() => TestDefaultBinaryMessengerBinding
        .instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null));

    test('R-1 raisedNow keeps only valid, stricter-than-Off entries', () {
      final NotificationPrivacyStatus s =
          NotificationPrivacyStatus.fromMap(<String, Object?>{
        'raisedNow': <Object?, Object?>{
          'com.a': 'maximum',
          'com.b': 'hide_content',
          'com.c': 'off',
          'com.d': 'loud',
          7: 'maximum',
          'com.e': null,
        },
      });
      expect(s.raisedNow, <String, NotificationPrivacyMode>{
        'com.a': NotificationPrivacyMode.maximum,
        'com.b': NotificationPrivacyMode.hideContent,
      });
      for (final Object? bad in <Object?>[
        null,
        'x',
        3,
        <Object?>['maximum']
      ]) {
        expect(
            NotificationPrivacyStatus.fromMap(
                <String, Object?>{'raisedNow': bad}).raisedNow,
            isEmpty);
      }
      expect(NotificationPrivacyStatus.unknown.raisedNow, isEmpty);
    });

    test('R-2 raisedNow flows through the method channel', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
              channel,
              (MethodCall call) async => <String, Object?>{
                    'accessGranted': true,
                    'raisedNow': <String, Object?>{'com.kids.game': 'maximum'},
                  });
      final NotificationPrivacyStatus s =
          (await MethodChannelNotificationPrivacyService().status())
              .valueOrNull!;
      expect(s.raisedNow, <String, NotificationPrivacyMode>{
        'com.kids.game': NotificationPrivacyMode.maximum
      });
    });

    late StaticNotificationPrivacyService native;
    late AppContainer c;

    setUp(() async {
      native = StaticNotificationPrivacyService(accessGranted: true);
      c = AppContainer.inMemory(
          database: InMemoryLocalDatabase(), notificationPrivacy: native);
      await c.intruderStartup;
      await c.notificationPrivacyStartup;
      await c.protectedApps.add(ProtectedApp(
          packageName: 'com.kids.game',
          label: 'Game',
          addedAt: DateTime(2026, 10, 1)));
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
          home: NotificationPrivacyScreen(key: UniqueKey(), container: c),
        ),
      ));
      await tester.pumpAndSettle();
    }

    testWidgets('R-3 the screen states profiles/rules only make it stricter',
        (WidgetTester tester) async {
      await pumpScreen(tester);
      expect(find.byKey(const Key('np_profiles_note')), findsOneWidget);
      expect(NotificationPrivacyText.profilesNote,
          contains('never make it weaker'));
      expect(find.text(NotificationPrivacyMode.off.label), findsWidgets);
    });

    testWidgets(
        'R-4 a raised app shows its saved mode AND the stricter mode now; the '
        'saved setting is not changed', (WidgetTester tester) async {
      native.raisedNow = const <String, NotificationPrivacyMode>{
        'com.kids.game': NotificationPrivacyMode.maximum,
      };
      await pumpScreen(tester);
      final Text t = tester
          .widget<Text>(find.byKey(const Key('np_app_mode_com.kids.game')));
      expect(
          t.data,
          NotificationPrivacyText.raisedBy(
              NotificationPrivacyMode.off, NotificationPrivacyMode.maximum));
      expect(
          native.configured.where((Map<String, NotificationPrivacyMode> m) =>
              m.containsKey('com.kids.game')),
          isEmpty,
          reason: 'display only: the per-app mode stays Off');
    });
  });

  group('T placeholder wording matches the native presentation', () {
    test(
        'T-1 the Maximum privacy description names what Android actually '
        'shows: the native title, from Smart App Lock, no app name', () {
      final String engine = _kt('NotificationPrivacyEngine.kt');
      final String title = RegExp(r'const val NEW_NOTIFICATION = "([^"]+)"')
          .firstMatch(engine)!
          .group(1)!;
      expect(title, 'New notification');
      // Maximum: title only, no text, no app name.
      expect(
          RegExp(r'title = NEW_NOTIFICATION,\s*\n\s*text = null')
              .hasMatch(engine),
          isTrue);
      final String max =
          NotificationPrivacyText.modeHint(NotificationPrivacyMode.maximum);
      expect(max, contains('\u201c$title\u201d'));
      expect(max, contains('from Smart App Lock'));
      expect(max, contains('without the app\u2019s name'));
      expect(max, contains('Hidden on the lock screen'));
      expect(max, isNot(contains('Smart App Lock: ')));
      final String hide =
          NotificationPrivacyText.modeHint(NotificationPrivacyMode.hideContent);
      expect(hide, contains('\u201c$title\u201d'));
    });
  });

  group('W native wiring (source scan)', () {
    test(
        'W-1 configureProtection refreshes notification privacy after a '
        'successful apply (profile switch / rule edit act immediately)', () {
      final String w = _code('WatcherChannel.kt');
      final int applied = w.indexOf('outcome.applied');
      final int refresh =
          w.indexOf('SalNotificationListenerService.refreshBinding(activity)');
      expect(applied, greaterThan(0));
      expect(refresh, greaterThan(applied));
    });

    test(
        'W-2 the listener re-checks at rule boundaries and stops on '
        'disconnect', () {
      final String l = _code('SalNotificationListenerService.kt');
      expect(l, contains('nextRuleCheckDelayMs'));
      expect(l, contains('handler.removeCallbacks(ruleCheck)'));
      expect(
          RegExp(r'onListenerDisconnected[\s\S]*removeCallbacks\(ruleCheck\)')
              .hasMatch(l),
          isTrue);
      expect(l, isNot(contains('AlarmManager')));
      expect(l, isNot(contains('WakeLock')));
    });

    test(
        'W-3 floors come from the persisted rule store, damaged = strictest; '
        'native has no profile type and still never touches content', () {
      final String store = _code('NotificationPrivacyStore.kt');
      expect(store, contains('ProtectionStateStore.smartRules('));
      final String policy = _code('NotificationPrivacyPolicy.kt');
      expect(policy, contains('stricter('));
      for (final String f in <String>[
        'NotificationPrivacyPolicy.kt',
        'NotificationPrivacyStore.kt',
        'SalNotificationListenerService.kt',
      ]) {
        final String s = _code(f);
        expect(s, isNot(contains('SecurityProfile')), reason: f);
        expect(s, isNot(contains('EXTRA_TEXT')), reason: f);
        expect(s, isNot(contains('EXTRA_TITLE')), reason: f);
        expect(s, isNot(contains('tickerText')), reason: f);
      }
    });
  });
}
