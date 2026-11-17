// Phase 14 / M1 — notification privacy foundation: settings codec, store
// (fail-closed reads, never overwritten), controller (protected apps only,
// native sync) and the method-channel bridge.
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/notification_privacy/notification_privacy_controller.dart';
import 'package:smart_app_lock/security/notification_privacy/notification_privacy_settings.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/services/impl/method_channel_notification_privacy_service.dart';
import 'package:smart_app_lock/services/impl/static_notification_privacy_service.dart';
import 'package:smart_app_lock/services/notification_privacy_service.dart';

const String _bank = 'com.bank.app';
const String _chat = 'org.chat.app';
const String _key = NotificationPrivacySettingsStore.storageKey;

SettingsCipher _cipher() => AesGcmSettingsCipher(InMemorySecretStore(),
    database: InMemoryLocalDatabase());

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('N codec and store', () {
    late InMemoryLocalDatabase db;
    late SettingsCipher cipher;
    late NotificationPrivacySettingsStore store;

    setUp(() {
      db = InMemoryLocalDatabase();
      cipher = _cipher();
      store = NotificationPrivacySettingsStore(db, cipher);
    });

    Future<String> enc(String json) async =>
        'enc:v1:${await cipher.encryptString(json)}';

    test('N-1 mode ids, ranks and labels are pinned (shared with native)', () {
      expect(NotificationPrivacyMode.values.map((m) => m.id),
          <String>['off', 'hide_content', 'maximum']);
      expect(NotificationPrivacyMode.values.map((m) => m.rank), <int>[0, 1, 2]);
      expect(NotificationPrivacyMode.values.map((m) => m.label),
          <String>['Off', 'Hide content', 'Maximum privacy']);
      expect(
          NotificationPrivacyMode.maximum
              .isWeakenedBy(NotificationPrivacyMode.hideContent),
          isTrue);
      expect(
          NotificationPrivacyMode.hideContent
              .isWeakenedBy(NotificationPrivacyMode.off),
          isTrue);
      expect(
          NotificationPrivacyMode.off
              .isWeakenedBy(NotificationPrivacyMode.maximum),
          isFalse);
      expect(
          NotificationPrivacyMode.maximum
              .isWeakenedBy(NotificationPrivacyMode.maximum),
          isFalse);
      expect(NotificationPrivacyMode.fromId('MAXIMUM'), isNull);
    });

    test(
        'N-2 missing record: empty and writable; a save is one encrypted row '
        'without package names in clear', () async {
      final NotificationPrivacyRead r = await store.read();
      expect(r.health, NotificationPrivacyHealth.missing);
      expect(r.writable, isTrue);
      expect(r.settings.apps, isEmpty);
      final NotificationPrivacySettings? s = await store.update(
          (NotificationPrivacySettings c) =>
              c.withMode(_bank, NotificationPrivacyMode.hideContent));
      expect(s!.modeFor(_bank), NotificationPrivacyMode.hideContent);
      final String raw = (await db.getSetting(_key))!;
      expect(raw.startsWith('enc:v1:'), isTrue);
      expect(raw.contains(_bank), isFalse);
      expect(
          jsonDecode(await cipher.decryptString(raw.substring(7))),
          <String, Object?>{
            'v': 1,
            'apps': <String, Object?>{_bank: 'hide_content'},
          });
    });

    test('N-3 round trip; Off removes the entry; other apps untouched',
        () async {
      await store.update((c) => c
          .withMode(_bank, NotificationPrivacyMode.maximum)
          .withMode(_chat, NotificationPrivacyMode.hideContent));
      await store.update((c) => c.withMode(_bank, NotificationPrivacyMode.off));
      final NotificationPrivacyRead r = await store.read();
      expect(r.health, NotificationPrivacyHealth.ok);
      expect(r.settings.apps, <String, NotificationPrivacyMode>{
        _chat: NotificationPrivacyMode.hideContent
      });
      expect(r.settings.modeFor(_bank), NotificationPrivacyMode.off);
    });

    for (final (String name, Future<String> Function() raw)
        in <(String, Future<String> Function())>[
      ('no prefix', () async => '{"v":1,"apps":{}}'),
      ('not base64', () async => 'enc:v1:%%%'),
      ('bad json', () async => enc('{nope')),
      ('apps not a map', () async => enc('{"v":1,"apps":[]}')),
      (
        'invalid package',
        () async => enc('{"v":1,"apps":{"bad pkg":"maximum"}}')
      ),
      ('unknown mode', () async => enc('{"v":1,"apps":{"$_bank":"secret"}}')),
      ('stored off', () async => enc('{"v":1,"apps":{"$_bank":"off"}}')),
      ('v0', () async => enc('{"v":0,"apps":{}}')),
    ]) {
      test('N-4 corrupt ($name): never read as off, never overwritten',
          () async {
        final String stored = await raw();
        await db.setSetting(_key, stored);
        final NotificationPrivacyRead r = await store.read();
        expect(r.health, NotificationPrivacyHealth.corrupt);
        expect(r.writable, isFalse);
        expect(
            await store
                .update((c) => c.withMode(_bank, NotificationPrivacyMode.off)),
            isNull);
        expect(await db.getSetting(_key), stored);
      });
    }

    test('N-5 newer version: unsupported, never overwritten', () async {
      final String stored = await enc('{"v":2,"apps":{},"x":1}');
      await db.setSetting(_key, stored);
      expect(
          (await store.read()).health, NotificationPrivacyHealth.unsupported);
      expect(
          await store.update(
              (c) => c.withMode(_bank, NotificationPrivacyMode.maximum)),
          isNull);
      expect(await db.getSetting(_key), stored);
    });

    test('N-6 wrong key: unreadable (not corrupt), preserved byte-identical',
        () async {
      await store
          .update((c) => c.withMode(_bank, NotificationPrivacyMode.maximum));
      final String stored = (await db.getSetting(_key))!;
      final NotificationPrivacySettingsStore other =
          NotificationPrivacySettingsStore(db, _cipher());
      expect((await other.read()).health, NotificationPrivacyHealth.unreadable);
      expect(
          await other
              .update((c) => c.withMode(_bank, NotificationPrivacyMode.off)),
          isNull);
      expect(await db.getSetting(_key), stored);
    });

    test(
        'N-6b tampered ciphertext (right key, valid base64): unreadable, '
        'never read as off or missing, preserved byte-identical', () async {
      await store
          .update((c) => c.withMode(_bank, NotificationPrivacyMode.maximum));
      final String good = (await db.getSetting(_key))!;
      final List<int> bytes = base64Decode(good.substring(7));
      bytes[bytes.length - 1] ^= 0x01; // flip one MAC bit
      final String tampered = 'enc:v1:${base64Encode(bytes)}';
      await db.setSetting(_key, tampered);
      final NotificationPrivacyRead r = await store.read();
      expect(r.health, NotificationPrivacyHealth.unreadable);
      expect(r.writable, isFalse);
      expect(r.settings.apps, isEmpty);
      expect(
          await store.update(
              (c) => c.withMode(_chat, NotificationPrivacyMode.hideContent)),
          isNull);
      expect(await db.getSetting(_key), tampered);
    });

    test('N-7 too many apps or an invalid package is refused before writing',
        () async {
      expect(
          await store.update((c) =>
              c.withMode('not a package', NotificationPrivacyMode.maximum)),
          isNull);
      expect(
          await store.update((NotificationPrivacySettings c) {
            NotificationPrivacySettings s = c;
            for (int i = 0; i <= NotificationPrivacySettings.maxApps; i++) {
              s = s.withMode('com.a.p$i', NotificationPrivacyMode.maximum);
            }
            return s;
          }),
          isNull);
      expect(await db.getSetting(_key), isNull);
    });

    test('N-8 concurrent updates for two apps: both kept (serialized)',
        () async {
      await Future.wait(<Future<Object?>>[
        store.update((c) => c.withMode(_bank, NotificationPrivacyMode.maximum)),
        store.update(
            (c) => c.withMode(_chat, NotificationPrivacyMode.hideContent)),
      ]);
      expect(
          (await store.read()).settings.apps, <String, NotificationPrivacyMode>{
        _bank: NotificationPrivacyMode.maximum,
        _chat: NotificationPrivacyMode.hideContent,
      });
    });
  });

  group('C controller', () {
    late AppContainer c;
    late StaticNotificationPrivacyService native;
    late InMemoryLocalDatabase db;

    setUp(() async {
      native = StaticNotificationPrivacyService();
      db = InMemoryLocalDatabase();
      c = AppContainer.inMemory(database: db, notificationPrivacy: native);
      await c.notificationPrivacyStartup;
      await c.protectedApps.add(ProtectedApp(
          packageName: _bank, label: 'Bank', addedAt: DateTime(2026, 10, 1)));
    });

    test('C-1 startup sync pushes the (empty) stored snapshot', () {
      expect(native.configured, <Map<String, NotificationPrivacyMode>>[
        <String, NotificationPrivacyMode>{},
      ]);
    });

    test('C-2 an unprotected app is refused: nothing written or pushed',
        () async {
      final int before = native.configured.length;
      expect(
          await c.notificationPrivacy
              .setMode(_chat, NotificationPrivacyMode.maximum),
          NotificationPrivacyChangeOutcome.refused);
      expect(await db.getSetting(_key), isNull);
      expect(native.configured.length, before);
    });

    test(
        'C-3 protected app: saved and native receives the full snapshot; '
        'the same value again is unchanged', () async {
      expect(
          await c.notificationPrivacy
              .setMode(_bank, NotificationPrivacyMode.hideContent),
          NotificationPrivacyChangeOutcome.saved);
      expect(native.native, <String, NotificationPrivacyMode>{
        _bank: NotificationPrivacyMode.hideContent
      });
      expect(
          await c.notificationPrivacy
              .setMode(_bank, NotificationPrivacyMode.hideContent),
          NotificationPrivacyChangeOutcome.unchanged);
    });

    test('C-4 native refuses: saved but not applied; the next sync applies',
        () async {
      native.failConfigure = true;
      expect(
          await c.notificationPrivacy
              .setMode(_bank, NotificationPrivacyMode.maximum),
          NotificationPrivacyChangeOutcome.savedNotApplied);
      native.failConfigure = false;
      expect(await c.notificationPrivacy.sync(), isTrue);
      expect(native.native, <String, NotificationPrivacyMode>{
        _bank: NotificationPrivacyMode.maximum
      });
    });

    test(
        'C-5 unreadable record: sync pushes nothing (native keeps its last '
        'snapshot), changes refused', () async {
      await c.notificationPrivacy
          .setMode(_bank, NotificationPrivacyMode.maximum);
      final int before = native.configured.length;
      final StaticNotificationPrivacyService native2 =
          StaticNotificationPrivacyService();
      // Same database, different key (e.g. a lost or unverified key).
      final AppContainer other =
          AppContainer.inMemory(database: db, notificationPrivacy: native2);
      await other.notificationPrivacyStartup;
      expect(native2.configured, isEmpty, reason: 'startup pushed nothing');
      expect(await other.notificationPrivacy.sync(), isFalse);
      expect(
          await other.notificationPrivacy
              .setMode(_bank, NotificationPrivacyMode.off),
          NotificationPrivacyChangeOutcome.refused);
      expect((await other.notificationPrivacy.load()).writable, isFalse);
      expect(native.configured.length, before);
    });

    test(
        'C-6 a stored mode survives unprotecting the app and is still pushed '
        '(native decides eligibility from its protected set)', () async {
      await c.notificationPrivacy
          .setMode(_bank, NotificationPrivacyMode.maximum);
      await c.protectedApps.remove(_bank);
      expect(await c.notificationPrivacy.sync(), isTrue);
      expect(native.native, <String, NotificationPrivacyMode>{
        _bank: NotificationPrivacyMode.maximum
      });
      expect((await c.notificationPrivacy.load()).apps, isEmpty);
    });
  });

  group('M method channel', () {
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

    test('M-1 configure sends package -> mode id and reads "applied"',
        () async {
      reply = (_) => <String, Object?>{'applied': true, 'count': 1};
      final NotificationPrivacyService s =
          MethodChannelNotificationPrivacyService();
      expect(
          (await s.configure(<String, NotificationPrivacyMode>{
            _bank: NotificationPrivacyMode.maximum,
          }))
              .valueOrNull,
          isTrue);
      expect(calls.single.method, 'configure');
      expect(calls.single.arguments, <String, Object?>{
        'modes': <String, String>{_bank: 'maximum'},
      });
      reply = (_) => <String, Object?>{'applied': false, 'count': 0};
      expect(
          (await s.configure(const <String, NotificationPrivacyMode>{}))
              .valueOrNull,
          isFalse);
    });

    test('M-2 status parsing, settings links and errors', () async {
      final NotificationPrivacyService s =
          MethodChannelNotificationPrivacyService();
      reply = (MethodCall call) => switch (call.method) {
            'getStatus' => <String, Object?>{
                'accessGranted': true,
                'listenerConnected': false,
                'storeInvalid': true,
                'configuredCount': 2,
              },
            _ => true,
          };
      final NotificationPrivacyStatus st = (await s.status()).valueOrNull!;
      expect(st.accessGranted, isTrue);
      expect(st.listenerConnected, isFalse);
      expect(st.storeInvalid, isTrue);
      expect(st.configuredCount, 2);
      expect((await s.openAccessSettings()).valueOrNull, isTrue);
      expect((await s.openAppNotificationSettings(_bank)).valueOrNull, isTrue);
      expect(calls.last.arguments, <String, Object?>{'packageName': _bank});
      reply = (_) => throw PlatformException(code: 'x');
      expect((await s.status()).isFailure, isTrue);
      expect(
          (await s.configure(const <String, NotificationPrivacyMode>{}))
              .isFailure,
          isTrue);
    });
  });
}
