// F-KEY-1 owner decision G-7: neutral "secure storage unavailable" copy.
// SIMULATED (host widgets; the credential state is made unreadable by a
// failing master-key read, the key itself is untouched). Not device QA.
//
// Asserts: the message is shown; no credential setup/reset is offered; no
// "No PIN/pattern configured" claim; leaving returns false (no grant); the
// credential row is byte-identical; retry recovers when storage returns.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/ui/screens/pattern/pattern_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/widgets/secure_storage_unavailable.dart';

const String _pin = '482913';
const List<int> _pattern = <int>[1, 2, 3, 6, 9];
const String _settingsKey = 'security_settings';

class _Toggle implements SecretStore {
  _Toggle(this.inner);
  final InMemorySecretStore inner;
  bool fail = true;
  int writes = 0;
  @override
  Future<String?> read(String key) async {
    if (fail && key == SecretKeys.settingsMasterKey) {
      throw StateError('keystore unavailable');
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) async {
    writes++;
    if (fail) throw StateError('keystore unavailable');
    return inner.write(key, value);
  }

  @override
  Future<void> delete(String key) => inner.delete(key);
  @override
  Future<void> clear() => inner.clear();
  @override
  Future<bool> containsKey(String key) => inner.containsKey(key);
}

Future<(InMemoryLocalDatabase, _Toggle, AppContainer)> _setup(
    {bool pattern = false}) async {
  final InMemoryLocalDatabase db = InMemoryLocalDatabase();
  final InMemorySecretStore secrets = InMemorySecretStore();
  final AppContainer c1 =
      AppContainer.inMemory(database: db, secretStore: secrets);
  if (pattern) {
    expect((await c1.auth.enrollPattern(_pattern)).isSuccess, isTrue);
  } else {
    expect((await c1.auth.enrollPin(_pin)).isSuccess, isTrue);
  }
  final _Toggle t = _Toggle(secrets);
  return (db, t, AppContainer.inMemory(database: db, secretStore: t));
}

void main() {
  for (final bool pattern in <bool>[false, true]) {
    final String kind = pattern ? 'pattern' : 'PIN';
    testWidgets('G7-1 $kind unlock: unreadable credential state shows the '
        'neutral message, no setup offer, Back returns false; retry recovers',
        (WidgetTester tester) async {
      final (InMemoryLocalDatabase db, _Toggle secrets, AppContainer c) =
          await _setup(pattern: pattern);
      final String rowBefore = (await db.getSetting(_settingsKey))!;
      Object? result = 'pending';
      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (BuildContext ctx) => Scaffold(
            body: TextButton(
              onPressed: () async {
                result = await Navigator.of(ctx).push<bool>(
                  MaterialPageRoute<bool>(
                    builder: (_) => pattern
                        ? PatternUnlockScreen(credentialManager: c.auth)
                        : PinUnlockScreen(credentialManager: c.auth),
                  ),
                );
              },
              child: const Text('open'),
            ),
          ),
        ),
      ));
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      expect(find.text(SecureStorageUnavailableText.message), findsOneWidget);
      expect(find.text(PinUnlockScreen.noCredentialTitle), findsNothing);
      expect(find.text(PatternUnlockScreen.noCredentialTitle), findsNothing);
      expect(find.text(PinUnlockScreen.setUpPinLabel), findsNothing);
      expect(find.text(PatternUnlockScreen.setUpPatternLabel), findsNothing);

      // Retry while still unavailable: same neutral view.
      await tester.tap(find.byKey(const ValueKey<String>('secure_storage_retry')));
      await tester.pumpAndSettle();
      expect(find.text(SecureStorageUnavailableText.message), findsOneWidget);

      // Back: the route resolves false (never a grant).
      await tester.tap(find.text(pattern
          ? PatternUnlockScreen.backLabel
          : PinUnlockScreen.backLabel));
      await tester.pumpAndSettle();
      expect(result, isFalse);
      expect(await db.getSetting(_settingsKey), rowBefore);

      // Storage returns: retry reaches the normal entry view.
      secrets.fail = false;
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();
      expect(find.text(SecureStorageUnavailableText.message), findsNothing);
      if (pattern) {
        expect(find.text(PatternUnlockScreen.readyHint), findsOneWidget);
      } else {
        expect(find.byKey(const Key('pin_key_1')), findsOneWidget);
      }
      expect(await db.getSetting(_settingsKey), rowBefore);
    });
  }

  testWidgets('G7-2 Security tab: unreadable credential state shows the '
      'neutral banner (never "no PIN"); no key write',
      (WidgetTester tester) async {
    final (InMemoryLocalDatabase db, _Toggle secrets, AppContainer c) =
        await _setup();
    final String rowBefore = (await db.getSetting(_settingsKey))!;
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    addTearDown(c.capabilityMonitor.dispose);
    await tester.pumpWidget(SmartAppLockApp(container: c));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nav_security')));
    await tester.pumpAndSettle();
    expect(find.byKey(SecureStorageUnavailableBanner.bannerKey), findsOneWidget);
    expect(find.text(SecureStorageUnavailableText.message), findsOneWidget);
    expect(await db.getSetting(_settingsKey), rowBefore);
    expect(secrets.writes, 0, reason: 'no key write while unavailable');
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(minutes: 2, seconds: 1)); // drain timers
  });

  testWidgets('G7-3 Security tab: enabling biometrics while the credential '
      'state is unreadable shows the neutral snackbar (never "Set up a PIN '
      'or pattern first."); nothing written', (WidgetTester tester) async {
    final (InMemoryLocalDatabase db, _Toggle secrets, AppContainer c) =
        await _setup();
    final String rowBefore = (await db.getSetting(_settingsKey))!;
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    addTearDown(c.capabilityMonitor.dispose);
    await tester.pumpWidget(SmartAppLockApp(container: c));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nav_security')));
    await tester.pumpAndSettle();
    final Finder tile = find.text('Biometric unlock');
    await tester.ensureVisible(tile);
    await tester.pumpAndSettle();
    await tester.tap(tile);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    expect(
        find.descendant(
            of: find.byType(SnackBar),
            matching: find.text(SecureStorageUnavailableText.message)),
        findsOneWidget);
    expect(find.text('Set up a PIN or pattern first.'), findsNothing);
    expect(await db.getSetting(_settingsKey), rowBefore);
    expect(secrets.writes, 0, reason: 'no key write while unavailable');
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(minutes: 2, seconds: 1)); // drain timers
  });
}
