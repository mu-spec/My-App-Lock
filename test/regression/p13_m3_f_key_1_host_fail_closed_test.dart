// P13/M3 F-KEY-1 — FK-H: a protected-app launch after a (SIMULATED) process
// restart while the credential state is UNREADABLE must never grant access.
//
// Host evidence only: real app widgets + LockChallengeHost over the static
// native-contract model (mirrors WatcherService shield-first recovery). Not
// Android, not device QA. First launch / key creation is NOT exercised here
// (the key exists because process 1 enrolled a PIN); the unfixed key race is
// reproduced separately in p13_m3_f_key_1_open_reproducer_test.dart.
//
// Expected fail-closed shape (code-read, asserted here on host):
//  * protection bootstrap fails -> nothing sent to native; the persisted
//    native protected set stays active;
//  * native raises the opaque shield + persisted ticket; Dart's host ABORTs
//    (status unreadable) without presenting, granting or hiding anything;
//  * no authorizePackage, no Dart session, no launch, no shield hide;
//  * the settings row is byte-identical; no credential/lockout write;
//  * once storage is readable again, the original PIN is required and works.
// Residual (availability, not a grant): the user sees a shield with no
// challenge until storage recovers (recorded as F-KEY-1e). Batch 2 (G7-H1
// option 2): that shield now shows the neutral storage-unavailable text.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/protection/access_controller.dart';
import 'package:smart_app_lock/protection/impl/default_access_controller.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/services/impl/static_accessibility_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_installed_apps_service.dart';
import 'package:smart_app_lock/services/impl/static_native_challenge_contract.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';

const String _pin = '482914';
const String _pkg = 'com.bank.app';
const String _settingsKey = 'security_settings';
const String _mk = SecretKeys.settingsMasterKey;

enum _Mode { healthy, throws, nullOnce, wrongKey }

/// Wraps the persisted secret store of "process 1" and injects one fault
/// mode for the master key in "process 2".
class _FaultySecrets implements SecretStore {
  _FaultySecrets(this.inner, this.mode);
  final InMemorySecretStore inner;
  _Mode mode;
  int keyWrites = 0;
  bool _nullUsed = false;

  @override
  Future<String?> read(String key) async {
    if (key == _mk) {
      switch (mode) {
        case _Mode.healthy:
          break;
        case _Mode.throws:
          throw StateError('keystore unavailable');
        case _Mode.nullOnce:
          // flutter_secure_storage 11.2.0 resetOnError: a failed read
          // deletes the entry and reports "absent" once.
          if (!_nullUsed) {
            _nullUsed = true;
            return null;
          }
        case _Mode.wrongKey:
          return _wrongKey;
      }
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) {
    if (key == _mk) keyWrites++;
    return inner.write(key, value);
  }

  @override
  Future<void> delete(String key) => inner.delete(key);
  @override
  Future<void> clear() => inner.clear();
  @override
  Future<bool> containsKey(String key) => inner.containsKey(key);
}

/// A well-formed but WRONG 256-bit key (32 x 0x07, base64).
const String _wrongKey = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=';

StaticNativeChallengeContract _bind(
  AppContainer c, {
  required bool enabled,
  required Set<String> packages,
}) {
  final StaticNativeChallengeContract n = StaticNativeChallengeContract();
  (c.overlay as StaticOverlayLockService).nativeContract = n;
  (c.watcher as StaticWatcherService).nativeContract = n;
  n.configure(enabled: enabled, packages: packages);
  return n;
}

void main() {
  late InMemoryLocalDatabase disk;
  late InMemorySecretStore secrets;
  late Set<String> nativePackages;

  /// Process 1: enroll, protect, synchronize native. Returns nothing; the
  /// persisted state lives in [disk], [secrets] and [nativePackages].
  Future<void> process1() async {
    disk = InMemoryLocalDatabase();
    secrets = InMemorySecretStore();
    final AppContainer c1 =
        AppContainer.inMemory(database: disk, secretStore: secrets);
    await c1.auth.enrollPin(_pin);
    await c1.protectedApps.add(ProtectedApp(
      packageName: _pkg,
      label: _pkg,
      addedAt: DateTime(2026, 10, 22),
    ));
    expect((await c1.protectionBootstrap.synchronize()).isSuccess, isTrue);
    final StaticWatcherService w = c1.watcher as StaticWatcherService;
    expect(w.protectionConfigured, isTrue);
    nativePackages = Set<String>.of(w.protectedPackages);
    expect(nativePackages, contains(_pkg));
  }

  // nullOnce is FLIPPED by Batch 2 into its own test (FK-H nullOnce
  // FLIPPED, below): one null read no longer yields a persistent
  // unreadable state, so the persistent-fault assertions here no longer
  // describe it.
  for (final _Mode mode in <_Mode>[
    _Mode.throws,
    _Mode.wrongKey
  ]) {
    testWidgets(
        'FK-H ${mode.name}: protected launch with unreadable '
        'credential state never grants access', (WidgetTester t) async {
      t.view.physicalSize = const Size(800, 1600);
      t.view.devicePixelRatio = 1.0;
      addTearDown(t.view.reset);
      await process1();
      final String rowBefore = (await disk.getSetting(_settingsKey))!;
      final String keyBefore = (await secrets.read(_mk))!;

      // Process 2 (SIMULATED restart) with the master key unreadable.
      final _FaultySecrets faulty = _FaultySecrets(secrets, mode);
      final AppContainer c2 =
          AppContainer.inMemory(database: disk, secretStore: faulty);
      final StaticNativeChallengeContract n2 =
          _bind(c2, enabled: true, packages: nativePackages);
      await t.pumpWidget(SmartAppLockApp(container: c2));
      await t.pumpAndSettle();
      final StaticWatcherService w2 = c2.watcher as StaticWatcherService;

      expect((await c2.auth.status()).isFailure, isTrue);
      expect((await c2.protectionBootstrap.synchronize()).isFailure, isTrue);
      expect(n2.enabled, isTrue, reason: 'native protection never disabled');
      expect(n2.protectedPackages, nativePackages);

      // Production order: native first, then Dart.
      n2.reportForeground(_pkg);
      (c2.accessibility as StaticAccessibilityLockService)
          .emitForegroundPackage(_pkg);
      await t.pumpAndSettle();
      await t.pump(const Duration(seconds: 5)); // heartbeat retries
      await t.pumpAndSettle();

      expect(n2.shieldVisible, isTrue, reason: 'opaque shield stays up');
      expect(n2.pending?.packageName, _pkg, reason: 'ticket stays pending');
      expect(n2.authorizedPackages, isEmpty);
      expect(w2.authorizePackageCalls, 0);
      expect((c2.accessController as DefaultAccessController).sessionFor(_pkg),
          isNull);
      expect(await c2.accessController.evaluate(_pkg),
          isNot(AccessDecision.allow));
      expect(
          (c2.overlay as StaticOverlayLockService).hideLockChallengeCalls, 0);
      expect(
          (c2.installedAppsService as StaticInstalledAppsService)
              .launchAppCalls,
          0);
      // F-KEY-1e: no challenge UI, and (Batch 2, G7-H1 option 2) the
      // VISIBLE shield now carries the neutral storage-unavailable text.
      expect(find.byType(PinUnlockScreen), findsNothing);
      expect(
          (c2.overlay as StaticOverlayLockService)
              .storageUnavailableNoticeCalls,
          greaterThan(0));
      expect(n2.storageUnavailableNotice, isTrue);
      expect(n2.shieldVisible, isTrue, reason: 'text only, never hidden');
      expect(n2.readyChallenge, isNull, reason: 'never markChallengeReady');
      // Credential + lockout row untouched.
      expect(await disk.getSetting(_settingsKey), rowBefore);
      // F-KEY-1d FLIPPED (Batch 2): the original asserted that one null
      // read minted and persisted a replacement key (preserved in the sealed
      // F_KEY_1/tests copy). Now NO mode writes a key and the original key
      // survives, so every mode recovers below with the ORIGINAL PIN.
      expect(faulty.keyWrites, 0);
      expect(await secrets.read(_mk), keyBefore);
      await t.pumpWidget(const SizedBox());
      await t.pumpAndSettle();

      // Recovery: storage readable again -> the ORIGINAL PIN is required.
      final AppContainer c3 =
          AppContainer.inMemory(database: disk, secretStore: secrets);
      final StaticNativeChallengeContract n3 =
          _bind(c3, enabled: true, packages: nativePackages);
      await t.pumpWidget(SmartAppLockApp(container: c3));
      await t.pumpAndSettle();
      n3.reportForeground(_pkg);
      (c3.accessibility as StaticAccessibilityLockService)
          .emitForegroundPackage(_pkg);
      await t.pumpAndSettle();
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      for (final String d in '000000'.split('')) {
        await t.tap(find.byKey(Key('pin_key_$d')));
        await t.pump(const Duration(milliseconds: 20));
      }
      await t.pumpAndSettle();
      expect(n3.authorizedPackages, isEmpty);
      await t.pump(const Duration(seconds: 2));
      await t.pumpAndSettle();
      for (final String d in _pin.split('')) {
        await t.tap(find.byKey(Key('pin_key_$d')));
        await t.pump(const Duration(milliseconds: 20));
      }
      await t.pumpAndSettle();
      expect(n3.authorizedPackages, contains(_pkg));
      expect((c3.watcher as StaticWatcherService).authorizePackageCalls, 1);
    });
  }

  testWidgets(
      'FK-H5 Batch 2: a genuinely unenrolled state (readable, no credential) '
      'never shows the storage-unavailable notice', (WidgetTester t) async {
    t.view.physicalSize = const Size(800, 1600);
    t.view.devicePixelRatio = 1.0;
    addTearDown(t.view.reset);
    final AppContainer c = AppContainer.inMemory(
        database: InMemoryLocalDatabase(), secretStore: InMemorySecretStore());
    // The package IS protected (Dart + native), so the host really reaches
    // its no-credential branch (pass-1 B2-19 SURVIVED without this).
    await c.protectedApps.add(ProtectedApp(
      packageName: _pkg,
      label: _pkg,
      addedAt: DateTime(2026, 10, 22),
    ));
    final StaticNativeChallengeContract n =
        _bind(c, enabled: true, packages: <String>{_pkg});
    await t.pumpWidget(SmartAppLockApp(container: c));
    await t.pumpAndSettle();
    expect((await c.auth.status()).isSuccess, isTrue);
    n.reportForeground(_pkg);
    (c.accessibility as StaticAccessibilityLockService)
        .emitForegroundPackage(_pkg);
    await t.pumpAndSettle();
    await t.pump(const Duration(seconds: 5));
    await t.pumpAndSettle();
    expect(
        (c.overlay as StaticOverlayLockService).storageUnavailableNoticeCalls,
        0);
    expect(n.storageUnavailableNotice, isFalse);
    await t.pumpWidget(const SizedBox());
    await t.pumpAndSettle();
  });

  // F-KEY-1d FLIPPED (Batch 2). The ORIGINAL nullOnce case asserted that one
  // null read minted and persisted a replacement key, losing the credential
  // for good (sealed copy in Phase13/.../F_KEY_1/tests/). Repaired: that
  // read fails closed WITHOUT any key write; the next read recovers the
  // original key; a protected launch then requires the ORIGINAL PIN.
  testWidgets(
      'FK-H nullOnce FLIPPED: one null key read fails closed, writes no key, '
      'and the original PIN is then required and works', (WidgetTester t) async {
    t.view.physicalSize = const Size(800, 1600);
    t.view.devicePixelRatio = 1.0;
    addTearDown(t.view.reset);
    await process1();
    final String rowBefore = (await disk.getSetting(_settingsKey))!;
    final String keyBefore = (await secrets.read(_mk))!;
    final _FaultySecrets faulty = _FaultySecrets(secrets, _Mode.nullOnce);
    final AppContainer c2 =
        AppContainer.inMemory(database: disk, secretStore: faulty);
    // The read that sees the null fails closed (never "no credential").
    expect((await c2.auth.status()).isFailure, isTrue);
    // An authentication whose key read sees the null never grants, even
    // with the CORRECT PIN (separate process view, its own null read).
    final _FaultySecrets faultyB = _FaultySecrets(secrets, _Mode.nullOnce);
    final AppContainer c2b =
        AppContainer.inMemory(database: disk, secretStore: faultyB);
    expect((await c2b.auth.authenticatePin(_pin)).valueOrNull,
        isNot(isA<AuthSuccess>()));
    expect(faultyB.keyWrites, 0);
    expect(faulty.keyWrites, 0, reason: 'FIXED: no replacement key');
    expect(await secrets.read(_mk), keyBefore);
    expect(await disk.getSetting(_settingsKey), rowBefore);
    // Not cached as a failure: the next read recovers the SAME state.
    expect((await c2.auth.status()).valueOrNull!.hasAnyCredential, isTrue);

    final StaticNativeChallengeContract n2 =
        _bind(c2, enabled: true, packages: nativePackages);
    await t.pumpWidget(SmartAppLockApp(container: c2));
    await t.pumpAndSettle();
    n2.reportForeground(_pkg);
    (c2.accessibility as StaticAccessibilityLockService)
        .emitForegroundPackage(_pkg);
    await t.pumpAndSettle();
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    expect(n2.storageUnavailableNotice, isFalse);
    for (final String d in '000000'.split('')) {
      await t.tap(find.byKey(Key('pin_key_$d')));
      await t.pump(const Duration(milliseconds: 20));
    }
    await t.pumpAndSettle();
    expect(n2.authorizedPackages, isEmpty);
    await t.pump(const Duration(seconds: 2));
    await t.pumpAndSettle();
    for (final String d in _pin.split('')) {
      await t.tap(find.byKey(Key('pin_key_$d')));
      await t.pump(const Duration(milliseconds: 20));
    }
    await t.pumpAndSettle();
    expect(n2.authorizedPackages, contains(_pkg));
    expect(faulty.keyWrites, 0);
    await t.pumpWidget(const SizedBox());
    await t.pumpAndSettle();
  });
}
