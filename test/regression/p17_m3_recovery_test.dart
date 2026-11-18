import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/services/impl/static_accessibility_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_native_challenge_contract.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/services/pending_lock_challenge.dart';
import 'package:smart_app_lock/services/watcher_last_error_code.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';

import '../support/p17_latency_device.dart';

/// Phase 17 / M3 — recovery: service destroy/restart cycles, engine detach
/// and re-attach, an interrupted challenge, delayed Flutter initialization,
/// protected-app changes while the screen is off, and credential storage
/// that is temporarily unreadable while a challenge is shown.
///
/// SIMULATED (evidence B): [StaticNativeChallengeContract] mirrors the
/// Kotlin policies; nothing here proves Android restarted a component.
const String _open = 'com.example.notes';

Future<void> _foreground(P17Device d, String pkg) async {
  d.native.reportForeground(pkg);
  (d.container.accessibility as StaticAccessibilityLockService)
      .emitForegroundPackage(pkg);
  await d.tester.pumpAndSettle();
}

Future<void> _unmount(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 5));
}

void main() {
  testWidgets(
      'RC-1: 20 watcher destroy/restart cycles while authorized — each '
      'interruption revokes, only one restart decision per process, the '
      'interruption error clears on restart, a PIN is required again',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    final int decisionsBefore = d.native.restartDecisions;
    for (int i = 0; i < 20; i++) {
      await d.openProtectedApp();
      if (find.byType(PinUnlockScreen).evaluate().isNotEmpty) {
        await d.enterPin(p17Pin);
      }
      expect(d.native.authorizedPackages, <String>{p17Pkg}, reason: '#$i');
      d.native.serviceDestroyed();
      expect(d.native.authorizedPackages, isEmpty, reason: '#$i');
      expect(d.native.lastErrorCode, WatcherLastErrorCode.watcherInterrupted);
      d.native.serviceStart();
      expect(d.native.lastErrorCode, isNull, reason: '#$i');
      expect(d.native.authorizedPackages, isEmpty,
          reason: '#$i a restart never grants');
      await tester.pumpAndSettle();
      // Returning to the app requires a fresh PIN.
      await _foreground(d, _open);
      await d.openProtectedApp();
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      d.expectNoAccess();
    }
    expect(d.native.restartDecisions - decisionsBefore, lessThanOrEqualTo(1),
        reason: 'OneShotLatch: one restart decision per process');
    await _unmount(tester);
  });

  testWidgets(
      'RC-2: engine detach without the watcher revokes; with the watcher '
      'running, screen-off still revokes (10 cycles each)',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    for (int i = 0; i < 10; i++) {
      await d.openProtectedApp();
      await d.enterPin(p17Pin);
      expect(d.native.authorizedPackages, <String>{p17Pkg});
      d.native.serviceDestroyed();
      d.native.activityDestroyed();
      expect(d.native.authorizedPackages, isEmpty, reason: 'down #$i');
      d.native.serviceStart();
      d.native.onActivityResumed();
      await tester.pumpAndSettle();
      await _foreground(d, _open);
    }
    for (int i = 0; i < 10; i++) {
      await d.openProtectedApp();
      await d.enterPin(p17Pin);
      d.native.activityDestroyed(); // watcher still running
      d.native.screenOff();
      expect(d.native.authorizedPackages, isEmpty, reason: 'up #$i');
      d.native.screenOn();
      d.native.onActivityResumed();
      await tester.pumpAndSettle();
      await _foreground(d, _open);
    }
    await _unmount(tester);
  });

  testWidgets(
      'RC-3: an interrupted challenge (half-typed PIN, engine torn down and '
      're-attached 10 times) keeps the ticket and starts entry from scratch',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    await d.openProtectedApp();
    final PendingLockChallenge ticket = d.native.pending!;
    for (int i = 0; i < 10; i++) {
      await tester.tap(find.byKey(const Key('pin_key_1')));
      await tester.tap(find.byKey(const Key('pin_key_2')));
      await tester.pump();
      // Engine detach: the Flutter tree goes away mid-entry.
      await tester.pumpWidget(const SizedBox());
      d.native.activityDestroyed();
      await tester.pump(const Duration(seconds: 1));
      d.expectNoAccess();
      expect(d.native.pending, ticket, reason: '#$i');
      // Re-attach over the same process state.
      d.native.onActivityResumed();
      await tester.pumpWidget(SmartAppLockApp(container: d.container));
      await tester.pumpAndSettle();
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      // Completing only the remaining two digits must not unlock.
      await d.enterPin('34');
      await tester.pump(const Duration(seconds: 1));
      d.expectNoAccess();
      // Discard the two digits too (another detach) so that no attempt is
      // ever submitted: wrong attempts would otherwise reach the lockout.
      await tester.pumpWidget(const SizedBox());
      await tester.pumpWidget(SmartAppLockApp(container: d.container));
      await tester.pumpAndSettle();
    }
    await d.enterPin(p17Pin);
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    await _unmount(tester);
  });

  testWidgets(
      'RC-4: delayed Flutter initialization — the shield is up before any '
      'UI, the restored challenge is the persisted ticket, no access',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester, nativeTicketBeforeMount: true);
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    d.expectNoAccess();
    final PendingLockChallenge ticket = d.native.pending!;
    // Repeated retry ticks and duplicate service starts change nothing.
    for (int i = 0; i < 20; i++) {
      d.native.recoveryRetryTick();
      d.native.serviceStart();
      await tester.pump(const Duration(milliseconds: 50));
    }
    await tester.pumpAndSettle();
    expect(d.native.pending, ticket);
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    d.expectNoAccess();
    await d.enterPin(p17Pin);
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    await _unmount(tester);
  });

  testWidgets(
      'RC-5: unprotect and re-protect while the screen is off never revives '
      'an authorization; the wake challenge is still required',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    await d.openProtectedApp();
    await d.enterPin(p17Pin);
    for (int i = 0; i < 5; i++) {
      await d.screenOff();
      expect(d.native.authorizedPackages, isEmpty);
      await d.container.protectedApps.remove(p17Pkg);
      await d.container.protectionBootstrap.synchronize();
      expect(d.native.isProtected(p17Pkg), isFalse);
      await d.container.protectedApps.add(ProtectedApp(
        packageName: p17Pkg,
        label: 'WhatsApp',
        addedAt: DateTime(2026, 10, 22),
      ));
      await d.container.protectionBootstrap.synchronize();
      expect(d.native.isProtected(p17Pkg), isTrue);
      await d.screenOnBehindKeyguard();
      d.native.dismissKeyguard();
      d.screen.emitUserPresent();
      await tester.pumpAndSettle();
      await d.openProtectedApp();
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      d.expectNoAccess();
      await d.enterPin(p17Pin);
      expect(d.native.authorizedPackages, <String>{p17Pkg}, reason: '#$i');
    }
    await _unmount(tester);
  });

  testWidgets(
      'RC-7 (A11Y-1): an Accessibility unbind ends native grants, so a '
      'return that went unobserved during the outage needs a PIN (10x)',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    await d.openProtectedApp();
    await d.enterPin(p17Pin);
    for (int i = 0; i < 10; i++) {
      expect(d.native.authorizedPackages, <String>{p17Pkg}, reason: '#$i');
      // Accessibility is unbound (OEM kill / toggle) while the process and
      // the watcher live on. During the outage the user leaves and comes
      // back; with no UsageEvents fallback nothing reports it.
      d.native.accessibilityDisconnected();
      await tester.pump(const Duration(seconds: 30));
      // Rebind: the first report is the same protected package.
      d.native.reportForeground(p17Pkg);
      await tester.pumpAndSettle();
      expect(d.native.authorizedPackages, isEmpty,
          reason: '#$i no grant spans an unobserved interval');
      expect(d.native.pending?.packageName, p17Pkg, reason: '#$i');
      expect(
          d.native.shieldVisible ||
              find.byType(PinUnlockScreen).evaluate().isNotEmpty,
          isTrue,
          reason: '#$i shielded');
      // The host's heartbeat pull presents the pending native ticket.
      await tester.pump(const Duration(seconds: 3));
      await tester.pumpAndSettle();
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      // Dart was equally blind during the outage, so its own session can
      // remain (bookkeeping only); it never authorizes natively and never
      // dismisses the challenge: the pending native ticket wins.
      await tester.pump(const Duration(seconds: 5));
      await tester.pumpAndSettle();
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      expect(d.native.authorizedPackages, isEmpty, reason: '#$i');
      expect(d.native.pending?.packageName, p17Pkg, reason: '#$i');
      await d.enterPin(p17Pin);
    }
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    await _unmount(tester);
  });

  testWidgets(
      'RC-6: credential storage unreadable while the challenge is shown — '
      'neutral view, shield and ticket kept, no access; storage recovery '
      'still needs the real PIN', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(800, 1600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    final InMemorySecretStore secrets = InMemorySecretStore();
    final AppContainer first =
        AppContainer.inMemory(database: db, secretStore: secrets);
    expect((await first.auth.enrollPin(p17Pin)).isSuccess, isTrue);
    // New process over the same disk; the Keystore is unavailable.
    final _ToggleSecrets toggle = _ToggleSecrets(secrets);
    final AppContainer c =
        AppContainer.inMemory(database: db, secretStore: toggle);
    final StaticNativeChallengeContract native =
        StaticNativeChallengeContract.bind(
      overlay: c.overlay as StaticOverlayLockService,
      watcher: c.watcher as StaticWatcherService,
    );
    // Native protection config persisted by the earlier process
    // (SharedPreferences); production does not reconfigure on restart.
    native.enabled = true;
    native.protectedPackages = <String>{p17Pkg};
    await c.protectedApps.add(ProtectedApp(
      packageName: p17Pkg,
      label: 'WhatsApp',
      addedAt: DateTime(2026, 10, 22),
    ));
    // The credential status is unreadable: the bootstrap fails without
    // touching the native configuration (unknown is never "disable").
    expect((await c.protectionBootstrap.synchronize()).isFailure, isTrue);
    expect(native.enabled, isTrue);
    expect(native.isProtected(p17Pkg), isTrue);
    await tester.pumpWidget(SmartAppLockApp(container: c));
    await tester.pumpAndSettle();
    final P17Device d = P17Device(tester, c, native);
    await d.openProtectedApp();
    final PendingLockChallenge ticket = native.pending!;
    // P13/M3 G7-H1 (owner-approved): an unreadable credential state presents
    // nothing and grants nothing; the native shield stays with the neutral
    // notice. Repeated foreground events and retry ticks keep it that way.
    for (int i = 0; i < 5; i++) {
      expect(find.byType(PinUnlockScreen), findsNothing, reason: '#$i');
      expect(native.shieldVisible, isTrue, reason: '#$i');
      expect(native.storageUnavailableNotice, isTrue, reason: '#$i');
      expect(native.pending, ticket, reason: '#$i');
      d.expectNoAccess();
      native.recoveryRetryTick();
      await d.openProtectedApp();
    }
    // Storage returns: the next requirement presents the real challenge.
    toggle.fail = false;
    await _foreground(d, _open);
    await d.openProtectedApp();
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    d.expectNoAccess();
    await d.enterPin('0000');
    d.expectNoAccess();
    await d.enterPin(p17Pin);
    expect(native.authorizedPackages, <String>{p17Pkg});
    await _unmount(tester);
    c.capabilityMonitor.dispose();
  });
}

class _ToggleSecrets implements SecretStore {
  _ToggleSecrets(this.inner);
  final InMemorySecretStore inner;
  bool fail = true;

  @override
  Future<String?> read(String key) async {
    if (fail && key == SecretKeys.settingsMasterKey) {
      throw StateError('keystore unavailable');
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) async {
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
