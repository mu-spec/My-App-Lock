import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/services/impl/static_accessibility_lock_service.dart';
import 'package:smart_app_lock/services/pending_lock_challenge.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';

import '../support/p17_latency_device.dart';

/// Phase 17 / M3 — stress: repeated protected launches, rapid switching,
/// repeated wrong PINs into a lockout, background/foreground churn and
/// duplicate foreground callbacks on the full challenge host.
///
/// SIMULATED (evidence B): fake clock + [StaticNativeChallengeContract].
/// Iteration counts are fixed and bounded. Not device evidence.
const String _open = 'com.example.notes'; // never protected

Future<void> _foreground(P17Device d, String pkg) async {
  d.native.reportForeground(pkg);
  (d.container.accessibility as StaticAccessibilityLockService)
      .emitForegroundPackage(pkg);
  await d.tester.pumpAndSettle();
}

/// Unmount; flutter_test fails the test if any Timer is still pending.
Future<void> _unmount(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 5));
}

void main() {
  testWidgets(
      'ST-1: 20 launch/PIN/leave cycles — a PIN is required on every launch, '
      'never more than one challenge, authorization ends at every leave',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    for (int i = 0; i < 20; i++) {
      await d.openProtectedApp();
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      d.expectNoAccess();
      await d.enterPin(p17Pin);
      expect(d.native.authorizedPackages, <String>{p17Pkg}, reason: '#$i');
      expect(d.native.pending, isNull, reason: '#$i');
      await _foreground(d, _open);
      expect(d.native.authorizedPackages, isEmpty,
          reason: '#$i zero-grace leave ends the native grant');
      expect(find.byType(PinUnlockScreen), findsNothing, reason: '#$i');
    }
    expect(d.native.authorizeRejections, 0);
    await _unmount(tester);
  });

  testWidgets(
      'ST-2: 100 rapid protected/unprotected switches without a PIN never '
      'grant access, never stack challenges, and keep one live ticket',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    for (int i = 0; i < 100; i++) {
      final String pkg = i.isEven ? p17Pkg : _open;
      d.native.reportForeground(pkg);
      (d.container.accessibility as StaticAccessibilityLockService)
          .emitForegroundPackage(pkg);
      // Mostly no settle between events: a burst like a fast app switcher.
      if (i % 10 == 9) {
        await tester.pumpAndSettle();
      } else {
        await tester.pump(const Duration(milliseconds: 16));
      }
      d.expectNoAccess();
      expect(
          find.byType(PinUnlockScreen).evaluate().length, lessThanOrEqualTo(1),
          reason: '#$i');
    }
    // End on the protected app: exactly one challenge for one ticket.
    await d.openProtectedApp();
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    expect(d.native.pending?.packageName, p17Pkg);
    d.expectNoAccess();
    await d.enterPin(p17Pin);
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    await _unmount(tester);
  });

  testWidgets(
      'ST-3: repeated wrong PINs reach the lockout; correct-PIN taps during '
      'the lockout never authorize; the countdown timer ends on unmount',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    await d.openProtectedApp();
    for (int i = 0; i < 3; i++) {
      await d.enterPin('0000');
      d.expectNoAccess();
    }
    expect(find.text(PinUnlockScreen.lockedOutTitle), findsOneWidget);
    // Hammer the (disabled) pad with the correct PIN.
    for (int i = 0; i < 10; i++) {
      for (final String digit in p17Pin.split('')) {
        final Finder key = find.byKey(Key('pin_key_$digit'));
        if (key.evaluate().isNotEmpty) {
          await tester.tap(key, warnIfMissed: false);
        }
      }
      await tester.pump(const Duration(milliseconds: 200));
      d.expectNoAccess();
      expect(d.native.pending?.packageName, p17Pkg);
    }
    expect(find.text(PinUnlockScreen.lockedOutTitle), findsOneWidget);
    await _unmount(tester);
  });

  testWidgets(
      'ST-4: 30 background/foreground cycles with a pending challenge keep '
      'the same ticket, one challenge, and no access',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    await d.openProtectedApp();
    final PendingLockChallenge ticket = d.native.pending!;
    for (int i = 0; i < 30; i++) {
      d.native.onActivityPaused();
      await d.lifecycle(AppLifecycleState.paused);
      await tester.pump(const Duration(milliseconds: 100));
      d.expectNoAccess();
      d.native.onActivityResumed();
      await d.lifecycle(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(d.native.pending, ticket, reason: '#$i');
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      d.expectNoAccess();
    }
    await d.enterPin(p17Pin);
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    await _unmount(tester);
  });

  testWidgets(
      'ST-5: 50 duplicate foreground callbacks for the same app never '
      'regenerate the ticket or stack challenges', (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    await d.openProtectedApp();
    final PendingLockChallenge ticket = d.native.pending!;
    for (int i = 0; i < 50; i++) {
      d.native.reportForeground(p17Pkg);
      (d.container.accessibility as StaticAccessibilityLockService)
          .emitForegroundPackage(p17Pkg);
      await tester.pump(const Duration(milliseconds: 16));
    }
    await tester.pumpAndSettle();
    expect(d.native.pending, ticket);
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    d.expectNoAccess();
    await d.enterPin(p17Pin);
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    // Duplicates after authorization do not create a new challenge.
    for (int i = 0; i < 20; i++) {
      d.native.reportForeground(p17Pkg);
      await tester.pump(const Duration(milliseconds: 16));
    }
    expect(d.native.pending, isNull);
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    await _unmount(tester);
  });

  testWidgets(
      'ST-6: 15 screen off/on cycles behind the keyguard after a PIN — every '
      'screen-off revokes, every wake needs a fresh PIN',
      (WidgetTester tester) async {
    final P17Device d = await p17Launch(tester);
    await d.openProtectedApp();
    await d.enterPin(p17Pin);
    expect(d.native.authorizedPackages, <String>{p17Pkg});
    for (int i = 0; i < 15; i++) {
      await d.screenOff();
      expect(d.native.authorizedPackages, isEmpty, reason: '#$i');
      expect(d.native.shieldVisible, isTrue, reason: '#$i');
      expect(d.native.pending?.packageName, p17Pkg, reason: '#$i');
      await d.screenOnBehindKeyguard();
      d.expectNoAccess();
      expect(d.native.shieldVisible, isTrue,
          reason: '#$i shield stays while the keyguard is up');
      d.native.dismissKeyguard();
      d.screen.emitUserPresent();
      await tester.pumpAndSettle();
      expect(find.byType(PinUnlockScreen), findsOneWidget, reason: '#$i');
      d.expectNoAccess();
      await d.enterPin(p17Pin);
      expect(d.native.authorizedPackages, <String>{p17Pkg}, reason: '#$i');
    }
    await _unmount(tester);
  });
}
