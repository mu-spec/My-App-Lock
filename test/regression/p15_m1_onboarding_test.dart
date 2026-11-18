// Phase 15 / Milestone 1 — Welcome & Authentication Setup.
//
// SIMULATED (host widget tests over the production app root, credential
// manager, setup/unlock screens and H-3 enablement; the biometric OS layer
// is a fake BiometricService). Not device QA.
//
// Asserts:
//  D  launch decision is credential-state based; the onboarding flag is
//     never a gate; an unreadable state never starts onboarding.
//  F  Welcome → PIN or pattern setup → optional biometric → main shell.
//  S  setup pop is never trusted (Phase 5I); no setup is offered over an
//     existing credential; biometric activation follows H-3 (strong
//     biometric only, primary credential verified, biometric-only options).
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/design_system/design_system.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/biometric_options.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/services/biometric_service.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_apps_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_decision.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_health_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_permissions_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_screen.dart';
import 'package:smart_app_lock/ui/screens/pattern/pattern_setup_screen.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_setup_screen.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/shell/main_shell.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '482916';
const List<int> _pattern = <int>[3, 6, 9, 8];

class _FakeBiometrics implements BiometricService {
  bool supported = true;
  Set<BiometricKind> kinds = <BiometricKind>{BiometricKind.strong};
  int prompts = 0;

  @override
  Future<Result<bool>> isSupported() async => Result.success(supported);

  @override
  Future<Result<Set<BiometricKind>>> availableKinds() async =>
      Result.success(Set<BiometricKind>.of(kinds));

  @override
  Future<Result<bool>> authenticate({
    required String reason,
    BiometricOptions? options,
  }) async {
    prompts++;
    return Result.success(false);
  }
}

class _FailingSecrets implements SecretStore {
  _FailingSecrets(this.inner);
  final InMemorySecretStore inner;
  @override
  Future<String?> read(String key) async {
    if (key == SecretKeys.settingsMasterKey) {
      throw StateError('keystore unavailable');
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) async =>
      throw StateError('keystore unavailable');
  @override
  Future<void> delete(String key) => inner.delete(key);
  @override
  Future<void> clear() => inner.clear();
  @override
  Future<bool> containsKey(String key) => inner.containsKey(key);
}

void main() {
  late _FakeBiometrics bio;

  setUp(() => bio = _FakeBiometrics());

  AppContainer newContainer() => AppContainer.inMemory(biometrics: bio);

  Future<CredentialState> state(AppContainer c) async =>
      (await c.auth.status()).valueOrNull!;

  Future<BiometricOptions?> storedOptions(AppContainer c) async =>
      (await c.securitySettings.getSettings()).valueOrNull!.biometricOptions;

  Future<void> pumpApp(WidgetTester tester, AppContainer c) async {
    tester.view.physicalSize = const Size(800, 1600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      SmartAppLockApp(
        container: c,
        startWithOnboarding: await tester.runAsync(
              () => shouldStartOnboarding(c.auth),
            ) ??
            false,
      ),
    );
    await tester.pumpAndSettle();
  }

  Future<void> tapText(WidgetTester tester, String text) async {
    await tester.ensureVisible(find.text(text));
    await tester.pumpAndSettle();
    await tester.tap(find.text(text));
    await tester.pumpAndSettle();
  }

  Future<void> tapDigits(WidgetTester tester, String digits) async {
    await tester.pump(const Duration(milliseconds: 250));
    for (final String d in digits.split('')) {
      await tester.tap(find.byKey(Key('pin_key_$d')));
      await tester.pump(const Duration(milliseconds: 50));
    }
    await tester.pumpAndSettle();
  }

  Future<void> drawPattern(WidgetTester tester, List<int> nodes) async {
    await tester.pump(const Duration(milliseconds: 450));
    final Rect bounds = tester.getRect(find.byType(DsPatternGrid));
    final double pad = bounds.width * 0.10;
    final double step = (bounds.width - 2 * pad) / 2;
    Offset center(int node) {
      final int i = node - 1;
      return Offset(
        bounds.left + pad + (i % 3) * step,
        bounds.top + pad + (i ~/ 3) * step,
      );
    }

    final TestGesture gesture = await tester.startGesture(center(nodes.first));
    await tester.pump();
    await gesture.moveBy(const Offset(20, 0));
    await tester.pump();
    Offset current = center(nodes.first).translate(20, 0);
    for (final int node in nodes.skip(1)) {
      final Offset target = center(node);
      const int steps = 6;
      for (int s = 1; s <= steps; s++) {
        await gesture.moveTo(Offset(
          current.dx + (target.dx - current.dx) * s / steps,
          current.dy + (target.dy - current.dy) * s / steps,
        ));
        await tester.pump();
      }
      current = target;
    }
    await gesture.up();
    await tester.pumpAndSettle();
  }

  /// Welcome → Get started → PIN setup (6 digits, entered twice) → Done.
  Future<void> setUpPinThroughOnboarding(WidgetTester tester) async {
    await tapText(tester, OnboardingScreen.getStartedLabel);
    await tapText(tester, OnboardingScreen.pinOptionTitle);
    expect(find.byType(PinSetupScreen), findsOneWidget);
    await tapText(tester, '6-digit PIN');
    await tapDigits(tester, _pin);
    await tapDigits(tester, _pin);
    expect(find.text(PinSetupScreen.successTitle), findsOneWidget);
    await tapText(tester, 'Done');
  }

  Finder onboarding() => find.byType(OnboardingScreen);
  Finder shell() => find.byType(MainShell);

  /// Phase 15 / M2–M3 continue after the biometric step: skip permissions
  /// (none granted in these containers) and the suggested apps (none
  /// installed), then leave the health check; ends at the shell.
  Future<void> skipM2Steps(WidgetTester tester) async {
    expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
    await tapText(tester, OnboardingPermissionsStep.skipLabel);
    expect(find.text(OnboardingAppsStep.title), findsOneWidget);
    await tapText(tester, OnboardingAppsStep.continueLabel);
    // Phase 15 / M3: no protected app, so the first health check reports
    // incomplete setup; finishing anyway reaches the shell.
    expect(find.text(OnboardingHealthStep.incompleteTitle), findsOneWidget);
    expect(find.text(OnboardingHealthStep.activeTitle), findsNothing);
    await tapText(tester, OnboardingHealthStep.finishAnywayLabel);
  }

  // -------------------------------------------------------------------------
  // D: launch decision
  // -------------------------------------------------------------------------
  group('D launch decision (credential state only)', () {
    test('D1 fresh install (no credential) starts onboarding', () async {
      expect(await shouldStartOnboarding(newContainer().auth), isTrue);
    });

    test('D2 an existing PIN or pattern never starts onboarding', () async {
      final AppContainer p = newContainer();
      expect((await p.auth.enrollPin(_pin)).isSuccess, isTrue);
      expect(await shouldStartOnboarding(p.auth), isFalse);
      final AppContainer q = newContainer();
      expect((await q.auth.enrollPattern(_pattern)).isSuccess, isTrue);
      expect(await shouldStartOnboarding(q.auth), isFalse);
    });

    test('D3 the onboarding flag is not a gate in either direction', () async {
      // Flag set but no credential: still onboarding (flag cannot skip it).
      final AppContainer a = newContainer();
      await a.preferences.setOnboardingCompleted(true);
      expect(await shouldStartOnboarding(a.auth), isTrue);
      // Credential present but flag unset (e.g. pattern-only upgrade):
      // never onboarding, so it can never be used to re-enroll.
      final AppContainer b = newContainer();
      expect((await b.auth.enrollPattern(_pattern)).isSuccess, isTrue);
      expect(await b.preferences.isOnboardingCompleted(), isFalse);
      expect(await shouldStartOnboarding(b.auth), isFalse);
    });

    test(
        'D4 an unreadable credential state never starts onboarding '
        '(even with no credential stored)', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final InMemorySecretStore secrets = InMemorySecretStore();
      final AppContainer writer =
          AppContainer.inMemory(database: db, secretStore: secrets);
      // Persist an encrypted settings document WITHOUT any credential.
      final SecuritySettings current =
          (await writer.securitySettings.getSettings()).valueOrNull!;
      expect(
        (await writer.securitySettings.saveSettings(current)).isSuccess,
        isTrue,
      );
      expect(
          (await writer.auth.status()).valueOrNull!.hasAnyCredential, isFalse);
      final AppContainer reader = AppContainer.inMemory(
          database: db, secretStore: _FailingSecrets(secrets));
      expect((await reader.auth.status()).isFailure, isTrue);
      expect(await shouldStartOnboarding(reader.auth), isFalse);
    });
  });

  // -------------------------------------------------------------------------
  // F: flow
  // -------------------------------------------------------------------------
  group('F onboarding flow', () {
    testWidgets('F1 fresh install opens Welcome, not the shell',
        (WidgetTester tester) async {
      await pumpApp(tester, newContainer());
      expect(onboarding(), findsOneWidget);
      expect(find.text(OnboardingScreen.welcomeTitle), findsOneWidget);
      expect(shell(), findsNothing);
    });

    testWidgets('F2 existing credential opens the shell, never onboarding',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await tester.runAsync(() => c.auth.enrollPin(_pin));
      await pumpApp(tester, c);
      expect(shell(), findsOneWidget);
      expect(onboarding(), findsNothing);
    });

    testWidgets(
        'F3 PIN setup → biometric enabled after verifying the new PIN '
        '→ shell; biometric-only options; flag recorded',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await setUpPinThroughOnboarding(tester);

      expect(find.text(OnboardingScreen.biometricTitle), findsOneWidget);
      final CredentialState s = (await tester.runAsync(() => state(c)))!;
      expect(s.primary, AuthType.pin);
      expect(s.hasEnrolled(AuthType.biometric), isFalse);

      await tapText(tester, OnboardingScreen.enableBiometricLabel);
      // H-3 F4: the just-created primary credential must be verified.
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      expect(await tester.runAsync<BiometricOptions?>(() => storedOptions(c)),
          isNull);
      await tapDigits(tester, _pin);

      final BiometricOptions? saved =
          await tester.runAsync<BiometricOptions?>(() => storedOptions(c));
      expect(saved, isNotNull);
      expect(saved!.allowStrongBiometrics, isTrue);
      expect(saved.allowDeviceCredential, isFalse);
      expect(saved.requireConfirmation, isTrue);
      expect(bio.prompts, 0, reason: 'enabling never needs a bio prompt');

      await skipM2Steps(tester);
      expect(shell(), findsOneWidget);
      expect(onboarding(), findsNothing);
      expect(
        await tester.runAsync(() => c.preferences.isOnboardingCompleted()),
        isTrue,
      );
      // Onboarding is gone from the stack: nothing to go back to.
      final NavigatorState nav = tester.state(find.byType(Navigator).first);
      expect(nav.canPop(), isFalse);
    });

    testWidgets('F4 pattern setup → "Not now" → shell, biometric not enabled',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await tapText(tester, OnboardingScreen.getStartedLabel);
      await tapText(tester, OnboardingScreen.patternOptionTitle);
      expect(find.byType(PatternSetupScreen), findsOneWidget);
      await drawPattern(tester, _pattern);
      await drawPattern(tester, _pattern);
      expect(find.text(PatternSetupScreen.successTitle), findsOneWidget);
      await tapText(tester, 'Done');

      expect(find.text(OnboardingScreen.biometricTitle), findsOneWidget);
      // System back cannot leave the biometric step (credential exists).
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.text(OnboardingScreen.biometricTitle), findsOneWidget);

      await tapText(tester, OnboardingScreen.notNowLabel);
      await skipM2Steps(tester);
      expect(shell(), findsOneWidget);
      final CredentialState s = (await tester.runAsync(() => state(c)))!;
      expect(s.primary, AuthType.pattern);
      expect(await tester.runAsync<BiometricOptions?>(() => storedOptions(c)),
          isNull);
    });

    testWidgets('F5 Back from the authentication step returns to Welcome',
        (WidgetTester tester) async {
      await pumpApp(tester, newContainer());
      await tapText(tester, OnboardingScreen.getStartedLabel);
      expect(find.text(OnboardingScreen.authTitle), findsOneWidget);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.text(OnboardingScreen.welcomeTitle), findsOneWidget);
      expect(onboarding(), findsOneWidget);
    });
  });

  // -------------------------------------------------------------------------
  // S: security properties
  // -------------------------------------------------------------------------
  group('S security properties', () {
    testWidgets(
        'S1 leaving setup without enrolling never advances (setup pop is '
        'not trusted; state is re-read)', (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await tapText(tester, OnboardingScreen.getStartedLabel);
      await tapText(tester, OnboardingScreen.pinOptionTitle);
      await tapText(tester, '6-digit PIN');
      await tapDigits(tester, _pin); // entered once, never confirmed
      final NavigatorState nav = tester.state(find.byType(Navigator).first);
      nav.pop(true); // even a `true` result must not count
      await tester.pumpAndSettle();

      expect(find.text(OnboardingScreen.authTitle), findsOneWidget);
      expect(find.text(OnboardingScreen.authNotSetMessage), findsOneWidget);
      expect(find.text(OnboardingScreen.biometricTitle), findsNothing);
      expect(shell(), findsNothing);
      final CredentialState s = (await tester.runAsync(() => state(c)))!;
      expect(s.hasAnyCredential, isFalse);
      expect(
        await tester.runAsync(() => c.preferences.isOnboardingCompleted()),
        isFalse,
      );
    });

    testWidgets(
        'S2 a credential created meanwhile is never re-enrolled: '
        'setup is not offered, onboarding skips to the biometric step',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await tester.runAsync(() => c.auth.enrollPattern(_pattern));
      await tapText(tester, OnboardingScreen.getStartedLabel);
      expect(find.byType(PinSetupScreen), findsNothing);
      expect(find.byType(PatternSetupScreen), findsNothing);
      expect(find.text(OnboardingScreen.biometricTitle), findsOneWidget);
      final CredentialState s = (await tester.runAsync(() => state(c)))!;
      expect(s.primary, AuthType.pattern);
    });

    testWidgets(
        'S3 device credential only (no enrolled biometric): enabling is '
        'not offered', (WidgetTester tester) async {
      bio.kinds = <BiometricKind>{BiometricKind.deviceCredential};
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await setUpPinThroughOnboarding(tester);
      expect(
          find.text(OnboardingScreen.biometricNotEnrolledText), findsOneWidget);
      expect(find.text(OnboardingScreen.enableBiometricLabel), findsNothing);
      await tapText(tester, OnboardingScreen.continueLabel);
      await skipM2Steps(tester);
      expect(shell(), findsOneWidget);
      expect(await tester.runAsync<BiometricOptions?>(() => storedOptions(c)),
          isNull);
    });

    testWidgets('S4 no biometric hardware: enabling is not offered',
        (WidgetTester tester) async {
      bio.supported = false;
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await setUpPinThroughOnboarding(tester);
      expect(
          find.text(OnboardingScreen.biometricUnavailableText), findsOneWidget);
      expect(find.text(OnboardingScreen.enableBiometricLabel), findsNothing);
      await tapText(tester, OnboardingScreen.continueLabel);
      await skipM2Steps(tester);
      expect(shell(), findsOneWidget);
      expect(await tester.runAsync<BiometricOptions?>(() => storedOptions(c)),
          isNull);
    });

    testWidgets(
        'S5 cancelling primary verification does not enable biometrics and '
        'stays on the biometric step', (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await setUpPinThroughOnboarding(tester);
      await tapText(tester, OnboardingScreen.enableBiometricLabel);
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();

      expect(find.byType(PinUnlockScreen), findsNothing);
      expect(find.text(OnboardingScreen.biometricNotEnabledMessage),
          findsOneWidget);
      expect(find.text(OnboardingScreen.biometricTitle), findsOneWidget);
      expect(await tester.runAsync<BiometricOptions?>(() => storedOptions(c)),
          isNull);
      expect(shell(), findsNothing);
    });

    testWidgets('S6 a wrong PIN at verification does not enable biometrics',
        (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await pumpApp(tester, c);
      await setUpPinThroughOnboarding(tester);
      await tapText(tester, OnboardingScreen.enableBiometricLabel);
      await tapDigits(tester, '000000');
      expect(await tester.runAsync<BiometricOptions?>(() => storedOptions(c)),
          isNull);
      final CredentialState s = (await tester.runAsync(() => state(c)))!;
      expect(s.failedAttempts, greaterThan(0));
      expect(s.hasEnrolled(AuthType.biometric), isFalse);
    });
  });
}
