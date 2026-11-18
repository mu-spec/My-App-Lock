// Phase 15 / Milestone 3 — Initial Health Check & Setup Complete.
//
// SIMULATED (host tests over the production onboarding, the Phase 7
// Protection Health engine/monitor/controller and the in-memory container's
// static platform services; the biometric OS layer is a fake). No Android
// device, Settings screen or OEM behaviour is observed. Not device QA.
//
//  C  classification: "Protection Active" only for a fresh SECURE report;
//     confirmed missing setup → "Setup Incomplete"; no/failed/stale/unknown
//     → "Unable to Verify". Exhaustive signal sweep: unknown is never active.
//  W  completion screen: one of three distinct states from the shared
//     monitor; bridge failure, slow/timed-out probe, stale report and a
//     missing monitor never show "You're Protected"; retry; no gate.
//  E  end-to-end: fresh install, interruption at every step resumes
//     correctly, existing users are never forced through onboarding,
//     unreadable credential storage stays fail-closed.
import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/theme/app_theme.dart';
import 'package:smart_app_lock/data/models/app_entry.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_key_value_store.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/design_system/design_system.dart';
import 'package:smart_app_lock/protection/health/protection_health_engine.dart';
import 'package:smart_app_lock/protection/health/protection_health_monitor.dart';
import 'package:smart_app_lock/security/credentials/biometric_options.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/services/biometric_service.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_apps_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_decision.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_health_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_permissions_step.dart';
import 'package:smart_app_lock/ui/screens/onboarding/onboarding_screen.dart';
import 'package:smart_app_lock/ui/shell/main_shell.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '482916';
const AppEntry _whatsapp =
    AppEntry(packageName: 'com.whatsapp', label: 'WhatsApp');

class _NoBiometrics implements BiometricService {
  @override
  Future<Result<bool>> isSupported() async => Result.success(false);
  @override
  Future<Result<Set<BiometricKind>>> availableKinds() async =>
      Result.success(<BiometricKind>{});
  @override
  Future<Result<bool>> authenticate({
    required String reason,
    BiometricOptions? options,
  }) async =>
      Result.success(false);
}

/// Secret store whose settings key is unreadable (Keystore unavailable).
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

// ---------------------------------------------------------------------------
// Pure signal builder (C group). Keys absent → a healthy value.
// `protectionConfigured` is derived from the credential / protected-app
// reads with ProtectionHealthMonitor's rule (it is never true unless both
// reads succeeded and are true) unless given explicitly.
// ---------------------------------------------------------------------------
final DateTime _t0 = DateTime(2026, 10, 22, 12);

bool? _monitorConfigured(bool? credential, bool? apps) {
  if (credential != null && apps != null) return credential && apps;
  if (credential == false || apps == false) return false;
  return null;
}

HealthSignals _signals([Map<String, Object?> o = const <String, Object?>{}]) {
  T v<T>(String k, T healthy) => o.containsKey(k) ? o[k] as T : healthy;
  final bool? credential = v<bool?>('credentialConfigured', true);
  final bool? apps = v<bool?>('hasProtectedApps', true);
  return HealthSignals(
    observedAt: _t0,
    protectionConfigured: o.containsKey('protectionConfigured')
        ? o['protectionConfigured'] as bool?
        : _monitorConfigured(credential, apps),
    credentialConfigured: credential,
    hasProtectedApps: apps,
    nativeProtectionEnabled: v<bool?>('nativeProtectionEnabled', true),
    overlayGranted: v<bool?>('overlayGranted', true),
    overlayEverGranted: true,
    accessibilityEnabled: v<bool?>('accessibilityEnabled', true),
    accessibilityEverGranted: true,
    usageAccessGranted: v<bool?>('usageAccessGranted', true),
    usageAccessEverGranted: true,
    nativeHealthAvailable: v<bool>('nativeHealthAvailable', true),
    accessibilityConnected: v<bool?>('accessibilityConnected', true),
    watcherRunning: v<bool?>('watcherRunning', true),
    shieldArmed: v<bool?>('shieldArmed', true),
    notificationsGranted: true,
    backgroundRestricted: v<bool?>('backgroundRestricted', false),
    sdkInt: 34,
    powerSaveMode: false,
    ignoringBatteryOptimizations: false,
  );
}

ProtectionHealthReport _eval(
  Map<String, Object?> o, {
  Duration age = Duration.zero,
}) =>
    ProtectionHealthEngine.evaluate(_signals(o), now: _t0.add(age));

void main() {
  // -------------------------------------------------------------------------
  // Shared widget fixtures
  // -------------------------------------------------------------------------
  AppContainer newContainer({
    List<AppEntry> apps = const <AppEntry>[],
    bool granted = false,
    InMemoryLocalDatabase? db,
    InMemorySecretStore? secrets,
    InMemoryKeyValueStore? kv,
  }) =>
      AppContainer.inMemory(
        biometrics: _NoBiometrics(),
        apps: apps,
        accessibilityEnabled: granted,
        overlayGranted: granted,
        usageAccessGranted: granted,
        database: db,
        secretStore: secrets,
        keyValueStore: kv,
      );

  StaticWatcherService watcherOf(AppContainer c) =>
      c.watcher as StaticWatcherService;

  /// Native engine running and fully observed (what Android would report
  /// on a working device). Protection configuration itself is left to the
  /// app unless [configured] is given.
  void nativeHealthy(AppContainer c, {bool? configured}) {
    final StaticWatcherService w = watcherOf(c);
    if (configured != null) w.protectionConfigured = configured;
    w
      ..running = true
      ..accessibilityServiceConnected = true
      ..shieldArmed = true
      ..challengePending = false
      ..backgroundRestricted = false
      ..powerSaveMode = false
      ..ignoringBatteryOptimizations = false
      ..sdkInt = 34;
  }

  /// A configured, healthy device: PIN + one protected app + every
  /// permission granted + native engine healthy.
  Future<AppContainer> healthyContainer() async {
    final AppContainer c = newContainer(granted: true);
    await c.auth.enrollPin(_pin);
    await c.protectedApps.add(
      ProtectedApp(
        packageName: _whatsapp.packageName,
        label: _whatsapp.label,
        addedAt: DateTime(2026, 10, 1),
      ),
    );
    nativeHealthy(c, configured: true);
    return c;
  }

  ProtectionHealthMonitor clockedMonitor(
    AppContainer c,
    DateTime Function() now,
  ) =>
      ProtectionHealthMonitor(
        protectedApps: c.protectedApps,
        credentials: c.auth,
        installedApps: c.installedAppsService,
        accessibility: c.accessibility,
        overlay: c.overlay,
        watcher: c.watcher,
        preferences: c.preferences,
        biometrics: c.biometrics,
        now: now,
      );

  void tallView(WidgetTester tester) {
    tester.view.physicalSize = const Size(800, 1800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
  }

  int finished = 0;
  int reviewed = 0;

  /// Pumps the completion step alone. Does not settle (the checking state
  /// animates); callers pump as needed.
  Future<void> pumpStep(
    WidgetTester tester,
    AppContainer? c, {
    ProtectionHealthMonitor? monitor,
  }) async {
    tallView(tester);
    finished = 0;
    reviewed = 0;
    final Widget app = MaterialApp(
      theme: AppTheme.light,
      home: Scaffold(
        body: OnboardingHealthStep(
          onFinish: () => finished++,
          onReviewSetup: () => reviewed++,
          debugMonitor: monitor,
        ),
      ),
    );
    await tester.pumpWidget(
      c == null ? app : AppScope(container: c, child: app),
    );
  }

  Finder title(String t) => find.byWidgetPredicate((Widget w) =>
      w is Text &&
      w.key == const Key('onboarding_health_title') &&
      w.data == t);

  void expectOutcome(OnboardingCompletion outcome) {
    expect(find.byKey(ValueKey<String>('onboarding_health_${outcome.name}')),
        findsOneWidget);
    for (final OnboardingCompletion other in OnboardingCompletion.values) {
      if (other == outcome) continue;
      expect(find.byKey(ValueKey<String>('onboarding_health_${other.name}')),
          findsNothing);
    }
    if (outcome != OnboardingCompletion.protectionActive) {
      expect(find.text(OnboardingHealthStep.activeTitle), findsNothing);
      expect(find.text(OnboardingHealthStep.activeLabel), findsNothing);
    }
  }

  Future<void> tapFinder(WidgetTester tester, Finder f) async {
    await tester.ensureVisible(f);
    await tester.pumpAndSettle();
    await tester.tap(f);
    await tester.pumpAndSettle();
  }

  Future<void> tapText(WidgetTester tester, String text) =>
      tapFinder(tester, find.text(text));

  Future<void> tapDigits(WidgetTester tester, String digits) async {
    await tester.pump(const Duration(milliseconds: 250));
    for (final String d in digits.split('')) {
      await tester.tap(find.byKey(Key('pin_key_$d')));
      await tester.pump(const Duration(milliseconds: 50));
    }
    await tester.pumpAndSettle();
  }

  Future<void> pumpApp(WidgetTester tester, AppContainer c) async {
    tallView(tester);
    final bool start =
        await tester.runAsync(() => shouldStartOnboarding(c.auth)) ?? false;
    await tester.pumpWidget(
      SmartAppLockApp(container: c, startWithOnboarding: start),
    );
    await tester.pumpAndSettle();
  }

  Finder shell() => find.byType(MainShell);

  // -------------------------------------------------------------------------
  // C: classification
  // -------------------------------------------------------------------------
  group('C classification', () {
    test('C1 a fresh SECURE report is Protection Active', () {
      final ProtectionHealthReport r = _eval(const <String, Object?>{});
      expect(r.state, ProtectionHealthState.secure, reason: '${r.issues}');
      expect(r.stale, isFalse);
      expect(classifyOnboardingCompletion(r),
          OnboardingCompletion.protectionActive);
    });

    test('C2 no report or a failed check is Unable to Verify, never active',
        () {
      expect(classifyOnboardingCompletion(null),
          OnboardingCompletion.unableToVerify);
      final ProtectionHealthReport secure = _eval(const <String, Object?>{});
      expect(classifyOnboardingCompletion(secure, failed: true),
          OnboardingCompletion.unableToVerify);
      expect(classifyOnboardingCompletion(null, failed: true),
          OnboardingCompletion.unableToVerify);
    });

    test('C3 a stale or future-dated snapshot is Unable to Verify', () {
      final ProtectionHealthReport old =
          _eval(const <String, Object?>{}, age: const Duration(seconds: 31));
      expect(old.stale, isTrue);
      expect(old.state, isNot(ProtectionHealthState.secure));
      expect(classifyOnboardingCompletion(old),
          OnboardingCompletion.unableToVerify);
      final ProtectionHealthReport future =
          _eval(const <String, Object?>{}, age: const Duration(seconds: -5));
      expect(classifyOnboardingCompletion(future),
          OnboardingCompletion.unableToVerify);
    });

    test('C4 unknown native health (bridge failure) is Unable to Verify', () {
      final ProtectionHealthReport r = _eval(const <String, Object?>{
        'nativeHealthAvailable': false,
        'watcherRunning': null,
        'shieldArmed': null,
        'accessibilityConnected': null,
        'nativeProtectionEnabled': null,
        'backgroundRestricted': null,
      });
      expect(r.state, isNot(ProtectionHealthState.secure));
      expect(
          classifyOnboardingCompletion(r), OnboardingCompletion.unableToVerify);
    });

    test('C5 every single unknown core signal blocks Protection Active', () {
      for (final String k in <String>[
        'protectionConfigured',
        'credentialConfigured',
        'hasProtectedApps',
        'nativeProtectionEnabled',
        'overlayGranted',
        'accessibilityEnabled',
        'accessibilityConnected',
        'watcherRunning',
        'shieldArmed',
      ]) {
        final ProtectionHealthReport r = _eval(<String, Object?>{k: null});
        expect(classifyOnboardingCompletion(r),
            isNot(OnboardingCompletion.protectionActive),
            reason: '$k unknown');
      }
    });

    test('C6 confirmed missing setup is Setup Incomplete', () {
      for (final Map<String, Object?> o in <Map<String, Object?>>[
        <String, Object?>{'overlayGranted': false},
        <String, Object?>{'accessibilityEnabled': false},
        <String, Object?>{
          'hasProtectedApps': false,
          'protectionConfigured': false,
        },
      ]) {
        final ProtectionHealthReport r = _eval(o);
        expect(classifyOnboardingCompletion(r),
            OnboardingCompletion.setupIncomplete,
            reason: '$o → ${r.issues}');
      }
    });

    test(
        'C7 confirmed missing setup is reported even when other signals '
        'are unknown (never active)', () {
      final ProtectionHealthReport r = _eval(const <String, Object?>{
        'overlayGranted': false,
        'nativeHealthAvailable': false,
        'watcherRunning': null,
      });
      expect(classifyOnboardingCompletion(r),
          OnboardingCompletion.setupIncomplete);
    });

    test('C8 a stopped engine with setup otherwise complete cannot be verified',
        () {
      final ProtectionHealthReport r =
          _eval(const <String, Object?>{'watcherRunning': false});
      expect(r.state, isNot(ProtectionHealthState.secure));
      expect(
          classifyOnboardingCompletion(r), OnboardingCompletion.unableToVerify);
    });

    test(
        'C10 a revoked permission and a background restriction are '
        'Setup Incomplete (both need a user action)', () {
      final ProtectionHealthReport revoked =
          _eval(const <String, Object?>{'overlayGranted': false});
      expect(
        revoked.issues.map((HealthIssue i) => i.category),
        contains(HealthIssueCategory.revoked),
      );
      expect(classifyOnboardingCompletion(revoked),
          OnboardingCompletion.setupIncomplete);
      final ProtectionHealthReport restricted =
          _eval(const <String, Object?>{'backgroundRestricted': true});
      expect(
        restricted.issues.map((HealthIssue i) => i.category).toSet(),
        <HealthIssueCategory>{HealthIssueCategory.restricted},
      );
      expect(classifyOnboardingCompletion(restricted),
          OnboardingCompletion.setupIncomplete);
    });

    test(
        'C9 exhaustive sweep: Protection Active ⇔ fresh SECURE, and any '
        'unknown core signal is never active', () {
      const List<String> keys = <String>[
        'credentialConfigured',
        'hasProtectedApps',
        'overlayGranted',
        'accessibilityEnabled',
        'accessibilityConnected',
        'watcherRunning',
        'shieldArmed',
        'backgroundRestricted',
      ];
      const List<bool?> values = <bool?>[true, false, null];
      int active = 0;
      int checked = 0;
      void sweep(int i, Map<String, Object?> o) {
        if (i == keys.length) {
          for (final bool native in <bool>[true, false]) {
            for (final Duration age in <Duration>[
              Duration.zero,
              const Duration(seconds: 31),
            ]) {
              final Map<String, Object?> m = <String, Object?>{
                ...o,
                'nativeHealthAvailable': native,
              };
              final ProtectionHealthReport r = _eval(m, age: age);
              final OnboardingCompletion c = classifyOnboardingCompletion(r);
              checked++;
              final bool expectActive =
                  r.state == ProtectionHealthState.secure && !r.stale;
              expect(c == OnboardingCompletion.protectionActive, expectActive,
                  reason: '$m age=$age');
              final bool anyUnknown = !native ||
                  age > Duration.zero ||
                  m.entries.any((MapEntry<String, Object?> e) =>
                      e.key != 'backgroundRestricted' && e.value == null);
              if (anyUnknown) {
                expect(c, isNot(OnboardingCompletion.protectionActive),
                    reason: '$m age=$age');
              }
              if (c == OnboardingCompletion.protectionActive) active++;
            }
          }
          return;
        }
        for (final bool? v in values) {
          sweep(i + 1, <String, Object?>{...o, keys[i]: v});
        }
      }

      sweep(0, const <String, Object?>{});
      expect(checked, 26244);
      expect(active, greaterThan(0), reason: 'the healthy case is reachable');
    });
  });

  // -------------------------------------------------------------------------
  // W: completion screen
  // -------------------------------------------------------------------------
  group('W completion screen', () {
    testWidgets(
        'W1 healthy device: "You\'re Protected" / Protection Active; '
        'finish leaves', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      await pumpStep(tester, c);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.protectionActive);
      expect(title(OnboardingHealthStep.activeTitle), findsOneWidget);
      expect(find.text(OnboardingHealthStep.activeLabel), findsOneWidget);
      expect(find.text(OnboardingHealthStep.checkAgainLabel), findsNothing);
      await tapText(tester, OnboardingHealthStep.finishLabel);
      expect(finished, 1);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W2 no protected app: Setup Incomplete with the issue and a way '
        'back to setup', (WidgetTester tester) async {
      final AppContainer c = newContainer(granted: true);
      await tester.runAsync(() => c.auth.enrollPin(_pin));
      nativeHealthy(c, configured: false);
      await pumpStep(tester, c);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.setupIncomplete);
      expect(title(OnboardingHealthStep.incompleteTitle), findsOneWidget);
      expect(
        find.byWidgetPredicate((Widget w) =>
            w.key is ValueKey<String> &&
            (w.key! as ValueKey<String>)
                .value
                .startsWith('onboarding_health_issue_')),
        findsWidgets,
      );
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(reviewed, 1);
      await tapText(tester, OnboardingHealthStep.finishAnywayLabel);
      expect(finished, 1, reason: 'the outcome never gates leaving');
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W3 overlay permission confirmed not granted: Setup Incomplete, '
        'never active', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      (c.overlay as StaticOverlayLockService).overlayGranted = false;
      await pumpStep(tester, c);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.setupIncomplete);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W4 health bridge failure: Unable to Verify (no raw error); '
        '"Check again" re-probes and can then confirm',
        (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      watcherOf(c).getHealthError = StateError('bridge down');
      await pumpStep(tester, c);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.unableToVerify);
      expect(title(OnboardingHealthStep.unableTitle), findsOneWidget);
      expect(find.textContaining('bridge down'), findsNothing);

      final int calls = watcherOf(c).getHealthCalls;
      watcherOf(c).getHealthError = null;
      await tapText(tester, OnboardingHealthStep.checkAgainLabel);
      expect(watcherOf(c).getHealthCalls, greaterThan(calls));
      expectOutcome(OnboardingCompletion.protectionActive);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W5 slow health channel: neutral checking state, never active; a '
        'timed-out probe is Unable to Verify', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      watcherOf(c).getHealthGate = Completer<void>();
      await pumpStep(tester, c);
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 500));
      expect(find.byKey(const ValueKey<String>('onboarding_health_checking')),
          findsOneWidget);
      expect(find.text(OnboardingHealthStep.activeTitle), findsNothing);
      expect(find.text(OnboardingHealthStep.finishLabel), findsNothing);

      // Past the monitor's probe timeout (3 s): UNKNOWN, not SECURE.
      await tester.pump(const Duration(seconds: 4));
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.unableToVerify);
      watcherOf(c).getHealthGate!.complete();
      watcherOf(c).getHealthGate = null;
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W6 a confirmed SECURE result turns into Unable to Verify once it '
        'is stale', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      final DateTime start = DateTime.now();
      DateTime clock = start;
      await pumpStep(tester, c, monitor: clockedMonitor(c, () => clock));
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.protectionActive);

      clock = start.add(const Duration(seconds: 31));
      await tester.pump(const Duration(seconds: 31));
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.unableToVerify);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W7 no health monitor at all: Unable to Verify, retry disabled, '
        'finish still available', (WidgetTester tester) async {
      await pumpStep(tester, null);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.unableToVerify);
      final DsButton retry = tester.widget<DsButton>(
          find.widgetWithText(DsButton, OnboardingHealthStep.checkAgainLabel));
      expect(retry.onPressed, isNull);
      await tapText(tester, OnboardingHealthStep.finishAnywayLabel);
      expect(finished, 1);
    });

    testWidgets(
        'W8 an earlier SECURE observation is not reused: the step shows '
        'checking until its own probe returns', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      await tester.runAsync(() => c.protectionHealth.refresh());
      expect(c.protectionHealth.latest()?.state, ProtectionHealthState.secure);
      watcherOf(c).getHealthGate = Completer<void>();
      await pumpStep(tester, c);
      // The very first frame, before this step's probe has started.
      expect(find.text(OnboardingHealthStep.activeTitle), findsNothing);
      expect(find.byKey(const ValueKey<String>('onboarding_health_checking')),
          findsOneWidget);
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 200));
      expect(find.text(OnboardingHealthStep.activeTitle), findsNothing);
      expect(find.byKey(const ValueKey<String>('onboarding_health_checking')),
          findsOneWidget);
      watcherOf(c).getHealthGate!.complete();
      watcherOf(c).getHealthGate = null;
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.protectionActive);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W9 a stopped protection engine is not shown as active or as '
        'missing setup', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      watcherOf(c).running = false;
      await pumpStep(tester, c);
      await tester.pumpAndSettle();
      expect(find.text(OnboardingHealthStep.activeTitle), findsNothing);
      expect(find.text(OnboardingHealthStep.activeLabel), findsNothing);
      expectOutcome(OnboardingCompletion.unableToVerify);
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W11 returning to the app (e.g. from Android Settings) re-checks '
        'with a fresh probe', (WidgetTester tester) async {
      final AppContainer c = newContainer(granted: true);
      await tester.runAsync(() => c.auth.enrollPin(_pin));
      nativeHealthy(c, configured: false);
      await pumpStep(tester, c);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.setupIncomplete);
      final int calls = watcherOf(c).getHealthCalls;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      await tester.pump();
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(watcherOf(c).getHealthCalls, greaterThan(calls));
      await tester.pumpWidget(const SizedBox());
    });

    testWidgets(
        'W12 (supplementary, after the sealed run) a probe already running '
        'from before a change is not reused: a permission revoked meanwhile '
        'is never shown as Protection Active', (WidgetTester tester) async {
      final AppContainer c = (await tester.runAsync(healthyContainer))!;
      final StaticWatcherService w = watcherOf(c);
      // A collection started while everything was still granted…
      w.getHealthGate = Completer<void>();
      final int before = w.getHealthCalls;
      unawaited(c.protectionHealth.refresh());
      await tester.pump();
      expect(w.getHealthCalls, before + 1, reason: 'earlier probe in flight');
      // …then the overlay permission is revoked before the step opens.
      (c.overlay as StaticOverlayLockService).overlayGranted = false;
      await pumpStep(tester, c);
      await tester.pump();
      w.getHealthGate!.complete();
      w.getHealthGate = null;
      await tester.pumpAndSettle();
      expect(w.getHealthCalls, before + 2,
          reason: 'the step waits for a collection started after it opened');
      expectOutcome(OnboardingCompletion.setupIncomplete);
      await tester.pumpWidget(const SizedBox());
    });

    test('W10 the step never grants, starts or arms anything', () {
      final String src = File(
        'lib/ui/screens/onboarding/onboarding_health_step.dart',
      ).readAsStringSync();
      for (final String banned in <String>[
        'requestPermission',
        'openProtectionSettings',
        '.start(',
        '.configure(',
        'setProtection',
        'protectedApps.add',
        'enrollPin',
        'enrollPattern',
      ]) {
        expect(src.contains(banned), isFalse, reason: banned);
      }
    });
  });

  // -------------------------------------------------------------------------
  // E: end-to-end
  // -------------------------------------------------------------------------
  group('E end-to-end and recovery', () {
    /// Welcome → PIN → (no biometric hardware) Continue → permissions.
    Future<void> throughM1(WidgetTester tester) async {
      await tapText(tester, OnboardingScreen.getStartedLabel);
      await tapText(tester, OnboardingScreen.pinOptionTitle);
      await tapText(tester, '6-digit PIN');
      await tapDigits(tester, _pin);
      await tapDigits(tester, _pin);
      await tapText(tester, 'Done');
      await tapText(tester, OnboardingScreen.continueLabel);
      expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
    }

    testWidgets(
        'E1 fresh install, everything granted, one app protected: '
        '"You\'re Protected" → shell, flag recorded, relaunch opens shell',
        (WidgetTester tester) async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final InMemorySecretStore secrets = InMemorySecretStore();
      final InMemoryKeyValueStore kv = InMemoryKeyValueStore();
      final AppContainer c = newContainer(
          apps: const <AppEntry>[_whatsapp],
          granted: true,
          db: db,
          secrets: secrets,
          kv: kv);
      nativeHealthy(c);
      await pumpApp(tester, c);
      expect(find.text(OnboardingScreen.welcomeTitle), findsOneWidget);
      await throughM1(tester);
      await tapText(tester, OnboardingPermissionsStep.continueLabel);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapText(tester, OnboardingAppsStep.protectLabel(1));
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.protectionActive);
      await tapText(tester, OnboardingHealthStep.finishLabel);
      expect(shell(), findsOneWidget);
      expect(find.byType(OnboardingScreen), findsNothing);
      expect(await tester.runAsync(() => c.preferences.isOnboardingCompleted()),
          isTrue);
      await tester.pumpWidget(const SizedBox());
      await tester.pumpAndSettle();

      final AppContainer again = newContainer(
          apps: const <AppEntry>[_whatsapp],
          granted: true,
          db: db,
          secrets: secrets,
          kv: kv);
      await pumpApp(tester, again);
      expect(find.byType(OnboardingScreen), findsNothing);
    });

    testWidgets(
        'E2 fresh install with nothing granted or protected: Setup '
        'Incomplete → Review setup returns to permissions → finish',
        (WidgetTester tester) async {
      final AppContainer c = newContainer(apps: const <AppEntry>[_whatsapp]);
      await pumpApp(tester, c);
      await throughM1(tester);
      await tapText(tester, OnboardingPermissionsStep.skipLabel);
      await tapText(tester, OnboardingAppsStep.skipLabel);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.setupIncomplete);
      await tapText(tester, OnboardingHealthStep.reviewSetupLabel);
      expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
      await tapText(tester, OnboardingPermissionsStep.skipLabel);
      await tapText(tester, OnboardingAppsStep.skipLabel);
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.setupIncomplete);
      await tapText(tester, OnboardingHealthStep.finishAnywayLabel);
      expect(shell(), findsOneWidget);
      expect(await tester.runAsync(() => c.preferences.isOnboardingCompleted()),
          isTrue);
    });

    testWidgets(
        'E3 fresh install whose health check cannot complete: Unable to '
        'Verify, never active; finishing still reaches the shell',
        (WidgetTester tester) async {
      final AppContainer c =
          newContainer(apps: const <AppEntry>[_whatsapp], granted: true);
      nativeHealthy(c);
      watcherOf(c).getHealthError = StateError('bridge down');
      await pumpApp(tester, c);
      await throughM1(tester);
      await tapText(tester, OnboardingPermissionsStep.continueLabel);
      await tapFinder(
          tester, find.byKey(const Key('onboarding_app_com.whatsapp')));
      await tapText(tester, OnboardingAppsStep.protectLabel(1));
      await tester.pumpAndSettle();
      expectOutcome(OnboardingCompletion.unableToVerify);
      await tapText(tester, OnboardingHealthStep.finishAnywayLabel);
      expect(shell(), findsOneWidget);
    });

    // Interruption (process death) at every step, then relaunch with the
    // same persisted stores.
    for (final OnboardingStep stop in OnboardingStep.values) {
      final bool credentialSet =
          stop.index > OnboardingStep.authentication.index;
      testWidgets(
          'E4.${stop.name} interrupted at ${stop.name}: relaunch opens '
          '${credentialSet ? 'the shell (never forced again)' : 'Welcome'}',
          (WidgetTester tester) async {
        final InMemoryLocalDatabase db = InMemoryLocalDatabase();
        final InMemorySecretStore secrets = InMemorySecretStore();
        final InMemoryKeyValueStore kv = InMemoryKeyValueStore();
        final AppContainer first = newContainer(
            apps: const <AppEntry>[_whatsapp],
            db: db,
            secrets: secrets,
            kv: kv);
        await pumpApp(tester, first);
        if (stop.index >= OnboardingStep.authentication.index) {
          await tapText(tester, OnboardingScreen.getStartedLabel);
        }
        if (stop.index >= OnboardingStep.biometric.index) {
          await tapText(tester, OnboardingScreen.pinOptionTitle);
          await tapText(tester, '6-digit PIN');
          await tapDigits(tester, _pin);
          await tapDigits(tester, _pin);
          await tapText(tester, 'Done');
        }
        if (stop.index >= OnboardingStep.permissions.index) {
          await tapText(tester, OnboardingScreen.continueLabel);
          expect(find.text(OnboardingPermissionsStep.title), findsOneWidget);
        }
        if (stop.index >= OnboardingStep.apps.index) {
          await tapText(tester, OnboardingPermissionsStep.skipLabel);
          expect(find.text(OnboardingAppsStep.title), findsOneWidget);
        }
        if (stop.index >= OnboardingStep.health.index) {
          await tapText(tester, OnboardingAppsStep.skipLabel);
          await tester.pumpAndSettle();
          expect(find.byType(OnboardingHealthStep), findsOneWidget);
        }
        // Process death.
        await tester.pumpWidget(const SizedBox());
        await tester.pumpAndSettle();

        final AppContainer second = newContainer(
            apps: const <AppEntry>[_whatsapp],
            db: db,
            secrets: secrets,
            kv: kv);
        expect(await tester.runAsync(() => shouldStartOnboarding(second.auth)),
            !credentialSet);
        await pumpApp(tester, second);
        if (credentialSet) {
          expect(find.byType(OnboardingScreen), findsNothing);
          expect(find.text(OnboardingScreen.welcomeTitle), findsNothing);
          expect(
              (await tester.runAsync(() => second.auth.status()))!
                  .valueOrNull!
                  .hasAnyCredential,
              isTrue,
              reason: 'the credential set before the interruption is kept');
        } else {
          expect(find.text(OnboardingScreen.welcomeTitle), findsOneWidget);
          expect(shell(), findsNothing);
        }
      });
    }

    testWidgets(
        'E5 an existing user with unknown health is never sent through '
        'onboarding or the completion step', (WidgetTester tester) async {
      final AppContainer c = newContainer();
      await tester.runAsync(() => c.auth.enrollPin(_pin));
      watcherOf(c).getHealthError = StateError('bridge down');
      expect(await tester.runAsync(() => c.preferences.isOnboardingCompleted()),
          isFalse);
      await pumpApp(tester, c);
      expect(find.byType(OnboardingScreen), findsNothing);
      expect(find.byType(OnboardingHealthStep), findsNothing);
    });

    test(
        'E6 unreadable credential storage stays fail-closed: onboarding '
        '(and its completion step) never starts', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final InMemorySecretStore secrets = InMemorySecretStore();
      final AppContainer writer =
          AppContainer.inMemory(database: db, secretStore: secrets);
      final SecuritySettings current =
          (await writer.securitySettings.getSettings()).valueOrNull!;
      expect((await writer.securitySettings.saveSettings(current)).isSuccess,
          isTrue);
      final AppContainer reader = AppContainer.inMemory(
          database: db, secretStore: _FailingSecrets(secrets));
      expect((await reader.auth.status()).isFailure, isTrue);
      expect(await shouldStartOnboarding(reader.auth), isFalse);
    });
  });
}
