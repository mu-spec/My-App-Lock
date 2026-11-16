// P13/M3 NF-NS-1, owner decision 3 — T4 at the UI boundary.
//
// A REAL T4: the screen's manager verifies with a hasher that, after the
// KDF and before the commit, lets a SECOND manager on the same store replace
// the credential (PIN/pattern) or Clear All. The screen must then show the
// neutral retry message — never "Incorrect … attempts left", never unlock —
// and nothing is counted or reported to the intruder pipeline (no
// VerifiedAttempt). Host widget tests only: not device QA.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/app_scope.dart';
import 'package:smart_app_lock/app/theme/app_theme.dart';
import 'package:smart_app_lock/design_system/design_system.dart';
import 'package:smart_app_lock/security/credentials/credential_hash.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/ui/screens/pattern/pattern_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';

// Disposable test credentials only.
const String _pin = '482916';
const String _newPin = '739104';
const List<int> _pat = <int>[1, 2, 3, 6];
const List<int> _newPat = <int>[7, 4, 1, 2];

class _RacingPinHasher implements PinHasher {
  final Pbkdf2PinHasher _inner = Pbkdf2PinHasher(iterations: 200);

  /// Runs once, after the KDF of the next verification.
  Future<void> Function()? afterKdf;

  @override
  Future<PinHash> hash(String pin) => _inner.hash(pin);

  @override
  Future<bool> verify(String pin, PinHash stored) async {
    final bool ok = await _inner.verify(pin, stored);
    final Future<void> Function()? race = afterKdf;
    afterKdf = null;
    if (race != null) {
      await race();
    }
    return ok;
  }
}

class _RacingPatternHasher implements PatternHasher {
  final Pbkdf2PatternHasher _inner = Pbkdf2PatternHasher(iterations: 200);
  Future<void> Function()? afterKdf;

  @override
  Future<CredentialHash> hash(List<int> nodes) => _inner.hash(nodes);

  @override
  Future<bool> verify(List<int> nodes, CredentialHash stored) async {
    final bool ok = await _inner.verify(nodes, stored);
    final Future<void> Function()? race = afterKdf;
    afterKdf = null;
    if (race != null) {
      await race();
    }
    return ok;
  }
}

class _Observer implements VerifiedAttemptObserver {
  final List<VerifiedAttempt> attempts = <VerifiedAttempt>[];

  @override
  void onVerifiedAttempt(VerifiedAttempt attempt) => attempts.add(attempt);
}

void main() {
  late AppContainer container;
  late DefaultCredentialManager screenManager;
  late DefaultCredentialManager other;
  late _Observer observer;
  late List<Object?> results;

  CredentialStateMachine machine() => CredentialStateMachine(
        maxFailedAttempts: 3,
        lockoutDuration: const Duration(seconds: 30),
      );

  Future<void> host(
    WidgetTester tester, {
    required PinHasher pinHasher,
    required PatternHasher patternHasher,
    required Widget Function(DefaultCredentialManager m) screen,
  }) async {
    tester.view.physicalSize = const Size(800, 1400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    container = AppContainer.inMemory();
    observer = _Observer();
    screenManager = DefaultCredentialManager(
      settings: container.securitySettings,
      pinHasher: pinHasher,
      patternHasher: patternHasher,
      stateMachine: machine(),
      attemptObserver: observer,
    );
    // A second engine/manager over the SAME durable store.
    other = DefaultCredentialManager(
      settings: container.securitySettings,
      pinHasher: Pbkdf2PinHasher(iterations: 200),
      patternHasher: Pbkdf2PatternHasher(iterations: 200),
      stateMachine: machine(),
    );
    results = <Object?>[];
    await tester.pumpWidget(
      AppScope(
        container: container,
        child: MaterialApp(
          theme: AppTheme.dark,
          home: Builder(
            builder: (BuildContext context) => Scaffold(
              body: Center(
                child: TextButton(
                  key: const Key('open_unlock'),
                  onPressed: () async {
                    results.add(await Navigator.of(context).push<Object?>(
                      MaterialPageRoute<Object?>(
                        builder: (_) => screen(screenManager),
                      ),
                    ));
                  },
                  child: const Text('open'),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> open(WidgetTester tester) async {
    await tester.tap(find.byKey(const Key('open_unlock')));
    await tester.pumpAndSettle();
  }

  Future<void> tapDigits(WidgetTester tester, String digits) async {
    await tester.pump(const Duration(milliseconds: 250));
    for (final String d in digits.split('')) {
      await tester.tap(find.byKey(Key('pin_key_$d')));
      await tester.pump(const Duration(milliseconds: 50));
    }
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump(const Duration(milliseconds: 100));
  }

  // Same stroke technique as test/ui/pattern_unlock_screen_test.dart.
  Future<void> drawPattern(WidgetTester tester, List<int> nodes) async {
    await tester.pump(const Duration(milliseconds: 450));
    final Finder gridFinder = find.byType(DsPatternGrid);
    expect(gridFinder, findsOneWidget);
    final Rect bounds = tester.getRect(gridFinder);
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
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 700));
  }

  for (final String change in <String>['replace', 'clearAll']) {
    testWidgets('T4-UI-PIN ($change): neutral retry message, no attempts-left '
        'text, no unlock, uncounted, no verified attempt',
        (WidgetTester tester) async {
      final _RacingPinHasher hasher = _RacingPinHasher();
      await host(
        tester,
        pinHasher: hasher,
        patternHasher: Pbkdf2PatternHasher(iterations: 200),
        screen: (DefaultCredentialManager m) =>
            PinUnlockScreen(credentialManager: m),
      );
      expect((await other.enrollPin(_pin)).isSuccess, isTrue);
      final grant = (await other.verifyPinForCredentialChange(_pin))
          .valueOrNull!
          .authorization!;
      hasher.afterKdf = () async {
        final result = change == 'replace'
            ? await other.enrollPin(_newPin, authorization: grant)
            : await other.clearAll();
        expect(result.isSuccess, isTrue);
      };
      await open(tester);
      await tapDigits(tester, _pin);
      await tester.pumpAndSettle();

      expect(hasher.afterKdf, isNull, reason: 'the race must have run');
      expect(find.text(PinUnlockScreen.verifyFailedMessage), findsOneWidget);
      expect(find.textContaining(PinUnlockScreen.wrongPinPrefix), findsNothing);
      expect(find.textContaining('attempts left'), findsNothing);
      expect(results, isEmpty, reason: 'the unlock route must not pop');
      expect(observer.attempts, isEmpty);
      expect((await container.securitySettings.getSettings())
          .valueOrNull!
          .failedAttempts, 0);
    });

    testWidgets('T4-UI-PATTERN ($change): neutral retry message, no '
        'attempts-left text, no unlock, uncounted, no verified attempt',
        (WidgetTester tester) async {
      final _RacingPatternHasher hasher = _RacingPatternHasher();
      await host(
        tester,
        pinHasher: Pbkdf2PinHasher(iterations: 200),
        patternHasher: hasher,
        screen: (DefaultCredentialManager m) =>
            PatternUnlockScreen(credentialManager: m),
      );
      expect((await other.enrollPattern(_pat)).isSuccess, isTrue);
      final grant = (await other.verifyPatternForCredentialChange(_pat))
          .valueOrNull!
          .authorization!;
      hasher.afterKdf = () async {
        final result = change == 'replace'
            ? await other.enrollPattern(_newPat, authorization: grant)
            : await other.clearAll();
        expect(result.isSuccess, isTrue);
      };
      await open(tester);
      await drawPattern(tester, _pat);
      await tester.pumpAndSettle();

      expect(hasher.afterKdf, isNull, reason: 'the race must have run');
      expect(
          find.text(PatternUnlockScreen.verifyFailedMessage), findsOneWidget);
      expect(find.textContaining(PatternUnlockScreen.wrongPatternPrefix),
          findsNothing);
      expect(find.textContaining('attempts left'), findsNothing);
      expect(results, isEmpty, reason: 'the unlock route must not pop');
      expect(observer.attempts, isEmpty);
      expect((await container.securitySettings.getSettings())
          .valueOrNull!
          .failedAttempts, 0);
    });
  }
}
