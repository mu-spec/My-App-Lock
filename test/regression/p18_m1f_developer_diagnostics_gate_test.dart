// Phase 18 / M1F — F18-5 proposal: the temporary Phase 5B "Detection
// diagnostics" developer tools exist only in debug builds.
//
// SIMULATED (host widget tests always run in debug mode, so a non-debug
// build is simulated with `debugDeveloperDiagnosticsOverride = false`) plus
// a STATIC check that the release guard is a compile-time `kReleaseMode`
// short-circuit evaluated BEFORE the test override. Release builds are not
// executed here (no APK); device/release verification is PENDING.
//
//  DG1 non-debug: Home shows no "Developer" section / diagnostics card.
//  DG2 non-debug: the diagnostics route does not resolve (null).
//  DG3 debug (default in tests): card and route are unchanged.
//  DG4 static: release short-circuit precedes the override; Home and the
//      router both consult the same gate.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/developer_tools_gate.dart';
import 'package:smart_app_lock/app/router.dart';

void main() {
  tearDown(() => debugDeveloperDiagnosticsOverride = null);

  Future<void> pumpHome(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1080, 2340);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(const SmartAppLockApp());
    await tester.pump();
  }

  testWidgets('DG1 non-debug build: no Developer section or card',
      (WidgetTester tester) async {
    debugDeveloperDiagnosticsOverride = false;
    await pumpHome(tester);
    expect(find.byKey(const Key('quick_access_settings')), findsOneWidget,
        reason: 'Home rendered');
    expect(
      find.byKey(const Key('quick_access_diagnostics'), skipOffstage: false),
      findsNothing,
    );
    expect(find.text('Developer', skipOffstage: false), findsNothing);
    expect(
        find.text('Detection diagnostics', skipOffstage: false), findsNothing);
    expect(tester.takeException(), isNull);
  });

  test('DG2 non-debug build: the diagnostics route does not resolve', () {
    debugDeveloperDiagnosticsOverride = false;
    expect(
      AppRouter.onGenerateRoute(
        const RouteSettings(name: RouteNames.detectionDiagnostics),
      ),
      isNull,
    );
    // Other routes are unaffected.
    expect(
      AppRouter.onGenerateRoute(const RouteSettings(name: RouteNames.home)),
      isNotNull,
    );
  });

  testWidgets('DG3 debug build (default): card and route unchanged',
      (WidgetTester tester) async {
    expect(developerDiagnosticsEnabled, isTrue);
    await pumpHome(tester);
    expect(
      find.byKey(const Key('quick_access_diagnostics'), skipOffstage: false),
      findsOneWidget,
    );
    expect(
      AppRouter.onGenerateRoute(
        const RouteSettings(name: RouteNames.detectionDiagnostics),
      ),
      isNotNull,
    );
  });

  test('DG4 static: release short-circuit precedes the override', () {
    final String gate =
        File('lib/app/developer_tools_gate.dart').readAsStringSync();
    final int release = gate.indexOf('if (kReleaseMode) return false;');
    final int override =
        gate.indexOf('return debugDeveloperDiagnosticsOverride');
    expect(release, greaterThan(0));
    expect(override, greaterThan(release));
    final String home =
        File('lib/ui/screens/home/home_screen.dart').readAsStringSync();
    final String router = File('lib/app/router.dart').readAsStringSync();
    final int card = home.indexOf("Key('quick_access_diagnostics')");
    final int guard = home.indexOf('if (developerDiagnosticsEnabled)');
    expect(guard, greaterThan(0));
    expect(card, greaterThan(guard));
    expect(router, contains('if (!developerDiagnosticsEnabled) return null;'));
  });
}
