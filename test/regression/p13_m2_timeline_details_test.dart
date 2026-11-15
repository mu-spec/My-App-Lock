// Phase 13 / M2 — T7: timeline details screen (W-01…W-05, W-10…W-12) and
// the health-recorder stream lifecycle (F-08).
//
// SIMULATED: widget tests on the real app (AppContainer.inMemory built in
// the test body); FLAG_SECURE is the in-memory overlay fake. Device
// FLAG_SECURE behaviour (recents / screenshots) is NOT claimable here.
// The screen-state ERROR leg of W-03 is not simulable: the existing
// StaticScreenStateService has no error hook and adding one is outside the
// M2 manifest (disclosed in the report; the code path is the M1 one).

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/app/protection_health_journal_recorder.dart';
import 'package:smart_app_lock/data/models/app_security_level.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/protection/health/protection_health_engine.dart';
import 'package:smart_app_lock/protection/health/protection_health_monitor.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/services/impl/static_intruder_evidence_service.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_screen_state_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_detail_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_screen.dart';

import '../support/credential_change_grant.dart';

const String _pin = '482916';
const String _app = 'com.example.bank';

class _FakeMonitor implements ProtectionHealthMonitor {
  final StreamController<ProtectionHealthReport> controller =
      StreamController<ProtectionHealthReport>.broadcast();
  int listens = 0;
  int refreshCalls = 0;

  @override
  Stream<ProtectionHealthReport> get changes {
    listens++;
    return controller.stream;
  }

  @override
  Future<ProtectionHealthReport> refresh({bool afterChange = false}) {
    refreshCalls++;
    throw StateError('never');
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnsupportedError('${invocation.memberName}');
}

void main() {
  late AppContainer c;
  int violations = 0;
  int detailFrames = 0;

  StaticOverlayLockService overlay() => c.overlay as StaticOverlayLockService;

  bool keyed(Widget w, List<String> prefixes) =>
      w.key is ValueKey<String> &&
      prefixes
          .any((String p) => (w.key! as ValueKey<String>).value.startsWith(p));

  Finder detail() => find.byWidgetPredicate(
      (Widget w) => keyed(w, <String>[
            'security_timeline_detail_list',
            'security_timeline_detail_group_',
            'security_timeline_detail_attempt_',
            'security_timeline_detail_event_',
          ]),
      skipOffstage: false);

  Finder history() => find.byWidgetPredicate(
      (Widget w) => keyed(w, <String>[
            'security_timeline_entry_',
            'security_timeline_group_',
          ]),
      skipOffstage: false);

  void sample(bool secureBefore) {
    final bool shown = detail().evaluate().isNotEmpty;
    if (shown) detailFrames++;
    if ((shown || history().evaluate().isNotEmpty) &&
        (!overlay().secureWindow || !secureBefore)) {
      violations++;
    }
  }

  Future<void> frames(WidgetTester t, [int n = 40]) async {
    for (int i = 0; i < n; i++) {
      final bool before = overlay().secureWindow;
      await t.pump(const Duration(milliseconds: 16));
      sample(before);
    }
  }

  Future<void> settle(WidgetTester t) async {
    await frames(t);
    await t.pumpAndSettle();
    sample(true);
  }

  Future<void> typePin(WidgetTester t, String pin) async {
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    await frames(t, 16);
    for (final String d in pin.split('')) {
      await t.tap(find.byKey(Key('pin_key_$d')));
      await frames(t, 3);
    }
    await settle(t);
  }

  NavigatorState nav(WidgetTester t) =>
      t.state<NavigatorState>(find.byType(Navigator).first);

  Future<void> boot(WidgetTester t,
      {InMemoryLocalDatabase? database, int wrongBefore = 2}) async {
    violations = 0;
    detailFrames = 0;
    c = AppContainer.inMemory(
      intruderEvidence: StaticIntruderEvidenceService(),
      database: database ?? InMemoryLocalDatabase(),
    );
    t.view.physicalSize = const Size(800, 2400);
    t.view.devicePixelRatio = 1.0;
    addTearDown(t.view.reset);
    await t.pumpWidget(SmartAppLockApp(container: c));
    await t.pumpAndSettle();
    await c.auth.enrollPin(_pin);
    await c.protectedApps.add(ProtectedApp(
      packageName: _app,
      label: _app,
      addedAt: DateTime(2026, 10, 22),
      securityLevel: AppSecurityLevel.defaultLevel,
    ));
    await c.protectionBootstrap.synchronize();
    await c.intruderStartup;
    await c.securityJournalStartup;
    for (int i = 0; i < wrongBefore; i++) {
      await c.auth.authenticatePin('000000');
    }
    await c.intruderMonitor.idle();
    await t.pumpAndSettle();
  }

  Future<void> openTimeline(WidgetTester t) async {
    late BuildContext launcher;
    nav(t).push(MaterialPageRoute<void>(builder: (BuildContext ctx) {
      launcher = ctx;
      return const Scaffold(body: Text('launcher'));
    }));
    await settle(t);
    unawaited(openSecurityTimeline(launcher, c));
    await settle(t);
    await typePin(t, _pin);
    expect(find.byType(SecurityTimelineScreen), findsOneWidget);
  }

  Future<void> openDetails(WidgetTester t) async {
    final Finder btn =
        find.byKey(const ValueKey<String>('security_timeline_group_details_1'));
    await t.scrollUntilVisible(btn, 200,
        scrollable: find.byType(Scrollable).last);
    await settle(t);
    await t.tap(btn);
    await settle(t);
  }

  void expectAllClosed() {
    expect(find.byType(SecurityTimelineDetailScreen), findsNothing);
    expect(find.byType(SecurityTimelineScreen), findsNothing);
    expect(detail(), findsNothing);
    expect(c.securityTimelineSessions.current, isNull);
  }

  List<String> texts(WidgetTester t, Type under) => find
      .descendant(of: find.byType(under), matching: find.byType(Text))
      .evaluate()
      .map((Element e) => (e.widget as Text).data ?? '')
      .toList();

  testWidgets(
      'W-01 details: FLAG_SECURE before any detail text; session '
      'kept; group detail rendered', (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDetails(t);
    expect(find.byType(SecurityTimelineDetailScreen), findsOneWidget);
    expect(
        find.byKey(const Key('security_timeline_detail_list')), findsOneWidget);
    expect(find.byKey(const Key('security_timeline_detail_group_1')),
        findsOneWidget);
    expect(c.securityTimelineSessions.current, isNotNull);
    expect(overlay().secureWindow, isTrue);
    expect(violations, 0);
    expect(detailFrames, greaterThan(0));
  });

  testWidgets(
      'W-01 details: setSecureWindow fails ⇒ secureFailed, no detail '
      'text in any frame', (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    overlay().secureWindowFails = true;
    detailFrames = 0;
    await openDetails(t);
    expect(find.byKey(const Key('security_timeline_detail_secure_failed')),
        findsOneWidget);
    expect(detail(), findsNothing);
    expect(detailFrames, 0);
  });

  testWidgets(
      'W-02 credential no longer current on open ⇒ invalidated, '
      'nothing rendered, all closed', (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await c.auth.enrollPattern(const <int>[1, 2, 3, 6],
        authorization: await grantWithPin(c.auth, _pin));
    detailFrames = 0;
    await openDetails(t);
    await settle(t);
    expect(detailFrames, 0);
    expectAllClosed();
  });

  for (final String s in <String>[
    'inactive',
    'paused',
    'hidden',
    'screenOff',
    'expiry',
  ]) {
    testWidgets(
        'W-03 invalidation on details: $s ⇒ data dropped in details '
        'and timeline; routes close', (WidgetTester t) async {
      await boot(t);
      await openTimeline(t);
      await openDetails(t);
      expect(detail(), findsWidgets);
      switch (s) {
        case 'inactive':
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
        case 'paused':
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
        case 'hidden':
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
        case 'screenOff':
          (c.screenState as StaticScreenStateService).emitScreenOff();
        case 'expiry':
          await t.pump(const Duration(minutes: 2, seconds: 1));
      }
      await settle(t);
      if (s != 'screenOff' && s != 'expiry') {
        if (s == 'paused') {
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
        }
        if (s != 'inactive') {
          t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
        }
        t.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
        await settle(t);
      }
      expectAllClosed();
      expect(violations, 0);
    });
  }

  testWidgets(
      'W-04 foreign route over details ⇒ session ends; the foreign '
      'route is not popped; details/timeline close on surfacing',
      (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDetails(t);
    final Completer<void> closed = Completer<void>();
    unawaited(nav(t)
        .push(MaterialPageRoute<void>(
            builder: (_) => const Scaffold(body: Text('foreign'))))
        .then((_) => closed.complete()));
    await settle(t);
    expect(find.text('foreign'), findsOneWidget);
    expect(c.securityTimelineSessions.current, isNull);
    expect(detail(), findsNothing);
    expect(closed.isCompleted, isFalse, reason: 'never popped by us');
    nav(t).pop();
    await settle(t);
    expectAllClosed();
  });

  testWidgets(
      'W-05 back from details: the timeline renders nothing until '
      'FLAG_SECURE → re-check → load (a failing FLAG_SECURE on return '
      'fails closed)', (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDetails(t);
    overlay().secureWindowFails = true;
    nav(t).pop();
    await t.pump();
    expect(history(), findsNothing, reason: 'no cached snapshot on surface');
    await settle(t);
    expect(find.byKey(const Key('security_timeline_secure_failed')),
        findsOneWidget);
    expect(history(), findsNothing);
  });

  testWidgets(
      'W-05 back from details after a credential change ⇒ the '
      're-check ends the session (nothing rendered)', (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDetails(t);
    // A grant-based change while details are open; details re-check only on
    // surfacing, so pop directly to the timeline.
    await c.auth.enrollPattern(const <int>[1, 2, 3, 6],
        authorization: await grantWithPin(c.auth, _pin));
    nav(t).pop();
    await settle(t);
    expect(history(), findsNothing);
    expectAllClosed();
  });

  testWidgets(
      'W-10 / W-12 notices and rows: reset facts, health coverage, '
      'photo link, process death; M1 footer verbatim; health/storage/alarm '
      'wording', (WidgetTester t) async {
    await boot(t);
    final SecurityEventJournal j = c.securityJournal;
    j.record(SecurityJournalEventType.journalRecovered);
    await j.idle();
    j.recordHealthObservation(
        HState.attention, <HCode>[HCode.overlayUnavailable]);
    j.recordStorageObservation(StorageSource.failureLog, StoreState.failing);
    // trig 99 has no failed attempt ⇒ a standalone (detached) alarm row.
    j.recordEvent(
        SecurityJournalEventType.alarmStarted, const AlarmStartedFields(99));
    j.recordEvent(
        SecurityJournalEventType.alarmStopped, const AlarmStoppedFields());
    await j.idle();
    await openTimeline(t);
    for (final String k in <String>[
      'security_timeline_health_coverage',
      'security_timeline_photo_link',
      'security_timeline_footer',
      'security_timeline_footer_process_death',
    ]) {
      final Finder f = find.byKey(ValueKey<String>(k));
      await t.scrollUntilVisible(f, 200,
          scrollable: find.byType(Scrollable).last);
      expect(f, findsOneWidget, reason: k);
    }
    final List<String> all = texts(t, SecurityTimelineScreen);
    final String joined = all.join('\n');
    expect(joined, contains('Protection needs attention'));
    expect(joined, contains('detected at'));
    expect(joined, contains('Alarm stop requested'));
    expect(joined, contains('Alarm started · plays up to 30 s'));
    for (final String bad in <String>[
      'lasted',
      'until',
      'install',
      'app start'
    ]) {
      expect(joined.toLowerCase(), isNot(contains(bad)), reason: bad);
    }
    // Health/storage ROWS must not claim an onset. The coverage notice is
    // excluded: it deliberately says problems "may have started earlier".
    final Iterable<String> healthLines = all.where((String s) =>
        !s.startsWith('Protection status is checked only while') &&
        (s.startsWith('Protection') ||
            s.contains('history storage') ||
            s.contains('Failed-unlock history')));
    expect(healthLines.length, greaterThanOrEqualTo(3));
    for (final String l in healthLines) {
      expect(l.toLowerCase(), isNot(contains('started')), reason: l);
    }
    expect(
        find.byKey(const Key('security_timeline_reset_pending')), findsNothing);
  });

  testWidgets(
      'W-11 privacy: no PIN digits, owner/unlocked/success wording or '
      'Image widgets in the timeline or details', (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    final List<String> tl = texts(t, SecurityTimelineScreen);
    await openDetails(t);
    final List<String> dt = texts(t, SecurityTimelineDetailScreen);
    for (final String s in <String>[...tl, ...dt]) {
      expect(s, isNot(contains(_pin)));
      expect(s, isNot(contains('000000')));
      for (final String w in <String>[
        'owner',
        'unlocked',
        'success',
        'vid',
        'chal'
      ]) {
        expect(RegExp('\\b$w\\b', caseSensitive: false).hasMatch(s), isFalse,
            reason: '"$w" in "$s"');
      }
    }
    expect(
        find.descendant(
            of: find.byType(SecurityTimelineDetailScreen),
            matching: find.byType(Image)),
        findsNothing);
    expect(find.byType(SelectableText), findsNothing);
  });

  test(
      'F-08 recorder: error, then a valid report, then done ⇒ survives, '
      'records the valid report, never re-subscribes or refreshes', () async {
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    final SecurityEventJournal j =
        SecurityEventJournal(store: SecurityEventJournalStore(db));
    j.record(SecurityJournalEventType.journalRecovered);
    await j.idle();
    final _FakeMonitor m = _FakeMonitor();
    final ProtectionHealthJournalRecorder r =
        ProtectionHealthJournalRecorder(journal: j)..attach(m);
    m.controller.addError(StateError('boom'));
    await Future<void>.delayed(Duration.zero);
    final DateTime now = DateTime.now();
    final ProtectionHealthReport rep = ProtectionHealthEngine.evaluate(
      HealthSignals(
        observedAt: now,
        protectionConfigured: true,
        credentialConfigured: true,
        hasProtectedApps: true,
        nativeProtectionEnabled: true,
        overlayGranted: false,
        overlayEverGranted: true,
        accessibilityEnabled: true,
        accessibilityEverGranted: true,
        accessibilityConnected: true,
        usageAccessGranted: true,
        usageAccessEverGranted: true,
        nativeHealthAvailable: true,
        watcherRunning: true,
        shieldArmed: true,
        notificationsGranted: true,
        backgroundRestricted: false,
        sdkInt: 34,
      ),
      now: now,
    );
    m.controller.add(rep);
    await Future<void>.delayed(Duration.zero);
    expect(r.recorded, 1);
    await m.controller.close();
    await Future<void>.delayed(Duration.zero);
    expect(m.listens, 1);
    expect(m.refreshCalls, 0);
    r.attach(m); // already attached: no second subscription
    expect(m.listens, 1);
    await j.idle();
    final List<SecurityJournalEvent> h = (await j.read())
        .events
        .where((SecurityJournalEvent e) =>
            e.type == SecurityJournalEventType.protectionHealth)
        .toList();
    expect(h.length, 1);
  });
}
