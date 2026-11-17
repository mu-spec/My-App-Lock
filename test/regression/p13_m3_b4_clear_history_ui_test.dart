// P13/M3 Batch 4 — Clear History UI through the REAL app (SmartAppLockApp
// over AppContainer.inMemory): action, explicit confirmation, photos opt-in
// (default off), fresh owner verification, pending notice + Finish, refused
// storage, and session loss during the flow. FLAG_SECURE is sampled on every
// pumped frame: no timeline history may be on screen while it is off.
//
// SIMULATED: widget tests; the Android window flag is NOT exercised.

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/services/impl/static_intruder_evidence_service.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/services/impl/static_screen_state_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_screen.dart';

const String _pin = '482916';

/// Failure-log CAS writes fail while [blockLog] is set (step (b) "crash").
class _Db extends InMemoryLocalDatabase {
  bool blockLog = false;

  @override
  Future<CasOutcome> compareAndSetSetting(String key,
      {required String? expected, required String next}) async {
    if (blockLog && key == IntruderFailureLogStore.storageKey) {
      throw StateError('injected');
    }
    return super.compareAndSetSetting(key, expected: expected, next: next);
  }
}

void main() {
  late AppContainer c;
  late InMemoryLocalDatabase database;
  int violations = 0;

  StaticOverlayLockService overlay() => c.overlay as StaticOverlayLockService;

  Finder history() => find.byWidgetPredicate(
        (Widget w) =>
            w.key is ValueKey<String> &&
            (w.key! as ValueKey<String>)
                .value
                .startsWith('security_timeline_entry_failedAttempts'),
        skipOffstage: false,
      );

  Future<void> frames(WidgetTester t, [int n = 40]) async {
    for (int i = 0; i < n; i++) {
      final bool before = overlay().secureWindow;
      await t.pump(const Duration(milliseconds: 16));
      if (history().evaluate().isNotEmpty &&
          (!overlay().secureWindow || !before)) {
        violations++;
      }
    }
  }

  Future<void> settle(WidgetTester t) async {
    await frames(t);
    await t.pumpAndSettle();
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

  Future<void> boot(WidgetTester t, {InMemoryLocalDatabase? db}) async {
    violations = 0;
    database = db ?? InMemoryLocalDatabase();
    c = AppContainer.inMemory(
      intruderEvidence: StaticIntruderEvidenceService(),
      database: database,
    );
    t.view.physicalSize = const Size(800, 2400);
    t.view.devicePixelRatio = 1.0;
    addTearDown(t.view.reset);
    await t.pumpWidget(SmartAppLockApp(container: c));
    await t.pumpAndSettle();
    await c.auth.enrollPin(_pin);
    await c.intruderStartup;
    await c.securityJournalStartup;
    for (int i = 0; i < 2; i++) {
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
    expect(history(), findsNWidgets(2));
  }

  Future<List<FailedAttemptEvent>> logEvents() async {
    final IntruderLogRead r =
        await IntruderFailureLogStore(database, cipher: c.settingsCipher)
            .read();
    return (r as IntruderLogLoaded).log.events;
  }

  Future<HistoryClearedFields?> marker() async {
    final SecurityJournalRead r =
        await SecurityEventJournalStore(database, cipher: c.settingsCipher)
            .read();
    if (r is! SecurityJournalLoaded) return null;
    return r.document.historyMarker?.fields as HistoryClearedFields?;
  }

  Future<void> openDialog(WidgetTester t) async {
    await t.tap(find.byKey(const Key('security_timeline_clear')));
    await settle(t);
    expect(find.text(SecurityTimelineText.clearTitle), findsOneWidget);
  }

  testWidgets(
      'UI-1 action opens an explicit confirmation; photos default '
      'off; Cancel changes nothing and asks for no verification',
      (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDialog(t);
    expect(find.text(SecurityTimelineText.clearBody), findsOneWidget);
    final CheckboxListTile box =
        t.widget(find.byKey(const Key('security_timeline_clear_photos')));
    expect(box.value, isFalse);
    await t.tap(find.byKey(const Key('security_timeline_clear_cancel')));
    await settle(t);
    expect(find.byType(PinUnlockScreen), findsNothing);
    expect(find.text(SecurityTimelineText.clearNotDone), findsOneWidget);
    expect(await logEvents(), hasLength(2));
    expect(await marker(), isNull);
    expect(c.securityTimelineSessions.current, isNotNull,
        reason: 'own dialog does not end the session');
    expect(history(), findsNWidgets(2));
    expect(violations, 0);
  });

  testWidgets(
      'UI-2 confirm + fresh PIN -> history cleared, marker shown, '
      'session kept, FLAG_SECURE never off with history visible',
      (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDialog(t);
    await t.tap(find.byKey(const Key('security_timeline_clear_confirm')));
    await settle(t);
    expect(find.byType(PinUnlockScreen), findsOneWidget,
        reason: 'a cached session never counts: fresh verification');
    expect(history(), findsNothing, reason: 'nothing shown while covered');
    await typePin(t, _pin);
    await settle(t);
    expect(find.byType(SecurityTimelineScreen), findsOneWidget);
    expect(find.text(SecurityTimelineText.cleared), findsOneWidget);
    expect(history(), findsNothing);
    expect(
        find.text(SecurityTimelineText.clearedTitle(HistoryClearScope.history)),
        findsOneWidget);
    expect(await logEvents(), isEmpty);
    final HistoryClearedFields m = (await marker())!;
    expect(m.state, HistoryClearState.done);
    expect(m.scope, HistoryClearScope.history);
    expect(c.securityTimelineSessions.current, isNotNull);
    expect(overlay().secureWindow, isTrue);
    expect(violations, 0);
  });

  testWidgets('UI-3 verification cancelled -> nothing cleared',
      (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDialog(t);
    await t.tap(find.byKey(const Key('security_timeline_clear_confirm')));
    await settle(t);
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    nav(t).pop();
    await settle(t);
    expect(await logEvents(), hasLength(2));
    expect(await marker(), isNull);
    expect(find.text(SecurityTimelineText.clearNotDone), findsOneWidget);
    expect(violations, 0);
  });

  testWidgets('UI-4 photos opt-in is recorded in the marker scope',
      (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDialog(t);
    await t.tap(find.byKey(const Key('security_timeline_clear_photos')));
    await t.pump();
    await t.tap(find.byKey(const Key('security_timeline_clear_confirm')));
    await settle(t);
    await typePin(t, _pin);
    await settle(t);
    expect((await marker())!.scope, HistoryClearScope.historyPhotos);
    expect(
        find.text(
            SecurityTimelineText.clearedTitle(HistoryClearScope.historyPhotos)),
        findsOneWidget);
  });

  testWidgets(
      'UI-5 interrupted clear: pending notice, cleared rows hidden; '
      'Finish needs a fresh PIN and completes', (WidgetTester t) async {
    final _Db db = _Db();
    await boot(t, db: db);
    await openTimeline(t);
    db.blockLog = true;
    await openDialog(t);
    await t.tap(find.byKey(const Key('security_timeline_clear_confirm')));
    await settle(t);
    await typePin(t, _pin);
    await settle(t);
    expect(find.text(SecurityTimelineText.clearInterrupted), findsOneWidget);
    expect(find.byKey(const Key('security_timeline_clear_pending')),
        findsOneWidget);
    expect(history(), findsNothing, reason: 'the cleared set stays hidden');
    expect(await logEvents(), hasLength(2), reason: 'not deleted yet');
    expect((await marker())!.state, HistoryClearState.pending);
    db.blockLog = false;
    await t.tap(find.byKey(const Key('security_timeline_clear_finish')));
    await settle(t);
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    await typePin(t, _pin);
    await settle(t);
    expect(find.text(SecurityTimelineText.cleared), findsOneWidget);
    expect(
        find.byKey(const Key('security_timeline_clear_pending')), findsNothing);
    expect(await logEvents(), isEmpty);
    expect((await marker())!.state, HistoryClearState.done);
    expect(violations, 0);
  });

  testWidgets('UI-6 journal from a newer version: refused, nothing changed',
      (WidgetTester t) async {
    final _Db db = _Db();
    await boot(t, db: db);
    await openTimeline(t);
    // Another (newer) build replaced the journal while this one runs: the
    // clear re-reads the row (never trusts its cache) and refuses.
    final String newer =
        'enc:v1:${await c.settingsCipher.encryptString(jsonEncode(<String, Object?>{
          'schema': SecurityJournalDocument.schema,
          'v': 5,
        }))}';
    await db.setSetting(SecurityEventJournalStore.storageKey, newer);
    final String? logRow =
        await db.getSetting(IntruderFailureLogStore.storageKey);
    await openDialog(t);
    await t.tap(find.byKey(const Key('security_timeline_clear_confirm')));
    await settle(t);
    await typePin(t, _pin);
    await settle(t);
    expect(find.text(SecurityTimelineText.clearRefused), findsOneWidget);
    expect(await db.getSetting(IntruderFailureLogStore.storageKey), logRow);
    expect(await db.getSetting(SecurityEventJournalStore.storageKey), newer);
    expect(history(), findsNWidgets(2));
  });

  testWidgets(
      'UI-7 screen off while the dialog is open: session ends, '
      'timeline closes, nothing cleared', (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDialog(t);
    (c.screenState as StaticScreenStateService).emitScreenOff();
    await settle(t);
    expect(find.byType(SecurityTimelineScreen), findsNothing);
    expect(c.securityTimelineSessions.current, isNull);
    expect(await logEvents(), hasLength(2));
    expect(await marker(), isNull);
    expect(violations, 0);
  });

  testWidgets(
      'UI-8 screen off during the fresh verification: verification '
      'and timeline close, nothing cleared, no history shown',
      (WidgetTester t) async {
    await boot(t);
    await openTimeline(t);
    await openDialog(t);
    await t.tap(find.byKey(const Key('security_timeline_clear_confirm')));
    await settle(t);
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    (c.screenState as StaticScreenStateService).emitScreenOff();
    await settle(t);
    expect(find.byType(PinUnlockScreen), findsNothing);
    expect(find.byType(SecurityTimelineScreen), findsNothing);
    expect(c.securityTimelineSessions.current, isNull);
    expect(await logEvents(), hasLength(2));
    expect(await marker(), isNull);
    expect(violations, 0);
  });

  testWidgets(
      'UI-9 re-opening the timeline with a pending clear never resumes '
      'it automatically (no deletion without Finish + fresh PIN)',
      (WidgetTester t) async {
    final _Db db = _Db();
    await boot(t, db: db);
    await openTimeline(t);
    db.blockLog = true;
    await openDialog(t);
    await t.tap(find.byKey(const Key('security_timeline_clear_confirm')));
    await settle(t);
    await typePin(t, _pin);
    await settle(t);
    expect((await marker())!.state, HistoryClearState.pending);
    db.blockLog = false; // storage healthy again
    nav(t).pop(); // close the timeline
    await settle(t);
    expect(find.byType(SecurityTimelineScreen), findsNothing);
    late BuildContext launcher;
    nav(t).push(MaterialPageRoute<void>(builder: (BuildContext ctx) {
      launcher = ctx;
      return const Scaffold(body: Text('launcher2'));
    }));
    await settle(t);
    unawaited(openSecurityTimeline(launcher, c));
    await settle(t);
    await typePin(t, _pin);
    await settle(t);
    expect(find.byKey(const Key('security_timeline_clear_pending')),
        findsOneWidget);
    await c.intruderMonitor.idle();
    expect(await logEvents(), hasLength(2), reason: 'nothing auto-deleted');
    expect((await marker())!.state, HistoryClearState.pending);
    expect(history(), findsNothing, reason: 'still hidden');
    expect(violations, 0);
  });
}
