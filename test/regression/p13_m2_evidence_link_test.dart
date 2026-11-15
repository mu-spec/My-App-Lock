// Phase 13 / M2 — T8: "View photo" link from timeline details into the
// Phase 12 viewer (W-06…W-09, W-13…W-15, C-10, C-11, F-11, F-12).
//
// SIMULATED: widget tests on the real app with an in-memory DB (gated /
// faulted reads) and the in-memory FLAG_SECURE fake. No device claims.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/services/impl/static_screen_state_service.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/models/app_security_level.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/services/impl/static_intruder_evidence_service.dart';
import 'package:smart_app_lock/services/impl/static_overlay_lock_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/security/intruder_evidence_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_detail_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_screen.dart';

import '../support/credential_change_grant.dart';
import '../support/intruder_fixtures.dart';

const String _pin = '482916';
const String _app = 'com.example.bank';

class _GateDb extends InMemoryLocalDatabase {
  final Set<String> gatedPrefixes = <String>{};
  final Set<String> failPrefixes = <String>{};
  int gateSkip = 0; // matching reads allowed through before gating
  Completer<void> gate = Completer<void>();
  final List<String> reads = <String>[];

  bool _match(Set<String> p, String key) => p.any(key.startsWith);

  void release() {
    gatedPrefixes.clear();
    if (!gate.isCompleted) gate.complete();
  }

  @override
  Future<String?> getSetting(String key) async {
    reads.add(key);
    if (_match(gatedPrefixes, key)) {
      if (gateSkip > 0) {
        gateSkip--;
      } else {
        await gate.future;
      }
    }
    if (_match(failPrefixes, key)) throw StateError('read fault');
    return super.getSetting(key);
  }
}

void main() {
  late AppContainer c;
  late _GateDb db;
  int imageFrames = 0;

  StaticOverlayLockService overlay() => c.overlay as StaticOverlayLockService;
  Finder image() => find.byKey(const Key('intruder_evidence_image'));
  NavigatorState nav(WidgetTester t) =>
      t.state<NavigatorState>(find.byType(Navigator).first);

  Future<void> frames(WidgetTester t, [int n = 30]) async {
    for (int i = 0; i < n; i++) {
      await t.pump(const Duration(milliseconds: 16));
      if (image().evaluate().isNotEmpty) imageFrames++;
    }
  }

  Future<void> settle(WidgetTester t) async {
    await frames(t);
    await t.pumpAndSettle();
    if (image().evaluate().isNotEmpty) imageFrames++;
  }

  Future<void> typePin(WidgetTester t, String pin,
      {bool settleAfter = true}) async {
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    await frames(t, 16);
    for (final String d in pin.split('')) {
      await t.tap(find.byKey(Key('pin_key_$d')));
      await frames(t, 3);
    }
    if (settleAfter) await settle(t);
  }

  Future<void> boot(WidgetTester t, {bool seed = true}) async {
    imageFrames = 0;
    db = _GateDb();
    c = AppContainer.inMemory(
        intruderEvidence: StaticIntruderEvidenceService(), database: db);
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
    for (int i = 0; i < 2; i++) {
      await c.auth.authenticatePin('000000');
    }
    await c.intruderMonitor.idle();
    if (seed) {
      expect(await c.intruderEvidence.save(seq: 1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
    }
    c.securityJournal.recordEvent(
        SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
    await c.securityJournal.idle();
    await t.pumpAndSettle();
  }

  Future<void> openToViewPhoto(WidgetTester t) async {
    late BuildContext launcher;
    nav(t).push(MaterialPageRoute<void>(builder: (BuildContext ctx) {
      launcher = ctx;
      return const Scaffold(body: Text('launcher'));
    }));
    await settle(t);
    unawaited(openSecurityTimeline(launcher, c));
    await settle(t);
    await typePin(t, _pin);
    final Finder btn =
        find.byKey(const ValueKey<String>('security_timeline_group_details_1'));
    await t.scrollUntilVisible(btn, 200,
        scrollable: find.byType(Scrollable).last);
    await settle(t);
    await t.tap(btn);
    await settle(t);
    final Finder view = find
        .byKey(const ValueKey<String>('security_timeline_detail_view_photo_1'));
    await t.scrollUntilVisible(view, 200,
        scrollable: find.byType(Scrollable).last);
    await settle(t);
    expect(view, findsOneWidget);
  }

  Future<void> tapView(WidgetTester t, {bool settleAfter = true}) async {
    await t.tap(find.byKey(
        const ValueKey<String>('security_timeline_detail_view_photo_1')));
    if (settleAfter) await settle(t);
  }

  // F-CL-1: a previous process recorded attempts 0,1, the photo for seq 1
  // and captureSaved(trig 1); then ONLY the failure-log row is damaged and a
  // new process records attempts that reuse seqs 0,1.
  Future<int> bootAfterLogReset(WidgetTester t) async {
    imageFrames = 0;
    db = _GateDb();
    final InMemorySecretStore ss = InMemorySecretStore();
    final AppContainer before = AppContainer.inMemory(
        intruderEvidence: StaticIntruderEvidenceService(),
        database: db,
        secretStore: ss);
    await before.intruderStartup;
    await before.securityJournalStartup;
    await before.auth.enrollPin(_pin);
    await before.protectedApps.add(ProtectedApp(
      packageName: _app,
      label: _app,
      addedAt: DateTime(2026, 10, 22),
      securityLevel: AppSecurityLevel.defaultLevel,
    ));
    for (int i = 0; i < 2; i++) {
      await before.auth.authenticatePin('000000');
    }
    await before.intruderMonitor.idle();
    expect(await before.intruderEvidence.save(seq: 1, jpeg: jpegWithMetadata()),
        EvidenceSaveResult.saved);
    before.securityJournal.recordEvent(
        SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
    await before.securityJournal.idle();
    expect((await before.auth.authenticatePin(_pin)).isSuccess, isTrue);
    await before.intruderMonitor.idle();
    await db.setSetting(IntruderFailureLogStore.storageKey, '{not json');
    await t
        .runAsync(() => Future<void>.delayed(const Duration(milliseconds: 20)));
    c = AppContainer.inMemory(
        intruderEvidence: StaticIntruderEvidenceService(),
        database: db,
        secretStore: ss);
    t.view.physicalSize = const Size(800, 2400);
    t.view.devicePixelRatio = 1.0;
    addTearDown(t.view.reset);
    await t.pumpWidget(SmartAppLockApp(container: c));
    await t.pumpAndSettle();
    await c.protectionBootstrap.synchronize();
    await c.intruderStartup;
    await c.securityJournalStartup;
    for (int i = 0; i < 2; i++) {
      await c.auth.authenticatePin('000000');
    }
    await c.intruderMonitor.idle();
    expect(c.intruderMonitor.status.quarantinedCorruptLog, isTrue);
    final SecurityJournalView v = await c.securityJournal.read();
    await t.pumpAndSettle();
    return v.events
        .singleWhere((SecurityJournalEvent e) =>
            e.type == SecurityJournalEventType.captureSaved)
        .seq;
  }

  Future<void> openTimelineOnly(WidgetTester t) async {
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

  Future<void> tapScrolled(WidgetTester t, Finder f) async {
    await t.scrollUntilVisible(f, 200,
        scrollable: find.byType(Scrollable).last);
    await settle(t);
    await t.tap(f);
    await settle(t);
  }

  void expectTimelineClosed() {
    expect(find.byType(SecurityTimelineScreen), findsNothing);
    expect(find.byType(SecurityTimelineDetailScreen), findsNothing);
    expect(c.securityTimelineSessions.current, isNull);
  }

  testWidgets(
      'W-06 the timeline session ends BEFORE the verification route; '
      'cancel ⇒ nothing opens and the timeline closes', (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    expect(c.securityTimelineSessions.current, isNotNull);
    await tapView(t, settleAfter: false);
    expect(c.securityTimelineSessions.current, isNull,
        reason: 'invalidated synchronously on tap');
    await settle(t);
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    nav(t).pop();
    await settle(t);
    expect(find.byType(IntruderEvidenceScreen), findsNothing);
    expect(c.intruderOwnerSessions.current, isNull);
    expectTimelineClosed();
    expect(imageFrames, 0);
  });

  testWidgets(
      'W-07 success: evidence session begun, no timeline session; '
      'list route then focused detail; FLAG_SECURE first',
      (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    await tapView(t);
    await typePin(t, _pin);
    expect(c.securityTimelineSessions.current, isNull);
    expect(c.intruderOwnerSessions.current, isNotNull);
    expect(find.byType(IntruderEvidenceScreen, skipOffstage: false),
        findsOneWidget);
    expect(find.byType(IntruderEvidenceDetailScreen), findsOneWidget);
    expect(image(), findsOneWidget);
    expect(overlay().secureWindow, isTrue);
    // Back from the detail lands on the verified list (not on details).
    nav(t).pop();
    await settle(t);
    expect(find.byType(IntruderEvidenceScreen), findsOneWidget);
    expect(find.byType(SecurityTimelineDetailScreen), findsNothing);
  });

  for (final String how in <String>['delete', 'clearFloor']) {
    testWidgets(
        'W-08 focus seq retired ($how) ⇒ "Photo no longer available."; '
        'no detail pushed', (WidgetTester t) async {
      await boot(t);
      await openToViewPhoto(t);
      if (how == 'delete') {
        await c.intruderEvidence.delete(1);
      } else {
        await c.intruderEvidence.clearAll(floorSeq: 1);
      }
      await tapView(t);
      await typePin(t, _pin);
      expect(find.byType(IntruderEvidenceScreen), findsOneWidget);
      expect(find.text(IntruderEvidenceText.noLongerAvailable), findsOneWidget);
      expect(find.byType(IntruderEvidenceDetailScreen), findsNothing);
      expect(
          db.reads.where((String k) =>
              k.startsWith('${IntruderEvidenceStore.blobPrefix}1')),
          isEmpty);
      expect(imageFrames, 0);
    });
  }

  testWidgets(
      'W-09 / F-11 evidence index unreadable at focus ⇒ existing '
      'viewer message, no detail pushed; the timeline never touched the '
      'evidence index', (WidgetTester t) async {
    await boot(t);
    final int start = db.reads.length;
    await openToViewPhoto(t);
    final List<String> timelineReads = db.reads.sublist(start);
    expect(timelineReads, isNotEmpty);
    expect(
        timelineReads.where((String k) =>
            k.startsWith(IntruderEvidenceStore.indexKey) ||
            k.startsWith(IntruderEvidenceStore.blobPrefix)),
        isEmpty,
        reason: 'timeline + details never read the evidence index or blobs');
    db.failPrefixes.add(IntruderEvidenceStore.indexKey);
    await tapView(t);
    await typePin(t, _pin);
    expect(find.byType(IntruderEvidenceDetailScreen), findsNothing);
    expect(imageFrames, 0);
  });

  testWidgets(
      'W-13 openIntruderEvidenceForSeq(seq < 0) ⇒ false, no route, '
      'no verification', (WidgetTester t) async {
    await boot(t, seed: false);
    late BuildContext ctx;
    nav(t).push(MaterialPageRoute<void>(builder: (BuildContext x) {
      ctx = x;
      return const Scaffold(body: Text('launcher'));
    }));
    await settle(t);
    final bool r = await openIntruderEvidenceForSeq(ctx, c, -1);
    await settle(t);
    expect(r, isFalse);
    expect(find.byType(PinUnlockScreen), findsNothing);
    expect(find.byType(IntruderEvidenceScreen), findsNothing);
  });

  testWidgets(
      'W-14 focused detail showing, then app paused ⇒ pixels dropped, '
      'routes close', (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    await tapView(t);
    await typePin(t, _pin);
    expect(image(), findsOneWidget);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await t.pump();
    await t.pump();
    expect(image(), findsNothing, reason: 'pixels dropped on the first change');
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await t.pump();
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    t.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await settle(t);
    expect(find.byType(IntruderEvidenceScreen), findsNothing);
    expect(find.byType(IntruderEvidenceDetailScreen), findsNothing);
    expect(c.intruderOwnerSessions.current, isNull);
  });

  testWidgets(
      'W-15 credential changed (CR-3 grant) between verification and '
      'focus ⇒ the list load invalidates; no detail pushed',
      (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    await tapView(t);
    await typePin(t, _pin.substring(0, 5), settleAfter: false);
    await t.tap(find.byKey(Key('pin_key_${_pin[5]}')));
    // No frame between the last digit and the credential change.
    await c.auth.enrollPattern(const <int>[1, 2, 3, 6],
        authorization: await grantWithPin(c.auth, _pin));
    await settle(t);
    expect(find.byType(IntruderEvidenceDetailScreen), findsNothing);
    expect(imageFrames, 0);
    expect(c.intruderOwnerSessions.current, isNull);
  });

  testWidgets(
      'C-10 focus seq deleted between the list snapshot and the '
      'detail image read ⇒ detail unavailable; no pixels',
      (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    // The list load reads the index twice (enforceRetention, snapshot):
    // gate the snapshot read, queue the delete behind it (serialized store),
    // then release — the delete commits after the list snapshot listed the
    // photo and before the focused detail's readImage.
    db.gatedPrefixes.add(IntruderEvidenceStore.indexKey);
    db.gateSkip = 1;
    db.gate = Completer<void>();
    await tapView(t);
    await typePin(t, _pin, settleAfter: false);
    await frames(t, 10);
    expect(find.byType(IntruderEvidenceScreen), findsOneWidget);
    final Future<EvidenceDeleteResult> del = c.intruderEvidence.delete(1);
    db.release();
    await frames(t, 40);
    expect(await del, isNotNull);
    expect(find.byType(IntruderEvidenceDetailScreen), findsOneWidget,
        reason: 'the photo was listed when the snapshot ran');
    await frames(t, 20);
    expect(image(), findsNothing);
    expect(find.text(IntruderEvidenceText.unavailable), findsWidgets);
    expect(imageFrames, 0);
  });

  for (final String v in <String>['screenOff', 'expiry']) {
    testWidgets(
        'W-14 ($v) focused detail showing, then $v ⇒ pixels dropped, '
        'routes close', (WidgetTester t) async {
      await boot(t);
      await openToViewPhoto(t);
      await tapView(t);
      await typePin(t, _pin);
      expect(image(), findsOneWidget);
      if (v == 'screenOff') {
        (c.screenState as StaticScreenStateService).emitScreenOff();
        await t.pump();
        await t.pump();
        expect(image(), findsNothing, reason: 'pixels dropped on screen-off');
      } else {
        await t.pump(const Duration(minutes: 2, seconds: 1));
        await t.pump();
        expect(image(), findsNothing, reason: 'pixels dropped on expiry');
      }
      await settle(t);
      expect(find.byType(IntruderEvidenceScreen), findsNothing);
      expect(find.byType(IntruderEvidenceDetailScreen), findsNothing);
      expect(c.intruderOwnerSessions.current, isNull);
      // The timeline session ended before verification (W-06) and stays
      // ended: nothing from the timeline is reachable either.
      expectTimelineClosed();
      expect(imageFrames, greaterThan(0), reason: 'the photo was shown first');
    });
  }

  testWidgets(
      'C-11b foreign route pushed in the SAME turn the list snapshot '
      'completes (before any frame) ⇒ no detail is ever pushed or read',
      (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    db.gatedPrefixes.add(IntruderEvidenceStore.indexKey);
    db.gateSkip = 1; // enforceRetention passes; the snapshot read is gated
    db.gate = Completer<void>();
    await tapView(t);
    await typePin(t, _pin, settleAfter: false);
    await frames(t, 10);
    expect(find.byType(IntruderEvidenceScreen), findsOneWidget);
    expect(c.intruderOwnerSessions.current, isNotNull);
    final int start = db.reads.length;
    nav(t).push(MaterialPageRoute<void>(
        builder: (_) => const Scaffold(body: Text('lock challenge'))));
    db.release(); // no pump in between: the cover is not yet observed
    bool detailSeen = false;
    for (int i = 0; i < 40; i++) {
      await t.pump(const Duration(milliseconds: 16));
      if (find
          .byType(IntruderEvidenceDetailScreen, skipOffstage: false)
          .evaluate()
          .isNotEmpty) {
        detailSeen = true;
      }
    }
    expect(detailSeen, isFalse,
        reason: 'a detail was pushed above the foreign route');
    expect(
        db.reads.sublist(start).where(
            (String k) => k.startsWith(IntruderEvidenceStore.blobPrefix)),
        isEmpty);
    expect(find.text('lock challenge'), findsOneWidget);
    expect(ModalRoute.of(t.element(find.text('lock challenge')))!.isCurrent,
        isTrue,
        reason: 'the foreign route stays authoritative (top-most)');
    expect(c.intruderOwnerSessions.current, isNull);
    expectTimelineClosed();
    expect(imageFrames, 0);
  });

  testWidgets(
      'C-11 foreign route pushed while the list load is awaiting ⇒ no '
      'detail above it; the evidence session ends', (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    db.gatedPrefixes.add(IntruderEvidenceStore.indexKey);
    db.gate = Completer<void>();
    await tapView(t);
    // No pumpAndSettle while the list spinner runs (fake time would reach the
    // 2-minute evidence-session expiry and close the list vacuously).
    await typePin(t, _pin, settleAfter: false);
    await frames(t, 10);
    expect(find.byType(IntruderEvidenceScreen), findsOneWidget);
    expect(c.intruderOwnerSessions.current, isNotNull);
    nav(t).push(MaterialPageRoute<void>(
        builder: (_) => const Scaffold(body: Text('lock challenge'))));
    await t.pump();
    db.release();
    await frames(t, 40);
    expect(find.text('lock challenge'), findsOneWidget);
    expect(find.byType(IntruderEvidenceDetailScreen), findsNothing);
    expect(c.intruderOwnerSessions.current, isNull);
    expect(imageFrames, 0);
  });

  testWidgets(
      'F-12 setSecureWindow fails at the focused detail ⇒ no pixels '
      'in any frame', (WidgetTester t) async {
    await boot(t);
    await openToViewPhoto(t);
    await tapView(t, settleAfter: false);
    overlay().secureWindowFails = true;
    await settle(t);
    await typePin(t, _pin);
    expect(image(), findsNothing);
    expect(imageFrames, 0);
  });

  testWidgets(
      'F-CL-1 reproduced failure-log corruption + seq reuse: the new '
      'attempt group shows no outcome and no View photo; the pre-reset '
      'outcome is a detached row', (WidgetTester t) async {
    final int outSeq = await bootAfterLogReset(t);
    await openTimelineOnly(t);
    final Finder row =
        find.byKey(ValueKey<String>('security_timeline_entry_journal_$outSeq'));
    await t.scrollUntilVisible(row, 200,
        scrollable: find.byType(Scrollable).last);
    await settle(t);
    expect(
        find.descendant(
            of: row,
            matching:
                find.textContaining(SecurityTimelineText.detachedOutcome)),
        findsOneWidget);
    await tapScrolled(
        t,
        find.byKey(
            const ValueKey<String>('security_timeline_group_details_1')));
    expect(find.byType(SecurityTimelineDetailScreen), findsOneWidget);
    expect(
        find.byKey(const Key('security_timeline_detail_outcome_not_recorded')),
        findsOneWidget);
    expect(
        find.byKey(
            const ValueKey<String>('security_timeline_detail_view_photo_1')),
        findsNothing,
        reason: 'no photo is offered under the NEW attempts');
    expect(
        find.descendant(
            of: find.byType(SecurityTimelineDetailScreen),
            matching: find.text('Photo saved')),
        findsNothing);
    expect(imageFrames, 0);
  });

  // F-CL-1 metadata safety (2026-10-22 decision): ambiguous journal rows
  // offer no photo action, so they can never start a focusSeq lookup.
  bool evidenceRead(String k) =>
      k == IntruderEvidenceStore.indexKey ||
      k.startsWith(IntruderEvidenceStore.blobPrefix);

  testWidgets(
      'F-CL-1 detached captureSaved: no photo action and no focusSeq lookup '
      '(no evidence read); the independent verified Intruder photos list '
      'stays accessible and lists the photo', (WidgetTester t) async {
    final int outSeq = await bootAfterLogReset(t);
    await openTimelineOnly(t);
    final int start = db.reads.length;
    await tapScrolled(
        t,
        find.byKey(
            ValueKey<String>('security_timeline_entry_journal_$outSeq')));
    expect(find.byType(SecurityTimelineDetailScreen), findsOneWidget);
    expect(
        find.text('This event could not be matched to a failed attempt in the '
            'available history.'),
        findsOneWidget);
    expect(
        find.byKey(
            const ValueKey<String>('security_timeline_detail_view_photo_1')),
        findsNothing);
    expect(find.text(SecurityTimelineDetailText.viewPhoto), findsNothing);
    expect(
        find.descendant(
            of: find.byType(SecurityTimelineDetailScreen),
            matching: find.byType(TextButton)),
        findsNothing);
    expect(db.reads.sublist(start).where(evidenceRead), isEmpty,
        reason: 'the timeline never looks a photo up');
    expect(imageFrames, 0);
    // Close the timeline; the Phase 12 list is reached independently.
    nav(t).popUntil((Route<dynamic> r) => r.isFirst);
    await settle(t);
    expectTimelineClosed();
    late BuildContext launcher;
    nav(t).push(MaterialPageRoute<void>(builder: (BuildContext ctx) {
      launcher = ctx;
      return const Scaffold(body: Text('launcher'));
    }));
    await settle(t);
    unawaited(openIntruderEvidence(launcher, c));
    await settle(t);
    expect(imageFrames, 0, reason: 'no pixels before fresh verification');
    await typePin(t, _pin);
    expect(find.byType(IntruderEvidenceScreen), findsOneWidget);
    expect(find.byKey(const Key('intruder_evidence_item_1')), findsOneWidget);
    expect(overlay().secureWindow, isTrue);
    expect(c.intruderOwnerSessions.current, isNotNull);
  });

  testWidgets(
      'F-CL-1 failure-log recovery: an ATTACHED captureSaved for a new, '
      'never-reused seq still offers no photo action (identity ambiguous '
      'after recovery); no evidence read', (WidgetTester t) async {
    await bootAfterLogReset(t);
    // Owner success (ends the run; avoids the credential cooldown), then a
    // fresh attempt: post-reset seq 2, never used before the reset.
    expect((await c.auth.authenticatePin(_pin)).isSuccess, isTrue);
    await c.auth.authenticatePin('000000');
    await c.intruderMonitor.idle();
    c.securityJournal.recordEvent(
        SecurityJournalEventType.captureSaved, const CaptureSavedFields(2));
    await c.securityJournal.idle();
    final SecurityJournalView v = await c.securityJournal.read();
    expect(
        v.events.where((SecurityJournalEvent e) =>
            e.type == SecurityJournalEventType.captureSaved),
        hasLength(2),
        reason: 'the new outcome was stored (not a reused seq)');
    await t.pumpAndSettle();
    await openTimelineOnly(t);
    final int start = db.reads.length;
    await tapScrolled(
        t,
        find.byKey(
            const ValueKey<String>('security_timeline_group_details_2')));
    expect(find.byType(SecurityTimelineDetailScreen), findsOneWidget);
    expect(
        find.byKey(const Key('security_timeline_detail_outcome_not_recorded')),
        findsNothing,
        reason: 'the captureSaved IS attached to the new group');
    expect(
        find.byKey(
            const ValueKey<String>('security_timeline_detail_view_photo_2')),
        findsNothing);
    expect(find.text(SecurityTimelineDetailText.viewPhoto), findsNothing);
    expect(db.reads.sublist(start).where(evidenceRead), isEmpty);
    expect(imageFrames, 0);
  });
}
