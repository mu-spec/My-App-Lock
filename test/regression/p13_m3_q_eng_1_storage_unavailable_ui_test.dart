// P13/M3 Q-ENG-1 contract A §4.3: storage-unavailable regression (reader +
// widget). Previously, a monitor that had already read the log returned its
// CACHED copy when a later read failed. Now a failed authoritative read is
// "unavailable": the timeline must say the history couldn't be read. It
// must never show stale entries as current and never claim "no events".
// lastKnown() is the only stale accessor and is explicitly labelled.
//
// SIMULATED: real app widgets over AppContainer.inMemory. Key handling here
// is the normal enrolled state (the key exists because a PIN was enrolled),
// not a first-launch test.
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';
import 'package:smart_app_lock/services/impl/static_intruder_evidence_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_screen.dart';

const String _pin = '482917';

/// Read faults on the failure-log row only (reads are not CAS; CAS-G2's
/// setSetting inventory is unaffected).
class _LogReadFaultDb extends InMemoryLocalDatabase {
  bool failLogReads = false;

  @override
  Future<String?> getSetting(String key) async {
    if (failLogReads && key == IntruderFailureLogStore.storageKey) {
      throw StateError('log read fault');
    }
    return super.getSetting(key);
  }
}

void main() {
  late AppContainer c;
  late _LogReadFaultDb db;

  Future<void> boot(WidgetTester t) async {
    db = _LogReadFaultDb();
    c = AppContainer.inMemory(
      intruderEvidence: StaticIntruderEvidenceService(),
      database: db,
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

  testWidgets('reader: recorded failures, then the log becomes unreadable '
      '-> unavailableUnreadable, no stale entries; recovers', (t) async {
    await boot(t);
    SecurityTimelineSnapshot s = await c.securityTimeline.load();
    expect(s.sources[0].state, TimelineSourceState.available);
    expect(
        s.entries.where(
            (TimelineEntry e) => e.source == TimelineSource.failedAttempts),
        hasLength(2));

    db.failLogReads = true;
    s = await c.securityTimeline.load();
    expect(s.sources[0].state, TimelineSourceState.unavailableUnreadable,
        reason: 'never the cached copy (Q-ENG-1 §4.3)');
    expect(
        s.entries.where(
            (TimelineEntry e) => e.source == TimelineSource.failedAttempts),
        isEmpty);
    expect(s.confirmedEmpty, isFalse);
    expect(s.hasGaps, isTrue);
    final IntruderLastKnown? last = c.intruderMonitor.lastKnown();
    expect(last!.stale, isTrue);
    expect(last.log.events, hasLength(2));

    db.failLogReads = false;
    s = await c.securityTimeline.load();
    expect(s.sources[0].state, TimelineSourceState.available);
    expect(
        s.entries.where(
            (TimelineEntry e) => e.source == TimelineSource.failedAttempts),
        hasLength(2));
  });

  testWidgets('screen: an unreadable failure log shows "couldn\'t be read", '
      'never the empty claim', (t) async {
    await boot(t);
    db.failLogReads = true;
    late BuildContext launcher;
    t.state<NavigatorState>(find.byType(Navigator).first).push(
      MaterialPageRoute<void>(builder: (BuildContext ctx) {
        launcher = ctx;
        return const Scaffold(body: Text('launcher'));
      }),
    );
    await t.pumpAndSettle();
    unawaited(openSecurityTimeline(launcher, c));
    await t.pumpAndSettle();
    expect(find.byType(PinUnlockScreen), findsOneWidget);
    for (final String d in _pin.split('')) {
      await t.tap(find.byKey(Key('pin_key_$d')));
      await t.pump(const Duration(milliseconds: 50));
    }
    await t.pumpAndSettle();
    expect(find.byType(SecurityTimelineScreen), findsOneWidget);
    await t.pumpAndSettle();
    expect(
      find.text(SecurityTimelineText.unavailable(
          TimelineSource.failedAttempts,
          TimelineSourceState.unavailableUnreadable)),
      findsOneWidget,
    );
    expect(find.text(SecurityTimelineText.empty), findsNothing);
    expect(c.intruderMonitor.status.health,
        IntruderMonitorHealth.storageError);
  });
}
