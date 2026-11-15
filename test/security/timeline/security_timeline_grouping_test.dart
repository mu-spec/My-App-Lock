// Phase 13 / M2 — T4: presentation grouping (U-20…U-23, G-P1, R-P2).
//
// SIMULATED: pure Dart; seeded pseudo-random property tests.

import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';
import 'package:smart_app_lock/security/timeline/security_timeline_grouping.dart';

final DateTime _t0 = DateTime(2026, 10, 22, 12);

TimelineEntry fail(int seq, int run,
        {Duration after = Duration.zero,
        DateTime? at,
        String? pkg = 'com.bank',
        bool lockout = false,
        bool persisted = true}) =>
    TimelineEntry(
      source: TimelineSource.failedAttempts,
      sourceSeq: seq,
      at: at ?? _t0.add(after),
      kind: TimelineEntryKind.failedUnlock,
      method: FailedAttemptMethod.pin,
      surface: AuthAttemptSurface.protectedAppChallenge,
      packageName: pkg,
      consecutiveFailures: run,
      lockoutTriggered: lockout,
      persisted: persisted,
    );

TimelineEntry outcome(int seq, TimelineEntryKind kind, int? trig,
        {Duration after = Duration.zero}) =>
    TimelineEntry(
      source: TimelineSource.journal,
      sourceSeq: seq,
      at: _t0.add(after),
      kind: kind,
      trig: trig,
    );

List<TimelineEntry> sorted(List<TimelineEntry> e) =>
    List<TimelineEntry>.of(e)..sort(SecurityTimelineReader.compare);

List<TimelineFailureGroup> groups(List<TimelineRow> rows) =>
    rows.whereType<TimelineFailureGroup>().toList();

void main() {
  group('U-20 grouping table', () {
    const Duration m = Duration(minutes: 1);
    test(
        'consecutive seq + run + ≤ 15 min ⇒ one group (mixed packages and a '
        'lockout inside)', () {
      final List<TimelineRow> rows = buildTimelineRows(sorted(<TimelineEntry>[
        fail(1, 1),
        fail(2, 2, after: m, pkg: 'com.mail'),
        fail(3, 3, after: m * 2, lockout: true),
      ]));
      final List<TimelineFailureGroup> g = groups(rows);
      expect(g.length, 1);
      expect(g.single.count, 3);
      expect(g.single.packages.toSet(), <String>{'com.bank', 'com.mail'});
      expect(g.single.lockouts, 1);
      expect(g.single.lastSeq, 3);
      expect(g.single.firstSeq, 1);
    });

    test('seq gap splits', () {
      final List<TimelineRow> rows = buildTimelineRows(sorted(<TimelineEntry>[
        fail(1, 1),
        fail(3, 2, after: m),
      ]));
      expect(groups(rows).length, 2);
    });

    test('run reset splits', () {
      final List<TimelineRow> rows = buildTimelineRows(sorted(<TimelineEntry>[
        fail(1, 1),
        fail(2, 1, after: m),
      ]));
      expect(groups(rows).length, 2);
    });

    test('> 15 min splits; exactly 15 min joins', () {
      expect(
          groups(buildTimelineRows(sorted(<TimelineEntry>[
            fail(1, 1),
            fail(2, 2, after: const Duration(minutes: 15, seconds: 1)),
          ]))).length,
          2);
      expect(
          groups(buildTimelineRows(sorted(<TimelineEntry>[
            fail(1, 1),
            fail(2, 2, after: const Duration(minutes: 15)),
          ]))).length,
          1);
    });

    test('backwards clock splits', () {
      expect(
          groups(buildTimelineRows(sorted(<TimelineEntry>[
            fail(1, 1),
            fail(2, 2, after: -m),
          ]))).length,
          2);
    });
  });

  group('U-21 / U-22', () {
    test('N is the row count, never the run (stale run starting at 4)', () {
      final TimelineFailureGroup g = groups(buildTimelineRows(
          sorted(<TimelineEntry>[
        fail(10, 4),
        fail(11, 5, after: const Duration(seconds: 5))
      ]))).single;
      expect(g.count, 2);
      expect(g.attempts.first.consecutiveFailures, 5);
    });

    test('persisted = false on any attempt ⇒ group flag', () {
      final TimelineFailureGroup g = groups(buildTimelineRows(sorted(
          <TimelineEntry>[fail(1, 1), fail(2, 2, persisted: false)]))).single;
      expect(g.counterNotSaved, isTrue);
      final TimelineFailureGroup ok = groups(buildTimelineRows(
          sorted(<TimelineEntry>[fail(1, 1), fail(2, 2)]))).single;
      expect(ok.counterNotSaved, isFalse);
    });
  });

  group('U-23 outcome attachment', () {
    test('an outcome whose trig is in a group is attached only', () {
      final List<TimelineRow> rows = buildTimelineRows(sorted(<TimelineEntry>[
        fail(1, 1),
        fail(2, 2),
        outcome(5, TimelineEntryKind.captureSaved, 2),
        outcome(6, TimelineEntryKind.alarmStarted, 2),
      ]));
      final TimelineFailureGroup g = groups(rows).single;
      expect(g.outcomes.map((TimelineEntry e) => e.sourceSeq), <int>[5, 6]);
      expect(g.has(TimelineEntryKind.captureSaved), isTrue);
      expect(rows.whereType<TimelineEntryRow>(), isEmpty);
    });

    test('trigger missing / failure log unavailable ⇒ standalone, detached',
        () {
      final List<TimelineRow> rows = buildTimelineRows(sorted(<TimelineEntry>[
        outcome(5, TimelineEntryKind.captureNotSaved, 99),
        outcome(6, TimelineEntryKind.alarmStopped, null),
      ]));
      final List<TimelineEntryRow> e =
          rows.whereType<TimelineEntryRow>().toList();
      expect(e.length, 2);
      expect(e.where((TimelineEntryRow r) => r.detachedOutcome).length, 1);
      expect(groups(rows), isEmpty);
    });

    test(
        'visibleRowCount counts every entry of a group (no overflow '
        'hidden behind the page size)', () {
      final List<TimelineRow> rows = buildTimelineRows(sorted(<TimelineEntry>[
        fail(1, 1),
        fail(2, 2),
        fail(3, 3),
        outcome(9, TimelineEntryKind.journalStarted, null,
            after: const Duration(hours: -1)),
      ]));
      expect(rows.length, 2);
      expect(visibleRowCount(rows, 1), 1);
      expect(visibleRowCount(rows, 3), 1);
      expect(visibleRowCount(rows, 4), 2);
    });
  });

  group('F-CL-1 outcome association guard', () {
    const Duration window = SecurityTimelineGrouping.maxOutcomeDelay;
    const Duration ms = Duration(milliseconds: 1);

    TimelineEntry out(int seq, TimelineEntryKind kind, int trig, DateTime at,
            {bool clockBack = false}) =>
        TimelineEntry(
          source: TimelineSource.journal,
          sourceSeq: seq,
          at: at,
          kind: kind,
          trig: trig,
          clockBack: clockBack,
        );

    void expectOnce(List<TimelineEntry> all, List<TimelineRow> rows) {
      final List<int> rendered = <int>[
        for (final TimelineRow row in rows)
          if (row is TimelineEntryRow)
            row.entry.sourceSeq
          else if (row is TimelineFailureGroup)
            ...row.outcomes.map((TimelineEntry e) => e.sourceSeq),
      ];
      final List<int> journal = all
          .where((TimelineEntry e) => e.source == TimelineSource.journal)
          .map((TimelineEntry e) => e.sourceSeq)
          .toList();
      expect(rendered..sort(), journal..sort());
    }

    test(
        'F-CL-1a failure-log reinitialization (seq reuse): the pre-reset '
        'outcome is NOT attached to the new attempts; detached row instead',
        () {
      // Reproduces PROBE-P10: old attempts 0,1 quarantined; the journal kept
      // captureSaved(trig 1); the new log restarts at 0 one hour later.
      final DateTime reset = _t0.add(const Duration(hours: 1));
      final List<TimelineEntry> all = sorted(<TimelineEntry>[
        fail(0, 1, at: reset),
        fail(1, 2, at: reset.add(const Duration(seconds: 12))),
        out(7, TimelineEntryKind.captureSaved, 1,
            _t0.add(const Duration(seconds: 3))),
        out(8, TimelineEntryKind.alarmStarted, 1,
            _t0.add(const Duration(seconds: 1))),
      ]);
      final List<TimelineRow> rows = buildTimelineRows(all);
      final TimelineFailureGroup g = groups(rows).single;
      expect(g.attempts.map((TimelineEntry e) => e.sourceSeq), <int>[1, 0]);
      expect(g.outcomes, isEmpty);
      expect(g.has(TimelineEntryKind.captureSaved), isFalse);
      final List<TimelineEntryRow> standalone =
          rows.whereType<TimelineEntryRow>().toList();
      expect(standalone.map((TimelineEntryRow r) => r.entry.sourceSeq).toSet(),
          <int>{7, 8});
      expect(
          standalone.every((TimelineEntryRow r) => r.detachedOutcome), isTrue);
      expectOnce(all, rows);
    });

    test(
        'F-CL-1b old captureSaved followed by a NEW attempt with the same seq '
        '1 ms later ⇒ detached (never earlier than its attempt)', () {
      final List<TimelineEntry> all = sorted(<TimelineEntry>[
        out(3, TimelineEntryKind.captureSaved, 4, _t0),
        fail(4, 1, at: _t0.add(ms)),
      ]);
      final List<TimelineRow> rows = buildTimelineRows(all);
      expect(groups(rows).single.outcomes, isEmpty);
      expect(rows.whereType<TimelineEntryRow>().single.detachedOutcome, isTrue);
      expectOnce(all, rows);
    });

    test(
        'F-CL-1c window: equal time and exactly maxOutcomeDelay attach; '
        'window + 1 ms is detached', () {
      final List<TimelineEntry> all = sorted(<TimelineEntry>[
        fail(1, 1),
        fail(2, 2, after: const Duration(minutes: 1)),
        out(5, TimelineEntryKind.alarmStarted, 1, _t0),
        out(6, TimelineEntryKind.captureSaved, 1, _t0.add(window)),
        out(7, TimelineEntryKind.captureNotSaved, 2,
            _t0.add(const Duration(minutes: 1)).add(window).add(ms)),
      ]);
      final List<TimelineRow> rows = buildTimelineRows(all);
      final TimelineFailureGroup g = groups(rows).single;
      expect(g.outcomes.map((TimelineEntry e) => e.sourceSeq), <int>[5, 6]);
      final TimelineEntryRow d = rows.whereType<TimelineEntryRow>().single;
      expect(d.entry.sourceSeq, 7);
      expect(d.detachedOutcome, isTrue);
      expect(window, const Duration(minutes: 5));
      expectOnce(all, rows);
    });

    test(
        'F-CL-1d clock rollback: an outcome stamped before its attempt '
        '(clockBack) is detached, never attached', () {
      final List<TimelineEntry> all = sorted(<TimelineEntry>[
        fail(1, 1, after: const Duration(minutes: 10)),
        out(5, TimelineEntryKind.captureSaved, 1,
            _t0.add(const Duration(minutes: 2)),
            clockBack: true),
      ]);
      final List<TimelineRow> rows = buildTimelineRows(all);
      expect(groups(rows).single.outcomes, isEmpty);
      expect(rows.whereType<TimelineEntryRow>().single.detachedOutcome, isTrue);
      expectOnce(all, rows);
    });

    test(
        'F-CL-1e clock forward jump: an outcome stamped hours after its '
        'attempt is detached', () {
      final List<TimelineEntry> all = sorted(<TimelineEntry>[
        fail(1, 1),
        out(5, TimelineEntryKind.alarmNotStarted, 1,
            _t0.add(const Duration(hours: 3))),
      ]);
      final List<TimelineRow> rows = buildTimelineRows(all);
      expect(groups(rows).single.outcomes, isEmpty);
      expect(rows.whereType<TimelineEntryRow>().single.detachedOutcome, isTrue);
      expectOnce(all, rows);
    });

    test('F-CL-1f outcomeMatchesAttempt: null attempt ⇒ false (no search)', () {
      expect(
          outcomeMatchesAttempt(
              null, out(1, TimelineEntryKind.captureSaved, 1, _t0)),
          isFalse);
    });

    test(
        'F-CL-1g property: 300 seeded fixtures ⇒ every attached outcome is '
        'within [attempt.at, attempt.at + window]; all rendered once', () {
      final Random r = Random(1313);
      for (int s = 0; s < 300; s++) {
        final List<TimelineEntry> all = <TimelineEntry>[];
        final int n = 1 + r.nextInt(8);
        for (int i = 0; i < n; i++) {
          all.add(fail(i, i + 1, after: Duration(minutes: i)));
        }
        for (int j = 0; j < 1 + r.nextInt(10); j++) {
          all.add(out(100 + j, TimelineEntryKind.captureSaved, r.nextInt(n + 2),
              _t0.add(Duration(seconds: r.nextInt(1200) - 600))));
        }
        final List<TimelineEntry> sortedAll = sorted(all);
        final List<TimelineRow> rows = buildTimelineRows(sortedAll);
        for (final TimelineFailureGroup g in groups(rows)) {
          for (final TimelineEntry o in g.outcomes) {
            final TimelineEntry a = g.attempts
                .singleWhere((TimelineEntry e) => e.sourceSeq == o.trig);
            expect(o.at.isBefore(a.at), isFalse, reason: 'seed $s');
            expect(o.at.difference(a.at) <= window, isTrue, reason: 'seed $s');
          }
        }
        expectOnce(sortedAll, rows);
      }
    });
  });

  group('F-CL-1 metadata safety: photo action', () {
    TimelineSourceStatus src(TimelineSource s, bool? damaged) =>
        TimelineSourceStatus(
          source: s,
          state: TimelineSourceState.available,
          discarded: 0,
          lost: 0,
          damagedEarlier: damaged,
        );

    SecurityTimelineSnapshot snap(bool? failuresDamaged,
            {bool? journalDamaged = false, bool withFailures = true}) =>
        SecurityTimelineSnapshot(
            entries: const <TimelineEntry>[],
            sources: <TimelineSourceStatus>[
              if (withFailures)
                src(TimelineSource.failedAttempts, failuresDamaged),
              src(TimelineSource.journal, journalDamaged),
            ]);

    test(
        'PA-1 failureLogDamagedEarlier reads ONLY the failed-attempt source; '
        'missing source ⇒ null (unknown)', () {
      expect(
          failureLogDamagedEarlier(snap(false, journalDamaged: true)), isFalse);
      expect(failureLogDamagedEarlier(snap(true)), isTrue);
      expect(failureLogDamagedEarlier(snap(null)), isNull);
      expect(
          failureLogDamagedEarlier(snap(false, withFailures: false)), isNull);
    });

    test(
        'PA-2 only an ATTACHED captureSaved with an undamaged failure log '
        'gets a photo action; recovered / unknown / detached / other kinds '
        '/ foreign outcomes never do (no focusSeq lookup)', () {
      final List<TimelineEntry> all = sorted(<TimelineEntry>[
        fail(0, 1),
        fail(1, 2, after: const Duration(seconds: 1)),
        outcome(10, TimelineEntryKind.captureSaved, 1,
            after: const Duration(seconds: 3)),
        outcome(11, TimelineEntryKind.alarmStarted, 1,
            after: const Duration(seconds: 4)),
        // Detached: stamped before its attempt (pre-reset epoch).
        outcome(12, TimelineEntryKind.captureSaved, 0,
            after: const Duration(seconds: -30)),
      ]);
      final List<TimelineRow> rows = buildTimelineRows(all);
      final TimelineFailureGroup g = groups(rows).single;
      final TimelineEntry saved =
          g.outcomes.singleWhere((TimelineEntry e) => e.sourceSeq == 10);
      final TimelineEntry alarm =
          g.outcomes.singleWhere((TimelineEntry e) => e.sourceSeq == 11);
      final TimelineEntryRow detached = rows
          .whereType<TimelineEntryRow>()
          .singleWhere((TimelineEntryRow r) => r.entry.sourceSeq == 12);
      expect(detached.detachedOutcome, isTrue);

      expect(timelinePhotoActionAllowed(g, saved, failureLogDamaged: false),
          isTrue);
      expect(timelinePhotoActionAllowed(g, saved, failureLogDamaged: true),
          isFalse,
          reason: 'failure-log recovery: seqs may have been reused');
      expect(timelinePhotoActionAllowed(g, saved, failureLogDamaged: null),
          isFalse,
          reason: 'unknown recovery state fails closed');
      expect(
          timelinePhotoActionAllowed(detached, detached.entry,
              failureLogDamaged: false),
          isFalse,
          reason: 'detached rows are ambiguous');
      expect(timelinePhotoActionAllowed(g, alarm, failureLogDamaged: false),
          isFalse);
      expect(
          timelinePhotoActionAllowed(g, detached.entry,
              failureLogDamaged: false),
          isFalse,
          reason: 'an outcome not attached to THIS group');
      final TimelineEntry copy = outcome(10, TimelineEntryKind.captureSaved, 1,
          after: const Duration(seconds: 3));
      expect(timelinePhotoActionAllowed(g, copy, failureLogDamaged: false),
          isFalse,
          reason: 'identity, never equality by fields');
    });

    test(
        'PA-3 property: over 300 seeded fixtures no detached row and no '
        'damaged/unknown history ever yields a photo action', () {
      final Random rnd = Random(4242);
      for (int it = 0; it < 300; it++) {
        final List<TimelineEntry> e = <TimelineEntry>[];
        int seq = 0;
        Duration at = Duration.zero;
        for (int i = 0; i < 1 + rnd.nextInt(6); i++) {
          e.add(fail(seq, i + 1, after: at));
          seq++;
          at += Duration(seconds: 1 + rnd.nextInt(20));
        }
        for (int j = 0; j < 1 + rnd.nextInt(4); j++) {
          e.add(outcome(
              100 + j,
              rnd.nextBool()
                  ? TimelineEntryKind.captureSaved
                  : TimelineEntryKind.captureNotSaved,
              rnd.nextInt(seq + 2),
              after: Duration(seconds: rnd.nextInt(900) - 300)));
        }
        final List<TimelineRow> rows = buildTimelineRows(sorted(e));
        for (final TimelineRow r in rows) {
          final List<TimelineEntry> outs = switch (r) {
            TimelineFailureGroup() => r.outcomes,
            TimelineEntryRow() => <TimelineEntry>[r.entry],
          };
          for (final TimelineEntry o in outs) {
            for (final bool? d in <bool?>[true, null]) {
              expect(timelinePhotoActionAllowed(r, o, failureLogDamaged: d),
                  isFalse);
            }
            if (r is TimelineEntryRow) {
              expect(timelinePhotoActionAllowed(r, o, failureLogDamaged: false),
                  isFalse);
            }
          }
        }
      }
    });
  });

  group('properties', () {
    test(
        'G-P1: 500 seeded failure streams ⇒ every failure in exactly one '
        'group; groups ordered newest first and internally contiguous', () {
      final Random r = Random(1302);
      for (int s = 0; s < 500; s++) {
        final List<TimelineEntry> fs = <TimelineEntry>[];
        int seq = r.nextInt(5);
        int run = 0;
        DateTime at = _t0;
        final int n = 1 + r.nextInt(25);
        for (int i = 0; i < n; i++) {
          seq += r.nextInt(10) == 0 ? 2 : 1;
          run = r.nextInt(8) == 0 ? 1 : run + 1;
          at = at
              .add(Duration(minutes: r.nextInt(10) == 0 ? -3 : r.nextInt(20)));
          fs.add(fail(seq, run, at: at, pkg: r.nextBool() ? 'a' : null));
        }
        final List<TimelineRow> rows = buildTimelineRows(sorted(fs));
        final List<int> seen = <int>[
          for (final TimelineFailureGroup g in groups(rows))
            ...g.attempts.map((TimelineEntry e) => e.sourceSeq),
        ];
        expect(seen.length, fs.length, reason: 'seed $s');
        expect(seen.toSet(), fs.map((TimelineEntry e) => e.sourceSeq).toSet());
        for (final TimelineFailureGroup g in groups(rows)) {
          for (int i = 1; i < g.attempts.length; i++) {
            expect(g.attempts[i - 1].sourceSeq, g.attempts[i].sourceSeq + 1);
          }
        }
        for (int i = 1; i < rows.length; i++) {
          expect(
              SecurityTimelineReader.compare(
                  rows[i - 1].anchor, rows[i].anchor),
              lessThanOrEqualTo(0));
        }
      }
    });

    test(
        'R-P2: random journal + failure fixtures ⇒ every journal event is '
        'rendered exactly once (attached XOR standalone)', () {
      final Random r = Random(2026);
      const List<TimelineEntryKind> kinds = <TimelineEntryKind>[
        TimelineEntryKind.captureSaved,
        TimelineEntryKind.captureNotSaved,
        TimelineEntryKind.alarmStarted,
        TimelineEntryKind.alarmNotStarted,
        TimelineEntryKind.alarmStopped,
        TimelineEntryKind.protectionHealth,
        TimelineEntryKind.storageUnavailable,
      ];
      for (int s = 0; s < 300; s++) {
        final List<TimelineEntry> all = <TimelineEntry>[];
        for (int i = 1; i <= 1 + r.nextInt(12); i++) {
          all.add(fail(i, i, after: Duration(minutes: i)));
        }
        for (int j = 0; j < r.nextInt(15); j++) {
          final TimelineEntryKind k = kinds[r.nextInt(kinds.length)];
          final bool hasTrig =
              k.index <= TimelineEntryKind.alarmNotStarted.index &&
                  k.index >= TimelineEntryKind.captureSaved.index;
          all.add(outcome(100 + j, k, hasTrig ? r.nextInt(20) : null,
              after: Duration(minutes: r.nextInt(30))));
        }
        final List<TimelineRow> rows = buildTimelineRows(sorted(all));
        final List<int> rendered = <int>[
          for (final TimelineRow row in rows)
            if (row is TimelineEntryRow)
              row.entry.sourceSeq
            else if (row is TimelineFailureGroup)
              ...row.outcomes.map((TimelineEntry e) => e.sourceSeq),
        ];
        final List<int> journal = all
            .where((TimelineEntry e) => e.source == TimelineSource.journal)
            .map((TimelineEntry e) => e.sourceSeq)
            .toList();
        expect(rendered.length, journal.length, reason: 'seed $s');
        expect(rendered.toSet(), journal.toSet());
      }
    });
  });
}
