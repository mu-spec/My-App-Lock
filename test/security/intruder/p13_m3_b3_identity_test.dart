// P13/M3 Batch 3 — generation-aware event identity: gate tests.
//
// B2 §6 / P4 §5: G-1..G-7 (failure-log generation lifecycle), GI-1..GI-7
// (identity linkage across failure log, journal, evidence and timeline),
// MIG-1..MIG-4 (lazy migration, no write-only migration, newer documents
// byte-identical) and the evidence / journal rows of the downgrade matrix
// (DG-E*, DG-J*), using the verbatim pre-Batch-3 code in legacy_t3/.
// Failure-log downgrade / process death: p13_m3_b3_downgrade_test.dart.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_coordinator.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_settings.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_service.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/intruder/log_generation.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/timeline/intruder_outcome_journal_adapter.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';
import 'package:smart_app_lock/security/timeline/security_timeline_grouping.dart';

import '../../support/intruder_fixtures.dart';
import 'legacy_t3/failed_attempt_event.dart' as oldf;
import 'legacy_t3/intruder_evidence_store.dart' as olde;
import 'legacy_t3/security_event_journal.dart' as oldj;
import 'legacy_t3/security_event_journal_store.dart' as oldj;
import 'legacy_t3/security_journal_event.dart' as oldj;

const String _g0 = 'Gen0__________________';
const String _g1 = 'Gen1__________________';
const String _g2 = 'Gen2__________________';
const String _logKey = IntruderFailureLogStore.storageKey;

final DateTime _t0 = DateTime(2026, 10, 22, 12);
int _vid = 0;

VerifiedAttempt _fail([String? vid]) => VerifiedAttempt(
      verificationId: vid ?? 'id:${++_vid}',
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
          reason: AuthFailureReason.wrongCredential, remainingAttempts: 2),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

VerifiedAttempt _ok() => VerifiedAttempt(
      verificationId: 'id:${++_vid}',
      type: AuthType.pin,
      matched: true,
      result: const AuthSuccess(type: AuthType.pin),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

FailedAttemptEvent _ev(int seq, String? gen, {int run = 1}) =>
    FailedAttemptEvent(
      seq: seq,
      verificationId: 'p:$gen:$seq',
      at: _t0,
      method: FailedAttemptMethod.pin,
      surface: AuthAttemptSurface.protectedAppChallenge,
      consecutiveFailures: run,
      lockoutTriggered: false,
      lockoutStreak: 0,
      counterPersisted: true,
      packageName: 'com.bank',
      logGen: gen,
    );

String Function() _mints(List<String> ids) {
  final List<String> q = List<String>.of(ids);
  return () => q.isEmpty ? throw StateError('unexpected mint') : q.removeAt(0);
}

/// Failure-log CAS fault: the next CAS throws an unknown outcome WITHOUT
/// committing.
class _UnknownOnceDb extends InMemoryLocalDatabase {
  bool unknownNext = false;

  @override
  Future<CasOutcome> compareAndSetSetting(
    String key, {
    required String? expected,
    required String next,
  }) async {
    if (key == _logKey && unknownNext) {
      unknownNext = false;
      throw const CasUnknownOutcome(CasUnknownCode.io);
    }
    return super.compareAndSetSetting(key, expected: expected, next: next);
  }
}

SettingsCipher _cipher() => AesGcmSettingsCipher(InMemorySecretStore(),
    database: InMemoryLocalDatabase());

class _Outcomes implements IntruderOutcomeObserver {
  final List<IntruderOutcome> got = <IntruderOutcome>[];
  @override
  void onIntruderOutcome(IntruderOutcome o) => got.add(o);
}

void main() {
  // ---------------------------------------------------------------------
  group('G: failure-log generation lifecycle (P4 §5)', () {
    late _UnknownOnceDb db;
    late SettingsCipher cipher;
    setUp(() {
      db = _UnknownOnceDb();
      cipher = _cipher();
    });
    IntruderMonitor mon(List<String> mints) => IntruderMonitor(
        store: IntruderFailureLogStore(db, cipher: cipher),
        now: () => _t0,
        mintGeneration: _mints(mints));
    Future<IntruderFailureLog> durable() async =>
        ((await IntruderFailureLogStore(db, cipher: cipher).read())
                as IntruderLogLoaded)
            .log;
    Future<String> plain() async =>
        cipher.decryptString((await db.getSetting(_logKey))!.substring(7));

    test('G-1 two engines from Missing: exactly one gen persisted, both adopt',
        () async {
      final IntruderMonitor a = mon(<String>[_g1, _g0]);
      final IntruderMonitor b = mon(<String>[_g2, _g0]);
      a.onVerifiedAttempt(_fail('A'));
      b.onVerifiedAttempt(_fail('B'));
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      final IntruderFailureLog l = await durable();
      expect(<String>[_g1, _g2], contains(l.gen));
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toSet(),
          <String>{'A', 'B'});
      expect(
          l.events.every((FailedAttemptEvent e) => e.logGen == l.gen), isTrue);
      expect(await plain(), isNot(contains(l.gen == _g1 ? _g2 : _g1)));
      expect(await plain(), isNot(contains(_g0)));
    });

    test(
        'G-2 corrupt + concurrent repair: one CAS wins, the loser adopts its '
        'gen, the corrupt bytes are quarantined once', () async {
      await db.setSetting(
          _logKey, 'enc:v1:${await cipher.encryptString('{x')}');
      final String corrupt = (await db.getSetting(_logKey))!;
      final IntruderMonitor a = mon(<String>[_g1, _g0]);
      final IntruderMonitor b = mon(<String>[_g2, _g0]);
      a.onVerifiedAttempt(_fail('A'));
      b.onVerifiedAttempt(_fail('B'));
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      expect(
          await db.getSetting(IntruderFailureLogStore.quarantineKey), corrupt);
      final IntruderFailureLog l = await durable();
      expect(<String>[_g1, _g2], contains(l.gen));
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toSet(),
          <String>{'A', 'B'});
    });

    test(
        'G-3 unknown-then-not-confirmed: the attempt is dropped, the minted '
        'gen is never used; the next write mints and commits a new one',
        () async {
      final IntruderMonitor a = mon(<String>[_g1, _g2]);
      db.unknownNext = true;
      a.onVerifiedAttempt(_fail('LOST'));
      await a.idle();
      expect(await db.getSetting(_logKey), isNull);
      expect(a.status.health, IntruderMonitorHealth.storageError);
      a.onVerifiedAttempt(_fail('N1'));
      await a.idle();
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g2);
      expect(await plain(), isNot(contains(_g1)));
      expect(await plain(), isNot(contains('LOST')));
    });

    test('G-4 an Unsupported (newer) log never triggers G-NEW; bytes unchanged',
        () async {
      final String newer =
          'enc:v1:${await cipher.encryptString(jsonEncode(<String, Object?>{
            'schema': IntruderFailureLog.schema,
            'v': 3,
            'gen': _g0,
          }))}';
      await db.setSetting(_logKey, newer);
      final IntruderMonitor a = mon(const <String>[]); // a mint would throw
      a.onVerifiedAttempt(_fail());
      a.onVerifiedAttempt(_ok());
      await a.idle();
      expect(await db.getSetting(_logKey), newer);
      expect(a.generationsMinted, 0);
      expect(a.status.health, IntruderMonitorHealth.readOnly);
    });

    test('G-7 an owner success (reset*) keeps the generation', () async {
      final IntruderMonitor a = mon(<String>[_g1]);
      a.onVerifiedAttempt(_fail());
      a.onVerifiedAttempt(_fail());
      a.onVerifiedAttempt(_ok());
      a.onVerifiedAttempt(_fail());
      await a.idle();
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g1);
      expect(l.consecutiveFailures, 1);
      expect(a.generationsMinted, 1);
    });
  });

  // ---------------------------------------------------------------------
  group('GI: identity linkage (B2 §6)', () {
    late InMemoryLocalDatabase db;
    late SettingsCipher cipher;
    late IntruderEvidenceStore store;
    setUp(() {
      db = InMemoryLocalDatabase();
      cipher = _cipher();
      store = IntruderEvidenceStore(db, cipher, now: () => _t0);
    });

    Uint8List jpeg([int fill = 0x11]) => jpegWithMetadata(fill: fill);

    test(
        'GI-1 old evidence (g0,5) is never the evidence of the new attempt '
        '(g1,5): not contained, not readable, not attachable', () async {
      expect(await store.save(seq: 5, gen: _g0, jpeg: jpeg()),
          EvidenceSaveResult.saved);
      expect(await store.contains(5, gen: _g0), isTrue);
      expect(await store.contains(5, gen: _g1), isFalse);
      expect(await store.contains(5), isFalse, reason: 'legacy space differs');
      expect(await store.readImage(5, gen: _g1), isNull);
      expect(await store.readImage(5), isNull);
      expect(await store.readImage(5, gen: _g0), isNotNull);
      // Timeline: an outcome for (g0,5) never attaches to attempt (g1,5).
      final List<TimelineRow> rows = buildTimelineRows(<TimelineEntry>[
        _outcome(10, trig: 5, tgen: _g0),
        _attempt(5, gen: _g1),
      ]);
      final TimelineFailureGroup g =
          rows.whereType<TimelineFailureGroup>().single;
      expect(g.outcomes, isEmpty);
      expect(rows.whereType<TimelineEntryRow>().single.detachedOutcome, isTrue);
    });

    test(
        'GI-1b a legacy outcome never attaches to a generation attempt, and '
        'a generation outcome never to a legacy attempt', () {
      for (final (String? og, String? ag) in <(String?, String?)>[
        (null, _g1),
        (_g1, null),
        (_g0, _g1),
      ]) {
        final List<TimelineRow> rows = buildTimelineRows(<TimelineEntry>[
          _outcome(10, trig: 5, tgen: og),
          _attempt(5, gen: ag),
        ]);
        expect(rows.whereType<TimelineFailureGroup>().single.outcomes, isEmpty,
            reason: 'outcome $og vs attempt $ag');
      }
    });

    test(
        'GI-1c an exact EID match attaches WITHOUT the 5-minute window; a '
        'legacy pair keeps the window', () {
      final DateTime late = _t0.add(const Duration(hours: 3));
      final List<TimelineRow> gen = buildTimelineRows(<TimelineEntry>[
        _outcome(10, trig: 5, tgen: _g1, at: late),
        _attempt(5, gen: _g1),
      ]);
      expect(
          gen.whereType<TimelineFailureGroup>().single.outcomes, hasLength(1));
      final List<TimelineRow> legacy = buildTimelineRows(<TimelineEntry>[
        _outcome(10, trig: 5, at: late),
        _attempt(5),
      ]);
      expect(legacy.whereType<TimelineFailureGroup>().single.outcomes, isEmpty,
          reason: 'F-CL-1 window unchanged for legacy rows');
      final List<TimelineRow> legacyOk = buildTimelineRows(<TimelineEntry>[
        _outcome(10, trig: 5, at: _t0.add(const Duration(minutes: 1))),
        _attempt(5),
      ]);
      expect(legacyOk.whereType<TimelineFailureGroup>().single.outcomes,
          hasLength(1));
    });

    test(
        'GI-1d a failure run never spans identity spaces (retained legacy '
        'events followed by generation events with contiguous seqs)', () {
      TimelineEntry at(int seq, String? gen, int run) => TimelineEntry(
            source: TimelineSource.failedAttempts,
            sourceSeq: seq,
            at: _t0.add(Duration(seconds: seq)),
            kind: TimelineEntryKind.failedUnlock,
            consecutiveFailures: run,
            logGen: gen,
          );
      final List<List<TimelineEntry>> g = groupFailedAttempts(<TimelineEntry>[
        at(1, null, 1),
        at(2, null, 2),
        at(3, _g1, 3),
        at(4, _g1, 4),
      ]);
      expect(
          g.map((List<TimelineEntry> r) =>
              r.map((TimelineEntry e) => e.sourceSeq).toList()),
          <List<int>>[
            <int>[1, 2],
            <int>[3, 4],
          ]);
    });

    test(
        'GI-2 a tombstone for (g0,5), or a legacy tombstone for seq 5, never '
        'suppresses (g1,5)', () async {
      expect(await store.save(seq: 5, jpeg: jpeg()), EvidenceSaveResult.saved);
      expect(await store.delete(5), EvidenceDeleteResult.deleted);
      expect(await store.save(seq: 5, gen: _g0, jpeg: jpeg()),
          EvidenceSaveResult.saved,
          reason: 'legacy tombstone applies to legacy items only');
      expect(await store.delete(5, gen: _g0), EvidenceDeleteResult.deleted);
      expect(await store.save(seq: 5, gen: _g0, jpeg: jpeg()),
          EvidenceSaveResult.superseded,
          reason: 'deleted evidence never comes back in its own generation');
      expect(await store.save(seq: 5, gen: _g1, jpeg: jpeg()),
          EvidenceSaveResult.saved);
      expect(
          await store.save(seq: 5, jpeg: jpeg()), EvidenceSaveResult.superseded,
          reason: 'the legacy tombstone still holds');
    });

    test(
        'GI-3 a late capture for a superseded generation is never saved; '
        'the coordinator reports captureNotSaved(superseded) with its EID',
        () async {
      final IntruderDefenseSettingsStore settings =
          IntruderDefenseSettingsStore(db, cipher);
      expect(
          await settings.write(const IntruderDefenseSettings(
              evidenceEnabled: true, alarmEnabled: false, threshold: 1)),
          isTrue);
      final GatedEvidenceService platform = GatedEvidenceService()
        ..permission = CameraPermissionState.granted;
      final IntruderDefenseCoordinator c = IntruderDefenseCoordinator(
          settings: settings, evidence: store, service: platform);
      final _Outcomes spy = _Outcomes();
      c.outcomeObserver = spy;
      platform.gate = Completer<CaptureResult>();
      c.onFailedAttemptRecorded(_ev(5, _g0)); // capture in flight for g0
      await pumpEventQueue();
      // The log is re-initialized (new generation) while the camera runs.
      c.onFailedAttemptRecorded(_ev(0, _g1)); // busy: slot held
      platform.gate!.complete(CaptureSucceeded(jpegWithMetadata()));
      await c.idle();
      expect(await store.list(), isEmpty, reason: 'g0 capture not saved');
      final List<String> got = <String>[
        for (final IntruderOutcome o in spy.got)
          if (o
              case CaptureNotSavedOutcome(
                :final int trig,
                :final why,
                :final tgen
              ))
            '$tgen:$trig:${why.name}',
      ];
      expect(got, containsAll(<String>['$_g1:0:busy', '$_g0:5:superseded']));
      // Store level (the coordinator always passes its newest generation as
      // currentGen): superseded generations stay closed.
      expect(await store.save(seq: 1, gen: _g1, currentGen: _g1, jpeg: jpeg()),
          EvidenceSaveResult.saved);
      expect(await store.save(seq: 6, gen: _g0, currentGen: _g1, jpeg: jpeg()),
          EvidenceSaveResult.superseded);
      expect(await store.save(seq: 2, gen: _g2, currentGen: _g2, jpeg: jpeg()),
          EvidenceSaveResult.saved);
      expect(await store.save(seq: 3, gen: _g1, currentGen: _g2, jpeg: jpeg()),
          EvidenceSaveResult.superseded,
          reason: 'g1 was superseded by g2');
      expect(await store.save(seq: 3, gen: _g1, jpeg: jpeg()),
          EvidenceSaveResult.superseded,
          reason: 'a superseded generation is closed even with no hint');
      expect((await store.list()).map((EvidenceItem e) => '${e.gen}:${e.seq}'),
          <String>['$_g1:1', '$_g2:2'],
          reason: 'items of a superseded generation stay listed');
    });

    test(
        'GI-3b journal: the superseded outcome is stored with a fixed '
        'allowlisted reason and its tgen', () async {
      final SecurityEventJournal j = SecurityEventJournal(
          store: SecurityEventJournalStore(db, cipher: cipher), now: () => _t0);
      final IntruderOutcomeJournalAdapter a = IntruderOutcomeJournalAdapter(j);
      a.onIntruderOutcome(const CaptureNotSavedOutcome(
          5, IntruderCaptureWhy.superseded,
          tgen: _g0));
      await pumpEventQueue();
      await j.idle();
      final SecurityJournalEvent e = (await j.read()).events.last;
      final CaptureNotSavedFields f = e.fields! as CaptureNotSavedFields;
      expect(f.why, CaptureWhy.superseded);
      expect(f.tgen, _g0);
      expect(f.trig, 5);
    });

    test(
        'GI-4 journal dedup is (family, tgen, trig): (capture,g0,5), '
        '(capture,g1,5) and legacy (capture,5) are all stored; a contradiction '
        'within one EID is lost', () async {
      final SecurityEventJournal j = SecurityEventJournal(
          store: SecurityEventJournalStore(db, cipher: cipher), now: () => _t0);
      j.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(5, tgen: _g0));
      j.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(5, tgen: _g1));
      j.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(5));
      j.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(5, tgen: _g1)); // exact duplicate
      j.recordEvent(SecurityJournalEventType.captureNotSaved,
          const CaptureNotSavedFields(5, CaptureWhy.camera, tgen: _g0));
      await j.idle();
      final SecurityJournalView v = await j.read();
      final List<String> ids = <String>[
        for (final SecurityJournalEvent e in v.events)
          if (e.type.isOutcome)
            '${e.type.name}:${e.fields!.tgen}:${e.fields!.trig}',
      ];
      expect(ids, <String>[
        'captureSaved:$_g0:5',
        'captureSaved:$_g1:5',
        'captureSaved:null:5',
      ]);
      expect(v.lost, 1, reason: 'the contradiction is disclosed, not stored');
      // Decoder enforces the same identity.
      Map<String, Object?> o(String? tgen) => <String, Object?>{
            'seq': 0,
            'at': 1,
            'type': 'captureSaved',
            'f': <String, Object?>{'trig': 5, if (tgen != null) 'tgen': tgen},
          };
      Map<String, Object?> doc(List<Map<String, Object?>> evs) =>
          <String, Object?>{
            'schema': SecurityJournalDocument.schema,
            'v': 3,
            'nextSeq': evs.length,
            'discarded': 0,
            'lost': 0,
            'events': <Object?>[
              for (int i = 0; i < evs.length; i++)
                <String, Object?>{...evs[i], 'seq': i},
            ],
          };
      expect(
          SecurityJournalDocument.fromJson(
              doc(<Map<String, Object?>>[o(_g0), o(_g1), o(null)])).events,
          hasLength(3));
      expect(
          () => SecurityJournalDocument.fromJson(
              doc(<Map<String, Object?>>[o(_g0), o(_g0)])),
          throwsFormatException);
      expect(
          () => SecurityJournalDocument.fromJson(
              doc(<Map<String, Object?>>[o(null), o(null)])),
          throwsFormatException);
      // tgen is v3-only: a v2 document carrying it is corrupt.
      expect(
          () => SecurityJournalDocument.fromJson(<String, Object?>{
                ...doc(<Map<String, Object?>>[o(_g0)]),
                'v': 2
              }),
          throwsFormatException);
    });

    test(
        'GI-5 coordinator: handled identities are EIDs (a re-initialized '
        'log\'s seq 5 is handled again); clear-all floors the current gen',
        () async {
      final IntruderDefenseSettingsStore settings =
          IntruderDefenseSettingsStore(db, cipher);
      await settings.write(const IntruderDefenseSettings(
          evidenceEnabled: true, alarmEnabled: false, threshold: 1));
      final GatedEvidenceService platform = GatedEvidenceService()
        ..permission = CameraPermissionState.granted;
      final IntruderDefenseCoordinator c = IntruderDefenseCoordinator(
          settings: settings, evidence: store, service: platform);
      c.onFailedAttemptRecorded(_ev(5, _g0));
      await c.idle();
      c.onFailedAttemptRecorded(_ev(5, _g0)); // duplicate notification
      await c.idle();
      expect(platform.captures, 1);
      c.onFailedAttemptRecorded(_ev(5, _g1)); // same seq, new generation
      await c.idle();
      expect(platform.captures, 2);
      expect(c.currentGen, _g1);
      expect(c.currentGenHighestSeq, 5);
      expect((await store.list()).map((EvidenceItem e) => '${e.gen}:${e.seq}'),
          <String>['$_g0:5', '$_g1:5']);
      expect(
          await store.clearAll(
              floorGen: c.currentGen, floorSeq: c.currentGenHighestSeq),
          EvidenceClearResult.cleared);
      expect(await store.list(), isEmpty);
      expect(await store.save(seq: 5, gen: _g1, jpeg: jpeg()),
          EvidenceSaveResult.superseded);
      expect(await store.save(seq: 4, gen: _g0, jpeg: jpeg()),
          EvidenceSaveResult.superseded);
      expect(await store.save(seq: 6, gen: _g1, jpeg: jpeg()),
          EvidenceSaveResult.saved,
          reason: 'a later attempt of the current gen is not over-retired');
    });

    test(
        'GI-6 no secure generator: no log is created, nothing is minted with '
        'a fallback, the observer never throws (auth path independent)',
        () async {
      final InMemoryLocalDatabase d = InMemoryLocalDatabase();
      final IntruderMonitor m = IntruderMonitor(
        store: IntruderFailureLogStore(d, cipher: cipher),
        now: () => _t0,
        mintGeneration: () => throw UnsupportedError('no secure random'),
      );
      expect(() => m.onVerifiedAttempt(_fail()), returnsNormally);
      await m.idle();
      expect(await d.getSetting(_logKey), isNull);
      expect(m.status.health, IntruderMonitorHealth.storageError);
      expect(m.generationsMinted, 0);
    });

    test(
        'GI-7 generation syntax: 21/23 chars, padding, "/", "+", non-ASCII '
        'are corrupt in the log, the evidence index and the journal', () async {
      final List<Object?> bad = <Object?>[
        'A' * 21,
        'A' * 23,
        '${'A' * 20}==',
        '${'A' * 21}/',
        '${'A' * 21}+',
        '${'A' * 21}é',
        22,
        null,
      ];
      for (final Object? g in bad) {
        expect(LogGeneration.isValid(g), isFalse, reason: '$g');
        expect(
            () => IntruderFailureLog.fromJson(<String, Object?>{
                  'schema': IntruderFailureLog.schema,
                  'v': 2,
                  'gen': g,
                  'nextSeq': 0,
                  'run': 0,
                  'events': <Object?>[],
                }),
            throwsFormatException,
            reason: 'log gen $g');
        if (g != null) {
          expect(
              () => SecurityEventFields.fromJson(
                  SecurityJournalEventType.captureSaved,
                  true,
                  <String, Object?>{'trig': 5, 'tgen': g},
                  v3: true),
              throwsFormatException,
              reason: 'journal tgen $g');
          await db.setSetting(
              IntruderEvidenceStore.indexKey,
              'enc:v1:${await cipher.encryptString(jsonEncode(<String, Object?>{
                    'v': 2,
                    'nextBid': 1,
                    'cur': g,
                    'items': <Object?>[],
                    'retired': <String, Object?>{},
                  }))}');
          expect(await store.health(), EvidenceIndexHealth.unreadable,
              reason: 'evidence cur $g');
        }
      }
      expect(LogGeneration.isValid('${'A' * 21}_'), isTrue);
      expect(LogGeneration.isValid('${'A' * 21}-'), isTrue);
    });
  });

  // ---------------------------------------------------------------------
  group('MIG: lazy migration (B2 §4)', () {
    late InMemoryLocalDatabase db;
    late SettingsCipher cipher;
    setUp(() {
      db = InMemoryLocalDatabase();
      cipher = _cipher();
    });

    test(
        'MIG-1 failure log v1: snapshot / owner success with run 0 write '
        'nothing; the first needed write stores v2', () async {
      final String v1 =
          'enc:v1:${await cipher.encryptString(jsonEncode(<String, Object?>{
            'schema': IntruderFailureLog.schema,
            'v': 1,
            'nextSeq': 3,
            'run': 0,
            'events': <Object?>[],
          }))}';
      await db.setSetting(_logKey, v1);
      final IntruderMonitor m = IntruderMonitor(
          store: IntruderFailureLogStore(db, cipher: cipher),
          now: () => _t0,
          mintGeneration: _mints(<String>[_g1]));
      expect((await m.snapshot())!.gen, isNull);
      m.onVerifiedAttempt(_ok()); // run already 0: nothing to write
      await m.idle();
      expect(await db.getSetting(_logKey), v1,
          reason: 'no write-only migration');
      expect(m.generationsMinted, 0);
      m.onVerifiedAttempt(_fail());
      await m.idle();
      final Map<String, Object?> d = jsonDecode(await cipher
              .decryptString((await db.getSetting(_logKey))!.substring(7)))
          as Map<String, Object?>;
      expect(d['v'], 2);
      expect(d['gen'], _g1);
      expect(d['nextSeq'], 4, reason: 'nextSeq continues unchanged');
    });

    test(
        'MIG-2 journal v2: startup + read write nothing; the first append '
        'writes v3 (no marker for v2->v3), legacy outcomes keep no tgen',
        () async {
      final SecurityEventJournalStore s = SecurityEventJournalStore(db);
      final String v2 = jsonEncode(<String, Object?>{
        'schema': SecurityJournalDocument.schema,
        'v': 2,
        'nextSeq': 2,
        'discarded': 0,
        'lost': 0,
        'events': <Object?>[
          // Recent timestamps (retention would otherwise prune and write).
          <String, Object?>{
            'seq': 0,
            'at': _t0.millisecondsSinceEpoch - 2000,
            'type': 'journalStarted'
          },
          <String, Object?>{
            'seq': 1,
            'at': _t0.millisecondsSinceEpoch - 1000,
            'type': 'captureSaved',
            'f': <String, Object?>{'trig': 5},
          },
        ],
      });
      await db.setSetting(SecurityEventJournalStore.storageKey, v2);
      final SecurityEventJournal j =
          SecurityEventJournal(store: s, now: () => _t0);
      await j.startup();
      await j.read();
      await j.idle();
      expect(await db.getSetting(SecurityEventJournalStore.storageKey), v2);
      j.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(5, tgen: _g1));
      await j.idle();
      final Map<String, Object?> d = jsonDecode(
              (await db.getSetting(SecurityEventJournalStore.storageKey))!)
          as Map<String, Object?>;
      expect(d['v'], 3);
      final List<Object?> evs = d['events']! as List<Object?>;
      expect(evs.map((Object? e) => (e! as Map)['type']),
          <String>['journalStarted', 'captureSaved', 'captureSaved']);
      expect(((evs[1]! as Map)['f'] as Map).containsKey('tgen'), isFalse);
      expect(((evs[2]! as Map)['f'] as Map)['tgen'], _g1);
    });

    test(
        'MIG-3 evidence v1: reads / maintenance write nothing; the first save '
        'writes v2, legacy items and blob rows unchanged, guards moved to '
        'retired.legacy', () async {
      final IntruderEvidenceStore s =
          IntruderEvidenceStore(db, cipher, now: () => _t0);
      final olde.IntruderEvidenceStore v1Store =
          olde.IntruderEvidenceStore(db, cipher, now: () => _t0);
      expect(await v1Store.save(seq: 3, jpeg: jpegWithMetadata()),
          olde.EvidenceSaveResult.saved);
      expect(await v1Store.save(seq: 4, jpeg: jpegWithMetadata(fill: 0x22)),
          olde.EvidenceSaveResult.saved);
      expect(await v1Store.delete(4), olde.EvidenceDeleteResult.deleted);
      final String idx1 =
          (await db.getSetting(IntruderEvidenceStore.indexKey))!;
      final String blob3 =
          (await db.getSetting(IntruderEvidenceStore.blobKey(3)))!;
      await s.list();
      await s.summary();
      await s.readImage(3);
      await s.startupMaintenance();
      expect(await db.getSetting(IntruderEvidenceStore.indexKey), idx1);
      expect(await s.save(seq: 4, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.superseded,
          reason: 'v1 tombstone honoured');
      expect(await db.getSetting(IntruderEvidenceStore.indexKey), idx1);
      expect(await s.save(seq: 3, gen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      final Map<String, Object?> d = jsonDecode(await cipher.decryptString(
          (await db.getSetting(IntruderEvidenceStore.indexKey))!
              .substring(7))) as Map<String, Object?>;
      expect(d['v'], 2);
      expect(d['cur'], _g1);
      expect(d['nextBid'], 1);
      expect((d['retired']! as Map)['legacy'], <String, Object?>{
        'tomb': <int>[4]
      });
      final List<Object?> items = d['items']! as List<Object?>;
      expect((items[0]! as Map).containsKey('gen'), isFalse);
      expect((items[1]! as Map)['gen'], _g1);
      expect(await db.getSetting(IntruderEvidenceStore.blobKey(3)), blob3,
          reason: 'legacy blob rows are never renamed or rewritten');
      expect(await db.getSetting(IntruderEvidenceStore.blobKey2(0)), isNotNull);
      expect(await s.readImage(3), isNotNull);
      expect(await s.readImage(3, gen: _g1), isNotNull);
    });

    test(
        // Batch 4 (disclosed re-baseline): journal v4 is now readable (v3 +
        // clear marker); the first newer journal is v5.
        'MIG-4 newer documents are byte-identical: log v3, journal v5, '
        'evidence v3', () async {
      final String log = jsonEncode(<String, Object?>{
        'schema': IntruderFailureLog.schema,
        'v': 3,
      });
      final String jr = jsonEncode(<String, Object?>{
        'schema': SecurityJournalDocument.schema,
        'v': 6, // Batch 5 (disclosed): v5 is readable; "newer" is v6
      });
      final String ev =
          'enc:v1:${await cipher.encryptString('{"v":3,"items":[]}')}';
      await db.setSetting(_logKey, log);
      await db.setSetting(SecurityEventJournalStore.storageKey, jr);
      await db.setSetting(IntruderEvidenceStore.indexKey, ev);
      await db.setSetting(IntruderEvidenceStore.blobKey2(0), 'enc:v1:future');
      final IntruderMonitor m = IntruderMonitor(
          store: IntruderFailureLogStore(db),
          now: () => _t0,
          mintGeneration: _mints(const <String>[]));
      m.onVerifiedAttempt(_fail());
      await m.idle();
      final SecurityEventJournal j = SecurityEventJournal(
          store: SecurityEventJournalStore(db), now: () => _t0);
      await j.startup();
      j.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(0, tgen: _g1));
      await j.idle();
      final IntruderEvidenceStore s =
          IntruderEvidenceStore(db, cipher, now: () => _t0);
      expect(await s.save(seq: 0, gen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.unsupportedSchema);
      await s.startupMaintenance();
      expect(await s.clearAll(floorGen: _g1),
          EvidenceClearResult.unsupportedSchema);
      expect(await db.getSetting(_logKey), log);
      expect(await db.getSetting(SecurityEventJournalStore.storageKey), jr);
      expect(await db.getSetting(IntruderEvidenceStore.indexKey), ev);
      expect(await db.getSetting(IntruderEvidenceStore.blobKey2(0)),
          'enc:v1:future');
    });
  });

  // ---------------------------------------------------------------------
  group('DG: evidence and journal downgrade (B2 §5, pre-Batch-3 code)', () {
    late InMemoryLocalDatabase db;
    late SettingsCipher cipher;
    setUp(() {
      db = InMemoryLocalDatabase();
      cipher = _cipher();
    });

    test(
        'DG-E1 old build on a v2 evidence index: refuses save / delete / '
        'clear, sweeps and expires nothing, touches no row; re-upgrade resumes',
        () async {
      final IntruderEvidenceStore s =
          IntruderEvidenceStore(db, cipher, now: () => _t0);
      expect(await s.save(seq: 1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      expect(await s.save(seq: 1, gen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      final Map<String, String> before = await db.getAllSettings();
      final olde.IntruderEvidenceStore o = olde.IntruderEvidenceStore(
          db, cipher,
          now: () => _t0.add(const Duration(days: 400)));
      expect(await o.health(), olde.EvidenceIndexHealth.unsupported);
      expect(await o.save(seq: 2, jpeg: jpegWithMetadata()),
          olde.EvidenceSaveResult.unsupportedSchema);
      expect(await o.delete(1), olde.EvidenceDeleteResult.unsupportedSchema);
      expect(await o.clearAll(floorSeq: 99),
          olde.EvidenceClearResult.unsupportedSchema);
      expect(await o.sweepOrphans(), 0);
      await o.startupMaintenance();
      expect(await o.enforceRetention(), 0);
      expect(await o.readImage(1), isNull);
      expect(await db.getAllSettings(), before,
          reason: 'every row byte-identical (index, blob_1, blob2_0)');
      // Re-upgrade: the new build resumes with all identities intact.
      expect(await s.readImage(1), isNotNull);
      expect(await s.readImage(1, gen: _g1), isNotNull);
      expect(await s.save(seq: 2, gen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      expect((await s.list()).length, 3);
    });

    test(
        'DG-J1 old build on a v3 journal: unsupported, read-only, never '
        'quarantined or overwritten; re-upgrade keeps every outcome', () async {
      final SecurityEventJournal j = SecurityEventJournal(
          store: SecurityEventJournalStore(db, cipher: cipher), now: () => _t0);
      j.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(5, tgen: _g1));
      await j.idle();
      final String v3 =
          (await db.getSetting(SecurityEventJournalStore.storageKey))!;
      final oldj.SecurityEventJournal o = oldj.SecurityEventJournal(
          store: oldj.SecurityEventJournalStore(db, cipher: cipher),
          now: () => _t0);
      await o.startup();
      o.recordEvent(oldj.SecurityJournalEventType.captureSaved,
          const oldj.CaptureSavedFields(6));
      await o.idle();
      expect((await o.read()).availability,
          oldj.SecurityJournalAvailability.unsupported);
      expect(await db.getSetting(SecurityEventJournalStore.storageKey), v3);
      expect(
          await db.getSetting(SecurityEventJournalStore.quarantineKey), isNull);
      final SecurityEventJournal again = SecurityEventJournal(
          store: SecurityEventJournalStore(db, cipher: cipher), now: () => _t0);
      again.recordEvent(SecurityJournalEventType.captureSaved,
          const CaptureSavedFields(6, tgen: _g1));
      await again.idle();
      final List<String> ids = <String>[
        for (final SecurityJournalEvent e in (await again.read()).events)
          if (e.type.isOutcome) '${e.fields!.tgen}:${e.fields!.trig}',
      ];
      expect(ids, <String>['$_g1:5', '$_g1:6']);
    });

    test(
        'DG-0b the old failure-log reader IGNORES unknown keys (an additive '
        '"gen" in v1 would be stripped on its next write): the version bump '
        'was required (B2 §5 alternative rejected)', () async {
      // Evidence via the old monitor is in p13_m3_b3_downgrade_test.dart;
      // here the property is shown on the old document codec directly.
      final Map<String, Object?> v1 = <String, Object?>{
        'schema': 'sal.intruder_log',
        'v': 1,
        'gen': _g1,
        'nextSeq': 0,
        'run': 0,
        'events': <Object?>[],
      };
      expect(() => IntruderFailureLog.fromJson(v1), throwsFormatException,
          reason: 'the NEW reader refuses a gen in a v1 document');
      // Old reader: accepted, and its re-encoding has no gen.
      final String reencoded = jsonEncode(_oldLogRoundTrip(v1));
      expect(reencoded, isNot(contains('gen')));
    });
  });
}

TimelineEntry _attempt(int seq, {String? gen}) => TimelineEntry(
      source: TimelineSource.failedAttempts,
      sourceSeq: seq,
      at: _t0,
      kind: TimelineEntryKind.failedUnlock,
      consecutiveFailures: 1,
      logGen: gen,
    );

TimelineEntry _outcome(int jseq,
        {required int trig, String? tgen, DateTime? at}) =>
    TimelineEntry(
      source: TimelineSource.journal,
      sourceSeq: jseq,
      at: at ?? _t0.add(const Duration(seconds: 5)),
      kind: TimelineEntryKind.captureSaved,
      trig: trig,
      tgen: tgen,
    );

/// The OLD (pre-Batch-3) failure-log codec: decode then re-encode.
Map<String, Object?> _oldLogRoundTrip(Map<String, Object?> doc) =>
    oldf.IntruderFailureLog.fromJson(doc).toJson();
