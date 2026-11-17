// P13/M3 Batch 5 — History retention controls (F-2): setting, enforcement
// at startup / append / open, coalesced expiry marker, change marker,
// fail-safe default, serialization, TL-3 byte-identity, downgrade.
//
// IDs follow P13_M3_TEST_AND_MUTATION_PLAN R-01..R-14 (plus V-xx codec).
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/history/history_clear_service.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/history/history_retention_service.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_settings.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';

import '../../support/intruder_fixtures.dart';
import 'legacy_b4/intruder_defense_settings.dart' as b4s;
import 'legacy_b4/security_event_journal_store.dart' as b4j;

final DateTime _t0 = DateTime(2026, 10, 22, 12);
const String _g1 = 'G1____________________';
const String _logKey = IntruderFailureLogStore.storageKey;
const String _jKey = SecurityEventJournalStore.storageKey;
const String _sKey = IntruderDefenseSettingsStore.storageKey;

/// Rows retention must never touch (TL-3).
const Map<String, String> _unrelated = <String, String>{
  'security_settings': 'credential-row',
  'credential_lockout_state': 'lockout-row',
  'app_settings': 'app-row',
  IntruderFailureLogStore.quarantineKey: 'log-quarantine',
  SecurityEventJournalStore.quarantineKey: 'journal-quarantine',
};

int _vid = 0;

class _World {
  _World() {
    build();
  }

  final InMemoryLocalDatabase db = InMemoryLocalDatabase();
  final SettingsCipher cipher = AesGcmSettingsCipher(InMemorySecretStore(),
      database: InMemoryLocalDatabase());
  DateTime now = _t0;
  late IntruderMonitor monitor;
  late SecurityEventJournal journal;
  late IntruderDefenseSettingsStore settings;
  late IntruderEvidenceStore evidence;
  late HistoryRetentionService service;
  late HistoryClearService clear;
  late SecurityTimelineReader reader;

  /// Production wiring (retention unknown until startup); = restart.
  void build() {
    monitor = IntruderMonitor(
        store: IntruderFailureLogStore(db, cipher: cipher),
        now: () => now,
        retention: null,
        mintGeneration: () => _g1);
    final SecurityEventJournalStore js =
        SecurityEventJournalStore(db, cipher: cipher);
    journal = SecurityEventJournal(store: js, now: () => now, retention: null);
    settings = IntruderDefenseSettingsStore(db, cipher);
    evidence = IntruderEvidenceStore(db, cipher, now: () => now);
    service = HistoryRetentionService(
        settings: settings, monitor: monitor, journal: journal);
    clear = HistoryClearService(
        monitor: monitor,
        journal: journal,
        evidence: evidence,
        liveGen: () => _g1);
    monitor.onHistoryExpired = journal.recordHistoryExpired;
    reader = SecurityTimelineReader(
        monitor: monitor, journal: journal, journalStore: js, database: db);
  }

  /// Production startup, then both queues settled (the failure-log purge
  /// reports to the journal after its own write).
  Future<void> startup() async {
    await service.startup();
    await monitor.idle();
    await journal.idle();
  }

  Future<void> fail({DateTime? at}) async {
    monitor.onVerifiedAttempt(VerifiedAttempt(
      verificationId: 'b5:${++_vid}',
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
          reason: AuthFailureReason.wrongCredential, remainingAttempts: 2),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: at ?? now,
    ));
    await monitor.idle();
    await journal.idle();
  }

  Future<void> outcome(int trig) async {
    journal.recordEvent(SecurityJournalEventType.captureSaved,
        CaptureSavedFields(trig, tgen: _g1));
    await journal.idle();
  }

  Future<void> setDays(int days) async {
    expect(
        await settings.update((IntruderDefenseSettings s) =>
            s.copyWith(historyRetentionDays: days)),
        isNotNull);
  }

  Future<RetentionChangeOutcome> change(int days,
      {bool confirmed = true, bool valid = true}) async {
    final RetentionChangeOutcome r = await service.change(days,
        stillValid: () => valid, shorteningConfirmed: confirmed);
    await monitor.idle();
    await journal.idle();
    return r;
  }

  Future<IntruderFailureLog> log() async =>
      ((await IntruderFailureLogStore(db, cipher: cipher).read())
              as IntruderLogLoaded)
          .log;

  Future<SecurityJournalDocument> doc() async =>
      ((await SecurityEventJournalStore(db, cipher: cipher).read())
              as SecurityJournalLoaded)
          .document;

  Future<Map<String, Object?>> rawJson(String key) async {
    final String raw = (await db.getSetting(key))!;
    return jsonDecode(await cipher.decryptString(raw.substring(7)))
        as Map<String, Object?>;
  }

  Future<List<SecurityJournalEventType>> types() async =>
      (await doc()).events.map((SecurityJournalEvent e) => e.type).toList();

  Future<HistoryExpiredFields?> expiry() async =>
      (await doc()).expiryMarker?.fields as HistoryExpiredFields?;

  Future<Map<String, String>> rows() => db.getAllSettings();

  /// Writes a settings row whose decoded JSON is [json] (app cipher).
  Future<void> putSettingsJson(Map<String, Object?> json) async =>
      db.setSetting(
          _sKey, 'enc:v1:${await cipher.encryptString(jsonEncode(json))}');
}

/// Seeds attempts and journal outcomes at days -50, -20, -5 and 0 relative
/// to [_t0] (clock moved for each), then returns the clock to [_t0].
Future<_World> _seed() async {
  final _World w = _World();
  for (final MapEntry<String, String> e in _unrelated.entries) {
    await w.db.setSetting(e.key, e.value);
  }
  int trig = 0;
  for (final int d in <int>[-50, -20, -5, 0]) {
    w.now = _t0.add(Duration(days: d));
    await w.fail();
    await w.outcome(trig++);
  }
  w.now = _t0;
  return w;
}

void main() {
  group('R-01/R-02/R-10 setting', () {
    test('R-01 hr round-trips in v1 settings; an older build ignores it',
        () async {
      final _World w = _World();
      await w.setDays(7);
      final Map<String, Object?> json = await w.rawJson(_sKey);
      expect(json['v'], 1);
      expect(json['hr'], 7);
      expect((await w.settings.read()).settings.historyRetentionDays, 7);
      // Pre-Batch-5 build: same record reads OK with every other field.
      final b4s.IntruderSettingsRead old =
          await b4s.IntruderDefenseSettingsStore(w.db, w.cipher).read();
      expect(old.health, b4s.IntruderSettingsHealth.ok);
      expect(old.settings.threshold, IntruderDefenseSettings.defaultThreshold);
    });

    test('R-02 absent -> 30; a default record has no hr (byte layout kept)',
        () async {
      final _World w = _World();
      expect(
          await w.settings.update((IntruderDefenseSettings s) => s), isNotNull);
      final Map<String, Object?> json = await w.rawJson(_sKey);
      expect(
          json.keys.toList(), <String>['v', 'evidence', 'alarm', 'threshold']);
      final IntruderSettingsRead r = await w.settings.read();
      expect(r.settings.historyRetentionDays, 30);
      expect(r.settings.retentionInvalid, isFalse);
      expect(await w.service.effectiveDays(), 30);
    });

    for (final Object? bad in <Object?>[
      14,
      0,
      -7,
      'x',
      null,
      7.0,
      <int>[7]
    ]) {
      test('R-10 invalid stored hr $bad -> 30 and a flag; never 7', () async {
        final _World w = _World();
        await w.putSettingsJson(<String, Object?>{
          'v': 1,
          'evidence': true,
          'alarm': false,
          'threshold': 4,
          'hr': bad,
        });
        final IntruderSettingsRead r = await w.settings.read();
        expect(r.health, IntruderSettingsHealth.ok); // record stays valid
        expect(r.settings.evidenceEnabled, isTrue);
        expect(r.settings.historyRetentionDays, 30);
        expect(r.settings.retentionInvalid, isTrue);
        expect(await w.service.effectiveDays(), 30);
        // An unrelated update writes the invalid value back verbatim.
        await w.settings
            .update((IntruderDefenseSettings s) => s.copyWith(threshold: 5));
        final Map<String, Object?> json = await w.rawJson(_sKey);
        expect(jsonEncode(json['hr']), jsonEncode(bad));
        expect(json.containsKey('hr'), isTrue);
        expect(json['threshold'], 5);
        // Only an explicit owner choice replaces it.
        expect(await w.change(90), RetentionChangeOutcome.changed);
        expect((await w.rawJson(_sKey))['hr'], 90);
        expect((await w.settings.read()).settings.retentionInvalid, isFalse);
      });
    }

    test('R-10 unreadable/corrupt settings record -> 30 (never shorter)',
        () async {
      final _World w = _World();
      await w.db.setSetting(_sKey, 'enc:v1:garbage');
      expect(
          (await w.settings.read()).health, isNot(IntruderSettingsHealth.ok));
      expect(await w.service.effectiveDays(), 30);
      expect(await w.change(7), RetentionChangeOutcome.refused);
      expect(await w.db.getSetting(_sKey), 'enc:v1:garbage');
    });
  });

  group('R-03/R-05/R-09 change', () {
    test('R-03 no fresh verification (session invalid): nothing written',
        () async {
      final _World w = await _seed();
      await w.startup();
      final Map<String, String> before = await w.rows();
      expect(await w.change(7, valid: false), RetentionChangeOutcome.cancelled);
      expect(await w.rows(), before);
    });

    test('R-03 session ends inside the serialized update: nothing written',
        () async {
      final _World w = await _seed();
      await w.startup();
      final Map<String, String> before = await w.rows();
      int calls = 0;
      // Valid for the pre-check, invalid right before the write.
      final RetentionChangeOutcome r = await w.service
          .change(7, stillValid: () => ++calls < 2, shorteningConfirmed: true);
      expect(r, RetentionChangeOutcome.cancelled);
      await w.journal.idle();
      expect(await w.rows(), before);
    });

    test('R-05 shortening unconfirmed: nothing written', () async {
      final _World w = await _seed();
      await w.startup();
      final Map<String, String> before = await w.rows();
      expect(await w.change(7, confirmed: false),
          RetentionChangeOutcome.needsConfirmation);
      expect(await w.rows(), before);
      // Lengthening needs no confirmation.
      expect(
          await w.change(90, confirmed: false), RetentionChangeOutcome.changed);
    });

    test(
        'R-05 confirmed: deletes exactly the events older than the cutoff '
        '(boundary kept)', () async {
      final _World w = _World();
      w.now = _t0.subtract(const Duration(days: 7));
      await w.fail(); // exactly at the cutoff: kept
      w.now = _t0.subtract(const Duration(days: 7, milliseconds: 1));
      await w.fail(); // 1 ms older: removed
      w.now = _t0;
      await w.startup();
      expect((await w.log()).events.length, 2);
      expect(await w.change(7), RetentionChangeOutcome.changed);
      final IntruderFailureLog log = await w.log();
      expect(log.events.map((e) => e.at).toList(),
          <DateTime>[_t0.subtract(const Duration(days: 7))]);
      final HistoryExpiredFields x = (await w.expiry())!;
      expect(x.n, 1);
      expect(
          x.from,
          _t0
              .subtract(const Duration(days: 7, milliseconds: 1))
              .millisecondsSinceEpoch);
      expect(x.to, x.from);
    });

    test('R-09 retentionChanged {old,new} once per change; none if unchanged',
        () async {
      final _World w = await _seed();
      await w.startup();
      expect(await w.change(90), RetentionChangeOutcome.changed);
      expect(await w.change(90), RetentionChangeOutcome.unchanged);
      expect(await w.change(7), RetentionChangeOutcome.changed);
      final List<RetentionChangedFields> changes = <RetentionChangedFields>[
        for (final SecurityJournalEvent e in (await w.doc()).events)
          if (e.fields is RetentionChangedFields)
            e.fields! as RetentionChangedFields,
      ];
      expect(changes.map((c) => '${c.oldDays}->${c.newDays}').toList(),
          <String>['30->90', '90->7']);
    });

    test('invalid choice refused', () async {
      final _World w = _World();
      for (final int d in <int>[0, 1, 14, 31, 365]) {
        expect(await w.change(d), RetentionChangeOutcome.refused);
      }
      expect(await w.db.getSetting(_sKey), isNull);
    });
  });

  group('R-04 enforcement at startup, append and open', () {
    test('unknown setting (before startup): nothing is age-purged', () async {
      final _World w = await _seed();
      // Seeding appended with retention unknown: the -50-day rows remain.
      expect((await w.log()).events.length, 4);
      expect((await w.types()).where((t) => t.isOutcome).length, 4);
      expect(await w.expiry(), isNull);
    });

    test('startup: 7 days applied to the journal and the failure log',
        () async {
      final _World w = await _seed();
      await w.setDays(7);
      w.build(); // restart
      await w.startup();
      await w.journal.idle();
      expect((await w.log()).events.map((e) => e.at).toList(),
          <DateTime>[_t0.subtract(const Duration(days: 5)), _t0]);
      final List<int> trigs = <int>[
        for (final SecurityJournalEvent e in (await w.doc()).events)
          if (e.type.isOutcome) e.fields!.trig!,
      ];
      expect(trigs, <int>[2, 3]);
      expect((await w.expiry())!.n,
          5); // 2 attempts + 2 outcomes + journalStarted (day -50)
    });

    test('startup: 90 days keeps everything younger than 90 days', () async {
      final _World w = await _seed();
      await w.setDays(90);
      w.build();
      await w.startup();
      await w.journal.idle();
      expect((await w.log()).events.length, 4);
      expect(await w.expiry(), isNull);
    });

    test('startup: default 30 days', () async {
      final _World w = await _seed();
      w.build();
      await w.startup();
      await w.journal.idle();
      expect((await w.log()).events.length, 3);
      expect((await w.expiry())!.n, 3); // incl. journalStarted (day -50)
    });

    test('append: a new record applies the setting to both stores', () async {
      final _World w = await _seed();
      await w.setDays(7);
      w.build();
      await w.startup();
      w.now = _t0.add(const Duration(days: 3)); // day -5 is now 8 days old
      await w.fail();
      expect((await w.log()).events.length, 2);
      await w.outcome(9);
      final List<int> trigs = <int>[
        for (final SecurityJournalEvent e in (await w.doc()).events)
          if (e.type.isOutcome) e.fields!.trig!,
      ];
      expect(trigs, <int>[3, 9]);
      expect((await w.expiry())!.n, 7);
    });

    test('open: the timeline read applies the setting to both stores',
        () async {
      final _World w = await _seed();
      await w.setDays(7);
      w.build();
      await w.startup();
      w.now = _t0.add(const Duration(days: 3));
      final SecurityTimelineSnapshot snap = await w.reader.load();
      expect((await w.log()).events.length, 1);
      final List<TimelineEntry> expired = snap.entries
          .where(
              (TimelineEntry e) => e.kind == TimelineEntryKind.historyExpired)
          .toList();
      expect(expired.length, 1);
      expect(expired.single.expiredCount, 7);
      expect(
          snap.entries
              .where(
                  (TimelineEntry e) => e.kind == TimelineEntryKind.failedUnlock)
              .length,
          1);
    });
  });

  group('R-06/R-07/R-08/R-13 marker and clock', () {
    test('R-06 coalesced: one marker, n summed, range widened', () async {
      final _World w = await _seed();
      w.build();
      await w.startup(); // 30 days: removes day -50 (attempt+outcome)
      await w.journal.idle();
      final HistoryExpiredFields a = (await w.expiry())!;
      final int d50 =
          _t0.subtract(const Duration(days: 50)).millisecondsSinceEpoch;
      expect((a.n, a.from, a.to), (3, d50, d50));
      expect(await w.change(7), RetentionChangeOutcome.changed);
      final HistoryExpiredFields b = (await w.expiry())!;
      final int d20 =
          _t0.subtract(const Duration(days: 20)).millisecondsSinceEpoch;
      expect((b.n, b.from, b.to), (5, d50, d20));
      expect(
          (await w.types())
              .where((t) => t == SecurityJournalEventType.historyExpired)
              .length,
          1);
      expect(await w.declaredVersion(), 5);
    });

    test('R-07 clock rollback: future rows kept, order unchanged', () async {
      final _World w = await _seed();
      await w.setDays(7);
      w.now = _t0.add(const Duration(days: 2));
      await w.fail();
      await w.outcome(7);
      w.now = _t0.subtract(const Duration(days: 45)); // clock moved back
      w.build();
      await w.startup();
      await w.journal.idle();
      final IntruderFailureLog log = await w.log();
      // Everything is newer than (now - 7 days): nothing purged, no marker.
      expect(log.events.length, 5);
      expect(log.events.map((e) => e.seq).toList(), <int>[0, 1, 2, 3, 4]);
      expect(await w.expiry(), isNull);
    });

    test('R-08 clock forward 40 days: rows purged AND the marker present',
        () async {
      final _World w = await _seed();
      await w.startup();
      await w.journal.idle();
      w.now = _t0.add(const Duration(days: 40));
      w.build();
      await w.startup();
      await w.journal.idle();
      expect((await w.log()).events, isEmpty);
      expect((await w.types()).where((t) => t.isOutcome), isEmpty);
      final HistoryExpiredFields x = (await w.expiry())!;
      expect(x.n, 9);
      expect(x.to, _t0.millisecondsSinceEpoch);
    });

    test('the expiry marker never ages out and is never evicted (n kept)',
        () async {
      final _World w = await _seed();
      await w.startup(); // marker n=3 (day -50 rows)
      final HistoryExpiredFields a = (await w.expiry())!;
      final int seq = (await w.doc()).expiryMarker!.seq;
      // 100 days later the marker itself is far older than the cutoff;
      // only the -20/-5/0 outcomes expire and are folded in.
      w.now = _t0.add(const Duration(days: 100));
      await w.journal.read();
      final HistoryExpiredFields b = (await w.expiry())!;
      expect(b.n, a.n + 3); // + 3 outcomes; the log is untouched here
      expect((await w.doc()).expiryMarker!.seq, greaterThan(seq));
      // Nothing else left to expire: re-reading changes nothing.
      w.now = _t0.add(const Duration(days: 300));
      await w.journal.read();
      expect((await w.expiry())!.n, b.n);
      // Count cap: a flood of journal events never evicts the marker.
      for (int i = 0; i < SecurityEventJournal.defaultMaxEvents + 5; i++) {
        await w.outcome(1000 + i);
      }
      expect((await w.expiry())!.n, b.n);
    });

    test('R-13 flood: at most one expiry and one clear marker', () async {
      final _World w = await _seed();
      await w.startup();
      expect(await w.clear.clear(photos: false, stillValid: () => true),
          HistoryClearOutcome.done);
      for (int i = 0; i < 60; i++) {
        w.now = _t0.add(Duration(days: i));
        await w.fail();
        await w.outcome(100 + i);
        if (i.isEven) await w.journal.read();
      }
      final List<SecurityJournalEventType> t = await w.types();
      expect(
          t.where((x) => x == SecurityJournalEventType.historyExpired).length,
          1);
      expect(
          t.where((x) => x == SecurityJournalEventType.historyCleared).length,
          1);
      expect((await w.expiry())!.n, greaterThan(50));
    });

    test('expiry report of a failed write is never claimed (journal lost)',
        () async {
      final _World w = _World();
      w.journal.recordHistoryExpired(0, _t0, _t0); // invalid n
      w.journal.recordHistoryExpired(
          1, _t0, _t0.subtract(const Duration(days: 1))); // from > to
      await w.journal.idle();
      expect(w.journal.pendingLost, 2);
    });
  });

  group('R-11/R-12/R-14 isolation', () {
    test('R-11 concurrent threshold and retention updates: no lost field',
        () async {
      final _World w = _World();
      await Future.wait(<Future<Object?>>[
        w.settings
            .update((IntruderDefenseSettings s) => s.copyWith(threshold: 6)),
        w.service
            .change(90, stillValid: () => true, shorteningConfirmed: false),
        w.settings.update(
            (IntruderDefenseSettings s) => s.copyWith(alarmEnabled: true)),
      ]);
      final IntruderDefenseSettings s = (await w.settings.read()).settings;
      expect(
          (s.threshold, s.historyRetentionDays, s.alarmEnabled), (6, 90, true));
    });

    test(
        'R-12 change + purge: run, nextSeq, gen, lockout, credential, '
        'quarantine and evidence rows byte-identical', () async {
      final _World w = await _seed();
      // Baseline BEFORE any purge ran (pinned literals: 4 attempts, run 4).
      final IntruderFailureLog seeded = await w.log();
      expect((seeded.nextSeq, seeded.consecutiveFailures, seeded.gen),
          (4, 4, _g1));
      await w.evidence
          .save(seq: 3, gen: _g1, currentGen: _g1, jpeg: jpegWithMetadata());
      await w.startup();
      await w.journal.idle();
      final IntruderFailureLog before = await w.log();
      expect(
          (before.nextSeq, before.consecutiveFailures, before.gen), (4, 4, _g1),
          reason: 'the startup purge kept the header');
      final SecurityJournalDocument jBefore = await w.doc();
      final Map<String, String> rows = await w.rows();
      expect(await w.change(7), RetentionChangeOutcome.changed);
      final IntruderFailureLog after = await w.log();
      expect(after.events.length, lessThan(before.events.length));
      expect((after.nextSeq, after.consecutiveFailures, after.gen),
          (before.nextSeq, before.consecutiveFailures, before.gen));
      final SecurityJournalDocument jAfter = await w.doc();
      expect(jAfter.lost, jBefore.lost);
      expect(jAfter.healthMark?.toJson(), jBefore.healthMark?.toJson());
      final Map<String, String> now = await w.rows();
      for (final String k in rows.keys) {
        if (k == _logKey || k == _jKey || k == _sKey) continue;
        expect(now[k], rows[k], reason: k);
      }
    });

    test('R-14 evidence retention unchanged by the history setting', () async {
      final _World w = _World();
      w.now = _t0.subtract(const Duration(days: 20));
      expect(
          await w.evidence.save(
              seq: 0, gen: _g1, currentGen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      w.now = _t0;
      await w.setDays(7);
      w.build();
      await w.startup();
      await w.evidence.startupMaintenance();
      expect((await w.evidence.list()).length, 1);
      expect(w.evidence.retention, const Duration(days: 30));
    });
  });

  group('V codec and downgrade', () {
    test('V-01 v5 iff a retention event; v4 / v3 otherwise', () async {
      final _World w = await _seed();
      await w.startup();
      await w.journal.idle();
      expect(await w.declaredVersion(), 5); // expiry marker present
      final _World fresh = _World();
      await fresh.startup();
      await fresh.outcome(0);
      expect(await fresh.declaredVersion(), 3);
    });

    test('V-02 strict decode: canonical v5, single expiry, types gated', () {
      Map<String, Object?> doc(int v, List<Map<String, Object?>> events) =>
          <String, Object?>{
            'schema': SecurityJournalDocument.schema,
            'v': v,
            'nextSeq': events.length,
            'discarded': 0,
            'lost': 0,
            'events': events,
          };
      Map<String, Object?> ev(int seq, String type, [Object? f]) =>
          <String, Object?>{
            'seq': seq,
            'at': 1000,
            'type': type,
            if (f != null) 'f': f,
          };
      final Map<String, Object?> rc = <String, Object?>{'old': 30, 'new': 7};
      final Map<String, Object?> he = <String, Object?>{
        'n': 3,
        'from': 10,
        'to': 20
      };
      // valid
      expect(
          SecurityJournalDocument.fromJson(
                  doc(5, <Map<String, Object?>>[ev(0, 'retentionChanged', rc)]))
              .encodedVersion,
          5);
      expect(
          SecurityJournalDocument.fromJson(doc(5, <Map<String, Object?>>[
            ev(0, 'historyExpired', he),
            ev(1, 'retentionChanged', rc)
          ])).expiryMarker,
          isNotNull);
      final List<Map<String, Object?>> bad = <Map<String, Object?>>[
        doc(5, <Map<String, Object?>>[ev(0, 'journalStarted')]), // no retention
        doc(4, <Map<String, Object?>>[ev(0, 'retentionChanged', rc)]),
        doc(3, <Map<String, Object?>>[ev(0, 'historyExpired', he)]),
        doc(5, <Map<String, Object?>>[
          ev(0, 'historyExpired', he),
          ev(1, 'historyExpired', he)
        ]),
        doc(5, <Map<String, Object?>>[
          ev(0, 'retentionChanged', <String, Object?>{'old': 30, 'new': 30})
        ]),
        doc(5, <Map<String, Object?>>[
          ev(0, 'retentionChanged', <String, Object?>{'old': 30, 'new': 14})
        ]),
        doc(5, <Map<String, Object?>>[
          ev(0, 'historyExpired', <String, Object?>{'n': 0, 'from': 1, 'to': 2})
        ]),
        doc(5, <Map<String, Object?>>[
          ev(0, 'historyExpired', <String, Object?>{'n': 1, 'from': 3, 'to': 2})
        ]),
        doc(5, <Map<String, Object?>>[
          ev(0, 'historyExpired',
              <String, Object?>{'n': 1, 'from': 1, 'to': 2, 'x': 1})
        ]),
        doc(5, <Map<String, Object?>>[
          <String, Object?>{...ev(0, 'historyExpired', he), 'cb': true}
        ]),
      ];
      for (final Map<String, Object?> d in bad) {
        expect(() => SecurityJournalDocument.fromJson(d), throwsFormatException,
            reason: jsonEncode(d));
      }
    });

    test('V-03 a pre-Batch-5 build reads v5 as unsupported (never corrupt)',
        () async {
      final _World w = await _seed();
      await w.startup();
      await w.journal.idle();
      expect(await w.declaredVersion(), 5);
      final String raw = (await w.db.getSetting(_jKey))!;
      final b4j.SecurityJournalRead r =
          await b4j.SecurityEventJournalStore(w.db, cipher: w.cipher).read();
      expect(r, isA<b4j.SecurityJournalUnsupported>());
      expect(await w.db.getSetting(_jKey), raw);
    });

    test('V-04 the current build reads v6 as unsupported', () async {
      final _World w = _World();
      await w.db.setSetting(
          _jKey,
          'enc:v1:${await w.cipher.encryptString(jsonEncode(<String, Object?>{
                'schema': SecurityJournalDocument.schema,
                'v': 6
              }))}');
      expect(await SecurityEventJournalStore(w.db, cipher: w.cipher).read(),
          isA<SecurityJournalUnsupported>());
    });

    test('timeline rows for the retention events', () async {
      final _World w = await _seed();
      await w.startup();
      expect(await w.change(7), RetentionChangeOutcome.changed);
      final SecurityTimelineSnapshot snap = await w.reader.load();
      final TimelineEntry rc = snap.entries.firstWhere(
          (TimelineEntry e) => e.kind == TimelineEntryKind.retentionChanged);
      expect((rc.retentionOld, rc.retentionNew), (30, 7));
      final TimelineEntry he = snap.entries.firstWhere(
          (TimelineEntry e) => e.kind == TimelineEntryKind.historyExpired);
      expect(he.expiredCount, 5);
      expect(he.expiredFrom, _t0.subtract(const Duration(days: 50)));
      expect(he.expiredTo, _t0.subtract(const Duration(days: 20)));
    });
  });
}

extension on _World {
  Future<int> declaredVersion() async => (await rawJson(_jKey))['v']! as int;
}
