// P13/M3 Batch 4 — Clear History: service, stores, read model, crash points,
// legacy history, unrelated evidence, unavailable/corrupt storage, downgrade.
//
// IDs follow C_P13_M3_CRASH_SAFE_CLEAR_HISTORY_DESIGN §5 (CH-01..13) plus
// Batch 4 additions (CH-14..). "Crash after step X" is reproduced exactly:
// the next step's row write fails (nothing of it lands), then every engine
// object is rebuilt over the same database ("restart").
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/history/history_clear_service.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';

import '../../support/intruder_fixtures.dart';
import '../intruder/legacy_t3/intruder_evidence_store.dart' as olde;
import '../intruder/legacy_t3/intruder_failure_log_store.dart' as oldl;
import '../intruder/legacy_t3/intruder_monitor.dart' as oldm;
import '../intruder/legacy_t3/security_event_journal.dart' as oldj;
import '../intruder/legacy_t3/security_event_journal_store.dart' as oldj;
import '../intruder/legacy_t3/security_journal_event.dart' as oldj;
import 'legacy_b3/security_event_journal_store.dart' as b3;

final DateTime _t0 = DateTime(2026, 10, 22, 12);
const String _g1 = 'G1____________________';
const String _g2 = 'G2____________________';
const String _logKey = IntruderFailureLogStore.storageKey;
const String _jKey = SecurityEventJournalStore.storageKey;
const String _idxKey = IntruderEvidenceStore.indexKey;

/// Rows Clear History must never touch (TL-3 / R-P13M1-2).
const Map<String, String> _unrelated = <String, String>{
  'security_settings': 'credential-row',
  'credential_lockout_state': 'lockout-row',
  'intruder_defense_settings': 'settings-row',
  'app_settings': 'app-row',
  IntruderFailureLogStore.quarantineKey: 'log-quarantine',
  SecurityEventJournalStore.quarantineKey: 'journal-quarantine',
};

int _vid = 0;
VerifiedAttempt _fail() => VerifiedAttempt(
      verificationId: 'b4:${++_vid}',
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
          reason: AuthFailureReason.wrongCredential, remainingAttempts: 2),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

/// Fault injection: writes to a key fail once its allowance is used up.
class _Db extends InMemoryLocalDatabase {
  final Map<String, int> allow = <String, int>{};
  int writes = 0;
  int journalWrites = 0;

  bool _blocked(String key) {
    final int? left = allow[key];
    if (left == null) return false;
    if (left <= 0) return true;
    allow[key] = left - 1;
    return false;
  }

  @override
  Future<void> setSetting(String key, String value) async {
    if (_blocked(key)) throw StateError('injected write fault: $key');
    writes++;
    if (key == _jKey) journalWrites++;
    return super.setSetting(key, value);
  }

  @override
  Future<void> removeSetting(String key) async {
    if (_blocked(key)) throw StateError('injected remove fault: $key');
    writes++;
    return super.removeSetting(key);
  }

  @override
  Future<CasOutcome> compareAndSetSetting(String key,
      {required String? expected, required String next}) async {
    if (_blocked(key)) throw StateError('injected CAS fault: $key');
    writes++;
    return super.compareAndSetSetting(key, expected: expected, next: next);
  }
}

class _World {
  _World(this.db, this.cipher, {List<String>? mints})
      : _mints = mints ?? <String>[_g1, _g2] {
    build();
  }

  final _Db db;
  final SettingsCipher cipher;
  final List<String> _mints;
  String? live = _g1;
  late IntruderMonitor monitor;
  late SecurityEventJournal journal;
  late IntruderEvidenceStore evidence;
  late HistoryClearService service;
  late SecurityTimelineReader reader;

  /// (Re)creates every engine object over the same database (= restart).
  void build() {
    monitor = IntruderMonitor(
        store: IntruderFailureLogStore(db, cipher: cipher),
        now: () => _t0,
        mintGeneration: () => _mints.removeAt(0));
    final SecurityEventJournalStore js =
        SecurityEventJournalStore(db, cipher: cipher);
    journal = SecurityEventJournal(store: js, now: () => _t0);
    evidence = IntruderEvidenceStore(db, cipher, now: () => _t0);
    service = HistoryClearService(
        monitor: monitor,
        journal: journal,
        evidence: evidence,
        liveGen: () => live);
    reader = SecurityTimelineReader(
        monitor: monitor, journal: journal, journalStore: js, database: db);
  }

  Future<void> fails(int n) async {
    for (int i = 0; i < n; i++) {
      monitor.onVerifiedAttempt(_fail());
    }
    await monitor.idle();
  }

  Future<void> outcome(int trig, {String? gen = _g1}) async {
    journal.recordEvent(SecurityJournalEventType.captureSaved,
        CaptureSavedFields(trig, tgen: gen));
    await journal.idle();
  }

  Future<void> photo(int seq, {String? gen = _g1, int fill = 0x21}) async {
    expect(
        await evidence.save(
            seq: seq,
            gen: gen,
            currentGen: gen,
            jpeg: jpegWithMetadata(fill: fill)),
        EvidenceSaveResult.saved);
  }

  Future<IntruderFailureLog> log() async =>
      ((await IntruderFailureLogStore(db, cipher: cipher).read())
              as IntruderLogLoaded)
          .log;

  Future<SecurityJournalDocument> doc() async =>
      ((await SecurityEventJournalStore(db, cipher: cipher).read())
              as SecurityJournalLoaded)
          .document;

  Future<Set<String>> photos() async => (await evidence.list())
      .map((EvidenceItem e) => '${e.gen ?? 'L'}:${e.seq}')
      .toSet();

  Future<int> declaredJournalVersion() async {
    final String raw = (await db.getSetting(_jKey))!;
    return (jsonDecode(await cipher.decryptString(raw.substring(7)))
        as Map<String, Object?>)['v']! as int;
  }
}

SettingsCipher _cipher() => AesGcmSettingsCipher(InMemorySecretStore(),
    database: InMemoryLocalDatabase());

/// Standard pre-clear history: attempts G1:0..2, outcomes G1 0..2 + one
/// legacy outcome, photos G1:0, G1:2 and legacy L:7, unrelated rows.
Future<_World> _seed({_Db? db}) async {
  final _World w = _World(db ?? _Db(), _cipher());
  for (final MapEntry<String, String> e in _unrelated.entries) {
    await w.db.setSetting(e.key, e.value);
  }
  await w.photo(7, gen: null, fill: 0x07);
  await w.fails(3);
  for (int t = 0; t <= 2; t++) {
    await w.outcome(t);
  }
  await w.outcome(9, gen: null); // legacy outcome
  await w.photo(0);
  await w.photo(2);
  expect((await w.log()).gen, _g1);
  return w;
}

bool _valid() => true;

Map<String, String> _only(Map<String, String> all, Set<String> keys) =>
    <String, String>{
      for (final String k in keys)
        if (all.containsKey(k)) k: all[k]!,
    };

Map<String, String> _evidenceRows(Map<String, String> all) => <String, String>{
      for (final MapEntry<String, String> e in all.entries)
        if (e.key.startsWith('intruder_evidence')) e.key: e.value,
    };

HistoryClearedFields? _marker(SecurityJournalDocument d) =>
    d.historyMarker?.fields as HistoryClearedFields?;

void main() {
  group('CH happy path', () {
    test(
        'CH-00 history only: attempts/outcomes/events removed; nextSeq, run, '
        'gen kept; marker done; photos untouched; unrelated rows identical',
        () async {
      final _World w = await _seed();
      final IntruderFailureLog before = await w.log();
      final SecurityJournalDocument jBefore = await w.doc();
      final Map<String, String> evBefore =
          _evidenceRows(await w.db.getAllSettings());
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      final IntruderFailureLog after = await w.log();
      expect(after.events, isEmpty);
      expect(after.nextSeq, before.nextSeq);
      expect(after.consecutiveFailures, before.consecutiveFailures);
      expect(after.gen, before.gen);
      final SecurityJournalDocument j = await w.doc();
      expect(j.events.map((SecurityJournalEvent e) => e.type),
          <SecurityJournalEventType>[SecurityJournalEventType.historyCleared]);
      final HistoryClearedFields m = _marker(j)!;
      expect(m.state, HistoryClearState.done);
      expect(m.scope, HistoryClearScope.history);
      expect(m.cut, 3);
      expect(m.cutGen, _g1);
      expect(m.bidCut, isNull);
      expect(j.events.single.seq, jBefore.nextSeq, reason: 'seq continues');
      expect(j.discarded, jBefore.discarded);
      expect(j.lost, jBefore.lost);
      expect(await w.declaredJournalVersion(), 4);
      expect(_evidenceRows(await w.db.getAllSettings()), evBefore);
      expect(_only(await w.db.getAllSettings(), _unrelated.keys.toSet()),
          _unrelated);
      final SecurityTimelineSnapshot snap = await w.reader.load();
      expect(snap.entries.map((TimelineEntry e) => e.kind),
          <TimelineEntryKind>[TimelineEntryKind.historyCleared]);
      expect(snap.historyClearPending, isFalse);
      expect(
          snap.sources
              .firstWhere((TimelineSourceStatus s) =>
                  s.source == TimelineSource.failedAttempts)
              .discarded,
          0,
          reason: 'cleared attempts are not reported as retention losses');
    });

    test(
        'CH-00p history + photos: photos of the cleared attempts (and legacy '
        'photos) removed with their blob rows; marker records bc', () async {
      final _World w = await _seed();
      expect(await w.photos(), <String>{'L:7', '$_g1:0', '$_g1:2'});
      expect(await w.service.clear(photos: true, stillValid: _valid),
          HistoryClearOutcome.done);
      expect(await w.photos(), isEmpty);
      final Map<String, String> all = await w.db.getAllSettings();
      expect(
          all.keys.where((String k) => k.startsWith('intruder_evidence_blob')),
          isEmpty);
      final HistoryClearedFields m = _marker(await w.doc())!;
      expect(m.scope, HistoryClearScope.historyPhotos);
      expect(m.bidCut, 2);
      expect(_only(all, _unrelated.keys.toSet()), _unrelated);
    });
  });

  group('CH crash points (restart after each)', () {
    Future<_World> crashAt(String key, int allowedWrites,
        {bool photos = true}) async {
      final _Db db = _Db();
      final _World w = await _seed(db: db);
      db.allow[key] = allowedWrites;
      expect(await w.service.clear(photos: photos, stillValid: _valid),
          HistoryClearOutcome.interrupted);
      db.allow.clear();
      w.build(); // restart
      return w;
    }

    test('CH-01 before (a): the marker write fails -> nothing changed',
        () async {
      final _Db db = _Db();
      final _World w = await _seed(db: db);
      final Map<String, String> before = await db.getAllSettings();
      db.allow[_jKey] = 0;
      expect(await w.service.clear(photos: true, stillValid: _valid),
          HistoryClearOutcome.failed);
      db.allow.clear();
      expect(await db.getAllSettings(), before);
    });

    test(
        'CH-02 after (a): marker pending; log/photos intact; C hidden; '
        'restart performs zero deletions (CH-07)', () async {
      final _World w = await crashAt(_logKey, 0);
      final Map<String, String> rows = await w.db.getAllSettings();
      expect((await w.log()).events, hasLength(3), reason: 'log untouched');
      expect(await w.photos(), hasLength(3), reason: 'photos untouched');
      expect(_marker(await w.doc())!.state, HistoryClearState.pending);
      await w.journal.startup();
      await w.evidence.startupMaintenance();
      final SecurityTimelineSnapshot snap = await w.reader.load();
      expect(snap.historyClearPending, isTrue);
      expect(snap.entries.map((TimelineEntry e) => e.kind),
          <TimelineEntryKind>[TimelineEntryKind.historyCleared]);
      final Map<String, String> after = await w.db.getAllSettings();
      expect(after[_logKey], rows[_logKey], reason: 'CH-07 no auto-resume');
      expect(_evidenceRows(after), _evidenceRows(rows));
      expect(_marker(await w.doc())!.state, HistoryClearState.pending);
    });

    test('CH-03 after (b): log cleared, photos intact, marker pending',
        () async {
      final _World w = await crashAt(_idxKey, 0);
      expect((await w.log()).events, isEmpty);
      expect(await w.photos(), hasLength(3));
      expect(_marker(await w.doc())!.state, HistoryClearState.pending);
      expect((await w.reader.load()).historyClearPending, isTrue);
    });

    test('CH-04 after (c): everything removed, marker still pending', () async {
      final _World w = await crashAt(_jKey, 1);
      expect((await w.log()).events, isEmpty);
      expect(await w.photos(), isEmpty);
      expect(_marker(await w.doc())!.state, HistoryClearState.pending);
    });

    test(
        'CH-05 finish after a crash runs only the remaining steps with the '
        'marker\'s fixed cut', () async {
      final _World w = await crashAt(_logKey, 0);
      final HistoryClearedFields m0 = _marker(await w.doc())!;
      expect(
          await w.service.finish(stillValid: _valid), HistoryClearOutcome.done);
      final HistoryClearedFields m1 = _marker(await w.doc())!;
      expect(m1.state, HistoryClearState.done);
      expect(<Object?>[m1.cut, m1.cutGen, m1.bidCut, m1.scope],
          <Object?>[m0.cut, m0.cutGen, m0.bidCut, m0.scope]);
      expect((await w.log()).events, isEmpty);
      expect(await w.photos(), isEmpty);
      expect(await w.service.finish(stillValid: _valid),
          HistoryClearOutcome.refused,
          reason: 'nothing left to finish');
    });

    test(
        'CH-09 attempts, outcomes and photos recorded while pending survive '
        'finish and are always shown', () async {
      final _World w = await crashAt(_logKey, 0);
      await w.fails(1); // seq 3 (after the cut)
      await w.outcome(3);
      await w.photo(3);
      SecurityTimelineSnapshot snap = await w.reader.load();
      expect(
          snap.entries
              .where(
                  (TimelineEntry e) => e.kind == TimelineEntryKind.failedUnlock)
              .map((TimelineEntry e) => e.sourceSeq),
          <int>[3]);
      expect(
          await w.service.finish(stillValid: _valid), HistoryClearOutcome.done);
      expect((await w.log()).events.map((FailedAttemptEvent e) => e.seq),
          <int>[3]);
      expect(await w.photos(), <String>{'$_g1:3'});
      snap = await w.reader.load();
      expect(snap.entries.map((TimelineEntry e) => '${e.kind.name}:${e.trig}'),
          containsAll(<String>['captureSaved:3', 'historyCleared:null']));
    });

    test(
        'CH-10 generation rolled while pending (corrupt log -> new '
        'generation): the new generation is untouched and visible', () async {
      final _World w = await crashAt(_logKey, 0);
      // Corrupt row; the quarantine slot must be free for the monitor to
      // preserve it and reinitialize (F-KEY-1 G-4 refuses otherwise).
      await w.db.removeSetting(IntruderFailureLogStore.quarantineKey);
      await w.db.setSetting(_logKey, 'garbage');
      w.build();
      w.live = _g2;
      await w.fails(2); // G2 seq 0, 1 (seq < cut, other generation)
      await w.photo(1, gen: _g2);
      expect((await w.log()).gen, _g2);
      SecurityTimelineSnapshot snap = await w.reader.load();
      expect(
          snap.entries
              .where(
                  (TimelineEntry e) => e.kind == TimelineEntryKind.failedUnlock)
              .map((TimelineEntry e) => e.sourceSeq)
              .toSet(),
          <int>{0, 1});
      expect(
          await w.service.finish(stillValid: _valid), HistoryClearOutcome.done);
      expect((await w.log()).events, hasLength(2));
      expect(await w.photos(), <String>{'$_g2:1'},
          reason: 'old-generation photos removed, the new one kept');
      snap = await w.reader.load();
      expect(
          snap.entries
              .where(
                  (TimelineEntry e) => e.kind == TimelineEntryKind.failedUnlock)
              .length,
          2);
    });

    test(
        'CH-13 session ends between steps: stop at once, marker pending, '
        'nothing further written', () async {
      final _World w = await _seed();
      final IntruderFailureLog logBefore = await w.log();
      final Map<String, String> evBefore =
          _evidenceRows(await w.db.getAllSettings());
      final int base = w.db.journalWrites;
      // The session ends the moment step (a) is durable.
      expect(
          await w.service.clear(
              photos: true, stillValid: () => w.db.journalWrites == base),
          HistoryClearOutcome.interrupted);
      expect(w.db.journalWrites, base + 1);
      final Map<String, String> after = await w.db.getAllSettings();
      expect((await w.log()).events, hasLength(logBefore.events.length));
      expect(_evidenceRows(after), evBefore);
      expect(_marker(await w.doc())!.state, HistoryClearState.pending);
    });
  });

  group('CH pre-check / unavailable / corrupt storage (zero writes)', () {
    Future<void> refusedZeroWrites(_World w, {required bool photos}) async {
      await w.journal.read(); // settle any pending journal maintenance
      final Map<String, String> before = await w.db.getAllSettings();
      final int writes = w.db.writes;
      expect(await w.service.clear(photos: photos, stillValid: _valid),
          HistoryClearOutcome.refused);
      expect(w.db.writes, writes);
      expect(await w.db.getAllSettings(), before);
    }

    test('CH-12a failure log corrupt: refused; NOT quarantined or reset',
        () async {
      final _World w = await _seed();
      await w.db.setSetting(_logKey, 'garbage');
      await w.db.removeSetting(IntruderFailureLogStore.quarantineKey);
      w.build();
      await refusedZeroWrites(w, photos: false);
      expect(await w.db.getSetting(_logKey), 'garbage');
      expect(
          await w.db.getSetting(IntruderFailureLogStore.quarantineKey), isNull);
    });

    test('CH-12b failure log from a newer version: refused', () async {
      final _World w = await _seed();
      await w.db.setSetting(
          _logKey,
          jsonEncode(
              <String, Object?>{'schema': IntruderFailureLog.schema, 'v': 9}));
      w.build();
      await refusedZeroWrites(w, photos: true);
    });

    test('CH-12c failure log unreadable (undecryptable): refused', () async {
      final _World w = await _seed();
      final _World other = _World(w.db, _cipher()); // wrong key
      await refusedZeroWrites(other, photos: false);
    });

    test('CH-12d journal from a newer version: refused, row byte-identical',
        () async {
      final _World w = await _seed();
      const String newer =
          '{"schema":"sal.security_journal","v":5,"nextSeq":0,"events":[]}';
      await w.db
          .setSetting(_jKey, 'enc:v1:${await w.cipher.encryptString(newer)}');
      w.build();
      await refusedZeroWrites(w, photos: false);
    });

    test(
        'CH-12e photos requested but the evidence index is from a newer '
        'version: refused; history-only still clears and never touches it',
        () async {
      final _World w = await _seed();
      final String ev =
          'enc:v1:${await w.cipher.encryptString('{"v":3,"items":[]}')}';
      await w.db.setSetting(_idxKey, ev);
      await refusedZeroWrites(w, photos: true);
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      expect(await w.db.getSetting(_idxKey), ev);
    });

    test(
        'CH-12f journal storage throwing: refused or failed, failure log '
        'and photos byte-identical', () async {
      final _World w = await _seed();
      final Map<String, String> before = await w.db.getAllSettings();
      w.db.allow[_jKey] = 0;
      w.build();
      final HistoryClearOutcome r =
          await w.service.clear(photos: true, stillValid: _valid);
      expect(r, anyOf(HistoryClearOutcome.refused, HistoryClearOutcome.failed));
      final Map<String, String> after = await w.db.getAllSettings();
      expect(after[_logKey], before[_logKey]);
      expect(_evidenceRows(after), _evidenceRows(before));
    });

    test(
        'CH-08 session already ended: cancelled, zero writes (clear and '
        'finish)', () async {
      final _World w = await _seed();
      await w.journal.read();
      final int writes = w.db.writes;
      expect(await w.service.clear(photos: true, stillValid: () => false),
          HistoryClearOutcome.cancelled);
      expect(await w.service.finish(stillValid: () => false),
          HistoryClearOutcome.cancelled);
      expect(w.db.writes, writes);
    });
  });

  // Added after mutation run 1 (B4-3 and CH-M5 survived); new tests only.
  group('CH mutation follow-up', () {
    test(
        'CH-25 step (a) alone already drops the cleared outcomes from the '
        'stored journal (pending row never persists cleared history)',
        () async {
      final _Db db = _Db();
      final _World w = await _seed(db: db);
      db.allow[_logKey] = 0; // crash right after (a)
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.interrupted);
      db.allow.clear();
      w.build();
      final SecurityJournalDocument d = await w.doc();
      expect(_marker(d)!.state, HistoryClearState.pending);
      expect(
          d.events.where((SecurityJournalEvent e) => e.type.isOutcome), isEmpty,
          reason: 'all seeded outcomes (gen trig 0..2 and legacy) are in C');
    });

    test(
        'CH-26 finish re-checks stillValid at every step: session ends after '
        'finish starts -> nothing deleted, marker stays pending', () async {
      final _Db db = _Db();
      final _World w = await _seed(db: db);
      db.allow[_logKey] = 0;
      expect(await w.service.clear(photos: true, stillValid: _valid),
          HistoryClearOutcome.interrupted);
      db.allow.clear();
      w.build();
      final Map<String, String> before = await db.getAllSettings();
      int calls = 0;
      // Valid for finish's own entry check only; the session then ends.
      final HistoryClearOutcome r =
          await w.service.finish(stillValid: () => calls++ == 0);
      expect(r, isNot(HistoryClearOutcome.done));
      expect(await db.getAllSettings(), before, reason: 'zero writes');
      expect((await w.log()).events, hasLength(3));
      expect(_marker(await w.doc())!.state, HistoryClearState.pending);
    });
  });

  // ENG-04 (DURABLE_IDENTITY v2 §9): clear in engine A, then a write in
  // engine B whose caches were warmed before the clear. The failure log is
  // CAS-protected (Q-ENG-1), so it holds. The journal and the evidence index
  // are NOT CAS-protected (R8 / R-P13M3-T1 OPEN); ENG-04j pins the measured
  // behaviour of the journal so the limitation is visible, not hidden.
  group('ENG-04 second engine with stale caches', () {
    Future<(_World, _World)> twoEngines() async {
      final _World a = await _seed();
      final _World b = _World(a.db, a.cipher, mints: <String>[]);
      await b.monitor.snapshot(); // warm B's failure-log cache
      await b.journal.startup();
      await b.journal.read(); // warm B's journal cache
      expect(await a.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      return (a, b);
    }

    test(
        'ENG-04a failure log: B records a failure after A cleared -> '
        'cleared attempts stay cleared (CAS reload)', () async {
      final (_World a, _World b) = await twoEngines();
      await b.fails(1);
      final IntruderFailureLog log = await a.log();
      expect(log.gen, _g1);
      expect(log.events.map((FailedAttemptEvent e) => e.seq), <int>[3]);
    });

    test(
        'ENG-04j journal (KNOWN LIMITATION, no CAS): B records an outcome '
        'from its stale cache -> marker lost and cleared outcomes return',
        () async {
      final (_World a, _World b) = await twoEngines();
      await b.outcome(3);
      final SecurityJournalDocument d = await a.doc();
      // Measured behaviour (not desired): pinned so that adding journal CAS
      // (E-2) flips this test and forces it to be rewritten as a guarantee.
      expect(_marker(d), isNull);
      expect(
          d.events.where((SecurityJournalEvent e) => e.type.isOutcome).length,
          greaterThan(1));
    });
  });

  group('CH identity, idempotency, linkage', () {
    test(
        'CH-11 TL-3: unrelated rows, quarantine rows, run counter and '
        'nextSeq byte-identical across clear and finish', () async {
      final _World w = await _seed();
      final IntruderFailureLog l0 = await w.log();
      expect(await w.service.clear(photos: true, stillValid: _valid),
          HistoryClearOutcome.done);
      expect(await w.service.finish(stillValid: _valid),
          HistoryClearOutcome.refused);
      expect(_only(await w.db.getAllSettings(), _unrelated.keys.toSet()),
          _unrelated);
      final IntruderFailureLog l1 = await w.log();
      expect(<Object?>[l1.nextSeq, l1.consecutiveFailures, l1.gen],
          <Object?>[l0.nextSeq, l0.consecutiveFailures, l0.gen]);
    });

    test('CH-14 every step is idempotent: repeating it writes nothing',
        () async {
      final _World w = await _seed();
      expect(await w.service.clear(photos: true, stillValid: _valid),
          HistoryClearOutcome.done);
      final HistoryClearedFields m = _marker(await w.doc())!;
      final int seq = (await w.doc()).historyMarker!.seq;
      final int writes = w.db.writes;
      expect(
          await w.monitor.clearEventsBefore(
              IntruderHistoryCut(gen: m.cutGen, nextSeq: m.cut)),
          IntruderHistoryClearResult.cleared);
      expect(
          await w.evidence.clearHistoryItems(
              cutGen: m.cutGen, cutSeq: m.cut, bidCut: m.bidCut!, liveGen: _g1),
          EvidenceClearResult.cleared);
      expect(await w.journal.completeHistoryClear(seq),
          HistoryClearJournalResult.committed);
      expect(w.db.writes, writes);
    });

    test(
        'CH-15 a late capture for a cleared attempt is refused; captures '
        'for later attempts are saved', () async {
      final _World w = await _seed();
      expect(await w.service.clear(photos: true, stillValid: _valid),
          HistoryClearOutcome.done);
      for (final int seq in <int>[0, 1, 2]) {
        expect(
            await w.evidence.save(
                seq: seq, gen: _g1, currentGen: _g1, jpeg: jpegWithMetadata()),
            EvidenceSaveResult.superseded,
            reason: 'G1:$seq');
      }
      expect(await w.evidence.save(seq: 7, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.superseded,
          reason: 'legacy');
      await w.fails(1);
      await w.photo(3);
      expect(await w.photos(), <String>{'$_g1:3'});
    });

    test(
        'CH-16 a late outcome of a cleared attempt is never stored; later '
        'outcomes are', () async {
      final _World w = await _seed();
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      await w.outcome(1);
      await w.outcome(11, gen: null);
      await w.outcome(3);
      await w.outcome(0, gen: _g2); // other generation: never cleared
      final List<String> stored = (await w.doc())
          .events
          .where((SecurityJournalEvent e) => e.type.isOutcome)
          .map(
              (SecurityJournalEvent e) => '${e.fields!.tgen}:${e.fields!.trig}')
          .toList();
      expect(stored, <String>['$_g1:3', '$_g2:0']);
    });

    test(
        'CH-17 the marker is exempt from age retention and caps; one marker '
        'only; a new clear replaces it and covers later history', () async {
      final _World w = await _seed();
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      final DateTime late = _t0.add(const Duration(days: 400));
      final SecurityEventJournal j = SecurityEventJournal(
          store: SecurityEventJournalStore(w.db, cipher: w.cipher),
          now: () => late,
          maxEvents: 5,
          maxEncodedBytes: 900);
      for (int t = 100; t < 130; t++) {
        j.recordEvent(SecurityJournalEventType.captureSaved,
            CaptureSavedFields(t, tgen: _g2));
      }
      await j.idle();
      SecurityJournalDocument d = await w.doc();
      expect(d.historyMarker, isNotNull);
      expect(d.events.length, lessThanOrEqualTo(5));
      w.build();
      await w.fails(2); // G1 seq 3, 4
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      d = await w.doc();
      expect(
          d.events
              .where((SecurityJournalEvent e) =>
                  e.type == SecurityJournalEventType.historyCleared)
              .length,
          1);
      expect(_marker(d)!.cut, 5);
      expect((await w.log()).events, isEmpty);
    });

    test(
        'CH-18 legacy history (pre-Batch-3 v1 log, v2 journal, v1 index) is '
        'cleared; the log adopts a generation first; new attempts shown',
        () async {
      final _Db db = _Db();
      final SettingsCipher c = _cipher();
      final oldm.IntruderMonitor om = oldm.IntruderMonitor(
          store: oldl.IntruderFailureLogStore(db, cipher: c), now: () => _t0);
      om.onVerifiedAttempt(_fail());
      om.onVerifiedAttempt(_fail());
      await om.idle();
      final oldj.SecurityEventJournal oj = oldj.SecurityEventJournal(
          store: oldj.SecurityEventJournalStore(db, cipher: c), now: () => _t0);
      await oj.startup();
      oj.recordEvent(oldj.SecurityJournalEventType.captureSaved,
          const oldj.CaptureSavedFields(1));
      await oj.idle();
      final olde.IntruderEvidenceStore oe =
          olde.IntruderEvidenceStore(db, c, now: () => _t0);
      expect(await oe.save(seq: 1, jpeg: jpegWithMetadata()),
          olde.EvidenceSaveResult.saved);
      final _World w = _World(db, c);
      expect((await w.log()).gen, isNull);
      expect(await w.service.clear(photos: true, stillValid: _valid),
          HistoryClearOutcome.done);
      final IntruderFailureLog l = await w.log();
      expect(l.gen, _g1, reason: 'adopted before the cut');
      expect(l.events, isEmpty);
      expect(l.nextSeq, 2);
      expect(await w.photos(), isEmpty);
      expect(
          (await w.doc())
              .events
              .where((SecurityJournalEvent e) => e.type.isOutcome),
          isEmpty);
      await w.fails(1);
      final SecurityTimelineSnapshot snap = await w.reader.load();
      expect(
          snap.entries
              .where(
                  (TimelineEntry e) => e.kind == TimelineEntryKind.failedUnlock)
              .map((TimelineEntry e) => e.sourceSeq),
          <int>[2]);
    });

    test(
        'CH-19 unrelated evidence is never deleted: only legacy, cut-gen '
        'seq < cut and other-gen bid < bidCut photos go', () async {
      final _Db db = _Db();
      final _World w = _World(db, _cipher());
      await w.photo(5, gen: null); // legacy -> removed
      await w.photo(0, gen: _g2); // other gen, bid 0 -> removed
      await w.photo(1, gen: _g1); // cut gen, seq 1 < 3 -> removed (bid 1)
      await w.photo(4, gen: _g1); // cut gen, seq 4 >= 3 -> kept (bid 2)
      final Map<String, String> before = await db.getAllSettings();
      final List<EvidenceItem> items = await w.evidence.list();
      final EvidenceItem keep =
          items.firstWhere((EvidenceItem e) => e.seq == 4);
      expect(
          await w.evidence.clearHistoryItems(
              cutGen: _g1, cutSeq: 3, bidCut: 2, liveGen: _g1),
          EvidenceClearResult.cleared);
      expect(await w.photos(), <String>{'$_g1:4'});
      final String k = IntruderEvidenceStore.blobKey2(keep.bid!);
      expect((await db.getAllSettings())[k], before[k]);
      // A photo id at/after bidCut of another generation is kept.
      final _World w2 = _World(_Db(), _cipher());
      await w2.photo(0, gen: _g2); // bid 0
      await w2.photo(9, gen: _g1); // bid 1, cut gen, seq >= cut
      expect(
          await w2.evidence.clearHistoryItems(
              cutGen: _g1, cutSeq: 3, bidCut: 0, liveGen: _g1),
          EvidenceClearResult.cleared);
      expect(await w2.photos(), <String>{'$_g2:0', '$_g1:9'});
    });

    test(
        'CH-20 the photo rule in the store equals the marker rule '
        '(HistoryClearedFields.clearsPhoto)', () async {
      const HistoryClearedFields m = HistoryClearedFields(
          scope: HistoryClearScope.historyPhotos,
          state: HistoryClearState.done,
          cut: 3,
          cutGen: _g1,
          bidCut: 2);
      final List<(String?, int, int?)> cases = <(String?, int, int?)>[
        (null, 5, null),
        (_g2, 0, 0),
        (_g2, 0, 2),
        (_g1, 1, 1),
        (_g1, 4, 0),
        (_g1, 2, 9),
      ];
      for (final (String? g, int seq, int? bid) in cases) {
        final bool store = g == null || bid == null
            ? true
            : g == _g1
                ? seq < 3
                : bid < 2;
        expect(m.clearsPhoto(g, seq, bid), store, reason: '$g:$seq:$bid');
      }
    });

    test(
        'CH-21 a clear with no generation-bearing history hides nothing that '
        'is recorded later', () async {
      final _World w = _World(_Db(), _cipher());
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      expect(_marker(await w.doc())!.cutGen, isNull);
      await w.fails(2);
      final SecurityTimelineSnapshot snap = await w.reader.load();
      expect(
          snap.entries
              .where(
                  (TimelineEntry e) => e.kind == TimelineEntryKind.failedUnlock)
              .length,
          2);
    });
  });

  group('CH codec + downgrade', () {
    Map<String, Object?> markerEvent(Map<String, Object?> f) =>
        <String, Object?>{
          'seq': 0,
          'at': _t0.millisecondsSinceEpoch,
          'type': 'historyCleared',
          'f': f,
        };
    Map<String, Object?> docOf(int v, List<Object?> events) =>
        <String, Object?>{
          'schema': SecurityJournalDocument.schema,
          'v': v,
          'nextSeq': 5,
          'discarded': 0,
          'lost': 0,
          'events': events,
        };

    test('CH-22 strict codec: v4 <=> exactly one marker; marker keys strict',
        () {
      final Map<String, Object?> ok = markerEvent(<String, Object?>{
        'scope': 'history',
        'st': 'done',
        'cut': 3,
        'cg': _g1
      });
      expect(
          SecurityJournalDocument.fromJson(docOf(4, <Object?>[ok]))
              .historyMarker,
          isNotNull);
      final List<Map<String, Object?>> bad = <Map<String, Object?>>[
        docOf(3, <Object?>[ok]), // marker before v4
        docOf(4, <Object?>[]), // v4 without marker
        docOf(4, <Object?>[
          ok,
          <String, Object?>{...ok, 'seq': 1}
        ]), // two
        docOf(4, <Object?>[
          markerEvent(<String, Object?>{
            'scope': 'historyPhotos',
            'st': 'done',
            'cut': 3
          })
        ]), // photos without bc
        docOf(4, <Object?>[
          markerEvent(<String, Object?>{
            'scope': 'history',
            'st': 'done',
            'cut': 3,
            'bc': 1
          })
        ]), // bc without photos
        docOf(4, <Object?>[
          markerEvent(<String, Object?>{
            'scope': 'history',
            'st': 'done',
            'cut': 3,
            'cg': 'x'
          })
        ]),
        docOf(4, <Object?>[
          markerEvent(
              <String, Object?>{'scope': 'history', 'st': 'maybe', 'cut': 3})
        ]),
        docOf(4, <Object?>[
          markerEvent(
              <String, Object?>{'scope': 'history', 'st': 'done', 'cut': -1})
        ]),
        docOf(4, <Object?>[
          markerEvent(<String, Object?>{
            'scope': 'history',
            'st': 'done',
            'cut': 1,
            'x': 1
          })
        ]),
        docOf(4, <Object?>[
          <String, Object?>{...ok, 'cb': true}
        ]),
      ];
      for (final Map<String, Object?> b in bad) {
        expect(() => SecurityJournalDocument.fromJson(b), throwsFormatException,
            reason: jsonEncode(b));
      }
    });

    test(
        'CH-23 downgrade: the Batch-3 build and the pre-Batch-3 build read a '
        'cleared (v4) journal as unsupported — never corrupt, never written',
        () async {
      final _World w = await _seed();
      expect(await w.service.clear(photos: false, stillValid: _valid),
          HistoryClearOutcome.done);
      final Map<String, String> before = await w.db.getAllSettings();
      final Object b3r =
          await b3.SecurityEventJournalStore(w.db, cipher: w.cipher).read();
      expect(b3r, isA<b3.SecurityJournalUnsupported>());
      final oldj.SecurityEventJournal oj = oldj.SecurityEventJournal(
          store: oldj.SecurityEventJournalStore(w.db, cipher: w.cipher),
          now: () => _t0);
      await oj.startup();
      oj.recordEvent(oldj.SecurityJournalEventType.captureSaved,
          const oldj.CaptureSavedFields(5));
      await oj.idle();
      expect((await oj.read()).availability,
          oldj.SecurityJournalAvailability.unsupported);
      expect(await w.db.getAllSettings(), before);
    });

    test('CH-24 an uncleared journal stays v3 (Batch-3 builds unaffected)',
        () async {
      final _World w = await _seed();
      expect(await w.declaredJournalVersion(), 3);
    });

    test('legacy_b3 fixture integrity (verbatim except import paths)',
        () async {
      final List<String> lines =
          await File('test/security/history/legacy_b3/MANIFEST.txt')
              .readAsLines();
      for (final String l in lines.where((String l) => l.contains('  '))) {
        final List<String> p = l.split('  ');
        String src = await File('test/security/history/legacy_b3/${p[1]}')
            .readAsString();
        src = src
            .replaceAll(
                "import 'package:smart_app_lock/data/storage/local_database.dart';",
                "import '../../data/storage/local_database.dart';")
            .replaceAll(
                "import 'package:smart_app_lock/security/encryption/settings_cipher.dart';",
                "import '../encryption/settings_cipher.dart';");
        expect(sha256.convert(utf8.encode(src)).toString(), p[0], reason: p[1]);
      }
      expect(lines.where((String l) => l.contains('  ')), hasLength(2));
    });
  });
}
