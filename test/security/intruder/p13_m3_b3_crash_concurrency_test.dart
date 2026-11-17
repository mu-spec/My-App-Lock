// P13/M3 Batch 3 — generation identity: concurrency and crash recovery.
//
// P4 §5 rows not covered elsewhere:
//   G-3 confirmed / not-confirmed-with-a-concurrent-writer,
//   G-6 bounded conflicts, G-7 "Clear All does not change gen".
// B2 §6 mutation targets: the gen is never reused on re-init (corrupt or
// missing row), the blob id is never reused (delete / clear / new
// instance), no non-secure generator exists, and an interrupted save
// (blob written, index not) is recovered at startup.
import 'dart:io';
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
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';

import '../../support/intruder_fixtures.dart';

const String _g1 = 'Gen1__________________';
const String _g2 = 'Gen2__________________';
const String _logKey = IntruderFailureLogStore.storageKey;
final DateTime _t0 = DateTime(2026, 10, 22, 12);
int _vid = 0;

VerifiedAttempt _fail([String? vid]) => VerifiedAttempt(
      verificationId: vid ?? 'c:${++_vid}',
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
          reason: AuthFailureReason.wrongCredential, remainingAttempts: 2),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

String Function() _mints(List<String> ids) {
  final List<String> q = List<String>.of(ids);
  return () => q.isEmpty ? throw StateError('unexpected mint') : q.removeAt(0);
}

String Function() _counterMint() {
  int n = 0;
  return () => 'Mint${(n++).toString().padLeft(18, '_')}';
}

enum _Mode { none, commitThenUnknown, foreignThenUnknown, alwaysConflict }

class _FaultDb extends InMemoryLocalDatabase {
  _Mode mode = _Mode.none;
  String? foreign;
  int logCas = 0;

  @override
  Future<CasOutcome> compareAndSetSetting(
    String key, {
    required String? expected,
    required String next,
  }) async {
    if (key != _logKey) {
      return super.compareAndSetSetting(key, expected: expected, next: next);
    }
    logCas++;
    switch (mode) {
      case _Mode.none:
        return super.compareAndSetSetting(key, expected: expected, next: next);
      case _Mode.commitThenUnknown:
        mode = _Mode.none;
        final CasOutcome o = await super
            .compareAndSetSetting(key, expected: expected, next: next);
        expect(o, CasOutcome.committed);
        throw const CasUnknownOutcome(CasUnknownCode.io);
      case _Mode.foreignThenUnknown:
        mode = _Mode.none;
        // Another engine's write lands; ours does not.
        await super.setSetting(key, foreign!);
        throw const CasUnknownOutcome(CasUnknownCode.busy);
      case _Mode.alwaysConflict:
        return CasOutcome.conflict;
    }
  }
}

class _Heard implements IntruderEventListener {
  final List<FailedAttemptEvent> events = <FailedAttemptEvent>[];
  @override
  void onFailedAttemptRecorded(FailedAttemptEvent event) => events.add(event);
  @override
  void onOwnerVerified() {}
}

SettingsCipher _cipher() => AesGcmSettingsCipher(InMemorySecretStore(),
    database: InMemoryLocalDatabase());

void main() {
  late _FaultDb db;
  late SettingsCipher cipher;
  setUp(() {
    db = _FaultDb();
    cipher = _cipher();
  });

  IntruderMonitor mon(String Function() mint) => IntruderMonitor(
      store: IntruderFailureLogStore(db, cipher: cipher),
      now: () => _t0,
      mintGeneration: mint);

  Future<IntruderFailureLog> durable() async =>
      ((await IntruderFailureLogStore(db, cipher: cipher).read())
              as IntruderLogLoaded)
          .log;

  Future<String> plain() async =>
      cipher.decryptString((await db.getSetting(_logKey))!.substring(7));

  group('G: generation under unknown outcomes and conflicts (P4 §5)', () {
    test(
        'G-3a unknown-then-CONFIRMED: the minted gen is used exactly once '
        '(no second mint, the event is recorded once)', () async {
      final IntruderMonitor a = mon(_mints(<String>[_g1]));
      db.mode = _Mode.commitThenUnknown;
      a.onVerifiedAttempt(_fail('U1'));
      await a.idle();
      a.onVerifiedAttempt(_fail('U2'));
      await a.idle();
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g1);
      expect(a.generationsMinted, 1);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId),
          <String>['U1', 'U2']);
      expect(l.events.every((FailedAttemptEvent e) => e.logGen == _g1), isTrue);
    });

    test(
        'G-3b unknown-then-NOT-confirmed with a concurrent writer: the '
        'stored gen is adopted; ours is never persisted', () async {
      // The other engine's row (same cipher), generation g2.
      final InMemoryLocalDatabase other = InMemoryLocalDatabase();
      final IntruderMonitor b = IntruderMonitor(
          store: IntruderFailureLogStore(other, cipher: cipher),
          now: () => _t0,
          mintGeneration: _mints(<String>[_g2]));
      b.onVerifiedAttempt(_fail('B1'));
      await b.idle();
      db.foreign = await other.getSetting(_logKey);

      final IntruderMonitor a = mon(_mints(<String>[_g1]));
      db.mode = _Mode.foreignThenUnknown;
      a.onVerifiedAttempt(_fail('A1'));
      await a.idle();
      a.onVerifiedAttempt(_fail('A2'));
      await a.idle();
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g2);
      expect(await plain(), isNot(contains(_g1)));
      expect(l.events.first.verificationId, 'B1');
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId),
          contains('A2'));
      expect(l.events.every((FailedAttemptEvent e) => e.logGen == _g2), isTrue);
      expect(a.generationsMinted, 1);
    });

    // P4 G-6 says "3 conflicts -> storageError". The governing, approved
    // Q-ENG-1 contract (A_Q_ENG_1 §4 L145/L154, committed in Batch 1) says
    // the op is DROPPED and counted in `conflictDrops`, with no listener
    // call. This test pins the contract and the bound (discrepancy
    // disclosed in BATCH_3_STATUS.md; Batch 1 not reopened).
    test(
        'G-6 persistent conflicts: bounded to exactly maxCasAttempts CAS '
        'calls, the record is a counted conflict drop, nothing written, no '
        'listener call', () async {
      final IntruderMonitor a = mon(_counterMint());
      final _Heard heard = _Heard();
      a.listener = heard;
      db.mode = _Mode.alwaysConflict;
      a.onVerifiedAttempt(_fail());
      await a.idle();
      expect(db.logCas, IntruderMonitor.maxCasAttempts);
      expect(IntruderMonitor.maxCasAttempts, 3);
      expect(await db.getSetting(_logKey), isNull);
      expect(a.status.conflictDrops, 1);
      expect(a.status.droppedFailureRecords, 1);
      expect(heard.events, isEmpty);
      expect(a.generationsMinted, lessThanOrEqualTo(3));
    });
  });

  group('G: the generation is never reused on re-init (B2 §6 MG-2)', () {
    test(
        'a corrupt row is re-initialized with a NEW gen (never the last '
        'known one)', () async {
      final IntruderMonitor a = mon(_mints(<String>[_g1, _g2]));
      a.onVerifiedAttempt(_fail());
      await a.idle();
      expect((await durable()).gen, _g1);
      await db.setSetting(
          _logKey, 'enc:v1:${await cipher.encryptString('{x')}');
      a.onVerifiedAttempt(_fail());
      await a.idle();
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g2);
      expect(await plain(), isNot(contains(_g1)));
      expect(a.generationsMinted, 2);
    });

    test('a missing row (deleted) is re-initialized with a NEW gen', () async {
      final IntruderMonitor a = mon(_mints(<String>[_g1, _g2]));
      a.onVerifiedAttempt(_fail());
      await a.idle();
      await db.removeSetting(_logKey);
      a.onVerifiedAttempt(_fail());
      await a.idle();
      expect((await durable()).gen, _g2);
      expect(a.generationsMinted, 2);
    });

    test('G-7 Clear All (evidence) does not change the log gen', () async {
      final IntruderMonitor a = mon(_mints(<String>[_g1]));
      a.onVerifiedAttempt(_fail());
      await a.idle();
      final IntruderEvidenceStore s =
          IntruderEvidenceStore(db, cipher, now: () => _t0);
      expect(await s.save(seq: 0, gen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      expect(await s.clearAll(floorGen: _g1, floorSeq: 0),
          EvidenceClearResult.cleared);
      a.onVerifiedAttempt(_fail());
      await a.idle();
      expect((await durable()).gen, _g1);
      expect(a.generationsMinted, 1);
    });
  });

  group('evidence blob ids and crash recovery', () {
    late IntruderEvidenceStore s;
    setUp(() => s = IntruderEvidenceStore(db, cipher, now: () => _t0));

    Future<Uint8List?> img(int seq) => s.readImage(seq, gen: _g1);

    test(
        'BID-1 a blob id is never reused: after delete, after clear-all, '
        'and by a new store instance', () async {
      final Uint8List a = jpegWithMetadata(fill: 0x21);
      final Uint8List b = jpegWithMetadata(fill: 0x42);
      final Uint8List c = jpegWithMetadata(fill: 0x63);
      expect(await s.save(seq: 1, gen: _g1, jpeg: a), EvidenceSaveResult.saved);
      expect(await s.save(seq: 2, gen: _g1, jpeg: b), EvidenceSaveResult.saved);
      final Uint8List? imgB = await img(2);
      expect(imgB, isNotNull);
      expect(await img(1), isNot(equals(imgB)));
      expect(await s.delete(1, gen: _g1), EvidenceDeleteResult.deleted);
      expect(await s.save(seq: 3, gen: _g1, jpeg: c), EvidenceSaveResult.saved);
      expect((await s.list()).map((EvidenceItem e) => e.bid), <int>[1, 2]);
      expect(await img(2), imgB, reason: 'item 2 still reads its own bytes');
      expect(await db.getSetting(IntruderEvidenceStore.blobKey2(0)), isNull);
      expect(await s.clearAll(floorGen: _g1, floorSeq: 3),
          EvidenceClearResult.cleared);
      final IntruderEvidenceStore fresh =
          IntruderEvidenceStore(db, cipher, now: () => _t0);
      expect(await fresh.save(seq: 4, gen: _g1, jpeg: a),
          EvidenceSaveResult.saved);
      expect((await fresh.list()).single.bid, 3,
          reason: 'ids 0..2 are never handed out again');
    });

    test(
        'CR-1 interrupted save (blob row written, index not): the orphan is '
        'swept at startup, the index is untouched, the next save is intact',
        () async {
      expect(await s.save(seq: 1, gen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      final String idx = (await db.getSetting(IntruderEvidenceStore.indexKey))!;
      // Simulated process death: the next blob row exists, its index entry
      // never committed.
      await db.setSetting(IntruderEvidenceStore.blobKey2(1), 'enc:v1:orphan');
      await s.startupMaintenance();
      expect(await db.getSetting(IntruderEvidenceStore.blobKey2(1)), isNull);
      expect(await db.getSetting(IntruderEvidenceStore.indexKey), idx);
      final Uint8List d = jpegWithMetadata(fill: 0x55);
      expect(await s.save(seq: 2, gen: _g1, jpeg: d), EvidenceSaveResult.saved);
      expect(await img(2), isNotNull);
      expect(await img(1), isNotNull);
    });

    test(
        'CR-2 an index entry whose blob row vanished is dropped by the '
        'sweep; the item is never served from another row', () async {
      expect(await s.save(seq: 1, gen: _g1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      expect(await s.save(seq: 2, gen: _g1, jpeg: jpegWithMetadata(fill: 0x33)),
          EvidenceSaveResult.saved);
      await db.removeSetting(IntruderEvidenceStore.blobKey2(0));
      expect(await img(1), isNull);
      await s.sweepOrphans();
      expect((await s.list()).map((EvidenceItem e) => e.seq), <int>[2]);
      expect(await img(2), isNotNull);
    });
  });

  group('ST: no non-secure generator (B2 §2, P4 planned mutation)', () {
    test('ST-G1 the generation id comes only from Random.secure()', () {
      final String src =
          File('lib/security/intruder/log_generation.dart').readAsStringSync();
      expect(src, contains('?? Random.secure()'));
      for (final String f in <String>[
        'lib/security/intruder/log_generation.dart',
        'lib/security/intruder/intruder_monitor.dart',
        'lib/security/intruder/intruder_evidence_store.dart',
        'lib/security/intruder/failed_attempt_event.dart',
        'lib/security/intruder/intruder_defense_coordinator.dart',
        'lib/security/timeline/security_event_journal.dart',
      ]) {
        // Code only: comment lines are excluded (they may NAME the
        // forbidden constructor).
        final String s = File(f)
            .readAsLinesSync()
            .where((String l) => !l.trimLeft().startsWith('//'))
            .join('\n');
        expect(RegExp(r'Random\(\s*\d*\s*\)').hasMatch(s), isFalse, reason: f);
        expect(s.contains('DateTime.now().microsecondsSinceEpoch.toRadix'),
            isFalse,
            reason: f);
      }
    });
  });
}
