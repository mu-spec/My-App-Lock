// P13/M3 Q-ENG-1 — failure-log persistence through compare-and-set
// (contract A §3/§4, tests T-Q1…T-Q16, ST-1).
//
// SIMULATED: pure Dart VM, in-memory storage with deterministic hooks that
// interleave several monitors sharing ONE database (as several engines /
// isolates share one SQLite file in production). Real-SQL behaviour is in
// test/data/storage/p13_m3_cas_sqlite_test.dart and the RS-* file.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';

const String _key = IntruderFailureLogStore.storageKey;
const String _qKey = IntruderFailureLogStore.quarantineKey;

enum _CasFault { none, commitThenThrow, throwBeforeCommit, hangAfterCommit }

/// One database shared by several monitors, with hooks on the log key.
class _QDb extends InMemoryLocalDatabase {
  _QDb({this.random});

  final Random? random; // seeded interleaving (T-Q4b)
  int logReads = 0;
  int casCalls = 0;
  int commits = 0;
  int conflicts = 0;
  bool failLogReads = false;
  _CasFault fault = _CasFault.none;
  bool failReadsAfterUnknown = false;

  /// Synchronous mirror of the durable log row (updated the instant a
  /// statement commits), so a listener can prove it ran AFTER the commit.
  String? durable;

  /// Runs before every log-key CAS (may await, may mutate the row).
  Future<void> Function()? beforeCas;
  final List<Completer<void>> _readWaiters = <Completer<void>>[];

  /// Completes once at least [n] log-key reads have happened.
  Future<void> readsReached(int n) {
    if (logReads >= n) return Future<void>.value();
    final Completer<void> c = Completer<void>();
    _readWaiters.add(c);
    unawaited(() async {
      while (logReads < n) {
        await Future<void>.delayed(Duration.zero);
      }
      if (!c.isCompleted) c.complete();
    }());
    return c.future;
  }

  Future<void> _jitter() async {
    final Random? r = random;
    if (r == null) return;
    for (int i = r.nextInt(4); i > 0; i--) {
      await Future<void>.delayed(Duration.zero);
    }
  }

  @override
  Future<String?> getSetting(String key) async {
    if (key == _key) {
      await _jitter();
      if (failLogReads) throw StateError('log read fault');
      logReads++;
    }
    return super.getSetting(key);
  }

  /// Direct write that bypasses CAS accounting (a competing writer).
  Future<void> poke(String value) async {
    await super.setSetting(_key, value);
    durable = value;
  }

  @override
  Future<CasOutcome> compareAndSetSetting(
    String key, {
    required String? expected,
    required String next,
  }) async {
    if (key != _key) {
      return super.compareAndSetSetting(key, expected: expected, next: next);
    }
    casCalls++;
    final Future<void> Function()? hook = beforeCas;
    if (hook != null) await hook();
    await _jitter();
    if (fault == _CasFault.throwBeforeCommit) {
      if (failReadsAfterUnknown) failLogReads = true;
      throw const CasUnknownOutcome(CasUnknownCode.io);
    }
    final CasOutcome out =
        await super.compareAndSetSetting(key, expected: expected, next: next);
    if (out == CasOutcome.committed) {
      commits++;
      durable = next;
    } else {
      conflicts++;
    }
    switch (fault) {
      case _CasFault.commitThenThrow:
        if (failReadsAfterUnknown) failLogReads = true;
        throw const CasUnknownOutcome(CasUnknownCode.busy);
      case _CasFault.hangAfterCommit:
        return Completer<CasOutcome>().future; // process "dies" here
      case _CasFault.none:
      case _CasFault.throwBeforeCommit:
        return out;
    }
  }
}

/// Records listener calls and proves each one followed a durable commit.
class _Listener implements IntruderEventListener {
  _Listener(this.db);

  final _QDb db;
  final List<String> recorded = <String>[];
  final List<String> notDurableAtNotify = <String>[];

  @override
  void onFailedAttemptRecorded(FailedAttemptEvent event) {
    recorded.add(event.verificationId);
    if (!(db.durable ?? '').contains('"${event.verificationId}"')) {
      notDurableAtNotify.add(event.verificationId);
    }
  }

  @override
  void onOwnerVerified() {}
}

int _vidN = 0;
final DateTime _t0 = DateTime(2026, 10, 22, 12);

VerifiedAttempt _fail({String? vid}) => VerifiedAttempt(
      verificationId: vid ?? 'q:${++_vidN}',
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
        reason: AuthFailureReason.wrongCredential,
        remainingAttempts: 2,
      ),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

VerifiedAttempt _success() => VerifiedAttempt(
      verificationId: 'ok:${++_vidN}',
      type: AuthType.pin,
      matched: true,
      result: const AuthSuccess(type: AuthType.pin),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

IntruderMonitor _monitor(
  _QDb db, {
  _Listener? listener,
  int maxEvents = IntruderMonitor.defaultMaxEvents,
  int maxBytes = IntruderMonitor.defaultMaxEncodedBytes,
}) =>
    IntruderMonitor(
      store: IntruderFailureLogStore(db),
      now: () => _t0,
      maxEvents: maxEvents,
      maxEncodedBytes: maxBytes,
    )..listener = listener;

Future<IntruderFailureLog> _durable(_QDb db) async {
  final IntruderLogRead r = await IntruderFailureLogStore(db).read();
  return (r as IntruderLogLoaded).log;
}

List<int> _seqs(IntruderFailureLog l) =>
    l.events.map((FailedAttemptEvent e) => e.seq).toList();

/// Batch 3: the failure log is v2; a probe document needs a generation.
const String _tq15Gen = 'AAAAAAAAAAAAAAAAAAAAAA';

void main() {
  group('T-Q concurrent monitors on one database', () {
    test('T-Q1 interleaved read/read/CAS/CAS: both stored, B rebased once',
        () async {
      final _QDb db = _QDb();
      final _Listener la = _Listener(db), lb = _Listener(db);
      final IntruderMonitor a = _monitor(db, listener: la);
      final IntruderMonitor b = _monitor(db, listener: lb);
      // Neither CAS runs until BOTH monitors have read the same base.
      db.beforeCas = () => db.readsReached(2);
      a.onVerifiedAttempt(_fail(vid: 'A1'));
      b.onVerifiedAttempt(_fail(vid: 'B1'));
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      final IntruderFailureLog l = await _durable(db);
      expect(_seqs(l), <int>[0, 1]);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toSet(),
          <String>{'A1', 'B1'});
      expect(l.nextSeq, 2);
      expect(l.consecutiveFailures, 2);
      expect(db.conflicts, 1, reason: 'exactly one rebase');
      expect(db.commits, 2);
      expect(la.recorded, <String>['A1']);
      expect(lb.recorded, <String>['B1']);
      expect(la.notDurableAtNotify, isEmpty);
      expect(lb.notDurableAtNotify, isEmpty);
      expect(
          a.status.droppedFailureRecords + b.status.droppedFailureRecords, 0);
    });

    test('T-Q2 stale-base pattern A, B x5, A: 7 unique increasing seqs',
        () async {
      final _QDb db = _QDb();
      final IntruderMonitor a = _monitor(db);
      final IntruderMonitor b = _monitor(db);
      a.onVerifiedAttempt(_fail());
      await a.idle();
      for (int i = 0; i < 5; i++) {
        b.onVerifiedAttempt(_fail());
      }
      await b.idle();
      a.onVerifiedAttempt(_fail()); // A's last read is 5 commits stale
      await a.idle();
      final IntruderFailureLog l = await _durable(db);
      expect(_seqs(l), <int>[0, 1, 2, 3, 4, 5, 6]);
      expect(l.nextSeq, 7);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toSet(),
          hasLength(7));
      expect(db.conflicts, 0, reason: 'every op re-reads; no stale base');
    });

    test('T-Q3 the same verificationId at two monitors: 1 event, 1 notify',
        () async {
      final _QDb db = _QDb();
      final _Listener la = _Listener(db), lb = _Listener(db);
      final IntruderMonitor a = _monitor(db, listener: la);
      final IntruderMonitor b = _monitor(db, listener: lb);
      db.beforeCas = () => db.readsReached(2);
      final VerifiedAttempt same = _fail(vid: 'SAME');
      a.onVerifiedAttempt(same);
      b.onVerifiedAttempt(same);
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      final IntruderFailureLog l = await _durable(db);
      expect(l.events, hasLength(1));
      expect(la.recorded.length + lb.recorded.length, 1);
      expect(a.status.droppedFailureRecords + b.status.droppedFailureRecords, 0,
          reason: 'a duplicate is not a drop');
    });

    test('T-Q4 permanent contention: exactly 3 attempts, dropped, 0 notify',
        () async {
      final _QDb db = _QDb();
      final _Listener l = _Listener(db);
      final IntruderMonitor m = _monitor(db, listener: l);
      int bump = 100;
      db.beforeCas = () async {
        // A competing engine commits before every CAS of this monitor.
        await db.poke(IntruderFailureLogStore.encode(IntruderFailureLog(
          nextSeq: ++bump,
          gen: _tq15Gen, // Batch 3: v2 documents carry a generation
          consecutiveFailures: 0,
          events: const <FailedAttemptEvent>[],
        )));
      };
      m.onVerifiedAttempt(_fail(vid: 'LOST'));
      await m.idle();
      expect(db.casCalls, IntruderMonitor.maxCasAttempts);
      expect(IntruderMonitor.maxCasAttempts, 3);
      expect(db.conflicts, 3);
      expect(db.commits, 0);
      expect(m.status.conflictDrops, 1);
      expect(m.status.droppedFailureRecords, 1);
      expect(m.status.unknownOutcomes, 0);
      expect(l.recorded, isEmpty);
      expect(db.durable, isNot(contains('LOST')));
    });

    test(
        'T-Q4b 8 monitors x 50 failures, 20 seeded interleavings: '
        'committed + dropped = 400, no duplicate seq, notify = committed',
        () async {
      for (int seed = 0; seed < 20; seed++) {
        final _QDb db = _QDb(random: Random(seed));
        final List<_Listener> ls = <_Listener>[];
        final List<IntruderMonitor> ms = <IntruderMonitor>[];
        for (int i = 0; i < 8; i++) {
          final _Listener l = _Listener(db);
          ls.add(l);
          ms.add(_monitor(db, listener: l, maxEvents: 1000, maxBytes: 1 << 22));
        }
        final Random order = Random(seed + 1000);
        final List<int> remaining = List<int>.filled(8, 50);
        int left = 400;
        while (left > 0) {
          final int i = order.nextInt(8);
          if (remaining[i] == 0) continue;
          remaining[i]--;
          left--;
          ms[i].onVerifiedAttempt(_fail(vid: 's$seed-m$i-${remaining[i]}'));
          if (order.nextInt(3) == 0) await Future<void>.delayed(Duration.zero);
        }
        await Future.wait(ms.map((IntruderMonitor m) => m.idle()));
        final IntruderFailureLog l = await _durable(db);
        final int notified =
            ls.fold<int>(0, (int s, _Listener x) => s + x.recorded.length);
        final int dropped = ms.fold<int>(0,
            (int s, IntruderMonitor m) => s + m.status.droppedFailureRecords);
        final int conflictDrops = ms.fold<int>(
            0, (int s, IntruderMonitor m) => s + m.status.conflictDrops);
        expect(notified + dropped, 400, reason: 'seed $seed');
        expect(dropped, conflictDrops,
            reason: 'seed $seed: only contention drops exist here');
        expect(l.events.length, notified, reason: 'seed $seed');
        expect(_seqs(l).toSet().length, l.events.length, reason: 'seed $seed');
        expect(_seqs(l), List<int>.generate(l.events.length, (int i) => i),
            reason: 'seed $seed: gapless, increasing');
        expect(l.nextSeq, l.events.length, reason: 'seed $seed');
        expect(ls.every((_Listener x) => x.notDurableAtNotify.isEmpty), isTrue);
        final Set<String> stored =
            l.events.map((FailedAttemptEvent e) => e.verificationId).toSet();
        for (final _Listener x in ls) {
          expect(stored.containsAll(x.recorded), isTrue, reason: 'seed $seed');
        }
        expect(ms.every((IntruderMonitor m) => m.status.unknownOutcomes == 0),
            isTrue);
      }
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  group('T-Q unknown outcomes are reconciled, never assumed', () {
    test('T-Q5 commit-then-throw: re-read finds the vid -> saved, 1 notify',
        () async {
      final _QDb db = _QDb()..fault = _CasFault.commitThenThrow;
      final _Listener l = _Listener(db);
      final IntruderMonitor m = _monitor(db, listener: l);
      m.onVerifiedAttempt(_fail(vid: 'U1'));
      await m.idle();
      expect((await _durable(db)).events.single.verificationId, 'U1');
      expect(l.recorded, <String>['U1']);
      expect(m.status.droppedFailureRecords, 0);
      expect(m.status.unknownOutcomes, 0);
      expect(m.status.health, IntruderMonitorHealth.ok);
      expect(db.casCalls, 1, reason: 'an unknown is never blindly retried');
    });

    test('T-Q6 throw-before-commit: row byte-identical, not saved, 0 notify',
        () async {
      final _QDb db = _QDb();
      final IntruderMonitor seed = _monitor(db);
      seed.onVerifiedAttempt(_fail(vid: 'S0'));
      await seed.idle();
      final String before = (await db.getSetting(_key))!;
      final int casBefore = db.casCalls;
      db.fault = _CasFault.throwBeforeCommit;
      final _Listener l = _Listener(db);
      final IntruderMonitor m = _monitor(db, listener: l);
      m.onVerifiedAttempt(_fail(vid: 'U2'));
      await m.idle();
      expect(await db.getSetting(_key), before);
      expect(l.recorded, isEmpty);
      expect(m.status.droppedFailureRecords, 1);
      expect(m.status.unknownOutcomes, 0);
      expect(m.status.health, IntruderMonitorHealth.storageError);
      expect(db.casCalls - casBefore, 1);
    });

    test(
        'T-Q7 throw, then the re-read throws: unknown, 0 notify; a later '
        'redelivery dedups', () async {
      final _QDb db = _QDb()
        ..fault = _CasFault.commitThenThrow
        ..failReadsAfterUnknown = true;
      final _Listener l = _Listener(db);
      final IntruderMonitor m = _monitor(db, listener: l);
      final VerifiedAttempt a = _fail(vid: 'U3');
      m.onVerifiedAttempt(a);
      await m.idle();
      expect(m.status.unknownOutcomes, 1);
      expect(m.status.droppedFailureRecords, 0,
          reason: 'unknown is not known-lost');
      expect(m.status.health, IntruderMonitorHealth.storageError);
      expect(l.recorded, isEmpty);
      // Storage recovers; the same attempt is redelivered.
      db
        ..fault = _CasFault.none
        ..failReadsAfterUnknown = false
        ..failLogReads = false;
      final int casBefore = db.casCalls;
      m.onVerifiedAttempt(a);
      await m.idle();
      final IntruderFailureLog log = await _durable(db);
      expect(log.events, hasLength(1));
      expect(db.casCalls, casBefore, reason: 'durable vid: nothing to write');
      expect(l.recorded, isEmpty, reason: 'never notified for an unknown');
    });

    test('T-Q7b throw-before-commit then unreadable: unknown, row unchanged',
        () async {
      final _QDb db = _QDb()
        ..fault = _CasFault.throwBeforeCommit
        ..failReadsAfterUnknown = true;
      final IntruderMonitor m = _monitor(db);
      m.onVerifiedAttempt(_fail());
      await m.idle();
      expect(m.status.unknownOutcomes, 1);
      expect(m.status.droppedFailureRecords, 0);
      db.failLogReads = false;
      expect(await db.getSetting(_key), isNull);
    });

    test(
        'T-Q10 commit, then the monitor dies before notifying: a new '
        'monitor given the redelivery neither duplicates nor notifies',
        () async {
      final _QDb db = _QDb()..fault = _CasFault.hangAfterCommit;
      final _Listener dead = _Listener(db);
      final IntruderMonitor a = _monitor(db, listener: dead);
      final VerifiedAttempt at = _fail(vid: 'D1');
      a.onVerifiedAttempt(at);
      await db.readsReached(1);
      while (db.commits == 0) {
        await Future<void>.delayed(Duration.zero);
      }
      db.fault = _CasFault.none;
      final _Listener l = _Listener(db);
      final IntruderMonitor b = _monitor(db, listener: l);
      b.onVerifiedAttempt(at);
      await b.idle();
      expect((await _durable(db)).events, hasLength(1));
      expect(l.recorded, isEmpty);
      expect(dead.recorded, isEmpty);
    });
  });

  group('T-Q corrupt, unsupported, reset and snapshot', () {
    test(
        'T-Q8 corrupt row raced by two monitors: one quarantine, one repair '
        'wins, the loser rebases', () async {
      final _QDb db = _QDb();
      await db.poke('{corrupt');
      final IntruderMonitor a = _monitor(db);
      final IntruderMonitor b = _monitor(db);
      db.beforeCas = () => db.readsReached(2);
      a.onVerifiedAttempt(_fail(vid: 'C1'));
      b.onVerifiedAttempt(_fail(vid: 'C2'));
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      expect(await db.getSetting(_qKey), '{corrupt');
      final IntruderFailureLog l = await _durable(db);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toSet(),
          <String>{'C1', 'C2'});
      expect(_seqs(l), <int>[0, 1]);
      expect(db.conflicts, 1);
      // A second corruption never replaces the first quarantined value.
      await db.poke('{corrupt-2');
      final IntruderMonitor c = _monitor(db);
      c.onVerifiedAttempt(_fail());
      await c.idle();
      expect(await db.getSetting(_qKey), '{corrupt');
    });

    test('T-Q9 unsupported (newer) row: byte-identical, no CAS, read-only',
        () async {
      final _QDb db = _QDb();
      final String v2 = jsonEncode(<String, Object?>{
        'schema': IntruderFailureLog.schema,
        'v': IntruderFailureLog.version + 1,
        'gen': 'future',
        'events': <Object?>[],
      });
      await db.poke(v2);
      final _Listener l = _Listener(db);
      final IntruderMonitor m = _monitor(db, listener: l);
      for (int i = 0; i < 3; i++) {
        m.onVerifiedAttempt(_fail());
        m.onVerifiedAttempt(_success());
      }
      await m.idle();
      expect(await db.getSetting(_key), v2);
      expect(db.casCalls, 0);
      expect(await db.getSetting(_qKey), isNull);
      expect(m.status.health, IntruderMonitorHealth.readOnly);
      expect(l.recorded, isEmpty);
      expect(await m.snapshot(), isNull);
    });

    test('T-Q11 reset vs record race: run restarts, events intact', () async {
      final _QDb db = _QDb();
      final IntruderMonitor a = _monitor(db);
      final IntruderMonitor b = _monitor(db);
      a
        ..onVerifiedAttempt(_fail(vid: 'R1'))
        ..onVerifiedAttempt(_fail(vid: 'R2'));
      await a.idle();
      expect((await _durable(db)).consecutiveFailures, 2);
      final int base = db.logReads;
      db.beforeCas = () => db.readsReached(base + 2);
      a.onVerifiedAttempt(_success()); // reset op
      b.onVerifiedAttempt(_fail(vid: 'R3'));
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      final IntruderFailureLog l = await _durable(db);
      expect(_seqs(l), <int>[0, 1, 2]);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toList(),
          <String>['R1', 'R2', 'R3']);
      expect(db.conflicts, 1);
      // Whichever won, the record never resurrects the pre-reset run 2.
      expect(l.consecutiveFailures, anyOf(0, 1));
      expect(l.events.last.consecutiveFailures, anyOf(1, 3));
      if (l.events.last.consecutiveFailures == 1) {
        // the reset committed first: the record rebased onto run 0
        expect(l.consecutiveFailures, 1);
      } else {
        // the record committed first; the reset rebased onto it
        expect(l.consecutiveFailures, 0);
      }
      expect(a.status.resetPending, isFalse);
    });

    test(
        'T-Q16 snapshot on read failure is unavailable, never cached data; '
        'lastKnown() is explicitly stale', () async {
      final _QDb db = _QDb();
      final IntruderMonitor m = _monitor(db);
      m.onVerifiedAttempt(_fail(vid: 'K1'));
      await m.idle();
      expect((await m.snapshot())!.events.single.verificationId, 'K1');
      db.failLogReads = true;
      expect(await m.snapshot(), isNull);
      expect(m.status.health, IntruderMonitorHealth.storageError);
      final IntruderLastKnown? last = m.lastKnown();
      expect(last, isNotNull);
      expect(last!.stale, isTrue);
      expect(last.log.events.single.verificationId, 'K1');
      expect(last.asOf, _t0);
    });

    test(
        'encrypted rows: tokens differ per write and concurrent monitors '
        'still never lose events', () async {
      final _QDb db = _QDb();
      final AesGcmSettingsCipher cipher = AesGcmSettingsCipher(
          InMemorySecretStore(),
          database: InMemoryLocalDatabase());
      // The master key exists before any failed attempt can occur (a
      // credential must be enrolled first). Its lazy FIRST creation is not
      // concurrency-safe: finding F-KEY-1, characterized separately.
      await cipher.decryptString(await cipher.encryptString('init'));
      IntruderMonitor enc() => IntruderMonitor(
            store: IntruderFailureLogStore(db, cipher: cipher),
            now: () => _t0,
          );
      final IntruderMonitor a = enc(), b = enc();
      db.beforeCas = () => db.readsReached(2);
      a.onVerifiedAttempt(_fail(vid: 'E1'));
      b.onVerifiedAttempt(_fail(vid: 'E2'));
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      db.beforeCas = null;
      final IntruderLogRead r =
          await IntruderFailureLogStore(db, cipher: cipher).read();
      final IntruderFailureLog l = (r as IntruderLogLoaded).log;
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toSet(),
          <String>{'E1', 'E2'});
      expect(r.raw, startsWith('enc:v1:'));
      // Batch 3 (disclosed): the former probe `isNot(contains('E1'))` on
      // the base64 row was probabilistic (any 2-char pair occurs in random
      // base64 of this length with ~5-8% probability; the 22-char gen made
      // the row longer) and failed once in the full suite. The plaintext
      // JSON token '"E1"' can appear neither in the row nor in the decoded
      // ciphertext bytes (4-byte chance match: negligible).
      expect(r.raw, isNot(contains('"E1"')));
      final String bytes = latin1.decode(base64Decode(r.raw.substring(7)));
      expect(bytes, isNot(contains('"E1"')));
      expect(bytes, isNot(contains('"vid"')));
    });
  });

  group('store contract', () {
    test('writeIfUnchanged: insert-if-absent, exact-bytes replace, conflict',
        () async {
      final _QDb db = _QDb();
      final IntruderFailureLogStore s = IntruderFailureLogStore(db);
      final IntruderWriteResult w1 = await s.writeIfUnchanged(
          IntruderFailureLog.empty.adoptGeneration(_tq15Gen),
          expectedRaw: null);
      expect(w1, isA<IntruderWriteCommitted>());
      final String raw1 = (w1 as IntruderWriteCommitted).raw;
      expect(await db.getSetting(_key), raw1);
      // A second insert-if-absent conflicts and changes nothing.
      const IntruderFailureLog other = IntruderFailureLog(
          nextSeq: 9,
          gen: _tq15Gen, // Batch 3: v2 documents carry a generation
          consecutiveFailures: 0,
          events: <FailedAttemptEvent>[]);
      expect(await s.writeIfUnchanged(other, expectedRaw: null),
          isA<IntruderWriteConflict>());
      expect(await s.writeIfUnchanged(other, expectedRaw: 'stale'),
          isA<IntruderWriteConflict>());
      expect(await db.getSetting(_key), raw1);
      expect(await s.writeIfUnchanged(other, expectedRaw: raw1),
          isA<IntruderWriteCommitted>());
      final IntruderLogRead r = await s.read();
      expect((r as IntruderLogLoaded).log.nextSeq, 9);
      expect(r.raw, await db.getSetting(_key));
    });

    test('writeIfUnchanged never throws; storage errors are UNKNOWN', () async {
      final _QDb db = _QDb()..fault = _CasFault.throwBeforeCommit;
      final IntruderWriteResult w = await IntruderFailureLogStore(db)
          .writeIfUnchanged(IntruderFailureLog.empty.adoptGeneration(_tq15Gen),
              expectedRaw: null);
      expect(w, isA<IntruderWriteUnknown>());
      expect((w as IntruderWriteUnknown).code, CasUnknownCode.io);
      expect(w.attemptedRaw, isNotNull);
    });

    test('an equal plaintext value is UNKNOWN, never a claimed commit',
        () async {
      final _QDb db = _QDb();
      final IntruderFailureLogStore s = IntruderFailureLogStore(db);
      // Batch 3: v2 documents carry a gen; both sides use the same one.
      final IntruderFailureLog doc =
          IntruderFailureLog.empty.adoptGeneration(_tq15Gen);
      final String same = IntruderFailureLogStore.encode(doc);
      final IntruderWriteResult w =
          await s.writeIfUnchanged(doc, expectedRaw: same);
      expect(w, isA<IntruderWriteUnknown>());
      expect(db.casCalls, 0);
    });

    test('quarantineOnce is insert-if-absent', () async {
      final _QDb db = _QDb();
      final IntruderFailureLogStore s = IntruderFailureLogStore(db);
      expect(await s.quarantineOnce('first'), isTrue);
      expect(await s.quarantineOnce('second'), isFalse);
      expect(await db.getSetting(_qKey), 'first');
    });

    test('Unsupported carries the exact raw; Loaded carries the token',
        () async {
      final _QDb db = _QDb();
      final String v9 = jsonEncode(<String, Object?>{
        'schema': IntruderFailureLog.schema,
        'v': 9,
      });
      await db.poke(v9);
      final IntruderLogRead r = await IntruderFailureLogStore(db).read();
      expect(r, isA<IntruderLogUnsupported>());
      expect((r as IntruderLogUnsupported).raw, v9);
      expect(r.version, 9);
    });
  });

  group('ST static guards', () {
    String src(String p) => File(p).readAsStringSync();
    const String store =
        'lib/security/intruder/intruder_failure_log_store.dart';
    const String monitor = 'lib/security/intruder/intruder_monitor.dart';

    test('ST-1 no blind write exists for the failure log', () {
      final String s = src(store);
      expect(s, isNot(contains('setSetting(')));
      expect(s, isNot(contains('removeSetting(')));
      expect(s, isNot(contains('Future<void> write(')));
      expect(s, isNot(contains('Future<bool> quarantine(')));
      expect(RegExp(r'compareAndSetSetting\(').allMatches(s).length, 2,
          reason: 'writeIfUnchanged + quarantineOnce only');
      final String m = src(monitor);
      expect(m, isNot(contains('_store.write(')));
      expect(m, isNot(contains('_cache')));
      expect(m, isNot(contains('compareAndSetSetting')));
      expect(m, isNot(contains('LocalDatabase')));
    });

    test('ST-3 the monitor never notifies outside the confirmed path', () {
      final String m = src(monitor);
      expect(
          RegExp(r'onFailedAttemptRecorded\(event\)').allMatches(m).length, 1);
      expect(RegExp(r'_recorded\(').allMatches(m).length, 3,
          reason: 'definition + Committed + vid-confirmed Unknown');
    });
  });
}
