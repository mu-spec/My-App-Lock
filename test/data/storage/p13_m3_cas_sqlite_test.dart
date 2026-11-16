// P13/M3 F-1 — compareAndSetSetting against REAL SQLite (sqflite_common_ffi,
// test-only). Host evidence only: not Android, not device QA.
//
// Groups:
//   CAS-S  single-connection semantics (insert-if-absent, update, conflict,
//          missing/corrupt values, argument contract, no REPLACE/UPSERT/BEGIN)
//   CAS-X  cross-connection / cross-isolate / cross-process atomicity
//   CAS-B  bounded busy behaviour (Android busy_timeout 2500 ms and 0 ms)
//   CAS-F  adapter fault injection + ambiguous-write reconciliation
//   CAS-T  no transaction is held between the caller's read and the CAS
import 'dart:io';
import 'dart:isolate';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:smart_app_lock/data/storage/impl/sqflite_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:sqflite/sqflite.dart' as sqflite;
// The fault layer needs sqflite's own invoke-handler factory builder.
// ignore: depend_on_referenced_packages, implementation_imports
import 'package:sqflite_common/src/mixin/factory.dart' show buildDatabaseFactory;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

const String kKey = 'security_settings';
const String kDbName = 'smart_app_lock.db';

late Directory tmp;

Future<SqfliteLocalDatabase> openAdapter() async {
  final SqfliteLocalDatabase db = SqfliteLocalDatabase();
  await db.init();
  return db;
}

/// A SECOND, independent SQLite connection to the same file.
Future<Database> rawConnection({int busyMs = 2500}) async {
  final Database raw = await databaseFactoryFfi.openDatabase(
    p.join(tmp.path, kDbName),
    options: OpenDatabaseOptions(singleInstance: false),
  );
  await raw.rawQuery('PRAGMA busy_timeout = $busyMs');
  return raw;
}

/// The adapter's own shared connection (sqflite `singleInstance`), used only
/// to emulate the Android framework's busy timeout (the adapter never sets
/// one; Android's SQLiteConnection sets 2500 ms).
Future<void> setAdapterBusyTimeout(int ms) async {
  final Database shared = await databaseFactoryFfi.openDatabase(
    p.join(tmp.path, kDbName),
  );
  await shared.rawQuery('PRAGMA busy_timeout = $ms');
}

String value(int n, String who) => '$n|$who';
int countOf(String? v) => v == null ? 0 : int.parse(v.split('|').first);

// ---------------------------------------------------------------- isolates
class WorkerArgs {
  WorkerArgs(this.dir, this.who, this.n, this.blind, this.busyMs, this.out);
  final String dir;
  final String who;
  final int n;
  final bool blind;
  final int busyMs;
  final SendPort out;
}

Future<void> _worker(WorkerArgs a) async {
  sqfliteFfiInit();
  sqflite.databaseFactory = databaseFactoryFfiNoIsolate;
  await databaseFactoryFfiNoIsolate.setDatabasesPath(a.dir);
  // The schema already exists (created by the test before spawning), so
  // the shared handle is opened first to set the busy timeout before the
  // adapter reuses it (sqflite singleInstance).
  final Database shared = await databaseFactoryFfiNoIsolate
      .openDatabase(p.join(a.dir, kDbName));
  await shared.rawQuery('PRAGMA busy_timeout = ${a.busyMs}');
  final SqfliteLocalDatabase db = SqfliteLocalDatabase();
  await db.init();
  // Reads are not under test: a busy READ is retried (bounded).
  Future<String?> read() async {
    for (int r = 0; r < 1000; r++) {
      try {
        return await db.getSetting(kKey);
      } on DatabaseException {
        await Future<void>.delayed(const Duration(milliseconds: 1));
      }
    }
    throw StateError('read exhausted');
  }

  int unknown = 0;
  int confirmedAfterUnknown = 0;
  int conflicts = 0;
  for (int i = 0; i < a.n; i++) {
    if (a.blind) {
      final String? cur = await read();
      for (int r = 0;; r++) {
        try {
          await db.setSetting(kKey, value(countOf(cur) + 1, '${a.who}#$i'));
          break;
        } on DatabaseException {
          if (r > 1000) rethrow;
        }
      }
      continue;
    }
    for (int attempt = 1;; attempt++) {
      if (attempt > 2000) throw StateError('exhausted');
      final String? cur = await read();
      final String next = value(countOf(cur) + 1, '${a.who}#$i#$attempt');
      try {
        if (await db.compareAndSetSetting(kKey, expected: cur, next: next) ==
            CasOutcome.committed) {
          break;
        }
        conflicts++;
      } on CasUnknownOutcome {
        unknown++;
        CasReconciliation rec = await reconcileCompareAndSet(db, kKey, next);
        for (int r = 0; rec == CasReconciliation.unreadable && r < 1000; r++) {
          rec = await reconcileCompareAndSet(db, kKey, next);
        }
        if (rec == CasReconciliation.unreadable) throw StateError('unknown');
        if (rec == CasReconciliation.confirmedCommitted) {
          confirmedAfterUnknown++;
          break;
        }
      }
    }
  }
  await db.close();
  a.out.send(<int>[unknown, confirmedAfterUnknown, conflicts]);
}

Future<List<List<int>>> runIsolates(int workers, int n,
    {bool blind = false, int busyMs = 2500}) async {
  final ReceivePort rp = ReceivePort();
  final List<Isolate> iso = <Isolate>[];
  for (int w = 0; w < workers; w++) {
    iso.add(await Isolate.spawn(
        _worker, WorkerArgs(tmp.path, 'iso$w', n, blind, busyMs, rp.sendPort),
        errorsAreFatal: true, onError: rp.sendPort));
  }
  final List<List<int>> results = <List<int>>[];
  await for (final Object? m in rp) {
    if (m is List<int>) {
      results.add(m);
    } else {
      rp.close();
      throw StateError('isolate error: $m');
    }
    if (results.length == workers) break;
  }
  rp.close();
  return results;
}

// ------------------------------------------------------------ fault proxy
// Faults are injected at the sqflite method-channel layer (`invokeMethod`)
// beneath the REAL adapter, and only for the two CAS statements; everything
// else is forwarded to the real FFI SQLite engine.
enum Fault { none, throwBefore, throwAfter, rowsTwo, rowsMinusOne, closedErr }

class Faults {
  Fault fault = Fault.none;
  int casCalls = 0;
  final List<String> sqlSeen = <String>[];
}

bool _isCas(Object? args) {
  if (args is! Map) return false;
  final Object? sql = args['sql'];
  return sql == SqfliteLocalDatabase.casUpdateSql ||
      sql == SqfliteLocalDatabase.casInsertSql;
}

DatabaseFactory faultFactory(Faults f) {
  final dynamic inner = databaseFactoryFfi;
  Future<dynamic> forward(String method, [Object? arguments]) =>
      inner.invokeMethod<dynamic>(method, arguments) as Future<dynamic>;
  return buildDatabaseFactory(
    tag: 'fault',
    invokeMethod: (String method, [Object? arguments]) async {
      if (method == 'getDatabasesPath') return tmp.path;
      if (arguments is Map && arguments['sql'] is String) {
        f.sqlSeen.add(arguments['sql'] as String);
      }
      if (!_isCas(arguments) || f.fault == Fault.none) {
        if (_isCas(arguments)) f.casCalls++;
        return forward(method, arguments);
      }
      f.casCalls++;
      switch (f.fault) {
        case Fault.none:
          return forward(method, arguments);
        case Fault.throwBefore:
          throw _FakeDbException('disk I/O error (code 10)', resultCode: 10);
        case Fault.throwAfter:
          await forward(method, arguments);
          throw _FakeDbException('disk I/O error (code 10)', resultCode: 10);
        case Fault.rowsTwo:
          return 2;
        case Fault.rowsMinusOne:
          return -1;
        case Fault.closedErr:
          throw _FakeDbException('error database_closed');
      }
    },
  );
}

class _FakeDbException extends DatabaseException {
  _FakeDbException(super.message, {this.resultCode});
  final int? resultCode;
  @override
  int? getResultCode() => resultCode;
  @override
  Object? get result => null;
}

void main() {
  setUpAll(sqfliteFfiInit);

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('cas_');
    sqflite.databaseFactory = databaseFactoryFfi;
    await databaseFactoryFfi.setDatabasesPath(tmp.path);
  });

  tearDown(() async {
    await databaseFactoryFfi.deleteDatabase(p.join(tmp.path, kDbName));
    await tmp.delete(recursive: true);
  });

  group('CAS-S semantics (real SQLite)', () {
    test('CAS-S1 insert-if-absent commits exactly once; second is conflict',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      expect(await db.compareAndSetSetting(kKey, expected: null, next: 'A'),
          CasOutcome.committed);
      expect(await db.getSetting(kKey), 'A');
      expect(await db.compareAndSetSetting(kKey, expected: null, next: 'B'),
          CasOutcome.conflict);
      expect(await db.getSetting(kKey), 'A', reason: 'never replaced');
      await db.close();
    });

    test('CAS-S2 update commits only on exact match; stale is conflict',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      expect(await db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          CasOutcome.committed);
      expect(await db.compareAndSetSetting(kKey, expected: 'A', next: 'C'),
          CasOutcome.conflict, reason: '0 rows changed = conflict');
      expect(await db.getSetting(kKey), 'B');
      // Exact bytes: case, whitespace and prefix differences all conflict.
      for (final String near in <String>['b', 'B ', ' B', 'B\u0000', '']) {
        expect(await db.compareAndSetSetting(kKey, expected: near, next: 'Z'),
            CasOutcome.conflict, reason: 'near-miss ${near.codeUnits}');
      }
      expect(await db.getSetting(kKey), 'B');
      await db.close();
    });

    test('CAS-S3 missing row with non-null expectation is conflict (no insert)',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      expect(await db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          CasOutcome.conflict);
      expect(await db.getSetting(kKey), isNull, reason: 'nothing created');
      await db.close();
    });

    test('CAS-S4 corrupt / non-JSON stored value is compared as bytes',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      const String corrupt = '{"truncated":';
      await db.setSetting(kKey, corrupt);
      expect(await db.compareAndSetSetting(kKey, expected: '{}', next: 'X'),
          CasOutcome.conflict);
      expect(await db.compareAndSetSetting(kKey, expected: null, next: 'X'),
          CasOutcome.conflict, reason: 'present-but-corrupt is not absent');
      expect(await db.getSetting(kKey), corrupt);
      expect(await db.compareAndSetSetting(kKey, expected: corrupt, next: 'X'),
          CasOutcome.committed, reason: 'caller may repair with exact bytes');
      await db.close();
    });

    test('CAS-S5 removed row behaves as absent', () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      await db.removeSetting(kKey);
      expect(await db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          CasOutcome.conflict);
      expect(await db.compareAndSetSetting(kKey, expected: null, next: 'B'),
          CasOutcome.committed);
      await db.close();
    });

    test('CAS-S6 next == expected is rejected before any I/O, value unsent',
        () async {
      final Faults f = Faults();
      sqflite.databaseFactory = faultFactory(f);
      final SqfliteLocalDatabase db = await openAdapter();
      await expectLater(
          db.compareAndSetSetting(kKey, expected: 'SECRET', next: 'SECRET'),
          throwsA(isA<ArgumentError>().having(
              (ArgumentError e) => e.toString(),
              'message',
              isNot(contains('SECRET')))));
      expect(f.casCalls, 0);
      await db.close();
    });

    test('CAS-S7 statements: no REPLACE/UPSERT/BEGIN; value in WHERE', () {
      for (final String sql in <String>[
        SqfliteLocalDatabase.casUpdateSql,
        SqfliteLocalDatabase.casInsertSql,
      ]) {
        final String u = sql.toUpperCase();
        expect(u, isNot(contains('REPLACE')));
        expect(u, isNot(contains('ON CONFLICT')));
        expect(u, isNot(contains('BEGIN')));
        expect(u, isNot(contains('DO UPDATE')));
      }
      expect(SqfliteLocalDatabase.casUpdateSql,
          contains('WHERE key = ? AND value = ?'));
      expect(SqfliteLocalDatabase.casInsertSql, startsWith('INSERT OR IGNORE'));
    });

    test('CAS-S8 other keys are never touched', () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting('other', 'O');
      await db.setSetting(kKey, 'A');
      await db.compareAndSetSetting(kKey, expected: 'A', next: 'B');
      await db.compareAndSetSetting('other2', expected: null, next: 'N');
      expect(await db.getAllSettings(),
          <String, String>{'other': 'O', kKey: 'B', 'other2': 'N'});
      await db.close();
    });
  });

  group('CAS-X atomicity across connections / isolates / processes', () {
    test('CAS-X1 adapter vs independent connection: stale side conflicts',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      final Database other = await rawConnection();
      final String? seen = await db.getSetting(kKey); // 'A'
      expect(
          await other.rawUpdate(SqfliteLocalDatabase.casUpdateSql,
              <Object?>['OTHER', 1, kKey, 'A']),
          1);
      expect(await db.compareAndSetSetting(kKey, expected: seen, next: 'MINE'),
          CasOutcome.conflict);
      expect(await db.getSetting(kKey), 'OTHER', reason: 'no lost update');
      await other.close();
      await db.close();
    });

    test('CAS-X2 4 isolates x 50 CAS increments: no lost update', () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.close();
      final List<List<int>> r = await runIsolates(4, 50);
      final SqfliteLocalDatabase check = await openAdapter();
      expect(countOf(await check.getSetting(kKey)), 200);
      // ignore: avoid_print
      print('CAS-X2 unknown=${r.map((List<int> e) => e[0]).toList()} '
          'confirmedAfterUnknown=${r.map((List<int> e) => e[1]).toList()} '
          'conflicts=${r.map((List<int> e) => e[2]).toList()}');
      await check.close();
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('CAS-X3 CONTROL 4 isolates x 50 blind writes (observational)',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.close();
      await runIsolates(4, 50, blind: true);
      final SqfliteLocalDatabase check = await openAdapter();
      final int total = countOf(await check.getSetting(kKey));
      // ignore: avoid_print
      print('CAS-X3 CONTROL blind total=$total of 200 (lost=${200 - total})');
      expect(total, lessThanOrEqualTo(200));
      await check.close();
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('CAS-X4 cross-process: 2 isolates x 50 + 2 python3 processes x 150',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.close();
      final String script = p.join(tmp.path, 'w.py');
      File(script).writeAsStringSync(_pyWorker);
      Future<ProcessResult> py(String who) => Process.run('python3', <String>[
            script,
            p.join(tmp.path, kDbName),
            who,
            '150',
            SqfliteLocalDatabase.casUpdateSql,
            SqfliteLocalDatabase.casInsertSql,
          ]);
      final List<Object> all = await Future.wait<Object>(<Future<Object>>[
        runIsolates(2, 50),
        py('pyA'),
        py('pyB'),
      ]);
      for (final Object o in all.skip(1)) {
        final ProcessResult pr = o as ProcessResult;
        expect(pr.exitCode, 0, reason: '${pr.stderr}');
      }
      final SqfliteLocalDatabase check = await openAdapter();
      expect(countOf(await check.getSetting(kKey)), 400);
      // ignore: avoid_print
      final List<List<int>> iso = all.first as List<List<int>>;
      // ignore: avoid_print
      print('CAS-X4 iso(unknown,confirmed,conflicts)=$iso');
      // ignore: avoid_print
      print('CAS-X4 py=${all.skip(1).map((Object o) => (o as ProcessResult).stdout.toString().trim()).toList()}');
      await check.close();
    }, timeout: const Timeout(Duration(minutes: 3)));
  });

  group('CAS-B bounded busy', () {
    test('CAS-B1 writer lock held: CAS throws UNKNOWN(busy) within ~2.5 s, '
        'value unchanged', () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      await setAdapterBusyTimeout(2500);
      final Database other = await rawConnection();
      await other.execute('BEGIN IMMEDIATE');
      final Stopwatch sw = Stopwatch()..start();
      await expectLater(
          db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          throwsA(isA<CasUnknownOutcome>()
              .having((CasUnknownOutcome e) => e.code, 'code',
                  CasUnknownCode.busy)
              .having((CasUnknownOutcome e) => e.toString(), 'text',
                  allOf(isNot(contains("'A'")),
                      isNot(contains('security_settings'))))));
      sw.stop();
      // ignore: avoid_print
      print('CAS-B1 busy after ${sw.elapsedMilliseconds} ms');
      // BOUNDED is the property: never an unbounded wait or internal retry
      // loop. (Host note: inside the Dart VM the SQLite busy-handler sleeps
      // are observed to end early, so no lower bound is asserted; Android's
      // framework budget is 2500 ms per AOSP SQLiteConnection.cpp.)
      expect(sw.elapsedMilliseconds, lessThan(6000));
      await other.execute('ROLLBACK');
      expect(await db.getSetting(kKey), 'A');
      expect(await reconcileCompareAndSet(db, kKey, 'B'),
          CasReconciliation.notConfirmed);
      await other.close();
      await db.close();
    });

    test('CAS-B2 busy_timeout 0: immediate UNKNOWN(busy), no retry loop',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      await setAdapterBusyTimeout(0);
      final Database other = await rawConnection();
      await other.execute('BEGIN IMMEDIATE');
      final Stopwatch sw = Stopwatch()..start();
      await expectLater(db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          throwsA(isA<CasUnknownOutcome>()));
      expect(sw.elapsedMilliseconds, lessThan(1000));
      await other.execute('ROLLBACK');
      await other.close();
      await db.close();
    });
  });

  group('CAS-F fault injection + reconciliation', () {
    Future<(SqfliteLocalDatabase, Faults)> faulty() async {
      final Faults f = Faults();
      sqflite.databaseFactory = faultFactory(f);
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      return (db, f);
    }

    test('CAS-F1 throw before execution: UNKNOWN(io); reconcile notConfirmed',
        () async {
      final (SqfliteLocalDatabase db, Faults fdb) = await faulty();
      fdb.fault = Fault.throwBefore;
      await expectLater(db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          throwsA(isA<CasUnknownOutcome>().having(
              (CasUnknownOutcome e) => e.code, 'code', CasUnknownCode.io)));
      fdb.fault = Fault.none;
      expect(await reconcileCompareAndSet(db, kKey, 'B'),
          CasReconciliation.notConfirmed);
      expect(await db.getSetting(kKey), 'A');
      await db.close();
    });

    test('CAS-F2 AMBIGUOUS: write landed then error: UNKNOWN, never '
        'conflict; reconcile confirmedCommitted', () async {
      final (SqfliteLocalDatabase db, Faults fdb) = await faulty();
      fdb.fault = Fault.throwAfter;
      await expectLater(db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          throwsA(isA<CasUnknownOutcome>()));
      fdb.fault = Fault.none;
      expect(await reconcileCompareAndSet(db, kKey, 'B'),
          CasReconciliation.confirmedCommitted);
      await db.close();
    });

    test('CAS-F3 impossible row counts (2, -1) are UNKNOWN, never guessed',
        () async {
      final (SqfliteLocalDatabase db, Faults fdb) = await faulty();
      for (final Fault f in <Fault>[Fault.rowsTwo, Fault.rowsMinusOne]) {
        fdb.fault = f;
        await expectLater(
            db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
            throwsA(isA<CasUnknownOutcome>().having(
                (CasUnknownOutcome e) => e.code, 'code', CasUnknownCode.other)),
            reason: '$f');
        await expectLater(
            db.compareAndSetSetting(kKey, expected: null, next: 'B'),
            throwsA(isA<CasUnknownOutcome>()),
            reason: '$f insert path');
      }
      await db.close();
    });

    test('CAS-F4 closed-database error maps to UNKNOWN(closed)', () async {
      final (SqfliteLocalDatabase db, Faults fdb) = await faulty();
      fdb.fault = Fault.closedErr;
      await expectLater(db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          throwsA(isA<CasUnknownOutcome>().having(
              (CasUnknownOutcome e) => e.code, 'code', CasUnknownCode.closed)));
      await db.close();
    });

    test('CAS-F5 REAL closed connection (shared handle closed underneath)',
        () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      final Database shared =
          await databaseFactoryFfi.openDatabase(p.join(tmp.path, kDbName));
      await shared.close();
      await expectLater(db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          throwsA(isA<CasUnknownOutcome>()));
    });

    test('CAS-F6 corrupt database file: UNKNOWN, never committed/conflict',
        () async {
      File(p.join(tmp.path, kDbName))
          .writeAsBytesSync(List<int>.filled(4096, 0x5a));
      final SqfliteLocalDatabase db = SqfliteLocalDatabase();
      await expectLater(db.compareAndSetSetting(kKey, expected: null, next: 'B'),
          throwsA(isA<CasUnknownOutcome>()));
    });

    test('CAS-F7 exactly one statement per call, no internal retry', () async {
      final (SqfliteLocalDatabase db, Faults fdb) = await faulty();
      final int before = fdb.casCalls;
      final int sqlBefore = fdb.sqlSeen.length;
      fdb.fault = Fault.throwBefore;
      await expectLater(db.compareAndSetSetting(kKey, expected: 'A', next: 'B'),
          throwsA(isA<CasUnknownOutcome>()));
      fdb.fault = Fault.none;
      await db.compareAndSetSetting(kKey, expected: 'A', next: 'B');
      await db.compareAndSetSetting(kKey, expected: 'A', next: 'C');
      expect(fdb.casCalls - before, 3);
      final List<String> during = fdb.sqlSeen.sublist(sqlBefore);
      expect(during, hasLength(3));
      expect(during.any((String s) => s.toUpperCase().contains('BEGIN')),
          isFalse);
      await db.close();
    });

    test('CAS-F8 reconcile on unreadable store reports unreadable', () async {
      final SqfliteLocalDatabase db = await openAdapter();
      final Database shared =
          await databaseFactoryFfi.openDatabase(p.join(tmp.path, kDbName));
      await shared.close();
      expect(await reconcileCompareAndSet(db, kKey, 'B'),
          CasReconciliation.unreadable);
    });
  });

  group('CAS-T no transaction spans the caller work', () {
    test('CAS-T1 slow work (e.g. KDF/encryption) between read and CAS does '
        'not block other writers; stale CAS then conflicts', () async {
      final SqfliteLocalDatabase db = await openAdapter();
      await db.setSetting(kKey, 'A');
      final Database other = await rawConnection(busyMs: 0);
      final String? seen = await db.getSetting(kKey);
      // "Slow work" window: another writer with busy_timeout 0 must succeed
      // immediately, proving the adapter holds no lock/transaction here.
      final Stopwatch sw = Stopwatch()..start();
      expect(
          await other.rawUpdate(SqfliteLocalDatabase.casUpdateSql,
              <Object?>['W', 1, kKey, 'A']),
          1);
      expect(sw.elapsedMilliseconds, lessThan(500));
      expect(await db.compareAndSetSetting(kKey, expected: seen, next: 'X'),
          CasOutcome.conflict);
      // And right after a committed CAS, a busy_timeout-0 writer is not
      // blocked either (no lingering transaction).
      expect(await db.compareAndSetSetting(kKey, expected: 'W', next: 'Y'),
          CasOutcome.committed);
      expect(
          await other.rawUpdate(SqfliteLocalDatabase.casUpdateSql,
              <Object?>['Z', 2, kKey, 'Y']),
          1);
      await other.close();
      await db.close();
    });
  });
}

const String _pyWorker = r'''
import sqlite3, sys
path, who, n, upd, ins = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
con = sqlite3.connect(path, timeout=2.5, isolation_level=None)
def count(v): return 0 if v is None else int(v.split('|')[0])
unknown = 0
conflicts = 0
for i in range(n):
    for attempt in range(1, 501):
        row = con.execute("SELECT value FROM security_settings WHERE key=?", ("security_settings",)).fetchone()
        cur = None if row is None else row[0]
        nxt = "%d|%s#%d#%d" % (count(cur) + 1, who, i, attempt)
        try:
            if cur is None:
                c = con.execute(ins, ("security_settings", nxt, 0)).rowcount
            else:
                c = con.execute(upd, (nxt, 0, "security_settings", cur)).rowcount
        except sqlite3.OperationalError:
            unknown += 1
            row = con.execute("SELECT value FROM security_settings WHERE key=?", ("security_settings",)).fetchone()
            if row is not None and row[0] == nxt: break
            continue
        if c == 1: break
        conflicts += 1
    else:
        sys.exit(3)
print("%s unknown=%d conflicts=%d" % (who, unknown, conflicts))
''';
