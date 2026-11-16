// P13/M3 NF-NS-1 — credential state transitions over REAL SQLite
// (sqflite_common_ffi, test-only): several managers, each on its OWN
// connection in its own isolate, plus a foreign OS process. Host evidence
// only: not Android, not device QA.
//
//   T-NS-1   N managers x M concurrent wrong PINs: counters equal the
//            committed transitions (no lost increment, none invented)
//   T-NS-1b  threshold 3 under real concurrency: exactly one lockout,
//            streak 1, failedAttempts 3
//   T-NS-3   a stale manager in another isolate cannot erase a lockout
//   T-NS-12  2 isolates + main-isolate manager + 1 python3 process
//   T-NS-11p slow KDF holds no database lock / transaction
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:smart_app_lock/data/models/security_settings.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/storage/impl/sqflite_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_state_errors.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/utilities/result.dart';
import 'package:sqflite/sqflite.dart' as sqflite;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

const String kKey = 'security_settings';
const String kDbName = 'smart_app_lock.db';
const String _pin = '4829';
const String _wrong = '0000';

late Directory tmp;

DefaultCredentialManager buildManager(
  SqfliteLocalDatabase db, {
  required int maxAttempts,
  required DateTime now,
  PinHasher? hasher,
}) =>
    DefaultCredentialManager(
      settings: SecuritySettingsRepositoryImpl(db),
      pinHasher: hasher ?? Pbkdf2PinHasher(iterations: 200),
      patternHasher: Pbkdf2PatternHasher(iterations: 200),
      stateMachine: CredentialStateMachine(
        maxFailedAttempts: maxAttempts,
        lockoutDuration: const Duration(seconds: 30),
      ),
      now: () => now,
    );

/// Tallies of one worker: [verdicts, conflicts, unknown, other, lockedOut].
typedef Tally = List<int>;

Tally tally(List<Result<AuthAttemptResult>> rs) {
  int verdicts = 0, conflicts = 0, unknown = 0, other = 0, locked = 0;
  for (final Result<AuthAttemptResult> r in rs) {
    final AuthAttemptResult? v = r.valueOrNull;
    if (v is AuthFailure) {
      verdicts++;
    } else if (v is AuthLockedOut) {
      if (v.attemptsMade != null) verdicts++; // the attempt that tripped it
      locked++;
    } else if (r.errorOrNull is CredentialStateConflict) {
      conflicts++;
    } else if (r.errorOrNull is CredentialStateUnknown) {
      unknown++;
    } else {
      other++;
    }
  }
  return <int>[verdicts, conflicts, unknown, other, locked];
}

// ---------------------------------------------------------------- isolates
class _Args {
  _Args(this.dir, this.n, this.maxAttempts, this.nowMs, this.out,
      {this.parkFirst = false});
  final String dir;
  final int n;
  final int maxAttempts;
  final int nowMs;
  final SendPort out;
  final bool parkFirst;
}

Future<SqfliteLocalDatabase> _openInIsolate(String dir) async {
  sqfliteFfiInit();
  sqflite.databaseFactory = databaseFactoryFfiNoIsolate;
  await databaseFactoryFfiNoIsolate.setDatabasesPath(dir);
  final Database shared =
      await databaseFactoryFfiNoIsolate.openDatabase(p.join(dir, kDbName));
  await shared.rawQuery('PRAGMA busy_timeout = 2500');
  final SqfliteLocalDatabase db = SqfliteLocalDatabase();
  await db.init();
  return db;
}

/// Hasher that parks verify until the main isolate says go.
class _RemoteGatedHasher implements PinHasher {
  _RemoteGatedHasher(this.out);
  final SendPort out;
  final Pbkdf2PinHasher _inner = Pbkdf2PinHasher(iterations: 200);
  bool armed = true;

  @override
  Future<PinHash> hash(String pin) => _inner.hash(pin);

  @override
  Future<bool> verify(String pin, PinHash stored) async {
    if (armed) {
      armed = false;
      final ReceivePort go = ReceivePort();
      out.send(<Object>['parked', go.sendPort]);
      await go.first;
      go.close();
    }
    return _inner.verify(pin, stored);
  }
}

Future<void> _attemptWorker(_Args a) async {
  final SqfliteLocalDatabase db = await _openInIsolate(a.dir);
  final DefaultCredentialManager m = buildManager(
    db,
    maxAttempts: a.maxAttempts,
    now: DateTime.fromMillisecondsSinceEpoch(a.nowMs),
    hasher: a.parkFirst ? _RemoteGatedHasher(a.out) : null,
  );
  final List<Result<AuthAttemptResult>> rs = <Result<AuthAttemptResult>>[];
  for (int i = 0; i < a.n; i++) {
    rs.add(await m.authenticatePin(_wrong));
  }
  final Result<AuthAttemptResult> last = rs.last;
  await db.close();
  a.out.send(<Object>[
    'done',
    tally(rs),
    last.valueOrNull?.runtimeType.toString() ?? 'failure',
  ]);
}

class Worker {
  Worker(this.done, this.parked);
  final Future<List<Object>> done;
  final Future<SendPort>? parked;
}

Future<Worker> spawnWorker(int n, int maxAttempts, DateTime now,
    {bool parkFirst = false}) async {
  final ReceivePort rp = ReceivePort();
  await Isolate.spawn(
    _attemptWorker,
    _Args(tmp.path, n, maxAttempts, now.millisecondsSinceEpoch, rp.sendPort,
        parkFirst: parkFirst),
    errorsAreFatal: true,
    onError: rp.sendPort,
  );
  final Stream<Object?> s = rp.asBroadcastStream();
  final Future<List<Object>> done = s
      .firstWhere((Object? m) => m is! List || m.first != 'parked')
      .then((Object? m) {
    rp.close();
    if (m is List && m.first == 'done') return m.cast<Object>();
    throw StateError('isolate error: $m');
  });
  final Future<SendPort>? parked = parkFirst
      ? s
          .firstWhere((Object? m) => m is List && m.first == 'parked')
          .then((Object? m) => (m! as List)[1] as SendPort)
      : null;
  return Worker(done, parked);
}

Future<SqfliteLocalDatabase> openMain() async {
  final SqfliteLocalDatabase db = SqfliteLocalDatabase();
  await db.init();
  return db;
}

Future<Map<String, dynamic>> rawDoc(SqfliteLocalDatabase db) async =>
    (jsonDecode((await db.getSetting(kKey))!) as Map<String, dynamic>)
        .cast<String, dynamic>();

void main() {
  final DateTime now = DateTime(2026, 11, 16, 10);

  setUpAll(sqfliteFfiInit);

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('nfns1_');
    sqflite.databaseFactory = databaseFactoryFfi;
    await databaseFactoryFfi.setDatabasesPath(tmp.path);
    final SqfliteLocalDatabase db = await openMain();
    final DefaultCredentialManager m =
        buildManager(db, maxAttempts: 3, now: now);
    expect((await m.enrollPin(_pin)).isSuccess, isTrue);
    // Main-isolate handle: Android-like busy timeout.
    final Database shared =
        await databaseFactoryFfi.openDatabase(p.join(tmp.path, kDbName));
    await shared.rawQuery('PRAGMA busy_timeout = 2500');
  });

  tearDown(() async {
    await databaseFactoryFfi.deleteDatabase(p.join(tmp.path, kDbName));
    await tmp.delete(recursive: true);
  });

  test('T-NS-1 3 isolates (own connection + manager) x 15 wrong PINs: '
      'counters equal the committed transitions', () async {
    final List<Worker> ws = <Worker>[
      for (int i = 0; i < 3; i++) await spawnWorker(15, 1000000, now),
    ];
    final List<List<Object>> rs =
        await Future.wait(ws.map((Worker w) => w.done));
    final List<Tally> t = rs.map((List<Object> r) => r[1] as Tally).toList();
    final int verdicts = t.fold(0, (int a, Tally x) => a + x[0]);
    final int unknown = t.fold(0, (int a, Tally x) => a + x[2]);
    final int other = t.fold(0, (int a, Tally x) => a + x[3]);
    final SqfliteLocalDatabase db = await openMain();
    final Map<String, dynamic> d = await rawDoc(db);
    final int failed = d['failedAttempts'] as int;
    // ignore: avoid_print
    print('T-NS-1 tallies(verdicts,conflicts,unknown,other,locked)=$t '
        'failedAttempts=$failed rev=${d['_rev']}');
    expect(other, 0);
    // No released verdict was lost; nothing beyond possibly-landed
    // UNKNOWN attempts was invented.
    expect(failed, greaterThanOrEqualTo(verdicts));
    expect(failed, lessThanOrEqualTo(verdicts + unknown));
    expect(d['_rev'], greaterThanOrEqualTo(1 + failed));
    await db.close();
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('T-NS-1b threshold 3 under real concurrency: one lockout, streak 1',
      () async {
    final List<Worker> ws = <Worker>[
      for (int i = 0; i < 3; i++) await spawnWorker(4, 3, now),
    ];
    final List<List<Object>> rs =
        await Future.wait(ws.map((Worker w) => w.done));
    final List<Tally> t = rs.map((List<Object> r) => r[1] as Tally).toList();
    final SqfliteLocalDatabase db = await openMain();
    final SecuritySettings s =
        (await SecuritySettingsRepositoryImpl(db).getSettings()).valueOrNull!;
    // ignore: avoid_print
    print('T-NS-1b tallies=$t failed=${s.failedAttempts} '
        'streak=${s.lockoutStreak}');
    expect(s.lockedOutUntil, now.add(const Duration(seconds: 30)));
    expect(s.lockoutStreak, 1);
    expect(s.failedAttempts, 3);
    // Every worker's last attempt is refused by the lockout.
    for (final List<Object> r in rs) {
      expect(r[2], 'AuthLockedOut');
    }
    final int verdicts = t.fold(0, (int a, Tally x) => a + x[0]);
    final int unknown = t.fold(0, (int a, Tally x) => a + x[2]);
    expect(verdicts, lessThanOrEqualTo(3));
    expect(verdicts + unknown, greaterThanOrEqualTo(3));
    await db.close();
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('T-NS-3 a stale manager in another isolate cannot erase a lockout',
      () async {
    final SqfliteLocalDatabase db = await openMain();
    final DefaultCredentialManager a =
        buildManager(db, maxAttempts: 3, now: now);
    await a.authenticatePin(_wrong); // 1
    final Worker stale = await spawnWorker(1, 3, now, parkFirst: true);
    final SendPort go = await stale.parked!; // isolate holds S(failed=1)
    await a.authenticatePin(_wrong); // 2
    expect((await a.authenticatePin(_wrong)).valueOrNull,
        isA<AuthLockedOut>()); // 3 -> lockout
    final Map<String, dynamic> locked = await rawDoc(db);
    go.send(true);
    final List<Object> r = await stale.done;
    expect(r[2], 'AuthLockedOut');
    final Map<String, dynamic> after = await rawDoc(db);
    expect(after['lockedOutUntil'], locked['lockedOutUntil']);
    expect(after['lockoutStreak'], locked['lockoutStreak']);
    expect(after['failedAttempts'], locked['failedAttempts']);
    expect(after['_rev'], locked['_rev']); // T3: no write at all
    expect((await a.authenticatePin(_pin)).valueOrNull, isA<AuthLockedOut>());
    await db.close();
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('T-NS-12 2 isolates + main manager + python3 process: no lost or '
      'invented increments', () async {
    final String script = p.join(tmp.path, 'w.py');
    File(script).writeAsStringSync(_pyWorker);
    final SqfliteLocalDatabase db = await openMain();
    final DefaultCredentialManager m =
        buildManager(db, maxAttempts: 1000000, now: now);
    final List<Worker> ws = <Worker>[
      for (int i = 0; i < 2; i++) await spawnWorker(15, 1000000, now),
    ];
    final Future<ProcessResult> py = Process.run('python3', <String>[
      script,
      p.join(tmp.path, kDbName),
      '40',
      SqfliteLocalDatabase.casUpdateSql,
    ]);
    final List<Result<AuthAttemptResult>> mine = <Result<AuthAttemptResult>>[];
    for (int i = 0; i < 15; i++) {
      mine.add(await m.authenticatePin(_wrong));
    }
    final List<List<Object>> rs =
        await Future.wait(ws.map((Worker w) => w.done));
    final ProcessResult pr = await py;
    expect(pr.exitCode, 0, reason: '${pr.stderr}');
    final List<String> pyOut = pr.stdout.toString().trim().split(' ');
    final int pyCommitted = int.parse(pyOut[0]);
    final int pyUnknown = int.parse(pyOut[1]);
    final List<Tally> t = <Tally>[
      tally(mine),
      ...rs.map((List<Object> r) => r[1] as Tally),
    ];
    final int verdicts = t.fold(0, (int a, Tally x) => a + x[0]);
    final int unknown = t.fold(0, (int a, Tally x) => a + x[2]);
    final int other = t.fold(0, (int a, Tally x) => a + x[3]);
    final Map<String, dynamic> d = await rawDoc(db);
    final int failed = d['failedAttempts'] as int;
    // ignore: avoid_print
    print('T-NS-12 tallies=$t py(committed,unknown)=($pyCommitted,'
        '$pyUnknown) failed=$failed rev=${d['_rev']}');
    expect(other, 0);
    expect(failed, greaterThanOrEqualTo(verdicts + pyCommitted));
    expect(failed, lessThanOrEqualTo(verdicts + pyCommitted + unknown +
        pyUnknown));
    await db.close();
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('T-NS-11p slow KDF holds no database lock: a busy_timeout-0 writer '
      'commits during verification; the stale verdict then re-evaluates',
      () async {
    final SqfliteLocalDatabase db = await openMain();
    final Worker parked = await spawnWorker(1, 3, now, parkFirst: true);
    final SendPort go = await parked.parked!; // KDF in progress elsewhere
    final Database other = await databaseFactoryFfi.openDatabase(
      p.join(tmp.path, kDbName),
      options: OpenDatabaseOptions(singleInstance: false),
    );
    await other.rawQuery('PRAGMA busy_timeout = 0');
    final String cur = (await db.getSetting(kKey))!;
    final Map<String, dynamic> doc =
        (jsonDecode(cur) as Map<String, dynamic>).cast<String, dynamic>();
    doc['_rev'] = (doc['_rev'] as int) + 1;
    doc['failedAttempts'] = 1;
    final Stopwatch sw = Stopwatch()..start();
    expect(
      await other.rawUpdate(SqfliteLocalDatabase.casUpdateSql,
          <Object?>[jsonEncode(doc), 0, kKey, cur]),
      1,
    );
    expect(sw.elapsedMilliseconds, lessThan(500));
    await other.close();
    go.send(true);
    final List<Object> r = await parked.done;
    expect((r[1] as Tally)[0], 1); // its verdict was released ...
    expect((await rawDoc(db))['failedAttempts'], 2); // ... on fresh state
    await db.close();
  }, timeout: const Timeout(Duration(minutes: 2)));
}

/// Foreign process: a faithful CAS writer of the same envelope (counts one
/// failed attempt per commit, revision + 1). Prints "committed unknown".
const String _pyWorker = r'''
import json, sqlite3, sys
path, n, upd = sys.argv[1], int(sys.argv[2]), sys.argv[3]
con = sqlite3.connect(path, timeout=2.5, isolation_level=None)
committed = 0
unknown = 0
for i in range(n):
    for attempt in range(1, 4):
        try:
            row = con.execute("SELECT value FROM security_settings WHERE key=?", ("security_settings",)).fetchone()
        except sqlite3.OperationalError:
            continue
        cur = row[0]
        doc = json.loads(cur)
        doc["failedAttempts"] = doc.get("failedAttempts", 0) + 1
        doc["_rev"] = doc.get("_rev", 0) + 1
        doc["_schema"] = 2
        nxt = json.dumps(doc)
        try:
            c = con.execute(upd, (nxt, 0, "security_settings", cur)).rowcount
        except sqlite3.OperationalError:
            unknown += 1
            break
        if c == 1:
            committed += 1
            break
print("%d %d" % (committed, unknown))
''';
