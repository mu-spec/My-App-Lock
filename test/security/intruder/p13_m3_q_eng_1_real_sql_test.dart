// P13/M3 Q-ENG-1 RS-M: IntruderMonitor + IntruderFailureLogStore over REAL
// SQLite (sqflite_common_ffi, test-only), one independent connection per
// isolate, as several engines would hold in production. Host evidence only:
// not Android, not the shared native sqflite connection, not device QA.
//
// Encryption: PLAINTEXT rows here. Encrypted cross-isolate runs need a
// shared master key, i.e. a pre-initialized key, which would mask F-KEY-1.
// Encrypted concurrency is covered in-process by the T-Q file (pre-
// initialized, labelled) and F-KEY-1 is reproduced separately (FK-R*).
import 'dart:io';
import 'dart:isolate';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:smart_app_lock/data/storage/impl/sqflite_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:sqflite/sqflite.dart' as sqflite;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

const String kDbName = 'smart_app_lock.db';
final DateTime _t0 = DateTime(2026, 10, 22, 12);

VerifiedAttempt _fail(String vid) => VerifiedAttempt(
      verificationId: vid,
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

class _Count implements IntruderEventListener {
  final List<String> vids = <String>[];
  @override
  void onFailedAttemptRecorded(FailedAttemptEvent event) =>
      vids.add(event.verificationId);
  @override
  void onOwnerVerified() {}
}

IntruderMonitor _monitor(SqfliteLocalDatabase db, _Count l) => IntruderMonitor(
      store: IntruderFailureLogStore(db),
      now: () => _t0,
      maxEvents: 100000,
      maxEncodedBytes: 1 << 24,
      maxPending: 100000,
    )..listener = l;

class _Args {
  _Args(this.dir, this.vids, this.busyMs, this.out);
  final String dir;
  final List<String> vids;
  final int busyMs;
  final SendPort out;
}

/// One isolate = one connection + one monitor. Reports
/// [notifiedVids, dropped, conflictDrops, unknownOutcomes].
Future<void> _worker(_Args a) async {
  sqfliteFfiInit();
  sqflite.databaseFactory = databaseFactoryFfiNoIsolate;
  await databaseFactoryFfiNoIsolate.setDatabasesPath(a.dir);
  final Database shared =
      await databaseFactoryFfiNoIsolate.openDatabase(p.join(a.dir, kDbName));
  await shared.rawQuery('PRAGMA busy_timeout = ${a.busyMs}');
  final SqfliteLocalDatabase db = SqfliteLocalDatabase();
  await db.init();
  final _Count l = _Count();
  final IntruderMonitor m = _monitor(db, l);
  for (final String v in a.vids) {
    m.onVerifiedAttempt(_fail(v));
    if (v.hashCode % 3 == 0) await Future<void>.delayed(Duration.zero);
  }
  await m.idle();
  final IntruderMonitorStatus s = m.status;
  await db.close();
  a.out.send(<Object>[
    l.vids,
    s.droppedFailureRecords,
    s.conflictDrops,
    s.unknownOutcomes,
  ]);
}

late Directory tmp;

Future<List<List<Object>>> _run(List<List<String>> perIsolate,
    {int busyMs = 2500}) async {
  final ReceivePort rp = ReceivePort();
  for (final List<String> vids in perIsolate) {
    await Isolate.spawn(_worker, _Args(tmp.path, vids, busyMs, rp.sendPort),
        errorsAreFatal: true, onError: rp.sendPort);
  }
  final List<List<Object>> out = <List<Object>>[];
  await for (final Object? msg in rp) {
    if (msg is List<Object>) {
      out.add(msg);
    } else {
      rp.close();
      throw StateError('isolate error: $msg');
    }
    if (out.length == perIsolate.length) break;
  }
  rp.close();
  return out;
}

Future<IntruderFailureLog> _stored() async {
  final SqfliteLocalDatabase db = SqfliteLocalDatabase();
  await db.init();
  final IntruderLogRead r = await IntruderFailureLogStore(db).read();
  return (r as IntruderLogLoaded).log;
}

void main() {
  setUpAll(sqfliteFfiInit);

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('qeng1_');
    sqflite.databaseFactory = databaseFactoryFfi;
    await databaseFactoryFfi.setDatabasesPath(tmp.path);
    final SqfliteLocalDatabase db = SqfliteLocalDatabase();
    await db.init(); // schema exists before the isolates start
  });

  tearDown(() async {
    await databaseFactoryFfi.deleteDatabase(p.join(tmp.path, kDbName));
    await tmp.delete(recursive: true);
  });

  test('RS-M1 4 isolates x 50 failures over real SQLite: no committed event '
      'lost, gapless unique seqs, notify only for durable events', () async {
    final List<List<String>> plan = <List<String>>[
      for (int w = 0; w < 4; w++)
        <String>[for (int i = 0; i < 50; i++) 'w$w-$i'],
    ];
    final List<List<Object>> r = await _run(plan);
    final List<String> notified = <String>[
      for (final List<Object> x in r) ...(x[0] as List<Object?>).cast<String>(),
    ];
    final int dropped = r.fold<int>(0, (int s, List<Object> x) => s + (x[1] as int));
    final int unknown = r.fold<int>(0, (int s, List<Object> x) => s + (x[3] as int));
    final IntruderFailureLog log = await _stored();
    final Set<String> stored =
        log.events.map((FailedAttemptEvent e) => e.verificationId).toSet();
    // ignore: avoid_print
    print('RS-M1 notified=${notified.length} dropped=$dropped '
        'conflictDrops=${r.map((List<Object> x) => x[2]).toList()} '
        'unknown=$unknown stored=${log.events.length}');
    expect(notified.length + dropped + unknown, 200);
    expect(stored.length, log.events.length, reason: 'no duplicate vid');
    expect(stored.containsAll(notified), isTrue,
        reason: 'every notified event is durable');
    expect(log.events.length - notified.length, lessThanOrEqualTo(unknown),
        reason: 'only unconfirmed outcomes may be stored un-notified');
    expect(log.events.map((FailedAttemptEvent e) => e.seq).toList(),
        List<int>.generate(log.events.length, (int i) => i));
    expect(log.nextSeq, log.events.length);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('RS-M2 the SAME 50 attempts delivered to 4 isolates: each stored at '
      'most once and notified at most once in total', () async {
    final List<String> same = <String>[for (int i = 0; i < 50; i++) 'v$i'];
    final List<List<Object>> r = await _run(<List<String>>[
      for (int w = 0; w < 4; w++) same,
    ]);
    final List<String> notified = <String>[
      for (final List<Object> x in r) ...(x[0] as List<Object?>).cast<String>(),
    ];
    final IntruderFailureLog log = await _stored();
    final List<String> stored =
        log.events.map((FailedAttemptEvent e) => e.verificationId).toList();
    expect(stored.toSet().length, stored.length, reason: 'no duplicate event');
    expect(notified.toSet().length, notified.length,
        reason: 'no attempt notified twice across isolates');
    expect(stored.toSet().containsAll(notified), isTrue);
    expect(stored.toSet().difference(same.toSet()), isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('RS-M3 writer lock held elsewhere: the record is never reported '
      'saved and the row is byte-identical; storage recovers', () async {
    final SqfliteLocalDatabase db = SqfliteLocalDatabase();
    await db.init();
    final Database shared =
        await databaseFactoryFfi.openDatabase(p.join(tmp.path, kDbName));
    await shared.rawQuery('PRAGMA busy_timeout = 200');
    final _Count l = _Count();
    final IntruderMonitor m = _monitor(db, l);
    m.onVerifiedAttempt(_fail('seed'));
    await m.idle();
    final String before =
        (await db.getSetting(IntruderFailureLogStore.storageKey))!;
    final Database other = await databaseFactoryFfi.openDatabase(
      p.join(tmp.path, kDbName),
      options: OpenDatabaseOptions(singleInstance: false),
    );
    await other.execute('BEGIN IMMEDIATE');
    m.onVerifiedAttempt(_fail('blocked'));
    await m.idle();
    await other.execute('ROLLBACK');
    await other.close();
    expect(l.vids, <String>['seed'], reason: 'never notified while blocked');
    expect(await db.getSetting(IntruderFailureLogStore.storageKey), before);
    expect(
        m.status.droppedFailureRecords + m.status.unknownOutcomes, 1);
    expect(m.status.health, IntruderMonitorHealth.storageError);
    m.onVerifiedAttempt(_fail('after'));
    await m.idle();
    expect(l.vids, <String>['seed', 'after']);
    expect(m.status.health, IntruderMonitorHealth.ok);
    await db.close();
  }, timeout: const Timeout(Duration(minutes: 1)));
}
