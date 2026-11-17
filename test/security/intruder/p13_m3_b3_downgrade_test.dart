// P13/M3 Batch 3 — failure log v2 (generation id): B-D1 downgrade,
// re-upgrade, interrupted-migration and process-death proofs.
//
// "Old build" = the PRE-Batch-3 code (tree T3), copied verbatim into
// test/security/intruder/legacy_t3/ (only import paths rewritten; integrity
// checked by DG-0). The old and new code run against the SAME database and
// the SAME encryption key, which is exactly the situation of a downgraded
// binary opening upgraded data.
//
// Process death is modelled faithfully: the dying instance's CAS never
// returns (before or after the durable commit), the instance is abandoned
// and a NEW instance is built on the same storage (a restart has no memory).
import 'dart:async';
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
import 'package:smart_app_lock/security/intruder/failed_attempt_event.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/intruder/log_generation.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';

import 'legacy_t3/intruder_failure_log_store.dart' as old;
import 'legacy_t3/intruder_monitor.dart' as old;

const String _key = IntruderFailureLogStore.storageKey;
const String _g1 = 'GenerationOne_________';
const String _g2 = 'GenerationTwo-________';
const String _g3 = 'GenerationThree_______';

enum _Death { none, beforeCommit, afterCommit }

/// Failure-log CAS interception for process-death simulation. With
/// [death] set, the NEXT failure-log CAS never returns: either nothing was
/// written (beforeCommit) or the row was durably replaced (afterCommit).
class _DgDb extends InMemoryLocalDatabase {
  _Death death = _Death.none;
  int casCalls = 0;
  int abandoned = 0;

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
    final _Death d = death;
    death = _Death.none;
    switch (d) {
      case _Death.none:
        return super.compareAndSetSetting(key, expected: expected, next: next);
      case _Death.beforeCommit:
        abandoned++;
        return Completer<CasOutcome>().future; // process died: no write
      case _Death.afterCommit:
        final CasOutcome o = await super
            .compareAndSetSetting(key, expected: expected, next: next);
        expect(o, CasOutcome.committed, reason: 'harness precondition');
        abandoned++;
        return Completer<CasOutcome>().future; // died before the ack
    }
  }
}

int _vid = 0;
final DateTime _t0 = DateTime(2026, 10, 22, 12);

VerifiedAttempt _fail([String? vid]) => VerifiedAttempt(
      verificationId: vid ?? 'dg:${++_vid}',
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
      verificationId: 'dg:${++_vid}',
      type: AuthType.pin,
      matched: true,
      result: const AuthSuccess(type: AuthType.pin),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _t0,
    );

String Function() _mints(List<String> ids) {
  final List<String> q = List<String>.of(ids);
  return () => q.isEmpty ? throw StateError('unexpected mint') : q.removeAt(0);
}

void main() {
  late _DgDb db;
  late SettingsCipher cipher;

  IntruderMonitor newBuild({List<String> mints = const <String>[]}) =>
      IntruderMonitor(
        store: IntruderFailureLogStore(db, cipher: cipher),
        now: () => _t0,
        mintGeneration: _mints(mints),
      );

  old.IntruderMonitor oldBuild() => old.IntruderMonitor(
        store: old.IntruderFailureLogStore(db, cipher: cipher),
        now: () => _t0,
      );

  Future<String?> row() => db.getSetting(_key);

  Future<Map<String, Object?>> plain() async {
    final String raw = (await row())!;
    expect(raw, startsWith('enc:v1:'));
    return jsonDecode(await cipher.decryptString(raw.substring(7)))
        as Map<String, Object?>;
  }

  Future<String> plainText() async =>
      cipher.decryptString((await row())!.substring(7));

  Future<IntruderFailureLog> durable() async {
    final IntruderLogRead r =
        await IntruderFailureLogStore(db, cipher: cipher).read();
    expect(r, isA<IntruderLogLoaded>());
    return (r as IntruderLogLoaded).log;
  }

  /// Seeds a v1 log written by the OLD build (2 events, run 2).
  Future<void> seedV1ByOldBuild(
      [List<String> vids = const <String>['L1', 'L2']]) async {
    final old.IntruderMonitor o = oldBuild();
    for (final String v in vids) {
      o.onVerifiedAttempt(_fail(v));
    }
    await o.idle();
    expect((await plain())['v'], 1, reason: 'old build writes v1');
  }

  setUp(() {
    db = _DgDb();
    cipher = AesGcmSettingsCipher(InMemorySecretStore(),
        database: InMemoryLocalDatabase());
  });

  test('DG-0 the legacy fixture is the verbatim pre-Batch-3 code', () {
    final List<String> lines =
        File('test/security/intruder/legacy_t3/MANIFEST.txt')
            .readAsLinesSync()
            .where((String l) => l.contains('sha256='))
            .toList();
    expect(lines, hasLength(7));
    for (final String l in lines) {
      final String name = l.split(' ').first;
      final String want = l.split('sha256=').last.trim();
      String src =
          File('test/security/intruder/legacy_t3/$name').readAsStringSync();
      src = src.substring(src.indexOf('// ignore_for_file: type=lint\n\n') +
          '// ignore_for_file: type=lint\n\n'.length);
      src = src
          .replaceAll("import 'package:smart_app_lock/security/credentials/",
              "import '../credentials/")
          .replaceAll("import 'package:smart_app_lock/data/storage/",
              "import '../../data/storage/")
          .replaceAll("import 'package:smart_app_lock/security/encryption/",
              "import '../encryption/");
      expect(sha256.convert(utf8.encode(src)).toString(), want, reason: name);
      if (name == 'failed_attempt_event.dart') {
        expect(src, contains('static const int version = 1;'),
            reason: 'the old build knows only v1');
      }
    }
  });

  group('B-D1 condition 2/3: an old build never touches a v2 log', () {
    test(
        'DG-1 old build: failure + success + snapshot leave v2 byte-identical '
        '(read-only, 1 dropped, no CAS)', () async {
      final IntruderMonitor n = newBuild(mints: <String>[_g1]);
      n.onVerifiedAttempt(_fail('N1'));
      n.onVerifiedAttempt(_fail('N2'));
      await n.idle();
      final String v2 = (await row())!;
      expect((await plain())['v'], 2);
      expect((await plain())['gen'], _g1);
      final int cas = db.casCalls;

      final old.IntruderMonitor o = oldBuild();
      o.onVerifiedAttempt(_fail('OLD1'));
      o.onVerifiedAttempt(_ok()); // would reset the run
      await o.idle();
      expect(await o.snapshot(), isNull);
      expect(await row(), v2, reason: 'never overwritten, stripped or reset');
      expect(db.casCalls, cas, reason: 'the old build attempted no write');
      expect(o.status.health, old.IntruderMonitorHealth.readOnly);
      expect(o.status.droppedFailureRecords, 1);
      final old.IntruderLogRead r =
          await old.IntruderFailureLogStore(db, cipher: cipher).read();
      expect(r, isA<old.IntruderLogUnsupported>());
      expect((r as old.IntruderLogUnsupported).version, 2);
      expect(r.raw, v2);
    });

    test(
        'DG-2 a DAMAGED v2 (invalid gen) is still never touched by the old '
        'build; the new build treats it as corrupt (quarantine + new gen)',
        () async {
      final String bad =
          'enc:v1:${await cipher.encryptString(jsonEncode(<String, Object?>{
            'schema': 'sal.intruder_log',
            'v': 2,
            'gen': 'short',
            'nextSeq': 0,
            'run': 0,
            'events': <Object?>[],
          }))}';
      await db.setSetting(_key, bad);
      final old.IntruderMonitor o = oldBuild();
      o.onVerifiedAttempt(_fail());
      await o.idle();
      expect(await row(), bad);
      expect(o.status.health, old.IntruderMonitorHealth.readOnly);

      final IntruderMonitor n = newBuild(mints: <String>[_g2]);
      n.onVerifiedAttempt(_fail('N1'));
      await n.idle();
      expect(await db.getSetting(IntruderFailureLogStore.quarantineKey), bad);
      expect((await plain())['gen'], _g2);
    });
  });

  group('B-D1 condition 7: downgrade -> write -> re-upgrade', () {
    test(
        'DG-3 v2 -> old build writes (dropped) -> new build: gen kept, '
        'sequence continues, nothing minted', () async {
      final IntruderMonitor a = newBuild(mints: <String>[_g1]);
      a.onVerifiedAttempt(_fail('N1'));
      a.onVerifiedAttempt(_fail('N2'));
      await a.idle();

      final old.IntruderMonitor o = oldBuild();
      o.onVerifiedAttempt(_fail('OLD1'));
      o.onVerifiedAttempt(_ok());
      await o.idle();

      final IntruderMonitor b = newBuild(); // any mint would throw
      b.onVerifiedAttempt(_fail('N3'));
      await b.idle();
      expect(b.generationsMinted, 0);
      expect(b.status.health, IntruderMonitorHealth.ok);
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g1);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId),
          <String>['N1', 'N2', 'N3']);
      expect(l.events.map((FailedAttemptEvent e) => e.seq), <int>[0, 1, 2]);
      expect(l.events.every((FailedAttemptEvent e) => e.logGen == _g1), isTrue);
      expect(l.events.any((FailedAttemptEvent e) => e.legacy), isFalse);
      expect(l.consecutiveFailures, 3,
          reason: 'the old build\'s success never reached storage');
      expect(await plainText(), isNot(contains('OLD1')));
    });

    test(
        'DG-4 v1 (old) -> upgrade -> downgrade -> re-upgrade: v1 events are '
        'preserved as legacy, the gen is minted once and never changes',
        () async {
      await seedV1ByOldBuild();
      final IntruderMonitor a = newBuild(mints: <String>[_g1]);
      a.onVerifiedAttempt(_fail('N1'));
      await a.idle();
      expect(a.generationsMinted, 1);
      final Map<String, Object?> doc = await plain();
      expect(doc['v'], 2);
      expect(doc['gen'], _g1);
      final List<Object?> ev = doc['events']! as List<Object?>;
      expect(<Object?>[
        for (final Object? e in ev) (e! as Map)['legacy']
      ], <Object?>[
        true,
        true,
        null
      ], reason: 'v1-era events become legacy; v2 events carry no marker');
      final String upgraded = (await row())!;

      final old.IntruderMonitor o = oldBuild();
      o.onVerifiedAttempt(_fail('OLD1'));
      await o.idle();
      expect(await row(), upgraded);

      final IntruderMonitor b = newBuild();
      b.onVerifiedAttempt(_fail('N2'));
      await b.idle();
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g1);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId),
          <String>['L1', 'L2', 'N1', 'N2']);
      expect(l.events.map((FailedAttemptEvent e) => e.seq), <int>[0, 1, 2, 3]);
      expect(l.events.map((FailedAttemptEvent e) => e.legacy),
          <bool>[true, true, false, false]);
      expect(l.events.map((FailedAttemptEvent e) => e.logGen),
          <String?>[null, null, _g1, _g1]);
      expect(l.consecutiveFailures, 4, reason: 'run carried across v1 -> v2');
    });
  });

  group('B-D1 condition 7: process death and interrupted migration', () {
    test(
        'DG-5 death BEFORE the first v2 commit: v1 bytes intact; the old '
        'build may keep writing v1; the dead gen never appears', () async {
      await seedV1ByOldBuild();
      final String v1 = (await row())!;
      final IntruderMonitor dying = newBuild(mints: <String>[_g1]);
      db.death = _Death.beforeCommit;
      dying.onVerifiedAttempt(_fail('DEAD'));
      await pumpEventQueue();
      expect(db.abandoned, 1);
      expect(await row(), v1, reason: 'nothing was written');

      // Interrupted migration, then a downgrade: the old build still owns v1.
      final old.IntruderMonitor o = oldBuild();
      o.onVerifiedAttempt(_fail('L3'));
      await o.idle();
      expect((await plain())['v'], 1);

      final IntruderMonitor restarted = newBuild(mints: <String>[_g2]);
      restarted.onVerifiedAttempt(_fail('N1'));
      await restarted.idle();
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g2);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId),
          <String>['L1', 'L2', 'L3', 'N1']);
      expect(l.events.map((FailedAttemptEvent e) => e.legacy),
          <bool>[true, true, true, false]);
      final String text = await plainText();
      expect(text, isNot(contains(_g1)), reason: 'a lost gen is never stored');
      expect(text, isNot(contains('DEAD')));
    });

    test(
        'DG-6 death AFTER the commit, before the ack: the restart adopts the '
        'committed gen (no new mint) and the event exists exactly once',
        () async {
      await seedV1ByOldBuild();
      final IntruderMonitor dying = newBuild(mints: <String>[_g1]);
      db.death = _Death.afterCommit;
      dying.onVerifiedAttempt(_fail('D1'));
      await pumpEventQueue();
      expect(db.abandoned, 1);
      expect((await plain())['gen'], _g1);

      final IntruderMonitor restarted = newBuild(); // any mint would throw
      restarted.onVerifiedAttempt(_fail('D1')); // redelivery after restart
      restarted.onVerifiedAttempt(_fail('N2'));
      await restarted.idle();
      expect(restarted.generationsMinted, 0);
      final IntruderFailureLog l = await durable();
      expect(l.gen, _g1);
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId),
          <String>['L1', 'L2', 'D1', 'N2']);

      // And a downgrade after that still cannot touch it.
      final String v2 = (await row())!;
      final old.IntruderMonitor o = oldBuild();
      o.onVerifiedAttempt(_fail());
      o.onVerifiedAttempt(_ok());
      await o.idle();
      expect(await row(), v2);
    });

    test(
        'DG-7 death during the v2 -> v2 write after a downgrade: the old '
        'build ran in between, the gen survives', () async {
      final IntruderMonitor a = newBuild(mints: <String>[_g1]);
      a.onVerifiedAttempt(_fail('N1'));
      await a.idle();
      final old.IntruderMonitor o = oldBuild();
      o.onVerifiedAttempt(_fail());
      await o.idle();
      final String before = (await row())!;
      final IntruderMonitor dying = newBuild();
      db.death = _Death.beforeCommit;
      dying.onVerifiedAttempt(_fail('DEAD'));
      await pumpEventQueue();
      expect(await row(), before);
      final IntruderMonitor b = newBuild();
      b.onVerifiedAttempt(_fail('N2'));
      await b.idle();
      expect((await durable()).gen, _g1);
      expect(
          (await durable())
              .events
              .map((FailedAttemptEvent e) => e.verificationId),
          <String>['N1', 'N2']);
    });
  });

  group('first-upgrade concurrency and fail-closed minting', () {
    test(
        'DG-8 two instances race the first v1 -> v2 upgrade: exactly one gen '
        'wins, the loser adopts it, both events kept, the losing gen is '
        'never stored', () async {
      await seedV1ByOldBuild();
      final IntruderMonitor a = newBuild(mints: <String>[_g1, _g3]);
      final IntruderMonitor b = newBuild(mints: <String>[_g2, _g3]);
      a.onVerifiedAttempt(_fail('A1'));
      b.onVerifiedAttempt(_fail('B1'));
      await Future.wait(<Future<void>>[a.idle(), b.idle()]);
      final IntruderFailureLog l = await durable();
      expect(<String>[_g1, _g2], contains(l.gen));
      final String loser = l.gen == _g1 ? _g2 : _g1;
      expect(await plainText(), isNot(contains(loser)));
      expect(await plainText(), isNot(contains(_g3)));
      expect(l.events.map((FailedAttemptEvent e) => e.verificationId).toSet(),
          <String>{'L1', 'L2', 'A1', 'B1'});
      expect(
          l.events
              .where((FailedAttemptEvent e) => !e.legacy)
              .every((FailedAttemptEvent e) => e.logGen == l.gen),
          isTrue);
      expect(l.events.where((FailedAttemptEvent e) => e.legacy).length, 2);
      expect(
          a.status.droppedFailureRecords + b.status.droppedFailureRecords, 0);
    });

    test(
        'DG-9 no secure generator: the v1 row stays byte-identical, the '
        'attempt is reported dropped, NO v1-header fallback', () async {
      await seedV1ByOldBuild();
      final String v1 = (await row())!;
      final int cas = db.casCalls;
      final IntruderMonitor n = IntruderMonitor(
        store: IntruderFailureLogStore(db, cipher: cipher),
        now: () => _t0,
        mintGeneration: () => throw UnsupportedError('no secure random'),
      );
      n.onVerifiedAttempt(_fail('N1'));
      n.onVerifiedAttempt(_ok());
      await n.idle();
      expect(await row(), v1);
      expect(db.casCalls, cas);
      expect(n.status.health, IntruderMonitorHealth.storageError);
      expect(n.status.droppedFailureRecords, 1);
      expect(n.status.resetPending, isTrue);
      expect(() => IntruderFailureLog.empty.toJson(), throwsStateError);
      // An invalid id from a generator is equally refused.
      final IntruderMonitor bad = IntruderMonitor(
        store: IntruderFailureLogStore(db, cipher: cipher),
        now: () => _t0,
        mintGeneration: () => 'not-a-generation',
      );
      bad.onVerifiedAttempt(_fail('N2'));
      await bad.idle();
      expect(await row(), v1);
    });

    test('DG-10 production minting: 22-char base64url, 128-bit, distinct', () {
      final Set<String> ids = <String>{
        for (int i = 0; i < 2000; i++) LogGeneration.mint(),
      };
      expect(ids, hasLength(2000));
      for (final String id in ids) {
        expect(LogGeneration.isValid(id), isTrue);
        expect(base64Url.decode('$id=='), hasLength(16));
      }
      expect(LogGeneration.isValid('A' * 21), isFalse);
      expect(LogGeneration.isValid('${'A' * 21}='), isFalse);
      expect(LogGeneration.isValid(null), isFalse);
    });
  });
}
