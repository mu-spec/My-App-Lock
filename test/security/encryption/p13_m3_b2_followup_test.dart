// P13/M3 Batch 2 follow-up (owner decision after the Batch 2 report):
//   RF-01..05  B2-RET-1: wrapped bytes are never discarded on a transient
//              (or KEK-missing) unwrap failure; kept copies stay usable.
//   RF-06..08  legacy-slot guard: a null read of a PRESENT entry is an error;
//              the legacy key is never written over (T7 / T2).
//   RF-09..10  T4: invalid legacy slot + verified wrapped copy.
//   RF-11..19  B2-PEND-1: safe recovery of a stale pending commitment.
//   RF-20      `kept` parsing fails safe (unsupported, never rewritten).
//
// SIMULATED: host VM, in-memory DB / secret store / KEK double. NOT Android
// Keystore, NOT process death, NOT real isolates (DEVICE BLOCKED).
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/encryption/key_wrapper.dart';
import 'package:smart_app_lock/security/encryption/master_key_resolver.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';

const String _mk = SecretKeys.settingsMasterKey;
const String _commit = MasterKeyResolver.commitKey;

class _Secrets implements SecretStore {
  final InMemorySecretStore inner = InMemorySecretStore();
  int keyWrites = 0;
  int nullReads = 0; // null although the entry is present
  bool containsThrows = false;

  @override
  Future<String?> read(String key) async {
    await Future<void>.delayed(Duration.zero);
    if (key == _mk && nullReads > 0) {
      nullReads--;
      return null;
    }
    return inner.read(key);
  }

  @override
  Future<void> write(String key, String value) async {
    await Future<void>.delayed(Duration.zero);
    if (key == _mk) keyWrites++;
    return inner.write(key, value);
  }

  @override
  Future<void> delete(String key) async => throw StateError('never deletes');
  @override
  Future<void> clear() async => throw StateError('never clears');
  @override
  Future<bool> containsKey(String key) async {
    if (containsThrows) throw StateError('keystore busy');
    return inner.containsKey(key);
  }
}

/// Plain in-memory DB (no CAS override: the R8 inventory stays unchanged).
class _Db extends InMemoryLocalDatabase {}

/// KEK double whose unwrap can fail TRANSIENTLY for [transientUnwraps] calls.
class _Flaky implements KeyWrapper {
  _Flaky(this.inner);
  final InMemoryKeyWrapper inner;
  int transientUnwraps = 0;
  bool wrapUnavailable = false;
  @override
  Future<WrappedKey> wrapNew(Uint8List key) async {
    if (wrapUnavailable) throw const KeyWrapUnavailable('busy');
    return inner.wrapNew(key);
  }

  @override
  Future<Uint8List> unwrap(WrappedKey w) async {
    if (transientUnwraps > 0) {
      transientUnwraps--;
      throw const KeyWrapUnavailable('busy');
    }
    return inner.unwrap(w);
  }
}

DateTime _t0 = DateTime.utc(2026, 10, 1, 12);

MasterKeyResolver _resolver(SecretStore s, LocalDatabase db,
        {KeyWrapper wrapper = const NoKeyWrapper(), DateTime? now}) =>
    MasterKeyResolver(
      secrets: s,
      database: db,
      wrapper: wrapper,
      clock: () => now ?? _t0,
      pendingPollInterval: const Duration(milliseconds: 1),
      delay: (Duration d) => Future<void>.delayed(Duration.zero),
    );

Uint8List _key(int b) => Uint8List.fromList(List<int>.filled(32, b));
Future<String> _kid(int b) => MasterKeyResolver.kidOf(_key(b));
Map<String, Object?> _row(String? raw) =>
    (jsonDecode(raw!) as Map<Object?, Object?>).cast<String, Object?>();

Future<String> _rowOf(int b,
        {required bool active,
        WrappedKey? w,
        int? at,
        List<WrappedKey> kept = const <WrappedKey>[]}) async =>
    jsonEncode(<String, Object?>{
      'v': 1,
      'state': active ? 'active' : 'pending',
      'kid': await _kid(b),
      if (w != null) 'alias': w.alias,
      if (w != null) 'wrapped': w.blob,
      'at': at ?? _t0.millisecondsSinceEpoch,
      if (kept.isNotEmpty)
        'kept': <Map<String, String>>[
          for (final WrappedKey k in kept)
            <String, String>{'alias': k.alias, 'wrapped': k.blob},
        ],
    });

Map<String, String> _k(WrappedKey w) =>
    <String, String>{'alias': w.alias, 'wrapped': w.blob};

MasterKeyIssue? _issue(MasterKeyState s) =>
    s is MasterKeyUnavailable ? s.issue : null;

const int _min = 60 * 1000;

void main() {
  group('RF B2-RET-1 wrapped bytes are never discarded', () {
    test(
        'RF-01 T5 transient unwrap error: activates on the verified L, the '
        'unverified copy is KEPT byte-exact, a fresh verified copy is added',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      final _Flaky w = _Flaky(kek)..transientUnwraps = 1;
      final WrappedKey wk = await kek.wrapNew(_key(1));
      await s.inner.write(_mk, base64Encode(_key(1)));
      await db.setSetting(_commit, await _rowOf(1, active: false, w: wk));
      final MasterKeyState st = await _resolver(s, db, wrapper: w).resolve();
      expect(st, isA<MasterKeyReady>());
      final Map<String, Object?> row = _row(await db.getSetting(_commit));
      expect(row['state'], 'active');
      expect(row['kept'], <Object?>[_k(wk)]);
      expect(row['alias'], isNot(wk.alias));
      expect(s.keyWrites, 0, reason: 'L untouched');
      expect(kek.aliases, contains(wk.alias));
    });

    test('RF-02 T5 KEK missing: the dead copy is kept with its bytes too',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      final WrappedKey wk = await kek.wrapNew(_key(2));
      kek.loseAllKeks();
      await s.inner.write(_mk, base64Encode(_key(2)));
      await db.setSetting(_commit, await _rowOf(2, active: false, w: wk));
      expect(await _resolver(s, db, wrapper: kek).resolve(),
          isA<MasterKeyReady>());
      expect(_row(await db.getSetting(_commit))['kept'], <Object?>[_k(wk)]);
    });

    test(
        'RF-03 `kept` full: nothing is moved or dropped; the primary copy '
        'stays in place', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      final List<WrappedKey> full = <WrappedKey>[
        for (int i = 0; i < MasterKeyResolver.maxKept; i++)
          await kek.wrapNew(_key(3)),
      ];
      final WrappedKey wk = await kek.wrapNew(_key(3));
      final _Flaky w = _Flaky(kek)..transientUnwraps = 1;
      await s.inner.write(_mk, base64Encode(_key(3)));
      await db.setSetting(
          _commit, await _rowOf(3, active: false, w: wk, kept: full));
      expect(
          await _resolver(s, db, wrapper: w).resolve(), isA<MasterKeyReady>());
      final Map<String, Object?> row = _row(await db.getSetting(_commit));
      expect(row['alias'], wk.alias);
      expect(row['wrapped'], wk.blob);
      expect(row['kept'], <Object?>[for (final WrappedKey k in full) _k(k)]);
    });

    test(
        'RF-04 T5 L holds another key: the old pending copy is kept; with '
        '`kept` full the resolver fails closed and writes nothing', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      final WrappedKey wk = await kek.wrapNew(_key(4));
      await s.inner.write(_mk, base64Encode(_key(40)));
      await db.setSetting(_commit, await _rowOf(4, active: false, w: wk));
      final MasterKeyState st = await _resolver(s, db, wrapper: kek).resolve();
      expect((st as MasterKeyReady).kid, await _kid(40));
      expect(_row(await db.getSetting(_commit))['kept'], <Object?>[_k(wk)]);

      final _Secrets s2 = _Secrets();
      final _Db db2 = _Db();
      final List<WrappedKey> full = <WrappedKey>[
        for (int i = 0; i < MasterKeyResolver.maxKept; i++)
          await kek.wrapNew(_key(4)),
      ];
      await s2.inner.write(_mk, base64Encode(_key(40)));
      final String before = await _rowOf(4, active: false, w: wk, kept: full);
      await db2.setSetting(_commit, before);
      expect(_issue(await _resolver(s2, db2, wrapper: kek).resolve()),
          MasterKeyIssue.storageError);
      expect(await db2.getSetting(_commit), before);
      expect(s2.keyWrites, 0);
    });

    test(
        'RF-05 T7 primary KEK gone but a KEPT copy verifies: L is restored '
        'from the kept copy (kid verified)', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kekA = InMemoryKeyWrapper();
      final WrappedKey dead = await InMemoryKeyWrapper().wrapNew(_key(5));
      final WrappedKey good = await kekA.wrapNew(_key(5));
      await db.setSetting(_commit,
          await _rowOf(5, active: true, w: dead, kept: <WrappedKey>[good]));
      final MasterKeyState st = await _resolver(s, db, wrapper: kekA).resolve();
      expect((st as MasterKeyReady).readOnly, isFalse);
      expect(await s.inner.read(_mk), base64Encode(_key(5)));
      expect(s.keyWrites, 1);
    });
  });

  group('RF legacy-slot guard (present-but-null is an error)', () {
    test(
        'RF-06 active{k}, L physically holds ANOTHER key k\', one null read: '
        'L is NOT overwritten; the next read reports KeyMismatch', () async {
      final _Secrets s = _Secrets()..nullReads = 1;
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      await s.inner.write(_mk, base64Encode(_key(61)));
      await db.setSetting(_commit,
          await _rowOf(6, active: true, w: await kek.wrapNew(_key(6))));
      final MasterKeyState first =
          await _resolver(s, db, wrapper: kek).resolve();
      expect(first is MasterKeyReady ? first.readOnly : true, isTrue,
          reason: 'never a writable key from that read');
      expect(s.keyWrites, 0);
      expect(await s.inner.read(_mk), base64Encode(_key(61)),
          reason: 'the other legacy key is preserved');
      expect(_issue(await _resolver(s, db, wrapper: kek).resolve()),
          MasterKeyIssue.keyMismatch);
      expect(s.keyWrites, 0);
    });

    test(
        'RF-07 present-but-null with a verified wrapped copy: read-only, '
        'no write', () async {
      final _Secrets s = _Secrets()..nullReads = 1;
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      await s.inner.write(_mk, base64Encode(_key(7)));
      await db.setSetting(_commit,
          await _rowOf(7, active: true, w: await kek.wrapNew(_key(7))));
      final MasterKeyState st = await _resolver(s, db, wrapper: kek).resolve();
      expect((st as MasterKeyReady).readOnly, isTrue);
      expect(s.keyWrites, 0);
    });

    test(
        'RF-08 no commitment, L present but read null (or containsKey '
        'throws): storageError, no mint, no commitment written', () async {
      for (final bool containsThrows in <bool>[false, true]) {
        final _Secrets s = _Secrets()
          ..nullReads = 1
          ..containsThrows = containsThrows;
        final _Db db = _Db();
        await s.inner.write(_mk, base64Encode(_key(8)));
        expect(_issue(await _resolver(s, db).resolve()),
            MasterKeyIssue.storageError);
        expect(s.keyWrites, 0);
        expect(await db.getSetting(_commit), isNull);
        expect(await s.inner.read(_mk), base64Encode(_key(8)));
      }
    });
  });

  group('RF T4 invalid legacy slot with a verified wrapped copy', () {
    test(
        'RF-09 garbage L + verified copy: writable Ready, garbage untouched; '
        'a transient unwrap error first fails closed, then recovers', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      final _Flaky w = _Flaky(kek)..transientUnwraps = 1;
      await s.inner.write(_mk, 'Data has been reset');
      final String row =
          await _rowOf(9, active: true, w: await kek.wrapNew(_key(9)));
      await db.setSetting(_commit, row);
      expect(_issue(await _resolver(s, db, wrapper: w).resolve()),
          MasterKeyIssue.storageError);
      expect(await db.getSetting(_commit), row);
      final MasterKeyState st = await _resolver(s, db, wrapper: w).resolve();
      expect((st as MasterKeyReady).readOnly, isFalse);
      expect(st.key, _key(9));
      expect(await s.inner.read(_mk), 'Data has been reset');
      expect(s.keyWrites, 0);
      expect(await db.getSetting(_commit), row);
    });

    test('RF-10 garbage L + every KEK gone: KeyLost, nothing written',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      await s.inner.write(_mk, 'Data has been reset');
      await db.setSetting(_commit,
          await _rowOf(10, active: true, w: await kek.wrapNew(_key(10))));
      kek.loseAllKeks();
      expect(_issue(await _resolver(s, db, wrapper: kek).resolve()),
          MasterKeyIssue.keyLost);
      expect(s.keyWrites, 0);
      expect(await s.inner.read(_mk), 'Data has been reset');
    });
  });

  group('RF B2-PEND-1 stale pending recovery', () {
    Future<String> stale(int b, {WrappedKey? w}) => _rowOf(b,
        active: false, w: w, at: _t0.millisecondsSinceEpoch - 11 * _min);

    test(
        'RF-11 stale pending, L absent, no data, no usable copy: one takeover '
        'with a VERIFIED wrapped copy; Ready; L written once', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      await db.setSetting(_commit, await stale(11));
      final MasterKeyResolver r = _resolver(s, db, wrapper: kek);
      final MasterKeyState st = await r.resolve();
      expect(st, isA<MasterKeyReady>());
      expect(r.takeovers, 1);
      expect(s.keyWrites, 1);
      final Map<String, Object?> row = _row(await db.getSetting(_commit));
      expect(row['state'], 'active');
      expect(row['kid'], isNot(await _kid(11)));
      final Uint8List l = base64Decode((await s.inner.read(_mk))!);
      expect(await MasterKeyResolver.kidOf(l), row['kid']);
      expect(
          await kek.unwrap(WrappedKey(
              alias: row['alias']! as String, blob: row['wrapped']! as String)),
          l);
    });

    test('RF-12 pending younger than the threshold: no takeover', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String row = await _rowOf(12,
          active: false, at: _t0.millisecondsSinceEpoch - 9 * _min);
      await db.setSetting(_commit, row);
      final MasterKeyResolver r =
          _resolver(s, db, wrapper: InMemoryKeyWrapper());
      expect(_issue(await r.resolve()), MasterKeyIssue.initializing);
      expect(r.takeovers, 0);
      expect(await db.getSetting(_commit), row);
      expect(s.keyWrites, 0);
    });

    test('RF-13 pending stamped in the FUTURE (clock moved back): never stale',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String row = await _rowOf(13,
          active: false, at: _t0.millisecondsSinceEpoch + 24 * 60 * _min);
      await db.setSetting(_commit, row);
      expect(
          _issue(
              await _resolver(s, db, wrapper: InMemoryKeyWrapper()).resolve()),
          MasterKeyIssue.initializing);
      expect(await db.getSetting(_commit), row);
    });

    test('RF-14 stale pending but encrypted data exists: KeyLost, no takeover',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String row = await stale(14);
      await db.setSetting(_commit, row);
      await db.setSetting('x', 'enc:v1:AAAA');
      expect(
          _issue(
              await _resolver(s, db, wrapper: InMemoryKeyWrapper()).resolve()),
          MasterKeyIssue.keyLost);
      expect(await db.getSetting(_commit), row);
      expect(s.keyWrites, 0);
    });

    test(
        'RF-15 stale pending, wrapping unavailable or unverifiable: no '
        'takeover (fail closed)', () async {
      for (final bool flakyUnwrap in <bool>[false, true]) {
        final _Secrets s = _Secrets();
        final _Db db = _Db();
        final String row = await stale(15);
        await db.setSetting(_commit, row);
        final _Flaky w = _Flaky(InMemoryKeyWrapper());
        if (flakyUnwrap) {
          w.transientUnwraps = 1000;
        } else {
          w.wrapUnavailable = true;
        }
        final MasterKeyResolver r = _resolver(s, db, wrapper: w);
        expect(_issue(await r.resolve()), MasterKeyIssue.initializing);
        expect(r.takeovers, 0);
        expect(w.inner.wraps, flakyUnwrap ? 1 : 0,
            reason: 'at most one KEK minted per resolve, never per poll');
        expect(await db.getSetting(_commit), row);
        expect(s.keyWrites, 0);
      }
    });

    test('RF-16 a DECRYPT never takes over (allowGenesis=false)', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final String row = await stale(16);
      await db.setSetting(_commit, row);
      final MasterKeyResolver r =
          _resolver(s, db, wrapper: InMemoryKeyWrapper());
      expect(_issue(await r.resolve(allowGenesis: false)),
          MasterKeyIssue.initializing);
      expect(await db.getSetting(_commit), row);
    });

    test('RF-17 the old pending copy (KEK gone) is kept with its bytes',
        () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final WrappedKey old = await InMemoryKeyWrapper().wrapNew(_key(17));
      await db.setSetting(_commit, await stale(17, w: old));
      expect(await _resolver(s, db, wrapper: InMemoryKeyWrapper()).resolve(),
          isA<MasterKeyReady>());
      expect(_row(await db.getSetting(_commit))['kept'], <Object?>[_k(old)]);
    });

    test(
        'RF-18 8 instances on one stale pending row: exactly one takeover, '
        'one key, every instance Ready with the same kid', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      await db.setSetting(_commit, await stale(18));
      final List<MasterKeyResolver> rs = <MasterKeyResolver>[
        for (int i = 0; i < 8; i++) _resolver(s, db, wrapper: kek),
      ];
      final List<MasterKeyState> out =
          await Future.wait(rs.map((MasterKeyResolver r) => r.resolve()));
      expect(
          rs.fold<int>(0, (int a, MasterKeyResolver r) => a + r.takeovers), 1);
      final Set<String> kids = <String>{
        for (final MasterKeyState o in out) (o as MasterKeyReady).kid,
      };
      expect(kids, hasLength(1));
      // Losers may complete the SAME key idempotently (identical bytes).
      expect(
          await MasterKeyResolver.kidOf(
              base64Decode((await s.inner.read(_mk))!)),
          kids.single);
    });

    test(
        'RF-19 a STALLED creator writing its key after the takeover: '
        'KeyMismatch (fail closed); the new key stays in the verified '
        'wrapped copy; nothing is written or deleted', () async {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
      await db.setSetting(_commit, await stale(19));
      expect(await _resolver(s, db, wrapper: kek).resolve(),
          isA<MasterKeyReady>());
      final String rowAfter = (await db.getSetting(_commit))!;
      final Uint8List newKey = base64Decode((await s.inner.read(_mk))!);
      // The stalled creator (key 19) resumes and writes L unconditionally.
      await s.inner.write(_mk, base64Encode(_key(19)));
      final int writes = s.keyWrites;
      expect(_issue(await _resolver(s, db, wrapper: kek).resolve()),
          MasterKeyIssue.keyMismatch);
      expect(await db.getSetting(_commit), rowAfter);
      expect(s.keyWrites, writes);
      final Map<String, Object?> row = _row(rowAfter);
      expect(
          await kek.unwrap(WrappedKey(
              alias: row['alias']! as String, blob: row['wrapped']! as String)),
          newKey,
          reason: 'the taken-over key is recoverable (DB-3 decides how)');
    });
  });

  test('RF-20 malformed or oversized `kept`: unsupported, never rewritten',
      () async {
    final InMemoryKeyWrapper kek = InMemoryKeyWrapper();
    final WrappedKey w = await kek.wrapNew(_key(20));
    final String base = await _rowOf(20, active: true, w: w);
    final List<String> bad = <String>[
      base.replaceFirst('"at"', '"kept":[{"alias":1,"wrapped":"x"}],"at"'),
      base.replaceFirst('"at"', '"kept":"x","at"'),
      await _rowOf(20, active: true, w: w, kept: <WrappedKey>[
        for (int i = 0; i <= MasterKeyResolver.maxKept; i++) w,
      ]),
    ];
    for (final String row in bad) {
      final _Secrets s = _Secrets();
      final _Db db = _Db();
      await s.inner.write(_mk, base64Encode(_key(20)));
      await db.setSetting(_commit, row);
      expect(_issue(await _resolver(s, db, wrapper: kek).resolve()),
          MasterKeyIssue.unsupportedCommitment);
      expect(await db.getSetting(_commit), row);
      expect(s.keyWrites, 0);
    }
  });
}
