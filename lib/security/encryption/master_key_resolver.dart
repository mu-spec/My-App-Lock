import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../../data/storage/local_database.dart';
import '../storage/secret_store.dart';
import 'key_wrapper.dart';

/// Why the master data key is not usable right now.
enum MasterKeyIssue {
  /// SQLite or the legacy secret slot could not be read (transient).
  storageError,

  /// Another instance is initializing; retry.
  initializing,

  /// The legacy slot holds something that is not a 256-bit key (e.g. the
  /// plugin's "Data has been reset" string). Never overwritten.
  legacyKeyInvalid,

  /// The commitment row was written by a newer build. Never rewritten.
  unsupportedCommitment,

  /// Encrypted data exists but no copy of its key is available. Never
  /// replaced by a fresh key (F-KEY-1: no silent regeneration).
  keyLost,

  /// The legacy slot holds a different valid key than the committed one
  /// (e.g. written by an older build after a downgrade). Fail closed; both
  /// keys are preserved (owner decision DB-3 pending).
  keyMismatch,

  /// A decrypt was attempted but no key has ever been committed and none
  /// exists; decrypt paths never create one.
  noKey,
}

sealed class MasterKeyState {
  const MasterKeyState();
}

final class MasterKeyReady extends MasterKeyState {
  const MasterKeyReady(this.key, {required this.kid, this.readOnly = false});
  final Uint8List key;
  final String kid;

  /// The legacy slot could not be read; the key came from the wrapped copy
  /// and is used for decryption only until the slot reads cleanly.
  final bool readOnly;
}

final class MasterKeyUnavailable extends MasterKeyState {
  const MasterKeyUnavailable(this.issue);
  final MasterKeyIssue issue;
}

/// Thrown by the cipher when the key is not [MasterKeyReady]. Stores map it
/// to "unreadable" (never "corrupt"), so nothing is quarantined or replaced.
final class MasterKeyUnavailableException implements Exception {
  const MasterKeyUnavailableException(this.issue);
  final MasterKeyIssue issue;
  @override
  String toString() => 'MasterKeyUnavailableException(${issue.name})';
}

/// F-KEY-1 / K-2+B-compat master-key resolver (Batch 2).
///
/// Durable inputs (no atomicity is assumed between them):
///  * S: SQLite row [commitKey] `{v:1, state: pending|active, kid,
///    alias?, wrapped?, at}`, changed ONLY by `compareAndSetSetting`;
///  * L: the legacy secret slot [SecretKeys.settingsMasterKey] — the data
///    key itself, byte-compatible with every older build (downgrade-safe);
///  * W: an optional platform KEK copy (`wrapped` under `alias`);
///  * E: encrypted data exists (any setting value starting `enc:v1:`).
///
/// Invariants:
///  * I1 a key is returned only after its kid matches an ACTIVE commitment;
///  * I2 no key is ever minted while encrypted data exists;
///  * I3 nothing is deleted: not L, not S, not a KEK alias, no ciphertext;
///  * I4 L is written only while S is PENDING for that exact key and L is
///    absent (genesis), or to restore an ABSENT slot from a verified
///    wrapped copy. A present L is never overwritten.
///  * The ciphertext format is unchanged (`enc:v1:` + raw AES-GCM).
class MasterKeyResolver {
  MasterKeyResolver({
    required SecretStore secrets,
    required LocalDatabase database,
    KeyWrapper wrapper = const NoKeyWrapper(),
    Random? random,
    DateTime Function()? clock,
    Future<void> Function(Duration)? delay,
    this.pendingPolls = 10,
    this.pendingPollInterval = const Duration(milliseconds: 100),
  })  : _secrets = secrets,
        _db = database,
        _wrapper = wrapper,
        _random = random ?? Random.secure(),
        _clock = clock ?? DateTime.now,
        _delay = delay ?? Future<void>.delayed;

  static const String commitKey = 'sec.key_commit';
  static const String _enc = 'enc:v1:';
  static const int keyLength = 32;
  static const int maxRounds = 6;

  /// Superseded KEK aliases are recorded (never deleted); bounded.
  static const int maxRetired = 4;

  final SecretStore _secrets;
  final LocalDatabase _db;
  final KeyWrapper _wrapper;
  final Random _random;
  final DateTime Function() _clock;
  final Future<void> Function(Duration) _delay;
  final int pendingPolls;
  final Duration pendingPollInterval;

  MasterKeyReady? _ready;
  final Map<bool, Future<MasterKeyState>> _inFlight =
      <bool, Future<MasterKeyState>>{};

  /// Number of legacy-slot writes made by THIS resolver (tests/diagnostics).
  int legacyWrites = 0;

  /// Single-flight per instance (a performance measure only; correctness
  /// comes from the SQLite CAS). A writable Ready result is cached.
  ///
  /// [allowGenesis] false (decrypt paths) never creates a key, even when no
  /// encrypted data is visible: something is being decrypted, so a key must
  /// already exist (F-KEY-1 R3/R4).
  Future<MasterKeyState> resolve({bool allowGenesis = true}) {
    final MasterKeyReady? r = _ready;
    if (r != null) return Future<MasterKeyState>.value(r);
    // Block body on purpose: returning the removed Future from the
    // whenComplete callback would make the future wait on itself.
    return _inFlight[allowGenesis] ??=
        _resolveOnce(allowGenesis).whenComplete(() {
      _inFlight.remove(allowGenesis);
    });
  }

  Future<MasterKeyState> _resolveOnce(bool allowGenesis) async {
    final MasterKeyState s = await _run(allowGenesis);
    if (s is MasterKeyReady && !s.readOnly) _ready = s;
    return s;
  }

  static Future<String> kidOf(List<int> key) async {
    final Mac mac = await Hmac.sha256()
        .calculateMac(utf8.encode('sal-kid-v1'), secretKey: SecretKey(key));
    return mac.bytes
        .take(16)
        .map((int b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  Future<MasterKeyState> _run(bool allowGenesis) async {
    int polls = 0;
    for (int round = 0; round < maxRounds + pendingPolls; round++) {
      final _S? s;
      try {
        s = _S.parse(await _db.getSetting(commitKey));
      } on _Unsupported {
        return const MasterKeyUnavailable(MasterKeyIssue.unsupportedCommitment);
      } catch (_) {
        return const MasterKeyUnavailable(MasterKeyIssue.storageError);
      }
      final _L l = await _readL();
      final _Step step = s == null
          ? await _absent(l, allowGenesis)
          : s.active
              ? await _active(s, l)
              : await _pending(s, l);
      switch (step) {
        case _Done(:final MasterKeyState state):
          return state;
        case _Retry():
          continue;
        case _Wait():
          if (++polls > pendingPolls) {
            return const MasterKeyUnavailable(MasterKeyIssue.initializing);
          }
          await _delay(pendingPollInterval);
          continue;
      }
    }
    return const MasterKeyUnavailable(MasterKeyIssue.initializing);
  }

  // -- S absent ------------------------------------------------------------

  Future<_Step> _absent(_L l, bool allowGenesis) async {
    switch (l) {
      case _LError():
        return const _Done(MasterKeyUnavailable(MasterKeyIssue.storageError));
      case _LGarbage():
        return const _Done(
            MasterKeyUnavailable(MasterKeyIssue.legacyKeyInvalid));
      case _LValid(:final Uint8List key):
        // T1 adopt the legacy key (existing installs). Ciphertext untouched.
        final String kid = await kidOf(key);
        final WrappedKey? w = await _tryWrap(key);
        await _cas(null, _S.encode(false, kid, w, _now(), const <String>[]));
        return const _Retry(); // completes via the pending path (verify)
      case _LAbsent():
        final bool? e = await _encryptedDataExists();
        if (e == null) {
          return const _Done(MasterKeyUnavailable(MasterKeyIssue.storageError));
        }
        if (e) {
          // T3: never mint over encrypted data.
          return const _Done(MasterKeyUnavailable(MasterKeyIssue.keyLost));
        }
        if (!allowGenesis) {
          return const _Done(MasterKeyUnavailable(MasterKeyIssue.noKey));
        }
        // T2 genesis: commit FIRST (one CAS winner), then write L.
        final Uint8List fresh = _freshKey();
        final String kid = await kidOf(fresh);
        final WrappedKey? w = await _tryWrap(fresh);
        final String pending =
            _S.encode(false, kid, w, _now(), const <String>[]);
        if (!await _cas(null, pending)) return const _Retry(); // loser
        return _completeGenesis(pending, fresh, kid);
    }
  }

  // -- S pending -----------------------------------------------------------

  Future<_Step> _pending(_S s, _L l) async {
    switch (l) {
      case _LError():
        return const _Done(MasterKeyUnavailable(MasterKeyIssue.storageError));
      case _LGarbage():
        return const _Done(
            MasterKeyUnavailable(MasterKeyIssue.legacyKeyInvalid));
      case _LValid(:final Uint8List key):
        final String kidL = await kidOf(key);
        if (kidL == s.kid) {
          // T5: L matches. Activate only with a VERIFIED wrapped copy; an
          // unverifiable copy is dropped (alias recorded, never deleted).
          WrappedKey? keep = s.wrapped;
          List<String> retired = s.retired;
          if (keep != null) {
            final Uint8List? u = await _tryUnwrap(keep);
            if (u != null && await kidOf(u) != s.kid) {
              return const _Done(
                  MasterKeyUnavailable(MasterKeyIssue.keyMismatch));
            }
            if (u == null) {
              retired = _retire(retired, keep.alias);
              keep = null;
            }
          }
          await _cas(s.raw, _S.encode(true, s.kid, keep, s.at, retired));
          return const _Retry();
        }
        // T5: L holds another valid key. Nothing was ever encrypted under a
        // PENDING kid, so L wins: re-commit to L (pending), then verify.
        final WrappedKey? w = await _tryWrap(key);
        await _cas(
            s.raw,
            _S.encode(
                false,
                kidL,
                w,
                _now(),
                s.wrapped == null
                    ? s.retired
                    : _retire(s.retired, s.wrapped!.alias)));
        return const _Retry();
      case _LAbsent():
        final bool? e = await _encryptedDataExists();
        if (e == null) {
          return const _Done(MasterKeyUnavailable(MasterKeyIssue.storageError));
        }
        if (e) {
          return const _Done(MasterKeyUnavailable(MasterKeyIssue.keyLost));
        }
        // Complete the SAME pending key from the wrapped copy (idempotent:
        // every instance writes identical bytes).
        if (s.wrapped != null) {
          final Uint8List? u = await _tryUnwrap(s.wrapped!);
          if (u != null && await kidOf(u) == s.kid) {
            return _completeGenesis(s.raw, u, s.kid);
          }
        }
        // No usable wrapped copy: the creator may still be running. Losers
        // never mint and never take over (design §4): bounded wait, then
        // `initializing`. A pending row whose creator died before writing L
        // and that has no usable wrapped copy stays fail-closed (no data is
        // at risk: E is false). Disclosed as B2-PEND-1.
        return const _Wait();
    }
  }

  /// Writes L for a pending commitment we hold, verifies the read-back,
  /// then activates. Re-checks S immediately before the L write.
  Future<_Step> _completeGenesis(
      String pendingRaw, Uint8List key, String kid) async {
    try {
      if (await _db.getSetting(commitKey) != pendingRaw) return const _Retry();
      final _L now = await _readL();
      if (now is! _LAbsent) return const _Retry(); // never overwrite L
      await _secrets.write(SecretKeys.settingsMasterKey, base64Encode(key));
      legacyWrites++;
    } catch (_) {
      return const _Done(MasterKeyUnavailable(MasterKeyIssue.storageError));
    }
    return const _Retry(); // the pending path verifies kid(L) and activates
  }

  // -- S active ------------------------------------------------------------

  Future<_Step> _active(_S s, _L l) async {
    switch (l) {
      case _LValid(:final Uint8List key):
        final String kidL = await kidOf(key);
        if (kidL == s.kid) {
          // T6. Opportunistically add a wrapped copy if none exists yet.
          if (s.wrapped == null) {
            final WrappedKey? w = await _tryWrap(key);
            if (w != null) {
              final Uint8List? u = await _tryUnwrap(w);
              if (u != null && await kidOf(u) == s.kid) {
                await _cas(s.raw, _S.encode(true, s.kid, w, s.at, s.retired));
              }
            }
          }
          return _Done(MasterKeyReady(key, kid: s.kid));
        }
        // T8: a different valid key in L. Fail closed; touch nothing.
        return const _Done(MasterKeyUnavailable(MasterKeyIssue.keyMismatch));
      case _LAbsent():
      case _LGarbage():
        final _Unwrapped u = await _unwrapVerified(s);
        switch (u) {
          case _UOk(:final Uint8List key):
            if (l is _LAbsent) {
              // T7: restore the ABSENT slot from the verified copy.
              try {
                await _secrets.write(
                    SecretKeys.settingsMasterKey, base64Encode(key));
                legacyWrites++;
              } catch (_) {
                return _Done(MasterKeyReady(key, kid: s.kid, readOnly: true));
              }
              return const _Retry(); // re-verify via T6
            }
            // Garbage in L: never overwritten; the verified copy is used.
            return _Done(MasterKeyReady(key, kid: s.kid));
          case _UMissing():
            return const _Done(MasterKeyUnavailable(MasterKeyIssue.keyLost));
          case _UError():
            return const _Done(
                MasterKeyUnavailable(MasterKeyIssue.storageError));
        }
      case _LError():
        // T9: decrypt-only from the verified wrapped copy.
        final _Unwrapped u = await _unwrapVerified(s);
        if (u case _UOk(:final Uint8List key)) {
          return _Done(MasterKeyReady(key, kid: s.kid, readOnly: true));
        }
        return const _Done(MasterKeyUnavailable(MasterKeyIssue.storageError));
    }
  }

  // -- helpers -------------------------------------------------------------

  Future<_Unwrapped> _unwrapVerified(_S s) async {
    final WrappedKey? w = s.wrapped;
    if (w == null) return const _UMissing();
    try {
      final Uint8List k = await _wrapper.unwrap(w);
      if (await kidOf(k) != s.kid) return const _UError();
      return _UOk(k);
    } on KeyWrapMissing {
      return const _UMissing();
    } catch (_) {
      return const _UError();
    }
  }

  static List<String> _retire(List<String> retired, String alias) {
    final List<String> r = <String>[...retired, alias];
    return r.length <= maxRetired ? r : r.sublist(r.length - maxRetired);
  }

  Future<WrappedKey?> _tryWrap(Uint8List key) async {
    try {
      return await _wrapper.wrapNew(key);
    } catch (_) {
      return null; // runs without a wrapped copy (K-2+A degrade)
    }
  }

  Future<Uint8List?> _tryUnwrap(WrappedKey w) async {
    try {
      return await _wrapper.unwrap(w);
    } catch (_) {
      return null;
    }
  }

  Future<bool> _cas(String? expected, String next) async {
    try {
      return await _db.compareAndSetSetting(commitKey,
              expected: expected, next: next) ==
          CasOutcome.committed;
    } on CasUnknownOutcome {
      // One durable read decides. Sound for the only call whose result is
      // acted on (genesis): `next` carries a fresh random kid, so it is
      // unique. Every other caller re-reads S anyway.
      return await reconcileCompareAndSet(_db, commitKey, next) ==
          CasReconciliation.confirmedCommitted;
    } catch (_) {
      return false;
    }
  }

  Future<_L> _readL() async {
    final String? raw;
    try {
      raw = await _secrets.read(SecretKeys.settingsMasterKey);
    } catch (_) {
      return const _LError();
    }
    if (raw == null) return const _LAbsent();
    try {
      final Uint8List k = Uint8List.fromList(base64Decode(raw));
      if (k.length != keyLength) return const _LGarbage();
      return _LValid(k);
    } catch (_) {
      return const _LGarbage();
    }
  }

  /// null = could not be determined (treated as storage error).
  Future<bool?> _encryptedDataExists() async {
    try {
      final Map<String, String> all = await _db.getAllSettings();
      return all.values.any((String v) => v.startsWith(_enc));
    } catch (_) {
      return null;
    }
  }

  Uint8List _freshKey() => Uint8List.fromList(
      List<int>.generate(keyLength, (_) => _random.nextInt(256)));

  int _now() => _clock().millisecondsSinceEpoch;
}

// -- private model -----------------------------------------------------------

final class _Unsupported implements Exception {
  const _Unsupported();
}

final class _S {
  const _S(
      this.raw, this.active, this.kid, this.wrapped, this.at, this.retired);
  final String raw;
  final bool active;
  final String kid;
  final WrappedKey? wrapped;
  final int at;
  final List<String> retired;

  static _S? parse(String? raw) {
    if (raw == null) return null;
    final Object? d;
    try {
      d = jsonDecode(raw);
    } catch (_) {
      throw const _Unsupported();
    }
    if (d is! Map || d['v'] != 1) throw const _Unsupported();
    final Object? state = d['state'];
    final Object? kid = d['kid'];
    final Object? at = d['at'];
    final Object? alias = d['alias'];
    final Object? blob = d['wrapped'];
    final Object? retired = d['retired'] ?? const <Object?>[];
    if (retired is! List ||
        retired.length > MasterKeyResolver.maxRetired ||
        retired.any((Object? a) => a is! String) ||
        (state != 'pending' && state != 'active') ||
        kid is! String ||
        kid.length != 32 ||
        at is! int ||
        (alias == null) != (blob == null) ||
        (alias != null && (alias is! String || blob is! String))) {
      throw const _Unsupported();
    }
    return _S(
        raw,
        state == 'active',
        kid,
        alias == null
            ? null
            : WrappedKey(alias: alias as String, blob: blob as String),
        at,
        List<String>.unmodifiable(retired.cast<String>()));
  }

  static String encode(bool active, String kid, WrappedKey? w, int at,
          List<String> retired) =>
      jsonEncode(<String, Object?>{
        'v': 1,
        'state': active ? 'active' : 'pending',
        'kid': kid,
        if (w != null) 'alias': w.alias,
        if (w != null) 'wrapped': w.blob,
        'at': at,
        if (retired.isNotEmpty) 'retired': retired,
      });
}

sealed class _L {
  const _L();
}

final class _LAbsent extends _L {
  const _LAbsent();
}

final class _LError extends _L {
  const _LError();
}

final class _LGarbage extends _L {
  const _LGarbage();
}

final class _LValid extends _L {
  const _LValid(this.key);
  final Uint8List key;
}

sealed class _Step {
  const _Step();
}

final class _Done extends _Step {
  const _Done(this.state);
  final MasterKeyState state;
}

final class _Retry extends _Step {
  const _Retry();
}

final class _Wait extends _Step {
  const _Wait();
}

sealed class _Unwrapped {
  const _Unwrapped();
}

final class _UOk extends _Unwrapped {
  const _UOk(this.key);
  final Uint8List key;
}

final class _UMissing extends _Unwrapped {
  const _UMissing();
}

final class _UError extends _Unwrapped {
  const _UError();
}
