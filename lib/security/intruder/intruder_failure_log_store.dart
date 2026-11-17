// Phase 12 / Milestone 1 — Intruder Defense foundation.
//
// Persistence of the failed-attempt log: ONE row in the existing
// LocalDatabase settings table (SQLite in production — a single-row replace
// is atomic), encrypted with the SAME AES-256-GCM SettingsCipher and
// Keystore-backed master key as the security settings. No new store, SDK or
// permission.
//
// P13/M3 Q-ENG-1 (contract A §3): every read variant carries the exact
// durable bytes, and the ONLY write path is a compare-and-set against those
// bytes ([writeIfUnchanged]). There is no blind write: a stale base can
// never overwrite events committed by another monitor or engine.
import 'dart:convert';

import '../../data/storage/local_database.dart';
import '../encryption/settings_cipher.dart';
import 'failed_attempt_event.dart';

/// Outcome of reading the stored log.
sealed class IntruderLogRead {
  const IntruderLogRead();
}

/// Nothing stored yet.
final class IntruderLogMissing extends IntruderLogRead {
  const IntruderLogMissing();
}

/// A valid v1 document.
final class IntruderLogLoaded extends IntruderLogRead {
  const IntruderLogLoaded(this.log, {required this.raw});
  final IntruderFailureLog log;

  /// The exact stored value (the compare-and-set token).
  final String raw;
}

/// Decrypted (or plaintext) but unparsable or schema-invalid, or plaintext
/// where ciphertext belongs. [raw] is the stored value so it can be
/// quarantined before reinitialization. An UNDECRYPTABLE value is never
/// corrupt: it is [IntruderLogUnreadable] (F-KEY-1, Batch 1).
final class IntruderLogCorrupt extends IntruderLogRead {
  const IntruderLogCorrupt(this.raw);
  final String raw;
}

/// Written by a NEWER schema version: must never be overwritten.
final class IntruderLogUnsupported extends IntruderLogRead {
  const IntruderLogUnsupported(this.version, {required this.raw});
  final int version;

  /// The exact stored value. Carried for diagnostics/tests only: an
  /// unsupported row is NEVER a write base (invariant 8).
  final String raw;
}

/// Storage could not be read, the value could not be decrypted (missing,
/// wrong or unreadable master key, or damaged ciphertext), or encrypted data
/// without a cipher: nothing is known, so nothing may be overwritten.
final class IntruderLogUnreadable extends IntruderLogRead {
  const IntruderLogUnreadable({required this.permanent});

  /// True when retrying cannot help (encrypted data, no cipher).
  final bool permanent;
}

class IntruderFailureLogStore {
  IntruderFailureLogStore(this._database, {SettingsCipher? cipher})
      : _cipher = cipher;

  static const String storageKey = 'intruder_failure_log';
  static const String quarantineKey = 'intruder_failure_log.quarantine';
  static const String _encryptedPrefix = 'enc:v1:';

  final LocalDatabase _database;
  final SettingsCipher? _cipher;

  Future<IntruderLogRead> read() async {
    final String? raw;
    try {
      raw = await _database.getSetting(storageKey);
    } catch (_) {
      return const IntruderLogUnreadable(permanent: false);
    }
    if (raw == null) {
      return const IntruderLogMissing();
    }
    final String jsonText;
    if (raw.startsWith(_encryptedPrefix)) {
      final SettingsCipher? cipher = _cipher;
      if (cipher == null) {
        return const IntruderLogUnreadable(permanent: true);
      }
      try {
        jsonText =
            await cipher.decryptString(raw.substring(_encryptedPrefix.length));
      } catch (_) {
        // F-KEY-1 empty-quarantine fix (Batch 1): AES-GCM authenticates, so a
        // decrypt failure (missing/wrong master key, key read error, or
        // damaged ciphertext) cannot be told apart from intact data under
        // an unavailable key. It is UNREADABLE, never corrupt: nothing is
        // quarantined, replaced or reinitialized; the exact bytes stay put
        // and health reports a storage error. Only content that decrypts
        // (key proven by the GCM tag) and still fails to parse is corrupt.
        return const IntruderLogUnreadable(permanent: false);
      }
    } else if (_cipher == null) {
      jsonText = raw; // plaintext is only ever written without a cipher
    } else {
      return IntruderLogCorrupt(raw); // plaintext where ciphertext belongs
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(jsonText);
    } catch (_) {
      return IntruderLogCorrupt(raw);
    }
    final int? declared = IntruderFailureLog.declaredVersion(decoded);
    if (declared != null &&
        declared > IntruderFailureLog.version &&
        decoded is Map &&
        decoded['schema'] == IntruderFailureLog.schema) {
      return IntruderLogUnsupported(declared, raw: raw);
    }
    try {
      return IntruderLogLoaded(IntruderFailureLog.fromJson(decoded), raw: raw);
    } on FormatException {
      return IntruderLogCorrupt(raw);
    }
  }

  /// Serializes [log] exactly as [write] would store it (before encryption);
  /// used for the size bound.
  static String encode(IntruderFailureLog log) => jsonEncode(log.toJson());

  /// Encodes and (when a cipher is configured) encrypts [log] into the
  /// exact value that would be stored.
  Future<String> _seal(IntruderFailureLog log) async {
    final String json = encode(log);
    final SettingsCipher? cipher = _cipher;
    return cipher == null
        ? json
        : '$_encryptedPrefix${await cipher.encryptString(json)}';
  }

  /// Q-ENG-1: replaces the row with [next] ONLY if it still holds exactly
  /// [expectedRaw] (`null` = only if no row exists). One statement; never
  /// retried here. Never throws:
  ///  * [IntruderWriteCommitted]: THIS call changed the row;
  ///  * [IntruderWriteConflict]: the row changed since it was read; nothing
  ///    was written;
  ///  * [IntruderWriteUnknown]: completion could not be confirmed (any
  ///    storage or cipher error). The caller must reconcile by re-reading;
  ///    an unknown is never reported as saved.
  Future<IntruderWriteResult> writeIfUnchanged(
    IntruderFailureLog next, {
    required String? expectedRaw,
  }) async {
    final String stored;
    try {
      stored = await _seal(next);
    } catch (_) {
      return const IntruderWriteUnknown(CasUnknownCode.other);
    }
    if (stored == expectedRaw) {
      // Plaintext only (a cipher nonce makes every value distinct): the
      // durable bytes may already equal [next], but that is NOT confirmed
      // without a read. Never claim a commit this call did not make.
      return IntruderWriteUnknown(CasUnknownCode.other, attemptedRaw: stored);
    }
    try {
      final CasOutcome outcome = await _database.compareAndSetSetting(
        storageKey,
        expected: expectedRaw,
        next: stored,
      );
      return switch (outcome) {
        CasOutcome.committed => IntruderWriteCommitted(stored),
        CasOutcome.conflict => const IntruderWriteConflict(),
      };
    } on CasUnknownOutcome catch (e) {
      return IntruderWriteUnknown(e.code, attemptedRaw: stored);
    } catch (_) {
      return IntruderWriteUnknown(CasUnknownCode.other, attemptedRaw: stored);
    }
  }

  /// Keeps the FIRST corrupt value only (bounded; never overwritten):
  /// insert-if-absent on the quarantine key, so two racing repairers can
  /// never replace each other's copy. Returns true when [raw] was
  /// quarantined by THIS call. Throws on a storage error or an unknown
  /// outcome (callers treat quarantine as best effort).
  Future<bool> quarantineOnce(String raw) async {
    final CasOutcome outcome = await _database.compareAndSetSetting(
      quarantineKey,
      expected: null,
      next: raw,
    );
    return outcome == CasOutcome.committed;
  }

  /// F-KEY-1 G-4: the quarantined bytes, or null when the slot is empty.
  /// Throws on storage failure.
  Future<String?> readQuarantine() => _database.getSetting(quarantineKey);
}

/// Q-ENG-1 (contract A §3): result of [IntruderFailureLogStore
/// .writeIfUnchanged].
sealed class IntruderWriteResult {
  const IntruderWriteResult();
}

/// This call's statement changed the row to [raw].
final class IntruderWriteCommitted extends IntruderWriteResult {
  const IntruderWriteCommitted(this.raw);
  final String raw;
}

/// The row no longer held the expected bytes; nothing was written.
final class IntruderWriteConflict extends IntruderWriteResult {
  const IntruderWriteConflict();
}

/// Completion is not confirmed (fixed [code], never exception text).
/// [attemptedRaw] is the exact value that may or may not have landed
/// (null when the value could not even be produced).
final class IntruderWriteUnknown extends IntruderWriteResult {
  const IntruderWriteUnknown(this.code, {this.attemptedRaw});
  final CasUnknownCode code;
  final String? attemptedRaw;
}
