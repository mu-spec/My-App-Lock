// Phase 13 / Milestone 1 — encrypted single-row storage for the security
// event journal. Same database and AES-GCM settings cipher as the security
// settings; mirrors the Phase 12 failure-log store contract.
//
// M2: rows declaring version 1 or 2 are decoded (v1 is upgraded in memory
// only; the store never rewrites a row on read). A row of the journal
// schema declaring a version ABOVE 2 is `unsupported` (read-only for the
// process, never overwritten); any other invalid content — including a
// malformed version-2 row — is corrupt and goes through the M1
// quarantine-first path.
import 'dart:convert';

import '../../data/storage/local_database.dart';
import '../encryption/settings_cipher.dart';
import 'security_journal_event.dart';

sealed class SecurityJournalRead {
  const SecurityJournalRead();
}

final class SecurityJournalMissing extends SecurityJournalRead {
  const SecurityJournalMissing();
}

final class SecurityJournalLoaded extends SecurityJournalRead {
  const SecurityJournalLoaded(this.document);

  final SecurityJournalDocument document;
}

/// Decrypted (or plaintext) but unparsable or schema-invalid, or plaintext
/// where ciphertext belongs. [raw] is kept only so it can be quarantined
/// before reinitialization. An UNDECRYPTABLE value is never corrupt: it is
/// [SecurityJournalUnreadable] (F-KEY-1, Batch 1).
final class SecurityJournalCorrupt extends SecurityJournalRead {
  const SecurityJournalCorrupt(this.raw);

  final String raw;
}

/// Written by a NEWER schema version: must never be overwritten.
final class SecurityJournalUnsupported extends SecurityJournalRead {
  const SecurityJournalUnsupported(this.version);

  final int version;
}

/// Storage could not be read (or ciphertext without a cipher): nothing is
/// known, so nothing may be overwritten.
final class SecurityJournalUnreadable extends SecurityJournalRead {
  const SecurityJournalUnreadable({required this.permanent});

  final bool permanent;
}

class SecurityEventJournalStore {
  SecurityEventJournalStore(this._database, {SettingsCipher? cipher})
      : _cipher = cipher;

  static const String storageKey = 'security_event_journal';
  static const String quarantineKey = 'security_event_journal.quarantine';
  static const String _encryptedPrefix = 'enc:v1:';

  final LocalDatabase _database;
  final SettingsCipher? _cipher;

  Future<SecurityJournalRead> read() async => (await readWithRaw()).$1;

  /// E-2: the decoded row plus the exact stored bytes it was decoded from
  /// (null when missing or not readable): the `expected` value of the next
  /// [writeIfUnchanged].
  Future<(SecurityJournalRead, String?)> readWithRaw() async {
    final String? raw;
    try {
      raw = await _database.getSetting(storageKey);
    } catch (_) {
      return (const SecurityJournalUnreadable(permanent: false), null);
    }
    if (raw == null) {
      return (const SecurityJournalMissing(), null);
    }
    return (await _decode(raw), raw);
  }

  /// Exact stored bytes (throws on storage failure). Used to reconcile an
  /// unknown write outcome.
  Future<String?> readRaw() => _database.getSetting(storageKey);

  Future<SecurityJournalRead> _decode(String raw) async {
    final String jsonText;
    if (raw.startsWith(_encryptedPrefix)) {
      final SettingsCipher? cipher = _cipher;
      if (cipher == null) {
        return const SecurityJournalUnreadable(permanent: true);
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
        return const SecurityJournalUnreadable(permanent: false);
      }
    } else if (_cipher == null) {
      jsonText = raw; // plaintext is only ever written without a cipher
    } else {
      return SecurityJournalCorrupt(raw); // plaintext where ciphertext belongs
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(jsonText);
    } catch (_) {
      return SecurityJournalCorrupt(raw);
    }
    final int? declared = SecurityJournalDocument.declaredVersion(decoded);
    // Newer than this build (above version 5): never decoded, never
    // overwritten.
    if (declared != null &&
        declared > SecurityJournalDocument.newestVersion &&
        decoded is Map &&
        decoded['schema'] == SecurityJournalDocument.schema) {
      return SecurityJournalUnsupported(declared);
    }
    try {
      return SecurityJournalLoaded(SecurityJournalDocument.fromJson(decoded));
    } on FormatException {
      return SecurityJournalCorrupt(raw);
    }
  }

  /// Serialized exactly as [write] stores it (before encryption); used for
  /// the size bound.
  static String encode(SecurityJournalDocument doc) => jsonEncode(doc.toJson());

  Future<String> _seal(SecurityJournalDocument doc) async {
    final String json = encode(doc);
    final SettingsCipher? cipher = _cipher;
    return cipher == null
        ? json
        : '$_encryptedPrefix${await cipher.encryptString(json)}';
  }

  /// E-2 (R-P13M3-T1): writes [doc] only if the row still holds exactly
  /// [expectedRaw] (null = absent). There is no blind write: a second
  /// engine's stale copy can never replace a newer row (e.g. resurrect
  /// history the owner cleared). Never throws:
  ///  * [JournalWriteCommitted]: this call changed the row to `raw`;
  ///  * [JournalWriteConflict]: the row changed since it was read; nothing
  ///    was written;
  ///  * [JournalWriteUnknown]: completion not confirmed; the caller must
  ///    reconcile by re-reading and never report it as saved.
  Future<JournalWriteResult> writeIfUnchanged(
    SecurityJournalDocument doc, {
    required String? expectedRaw,
  }) async {
    final String stored;
    try {
      stored = await _seal(doc);
    } catch (_) {
      return const JournalWriteUnknown(null);
    }
    try {
      final CasOutcome outcome = await _database.compareAndSetSetting(
        storageKey,
        expected: expectedRaw,
        next: stored,
      );
      return switch (outcome) {
        CasOutcome.committed => JournalWriteCommitted(stored),
        CasOutcome.conflict => const JournalWriteConflict(),
      };
    } catch (_) {
      return JournalWriteUnknown(stored);
    }
  }

  /// Keeps the FIRST corrupt value only (bounded; never overwritten).
  /// Returns true when [raw] was quarantined now. Throws on storage failure.
  /// (Unchanged by E-2: the replacement of the corrupt row is itself
  /// conditional on the exact corrupt bytes, so only one engine replaces it.)
  Future<bool> quarantine(String raw) async {
    if (await _database.getSetting(quarantineKey) != null) {
      return false;
    }
    await _database.setSetting(quarantineKey, raw);
    return true;
  }

  /// F-KEY-1 G-4: the quarantined bytes, or null when the slot is empty.
  /// Throws on storage failure.
  Future<String?> readQuarantine() => _database.getSetting(quarantineKey);

  /// Presence of a quarantined (damaged) earlier journal. Throws on storage
  /// failure (the caller reports "integrity unknown").
  Future<bool> hasQuarantine() async =>
      await _database.getSetting(quarantineKey) != null;
}

/// E-2: result of [SecurityEventJournalStore.writeIfUnchanged].
sealed class JournalWriteResult {
  const JournalWriteResult();
}

/// This call's statement changed the row to [raw].
final class JournalWriteCommitted extends JournalWriteResult {
  const JournalWriteCommitted(this.raw);
  final String raw;
}

/// The row no longer held the expected bytes; nothing was written.
final class JournalWriteConflict extends JournalWriteResult {
  const JournalWriteConflict();
}

/// Completion is not confirmed. [attemptedRaw] is the exact value that may
/// or may not have landed (null when it could not even be produced).
final class JournalWriteUnknown extends JournalWriteResult {
  const JournalWriteUnknown(this.attemptedRaw);
  final String? attemptedRaw;
}
