// P13/M3 Batch 3 DOWNGRADE FIXTURE (B-D1 conditions 2/3/7): a verbatim
// copy of the PRE-Batch-3 build's lib/security/timeline/security_event_journal_store.dart
// (tree T3 0ac88c20, blob 1a8be7810a5cb9b94177c05b5c0e89f269ac3793, sha256 1749855a2d1420077093477450d939ff195e71484a2b62f775584eb7ba34f581).
// ONLY the relative import paths were rewritten to package: imports.
// It models the old binary running on upgraded data. Never edit.
// ignore_for_file: type=lint

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

import 'package:smart_app_lock/data/storage/local_database.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher.dart';
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

  Future<SecurityJournalRead> read() async {
    final String? raw;
    try {
      raw = await _database.getSetting(storageKey);
    } catch (_) {
      return const SecurityJournalUnreadable(permanent: false);
    }
    if (raw == null) {
      return const SecurityJournalMissing();
    }
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
    // Newer than this build (version 2): never decoded, never overwritten.
    if (declared != null &&
        declared > SecurityJournalDocument.version &&
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

  /// Throws on failure; the previous row stays intact (single-row replace).
  Future<void> write(SecurityJournalDocument doc) async {
    final String json = encode(doc);
    final SettingsCipher? cipher = _cipher;
    final String stored = cipher == null
        ? json
        : '$_encryptedPrefix${await cipher.encryptString(json)}';
    await _database.setSetting(storageKey, stored);
  }

  /// Keeps the FIRST corrupt value only (bounded; never overwritten).
  /// Returns true when [raw] was quarantined now. Throws on storage failure.
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
