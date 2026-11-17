// Phase 12 / Milestone 2 — encrypted, bounded, local evidence store.
//
// Layout (existing LocalDatabase settings table — app-private SQLite):
//  * `intruder_evidence_index`        enc JSON {v:1, items:[{seq,at,bytes,pkg}]}
//  * `intruder_evidence_blob_<seq>`   enc base64(JPEG)
// Keys derive ONLY from the integer M1 event seq (no paths, no traversal).
// Write order blob -> index; an orphan blob left by a crash is removed by
// [sweepOrphans]. AES-256-GCM via the Keystore-backed SettingsCipher; a
// cipher is mandatory (no plaintext mode). Metadata segments (EXIF/GPS/
// comments) are stripped before encryption. The M1 log and the credential
// document are never touched.
//
// Phase 12 / Milestone 3 — owner evidence management. The index may carry
// three optional, backward-compatible fields:
//  * `floor` int   — every seq <= floor was cleared by the owner and can
//                    never be saved again (clear-all resurrection guard);
//  * `tomb`  [int] — individually deleted seqs (at most [maxTombstones])
//                    that can never be saved again (delete-vs-late-capture
//                    guard);
//  * `hw`    int   — tombstone compaction high-water mark: every seq <= hw
//                    that is not currently listed is retired. When `tomb`
//                    would exceed its bound, ALL tombstones are folded into
//                    `hw` (never dropped), so no deleted seq is re-opened and
//                    no listed item is affected (listed items are exempt by
//                    definition and may lie below `hw`).
// Retired(s) := s <= floor || s in tomb || (s <= hw && s not listed).
// Deletes are logical-then-physical: the index rewrite is the commit point
// (the item is no longer listed or readable), then the blob row is removed;
// a crash in between leaves an orphan that [sweepOrphans] removes. Rows are
// deleted from SQLite; no secure physical erasure of flash is claimed.
//
// P13/M3 Batch 3 (B2 §3.3/§3.4, B-D2/B-D4) — index version 2:
//  * `intruder_evidence_index`  enc JSON {v:2, nextBid, cur?, items:[...],
//    retired:{legacy?, gens?, superseded?}}. Legacy items keep
//    {seq,at,bytes,pkg} and their `intruder_evidence_blob_<seq>` rows (NOT
//    renamed: no multi-row move, no crash window); generation items are
//    {gen,seq,bid,at,bytes,pkg} with rows `intruder_evidence_blob2_<bid>`.
//    `bid` is evidence-local, monotonic, never reused.
//  * Identity = EID (gen, seq). Retirement is per identity space: the v1
//    floor/tomb/hw rule applies to legacy items only; each generation has
//    its own record; a generation closed by a newer one is `superseded`
//    and late evidence for it is never saved. Bounds: <= 8 generation
//    records, <= 32 superseded generations (oldest evicted first).
//  * Lazy migration: a v1 index is read losslessly and written as v2 only
//    by a write that is needed anyway. An index newer than v2 is
//    unsupported: never written, swept or cleared (invariant 8). An old
//    (v1) build reads a v2 index as unsupported (its `v > schemaVersion`
//    branch), so it never overwrites, sweeps or clears it.
//  * Index writes remain whole-row writes serialized by the in-process
//    lock; CAS for the evidence index needs a separate R8 approval (B2
//    §3.3) and is NOT used here.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import '../../data/storage/local_database.dart';
import '../encryption/settings_cipher.dart';

/// One stored image's metadata (no image bytes, no credential material).
///
/// Batch 3 (B2 §3.3): identity is the failed-attempt EID `(gen, seq)`.
/// A legacy item (v1 era, or recorded for an event without a generation)
/// has `gen == null` and no `bid`; its blob row is keyed by `seq` exactly
/// as before. A generation item carries `gen` and an evidence-local blob id
/// `bid` (never reused) that keys its blob row, so two generations can
/// never share a row.
final class EvidenceItem {
  const EvidenceItem({
    required this.seq,
    required this.at,
    required this.bytes,
    this.packageName,
    this.gen,
    this.bid,
  }) : assert((gen == null) == (bid == null));

  /// The failed-attempt event seq this evidence belongs to.
  final int seq;
  final DateTime at;
  final int bytes;
  final String? packageName;

  /// The failure-log generation of the event (null = legacy).
  final String? gen;

  /// Evidence-local blob id (generation items only).
  final int? bid;

  bool get legacy => gen == null;

  /// True when this item is the evidence for EID `(gen, seq)`. A legacy
  /// identity never equals a generation identity.
  bool isFor(String? gen, int seq) => this.gen == gen && this.seq == seq;

  Map<String, Object?> toJson() => gen == null
      ? <String, Object?>{
          'seq': seq,
          'at': at.millisecondsSinceEpoch,
          'bytes': bytes,
          'pkg': packageName,
        }
      : <String, Object?>{
          'gen': gen,
          'seq': seq,
          'bid': bid,
          'at': at.millisecondsSinceEpoch,
          'bytes': bytes,
          'pkg': packageName,
        };

  static const Set<String> _legacyKeys = <String>{'seq', 'at', 'bytes', 'pkg'};
  static const Set<String> _genKeys = <String>{
    'gen',
    'seq',
    'bid',
    'at',
    'bytes',
    'pkg',
  };

  /// Strict decoder. [v2]: decoding an index of version 2 (generation items
  /// allowed; unknown keys rejected). A version-1 index decodes exactly as
  /// before (generation fields are not part of v1).
  static EvidenceItem fromJson(Object? raw, {bool v2 = false}) {
    if (raw is! Map ||
        raw['seq'] is! int ||
        raw['at'] is! int ||
        raw['bytes'] is! int ||
        (raw['pkg'] != null && raw['pkg'] is! String) ||
        (raw['seq'] as int) < 0 ||
        (raw['bytes'] as int) <= 0) {
      throw const FormatException('evidence item');
    }
    String? gen;
    int? bid;
    if (v2) {
      final bool isGen = raw.containsKey('gen');
      final Set<String> allowed = isGen ? _genKeys : _legacyKeys;
      for (final Object? k in raw.keys) {
        if (k is! String || !allowed.contains(k)) {
          throw const FormatException('evidence item key');
        }
      }
      if (!raw.containsKey('pkg')) {
        throw const FormatException('evidence item key');
      }
      if (isGen) {
        final Object? g = raw['gen'];
        final Object? b = raw['bid'];
        if (!_genValid(g) || b is! int || b < 0) {
          throw const FormatException('evidence item identity');
        }
        gen = g as String;
        bid = b;
      }
    } else if (raw.containsKey('gen') || raw.containsKey('bid')) {
      throw const FormatException('generation item in a v1 index');
    }
    return EvidenceItem(
      seq: raw['seq'] as int,
      at: DateTime.fromMillisecondsSinceEpoch(raw['at'] as int),
      bytes: raw['bytes'] as int,
      packageName: raw['pkg'] as String?,
      gen: gen,
      bid: bid,
    );
  }
}

/// Same rule as `LogGeneration.isValid` (kept local: the evidence store has
/// no dependency on the failure-log code).
final RegExp _genPattern = RegExp(r'^[A-Za-z0-9_-]{22}$');
bool _genValid(Object? v) => v is String && _genPattern.hasMatch(v);

enum EvidenceSaveResult {
  saved,

  /// The caller's `stillValid` check failed at the commit point (owner
  /// success / consent revoked): nothing was written.
  cancelled,
  duplicate,
  invalidImage,
  oversized,
  unsupportedSchema,
  encryptionFailed,
  storageFailed,

  /// Phase 12 / M3: the seq was deleted or cleared by the owner (tombstone
  /// or clear-all floor). Nothing was written — deleted evidence never
  /// comes back.
  superseded,
}

enum EvidenceIndexHealth { ok, unsupported, unreadable }

/// Phase 12 / M3 — outcome of an owner delete.
enum EvidenceDeleteResult {
  deleted,

  /// Not in the index (already deleted, swept or expired). Idempotent.
  notFound,

  /// The caller's `stillValid` check failed at the commit point.
  cancelled,

  /// Written by a newer schema: never overwritten.
  unsupportedSchema,

  /// The index could not be read or rewritten; nothing changed.
  storageFailed,
}

/// Phase 12 / M3 — outcome of an owner clear-all.
enum EvidenceClearResult {
  cleared,
  cancelled,
  unsupportedSchema,
  storageFailed
}

/// Phase 12 / M3 — index summary for the settings screen (no image bytes).
final class EvidenceSummary {
  const EvidenceSummary(this.count, this.totalBytes, this.health);

  final int count;
  final int totalBytes;
  final EvidenceIndexHealth health;
}

/// Phase 12 / M3 owner-retirement record of ONE identity space (the legacy
/// space, or one generation): Retired(s) := s <= floor || s in tomb ||
/// (s <= hw && s not listed in that space).
final class _Retire {
  const _Retire(
      {this.floor = -1, this.tombs = const <int>[], this.highWater = -1});

  static const _Retire none = _Retire();

  final int floor;
  final List<int> tombs;
  final int highWater;

  bool get isEmpty => floor < 0 && tombs.isEmpty && highWater < 0;

  bool retired(int seq, Iterable<int> listed) =>
      seq <= floor ||
      tombs.contains(seq) ||
      (seq <= highWater && !listed.contains(seq));

  Map<String, Object?> toJson() => <String, Object?>{
        if (floor >= 0) 'floor': floor,
        if (tombs.isNotEmpty) 'tomb': tombs,
        if (highWater >= 0) 'hw': highWater,
      };

  /// Decodes the v1 header fields / a v2 retirement record (strict).
  static _Retire fromJson(Map<Object?, Object?> raw, int maxTombstones,
      {bool exact = false}) {
    if (exact) {
      for (final Object? k in raw.keys) {
        if (k != 'floor' && k != 'tomb' && k != 'hw') {
          throw const FormatException('retired key');
        }
      }
    }
    final Object? f = raw['floor'];
    if (f != null && (f is! int || f < -1)) {
      throw const FormatException('floor');
    }
    final Object? t = raw['tomb'];
    if (t != null &&
        (t is! List ||
            t.length > maxTombstones ||
            t.any((Object? e) => e is! int || e < 0))) {
      throw const FormatException('tomb');
    }
    final Object? h = raw['hw'];
    if (h != null && (h is! int || h < -1)) {
      throw const FormatException('hw');
    }
    return _Retire(
      floor: (f as int?) ?? -1,
      tombs: List<int>.unmodifiable(<int>[
        for (final Object? e in (t as List?) ?? const <Object?>[]) e as int,
      ]),
      highWater: (h as int?) ?? -1,
    );
  }
}

/// The decoded evidence index (always held as version 2 in memory; a v1
/// index is migrated losslessly on read and only WRITTEN as v2 by a write
/// that is needed anyway — B2 §4 lazy migration).
final class _Index {
  const _Index(
    this.items,
    this.health, {
    this.legacy = _Retire.none,
    this.gens = const <String, _Retire>{},
    this.superseded = const <String>[],
    this.current,
    this.nextBid = 0,
  });

  final List<EvidenceItem> items;
  final EvidenceIndexHealth health;

  /// v1 semantics; applies ONLY to legacy items (gen == null).
  final _Retire legacy;

  /// Per-generation retirement (bounded: [IntruderEvidenceStore.maxGenRecords]).
  final Map<String, _Retire> gens;

  /// Generations closed by a newer one, oldest first (bounded FIFO:
  /// [IntruderEvidenceStore.maxSuperseded]). A late capture for one of
  /// them is never saved.
  final List<String> superseded;

  /// The newest generation the store has accepted evidence (or a clear) for.
  final String? current;

  /// Next blob id; never decremented, never reused.
  final int nextBid;

  Iterable<int> _listed(String? gen) => items
      .where((EvidenceItem e) => e.gen == gen)
      .map((EvidenceItem e) => e.seq);

  /// True when EID `(gen, seq)` was deleted or cleared by the owner, or its
  /// generation was superseded (B2 §3.4).
  bool retired(String? gen, int seq) {
    if (gen == null) return legacy.retired(seq, _listed(null));
    if (superseded.contains(gen)) return true;
    return (gens[gen] ?? _Retire.none).retired(seq, _listed(gen));
  }

  bool has(String? gen, int seq) =>
      items.any((EvidenceItem e) => e.isFor(gen, seq));

  _Index copyWith({
    List<EvidenceItem>? items,
    _Retire? legacy,
    Map<String, _Retire>? gens,
    List<String>? superseded,
    String? current,
    int? nextBid,
  }) =>
      _Index(
        items ?? this.items,
        health,
        legacy: legacy ?? this.legacy,
        gens: gens ?? this.gens,
        superseded: superseded ?? this.superseded,
        current: current ?? this.current,
        nextBid: nextBid ?? this.nextBid,
      );

  /// [gen] becomes the current generation: the previous current one is
  /// superseded (its record is dropped — superseded dominates it). The
  /// FIFO keeps the newest [maxSuperseded] entries.
  _Index advancedTo(String gen, int maxSuperseded) {
    if (current == gen) return this;
    final String? prev = current;
    if (prev == null) return copyWith(current: gen);
    return copyWith(
      current: gen,
      gens: <String, _Retire>{
        for (final MapEntry<String, _Retire> e in gens.entries)
          if (e.key != prev) e.key: e.value,
      },
      superseded: _push(superseded, <String>[prev], maxSuperseded),
    );
  }

  /// Every listed generation other than the current one is superseded
  /// (used by delete / clear so an item's generation can never come back
  /// as "new" after it was evicted from the FIFO).
  _Index supersedingListed(int maxSuperseded) {
    final List<String> add = <String>[
      for (final EvidenceItem e in items)
        if (e.gen != null && e.gen != current) e.gen!,
    ];
    return add.isEmpty
        ? this
        : copyWith(superseded: _push(superseded, add, maxSuperseded));
  }

  static List<String> _push(List<String> list, List<String> add, int max) {
    final List<String> out = <String>[...list];
    for (final String g in add) {
      if (!out.contains(g)) out.add(g);
    }
    while (out.length > max) {
      out.removeAt(0);
    }
    return List<String>.unmodifiable(out);
  }
}

abstract final class JpegSanitizer {
  static bool looksLikeJpeg(Uint8List b) =>
      b.length >= 4 &&
      b[0] == 0xFF &&
      b[1] == 0xD8 &&
      b[b.length - 2] == 0xFF &&
      b[b.length - 1] == 0xD9;

  /// Returns the image without APPn (n>=1) and COM segments, or null if the
  /// header structure is malformed. Image data after SOS is kept verbatim.
  static Uint8List? strip(Uint8List b) {
    if (!looksLikeJpeg(b)) return null;
    final BytesBuilder out = BytesBuilder(copy: false)..add(<int>[0xFF, 0xD8]);
    int i = 2;
    while (i + 4 <= b.length) {
      if (b[i] != 0xFF) return null;
      final int marker = b[i + 1];
      if (marker == 0xDA) {
        out.add(Uint8List.sublistView(b, i)); // SOS: rest of the file
        return out.takeBytes();
      }
      final int len = (b[i + 2] << 8) | b[i + 3];
      if (len < 2 || i + 2 + len > b.length) return null;
      final bool metadata =
          (marker >= 0xE1 && marker <= 0xEF) || marker == 0xFE;
      if (!metadata) {
        out.add(Uint8List.sublistView(b, i, i + 2 + len));
      }
      i += 2 + len;
    }
    return null; // no SOS
  }
}

class IntruderEvidenceStore {
  IntruderEvidenceStore(
    this._database,
    this._cipher, {
    DateTime Function()? now,
    this.maxImageBytes = defaultMaxImageBytes,
    this.maxItems = defaultMaxItems,
    this.maxTotalBytes = defaultMaxTotalBytes,
    this.retention = defaultRetention,
  }) : _now = now ?? DateTime.now;

  /// Batch 3: version 2 (generation-aware identity). Version 1 is read.
  static const int schemaVersion = 2;
  static const int legacySchemaVersion = 1;
  static const String indexKey = 'intruder_evidence_index';
  static const String quarantineKey = 'intruder_evidence_index.quarantine';
  static const String blobPrefix = 'intruder_evidence_blob_';

  /// Batch 3: generation-item blob rows (`<prefix><bid>`). Not a prefix
  /// match of [blobPrefix] (`blob2_` vs `blob_`), so v1 sweeps never see it.
  static const String blob2Prefix = 'intruder_evidence_blob2_';
  static const String _enc = 'enc:v1:';
  static const int defaultMaxImageBytes = 256 * 1024;
  static const int defaultMaxItems = 10;
  static const int defaultMaxTotalBytes = 2560 * 1024;
  static const Duration defaultRetention = Duration(days: 30);
  static const int maxTombstones = 64;

  /// Batch 3 (B-D4): per-generation retirement records / superseded FIFO.
  static const int maxGenRecords = 8;
  static const int maxSuperseded = 32;

  final LocalDatabase _database;
  final SettingsCipher _cipher;
  final DateTime Function() _now;
  final int maxImageBytes;
  final int maxItems;
  final int maxTotalBytes;
  final Duration retention;

  // Zone-safe FIFO lock (same design as the credential manager's: a held
  // flag plus one Completer per waiter, ownership handed over on release).
  bool _held = false;
  final Queue<Completer<void>> _waiters = Queue<Completer<void>>();

  /// Serializes every store operation (no concurrent index writes).
  /// E-2 (R-P13M3-T1): the exact index bytes the running operation read
  /// (null = absent); every index write is conditional on them. Operations
  /// are serialized in-process, so one field suffices.
  String? _indexRaw;
  bool _lastAttempt = false;

  /// E-2: total attempts per operation (1 + retries on conflict).
  static const int maxCasAttempts = 3;

  /// E-2: operations abandoned after [maxCasAttempts] conflicts.
  int casExhausted = 0;

  Future<T> _serial<T>(Future<T> Function() op) async {
    if (_held) {
      final Completer<void> turn = Completer<void>();
      _waiters.add(turn);
      await turn.future;
    } else {
      _held = true;
    }
    try {
      for (int attempt = 1;; attempt++) {
        _lastAttempt = attempt >= maxCasAttempts;
        try {
          return await op();
        } on _IndexConflict {
          // E-2: another engine changed the index since this operation read
          // it; nothing of ours is listed. Re-run on the fresh index.
        }
      }
    } finally {
      _lastAttempt = false;
      _indexRaw = null;
      if (_waiters.isEmpty) {
        _held = false;
      } else {
        _waiters.removeFirst().complete();
      }
    }
  }

  static String blobKey(int seq) {
    if (seq < 0) throw ArgumentError.value(seq, 'seq');
    return '$blobPrefix$seq';
  }

  /// Batch 3: blob row of a generation item (keyed by its blob id only).
  static String blobKey2(int bid) {
    if (bid < 0) throw ArgumentError.value(bid, 'bid');
    return '$blob2Prefix$bid';
  }

  static String _keyOf(EvidenceItem e) =>
      e.bid == null ? blobKey(e.seq) : blobKey2(e.bid!);

  Future<_Index> _readIndex() async {
    final String? raw;
    try {
      raw = await _database.getSetting(indexKey);
    } catch (_) {
      return const _Index(<EvidenceItem>[], EvidenceIndexHealth.unreadable);
    }
    _indexRaw = raw;
    if (raw == null) {
      return const _Index(<EvidenceItem>[], EvidenceIndexHealth.ok);
    }
    Object? decoded;
    try {
      if (!raw.startsWith(_enc)) throw const FormatException('plaintext');
      decoded =
          jsonDecode(await _cipher.decryptString(raw.substring(_enc.length)));
      if (decoded is Map &&
          decoded['v'] is int &&
          (decoded['v'] as int) > schemaVersion) {
        return const _Index(<EvidenceItem>[], EvidenceIndexHealth.unsupported);
      }
      if (decoded is! Map ||
          (decoded['v'] != schemaVersion &&
              decoded['v'] != legacySchemaVersion) ||
          decoded['items'] is! List) {
        throw const FormatException('index');
      }
      final bool v2 = decoded['v'] == schemaVersion;
      final List<EvidenceItem> items = <EvidenceItem>[
        for (final Object? e in decoded['items'] as List)
          EvidenceItem.fromJson(e, v2: v2),
      ];
      final Set<String> ids = <String>{
        for (final EvidenceItem e in items) '${e.gen}:${e.seq}',
      };
      if (ids.length != items.length) throw const FormatException('dup seq');
      if (!v2) {
        // Version 1 (Phase 12 M2/M3): migrated in memory; every item is
        // legacy and the guard fields become the legacy retirement record.
        final _Retire legacy = _Retire.fromJson(decoded, maxTombstones);
        if (items.any((EvidenceItem e) =>
            e.seq <= legacy.floor || legacy.tombs.contains(e.seq))) {
          throw const FormatException('retired item listed');
        }
        return _Index(items, EvidenceIndexHealth.ok, legacy: legacy);
      }
      return _decodeV2(decoded, items);
    } catch (_) {
      // F-KEY-1 owner decision G-3: an index that cannot be decrypted or
      // decoded is UNREADABLE, never a valid empty index. A decrypt failure
      // may be a missing/wrong master key (bytes intact and recoverable) and
      // is indistinguishable here from genuine damage, so nothing is
      // written, quarantined, removed or swept: the index and every blob
      // keep their exact bytes. All mutating paths (save, delete, clearAll,
      // sweep, retention) already refuse a non-ok index.
      return const _Index(<EvidenceItem>[], EvidenceIndexHealth.unreadable);
    }
  }

  static const Set<String> _v2Keys = <String>{
    'v',
    'items',
    'nextBid',
    'cur',
    'retired',
  };

  /// Strict version-2 decoder (unknown keys are corrupt, never ignored).
  _Index _decodeV2(Map<Object?, Object?> d, List<EvidenceItem> items) {
    for (final Object? k in d.keys) {
      if (k is! String || !_v2Keys.contains(k)) {
        throw const FormatException('index key');
      }
    }
    final Object? nb = d['nextBid'];
    if (nb is! int || nb < 0) throw const FormatException('nextBid');
    final Set<int> bids = <int>{};
    for (final EvidenceItem e in items) {
      if (e.bid != null && (e.bid! >= nb || !bids.add(e.bid!))) {
        throw const FormatException('bid');
      }
    }
    final Object? cur = d['cur'];
    if (d.containsKey('cur') && !_genValid(cur)) {
      throw const FormatException('cur');
    }
    if (cur == null && items.any((EvidenceItem e) => e.gen != null)) {
      throw const FormatException('cur missing');
    }
    final Object? r = d['retired'];
    if (r is! Map) throw const FormatException('retired');
    for (final Object? k in r.keys) {
      if (k != 'legacy' && k != 'gens' && k != 'superseded') {
        throw const FormatException('retired key');
      }
    }
    final Object? lr = r['legacy'] ?? const <String, Object?>{};
    final Object? gr = r['gens'] ?? const <String, Object?>{};
    final Object? sr = r['superseded'] ?? const <Object?>[];
    if (lr is! Map || gr is! Map || sr is! List) {
      throw const FormatException('retired');
    }
    final _Retire legacy = _Retire.fromJson(lr, maxTombstones, exact: true);
    if (gr.length > maxGenRecords) throw const FormatException('gens');
    final Map<String, _Retire> gens = <String, _Retire>{};
    for (final MapEntry<Object?, Object?> e in gr.entries) {
      if (!_genValid(e.key) || e.value is! Map) {
        throw const FormatException('gens');
      }
      gens[e.key! as String] =
          _Retire.fromJson(e.value! as Map, maxTombstones, exact: true);
    }
    if (sr.length > maxSuperseded ||
        sr.any((Object? g) => !_genValid(g)) ||
        sr.toSet().length != sr.length ||
        sr.contains(cur)) {
      throw const FormatException('superseded');
    }
    final _Index idx = _Index(
      List<EvidenceItem>.unmodifiable(items),
      EvidenceIndexHealth.ok,
      legacy: legacy,
      gens: Map<String, _Retire>.unmodifiable(gens),
      superseded: List<String>.unmodifiable(sr.cast<String>()),
      current: cur as String?,
      nextBid: nb,
    );
    // A listed item can never be retired by its OWN space's record (items
    // of a superseded generation stay listed until deleted or expired).
    for (final EvidenceItem e in items) {
      final _Retire own =
          e.gen == null ? legacy : (gens[e.gen] ?? _Retire.none);
      if (e.seq <= own.floor || own.tombs.contains(e.seq)) {
        throw const FormatException('retired item listed');
      }
    }
    return idx;
  }

  /// Always writes version 2 (there is no v1 write path any more).
  Future<void> _writeIndex(_Index idx) async {
    final String enc = await _cipher.encryptString(jsonEncode(<String, Object?>{
      'v': schemaVersion,
      'nextBid': idx.nextBid,
      if (idx.current != null) 'cur': idx.current,
      'items': <Object?>[for (final EvidenceItem e in idx.items) e.toJson()],
      'retired': <String, Object?>{
        if (!idx.legacy.isEmpty) 'legacy': idx.legacy.toJson(),
        if (idx.gens.isNotEmpty)
          'gens': <String, Object?>{
            for (final MapEntry<String, _Retire> e in idx.gens.entries)
              e.key: e.value.toJson(),
          },
        if (idx.superseded.isNotEmpty) 'superseded': idx.superseded,
      },
    }));
    final String next = '$_enc$enc';
    final CasOutcome outcome;
    try {
      outcome = await _database.compareAndSetSetting(indexKey,
          expected: _indexRaw, next: next);
    } catch (_) {
      // Unknown outcome: committed only if a re-read proves it.
      if (await _database.getSetting(indexKey) == next) {
        _indexRaw = next;
        return;
      }
      rethrow;
    }
    if (outcome == CasOutcome.conflict) {
      if (_lastAttempt) {
        casExhausted++;
        throw StateError('evidence index: write contention');
      }
      throw const _IndexConflict();
    }
    _indexRaw = next;
  }

  /// Items currently stored (oldest first). Empty when unreadable.
  Future<List<EvidenceItem>> list() =>
      _serial(() async => (await _readIndex()).items);

  Future<EvidenceIndexHealth> health() =>
      _serial(() async => (await _readIndex()).health);

  /// Whether evidence for EID `(gen, seq)` is listed ([gen] null = legacy).
  Future<bool> contains(int seq, {String? gen}) =>
      _serial(() async => (await _readIndex()).has(gen, seq));

  /// Phase 12 / M3 — items and index health from ONE serialized read.
  Future<(List<EvidenceItem>, EvidenceIndexHealth)> snapshot() =>
      _serial(() async {
        final _Index idx = await _readIndex();
        return (idx.items, idx.health);
      });

  /// Phase 12 / M3 — count / size / health for the settings screen. Never
  /// decrypts an image.
  Future<EvidenceSummary> summary() => _serial(() async {
        final _Index idx = await _readIndex();
        return EvidenceSummary(
          idx.items.length,
          idx.items.fold<int>(0, (int s, EvidenceItem e) => s + e.bytes),
          idx.health,
        );
      });

  /// Decrypts one image. Null when missing, corrupt, unreadable, or not
  /// (any longer) listed in the index — a deleted, cleared or expired item
  /// is never readable even if its row survived a crash. Phase 12 / M3: the
  /// owner evidence viewer calls this inside a verified owner session.
  /// Batch 3: the item is identified by EID `(gen, seq)` exactly.
  Future<Uint8List?> readImage(int seq, {String? gen}) => _serial(() async {
        if (seq < 0) return null;
        try {
          final _Index idx = await _readIndex();
          if (idx.health != EvidenceIndexHealth.ok) return null;
          EvidenceItem? item;
          for (final EvidenceItem e in idx.items) {
            if (e.isFor(gen, seq)) item = e;
          }
          if (item == null) return null;
          final String? raw = await _database.getSetting(_keyOf(item));
          if (raw == null || !raw.startsWith(_enc)) return null;
          final Uint8List bytes = base64Decode(
              await _cipher.decryptString(raw.substring(_enc.length)));
          return JpegSanitizer.looksLikeJpeg(bytes) ? bytes : null;
        } catch (_) {
          return null;
        }
      });

  /// Encrypts and stores [jpeg] as the evidence for failed-attempt EID
  /// `(gen, seq)` ([gen] null = legacy, keyed by seq as in v1).
  ///
  /// Batch 3 (B2 §3.4): [currentGen] is the newest generation the caller
  /// has seen (defaults to [gen]). Evidence for any other generation, or
  /// for a superseded one, is never saved ([EvidenceSaveResult.superseded]).
  ///
  /// [stillValid] is evaluated synchronously inside the serialized write,
  /// immediately before the blob is written (the commit point); when it
  /// returns false nothing is written and [EvidenceSaveResult.cancelled] is
  /// returned.
  Future<EvidenceSaveResult> save({
    required int seq,
    required Uint8List jpeg,
    String? packageName,
    String? gen,
    String? currentGen,
    bool Function()? stillValid,
  }) =>
      _serial(() async {
        if (seq < 0) return EvidenceSaveResult.invalidImage;
        if (gen != null && !_genValid(gen)) {
          return EvidenceSaveResult.invalidImage;
        }
        final Uint8List? clean = JpegSanitizer.strip(jpeg);
        if (clean == null) return EvidenceSaveResult.invalidImage;
        if (clean.length > maxImageBytes) return EvidenceSaveResult.oversized;
        _Index idx = await _readIndex();
        final _Index read = idx;
        if (idx.health == EvidenceIndexHealth.unsupported) {
          return EvidenceSaveResult.unsupportedSchema;
        }
        if (idx.health == EvidenceIndexHealth.unreadable) {
          return EvidenceSaveResult.storageFailed;
        }
        if (idx.has(gen, seq)) {
          return EvidenceSaveResult.duplicate;
        }
        // Phase 12 / M3: deleted / cleared evidence never comes back.
        // Batch 3: neither does evidence for a superseded generation.
        if (idx.retired(gen, seq)) {
          return EvidenceSaveResult.superseded;
        }
        if (gen != null) {
          final String target = currentGen ?? gen;
          if (gen != target || idx.superseded.contains(target)) {
            return EvidenceSaveResult.superseded; // a newer gen exists
          }
          idx = idx.advancedTo(gen, maxSuperseded);
        }
        final String blob;
        try {
          blob = await _cipher.encryptString(base64Encode(clean));
        } catch (_) {
          return EvidenceSaveResult.encryptionFailed;
        }
        final int? bid = gen == null ? null : idx.nextBid;
        final EvidenceItem item = EvidenceItem(
          seq: seq,
          at: _now(),
          bytes: clean.length,
          packageName: packageName,
          gen: gen,
          bid: bid,
        );
        final List<EvidenceItem> next = _bounded(<EvidenceItem>[
          ...idx.items,
          item,
        ]);
        if (stillValid != null && !stillValid()) {
          return EvidenceSaveResult.cancelled;
        }
        final String key = _keyOf(item);
        // E-2: the blob row is inserted only if absent: an existing row (an
        // in-flight save of another engine that picked the same blob id, or
        // a crash orphan) is NEVER overwritten.
        final CasOutcome placed;
        try {
          placed = await _database.compareAndSetSetting(key,
              expected: null, next: '$_enc$blob');
        } catch (_) {
          return EvidenceSaveResult.storageFailed; // nothing removed
        }
        if (placed == CasOutcome.conflict) {
          if (bid == null) return EvidenceSaveResult.storageFailed;
          // Skip the taken blob id (ids are never reused) and retry.
          try {
            await _writeIndex(read.copyWith(nextBid: bid + 1));
          } on _IndexConflict {
            rethrow;
          } catch (_) {
            return EvidenceSaveResult.storageFailed;
          }
          if (_lastAttempt) return EvidenceSaveResult.storageFailed;
          throw const _IndexConflict();
        }
        try {
          await _writeIndex(idx.copyWith(
            items: next,
            nextBid: bid == null ? null : bid + 1,
          ));
        } catch (e) {
          try {
            await _database.removeSetting(key); // our own row (inserted above)
          } catch (_) {}
          if (e is _IndexConflict) rethrow;
          return EvidenceSaveResult.storageFailed;
        }
        final Set<String> kept = next.map(_keyOf).toSet();
        for (final EvidenceItem e in idx.items) {
          if (!kept.contains(_keyOf(e))) {
            try {
              await _database.removeSetting(_keyOf(e));
            } catch (_) {}
          }
        }
        return EvidenceSaveResult.saved;
      });

  /// Age order for eviction: legacy items (by seq) are older than every
  /// generation item; generation items in blob-id (= insertion) order.
  static int _ageOrder(EvidenceItem a, EvidenceItem b) {
    if (a.bid == null && b.bid == null) return a.seq.compareTo(b.seq);
    if (a.bid == null) return -1;
    if (b.bid == null) return 1;
    return a.bid!.compareTo(b.bid!);
  }

  List<EvidenceItem> _bounded(List<EvidenceItem> items) {
    final DateTime cutoff = _now().subtract(retention);
    List<EvidenceItem> kept = items
        .where((EvidenceItem e) => !e.at.isBefore(cutoff)) // future kept
        .toList()
      ..sort(_ageOrder);
    while (kept.length > maxItems ||
        kept.fold<int>(0, (int s, EvidenceItem e) => s + e.bytes) >
            maxTotalBytes) {
      kept = kept.sublist(1);
    }
    return kept;
  }

  /// Removes blobs the index does not reference (crash between blob and
  /// index write) and index entries whose blob is missing. Returns the
  /// number of orphan blobs removed. Never touches a newer-schema index.
  Future<int> sweepOrphans() => _serial(_sweepUnlocked);

  /// Phase 12 / M3 — startup crash recovery then retention as ONE
  /// serialized operation (a single lock acquisition, as in M2).
  Future<void> startupMaintenance() => _serial(() async {
        await _sweepUnlocked();
        await _retentionUnlocked();
      });

  static bool _isBlobKey(String k) =>
      k.startsWith(blobPrefix) || k.startsWith(blob2Prefix);

  Future<int> _sweepUnlocked() async {
    final _Index idx = await _readIndex();
    final List<EvidenceItem> items = idx.items;
    if (idx.health != EvidenceIndexHealth.ok) return 0;
    final Map<String, String> all;
    try {
      all = await _database.getAllSettings();
    } catch (_) {
      return 0;
    }
    final Set<String> referenced = items.map(_keyOf).toSet();
    int removed = 0;
    for (final String k in all.keys) {
      if (_isBlobKey(k) && !referenced.contains(k)) {
        try {
          await _database.removeSetting(k);
          removed++;
        } catch (_) {}
      }
    }
    final List<EvidenceItem> present =
        items.where((EvidenceItem e) => all.containsKey(_keyOf(e))).toList();
    if (present.length != items.length) {
      try {
        await _writeIndex(idx.copyWith(items: present));
      } on _IndexConflict {
        rethrow;
      } catch (_) {}
    }
    return removed;
  }

  // -------------------------------------------------------------------
  // Phase 12 / Milestone 3 — owner evidence management.
  // -------------------------------------------------------------------

  /// Owner delete of the evidence for EID `(gen, seq)` ([gen] null =
  /// legacy item).
  ///
  /// Commit point: the index rewrite that removes the item AND records the
  /// tombstone in the same write — after it, the item is neither listed nor
  /// readable and a late save for the same EID is refused. The blob row is
  /// removed afterwards (a crash leaves an orphan for [sweepOrphans]).
  /// [stillValid] is evaluated synchronously immediately before the commit.
  /// Never touches the M1 log, counters, cooldown or settings.
  Future<EvidenceDeleteResult> delete(int seq,
          {String? gen, bool Function()? stillValid}) =>
      _serial(() async {
        if (seq < 0) return EvidenceDeleteResult.notFound;
        final _Index idx = await _readIndex();
        if (idx.health == EvidenceIndexHealth.unsupported) {
          return EvidenceDeleteResult.unsupportedSchema;
        }
        if (idx.health == EvidenceIndexHealth.unreadable) {
          return EvidenceDeleteResult.storageFailed;
        }
        EvidenceItem? item;
        for (final EvidenceItem e in idx.items) {
          if (e.isFor(gen, seq)) item = e;
        }
        if (item == null) return EvidenceDeleteResult.notFound;
        // A non-current generation is retired as a whole (superseded); the
        // current generation and the legacy space get a tombstone.
        _Index base = idx.supersedingListed(maxSuperseded);
        final _Retire own =
            gen == null ? base.legacy : (base.gens[gen] ?? _Retire.none);
        _Retire? updated;
        if (gen == null || gen == base.current) {
          List<int> tombs = <int>[...own.tombs, seq];
          int highWater = own.highWater;
          if (tombs.length > maxTombstones) {
            // R-M3-6 exact compaction: fold EVERY tombstone into the high-water
            // mark (never drop one). A tombstone is never listed, so it stays
            // retired as "<= hw and not listed"; listed items are exempt.
            for (final int t in tombs) {
              if (t > highWater) highWater = t;
            }
            tombs = <int>[];
          }
          updated = _Retire(
              floor: own.floor,
              tombs: List<int>.unmodifiable(tombs),
              highWater: highWater);
        }
        final List<EvidenceItem> next =
            base.items.where((EvidenceItem e) => !e.isFor(gen, seq)).toList();
        if (gen == null && updated != null) {
          base = base.copyWith(items: next, legacy: updated);
        } else if (updated != null) {
          base = base.copyWith(
              items: next,
              gens: <String, _Retire>{...base.gens, gen!: updated});
        } else {
          base = base.copyWith(items: next);
        }
        if (stillValid != null && !stillValid()) {
          return EvidenceDeleteResult.cancelled;
        }
        try {
          await _writeIndex(base);
        } on _IndexConflict {
          rethrow;
        } catch (_) {
          return EvidenceDeleteResult.storageFailed;
        }
        try {
          await _database.removeSetting(_keyOf(item));
        } catch (_) {
          // Orphan row (ciphertext, unreferenced): removed by sweepOrphans.
        }
        return EvidenceDeleteResult.deleted;
      });

  /// Owner clear-all.
  ///
  /// Commit point: ONE index write with no items. Legacy space:
  /// `floor = max(existing floor, every listed/tombstoned legacy seq, hw)`
  /// (and [floorSeq] when [floorGen] is null — the pre-Batch-3 contract).
  /// Batch 3: [floorGen] / [floorSeq] are the coordinator's current
  /// generation and its highest handled seq; that generation becomes current
  /// and gets the same floor rule, and every other listed generation is
  /// superseded — so a capture already in flight for an earlier failure can
  /// never be saved after the clear. Blob rows are then removed
  /// (best-effort; leftovers are unreferenced and swept).
  Future<EvidenceClearResult> clearAll({
    int floorSeq = -1,
    String? floorGen,
    bool Function()? stillValid,
  }) =>
      _serial(() async {
        _Index idx = await _readIndex();
        if (idx.health == EvidenceIndexHealth.unsupported) {
          return EvidenceClearResult.unsupportedSchema;
        }
        if (idx.health == EvidenceIndexHealth.unreadable) {
          return EvidenceClearResult.storageFailed;
        }
        if (floorGen != null && !_genValid(floorGen)) {
          return EvidenceClearResult.storageFailed;
        }
        if (floorGen != null && !idx.superseded.contains(floorGen)) {
          idx = idx.advancedTo(floorGen, maxSuperseded);
        }
        idx = idx.supersedingListed(maxSuperseded);
        _Retire cleared(_Retire r, String? gen, int extra) {
          int floor = r.floor > extra ? r.floor : extra;
          for (final EvidenceItem e in idx.items) {
            if (e.gen == gen && e.seq > floor) floor = e.seq;
          }
          for (final int t in r.tombs) {
            if (t > floor) floor = t;
          }
          if (r.highWater > floor) floor = r.highWater;
          return _Retire(floor: floor);
        }

        final _Retire legacy =
            cleared(idx.legacy, null, floorGen == null ? floorSeq : -1);
        final String? cur = idx.current;
        final Map<String, _Retire> gens = cur == null
            ? const <String, _Retire>{}
            : <String, _Retire>{
                cur: cleared(idx.gens[cur] ?? _Retire.none, cur,
                    floorGen == cur ? floorSeq : -1),
              };
        if (stillValid != null && !stillValid()) {
          return EvidenceClearResult.cancelled;
        }
        try {
          await _writeIndex(idx.copyWith(
            items: const <EvidenceItem>[],
            legacy: legacy,
            gens: gens,
          ));
        } on _IndexConflict {
          rethrow;
        } catch (_) {
          return EvidenceClearResult.storageFailed;
        }
        await _removeUnreferencedBlobs(const <String>{});
        return EvidenceClearResult.cleared;
      });

  /// Batch 4 (Clear History): the next blob id, read once when the clear
  /// is prepared. Every photo saved after this read has `bid >= ` it. Null
  /// unless the index is readable and supported.
  Future<int?> bidCut() => _serial(() async {
        final _Index idx = await _readIndex();
        return idx.health == EvidenceIndexHealth.ok ? idx.nextBid : null;
      });

  /// Batch 4 (Clear History, history+photos) step (c). Removes ONLY the
  /// photos of the clear's fixed set: every legacy photo; photos of
  /// [cutGen] with `seq < cutSeq`; photos of any other generation with
  /// `bid < bidCut` (saved before the clear). Photos of later attempts are
  /// kept. When [cutGen] is the live generation ([liveGen]) it becomes the
  /// current one and its floor rises to `cutSeq - 1`, so a capture still in
  /// flight for a cleared attempt is never saved afterwards; later attempts
  /// stay savable. Retirement follows the delete rules (legacy floor as in
  /// [clearAll]; every listed non-current generation superseded).
  /// Idempotent: nothing to change means no write. Commit point: one index
  /// write; blob rows are then removed (leftovers are swept).
  Future<EvidenceClearResult> clearHistoryItems({
    required String? cutGen,
    required int cutSeq,
    required int bidCut,
    String? liveGen,
    bool Function()? stillValid,
  }) =>
      _serial(() async {
        _Index idx = await _readIndex();
        if (idx.health == EvidenceIndexHealth.unsupported) {
          return EvidenceClearResult.unsupportedSchema;
        }
        if (idx.health == EvidenceIndexHealth.unreadable) {
          return EvidenceClearResult.storageFailed;
        }
        if ((cutGen != null && !_genValid(cutGen)) ||
            (liveGen != null && !_genValid(liveGen)) ||
            cutSeq < 0 ||
            bidCut < 0) {
          return EvidenceClearResult.storageFailed;
        }
        bool inCleared(EvidenceItem e) {
          if (e.gen == null || e.bid == null) return true;
          if (e.gen == cutGen) return e.seq < cutSeq;
          return e.bid! < bidCut;
        }

        final List<EvidenceItem> removed = idx.items.where(inCleared).toList();
        bool changed = removed.isNotEmpty;
        _Index next =
            removed.isEmpty ? idx : idx.supersedingListed(maxSuperseded);
        if (removed.any((EvidenceItem e) => e.gen == null)) {
          int floor = next.legacy.floor;
          for (final EvidenceItem e in removed) {
            if (e.gen == null && e.seq > floor) floor = e.seq;
          }
          for (final int t in next.legacy.tombs) {
            if (t > floor) floor = t;
          }
          if (next.legacy.highWater > floor) floor = next.legacy.highWater;
          next = next.copyWith(legacy: _Retire(floor: floor));
        }
        if (cutGen != null &&
            liveGen == cutGen &&
            !next.superseded.contains(cutGen)) {
          if (next.current != cutGen) {
            next = next.advancedTo(cutGen, maxSuperseded);
            changed = true;
          }
          final _Retire r = next.gens[cutGen] ?? _Retire.none;
          final int floor = r.floor > cutSeq - 1 ? r.floor : cutSeq - 1;
          if (floor != r.floor) {
            next = next.copyWith(gens: <String, _Retire>{
              ...next.gens,
              cutGen: _Retire(
                floor: floor,
                tombs:
                    List<int>.unmodifiable(r.tombs.where((int t) => t > floor)),
                highWater: r.highWater > floor ? r.highWater : -1,
              ),
            });
            changed = true;
          }
        }
        if (!changed) return EvidenceClearResult.cleared;
        final Set<String> gone = removed.map(_keyOf).toSet();
        next = next.copyWith(
            items: next.items
                .where((EvidenceItem e) => !gone.contains(_keyOf(e)))
                .toList());
        if (stillValid != null && !stillValid()) {
          return EvidenceClearResult.cancelled;
        }
        try {
          await _writeIndex(next);
        } on _IndexConflict {
          rethrow;
        } catch (_) {
          return EvidenceClearResult.storageFailed;
        }
        for (final String k in gone) {
          try {
            await _database.removeSetting(k);
          } catch (_) {
            // Orphan row (ciphertext, unreferenced): removed by sweepOrphans.
          }
        }
        return EvidenceClearResult.cleared;
      });

  /// Removes items older than [retention] (index first, then blobs).
  /// Runs at startup and before every owner list. Returns the number of
  /// items removed. Never touches a newer-schema or unreadable index.
  Future<int> enforceRetention() => _serial(_retentionUnlocked);

  Future<int> _retentionUnlocked() async {
    final _Index idx = await _readIndex();
    if (idx.health != EvidenceIndexHealth.ok) return 0;
    final DateTime cutoff = _now().subtract(retention);
    final List<EvidenceItem> kept =
        idx.items.where((EvidenceItem e) => !e.at.isBefore(cutoff)).toList();
    if (kept.length == idx.items.length) return 0;
    try {
      await _writeIndex(idx.copyWith(items: kept));
    } on _IndexConflict {
      rethrow;
    } catch (_) {
      return 0;
    }
    final Set<String> keptKeys = kept.map(_keyOf).toSet();
    for (final EvidenceItem e in idx.items) {
      if (!keptKeys.contains(_keyOf(e))) {
        try {
          await _database.removeSetting(_keyOf(e));
        } catch (_) {}
      }
    }
    return idx.items.length - kept.length;
  }

  Future<void> _removeUnreferencedBlobs(Set<String> referenced) async {
    final Map<String, String> all;
    try {
      all = await _database.getAllSettings();
    } catch (_) {
      return;
    }
    for (final String k in all.keys) {
      if (_isBlobKey(k) && !referenced.contains(k)) {
        try {
          await _database.removeSetting(k);
        } catch (_) {}
      }
    }
  }
}

/// E-2: the index changed since the running operation read it.
final class _IndexConflict implements Exception {
  const _IndexConflict();
}
