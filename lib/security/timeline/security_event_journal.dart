// Phase 13 / Milestones 1–2 — Security Event Database.
//
// Local, encrypted, bounded, versioned journal of security ANOMALIES that
// are not already persisted elsewhere (failed unlocks stay in the Phase 12
// failure log — never duplicated here).
//
// Isolation (corrections A/B): nothing in enforcement imports or awaits
// this class. [record] is synchronous, only enqueues, and never throws;
// every storage operation runs one at a time on the journal's own chain and
// any failure is contained (counted as lost / reported as health).
//
// M2: typed producer events ([SecurityEventFieldSink]), compare-and-append
// health and storage observations, a lazy v1 -> v2 upgrade (no write for
// the migration alone) and per-trigger outcome de-duplication. Bounds are
// applied on every write: age -> health quota -> count -> bytes.
import 'dart:async';
import 'dart:collection';
import 'dart:convert';

import 'security_event_journal_store.dart';
import 'security_journal_event.dart';

/// Producer-facing interface (M2+ producers depend on this, never on the
/// concrete journal).
abstract interface class SecurityEventSink {
  /// Must be synchronous, non-blocking and must never throw.
  void record(SecurityJournalEventType type);
}

/// M2 producer interface for typed events (outcomes). Implemented by the
/// journal; [SecurityEventSink] is unchanged.
abstract interface class SecurityEventFieldSink {
  /// Must be synchronous, non-blocking and must never throw. Invalid or
  /// mismatched input is counted as lost, never stored.
  void recordEvent(SecurityJournalEventType type, SecurityEventFields fields);

  /// Counts events a producer had to drop (bounded scheduling).
  void recordLost(int count);
}

/// The ONLY way producers may call a field sink (see
/// [recordSecurityEventSafely]).
void recordSecurityEventFieldsSafely(
  SecurityEventFieldSink? sink,
  SecurityJournalEventType type,
  SecurityEventFields fields,
) {
  if (sink == null) {
    return;
  }
  try {
    sink.recordEvent(type, fields);
  } catch (_) {
    // Journal failures never affect the producer (correction A).
  }
}

/// The ONLY way producers may call a sink: even a sink that violates its
/// contract and throws synchronously cannot propagate into the caller.
void recordSecurityEventSafely(
  SecurityEventSink? sink,
  SecurityJournalEventType type,
) {
  if (sink == null) {
    return;
  }
  try {
    sink.record(type);
  } catch (_) {
    // Journal failures never affect the producer (correction A).
  }
}

enum SecurityJournalHealth {
  /// Recording normally.
  ok,

  /// The last storage operation failed; the next operation retries.
  storageError,

  /// Newer schema or ciphertext without a cipher: kept untouched, nothing
  /// is written for the process lifetime.
  readOnly,
}

enum SecurityJournalAvailability {
  available,

  /// Written by a newer app version (never overwritten).
  unsupported,

  /// Could not be read now (storage error) or can never be read here.
  unreadable,
}

/// Batch 4: result of a Clear History journal step.
enum HistoryClearJournalResult {
  /// Durably written (or already in the requested state: idempotent).
  committed,

  /// Not written: the journal is read-only/unsupported/unreadable, the
  /// marker is invalid, or (finish) the marker was replaced or is gone.
  refused,

  /// Not written: the owner session ended just before the write.
  cancelled,

  /// The write failed (it may or may not have committed; the next read
  /// shows which — either way the state is consistent).
  failed,
}

/// Read result for the timeline. Never contains raw stored data.
final class SecurityJournalView {
  const SecurityJournalView({
    required this.availability,
    required this.events,
    required this.discarded,
    required this.lost,
    this.suppressed = 0,
  });

  final SecurityJournalAvailability availability;

  /// Oldest first (empty unless [availability] is available).
  final List<SecurityJournalEvent> events;

  /// Removed by retention / caps (persisted, cumulative).
  final int discarded;

  /// Never stored: persisted count plus this session's not-yet-persisted
  /// losses.
  final int lost;

  /// Protection changes not recorded individually (rate window), not yet
  /// attached to a recorded event.
  final int suppressed;
}

class SecurityEventJournal
    implements SecurityEventSink, SecurityEventFieldSink {
  SecurityEventJournal({
    required SecurityEventJournalStore store,
    DateTime Function()? now,
    this.maxEvents = defaultMaxEvents,
    this.retention = defaultRetention,
    this.maxPending = defaultMaxPending,
    this.maxEncodedBytes = defaultMaxEncodedBytes,
    this.maxHealthEvents = defaultMaxHealthEvents,
    this.healthRateWindow = defaultHealthRateWindow,
  })  : _store = store,
        _now = now ?? DateTime.now;

  static const int defaultMaxEvents = 200;
  static const Duration defaultRetention = Duration(days: 30);
  static const int defaultMaxPending = 64;
  static const int defaultMaxEncodedBytes = 64 * 1024;
  static const int defaultMaxHealthEvents = 100;
  static const Duration defaultHealthRateWindow = Duration(minutes: 10);

  final SecurityEventJournalStore _store;
  final DateTime Function() _now;
  final int maxEvents;
  final Duration retention;
  final int maxPending;
  final int maxEncodedBytes;

  /// M2: at most this many `protectionHealth` events are kept.
  final int maxHealthEvents;

  /// M2: at most one health event per state within this window.
  final Duration healthRateWindow;

  final Queue<Future<void> Function()> _queue =
      Queue<Future<void> Function()>();
  final List<Completer<void>> _idleWaiters = <Completer<void>>[];
  int _pending = 0;
  bool _draining = false;

  SecurityJournalDocument? _cache;
  bool _readOnly = false;
  bool _storageError = false;
  bool _quarantined = false;
  int _corruptUnpreserved = 0;
  bool _unsupported = false;

  /// Losses not yet added to the persisted `lost` counter.
  int _pendingLost = 0;

  /// M2 health: whether this process has observed a health report yet,
  /// the in-memory seed used while no journal row exists, and the last
  /// observation (read-only accounting).
  bool _healthObserved = false;
  SecurityJournalHealthMark? _healthSeed;
  SecurityJournalHealthMark? _healthLastSeen;

  SecurityJournalHealth get health => _readOnly
      ? SecurityJournalHealth.readOnly
      : _storageError
          ? SecurityJournalHealth.storageError
          : SecurityJournalHealth.ok;

  /// Whether this instance quarantined a corrupt journal row.
  bool get quarantinedCorruptJournal => _quarantined;

  /// F-KEY-1 G-4: damaged/undecryptable journals NOT replaced because their
  /// exact bytes could not be preserved (occupied quarantine / storage
  /// failure).
  int get corruptUnpreserved => _corruptUnpreserved;

  /// This session's losses not yet persisted.
  int get pendingLost => _pendingLost;

  // -- public API -----------------------------------------------------------

  @override
  void record(SecurityJournalEventType type) {
    try {
      // NF-B1-1 (Batch 1): every v2 event type except the field-less markers
      // REQUIRES typed fields; persisting one without them would write a
      // document this build's own strict decoder rejects, and the next
      // fresh read would quarantine and reinitialize the whole journal.
      // Such input is counted as lost and never stored.
      if (type != SecurityJournalEventType.journalStarted &&
          type != SecurityJournalEventType.journalRecovered) {
        _addLost(1);
        return;
      }
      final DateTime at = _now(); // "detected at" = when it was observed
      if (_pending >= maxPending) {
        _addLost(1);
        return;
      }
      _enqueue(() => _append(type, at));
    } catch (_) {
      _addLost(1);
    }
  }

  /// M2 typed producer events (intruder outcomes). Synchronous, only
  /// enqueues, never throws. Mismatched, invalid or non-producer input and
  /// a full queue are counted as lost.
  @override
  void recordEvent(SecurityJournalEventType type, SecurityEventFields fields) {
    try {
      final DateTime at = _now();
      if (fields.type != type ||
          !fields.isValid ||
          !(type.isOutcome || type == SecurityJournalEventType.alarmStopped)) {
        _addLost(1);
        return;
      }
      _enqueueBounded(() => _appendFields(fields, at));
    } catch (_) {
      _addLost(1);
    }
  }

  @override
  void recordLost(int count) {
    try {
      if (count > 0) _addLost(count);
    } catch (_) {
      // never throws
    }
  }

  /// M2 protection-health observation (compare-and-append in the queue).
  /// [codes] are the non-neutral, non-advisory issue codes. Never throws.
  void recordHealthObservation(HState state, Iterable<HCode> codes) {
    try {
      final SecurityJournalHealthMark obs =
          SecurityJournalHealthMark(state: state, codes: codes, at: _now());
      _enqueueBounded(() => _observeHealth(obs));
    } catch (_) {
      _addLost(1);
    }
  }

  /// M2 storage observation (compare-and-append in the queue). [state]
  /// `ok` may only be passed after a PROVEN successful read. Never throws.
  void recordStorageObservation(StorageSource source, StoreState state) {
    try {
      final DateTime at = _now();
      _enqueueBounded(() => _observeStorage(source, state, at));
    } catch (_) {
      _addLost(1);
    }
  }

  /// Startup maintenance: load, quarantine/reinitialize a corrupt row and
  /// apply retention. QUIET by design: a missing journal is NOT created here
  /// (nothing is written at startup unless integrity or retention requires
  /// it); the row and its start marker are created by the first [record] or
  /// [read]. Never throws.
  Future<void> startup() {
    final Completer<void> done = Completer<void>();
    _enqueue(() async {
      try {
        final SecurityJournalDocument? doc =
            await _ensureLoaded(createIfMissing: false);
        if (doc != null) {
          await _persistBounded(doc);
        }
      } finally {
        done.complete();
      }
    });
    return done.future;
  }

  /// Queue-ordered read for the timeline. Never throws.
  Future<SecurityJournalView> read() {
    final Completer<SecurityJournalView> out = Completer<SecurityJournalView>();
    _enqueue(() async {
      try {
        final SecurityJournalDocument? doc = await _ensureLoaded();
        if (doc == null) {
          out.complete(_unavailable());
          return;
        }
        final SecurityJournalDocument shown = await _persistBounded(doc);
        out.complete(SecurityJournalView(
          availability: SecurityJournalAvailability.available,
          events: shown.events,
          discarded: shown.discarded,
          lost: SecurityJournalDocument.saturatingAdd(shown.lost, _pendingLost),
          suppressed: shown.suppressed,
        ));
      } catch (_) {
        out.complete(_unavailable());
        rethrow;
      }
    });
    return out.future;
  }

  /// Completes when the queue is empty.
  Future<void> idle() {
    if (!_draining && _queue.isEmpty) {
      return Future<void>.value();
    }
    final Completer<void> waiter = Completer<void>();
    _idleWaiters.add(waiter);
    return waiter.future;
  }

  // -- Batch 4: Clear History -----------------------------------------------

  /// Step (a): ONE write that removes every journal event except outcomes
  /// outside [marker]'s cleared set (an outcome of an attempt after the cut)
  /// and appends [marker] (`pending`), replacing any earlier clear marker.
  /// `nextSeq`, `discarded`, `lost`, the health / storage marks and the
  /// suppressed count are kept (integrity disclosures, not history). The row
  /// is re-read first (never written from a cached copy); [stillValid] is
  /// evaluated synchronously immediately before the write. Never throws.
  Future<HistoryClearJournalResult> beginHistoryClear(
    HistoryClearedFields marker, {
    bool Function()? stillValid,
  }) {
    final Completer<HistoryClearJournalResult> out =
        Completer<HistoryClearJournalResult>();
    _enqueue(() async {
      try {
        if (!marker.isValid || !marker.pending) {
          out.complete(HistoryClearJournalResult.refused);
          return;
        }
        _cache = null;
        final SecurityJournalDocument? doc = await _ensureLoaded();
        if (doc == null) {
          out.complete(HistoryClearJournalResult.refused);
          return;
        }
        final SecurityJournalDocument base = _withUpgradeMarker(doc);
        final SecurityJournalDocument next = base.copyWith(
          nextSeq: base.nextSeq + 1,
          events: <SecurityJournalEvent>[
            for (final SecurityJournalEvent e in base.events)
              if (e.type.isOutcome &&
                  !marker.clearsOutcome(e.fields!.tgen, e.fields!.trig!))
                e,
            SecurityJournalEvent(
              seq: base.nextSeq,
              at: _now(),
              type: SecurityJournalEventType.historyCleared,
              fields: marker,
            ),
          ],
        );
        if (stillValid != null && !stillValid()) {
          out.complete(HistoryClearJournalResult.cancelled);
          return;
        }
        await _persistBounded(next);
        out.complete(HistoryClearJournalResult.committed);
      } catch (_) {
        if (!out.isCompleted) out.complete(HistoryClearJournalResult.failed);
        rethrow;
      }
    });
    return out.future;
  }

  /// Step (d): flips the marker with journal seq [markerSeq] to `done` and
  /// removes any outcome of its cleared set that was recorded meanwhile.
  /// Refused when that marker is gone or was replaced by a newer clear.
  /// Idempotent: an already-done marker with nothing to remove is not
  /// rewritten. Never throws.
  Future<HistoryClearJournalResult> completeHistoryClear(
    int markerSeq, {
    bool Function()? stillValid,
  }) {
    final Completer<HistoryClearJournalResult> out =
        Completer<HistoryClearJournalResult>();
    _enqueue(() async {
      try {
        _cache = null;
        final SecurityJournalDocument? doc =
            await _ensureLoaded(createIfMissing: false);
        final SecurityJournalEvent? m = doc?.historyMarker;
        if (doc == null || m == null || m.seq != markerSeq) {
          out.complete(HistoryClearJournalResult.refused);
          return;
        }
        final HistoryClearedFields f = m.fields! as HistoryClearedFields;
        final List<SecurityJournalEvent> events = <SecurityJournalEvent>[
          for (final SecurityJournalEvent e in doc.events)
            if (identical(e, m))
              SecurityJournalEvent(
                  seq: m.seq, at: m.at, type: m.type, fields: f.done())
            else if (!(e.type.isOutcome &&
                f.clearsOutcome(e.fields!.tgen, e.fields!.trig!)))
              e,
        ];
        if (!f.pending && events.length == doc.events.length) {
          out.complete(HistoryClearJournalResult.committed);
          return;
        }
        if (stillValid != null && !stillValid()) {
          out.complete(HistoryClearJournalResult.cancelled);
          return;
        }
        await _persistBounded(doc.copyWith(events: events));
        out.complete(HistoryClearJournalResult.committed);
      } catch (_) {
        if (!out.isCompleted) out.complete(HistoryClearJournalResult.failed);
        rethrow;
      }
    });
    return out.future;
  }

  // -- queue ----------------------------------------------------------------

  /// Bounded enqueue for M2 producers: a full queue counts the event as
  /// lost (the queue never grows beyond [maxPending]).
  void _enqueueBounded(Future<void> Function() op) {
    if (_pending < maxPending) {
      _enqueue(op);
    } else {
      _addLost(1);
    }
  }

  void _enqueue(Future<void> Function() op) {
    _pending++;
    _queue.add(op);
    if (!_draining) {
      unawaited(_drain());
    }
  }

  /// Runs queued operations one at a time, in order. Never throws.
  Future<void> _drain() async {
    _draining = true;
    try {
      while (_queue.isNotEmpty) {
        final Future<void> Function() op = _queue.removeFirst();
        try {
          await op();
        } catch (_) {
          _cache = null;
          _storageError = true;
        } finally {
          _pending--;
        }
      }
    } finally {
      _draining = false;
      final List<Completer<void>> waiters =
          List<Completer<void>>.of(_idleWaiters);
      _idleWaiters.clear();
      for (final Completer<void> w in waiters) {
        w.complete();
      }
    }
  }

  // -- operations -----------------------------------------------------------

  void _addLost(int n) {
    _pendingLost = SecurityJournalDocument.saturatingAdd(_pendingLost, n);
  }

  SecurityJournalView _unavailable() => SecurityJournalView(
        availability: _unsupported
            ? SecurityJournalAvailability.unsupported
            : SecurityJournalAvailability.unreadable,
        events: const <SecurityJournalEvent>[],
        discarded: 0,
        lost: _pendingLost,
      );

  Future<void> _append(SecurityJournalEventType type, DateTime at) async {
    try {
      final SecurityJournalDocument? doc = await _ensureLoaded();
      if (doc == null) {
        _addLost(1); // read-only: can never be stored by this build
        return;
      }
      await _persistBounded(_withEvent(doc, type, null, at));
    } catch (_) {
      _addLost(1);
      rethrow;
    }
  }

  /// Returns [doc] plus one event (adds the upgrade marker first when the
  /// document was migrated from version 1 and is about to be written).
  SecurityJournalDocument _withEvent(
    SecurityJournalDocument doc,
    SecurityJournalEventType type,
    SecurityEventFields? fields,
    DateTime at, {
    SecurityJournalHealthMark? healthMark,
    Map<StorageSource, StoreState>? storage,
    int? suppressed,
  }) {
    final SecurityJournalDocument base = _withUpgradeMarker(doc);
    final bool clockBack = !type.isMarker &&
        base.events.isNotEmpty &&
        at.isBefore(base.events.last.at);
    return base.copyWith(
      nextSeq: base.nextSeq + 1,
      events: <SecurityJournalEvent>[
        ...base.events,
        SecurityJournalEvent(
          seq: base.nextSeq,
          at: at,
          type: type,
          fields: fields,
          clockBack: clockBack,
        ),
      ],
      healthMark: healthMark,
      storage: storage,
      suppressed: suppressed,
    );
  }

  /// Lossless: every event, `seq`, `at` and counter is kept; the marker
  /// takes the next seq. Only called for a write that is needed anyway.
  SecurityJournalDocument _withUpgradeMarker(SecurityJournalDocument doc) {
    if (!doc.needsUpgradeMarker) return doc;
    return doc.copyWith(
      nextSeq: doc.nextSeq + 1,
      from: 1,
      decodedVersion: SecurityJournalDocument.version,
      events: <SecurityJournalEvent>[
        ...doc.events,
        SecurityJournalEvent(
          seq: doc.nextSeq,
          at: _now(),
          type: SecurityJournalEventType.journalUpgraded,
          fields: const JournalUpgradedFields(),
        ),
      ],
    );
  }

  Future<void> _appendFields(SecurityEventFields fields, DateTime at) async {
    try {
      final SecurityJournalDocument? doc = await _ensureLoaded();
      if (doc == null) {
        _addLost(1); // read-only: can never be stored by this build
        return;
      }
      final int? trig = fields.trig;
      final String? family = fields.type.terminalFamily;
      final SecurityEventFields? cleared = doc.historyMarker?.fields;
      if (trig != null &&
          fields.type.isOutcome &&
          cleared is HistoryClearedFields &&
          cleared.clearsOutcome(fields.tgen, trig)) {
        // Batch 4: an outcome of an attempt the owner cleared (it arrived
        // late) is never stored: cleared history never reappears.
        return;
      }
      if (trig != null && family != null) {
        // Batch 3: identity (family, tgen, trig); legacy and generation
        // outcomes never match each other.
        final String id = outcomeIdentity(family, fields.tgen, trig);
        SecurityJournalEvent? prior;
        for (final SecurityJournalEvent e in doc.events) {
          final SecurityEventFields? ef = e.fields;
          final String? efam = e.type.terminalFamily;
          if (efam != null &&
              ef != null &&
              outcomeIdentity(efam, ef.tgen, ef.trig!) == id) {
            prior = e;
            break;
          }
        }
        if (prior != null) {
          // Exact duplicate: already recorded (not stored, not lost).
          // Contradictory terminal outcome for the same trigger: the first
          // recorded outcome stands; the contradiction is never stored and
          // is disclosed as an event that couldn't be recorded.
          if (prior.type != fields.type) _addLost(1);
          return;
        }
      }
      if (fields.type == SecurityJournalEventType.alarmStopped &&
          !_hasUnmatchedAlarmStart(doc)) {
        // A stop is stored only after a recorded, still-unmatched start
        // (its start was never recorded, or was evicted): disclosed as lost.
        _addLost(1);
        return;
      }
      await _persistBounded(_withEvent(doc, fields.type, fields, at));
    } catch (_) {
      _addLost(1);
      rethrow;
    }
  }

  /// True when the newest alarm start/stop event is a start.
  static bool _hasUnmatchedAlarmStart(SecurityJournalDocument doc) {
    for (final SecurityJournalEvent e in doc.events.reversed) {
      if (e.type == SecurityJournalEventType.alarmStarted) return true;
      if (e.type == SecurityJournalEventType.alarmStopped) return false;
    }
    return false;
  }

  /// Existing journal only (null when missing or read-only).
  Future<SecurityJournalDocument?> _loadExisting() {
    return _ensureLoaded(createIfMissing: false);
  }

  Future<void> _observeHealth(SecurityJournalHealthMark obs) async {
    final bool firstInProcess = !_healthObserved;
    _healthObserved = true;
    final SecurityJournalHealthMark? lastSeen = _healthLastSeen;
    _healthLastSeen = obs;
    try {
      SecurityJournalDocument? doc = await _loadExisting();
      if (doc == null) {
        if (_readOnly) {
          if (lastSeen != null && !lastSeen.sameAs(obs.state, obs.codes)) {
            _addLost(1);
          }
          return;
        }
        final SecurityJournalHealthMark? seed = _healthSeed;
        if (firstInProcess || seed == null) {
          _healthSeed = obs; // quiet start: seeded in memory, no write
          return;
        }
        if (seed.sameAs(obs.state, obs.codes)) return;
        doc = await _ensureLoaded();
        if (doc == null) {
          _addLost(1);
          return;
        }
      }
      final SecurityJournalHealthMark? base = doc.healthMark ?? _healthSeed;
      if (base != null && base.sameAs(obs.state, obs.codes)) return;
      if (base == null && obs.state == HState.secure) {
        // No recorded state yet and nothing to report: remembered
        // silently, persisted with the next write that is needed anyway.
        _cache = doc.copyWith(healthMark: obs);
        return;
      }
      final DateTime window = obs.at.subtract(healthRateWindow);
      final bool limited = doc.events.any((SecurityJournalEvent e) =>
          e.type == SecurityJournalEventType.protectionHealth &&
          (e.fields as ProtectionHealthFields?)?.state == obs.state &&
          e.at.isAfter(window) &&
          !e.at.isAfter(obs.at));
      if (limited) {
        await _persistBounded(doc.copyWith(
          healthMark: obs,
          suppressed: SecurityJournalDocument.saturatingAdd(doc.suppressed, 1),
        ));
        return;
      }
      await _persistBounded(_withEvent(
        doc,
        SecurityJournalEventType.protectionHealth,
        ProtectionHealthFields(
          state: obs.state,
          codes: obs.codes,
          first: firstInProcess,
          suppressed: doc.suppressed,
        ),
        obs.at,
        healthMark: obs,
        suppressed: 0,
      ));
    } catch (_) {
      _addLost(1);
      rethrow;
    }
  }

  Future<void> _observeStorage(
    StorageSource source,
    StoreState state,
    DateTime at,
  ) async {
    try {
      if (state == StoreState.ok) {
        // "Restored" only over a recorded non-ok state; never creates the
        // journal and never writes a first-ever ok.
        final SecurityJournalDocument? doc = await _loadExisting();
        final StoreState? current = doc?.storage[source];
        if (doc == null || current == null || current == StoreState.ok) {
          return;
        }
        await _persistBounded(_withEvent(
          doc,
          SecurityJournalEventType.storageRestored,
          StorageRestoredFields(source),
          at,
          storage: <StorageSource, StoreState>{
            ...doc.storage,
            source: StoreState.ok,
          },
        ));
        return;
      }
      final SecurityJournalDocument? doc = await _ensureLoaded();
      if (doc == null) {
        _addLost(1); // read-only: can never be stored by this build
        return;
      }
      if (doc.storage[source] == state) return;
      await _persistBounded(_withEvent(
        doc,
        SecurityJournalEventType.storageUnavailable,
        StorageUnavailableFields(
          source,
          state == StoreState.readOnly ? StoreKind.readOnly : StoreKind.failing,
        ),
        at,
        storage: <StorageSource, StoreState>{...doc.storage, source: state},
      ));
    } catch (_) {
      _addLost(1);
      rethrow;
    }
  }

  /// Loads the journal once (cached). Returns null when read-only, or when
  /// missing and ![createIfMissing]. Throws on a transient storage failure
  /// (nothing is overwritten).
  Future<SecurityJournalDocument?> _ensureLoaded({
    bool createIfMissing = true,
  }) async {
    if (_readOnly) {
      return null;
    }
    final SecurityJournalDocument? cached = _cache;
    if (cached != null) {
      return cached;
    }
    final SecurityJournalRead r = await _store.read();
    switch (r) {
      case SecurityJournalLoaded(:final SecurityJournalDocument document):
        _cache = document;
        _storageError = false;
        return document;
      case SecurityJournalMissing():
        if (!createIfMissing) {
          return null;
        }
        return _initialize(SecurityJournalEventType.journalStarted);
      case SecurityJournalCorrupt(:final String raw):
        // Quarantine FIRST; if that fails, nothing is overwritten.
        // F-KEY-1 owner decision G-4: the bytes may be intact ciphertext
        // under a missing/wrong key. They are replaced only once provably
        // preserved: this call quarantined them, or the slot already holds
        // exactly these bytes. An occupied slot holding other bytes refuses
        // the overwrite (both rows keep their exact bytes); this is reported
        // like a transient storage failure: nothing is claimed persisted.
        if (!await _preserveCorrupt(raw)) {
          _corruptUnpreserved++;
          throw StateError('security journal damaged; not preserved');
        }
        return _initialize(SecurityJournalEventType.journalRecovered);
      case SecurityJournalUnsupported():
        _readOnly = true;
        _unsupported = true;
        return null;
      case SecurityJournalUnreadable(:final bool permanent):
        if (permanent) {
          _readOnly = true;
          return null;
        }
        throw StateError('security journal unreadable');
    }
  }

  Future<bool> _preserveCorrupt(String raw) async {
    try {
      if (await _store.quarantine(raw)) {
        _quarantined = true;
        return true;
      }
      if (await _store.readQuarantine() == raw) {
        _quarantined = true;
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  Future<SecurityJournalDocument> _initialize(
    SecurityJournalEventType marker,
  ) async {
    final SecurityJournalDocument doc = SecurityJournalDocument(
      nextSeq: 1,
      discarded: 0,
      lost: 0,
      events: <SecurityJournalEvent>[
        SecurityJournalEvent(seq: 0, at: _now(), type: marker),
      ],
    );
    return _persistBounded(doc, force: true);
  }

  /// Applies retention + caps, folds in pending losses and writes when
  /// anything changed (or [force]). Returns the stored document. Throws on
  /// write failure (cache dropped by the drain).
  ///
  /// M2: a version-1 document is written as version 2 (with the
  /// `journalUpgraded` marker) only when a write is needed anyway; bounds
  /// are applied in the order age -> health quota -> count -> bytes.
  Future<SecurityJournalDocument> _persistBounded(
    SecurityJournalDocument doc, {
    bool force = false,
  }) async {
    final int committedLost = _pendingLost;
    (SecurityJournalDocument, int) bounded = _bound(doc, committedLost);
    final bool changed =
        force || bounded.$2 > 0 || committedLost > 0 || !identical(doc, _cache);
    if (changed && doc.needsUpgradeMarker) {
      bounded = _bound(_withUpgradeMarker(doc), committedLost);
    }
    final SecurityJournalDocument out = bounded.$1;
    if (changed) {
      await _store.write(out);
      _pendingLost -= committedLost;
    }
    _cache = out;
    _storageError = false;
    return out;
  }

  /// Pure: [doc] with retention and caps applied and [committedLost]
  /// folded in, plus the number of events dropped.
  (SecurityJournalDocument, int) _bound(
    SecurityJournalDocument doc,
    int committedLost,
  ) {
    final List<SecurityJournalEvent> events =
        List<SecurityJournalEvent>.of(doc.events);
    int dropped = 0;
    // Age retention drops only events OLDER than the cutoff. Events stamped
    // in the future (clock moved backwards) are kept, never purged.
    // Batch 4: the clear marker is exempt from age, count and size bounds.
    bool exempt(SecurityJournalEvent e) =>
        e.type == SecurityJournalEventType.historyCleared;
    int oldestBounded() =>
        events.indexWhere((SecurityJournalEvent e) => !exempt(e));
    final DateTime cutoff = _now().subtract(retention);
    final int before = events.length;
    events.removeWhere(
        (SecurityJournalEvent e) => !exempt(e) && e.at.isBefore(cutoff));
    dropped += before - events.length;
    // M2 health quota: the oldest protection-health events go first.
    int health = events
        .where((SecurityJournalEvent e) =>
            e.type == SecurityJournalEventType.protectionHealth)
        .length;
    while (health > maxHealthEvents) {
      events.removeAt(events.indexWhere((SecurityJournalEvent e) =>
          e.type == SecurityJournalEventType.protectionHealth));
      health--;
      dropped++;
    }
    while (events.length > maxEvents && oldestBounded() >= 0) {
      events.removeAt(oldestBounded());
      dropped++;
    }
    SecurityJournalDocument next() => doc.copyWith(
          discarded:
              SecurityJournalDocument.saturatingAdd(doc.discarded, dropped),
          lost: SecurityJournalDocument.saturatingAdd(doc.lost, committedLost),
          events: List<SecurityJournalEvent>.unmodifiable(events),
        );
    SecurityJournalDocument out = next();
    while (oldestBounded() >= 0 &&
        utf8.encode(SecurityEventJournalStore.encode(out)).length >
            maxEncodedBytes) {
      events.removeAt(oldestBounded());
      dropped++;
      out = next();
    }
    return (out, dropped);
  }
}
