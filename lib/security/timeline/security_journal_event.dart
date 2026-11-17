// Phase 13 / Milestones 1–2 — Security Event Database: record + document.
//
// Pure data and a STRICT codec. Version 1 (M1) is still decoded exactly as
// before and is migrated IN MEMORY to version 2; only a write that is
// needed anyway stores version 2 (lazy, single-row, atomic). Any new event
// type, field or enum value requires a new document version (v3+): an
// older build then reads the newer journal as "unsupported" (read-only,
// never overwritten) instead of "corrupt".
//
// P13/M3 Batch 3 (B2 §3.2) — version 3: an intruder outcome may carry
// `tgen`, the failure-log generation of its attempt (EID = (tgen, trig)).
// De-duplication is per (family, tgen, trig); outcomes without `tgen`
// (v1/v2 era, legacy) keep the (family, trig) rule among themselves and are
// NEVER matched against generation outcomes. `tgen` is forbidden in v1/v2
// documents (a v2 build reads a v3 journal as unsupported, read-only). The
// v2 -> v3 step adds no marker event (journalUpgraded stays `from: 1`).
//
// P13/M3 Batch 4 (Clear History) — version 4 = version 3 plus exactly ONE
// `historyCleared` marker. A journal is written as v4 only while it holds
// that marker (and it always does once cleared: the marker is exempt from
// retention and caps and is only ever replaced); every other journal stays
// v3, so a Batch-3 build is affected only after a clear, and then reads the
// journal as unsupported (read-only, never overwritten), never as corrupt.
//
// P13/M3 Batch 5 (Retention Controls) — version 5 = version 4's content
// rules plus the retention events `retentionChanged {old, new}` and the
// coalesced `historyExpired {n, from, to}` (at most one; exempt from
// retention and caps). A journal is written as v5 only while it holds at
// least one of them (at most one `historyCleared` is still allowed); any
// earlier build reads it as unsupported (read-only, never overwritten).
//
// Privacy (TL-4 / correction F): anomalies only. There is deliberately no
// type for successful unlocks or routine usage, and no field may carry
// credential material, pixels, package names or free-form text. Every
// field is an integer, a boolean or a closed enum (wire name = enum name).

/// Journal event types. Wire names are the enum names.
enum SecurityJournalEventType {
  /// The journal row was created by its FIRST USE (lazy creation): no
  /// journal event was recorded before this time. This is never an install,
  /// upgrade or app-start time and must not be presented as one.
  journalStarted,

  /// A damaged journal row was quarantined and replaced: earlier journal
  /// history may be missing.
  journalRecovered,

  /// M2: the first version-2 write over a version-1 journal.
  journalUpgraded,

  /// M2: an intruder photo was saved for failed attempt `trig`.
  captureSaved,

  /// M2: no intruder photo was saved for failed attempt `trig`.
  captureNotSaved,

  /// M2: the platform reported that the alarm started for `trig`.
  alarmStarted,

  /// M2: the alarm did not start for `trig`.
  alarmNotStarted,

  /// M2: a stop of a playing alarm was requested (no reason is stored).
  alarmStopped,

  /// M2: a protection-health change, detected while the app was open.
  protectionHealth,

  /// M2: failed-unlock history storage was detected as unavailable.
  storageUnavailable,

  /// M2: failed-unlock history could be read again.
  storageRestored,

  /// Batch 4: the owner cleared history (exactly one in a v4 journal;
  /// exempt from age retention and caps; replaced by the next clear).
  historyCleared,

  /// Batch 5: the owner changed the history retention period (v5 only).
  retentionChanged,

  /// Batch 5: events were removed automatically by age retention (one
  /// coalesced marker; v5 only; exempt from age retention and caps).
  historyExpired;

  /// Batch 5: types that require a version-5 document.
  bool get inV5Only => this == retentionChanged || this == historyExpired;

  /// Types a version-1 document may contain.
  bool get inV1 => this == journalStarted || this == journalRecovered;

  /// Journal markers (never flagged `cb`).
  bool get isMarker =>
      this == journalStarted ||
      this == journalRecovered ||
      this == journalUpgraded ||
      this == historyCleared ||
      this == historyExpired;

  /// Intruder-response outcomes (carry `trig`; `(type, trig)` is unique in
  /// a journal — E-5).
  bool get isOutcome =>
      this == captureSaved ||
      this == captureNotSaved ||
      this == alarmStarted ||
      this == alarmNotStarted;

  /// Terminal-outcome family: at most ONE outcome per `(family, trig)` —
  /// a trigger can never hold both captureSaved and captureNotSaved, or
  /// both alarmStarted and alarmNotStarted (stricter than E-5's
  /// `(type, trig)`, which it implies). Null for non-outcomes.
  String? get terminalFamily => switch (this) {
        captureSaved || captureNotSaved => 'capture',
        alarmStarted || alarmNotStarted => 'alarm',
        _ => null,
      };
}

/// Why no photo was saved (closed set; never a platform string).
enum CaptureWhy {
  permission,
  camera,
  timeout,
  busy,
  cancelled,
  duplicate,
  storage,
  encryption,
  image,
  superseded,
  unsupported,
  error,
}

/// Why the alarm did not start (closed set; never a platform string).
enum AlarmWhy {
  alreadyPlaying,
  dnd,
  ringer,
  focusDenied,
  notForeground,
  cancelled,
  error,
}

/// Recorded protection state.
enum HState { secure, attention, offline }

/// The 13 non-advisory protection-health issue codes. Advisory codes are
/// not representable.
enum HCode {
  protectionNotConfigured,
  enforcementNotArmed,
  overlayUnavailable,
  detectionOffline,
  accessibilityUnavailable,
  accessibilityNotRunning,
  usageAccessUnavailable,
  watcherNotRunning,
  shieldNotArmed,
  notificationsDisabled,
  backgroundRestricted,
  signalUnknown,
  healthSnapshotStale,
}

/// Provable storage-unavailability kinds.
enum StoreKind { failing, readOnly }

/// Batch 4: what a Clear History removed (`history+photos` = the owner also
/// chose to delete the intruder photos of the cleared attempts).
enum HistoryClearScope { history, historyPhotos }

/// Batch 4: `pending` until every step of the clear committed (a crash or an
/// ended session leaves it pending: the cleared set stays hidden and the
/// owner is asked to finish), then `done`.
enum HistoryClearState { pending, done }

/// Persisted last-known storage state (`ss`).
enum StoreState { ok, failing, readOnly }

/// Storage whose availability is recorded.
enum StorageSource { failureLog }

/// Largest integer a JSON number keeps exactly (2^53 - 1).
const int securityJournalMaxSafeInt = 0x1fffffffffffff;

/// Largest wall-clock millisecond value a [DateTime] can hold.
const int securityJournalMaxAtMillis = 8640000000000000;

T _enumByName<T extends Enum>(List<T> values, Object? name, String what) {
  if (name is String) {
    for (final T v in values) {
      if (v.name == name) return v;
    }
  }
  throw FormatException('$what unknown');
}

int _intIn(Object? v, int max, String what) {
  if (v is! int || v < 0 || v > max) {
    throw FormatException('$what invalid');
  }
  return v;
}

void _exactKeys(Map<Object?, Object?> raw, Set<String> required,
    [Set<String> optional = const <String>{}]) {
  for (final Object? k in raw.keys) {
    if (k is! String || !(required.contains(k) || optional.contains(k))) {
      throw const FormatException('fields have an unknown key');
    }
  }
  for (final String k in required) {
    if (!raw.containsKey(k)) {
      throw const FormatException('fields miss a key');
    }
  }
}

/// Typed payload (`f`) of an M2 event. Integers, booleans and closed enums
/// only — by construction no string can be stored.
sealed class SecurityEventFields {
  const SecurityEventFields();

  /// The only event type these fields belong to.
  SecurityJournalEventType get type;

  /// The failed-attempt seq the event refers to (outcomes only).
  int? get trig => null;

  /// Batch 3: the failure-log generation of [trig] (v3 outcomes only;
  /// null = legacy outcome).
  String? get tgen => null;

  /// True when every value is in range (producers' input is validated
  /// before it is queued; invalid input is counted as lost).
  bool get isValid;

  Map<String, Object?> toJson();

  /// Strict decoder for `f` of [type] ([present]: whether `f` exists).
  /// [v3]: the document is version 3 (an outcome may carry `tgen`).
  static SecurityEventFields? fromJson(
    SecurityJournalEventType type,
    bool present,
    Object? raw, {
    bool v3 = false,
    bool v4 = false,
    bool v5 = false,
  }) {
    final bool needed = switch (type) {
      SecurityJournalEventType.journalStarted ||
      SecurityJournalEventType.journalRecovered =>
        false,
      _ => true,
    };
    if (!needed) {
      if (present) throw const FormatException('fields forbidden');
      return null;
    }
    if (!present || raw is! Map) {
      throw const FormatException('fields required');
    }
    switch (type) {
      case SecurityJournalEventType.journalStarted:
      case SecurityJournalEventType.journalRecovered:
        throw const FormatException('fields forbidden');
      case SecurityJournalEventType.journalUpgraded:
        _exactKeys(raw, const <String>{'from'});
        if (raw['from'] != 1) throw const FormatException('from invalid');
        return const JournalUpgradedFields();
      case SecurityJournalEventType.captureSaved:
        _exactKeys(raw, const <String>{'trig'}, _tgenKey(v3));
        return CaptureSavedFields(
            _intIn(raw['trig'], securityJournalMaxSafeInt, 'trig'),
            tgen: _tgenOf(raw));
      case SecurityJournalEventType.captureNotSaved:
        _exactKeys(raw, const <String>{'trig', 'why'}, _tgenKey(v3));
        return CaptureNotSavedFields(
          _intIn(raw['trig'], securityJournalMaxSafeInt, 'trig'),
          _enumByName(CaptureWhy.values, raw['why'], 'capture reason'),
          tgen: _tgenOf(raw),
        );
      case SecurityJournalEventType.alarmStarted:
        _exactKeys(raw, const <String>{'trig'}, _tgenKey(v3));
        return AlarmStartedFields(
            _intIn(raw['trig'], securityJournalMaxSafeInt, 'trig'),
            tgen: _tgenOf(raw));
      case SecurityJournalEventType.alarmNotStarted:
        _exactKeys(raw, const <String>{'trig', 'why'}, _tgenKey(v3));
        return AlarmNotStartedFields(
          _intIn(raw['trig'], securityJournalMaxSafeInt, 'trig'),
          _enumByName(AlarmWhy.values, raw['why'], 'alarm reason'),
          tgen: _tgenOf(raw),
        );
      case SecurityJournalEventType.alarmStopped:
        _exactKeys(raw, const <String>{});
        return const AlarmStoppedFields();
      case SecurityJournalEventType.protectionHealth:
        _exactKeys(
            raw, const <String>{'s', 'c', 'first'}, const <String>{'sup'});
        final Object? first = raw['first'];
        if (first is! bool) throw const FormatException('first invalid');
        return ProtectionHealthFields(
          state: _enumByName(HState.values, raw['s'], 'health state'),
          codes: decodeHealthCodes(raw['c']),
          first: first,
          suppressed: raw.containsKey('sup')
              ? _intIn(raw['sup'], SecurityJournalDocument.maxCounter, 'sup')
              : 0,
        );
      case SecurityJournalEventType.storageUnavailable:
        _exactKeys(raw, const <String>{'src', 'kind'});
        return StorageUnavailableFields(
          _enumByName(StorageSource.values, raw['src'], 'storage source'),
          _enumByName(StoreKind.values, raw['kind'], 'storage kind'),
        );
      case SecurityJournalEventType.storageRestored:
        _exactKeys(raw, const <String>{'src'});
        return StorageRestoredFields(
          _enumByName(StorageSource.values, raw['src'], 'storage source'),
        );
      case SecurityJournalEventType.historyCleared:
        if (!v4) throw const FormatException('historyCleared before v4');
        _exactKeys(raw, const <String>{'scope', 'st', 'cut'},
            const <String>{'cg', 'bc'});
        final HistoryClearScope scope =
            _enumByName(HistoryClearScope.values, raw['scope'], 'clear scope');
        final bool photos = scope == HistoryClearScope.historyPhotos;
        if (photos != raw.containsKey('bc')) {
          throw const FormatException('clear bc invalid');
        }
        final Object? cg = raw['cg'];
        if (raw.containsKey('cg') &&
            (cg is! String || !_tgenPattern.hasMatch(cg))) {
          throw const FormatException('clear cg invalid');
        }
        return HistoryClearedFields(
          scope: scope,
          state: _enumByName(HistoryClearState.values, raw['st'], 'clear st'),
          cut: _intIn(raw['cut'], securityJournalMaxSafeInt, 'cut'),
          cutGen: cg as String?,
          bidCut: photos
              ? _intIn(raw['bc'], securityJournalMaxSafeInt, 'bc')
              : null,
        );
      case SecurityJournalEventType.retentionChanged:
        if (!v5) throw const FormatException('retentionChanged before v5');
        _exactKeys(raw, const <String>{'old', 'new'});
        final RetentionChangedFields rc = RetentionChangedFields(
          oldDays: _intIn(raw['old'], 90, 'old'),
          newDays: _intIn(raw['new'], 90, 'new'),
        );
        if (!rc.isValid) throw const FormatException('retention invalid');
        return rc;
      case SecurityJournalEventType.historyExpired:
        if (!v5) throw const FormatException('historyExpired before v5');
        _exactKeys(raw, const <String>{'n', 'from', 'to'});
        final HistoryExpiredFields he = HistoryExpiredFields(
          n: _intIn(raw['n'], SecurityJournalDocument.maxCounter, 'n'),
          from: _intIn(raw['from'], securityJournalMaxAtMillis, 'from'),
          to: _intIn(raw['to'], securityJournalMaxAtMillis, 'to'),
        );
        if (!he.isValid) throw const FormatException('expiry invalid');
        return he;
    }
  }

  /// Canonical order of a code set: by wire name, unique.
  static List<HCode> canonicalCodes(Iterable<HCode> codes) {
    final List<HCode> out = codes.toSet().toList()
      ..sort((HCode a, HCode b) => a.name.compareTo(b.name));
    return List<HCode>.unmodifiable(out);
  }

  /// Strict: a sorted, unique list of known codes (<= 13).
  static List<HCode> decodeHealthCodes(Object? raw) {
    if (raw is! List || raw.length > HCode.values.length) {
      throw const FormatException('health codes invalid');
    }
    final List<HCode> out = <HCode>[];
    String? last;
    for (final Object? item in raw) {
      final HCode c = _enumByName(HCode.values, item, 'health code');
      if (last != null && c.name.compareTo(last) <= 0) {
        throw const FormatException('health codes not sorted/unique');
      }
      last = c.name;
      out.add(c);
    }
    return List<HCode>.unmodifiable(out);
  }
}

bool _trigOk(int trig) => trig >= 0 && trig <= securityJournalMaxSafeInt;

/// Batch 3: same rule as `LogGeneration.isValid` (the timeline layer does
/// not import the intruder code).
final RegExp _tgenPattern = RegExp(r'^[A-Za-z0-9_-]{22}$');
bool _tgenOk(String? g) => g == null || _tgenPattern.hasMatch(g);

Set<String> _tgenKey(bool v3) => v3 ? const <String>{'tgen'} : const <String>{};

String? _tgenOf(Map<Object?, Object?> raw) {
  if (!raw.containsKey('tgen')) return null;
  final Object? g = raw['tgen'];
  if (g is! String || !_tgenPattern.hasMatch(g)) {
    throw const FormatException('tgen invalid');
  }
  return g;
}

/// The outcome's de-duplication identity: (family, tgen, trig). A legacy
/// outcome (tgen null) can never equal a generation outcome.
String outcomeIdentity(String family, String? tgen, int trig) =>
    tgen == null ? 'L:$family:$trig' : 'G:$family:$tgen:$trig';

final class JournalUpgradedFields extends SecurityEventFields {
  const JournalUpgradedFields();

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.journalUpgraded;

  @override
  bool get isValid => true;

  @override
  Map<String, Object?> toJson() => <String, Object?>{'from': 1};
}

/// Batch 5: history retention periods the owner can choose (days).
const Set<int> historyRetentionDays = <int>{7, 30, 90};

/// Batch 5: the owner changed history retention from [oldDays] to
/// [newDays] (effective values; both in [historyRetentionDays]).
final class RetentionChangedFields extends SecurityEventFields {
  const RetentionChangedFields({required this.oldDays, required this.newDays});

  final int oldDays;
  final int newDays;

  @override
  SecurityJournalEventType get type =>
      SecurityJournalEventType.retentionChanged;

  @override
  bool get isValid =>
      historyRetentionDays.contains(oldDays) &&
      historyRetentionDays.contains(newDays) &&
      oldDays != newDays;

  @override
  Map<String, Object?> toJson() =>
      <String, Object?>{'old': oldDays, 'new': newDays};
}

/// Batch 5: [n] events (journal and failed-unlock history together;
/// saturating) were removed by age retention; their times span
/// [[from], [to]] (epoch milliseconds). Coalesced: one marker, widened.
final class HistoryExpiredFields extends SecurityEventFields {
  const HistoryExpiredFields(
      {required this.n, required this.from, required this.to});

  final int n;
  final int from;
  final int to;

  /// This marker with a purge of [count] events spanning [[start], [end]]
  /// folded in (n saturating, range
  /// widened).
  HistoryExpiredFields merge(int count, int start, int end) =>
      HistoryExpiredFields(
        n: SecurityJournalDocument.saturatingAdd(n, count),
        from: start < from ? start : from,
        to: end > to ? end : to,
      );

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.historyExpired;

  @override
  bool get isValid =>
      n >= 1 &&
      n <= SecurityJournalDocument.maxCounter &&
      from >= 0 &&
      from <= to &&
      to <= securityJournalMaxAtMillis;

  @override
  Map<String, Object?> toJson() =>
      <String, Object?>{'n': n, 'from': from, 'to': to};
}

/// Batch 4 (Clear History). The cleared set C is fixed when the marker is
/// written and never re-derived:
///  * failed attempts: those of generation [cutGen] with `seq < cut`
///    (including the legacy attempts kept in that generation's log); with no
///    [cutGen] (no generation-bearing history existed) no attempt;
///  * outcomes: every legacy outcome, and those with `tgen == cutGen` and
///    `trig < cut`;
///  * photos ([bidCut], history+photos only): every legacy photo, those of
///    [cutGen] with `seq < cut`, and those of any other generation saved
///    before the clear (`bid < bidCut`).
/// Anything recorded after the cut (a later seq, a later generation, a later
/// photo id) is never in C: it is never hidden and never deleted.
final class HistoryClearedFields extends SecurityEventFields {
  const HistoryClearedFields({
    required this.scope,
    required this.state,
    required this.cut,
    this.cutGen,
    this.bidCut,
  });

  final HistoryClearScope scope;
  final HistoryClearState state;
  final int cut;
  final String? cutGen;
  final int? bidCut;

  bool get photos => scope == HistoryClearScope.historyPhotos;
  bool get pending => state == HistoryClearState.pending;

  HistoryClearedFields done() => HistoryClearedFields(
      scope: scope,
      state: HistoryClearState.done,
      cut: cut,
      cutGen: cutGen,
      bidCut: bidCut);

  /// Attempt [seq] of a failure log whose generation is [logGen].
  bool clearsAttempt(String? logGen, int seq) =>
      cutGen != null && logGen == cutGen && seq < cut;

  /// Outcome of trigger ([tgen], [trig]).
  bool clearsOutcome(String? tgen, int trig) =>
      tgen == null || (tgen == cutGen && trig < cut);

  /// Photo ([gen], [seq], [bid]); legacy photos have no [gen] / [bid].
  bool clearsPhoto(String? gen, int seq, int? bid) {
    if (!photos) return false;
    if (gen == null || bid == null) return true;
    if (gen == cutGen) return seq < cut;
    return bid < bidCut!;
  }

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.historyCleared;

  @override
  bool get isValid =>
      cut >= 0 &&
      cut <= securityJournalMaxSafeInt &&
      _tgenOk(cutGen) &&
      (photos
          ? bidCut != null &&
              bidCut! >= 0 &&
              bidCut! <= securityJournalMaxSafeInt
          : bidCut == null);

  @override
  Map<String, Object?> toJson() => <String, Object?>{
        'scope': scope.name,
        'st': state.name,
        'cut': cut,
        if (cutGen != null) 'cg': cutGen,
        if (bidCut != null) 'bc': bidCut,
      };
}

final class CaptureSavedFields extends SecurityEventFields {
  const CaptureSavedFields(this.failedSeq, {this.tgen});

  final int failedSeq;

  @override
  final String? tgen;

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.captureSaved;

  @override
  int get trig => failedSeq;

  @override
  bool get isValid => _trigOk(failedSeq) && _tgenOk(tgen);

  @override
  Map<String, Object?> toJson() =>
      <String, Object?>{'trig': failedSeq, if (tgen != null) 'tgen': tgen};
}

final class CaptureNotSavedFields extends SecurityEventFields {
  const CaptureNotSavedFields(this.failedSeq, this.why, {this.tgen});

  @override
  final String? tgen;

  final int failedSeq;
  final CaptureWhy why;

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.captureNotSaved;

  @override
  int get trig => failedSeq;

  @override
  bool get isValid => _trigOk(failedSeq) && _tgenOk(tgen);

  @override
  Map<String, Object?> toJson() => <String, Object?>{
        'trig': failedSeq,
        'why': why.name,
        if (tgen != null) 'tgen': tgen,
      };
}

final class AlarmStartedFields extends SecurityEventFields {
  const AlarmStartedFields(this.failedSeq, {this.tgen});

  final int failedSeq;

  @override
  final String? tgen;

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.alarmStarted;

  @override
  int get trig => failedSeq;

  @override
  bool get isValid => _trigOk(failedSeq) && _tgenOk(tgen);

  @override
  Map<String, Object?> toJson() =>
      <String, Object?>{'trig': failedSeq, if (tgen != null) 'tgen': tgen};
}

final class AlarmNotStartedFields extends SecurityEventFields {
  const AlarmNotStartedFields(this.failedSeq, this.why, {this.tgen});

  @override
  final String? tgen;

  final int failedSeq;
  final AlarmWhy why;

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.alarmNotStarted;

  @override
  int get trig => failedSeq;

  @override
  bool get isValid => _trigOk(failedSeq) && _tgenOk(tgen);

  @override
  Map<String, Object?> toJson() => <String, Object?>{
        'trig': failedSeq,
        'why': why.name,
        if (tgen != null) 'tgen': tgen,
      };
}

final class AlarmStoppedFields extends SecurityEventFields {
  const AlarmStoppedFields();

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.alarmStopped;

  @override
  bool get isValid => true;

  @override
  Map<String, Object?> toJson() => <String, Object?>{};
}

final class ProtectionHealthFields extends SecurityEventFields {
  ProtectionHealthFields({
    required this.state,
    required Iterable<HCode> codes,
    required this.first,
    this.suppressed = 0,
  }) : codes = SecurityEventFields.canonicalCodes(codes);

  final HState state;

  /// Canonical (sorted by wire name, unique, unmodifiable).
  final List<HCode> codes;

  /// First observation in this process and different from the persisted
  /// state: the change happened while the app was not observing.
  final bool first;

  /// Changes suppressed by the rate window before this event.
  final int suppressed;

  @override
  SecurityJournalEventType get type =>
      SecurityJournalEventType.protectionHealth;

  @override
  bool get isValid =>
      suppressed >= 0 && suppressed <= SecurityJournalDocument.maxCounter;

  @override
  Map<String, Object?> toJson() => <String, Object?>{
        's': state.name,
        'c': <String>[for (final HCode c in codes) c.name],
        'first': first,
        if (suppressed > 0) 'sup': suppressed,
      };
}

final class StorageUnavailableFields extends SecurityEventFields {
  const StorageUnavailableFields(this.source, this.kind);

  final StorageSource source;
  final StoreKind kind;

  @override
  SecurityJournalEventType get type =>
      SecurityJournalEventType.storageUnavailable;

  @override
  bool get isValid => true;

  @override
  Map<String, Object?> toJson() =>
      <String, Object?>{'src': source.name, 'kind': kind.name};
}

final class StorageRestoredFields extends SecurityEventFields {
  const StorageRestoredFields(this.source);

  final StorageSource source;

  @override
  SecurityJournalEventType get type => SecurityJournalEventType.storageRestored;

  @override
  bool get isValid => true;

  @override
  Map<String, Object?> toJson() => <String, Object?>{'src': source.name};
}

final class SecurityJournalEvent {
  const SecurityJournalEvent({
    required this.seq,
    required this.at,
    required this.type,
    this.fields,
    this.clockBack = false,
  });

  /// Strictly increasing per journal (tie-break for equal wall times).
  final int seq;

  /// Wall-clock time the app OBSERVED the event ("detected at").
  final DateTime at;

  final SecurityJournalEventType type;

  /// Typed payload (M2 types; null for the M1 markers).
  final SecurityEventFields? fields;

  /// The wall clock was earlier than the previous event's time when this
  /// event was recorded (ordering caveat; the time is never re-stamped).
  final bool clockBack;

  Map<String, Object?> toJson() => <String, Object?>{
        'seq': seq,
        'at': at.millisecondsSinceEpoch,
        'type': type.name,
        if (fields != null) 'f': fields!.toJson(),
        if (clockBack) 'cb': true,
      };

  static const Set<String> _keys = <String>{'seq', 'at', 'type', 'f', 'cb'};

  /// Strict decoder for a document of [version]: throws [FormatException]
  /// on anything unexpected.
  static SecurityJournalEvent fromJson(
    Object? raw, {
    int version = SecurityJournalDocument.version,
  }) {
    if (raw is! Map) {
      throw const FormatException('event is not an object');
    }
    for (final Object? k in raw.keys) {
      if (k is! String || !_keys.contains(k)) {
        throw const FormatException('event has an unknown field');
      }
    }
    final Object? seq = raw['seq'];
    final Object? at = raw['at'];
    final Object? type = raw['type'];
    if (seq is! int || seq < 0 || at is! int || at < 0 || type is! String) {
      throw const FormatException('event field invalid');
    }
    SecurityJournalEventType? t;
    for (final SecurityJournalEventType v in SecurityJournalEventType.values) {
      if (v.name == type) {
        t = v;
        break;
      }
    }
    if (t == null) {
      throw const FormatException('event type unknown');
    }
    if (version == 1) {
      // J-8: a version-1 document cannot contain version-2 content.
      if (!t.inV1 || raw.containsKey('f') || raw.containsKey('cb')) {
        throw const FormatException('version-2 content in a v1 journal');
      }
      return SecurityJournalEvent(
        seq: seq,
        at: DateTime.fromMillisecondsSinceEpoch(at),
        type: t,
      );
    }
    if (seq > securityJournalMaxSafeInt || at > securityJournalMaxAtMillis) {
      throw const FormatException('event field out of range');
    }
    final bool clockBack = raw.containsKey('cb');
    if (clockBack && (raw['cb'] != true || t.isMarker)) {
      throw const FormatException('event cb invalid');
    }
    return SecurityJournalEvent(
      seq: seq,
      at: DateTime.fromMillisecondsSinceEpoch(at),
      type: t,
      fields: SecurityEventFields.fromJson(t, raw.containsKey('f'), raw['f'],
          v3: version >= 3, v4: version >= 4, v5: version >= 5),
      clockBack: clockBack,
    );
  }
}

/// Last recorded (or silently seeded) protection state (`hs`).
final class SecurityJournalHealthMark {
  SecurityJournalHealthMark({
    required this.state,
    required Iterable<HCode> codes,
    required this.at,
  }) : codes = SecurityEventFields.canonicalCodes(codes);

  final HState state;
  final List<HCode> codes;
  final DateTime at;

  /// Same state and same code set (time ignored).
  bool sameAs(HState s, List<HCode> c) {
    if (s != state || c.length != codes.length) return false;
    for (int i = 0; i < c.length; i++) {
      if (c[i] != codes[i]) return false;
    }
    return true;
  }

  Map<String, Object?> toJson() => <String, Object?>{
        's': state.name,
        'c': <String>[for (final HCode c in codes) c.name],
        'at': at.millisecondsSinceEpoch,
      };

  static SecurityJournalHealthMark fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('hs invalid');
    _exactKeys(raw, const <String>{'s', 'c', 'at'});
    return SecurityJournalHealthMark(
      state: _enumByName(HState.values, raw['s'], 'health state'),
      codes: SecurityEventFields.decodeHealthCodes(raw['c']),
      at: DateTime.fromMillisecondsSinceEpoch(
          _intIn(raw['at'], securityJournalMaxAtMillis, 'hs at')),
    );
  }
}

/// The whole journal (one encrypted settings row).
final class SecurityJournalDocument {
  const SecurityJournalDocument({
    required this.nextSeq,
    required this.discarded,
    required this.lost,
    required this.events,
    this.from,
    this.healthMark,
    this.storage = const <StorageSource, StoreState>{},
    this.suppressed = 0,
    this.decodedVersion = version,
  });

  static const String schema = 'sal.security_journal';

  /// Batch 3: version 3 (generation-qualified outcomes). 1 and 2 are read.
  static const int version = 3;

  /// Batch 4: a journal holding the `historyCleared` marker is written (and
  /// only then) as version 4. The highest version this build reads.
  static const int markerVersion = 4;

  /// Batch 5: a journal holding a retention event (`retentionChanged` or
  /// `historyExpired`) is written (and only then) as version 5.
  static const int retentionVersion = 5;

  /// Newest version this build decodes; anything above is unsupported.
  static const int newestVersion = retentionVersion;

  /// Decoder hard limit (well above the retention cap).
  static const int maxDecodableEvents = 1000;

  /// Saturation bound for counters (never overflows).
  static const int maxCounter = 0x7fffffff;

  static const SecurityJournalDocument empty = SecurityJournalDocument(
    nextSeq: 0,
    discarded: 0,
    lost: 0,
    events: <SecurityJournalEvent>[],
  );

  /// Sequence the next event receives.
  final int nextSeq;

  /// Events removed by retention / count cap / size cap (cumulative).
  final int discarded;

  /// Events that could never be stored (queue overflow, failures).
  final int lost;

  /// Oldest first, strictly increasing seq.
  final List<SecurityJournalEvent> events;

  /// 1 when this journal was upgraded from version 1 (J-5).
  final int? from;

  /// Last recorded protection state (`hs`).
  final SecurityJournalHealthMark? healthMark;

  /// Last recorded storage state per source (`ss`).
  final Map<StorageSource, StoreState> storage;

  /// Protection changes suppressed by the rate window and not yet
  /// attached to a recorded event (`sup`).
  final int suppressed;

  /// The stored version this document was decoded from. 1: migrated in
  /// memory only — the next needed write adds `journalUpgraded`.
  final int decodedVersion;

  bool get needsUpgradeMarker => decodedVersion == 1;

  /// Batch 4: the clear marker, if any (at most one).
  SecurityJournalEvent? get historyMarker {
    for (final SecurityJournalEvent e in events) {
      if (e.type == SecurityJournalEventType.historyCleared) return e;
    }
    return null;
  }

  /// Batch 5: the coalesced expiry marker, if any (at most one).
  SecurityJournalEvent? get expiryMarker {
    for (final SecurityJournalEvent e in events) {
      if (e.type == SecurityJournalEventType.historyExpired) return e;
    }
    return null;
  }

  /// The version this document is written as: 5 with a retention event,
  /// else 4 with the clear marker, else 3.
  int get encodedVersion =>
      events.any((SecurityJournalEvent e) => e.type.inV5Only)
          ? retentionVersion
          : historyMarker == null
              ? version
              : markerVersion;

  static int saturatingAdd(int a, int b) {
    final int s = a + b;
    return s > maxCounter || s < 0 ? maxCounter : s;
  }

  SecurityJournalDocument copyWith({
    int? nextSeq,
    int? discarded,
    int? lost,
    List<SecurityJournalEvent>? events,
    int? from,
    SecurityJournalHealthMark? healthMark,
    Map<StorageSource, StoreState>? storage,
    int? suppressed,
    int? decodedVersion,
  }) =>
      SecurityJournalDocument(
        nextSeq: nextSeq ?? this.nextSeq,
        discarded: discarded ?? this.discarded,
        lost: lost ?? this.lost,
        events: events ?? this.events,
        from: from ?? this.from,
        healthMark: healthMark ?? this.healthMark,
        storage: storage ?? this.storage,
        suppressed: suppressed ?? this.suppressed,
        decodedVersion: decodedVersion ?? this.decodedVersion,
      );

  /// Deterministic version-3 encoding (same layout as v2; outcomes may
  /// carry `tgen`): fixed key order; `from`, `hs`,
  /// `ss` and `sup` omitted when absent or zero.
  Map<String, Object?> toJson() => <String, Object?>{
        'schema': schema,
        'v': encodedVersion,
        'nextSeq': nextSeq,
        'discarded': discarded,
        'lost': lost,
        if (from != null) 'from': from,
        if (healthMark != null) 'hs': healthMark!.toJson(),
        if (storage.isNotEmpty)
          'ss': <String, Object?>{
            for (final StorageSource s in StorageSource.values)
              if (storage[s] != null) s.name: storage[s]!.name,
          },
        if (suppressed > 0) 'sup': suppressed,
        'events': <Object?>[
          for (final SecurityJournalEvent e in events) e.toJson(),
        ],
      };

  /// Reads only the declared version (null when absent or not an int).
  static int? declaredVersion(Object? raw) {
    if (raw is Map && raw['v'] is int) {
      return raw['v'] as int;
    }
    return null;
  }

  static const Set<String> _keys = <String>{
    'schema',
    'v',
    'nextSeq',
    'discarded',
    'lost',
    'events',
  };

  static const Set<String> _v2Keys = <String>{
    ..._keys,
    'from',
    'hs',
    'ss',
    'sup',
  };

  /// Strict decoder for versions 1, 2 and 3: throws [FormatException] on
  /// any invalid content. A version-1 document becomes an in-memory current
  /// document (lossless; `from: 1`; [decodedVersion] 1); a version-2
  /// document is read as-is (all its outcomes are legacy).
  static SecurityJournalDocument fromJson(Object? raw) {
    if (raw is! Map) {
      throw const FormatException('journal is not an object');
    }
    final Object? v = raw['v'];
    if (raw['schema'] != schema ||
        (v != 1 &&
            v != 2 &&
            v != version &&
            v != markerVersion &&
            v != retentionVersion)) {
      throw const FormatException('journal schema/version mismatch');
    }
    final int declared = v as int;
    final Set<String> allowed = declared == 1 ? _keys : _v2Keys;
    for (final Object? k in raw.keys) {
      if (k is! String || !allowed.contains(k)) {
        throw const FormatException('journal has an unknown field');
      }
    }
    final Object? nextSeq = raw['nextSeq'];
    final Object? discarded = raw['discarded'];
    final Object? lost = raw['lost'];
    final Object? list = raw['events'];
    if (nextSeq is! int ||
        nextSeq < 0 ||
        discarded is! int ||
        discarded < 0 ||
        discarded > maxCounter ||
        lost is! int ||
        lost < 0 ||
        lost > maxCounter ||
        list is! List ||
        list.length > maxDecodableEvents) {
      throw const FormatException('journal header invalid');
    }
    if (declared >= 2 && nextSeq > maxCounter) {
      throw const FormatException('journal header invalid');
    }
    final List<SecurityJournalEvent> events = <SecurityJournalEvent>[];
    final Set<String> outcomes = <String>{};
    int upgraded = 0;
    int markers = 0;
    int retentionEvents = 0;
    int expiries = 0;
    int lastSeq = -1;
    for (final Object? item in list) {
      final SecurityJournalEvent e =
          SecurityJournalEvent.fromJson(item, version: declared);
      if (e.seq <= lastSeq || e.seq >= nextSeq) {
        throw const FormatException('journal sequence invalid');
      }
      lastSeq = e.seq;
      if (e.type.isOutcome &&
          !outcomes.add(outcomeIdentity(
              e.type.terminalFamily!, e.fields!.tgen, e.fields!.trig!))) {
        throw const FormatException('duplicate outcome for a trigger');
      }
      if (e.type == SecurityJournalEventType.journalUpgraded) upgraded++;
      if (e.type == SecurityJournalEventType.historyCleared) markers++;
      if (e.type.inV5Only) retentionEvents++;
      if (e.type == SecurityJournalEventType.historyExpired) expiries++;
      events.add(e);
    }
    if (declared == 1) {
      return SecurityJournalDocument(
        nextSeq: nextSeq,
        discarded: discarded,
        lost: lost,
        events: List<SecurityJournalEvent>.unmodifiable(events),
        from: 1,
        decodedVersion: 1,
      );
    }
    final Object? from = raw['from'];
    if (raw.containsKey('from') && from != 1) {
      throw const FormatException('journal from invalid');
    }
    if (upgraded > 1 || (upgraded == 1 && from != 1)) {
      throw const FormatException('journal upgrade marker invalid');
    }
    // Batch 4: v4 <=> exactly one clear marker (canonical).
    // Batch 5: v5 <=> at least one retention event (canonical); at most one
    // clear marker and at most one expiry marker.
    if (markers > 1 || expiries > 1) {
      throw const FormatException('journal marker duplicated');
    }
    if (declared == retentionVersion) {
      if (retentionEvents == 0) {
        throw const FormatException('journal v5 without retention event');
      }
    } else if ((declared == markerVersion) != (markers == 1)) {
      throw const FormatException('journal clear marker invalid');
    }
    final Map<StorageSource, StoreState> storage =
        <StorageSource, StoreState>{};
    if (raw.containsKey('ss')) {
      final Object? ss = raw['ss'];
      if (ss is! Map) throw const FormatException('ss invalid');
      _exactKeys(ss, const <String>{}, <String>{
        for (final StorageSource s in StorageSource.values) s.name,
      });
      for (final StorageSource s in StorageSource.values) {
        if (ss.containsKey(s.name)) {
          storage[s] = _enumByName(StoreState.values, ss[s.name], 'ss value');
        }
      }
    }
    return SecurityJournalDocument(
      nextSeq: nextSeq,
      discarded: discarded,
      lost: lost,
      events: List<SecurityJournalEvent>.unmodifiable(events),
      from: from as int?,
      healthMark: raw.containsKey('hs')
          ? SecurityJournalHealthMark.fromJson(raw['hs'])
          : null,
      storage: Map<StorageSource, StoreState>.unmodifiable(storage),
      suppressed:
          raw.containsKey('sup') ? _intIn(raw['sup'], maxCounter, 'sup') : 0,
      decodedVersion: declared,
    );
  }
}
