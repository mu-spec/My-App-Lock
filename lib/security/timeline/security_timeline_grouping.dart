// Phase 13 / Milestone 2 — pure presentation grouping for the timeline.
//
// No I/O, no clock, no state: the same snapshot entries always produce the
// same rows. The read model stays one entry per source event; this file
// only decides how they are SHOWN.
//
// Failed-unlock groups (sealed design §5.1–5.2): a maximal run of
// failure-log events, in seq order, where each next event has
// `seq == prev.seq + 1`, `run == prev.run + 1`, `at - prev.at <= 15 min`
// and `at >= prev.at` (a backwards clock splits). The attempt count of a
// group is ALWAYS its number of rows, never the `run` field.
//
// Outcome attachment (gate R2 §4.2): a journal outcome whose `trig` is the
// seq of an attempt in a group is rendered inside that group and nowhere
// else; otherwise it is a standalone row. Every entry appears in exactly
// one row (property tests G-P1 / R-P2).
//
// F-CL-1 association guard (owner-approved Option A, partial): `trig` is a
// failure-log seq, and a corrupt/missing failure log restarts at seq 0
// while the journal survives, so an old outcome can name a NEW attempt
// with a reused seq. An outcome is therefore attached only when
// `attempt.at <= outcome.at <= attempt.at + maxOutcomeDelay`; otherwise it
// is shown as a standalone (detached) row. Never fabricated: no other
// attempt is searched. A clock rollback or forward jump between attempt and
// outcome fails safe (detached). This does NOT change journal identity or
// deduplication (duplicate suppression across reused seqs is unchanged).
//
// P13/M3 Batch 3 (B2 §3.2): a generation outcome (`tgen` set) attaches ONLY
// to the attempt with the exactly equal EID (logGen == tgen, seq == trig);
// the 5-minute window is not used for it. A legacy outcome (no `tgen`)
// attaches only to a legacy attempt (no generation) and keeps the F-CL-1
// window, detached text and photo-action rule unchanged.
//
// F-CL-1 metadata safety (2026-10-22 decision): a timeline photo action
// (a focusSeq lookup in the evidence viewer) is offered ONLY when the
// attempt identity of the outcome is unambiguous — see
// [timelinePhotoActionAllowed]. Detached outcomes and every outcome shown
// while the failed-attempt history was recovered (or its recovery state is
// unknown) get no photo action; the verified Intruder photos list stays the
// independent way to see saved photos.
import 'security_timeline.dart';

/// Grouping parameters (owner-reviewable, Q-M2-10).
abstract final class SecurityTimelineGrouping {
  static const Duration maxGap = Duration(minutes: 15);

  /// Newest attempt rows shown inline under a group header.
  static const int maxInlineAttempts = 3;

  /// F-CL-1: latest an outcome may be stamped after its attempt and still
  /// be attached. The coordinator reports every trig-bearing outcome
  /// within seconds of the attempt (capture timeout 12 s + store write;
  /// alarm start/not-started right after `startAlarm`, alarm 30 s); 5 min
  /// is a generous bound well below the 15-min grouping gap.
  static const Duration maxOutcomeDelay = Duration(minutes: 5);
}

/// One rendered timeline row.
sealed class TimelineRow {
  const TimelineRow();

  /// Source entries this row consumes from the page budget.
  int get size;

  /// The entry that positions the row in the M1 total order.
  TimelineEntry get anchor;
}

/// A single source entry rendered on its own.
final class TimelineEntryRow extends TimelineRow {
  const TimelineEntryRow(this.entry);

  final TimelineEntry entry;

  /// An intruder outcome whose failed attempt is not in the shown history.
  bool get detachedOutcome => entry.trig != null;

  @override
  int get size => 1;

  @override
  TimelineEntry get anchor => entry;
}

/// A run of failed attempts plus the outcomes attached to them.
final class TimelineFailureGroup extends TimelineRow {
  TimelineFailureGroup._(
      List<TimelineEntry> attempts, List<TimelineEntry> outcomes)
      : attempts = List<TimelineEntry>.unmodifiable(attempts),
        outcomes = List<TimelineEntry>.unmodifiable(outcomes);

  /// Newest first (highest seq first). Never empty.
  final List<TimelineEntry> attempts;

  /// Attached outcomes in journal order (oldest first).
  final List<TimelineEntry> outcomes;

  /// Number of failed attempts: always the row count (never `run`).
  int get count => attempts.length;

  int get lastSeq => attempts.first.sourceSeq;
  int get firstSeq => attempts.last.sourceSeq;
  DateTime get firstAt => attempts.last.at;
  DateTime get lastAt => attempts.first.at;

  /// Some attempt's counter write had failed (`persisted=false`).
  bool get counterNotSaved => attempts.any((TimelineEntry e) => !e.persisted);

  int get lockouts =>
      attempts.where((TimelineEntry e) => e.lockoutTriggered).length;

  /// Distinct protected-app packages (null = Smart App Lock itself), in
  /// newest-first order of appearance.
  List<String?> get packages {
    final List<String?> out = <String?>[];
    for (final TimelineEntry e in attempts) {
      // `packageName` is set for the protected-app challenge surface only.
      final String? p = e.packageName;
      if (!out.contains(p)) out.add(p);
    }
    return List<String?>.unmodifiable(out);
  }

  bool has(TimelineEntryKind k) =>
      outcomes.any((TimelineEntry e) => e.kind == k);

  @override
  int get size => attempts.length + outcomes.length;

  @override
  TimelineEntry get anchor => attempts.first;
}

/// F-CL-1 metadata safety: the failed-attempt source's recovery state in
/// [snapshot] — false only when that history is known undamaged (no
/// failure-log quarantine/reinitialization, so its seqs were never reused);
/// true when recovered; null when unknown or the source is missing.
bool? failureLogDamagedEarlier(SecurityTimelineSnapshot snapshot) {
  for (final TimelineSourceStatus s in snapshot.sources) {
    if (s.source == TimelineSource.failedAttempts) return s.damagedEarlier;
  }
  return null;
}

/// F-CL-1 metadata safety: whether the timeline may offer a photo action
/// (focusSeq = `outcome.trig`) for [outcome] shown in [row]. True ONLY for
/// a captureSaved outcome ATTACHED to its attempt group (never a detached
/// row) while the failed-attempt history is known undamaged
/// ([failureLogDamaged] == false). Otherwise the seq may name a different
/// attempt's photo, so no lookup is offered (fail closed).
bool timelinePhotoActionAllowed(
  TimelineRow row,
  TimelineEntry outcome, {
  required bool? failureLogDamaged,
}) {
  if (failureLogDamaged != false) return false;
  if (outcome.kind != TimelineEntryKind.captureSaved) return false;
  if (outcome.trig == null || row is! TimelineFailureGroup) return false;
  return row.outcomes.any((TimelineEntry o) => identical(o, outcome));
}

/// F-CL-1: whether [outcome] may be attached to [attempt] (the failure-log
/// entry whose seq equals `outcome.trig`). Never throws; null ⇒ false.
bool outcomeMatchesAttempt(TimelineEntry? attempt, TimelineEntry outcome) {
  if (attempt == null) return false;
  if (outcome.trig != attempt.sourceSeq) return false;
  // Batch 3: identity spaces never mix (legacy vs generation).
  if (outcome.tgen != attempt.logGen) return false;
  if (outcome.tgen != null) return true; // exact EID: no time window
  if (outcome.at.isBefore(attempt.at)) return false; // older: other epoch
  return outcome.at.difference(attempt.at) <=
      SecurityTimelineGrouping.maxOutcomeDelay;
}

bool _continues(TimelineEntry prev, TimelineEntry next) {
  final int? pr = prev.consecutiveFailures;
  final int? nr = next.consecutiveFailures;
  if (next.sourceSeq != prev.sourceSeq + 1) return false;
  // Batch 3: a run never spans identity spaces (legacy events retained from
  // a v1 log vs events of the log generation).
  if (next.logGen != prev.logGen) return false;
  if (pr == null || nr == null || nr != pr + 1) return false;
  if (next.at.isBefore(prev.at)) return false; // backwards clock splits
  return next.at.difference(prev.at) <= SecurityTimelineGrouping.maxGap;
}

/// Groups failure-log entries (any order in; groups out, each oldest seq
/// first internally, list ordered by first seq).
List<List<TimelineEntry>> groupFailedAttempts(
    Iterable<TimelineEntry> failures) {
  final List<TimelineEntry> bySeq = failures
      .where((TimelineEntry e) => e.source == TimelineSource.failedAttempts)
      .toList()
    ..sort((TimelineEntry a, TimelineEntry b) =>
        a.sourceSeq.compareTo(b.sourceSeq));
  final List<List<TimelineEntry>> groups = <List<TimelineEntry>>[];
  for (final TimelineEntry e in bySeq) {
    if (groups.isNotEmpty && _continues(groups.last.last, e)) {
      groups.last.add(e);
    } else {
      groups.add(<TimelineEntry>[e]);
    }
  }
  return groups;
}

/// Builds the rendered rows for [entries] (newest first, M1 total order).
/// Every entry is in exactly one row.
List<TimelineRow> buildTimelineRows(List<TimelineEntry> entries) {
  final List<List<TimelineEntry>> groups = groupFailedAttempts(entries);
  final Map<int, int> groupOfSeq = <int, int>{};
  final Map<int, TimelineEntry> attemptOfSeq = <int, TimelineEntry>{};
  for (int g = 0; g < groups.length; g++) {
    for (final TimelineEntry e in groups[g]) {
      groupOfSeq[e.sourceSeq] = g;
      attemptOfSeq[e.sourceSeq] = e;
    }
  }
  final List<List<TimelineEntry>> attached = List<List<TimelineEntry>>.generate(
      groups.length, (_) => <TimelineEntry>[]);
  final List<TimelineRow> rows = <TimelineRow>[];
  for (final TimelineEntry e in entries) {
    if (e.source != TimelineSource.journal) continue;
    final int? trig = e.trig;
    final int? g = trig == null || !outcomeMatchesAttempt(attemptOfSeq[trig], e)
        ? null
        : groupOfSeq[trig];
    if (g != null) {
      attached[g].add(e);
    } else {
      rows.add(TimelineEntryRow(e));
    }
  }
  for (int g = 0; g < groups.length; g++) {
    final List<TimelineEntry> outs = attached[g]
      ..sort((TimelineEntry a, TimelineEntry b) =>
          a.sourceSeq.compareTo(b.sourceSeq));
    rows.add(TimelineFailureGroup._(groups[g].reversed.toList(), outs));
  }
  rows.sort((TimelineRow a, TimelineRow b) =>
      SecurityTimelineReader.compare(a.anchor, b.anchor));
  return List<TimelineRow>.unmodifiable(rows);
}

/// Number of leading [rows] shown for a page budget of [visible] source
/// entries: a row is shown while the entries consumed BEFORE it are below
/// the budget (a group always consumes all of its entries).
int visibleRowCount(List<TimelineRow> rows, int visible) {
  int used = 0;
  int n = 0;
  for (final TimelineRow r in rows) {
    if (used >= visible) break;
    used += r.size;
    n++;
  }
  return n;
}
