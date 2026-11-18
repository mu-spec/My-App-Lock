/// Phase 17 / M1 — Flutter-side lock latency measurement (observational).
///
/// Times the Dart part of a challenge presentation on a monotonic clock
/// ([Stopwatch]): from the moment the host starts presenting until native
/// accepts the rendered challenge (the shield hand-off).
///
/// Contract:
///  * Observational only. The host never reads it to decide anything and no
///    method throws (every entry point is guarded).
///  * Privacy: it stores no package names, credentials, PIN/pattern input,
///    biometric data or wall-clock times. Only enum labels and durations.
///  * Bounded: at most [capacity] finished samples are kept in memory; they
///    are never persisted or sent anywhere.
library;

/// What started a measured presentation.
enum ChallengeLatencySource {
  /// The Dart lock trigger (foreground change) requested the challenge.
  lockTrigger,

  /// Cold start: a native pending ticket consumed after bootstrap.
  bootstrap,

  /// Resume/heartbeat: a native pending ticket consumed on a running engine.
  nativePending,

  /// Keyguard dismissed: a rejected ready hand-off was retried.
  userPresent,

  /// Anything else.
  other,
}

/// Ordered Dart-side stages of one presentation.
enum ChallengeLatencyStage {
  /// `auth.status()` returned (credential state read).
  credentialRead,

  /// Native `showLockChallenge` returned (ticket + shield + launch).
  nativeShow,

  /// FLAG_SECURE applied.
  secureWindow,

  /// The challenge route was pushed.
  routePushed,

  /// The first frame with the route rendered (post-frame callback).
  firstFrame,

  /// Native accepted the ready hand-off (shield released).
  readyAccepted,
}

/// How a measured presentation ended.
enum ChallengeLatencyOutcome { ready, abandoned, superseded }

/// One finished measurement. [stageMicros] holds the elapsed time from the
/// start to each stage that was reached.
class ChallengeLatencySample {
  const ChallengeLatencySample({
    required this.source,
    required this.outcome,
    required this.stageMicros,
    required this.ordered,
  });

  final ChallengeLatencySource source;
  final ChallengeLatencyOutcome outcome;
  final Map<ChallengeLatencyStage, int> stageMicros;
  final bool ordered;

  int? get totalMicros => stageMicros[ChallengeLatencyStage.readyAccepted];
}

/// Nearest-rank percentile statistics for a list of durations.
class LatencyStats {
  const LatencyStats({required this.n, this.p50, this.p95, this.max});

  /// P50 needs at least this many samples.
  static const int minSamplesP50 = 5;

  /// P95 needs at least this many samples.
  static const int minSamplesP95 = 20;

  final int n;
  final int? p50;
  final int? p95;
  final int? max;

  static int percentile(List<int> sorted, int p) {
    final int rank = (p / 100 * sorted.length).ceil().clamp(1, sorted.length);
    return sorted[rank - 1];
  }

  factory LatencyStats.of(Iterable<int> values) {
    final List<int> sorted = values.toList()..sort();
    final int n = sorted.length;
    return LatencyStats(
      n: n,
      p50: n >= minSamplesP50 ? percentile(sorted, 50) : null,
      p95: n >= minSamplesP95 ? percentile(sorted, 95) : null,
      max: n >= 1 ? sorted.last : null,
    );
  }

  @override
  String toString() => 'n=$n p50=${p50 ?? '-'} p95=${p95 ?? '-'} '
      'max=${max ?? '-'}';
}

class ChallengeLatencyRecorder {
  ChallengeLatencyRecorder({int Function()? nowMicros, this.capacity = 64})
      : _nowMicros = nowMicros ?? _monotonicMicros;

  static final Stopwatch _clock = Stopwatch()..start();
  static int _monotonicMicros() => _clock.elapsedMicroseconds;

  final int Function() _nowMicros;
  final int capacity;

  ChallengeLatencySource? _source;
  int? _startMicros;
  final Map<ChallengeLatencyStage, int> _stages =
      <ChallengeLatencyStage, int>{};
  bool _ordered = true;
  final List<ChallengeLatencySample> _samples = <ChallengeLatencySample>[];

  int duplicateStages = 0;
  int stagesWithoutAttempt = 0;

  bool get isOpen => _startMicros != null;
  List<ChallengeLatencySample> get samples =>
      List<ChallengeLatencySample>.unmodifiable(_samples);

  int _now() {
    try {
      return _nowMicros();
    } catch (_) {
      return 0;
    }
  }

  /// Starts a measurement. An open one is closed as superseded.
  void begin(ChallengeLatencySource source) {
    try {
      if (isOpen) _finish(ChallengeLatencyOutcome.superseded);
      _source = source;
      _startMicros = _now();
      _stages.clear();
      _ordered = true;
    } catch (_) {}
  }

  /// Records [stage] once. Marks without an open measurement are counted.
  void mark(ChallengeLatencyStage stage) {
    try {
      final int? start = _startMicros;
      if (start == null) {
        stagesWithoutAttempt++;
        return;
      }
      if (_stages.containsKey(stage)) {
        duplicateStages++;
        return;
      }
      final int elapsed = _now() - start;
      for (final MapEntry<ChallengeLatencyStage, int> e in _stages.entries) {
        if (e.key.index > stage.index || e.value > elapsed) _ordered = false;
      }
      _stages[stage] = elapsed;
      if (stage == ChallengeLatencyStage.readyAccepted) {
        _finish(ChallengeLatencyOutcome.ready);
      }
    } catch (_) {}
  }

  /// Clears every sample, the open measurement and the counters.
  void reset() {
    _source = null;
    _startMicros = null;
    _stages.clear();
    _ordered = true;
    _samples.clear();
    duplicateStages = 0;
    stagesWithoutAttempt = 0;
  }

  /// Ends an open measurement that never became ready.
  void abandon() {
    try {
      if (isOpen) _finish(ChallengeLatencyOutcome.abandoned);
    } catch (_) {}
  }

  void _finish(ChallengeLatencyOutcome outcome) {
    _samples.add(
      ChallengeLatencySample(
        source: _source ?? ChallengeLatencySource.other,
        outcome: outcome,
        stageMicros: Map<ChallengeLatencyStage, int>.unmodifiable(_stages),
        ordered: _ordered,
      ),
    );
    while (_samples.length > capacity) {
      _samples.removeAt(0);
    }
    _source = null;
    _startMicros = null;
    _stages.clear();
    _ordered = true;
  }

  /// Statistics of the ordered, ready samples (optionally one source).
  LatencyStats totalStats({ChallengeLatencySource? source}) =>
      LatencyStats.of(_ready(source).map((s) => s.totalMicros!));

  /// Statistics of the elapsed time to [stage].
  LatencyStats stageStats(
    ChallengeLatencyStage stage, {
    ChallengeLatencySource? source,
  }) =>
      LatencyStats.of(
        _ready(source).map((s) => s.stageMicros[stage]).whereType<int>(),
      );

  Iterable<ChallengeLatencySample> _ready(ChallengeLatencySource? source) =>
      _samples.where(
        (s) =>
            s.outcome == ChallengeLatencyOutcome.ready &&
            s.ordered &&
            (source == null || s.source == source),
      );

  /// A privacy-safe one-line description of [sample] (labels + µs only).
  static String describe(ChallengeLatencySample sample) {
    final String stages = ChallengeLatencyStage.values
        .where(sample.stageMicros.containsKey)
        .map((s) => '${s.name}=${sample.stageMicros[s]}us')
        .join(' ');
    return 'LATENCY source=${sample.source.name} '
        'outcome=${sample.outcome.name} ordered=${sample.ordered} $stages';
  }
}
