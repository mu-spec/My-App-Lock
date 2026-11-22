import 'dart:math';

import 'package:flutter/services.dart';

/// Phase 18 / M1F (F18-2): one reading of the device's monotonic clock.
///
/// [elapsedMs] is `SystemClock.elapsedRealtime()` (counts deep sleep, cannot
/// be changed by the user, restarts at every boot). [bootCount] is
/// `Settings.Global.BOOT_COUNT`, or -1 when the platform does not report it.
class MonotonicReading {
  const MonotonicReading({
    required this.elapsedMs,
    required this.bootCount,
    this.processScope,
  });

  final int elapsedMs;
  final int bootCount;

  /// Null for the native clock. Non-null for the in-process fallback
  /// ([ProcessMonotonicClock]): the scope id of THIS process, whose
  /// [elapsedMs] restarts with every process (a different scope is treated
  /// like another boot: full cooldown, fail closed).
  final String? processScope;

  /// Parses the native channel reply; anything malformed is null (the
  /// caller then uses the fail-closed [ProcessMonotonicClock] fallback).
  static MonotonicReading? fromMap(Map<Object?, Object?>? map) {
    if (map == null) return null;
    final Object? elapsed = map['elapsedMs'];
    final Object? boot = map['bootCount'];
    if (elapsed is! int || elapsed < 0) return null;
    return MonotonicReading(
      elapsedMs: elapsed,
      bootCount: boot is int && boot >= 0 ? boot : -1,
    );
  }
}

/// Source of [MonotonicReading]s. Returns null when no reading is available.
abstract interface class MonotonicClock {
  Future<MonotonicReading?> read();
}

/// Phase 18 / M1F (F18-2 hardening): the bounded, fail-closed fallback used
/// when the native clock is unavailable or malformed. A Dart [Stopwatch]
/// (a monotonic OS clock; the user cannot change it) started once per
/// process, scoped by a random per-process id. It may undercount deep sleep,
/// which can only lengthen a cooldown. It never consults the wall clock, so
/// moving the device time cannot end a lockout; a process restart restarts
/// the cooldown in full (bounded by the policy cap) — the recovery path is
/// to keep the app open for the cooldown.
class ProcessMonotonicClock implements MonotonicClock {
  ProcessMonotonicClock._();

  static final ProcessMonotonicClock instance = ProcessMonotonicClock._();
  static final Stopwatch _stopwatch = Stopwatch()..start();
  static final String _scope = _newScope();

  static String _newScope() {
    Random random;
    try {
      random = Random.secure();
    } on UnsupportedError {
      random = Random(DateTime.now().microsecondsSinceEpoch);
    }
    return List<String>.generate(
      16,
      (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
  }

  @override
  Future<MonotonicReading?> read() async => MonotonicReading(
        elapsedMs: _stopwatch.elapsedMilliseconds,
        bootCount: -1,
        processScope: _scope,
      );
}

/// Latch for [FailClosedLockoutClock]: once the primary clock fails, the
/// fallback is used for the rest of the owner's lifetime (production: the
/// single credential manager, i.e. the process), so the time base cannot
/// flap (each flap would restart the full cooldown).
class LockoutClockLatch {
  LockoutClockLatch();

  bool _fellBack = false;
  bool get fellBack => _fellBack;
}

/// Phase 18 / M1F (F18-2 hardening): the lockout clock the credential
/// manager actually uses. Never returns null and never falls back to the
/// wall clock: a null, malformed (negative / non-int elapsed) or throwing
/// primary reading latches [fallback] for the rest of this instance.
class FailClosedLockoutClock implements MonotonicClock {
  FailClosedLockoutClock(
    this._primary, {
    MonotonicClock? fallback,
    LockoutClockLatch? latch,
  })  : _fallback = fallback ?? ProcessMonotonicClock.instance,
        _latch = latch ?? LockoutClockLatch();

  final MonotonicClock _primary;
  final MonotonicClock _fallback;
  final LockoutClockLatch _latch;

  @override
  Future<MonotonicReading?> read() async {
    if (!_latch._fellBack) {
      MonotonicReading? r;
      try {
        r = await _primary.read();
      } on Object {
        r = null;
      }
      if (r != null &&
          r.processScope == null &&
          r.elapsedMs >= 0 &&
          r.bootCount >= -1) {
        return r;
      }
      _latch._fellBack = true;
    }
    final MonotonicReading? f = await _fallback.read();
    // A fallback reading without a scope would be mistaken for native:
    // refuse it (never happens with [ProcessMonotonicClock]).
    if (f == null || f.processScope == null || f.elapsedMs < 0) return null;
    return f;
  }
}

/// Production: `smart_app_lock/monotonic_clock` (`MonotonicClockChannel.kt`).
/// A missing plugin or any platform error yields null, never a guess.
class MethodChannelMonotonicClock implements MonotonicClock {
  const MethodChannelMonotonicClock({
    MethodChannel channel = const MethodChannel(channelName),
  }) : _channel = channel;

  static const String channelName = 'smart_app_lock/monotonic_clock';

  final MethodChannel _channel;

  @override
  Future<MonotonicReading?> read() async {
    try {
      return MonotonicReading.fromMap(
        await _channel.invokeMapMethod<Object?, Object?>('read'),
      );
    } on Object {
      return null;
    }
  }
}

/// Phase 18 / M1F (F18-2): where a lockout started on the monotonic clock.
/// Persisted (optional) in the encrypted security-settings document next to
/// `lockedOutUntilEpochMs`, which stays for display and as the fallback.
class LockoutAnchor {
  const LockoutAnchor({
    required this.elapsedMs,
    required this.bootCount,
    required this.wallMs,
    required this.durationMs,
    this.served = false,
    this.processScope,
  });

  /// Starts a lockout of [duration] at [reading] / [now].
  factory LockoutAnchor.start(
    MonotonicReading reading,
    DateTime now,
    Duration duration,
  ) =>
      LockoutAnchor(
        elapsedMs: reading.elapsedMs,
        bootCount: reading.bootCount,
        wallMs: now.millisecondsSinceEpoch,
        durationMs: duration.inMilliseconds,
        processScope: reading.processScope,
      );

  final int elapsedMs;
  final int bootCount;
  final int wallMs;
  final int durationMs;

  /// The full cooldown has been observed on the monotonic clock: the
  /// lockout is over whatever the clocks say later (a reboot after an
  /// expired lockout must not start another one).
  final bool served;

  /// [MonotonicReading.processScope] of the clock that anchored the lockout
  /// (null = the native clock).
  final String? processScope;

  LockoutAnchor asServed() => LockoutAnchor(
        elapsedMs: elapsedMs,
        bootCount: bootCount,
        wallMs: wallMs,
        durationMs: durationMs,
        served: true,
        processScope: processScope,
      );

  Map<String, dynamic> toJson() => <String, dynamic>{
        'elapsedMs': elapsedMs,
        'bootCount': bootCount,
        'wallMs': wallMs,
        'durationMs': durationMs,
        'served': served,
        if (processScope != null) 'processScope': processScope,
      };

  /// Lenient: an absent or malformed anchor is null (legacy handling).
  static LockoutAnchor? fromJson(Object? json) {
    if (json is! Map) return null;
    final Object? e = json['elapsedMs'];
    final Object? b = json['bootCount'];
    final Object? w = json['wallMs'];
    final Object? d = json['durationMs'];
    final Object? s = json['served'];
    final Object? p = json['processScope'];
    if (e is! int || b is! int || w is! int || d is! int || e < 0 || d <= 0) {
      return null;
    }
    if (p != null && p is! String) return null;
    return LockoutAnchor(
      elapsedMs: e,
      bootCount: b,
      wallMs: w,
      durationMs: d,
      served: s == true,
      processScope: p as String?,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is LockoutAnchor &&
      other.elapsedMs == elapsedMs &&
      other.bootCount == bootCount &&
      other.wallMs == wallMs &&
      other.durationMs == durationMs &&
      other.served == served &&
      other.processScope == processScope;

  @override
  int get hashCode => Object.hash(
      elapsedMs, bootCount, wallMs, durationMs, served, processScope);
}

/// Phase 18 / M1F (F18-2, owner-approved design): lockout timing that the
/// wall clock cannot shorten.
///
///  * Same boot: the monotonic clock is authoritative; wall-clock changes
///    (forward or backward) have no effect.
///  * Same-boot test mirrors the native `WakeIdentityBootScope.sameBoot`:
///    a lower elapsed value means another boot; otherwise known boot counts
///    are compared; otherwise the wall/monotonic drift must be <= 10 s.
///  * Another (or ambiguous) boot: the FULL cooldown restarts from the
///    first observation (re-anchored and persisted by the manager).
///  * A legacy lockout (no anchor) still active by the wall clock is
///    re-anchored once with the full policy cooldown for its streak.
///  * No reading: the wall-clock rule — reached only when NO clock is
///    configured (non-production constructors). Production falls back to
///    [ProcessMonotonicClock] when the native clock is unavailable or
///    malformed (owner instruction, Phase 18 / M1F final corrections:
///    replaces D2-a).
abstract final class LockoutClockPolicy {
  static const Duration bootDriftTolerance = Duration(seconds: 10);

  static bool sameBoot(
    LockoutAnchor anchor,
    MonotonicReading reading,
    DateTime now,
  ) {
    // Another clock source (native vs process fallback) or another process
    // is another time base: full cooldown (fail closed).
    if (anchor.processScope != reading.processScope) return false;
    if (reading.elapsedMs < anchor.elapsedMs) return false;
    // One process: its stopwatch never resets (no wall-clock drift test).
    if (anchor.processScope != null) return true;
    if (anchor.bootCount >= 0 && reading.bootCount >= 0) {
      return anchor.bootCount == reading.bootCount;
    }
    final int wallDelta = now.millisecondsSinceEpoch - anchor.wallMs;
    final int monoDelta = reading.elapsedMs - anchor.elapsedMs;
    return (wallDelta - monoDelta).abs() <= bootDriftTolerance.inMilliseconds;
  }

  /// The lockout end, expressed in the wall-clock frame of [now], to use for
  /// ONE decision. A non-null result that is not after [now] is an expired
  /// lockout (callers keep treating it as "expired", which restarts the
  /// attempt count exactly as before).
  static DateTime? effectiveUntil({
    required DateTime? storedUntil,
    required LockoutAnchor? anchor,
    required MonotonicReading? reading,
    required DateTime now,
  }) {
    if (storedUntil == null) return null;
    if (reading == null || anchor == null) return storedUntil;
    final DateTime expired = storedUntil.isAfter(now) ? now : storedUntil;
    if (anchor.served) return expired;
    if (!sameBoot(anchor, reading, now)) {
      // Not yet re-anchored for this boot: fail closed (full cooldown).
      return now.add(Duration(milliseconds: anchor.durationMs));
    }
    final int remaining =
        anchor.durationMs - (reading.elapsedMs - anchor.elapsedMs);
    return remaining > 0 ? now.add(Duration(milliseconds: remaining)) : expired;
  }

  /// The anchor the document must hold for this boot, or null when the
  /// stored one is already correct.
  static LockoutAnchor? reconcile({
    required DateTime? storedUntil,
    required LockoutAnchor? anchor,
    required int lockoutStreak,
    required MonotonicReading reading,
    required DateTime now,
    required Duration Function(int streak) cooldownForStreak,
  }) {
    if (storedUntil == null) return null;
    if (anchor == null) {
      if (!storedUntil.isAfter(now)) return null; // legacy, already expired
      return LockoutAnchor.start(
        reading,
        now,
        cooldownForStreak(lockoutStreak < 1 ? 1 : lockoutStreak),
      );
    }
    if (anchor.served) return null;
    if (!sameBoot(anchor, reading, now)) {
      return LockoutAnchor.start(
        reading,
        now,
        Duration(milliseconds: anchor.durationMs),
      );
    }
    if (reading.elapsedMs - anchor.elapsedMs >= anchor.durationMs) {
      return anchor.asServed();
    }
    return null;
  }
}
