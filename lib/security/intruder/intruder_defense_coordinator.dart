// Phase 12 / Milestone 2 — evidence capture + alarm coordinator.
//
// OBSERVE-ONLY. It listens to the M1 IntruderMonitor and is called only
// after a failed-attempt event was PERSISTED (and not superseded by a later
// owner success). It holds no reference to the credential manager, the
// access controller, the shield, profiles or rules; nothing it does can
// reach an authentication verdict. Every entry point is synchronous and
// returns immediately; all work is fire-and-forget and fails quiet into
// [IntruderDefenseStatus].
//
// Trigger (design gate §A): an event from a protected-app challenge whose
// run counter EQUALS the configured threshold — unique per run, so it fires
// once per threshold crossing. Evidence identity = the M1 event seq.
//
// Cancellation (final security gate B/C): an owner success or a consent
// revocation bumps an epoch SYNCHRONOUSLY and asks the platform to abort.
// Work started under an older epoch can never persist an image (checked
// after every await and, finally, inside the store's serialized write) and
// an alarm whose start was still pending is stopped as soon as it reports.
//
// Phase 13 / M2 — outcome observer. After each capture / alarm decision the
// coordinator reports ONE immutable [IntruderOutcome] (ints and enums only,
// never a platform string) to an optional [outcomeObserver]. The call is
// synchronous, made after the branch's counters and awaits, never awaited,
// and wrapped in try/catch: an observer can neither block nor change any
// capture, alarm, counter or epoch decision. No control flow reads the
// observer state except the `finally` fallback, which only decides whether
// to report.

import 'dart:async';
import 'dart:collection';

import '../credentials/verified_attempt.dart';
import 'failed_attempt_event.dart';
import 'intruder_defense_settings.dart';
import 'intruder_evidence_service.dart';
import 'intruder_evidence_store.dart';
import 'intruder_monitor.dart';

/// Why no photo was saved for a trigger (closed set; Phase 13 / M2).
enum IntruderCaptureWhy {
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

/// Why the alarm did not start for a trigger (closed set; Phase 13 / M2).
enum IntruderAlarmWhy {
  alreadyPlaying,
  dnd,
  ringer,
  focusDenied,
  notForeground,
  cancelled,
  error,
}

/// One terminal capture / alarm outcome (Phase 13 / M2). Immutable; holds
/// the failed-attempt seq ([trig]) and closed enums only. Batch 3: `tgen`
/// is the failure-log generation of that attempt (EID = (tgen, trig));
/// null only for an event without a generation (legacy).
sealed class IntruderOutcome {
  const IntruderOutcome();
}

final class CaptureSavedOutcome extends IntruderOutcome {
  const CaptureSavedOutcome(this.trig, {this.tgen});

  final int trig;
  final String? tgen;
}

final class CaptureNotSavedOutcome extends IntruderOutcome {
  const CaptureNotSavedOutcome(this.trig, this.why, {this.tgen});

  final int trig;
  final String? tgen;
  final IntruderCaptureWhy why;
}

final class AlarmStartedOutcome extends IntruderOutcome {
  const AlarmStartedOutcome(this.trig, {this.tgen});

  final int trig;
  final String? tgen;
}

final class AlarmNotStartedOutcome extends IntruderOutcome {
  const AlarmNotStartedOutcome(this.trig, this.why, {this.tgen});

  final int trig;
  final String? tgen;
  final IntruderAlarmWhy why;
}

/// A stop of an alarm that was reported playing was requested.
final class AlarmStoppedOutcome extends IntruderOutcome {
  const AlarmStoppedOutcome();
}

/// Receives outcomes synchronously. Must return quickly; exceptions are
/// swallowed by the coordinator.
abstract interface class IntruderOutcomeObserver {
  void onIntruderOutcome(IntruderOutcome o);
}

/// Counters only — no image data, no credential material.
final class IntruderDefenseStatus {
  int triggers = 0;
  int captured = 0;
  int captureSkipped = 0;
  int captureFailed = 0;
  int captureCancelled = 0;
  int saveFailed = 0;
  int alarmsStarted = 0;
  int alarmsSuppressed = 0;
  int alarmsCancelled = 0;
  int errors = 0;
  String? lastFailure;
}

class IntruderDefenseCoordinator implements IntruderEventListener {
  IntruderDefenseCoordinator({
    required IntruderDefenseSettingsStore settings,
    required IntruderEvidenceStore evidence,
    required IntruderEvidenceService service,
    this.alarmDuration = defaultAlarmDuration,
    this.captureTimeout = defaultCaptureTimeout,
  })  : _settings = settings,
        _evidence = evidence,
        _service = service;

  static const Duration defaultAlarmDuration = Duration(seconds: 30);

  /// Dart-side bound on one platform capture call (native: 4 s open +
  /// 0.7 s warm-up + 4 s capture). A late native reply is ignored.
  static const Duration defaultCaptureTimeout = Duration(seconds: 12);
  static const int _handledCapacity = 256;

  final IntruderDefenseSettingsStore _settings;
  final IntruderEvidenceStore _evidence;
  final IntruderEvidenceService _service;
  final Duration alarmDuration;
  final Duration captureTimeout;

  final IntruderDefenseStatus status = IntruderDefenseStatus();

  /// Batch 3 (B2 §3.5): handled-event identities are EIDs (gen, seq), so a
  /// re-initialized log's seq can never be mistaken for a handled one.
  final LinkedHashSet<String> _handled = LinkedHashSet<String>();

  /// Batch 3: the newest failure-log generation notified to this
  /// coordinator, and the highest seq handled in it (clear-all floor).
  String? _currentGen;
  int _currentGenHighest = -1;

  /// Phase 12 / M3: highest event seq ever handed to this coordinator
  /// (never evicted). Used as the clear-all floor so evidence for any
  /// failure that happened before the clear can never be saved after it.
  int _highestSeq = -1;
  final Set<Future<void>> _inFlight = <Future<void>>{};
  bool _capturing = false;

  /// Bumped by owner success and by photo-consent revocation.
  int _captureEpoch = 0;

  /// Bumped by owner success and by alarm-consent revocation.
  int _alarmEpoch = 0;
  bool _alarmPlaying = false;
  int _alarmStartsPending = 0;

  /// Phase 13 / M2: optional outcome observer (read at call time).
  IntruderOutcomeObserver? outcomeObserver;

  /// Trigger seq of the capture holding the single slot, and whether its
  /// terminal outcome was already reported. Read only by the reporting
  /// helpers and the `finally` fallback.
  int _captureTrig = -1;
  String? _captureGen;
  bool _captureReported = true;

  /// Completes when every started operation has finished (tests).
  Future<void> idle() async {
    while (_inFlight.isNotEmpty) {
      await Future.wait(_inFlight.toList());
    }
  }

  void _track(Future<void> work) {
    late final Future<void> op;
    op = work.whenComplete(() => _inFlight.remove(op));
    _inFlight.add(op);
  }

  @override
  void onFailedAttemptRecorded(FailedAttemptEvent event) {
    if (event.surface != AuthAttemptSurface.protectedAppChallenge) return;
    final String? gen = event.logGen;
    if (!_handled.add('$gen:${event.seq}')) return; // duplicate notification
    if (event.seq > _highestSeq) _highestSeq = event.seq;
    if (gen != null) {
      if (gen != _currentGen) {
        _currentGen = gen;
        _currentGenHighest = event.seq;
      } else if (event.seq > _currentGenHighest) {
        _currentGenHighest = event.seq;
      }
    }
    while (_handled.length > _handledCapacity) {
      _handled.remove(_handled.first);
    }
    _track(_handle(event, _captureEpoch, _alarmEpoch));
  }

  /// Synchronous and non-blocking: the owner just authenticated. Cancels any
  /// pending capture and silences (or pre-empts) the alarm.
  @override
  void onOwnerVerified() {
    _invalidateCapture();
    _invalidateAlarm();
  }

  /// The owner saved new settings (authorized flow). Revoked consent takes
  /// effect immediately for work already in progress.
  ///
  /// Revocation always signals the platform (both calls are idempotent), so a
  /// camera session or tone the coordinator does not know about is stopped.
  void onSettingsChanged(IntruderDefenseSettings settings) {
    if (!settings.evidenceEnabled) _invalidateCapture(force: true);
    if (!settings.alarmEnabled) _invalidateAlarm(force: true);
  }

  /// Phase 12 / M3 — highest failed-attempt seq this coordinator was
  /// notified of (-1 when none).
  int get highestHandledSeq => _highestSeq;

  /// Batch 3 — the newest failure-log generation this coordinator was
  /// notified of (null when only legacy events were seen).
  String? get currentGen => _currentGen;

  /// Batch 3 — highest seq handled in [currentGen] (-1 when none).
  int get currentGenHighestSeq => _currentGenHighest;

  /// Phase 12 / M3 — the owner (freshly verified) is clearing all evidence.
  /// Synchronous: bumps the capture epoch BEFORE the store clear so a
  /// capture already in flight fails its commit-point check, and signals
  /// the platform to abort any camera session. The alarm is untouched.
  void onEvidenceCleared() => _invalidateCapture(force: true);

  void _invalidateCapture({bool force = false}) {
    _captureEpoch++;
    if (force || _capturing) {
      _track(_quiet(_service.abortCapture));
    }
  }

  void _invalidateAlarm({bool force = false}) {
    _alarmEpoch++;
    final bool wasPlaying = _alarmPlaying;
    if (force || _alarmPlaying || _alarmStartsPending > 0) {
      _alarmPlaying = false;
      _track(_quiet(_service.stopAlarm));
      if (wasPlaying) _notify(const AlarmStoppedOutcome());
    }
  }

  Future<void> _quiet(Future<void> Function() call) async {
    try {
      await call();
    } catch (_) {
      status.errors++;
    }
  }

  Future<void> _handle(
    FailedAttemptEvent event,
    int captureEpoch,
    int alarmEpoch,
  ) async {
    try {
      final IntruderDefenseSettings s = (await _settings.read()).settings;
      if (event.consecutiveFailures != s.threshold) return;
      final bool alarm = s.alarmEnabled && alarmEpoch == _alarmEpoch;
      final bool photo = s.evidenceEnabled && captureEpoch == _captureEpoch;
      if (!alarm && !photo) return;
      status.triggers++;
      await Future.wait(<Future<void>>[
        if (alarm) _alarm(alarmEpoch, event.seq, event.logGen),
        if (photo) _capture(event, captureEpoch),
      ]);
    } catch (_) {
      status.errors++;
    }
  }

  Future<void> _alarm(int epoch, int trig, String? tgen) async {
    _alarmStartsPending++;
    AlarmStartResult r;
    try {
      r = await _service.startAlarm(duration: alarmDuration);
    } catch (_) {
      status.errors++;
      _notify(AlarmNotStartedOutcome(trig, IntruderAlarmWhy.error, tgen: tgen));
      return;
    } finally {
      _alarmStartsPending--;
    }
    if (r != AlarmStartResult.started) {
      status.alarmsSuppressed++;
      status.lastFailure = 'alarm:${r.name}';
      _notify(AlarmNotStartedOutcome(trig, _alarmWhy(r), tgen: tgen));
      return;
    }
    if (epoch != _alarmEpoch) {
      // Owner success / revocation arrived while the start was pending.
      status.alarmsCancelled++;
      await _quiet(_service.stopAlarm);
      _notify(
          AlarmNotStartedOutcome(trig, IntruderAlarmWhy.cancelled, tgen: tgen));
      return;
    }
    status.alarmsStarted++;
    _alarmPlaying = true;
    _notify(AlarmStartedOutcome(trig, tgen: tgen));
  }

  Future<void> _capture(FailedAttemptEvent event, int epoch) async {
    if (_capturing) {
      status.captureSkipped++; // single capture slot; never queued
      _notify(CaptureNotSavedOutcome(event.seq, IntruderCaptureWhy.busy,
          tgen: event.logGen));
      return;
    }
    _capturing = true;
    _captureTrig = event.seq;
    _captureGen = event.logGen;
    _captureReported = false;
    try {
      if (await _service.cameraPermission() != CameraPermissionState.granted) {
        status.captureSkipped++;
        status.lastFailure = 'capture:permission';
        _captureNotSaved(IntruderCaptureWhy.permission);
        return;
      }
      if (epoch != _captureEpoch) {
        _cancelled();
        return;
      }
      bool timedOut = false;
      final CaptureResult r = await _service
          .captureStill(maxBytes: _evidence.maxImageBytes)
          .timeout(captureTimeout, onTimeout: () {
        timedOut = true;
        return const CaptureFailed('timeout');
      });
      if (timedOut) {
        _track(_quiet(_service.abortCapture));
      }
      if (epoch != _captureEpoch) {
        _cancelled(); // late success / failure / timeout after cancel
        return;
      }
      switch (r) {
        case CaptureFailed(:final String reason):
          status.captureFailed++;
          status.lastFailure = 'capture:$reason';
          // The platform reason string is never forwarded.
          _captureNotSaved(reason == 'timeout'
              ? IntruderCaptureWhy.timeout
              : IntruderCaptureWhy.camera);
        case CaptureSucceeded(:final jpeg):
          // Authoritative consent re-check (corrupt/unreadable = disabled).
          final IntruderDefenseSettings now = (await _settings.read()).settings;
          if (!now.evidenceEnabled || epoch != _captureEpoch) {
            _cancelled();
            return;
          }
          final EvidenceSaveResult saved = await _evidence.save(
            seq: event.seq,
            // Batch 3: EID identity; a capture whose generation is no
            // longer the newest one notified is never saved (superseded).
            gen: event.logGen,
            currentGen: event.logGen == null ? null : _currentGen,
            jpeg: jpeg,
            packageName: event.packageName,
            // Linearization point: checked synchronously inside the store's
            // serialized write, immediately before the blob is written.
            stillValid: () => epoch == _captureEpoch,
          );
          if (saved == EvidenceSaveResult.saved) {
            status.captured++;
            _notifyCapture(
                CaptureSavedOutcome(_captureTrig, tgen: _captureGen));
          } else if (saved == EvidenceSaveResult.cancelled ||
              saved == EvidenceSaveResult.superseded) {
            if (saved == EvidenceSaveResult.superseded) {
              _captureNotSaved(IntruderCaptureWhy.superseded);
            }
            _cancelled();
          } else {
            status.saveFailed++;
            status.lastFailure = 'save:${saved.name}';
            _captureNotSaved(_saveWhy(saved));
          }
      }
    } catch (_) {
      status.errors++;
    } finally {
      // Exactly one capture outcome per slot entry (any missed path).
      if (!_captureReported) _captureNotSaved(IntruderCaptureWhy.error);
      _capturing = false;
    }
  }

  void _cancelled() {
    status.captureCancelled++;
    status.lastFailure = 'capture:cancelled';
    if (!_captureReported) _captureNotSaved(IntruderCaptureWhy.cancelled);
  }

  // -- Phase 13 / M2 outcome reporting (never affects a decision) ----------

  /// Synchronous; an observer exception is swallowed here, so it can never
  /// reach the coordinator's own error handling or counters.
  void _notify(IntruderOutcome o) {
    try {
      outcomeObserver?.onIntruderOutcome(o);
    } catch (_) {
      // Observer failures never affect capture, alarm or counters.
    }
  }

  /// Reports the slot's terminal capture outcome (marks it reported first,
  /// so a throwing observer can never cause a second outcome).
  void _notifyCapture(IntruderOutcome o) {
    _captureReported = true;
    _notify(o);
  }

  void _captureNotSaved(IntruderCaptureWhy why) => _notifyCapture(
      CaptureNotSavedOutcome(_captureTrig, why, tgen: _captureGen));

  static IntruderCaptureWhy _saveWhy(EvidenceSaveResult r) => switch (r) {
        EvidenceSaveResult.duplicate => IntruderCaptureWhy.duplicate,
        EvidenceSaveResult.storageFailed => IntruderCaptureWhy.storage,
        EvidenceSaveResult.encryptionFailed => IntruderCaptureWhy.encryption,
        EvidenceSaveResult.invalidImage ||
        EvidenceSaveResult.oversized =>
          IntruderCaptureWhy.image,
        EvidenceSaveResult.unsupportedSchema => IntruderCaptureWhy.unsupported,
        // Handled by the caller's other branches (never reached here).
        EvidenceSaveResult.saved ||
        EvidenceSaveResult.cancelled ||
        EvidenceSaveResult.superseded =>
          IntruderCaptureWhy.error,
      };

  static IntruderAlarmWhy _alarmWhy(AlarmStartResult r) => switch (r) {
        AlarmStartResult.alreadyPlaying => IntruderAlarmWhy.alreadyPlaying,
        AlarmStartResult.suppressedByDnd => IntruderAlarmWhy.dnd,
        AlarmStartResult.suppressedByRinger => IntruderAlarmWhy.ringer,
        AlarmStartResult.focusDenied => IntruderAlarmWhy.focusDenied,
        AlarmStartResult.notForeground => IntruderAlarmWhy.notForeground,
        // `started` is handled by the caller (never reached here).
        AlarmStartResult.started ||
        AlarmStartResult.error =>
          IntruderAlarmWhy.error,
      };
}
