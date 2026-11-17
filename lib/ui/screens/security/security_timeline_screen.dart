// Phase 13 / Milestone 1 — owner-only Security timeline.
//
// Opened only through [openSecurityTimeline]: fresh primary PIN/pattern
// verification -> a short-lived, in-memory session from the timeline's OWN
// session gate (never shared with the evidence viewer). Before any history
// is read, FLAG_SECURE is enabled; if that fails the timeline fails closed
// and reads nothing. The credential is re-checked before every load.
//
// The session ends on app backgrounding (any lifecycle state other than
// resumed), screen-off, absolute expiry, a credential change, or ANY route
// covering the timeline (it has no child routes of its own in M1). When it
// ends, the loaded history is dropped from state, nothing is rendered, and
// the timeline closes itself (immediately if it is on top, otherwise when
// it surfaces again — a foreign route is never popped).
//
// M2: failed attempts are shown in presentation-only groups (P10) with
// up to 3 inline attempt rows (M1 keys); a group or an M2 row opens the
// details route, which is the ONLY own child route. While the details
// route covers the timeline the loaded history is dropped (not the
// session); on surfacing the timeline re-runs FLAG_SECURE -> credential
// re-check -> load before anything renders. Any other covering route is
// foreign and ends the session.
//
// Metadata only. No share, export, clipboard, selection, file or log
// output. FLAG_SECURE is intentionally NOT cleared on exit (same as the
// Phase 12 evidence viewer; the lock host clears it at its own loop end).

import 'dart:async';

import 'package:flutter/material.dart';

import '../../../app/app_container.dart';
import '../../../design_system/design_system.dart';
import '../../../security/credentials/auth_type.dart';
import '../../../security/credentials/verified_attempt.dart';
import '../../../security/intruder/failed_attempt_event.dart';
import '../../../security/intruder/intruder_defense_coordinator.dart';
import '../../../security/intruder/intruder_owner_session.dart';
import '../../../security/history/history_clear_service.dart';
import '../../../security/timeline/security_journal_event.dart';
import '../../../security/timeline/security_timeline.dart';
import '../../../security/timeline/security_timeline_grouping.dart';
import '../../../services/screen_state_service.dart';
import '../../../utilities/result.dart';
import 'app_credential_verification.dart';
import 'intruder_owner_verification.dart';
import 'security_timeline_detail_screen.dart';

const String securityTimelineRouteName = '/security/timeline';

/// Routes that belong to the timeline flow (Q-M2-8 A: the verification
/// route is NOT own-flow).
/// Batch 4: the Clear History confirmation dialog.
const String securityTimelineClearRouteName = '/security/timeline/clear';

bool isSecurityTimelineFlowRoute(Route<dynamic> r) =>
    r.settings.name == securityTimelineRouteName ||
    r.settings.name == securityTimelineDetailRouteName;

/// Batch 4: routes the Clear History flow itself pushes (the confirmation
/// dialog and the owner verification). Accepted above the timeline ONLY
/// while that flow runs; anything else ends the session as before.
bool isSecurityTimelineClearFlowRoute(Route<dynamic> r) =>
    r.settings.name == securityTimelineClearRouteName ||
    r.settings.name == appCredentialVerifyRouteName;

Route<Object?>? _topRoute(NavigatorState navigator) {
  Route<Object?>? top;
  navigator.popUntil((Route<Object?> r) {
    top = r;
    return true;
  });
  return top;
}

abstract final class SecurityTimelineText {
  static const String title = 'Security timeline';
  static const String rowTitle = 'Security timeline';
  static const String rowSubtitle =
      'Failed unlocks and security events (PIN or pattern required)';
  static const String loading = 'Loading…';
  static const String empty = 'No security events are recorded.';
  static const String secureFailed =
      'The timeline can\'t be shown because screen-capture protection could '
      'not be enabled.';
  static const String sessionEnded = 'Security timeline closed for privacy.';
  static const String showOlder = 'Show older';
  static const String footer =
      'This timeline shows security events kept on this device (up to 30 '
      'days, within storage limits). It is not a complete forensic record.';

  static String sourceName(TimelineSource s) => switch (s) {
        TimelineSource.failedAttempts => 'Failed-unlock history',
        TimelineSource.journal => 'Security journal',
      };

  static String unavailable(TimelineSource s, TimelineSourceState st) =>
      switch (st) {
        TimelineSourceState.unavailableNewerVersion =>
          '${sourceName(s)} was saved by a newer version of the app and '
              'can\'t be shown here.',
        TimelineSourceState.unavailableBusy =>
          '${sourceName(s)} was busy and couldn\'t be read just now. This '
              'does not mean there are no events.',
        TimelineSourceState.available ||
        TimelineSourceState.unavailableUnreadable =>
          '${sourceName(s)} couldn\'t be read. This does not mean there '
              'are no events.',
      };

  // -- M2 (gate R2 §4.3) ---------------------------------------------------

  static const String resetPending =
      'A recent successful unlock hasn\'t been saved to the attempt counter '
      'yet. Consecutive-failure counters may be higher than the real number.';

  static String resetFailures(int n) =>
      '$n successful ${n == 1 ? 'unlock' : 'unlocks'} couldn\'t be saved to '
      'the attempt counter.';

  static const String healthCoverage =
      'Protection status is checked only while Smart App Lock is open. '
      'Problems may have started earlier, and short interruptions may be '
      'missing.';

  static const String photoLink =
      'Photos are listed in Intruder photos. Photos taken before this update '
      'aren\'t linked here.';

  static const String footerProcessDeath =
      'Events detected just before the app closed may be missing.';

  static const String details = 'Details';

  /// A-1: the lazily created marker is a FIRST-USE time.
  static const String journalStartedNote =
      'No journal events were recorded before this time.';

  static const String detachedOutcome =
      'This event could not be matched to a failed attempt in the available '
      'history.';

  static String moreInDetails(int n) => '+$n more in details';

  // -- Batch 4: Clear History ----------------------------------------------

  static const String clearAction = 'Clear history…';
  static const String clearTitle = 'Clear security history?';
  static const String clearBody =
      // First two sentences verbatim from SECURITY_DESIGN §1.1 (sealed).
      'Removes the security timeline and failed-attempt history. Lockout, '
      'PIN/pattern, biometric settings and protection are not changed. A note that history was cleared, and when, stays in the '
      'timeline. Rows are deleted from app storage; secure erasure of the '
      'device storage is not guaranteed.';
  static const String clearPhotos = 'Also delete intruder photos';
  static const String clearPhotosNote =
      'Only photos of the cleared attempts. Off: photos stay in Intruder '
      'photos.';
  static const String clearCancel = 'Cancel';
  static const String clearConfirm = 'Clear';
  static const String cleared = 'Security history cleared.';
  static const String clearRefused =
      'History can\'t be cleared right now. Nothing was changed.';
  static const String clearNotDone = 'History was not cleared.';
  static const String clearFailed =
      'History couldn\'t be cleared. The timeline shows what is stored now.';
  static const String clearInterrupted =
      'Clearing was interrupted. The cleared items are hidden; finish '
      'clearing to remove the rest.';
  static const String clearPendingNotice =
      'Clearing was interrupted. Cleared items are hidden but not all of '
      'them are deleted yet. Verify to finish clearing.';
  static const String clearFinish = 'Finish clearing';

  static String clearedTitle(HistoryClearScope? scope) =>
      scope == HistoryClearScope.historyPhotos
          ? 'History and intruder photos cleared'
          : 'History cleared';

  /// Batch 5.
  static String retentionDays(int? d) => '${d ?? '?'} days';

  static String day(DateTime? d) => d == null
      ? '?'
      : '${d.year}-${d.month.toString().padLeft(2, '0')}-'
          '${d.day.toString().padLeft(2, '0')}';

  static String attempts(int n) =>
      '$n failed ${n == 1 ? 'attempt' : 'attempts'}';

  static String appLabel(String? package, Map<String, String> labels) =>
      package == null ? 'in Smart App Lock' : (labels[package] ?? package);

  /// Gate R2 §1.2 reason wording (verbatim).
  static String captureWhy(CaptureWhy w) => switch (w) {
        CaptureWhy.permission => 'camera permission is off',
        CaptureWhy.camera => 'camera error',
        CaptureWhy.timeout => 'camera timed out',
        CaptureWhy.busy => 'another photo was being taken',
        CaptureWhy.cancelled => 'stopped',
        CaptureWhy.duplicate => 'a photo for this attempt already exists',
        CaptureWhy.storage => 'couldn\'t be stored',
        CaptureWhy.encryption => 'couldn\'t be encrypted',
        CaptureWhy.image => 'image was invalid or too large',
        CaptureWhy.superseded => 'photos were deleted',
        CaptureWhy.unsupported => 'photo storage is from a newer version',
        CaptureWhy.error => 'unexpected error',
      };

  static String alarmWhy(AlarmWhy w) => switch (w) {
        AlarmWhy.alreadyPlaying => 'already playing',
        AlarmWhy.dnd => 'Do Not Disturb',
        AlarmWhy.ringer => 'silent mode',
        AlarmWhy.focusDenied => 'audio unavailable',
        AlarmWhy.notForeground => 'app not in front',
        AlarmWhy.cancelled => 'stopped',
        AlarmWhy.error => 'unexpected error',
      };

  /// Configured alarm length shown on alarm rows ("plays up to …"); the
  /// row never states an end time.
  static final int alarmSeconds =
      IntruderDefenseCoordinator.defaultAlarmDuration.inSeconds;

  static String healthState(HState s) => switch (s) {
        HState.secure => 'secure',
        HState.attention => 'needs attention',
        HState.offline => 'offline',
      };

  static String healthCode(HCode c) => switch (c) {
        HCode.protectionNotConfigured => 'protection not set up',
        HCode.enforcementNotArmed => 'locking not active',
        HCode.overlayUnavailable => 'lock screen permission missing',
        HCode.detectionOffline => 'app detection off',
        HCode.accessibilityUnavailable => 'accessibility service off',
        HCode.accessibilityNotRunning => 'accessibility service not running',
        HCode.usageAccessUnavailable => 'usage access missing',
        HCode.watcherNotRunning => 'background watcher not running',
        HCode.shieldNotArmed => 'shield not active',
        HCode.notificationsDisabled => 'notifications off',
        HCode.backgroundRestricted => 'background use restricted',
        HCode.signalUnknown => 'some checks couldn\'t be completed',
        HCode.healthSnapshotStale => 'status check out of date',
      };

  /// (title, subtitle) for an M2 journal entry; time labels follow gate R2
  /// §1.2 ("recorded at" for outcomes, "detected at" for health/storage).
  static (String, String) entryText(TimelineEntry e, String time) =>
      switch (e.kind) {
        TimelineEntryKind.failedUnlock => (
            e.method == FailedAttemptMethod.pattern
                ? 'Failed pattern attempt'
                : 'Failed PIN attempt',
            time,
          ),
        TimelineEntryKind.journalStarted => (
            'Security journal first used',
            '$time · $journalStartedNote',
          ),
        TimelineEntryKind.journalRecovered => (
            'Security journal was damaged and reset',
            '$time · Earlier journal events may be missing.',
          ),
        TimelineEntryKind.journalUpgraded => (
            'Security journal updated to a new format',
            '$time · Earlier journal events were kept.',
          ),
        TimelineEntryKind.captureSaved => (
            'Photo saved',
            'recorded at $time',
          ),
        TimelineEntryKind.captureNotSaved => (
            'Photo not saved · '
                '${e.captureWhy == null ? 'unexpected error' : captureWhy(e.captureWhy!)}',
            'recorded at $time',
          ),
        TimelineEntryKind.alarmStarted => (
            'Alarm started · plays up to $alarmSeconds s',
            'recorded at $time',
          ),
        TimelineEntryKind.alarmNotStarted => (
            'Alarm not started · '
                '${e.alarmWhy == null ? 'unexpected error' : alarmWhy(e.alarmWhy!)}',
            'recorded at $time',
          ),
        TimelineEntryKind.alarmStopped => (
            'Alarm stop requested',
            'recorded at $time',
          ),
        TimelineEntryKind.protectionHealth => (
            'Protection '
                '${e.healthState == null ? 'status unknown' : healthState(e.healthState!)}',
            'detected at $time'
                '${e.healthCodes.isEmpty ? '' : ' · ${e.healthCodes.map(healthCode).join(', ')}'}',
          ),
        TimelineEntryKind.storageUnavailable => (
            'Failed-unlock history storage unavailable',
            'detected at $time · '
                '${e.storageKind == StoreKind.readOnly ? 'saved by a newer version of the app' : 'couldn\'t be saved or read'}',
          ),
        TimelineEntryKind.storageRestored => (
            'Failed-unlock history storage readable again',
            'detected at $time',
          ),
        TimelineEntryKind.historyCleared => (
            clearedTitle(e.clearScope),
            e.clearPending
                ? 'on $time · not finished'
                : 'on $time · Earlier events were removed by the owner.',
          ),
        TimelineEntryKind.retentionChanged => (
            'History retention changed',
            'on $time · from ${retentionDays(e.retentionOld)} to '
                '${retentionDays(e.retentionNew)}',
          ),
        TimelineEntryKind.historyExpired => (
            'Older history removed automatically',
            '${e.expiredCount ?? 0} '
                '${e.expiredCount == 1 ? 'event' : 'events'} from '
                '${day(e.expiredFrom)} to ${day(e.expiredTo)} passed the '
                'retention period · last on $time',
          ),
      };

  static String discarded(TimelineSource s, int n) =>
      '${sourceName(s)}: $n older ${n == 1 ? 'event is' : 'events are'} no '
      'longer kept.';

  static String lost(TimelineSource s, int n) =>
      '${sourceName(s)}: $n ${n == 1 ? 'event' : 'events'} couldn\'t be '
      'recorded.';

  static String damaged(TimelineSource s) =>
      '${sourceName(s)}: earlier history was damaged and couldn\'t be kept.';

  static String integrityUnknown(TimelineSource s) =>
      '${sourceName(s)}: couldn\'t confirm that earlier history is intact.';
}

Future<bool> openSecurityTimeline(
  BuildContext context,
  AppContainer container,
) async {
  final NavigatorState navigator = Navigator.of(context);
  final AuthType? method = await verifyIntruderOwner(navigator, container.auth);
  if (method == null) return false;
  final IntruderOwnerSession session =
      container.securityTimelineSessions.begin(method);
  try {
    await navigator.push<void>(MaterialPageRoute<void>(
      settings: const RouteSettings(name: securityTimelineRouteName),
      builder: (_) =>
          SecurityTimelineScreen(container: container, session: session),
    ));
  } finally {
    session.invalidate('closed');
  }
  return true;
}

String _fmtTime(DateTime t) {
  String two(int v) => v.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)} '
      '${two(t.hour)}:${two(t.minute)}';
}

class SecurityTimelineScreen extends StatefulWidget {
  const SecurityTimelineScreen({
    super.key,
    required this.container,
    required this.session,
  });

  final AppContainer container;
  final IntruderOwnerSession session;

  @override
  State<SecurityTimelineScreen> createState() => _SecurityTimelineScreenState();
}

class _SecurityTimelineScreenState extends State<SecurityTimelineScreen>
    with WidgetsBindingObserver {
  SecurityTimelineSnapshot? _snapshot;
  int _visible = SecurityTimelineReader.pageSize;
  bool _secureFailed = false;
  bool _closing = false;
  bool _covered = false;
  bool _paging = false;
  int _loadOp = 0;

  /// Batch 4: the Clear History flow (dialog / verification / steps) runs.
  bool _clearing = false;

  /// M2: the timeline's own details route while it is pushed.
  Route<void>? _detailRoute;

  /// M2: history was dropped because the own details route covered the
  /// timeline; a secure reload must run before anything renders again.
  bool _reloadOnSurface = false;
  Timer? _expiry;
  StreamSubscription<Result<ScreenStateEvent>>? _screen;

  IntruderOwnerSession get session => widget.session;

  void _onInvalidated(String reason) {
    // Drop history from memory now; navigation happens in a microtask
    // (listeners may fire during build).
    _snapshot = null;
    _loadOp++;
    scheduleMicrotask(() {
      if (mounted) _onSessionEnded();
    });
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    session.addListener(_onInvalidated);
    if (!session.isValid) _onInvalidated('expired');
    _expiry = Timer(session.remaining, () => session.invalidate('expired'));
    _screen = widget.container.screenState.events.listen(
      (Result<ScreenStateEvent> r) {
        if (r.isFailure || r.valueOrNull == ScreenStateEvent.screenOff) {
          session.invalidate('screenOff');
        }
      },
      onError: (Object _) => session.invalidate('screenStateError'),
      // W-03: an unexpected end of the screen-state stream means screen-off
      // can no longer arrive: fail closed (the session ends, pixels drop).
      onDone: () => session.invalidate('screenStateClosed'),
    );
    unawaited(_load());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) {
      session.invalidate('lifecycle:${state.name}');
    }
  }

  void _onSessionEnded() {
    if (_closing) return;
    setState(() => _snapshot = null);
    final ModalRoute<Object?>? me = ModalRoute.of(context);
    if (me == null || !me.isActive) {
      _closing = true; // already leaving
      return;
    }
    final NavigatorState navigator = Navigator.of(context);
    if (!me.isCurrent && _clearing) {
      // Batch 4: the session ended during the Clear History flow; its own
      // dialog / verification routes close with it (no step runs after).
      navigator
          .popUntil((Route<dynamic> r) => !isSecurityTimelineClearFlowRoute(r));
    }
    if (!me.isCurrent) return; // covered: close when it surfaces again
    _closing = true;
    final ScaffoldMessengerState? messenger =
        ScaffoldMessenger.maybeOf(context);
    navigator.pop();
    messenger?.hideCurrentSnackBar();
    messenger?.showSnackBar(
      const SnackBar(content: Text(SecurityTimelineText.sessionEnded)),
    );
  }

  Future<void> _load() async {
    final int op = ++_loadOp;
    final AppContainer c = widget.container;
    if (!session.isValid) return;
    final Result<void> secure = await c.overlay.setSecureWindow(true);
    if (!mounted || !session.isValid || op != _loadOp) return;
    if (secure.isFailure) {
      setState(() => _secureFailed = true); // fail closed: nothing is read
      return;
    }
    if (!await intruderOwnerStillCurrent(c.auth, session.method)) {
      session.invalidate('credentialChanged');
      return;
    }
    if (!mounted || !session.isValid || op != _loadOp) return;
    final SecurityTimelineSnapshot snap = await c.securityTimeline.load();
    if (!mounted || !session.isValid || op != _loadOp) return;
    setState(() => _snapshot = snap);
  }

  Future<void> _showOlder() async {
    if (_paging || !session.isValid) return;
    _paging = true;
    try {
      final AppContainer c = widget.container;
      if (!await intruderOwnerStillCurrent(c.auth, session.method)) {
        session.invalidate('credentialChanged');
        return;
      }
      if (!mounted || !session.isValid) return;
      setState(() => _visible += SecurityTimelineReader.pageSize);
    } finally {
      _paging = false;
    }
  }

  @override
  void dispose() {
    _expiry?.cancel();
    unawaited(_screen?.cancel());
    WidgetsBinding.instance.removeObserver(this);
    session.removeListener(_onInvalidated);
    session.invalidate('closed');
    _snapshot = null;
    super.dispose();
  }

  /// Cover tracking (called from build; acts in a microtask). The timeline
  /// pushes no routes of its own, so any route above it is foreign.
  void _trackCover(ModalRoute<Object?>? me) {
    final bool top = me?.isCurrent ?? false;
    if (!top && !_covered) {
      _covered = true;
      scheduleMicrotask(() {
        if (!mounted) return;
        final ModalRoute<Object?>? r = ModalRoute.of(context);
        if (r != null && r.isActive && !r.isCurrent && _ownDetailOnTop()) {
          _dropForOwnRoute(); // own details route: keep the session
          return;
        }
        if (r != null && r.isActive && !r.isCurrent && _ownClearFlowOnTop()) {
          _dropForOwnRoute(); // own clear dialog / verification
          return;
        }
        if (r != null && r.isActive && !r.isCurrent) {
          session.invalidate('covered');
        }
      });
    } else if (top && _covered) {
      _covered = false;
      scheduleMicrotask(() {
        if (mounted && !session.isValid) _onSessionEnded();
        if (mounted && session.isValid && _reloadOnSurface) {
          _reloadOnSurface = false;
          unawaited(_load()); // FLAG_SECURE -> re-check -> load
        }
      });
    }
  }

  bool _ownClearFlowOnTop() {
    if (!_clearing) return false;
    final Route<Object?>? t = _topRoute(Navigator.of(context));
    return t != null && isSecurityTimelineClearFlowRoute(t);
  }

  // -- Batch 4: Clear History ----------------------------------------------

  /// Explicit confirmation -> fresh owner verification -> clear. Every step
  /// re-checks the session; nothing is written unless the owner confirmed
  /// AND verified within this still-valid session.
  Future<void> _clearHistory() async {
    if (_clearing || !session.isValid || _snapshot == null) return;
    _clearing = true;
    try {
      final bool? photos = await _confirmClear();
      if (photos == null || !mounted || !session.isValid) {
        if (mounted && session.isValid) {
          _snack(SecurityTimelineText.clearNotDone);
        }
        return;
      }
      final HistoryClearOutcome? r = await _verifiedRun(
          (bool Function() valid) => widget.container.historyClear
              .clear(photos: photos, stillValid: valid));
      _report(r);
    } finally {
      _clearing = false;
    }
  }

  Future<void> _finishClear() async {
    if (_clearing || !session.isValid || _snapshot == null) return;
    _clearing = true;
    try {
      final HistoryClearOutcome? r = await _verifiedRun(
          (bool Function() valid) =>
              widget.container.historyClear.finish(stillValid: valid));
      _report(r);
    } finally {
      _clearing = false;
    }
  }

  /// Fresh verification (a cached session never counts), same credential as
  /// the session, then [run]. Null: not verified / session ended.
  Future<HistoryClearOutcome?> _verifiedRun(
      Future<HistoryClearOutcome> Function(bool Function() valid) run) async {
    final AppContainer c = widget.container;
    final AuthType? method =
        await verifyIntruderOwner(Navigator.of(context), c.auth);
    if (method == null || !mounted || !session.isValid) return null;
    if (session.method != method) {
      session.invalidate('credentialChanged');
      return null;
    }
    bool valid() => mounted && session.isValid;
    final HistoryClearOutcome r = await run(valid);
    if (mounted && session.isValid) await _load();
    return r;
  }

  void _report(HistoryClearOutcome? r) {
    if (!mounted || !session.isValid) return;
    _snack(switch (r) {
      null ||
      HistoryClearOutcome.cancelled =>
        SecurityTimelineText.clearNotDone,
      HistoryClearOutcome.done => SecurityTimelineText.cleared,
      HistoryClearOutcome.refused => SecurityTimelineText.clearRefused,
      HistoryClearOutcome.failed => SecurityTimelineText.clearFailed,
      HistoryClearOutcome.interrupted => SecurityTimelineText.clearInterrupted,
    });
  }

  void _snack(String text) {
    final ScaffoldMessengerState? m = ScaffoldMessenger.maybeOf(context);
    m?.hideCurrentSnackBar();
    m?.showSnackBar(SnackBar(content: Text(text)));
  }

  /// Null = cancelled; otherwise whether photos are included (default off).
  Future<bool?> _confirmClear() => showDialog<bool>(
        context: context,
        routeSettings:
            const RouteSettings(name: securityTimelineClearRouteName),
        builder: (BuildContext ctx) => const _ClearHistoryDialog(),
      );

  bool _ownDetailOnTop() {
    final Route<void>? d = _detailRoute;
    return d != null && d.isCurrent && isSecurityTimelineFlowRoute(d);
  }

  void _dropForOwnRoute() {
    _loadOp++;
    _reloadOnSurface = true;
    setState(() {
      _snapshot = null; // nothing is kept while covered
    });
  }

  Future<void> _openDetails(TimelineRow row) async {
    final SecurityTimelineSnapshot? snap = _snapshot;
    if (snap == null || !session.isValid || _detailRoute != null) return;
    final Route<void> route = MaterialPageRoute<void>(
      settings: const RouteSettings(name: securityTimelineDetailRouteName),
      builder: (_) => SecurityTimelineDetailScreen(
        container: widget.container,
        session: session,
        data: SecurityTimelineDetailData(row, snap.labels,
            failureLogDamaged: failureLogDamagedEarlier(snap)),
      ),
    );
    _detailRoute = route;
    try {
      await Navigator.of(context).push<void>(route);
    } finally {
      _detailRoute = null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final ModalRoute<Object?>? me = ModalRoute.of(context);
    _trackCover(me);
    final bool show = session.isValid && !_covered && (me?.isCurrent ?? false);
    final SecurityTimelineSnapshot? snap = show ? _snapshot : null;
    final Widget body;
    if (!show) {
      body = const SizedBox.shrink();
    } else if (_secureFailed) {
      body = const _Message(
        SecurityTimelineText.secureFailed,
        key: Key('security_timeline_secure_failed'),
      );
    } else if (snap == null) {
      body = const _Message(SecurityTimelineText.loading);
    } else {
      body = _TimelineList(
        snapshot: snap,
        visible: _visible,
        onShowOlder: _showOlder,
        onDetails: _openDetails,
        onFinishClear: _finishClear,
      );
    }
    final bool canClear = snap != null && !_secureFailed;
    return Scaffold(
      appBar: AppBar(
        title: const Text(SecurityTimelineText.title),
        actions: <Widget>[
          if (canClear)
            IconButton(
              key: const Key('security_timeline_clear'),
              tooltip: SecurityTimelineText.clearAction,
              icon: const Icon(Icons.delete_sweep_outlined),
              onPressed: _clearHistory,
            ),
        ],
      ),
      body: body,
    );
  }
}

class _TimelineList extends StatelessWidget {
  const _TimelineList({
    required this.snapshot,
    required this.visible,
    required this.onShowOlder,
    required this.onDetails,
    required this.onFinishClear,
  });

  final SecurityTimelineSnapshot snapshot;
  final int visible;
  final VoidCallback onShowOlder;
  final void Function(TimelineRow row) onDetails;
  final VoidCallback onFinishClear;

  @override
  Widget build(BuildContext context) {
    final List<Widget> rows = <Widget>[];
    if (snapshot.historyClearPending) {
      rows.add(ListTile(
        key: const Key('security_timeline_clear_pending'),
        leading: const Icon(Icons.pending_actions_outlined),
        title: const Text(SecurityTimelineText.clearPendingNotice),
        subtitle: Align(
          alignment: Alignment.centerLeft,
          child: TextButton(
            key: const Key('security_timeline_clear_finish'),
            onPressed: onFinishClear,
            child: const Text(SecurityTimelineText.clearFinish),
          ),
        ),
      ));
    }
    for (final TimelineSourceStatus s in snapshot.sources) {
      if (!s.available) {
        rows.add(_Notice(
          key: Key('security_timeline_unavailable_${s.source.name}'),
          icon: Icons.error_outline,
          text: SecurityTimelineText.unavailable(s.source, s.state),
        ));
      }
      if (s.damagedEarlier == true) {
        rows.add(_Notice(
          key: Key('security_timeline_damaged_${s.source.name}'),
          icon: Icons.report_outlined,
          text: SecurityTimelineText.damaged(s.source),
        ));
      } else if (s.damagedEarlier == null) {
        rows.add(_Notice(
          key: Key('security_timeline_integrity_unknown_${s.source.name}'),
          icon: Icons.help_outline,
          text: SecurityTimelineText.integrityUnknown(s.source),
        ));
      }
      if (s.discarded > 0) {
        rows.add(_Notice(
          key: Key('security_timeline_discarded_${s.source.name}'),
          icon: Icons.history_toggle_off,
          text: SecurityTimelineText.discarded(s.source, s.discarded),
        ));
      }
      if (s.lost > 0) {
        rows.add(_Notice(
          key: Key('security_timeline_lost_${s.source.name}'),
          icon: Icons.warning_amber_outlined,
          text: SecurityTimelineText.lost(s.source, s.lost),
        ));
      }
    }
    if (snapshot.resetPending) {
      rows.add(const _Notice(
        key: Key('security_timeline_reset_pending'),
        icon: Icons.info_outline,
        text: SecurityTimelineText.resetPending,
      ));
    }
    if (snapshot.resetFailures > 0) {
      rows.add(_Notice(
        key: const Key('security_timeline_reset_failures'),
        icon: Icons.warning_amber_outlined,
        text: SecurityTimelineText.resetFailures(snapshot.resetFailures),
      ));
    }
    final List<TimelineEntry> entries = snapshot.entries;
    if (entries.any(
        (TimelineEntry e) => e.kind == TimelineEntryKind.protectionHealth)) {
      rows.add(const _Notice(
        key: Key('security_timeline_health_coverage'),
        icon: Icons.info_outline,
        text: SecurityTimelineText.healthCoverage,
      ));
    }
    rows.add(const _Notice(
      key: Key('security_timeline_photo_link'),
      icon: Icons.photo_library_outlined,
      text: SecurityTimelineText.photoLink,
    ));
    if (snapshot.confirmedEmpty) {
      rows.add(const Padding(
        key: Key('security_timeline_empty'),
        padding: EdgeInsets.all(DsSpacing.xl),
        child: Text(SecurityTimelineText.empty, textAlign: TextAlign.center),
      ));
    }
    final List<TimelineRow> all = buildTimelineRows(entries);
    final int shown = visibleRowCount(all, visible);
    for (int i = 0; i < shown; i++) {
      final TimelineRow r = all[i];
      switch (r) {
        case TimelineFailureGroup():
          rows.add(_GroupHeader(
            group: r,
            labels: snapshot.labels,
            onDetails: () => onDetails(r),
          ));
          final int inline =
              r.count < SecurityTimelineGrouping.maxInlineAttempts
                  ? r.count
                  : SecurityTimelineGrouping.maxInlineAttempts;
          for (int k = 0; k < inline; k++) {
            rows.add(_EntryTile(r.attempts[k], labels: snapshot.labels));
          }
          if (r.count > inline) {
            rows.add(Padding(
              key: Key('security_timeline_group_more_${r.lastSeq}'),
              padding: const EdgeInsets.symmetric(
                  horizontal: DsSpacing.lg, vertical: DsSpacing.sm),
              child: Text(SecurityTimelineText.moreInDetails(r.count - inline)),
            ));
          }
        case TimelineEntryRow(:final TimelineEntry entry):
          final bool m2 = entry.source == TimelineSource.journal &&
              entry.kind.index > TimelineEntryKind.journalRecovered.index &&
              entry.kind != TimelineEntryKind.historyCleared &&
              entry.kind != TimelineEntryKind.retentionChanged &&
              entry.kind != TimelineEntryKind.historyExpired;
          rows.add(_EntryTile(
            entry,
            labels: snapshot.labels,
            detached: r.detachedOutcome,
            onTap: m2 ? () => onDetails(r) : null,
          ));
      }
      rows.add(const Divider(height: 1));
    }
    if (shown < all.length) {
      rows.add(Center(
        child: TextButton(
          key: const Key('security_timeline_show_older'),
          onPressed: onShowOlder,
          child: const Text(SecurityTimelineText.showOlder),
        ),
      ));
    }
    rows.add(const Padding(
      key: Key('security_timeline_footer'),
      padding: EdgeInsets.all(DsSpacing.lg),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(SecurityTimelineText.footer),
          SizedBox(height: DsSpacing.sm),
          Text(SecurityTimelineText.footerProcessDeath,
              key: Key('security_timeline_footer_process_death')),
        ],
      ),
    ));
    return ListView(
      key: const Key('security_timeline_list'),
      children: rows,
    );
  }
}

/// Group header (key deliberately NOT `security_timeline_entry_…`).
class _GroupHeader extends StatelessWidget {
  const _GroupHeader({
    required this.group,
    required this.labels,
    required this.onDetails,
  });

  final TimelineFailureGroup group;
  final Map<String, String> labels;
  final VoidCallback onDetails;

  @override
  Widget build(BuildContext context) {
    final TimelineFailureGroup g = group;
    final String apps = g.packages
        .map((String? p) => SecurityTimelineText.appLabel(p, labels))
        .join(', ');
    final String span = g.count == 1
        ? _fmtTime(g.lastAt)
        : '${_fmtTime(g.firstAt)} – ${_fmtTime(g.lastAt)}';
    final List<String> badges = <String>[
      if (g.lockouts == 1) 'Cooldown started',
      if (g.lockouts > 1) 'Cooldown started ×${g.lockouts}',
      if (g.has(TimelineEntryKind.captureSaved)) 'Photo saved',
      if (g.has(TimelineEntryKind.captureNotSaved)) 'Photo not saved',
      if (g.has(TimelineEntryKind.alarmStarted)) 'Alarm started',
      if (g.has(TimelineEntryKind.alarmNotStarted)) 'Alarm not started',
      if (g.counterNotSaved) '⚠ attempt counter couldn\'t be saved',
    ];
    return ListTile(
      key: Key('security_timeline_group_failedAttempts_${g.lastSeq}'),
      leading: const Icon(Icons.lock_outline),
      title: Text('${SecurityTimelineText.attempts(g.count)} · $apps · $span'),
      subtitle: badges.isEmpty ? null : Text(badges.join(' · ')),
      trailing: TextButton(
        key: Key('security_timeline_group_details_${g.lastSeq}'),
        onPressed: onDetails,
        child: const Text(SecurityTimelineText.details),
      ),
    );
  }
}

class _EntryTile extends StatelessWidget {
  const _EntryTile(
    this.e, {
    this.labels = const <String, String>{},
    this.detached = false,
    this.onTap,
  });

  final TimelineEntry e;
  final Map<String, String> labels;
  final bool detached;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final IconData icon = switch (e.kind) {
      TimelineEntryKind.failedUnlock => Icons.lock_outline,
      TimelineEntryKind.journalStarted => Icons.play_circle_outline,
      TimelineEntryKind.journalRecovered => Icons.report_outlined,
      TimelineEntryKind.journalUpgraded => Icons.upgrade,
      TimelineEntryKind.captureSaved => Icons.photo_camera_outlined,
      TimelineEntryKind.captureNotSaved => Icons.no_photography_outlined,
      TimelineEntryKind.alarmStarted ||
      TimelineEntryKind.alarmNotStarted ||
      TimelineEntryKind.alarmStopped =>
        Icons.notifications_active_outlined,
      TimelineEntryKind.protectionHealth => Icons.shield_outlined,
      TimelineEntryKind.storageUnavailable ||
      TimelineEntryKind.storageRestored =>
        Icons.storage_outlined,
      TimelineEntryKind.historyCleared => Icons.delete_sweep_outlined,
      TimelineEntryKind.retentionChanged => Icons.schedule_outlined,
      TimelineEntryKind.historyExpired => Icons.history_toggle_off,
    };
    final String time = _fmtTime(e.at);
    final (String title, String text) = SecurityTimelineText.entryText(e, time);
    final String subtitle = e.kind == TimelineEntryKind.failedUnlock
        ? '$time · '
            '${e.surface == AuthAttemptSurface.protectedAppChallenge ? (e.packageName == null ? 'Protected app' : SecurityTimelineText.appLabel(e.packageName, labels)) : 'Smart App Lock'}'
            '${e.lockoutTriggered ? ' · lock-out started' : ''}'
        : text;
    return ListTile(
      key: Key('security_timeline_entry_${e.source.name}_${e.sourceSeq}'),
      leading: Icon(icon),
      title: Text(title),
      subtitle: Text(detached
          ? '$subtitle\n${SecurityTimelineText.detachedOutcome}'
          : subtitle),
      onTap: onTap,
    );
  }
}

class _Notice extends StatelessWidget {
  const _Notice({super.key, required this.icon, required this.text});

  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) => ListTile(
        leading: Icon(icon),
        title: Text(text),
      );
}

class _Message extends StatelessWidget {
  const _Message(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(DsSpacing.xl),
          child: Text(text, textAlign: TextAlign.center),
        ),
      );
}

/// Batch 4: explicit confirmation with the photos opt-in (default off).
/// Pops null (cancel) or whether photos are included.
class _ClearHistoryDialog extends StatefulWidget {
  const _ClearHistoryDialog();

  @override
  State<_ClearHistoryDialog> createState() => _ClearHistoryDialogState();
}

class _ClearHistoryDialogState extends State<_ClearHistoryDialog> {
  bool _photos = false;

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: const Text(SecurityTimelineText.clearTitle),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              const Text(SecurityTimelineText.clearBody),
              const SizedBox(height: DsSpacing.md),
              CheckboxListTile(
                key: const Key('security_timeline_clear_photos'),
                contentPadding: EdgeInsets.zero,
                value: _photos,
                onChanged: (bool? v) => setState(() => _photos = v ?? false),
                title: const Text(SecurityTimelineText.clearPhotos),
                subtitle: const Text(SecurityTimelineText.clearPhotosNote),
              ),
            ],
          ),
        ),
        actions: <Widget>[
          TextButton(
            key: const Key('security_timeline_clear_cancel'),
            onPressed: () => Navigator.of(context).pop(),
            child: const Text(SecurityTimelineText.clearCancel),
          ),
          TextButton(
            key: const Key('security_timeline_clear_confirm'),
            onPressed: () => Navigator.of(context).pop(_photos),
            child: const Text(SecurityTimelineText.clearConfirm),
          ),
        ],
      );
}
