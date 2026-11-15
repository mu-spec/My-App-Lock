// Phase 13 / Milestone 2 — Security timeline details (owner-only).
//
// Reachable ONLY from a timeline row tap (MaterialPageRoute named
// [securityTimelineDetailRouteName]; deliberately NOT registered in the app
// router — no deep link). It uses the timeline's OWN session (never begins
// one), and renders nothing until FLAG_SECURE is enabled and the credential
// re-check passed; a FLAG_SECURE failure fails closed. Any route above the
// details is foreign and ends the session; foreign routes are never popped.
// On session end the data box is cleared and the route closes when current.
//
// "View photo" (an ATTACHED captureSaved only, while the failed-attempt
// history is known undamaged — F-CL-1 metadata safety) first ENDS the timeline session, then
// delegates to the Phase 12 viewer entry, which performs its own fresh
// verification and begins a separate evidence session. This screen never
// reads the evidence store and never renders an image.
//
// Metadata only. No share, export, clipboard, selection, file or log
// output. FLAG_SECURE is never cleared here.

import 'dart:async';

import 'package:flutter/material.dart';

import '../../../app/app_container.dart';
import '../../../design_system/design_system.dart';
import '../../../security/intruder/intruder_owner_session.dart';
import '../../../security/timeline/security_timeline.dart';
import '../../../security/timeline/security_timeline_grouping.dart';
import '../../../services/screen_state_service.dart';
import '../../../utilities/result.dart';
import 'intruder_evidence_screen.dart';
import 'intruder_owner_verification.dart';
import 'security_timeline_screen.dart';

const String securityTimelineDetailRouteName = '/security/timeline/detail';

abstract final class SecurityTimelineDetailText {
  static const String title = 'Event details';
  static const String viewPhoto =
      'View photo (needs your PIN or pattern; it may have been deleted)';
  static const String outcomeNotRecorded =
      'Outcome not recorded. If a photo was taken, it is still listed in '
      'Intruder photos.';
  static const String counterHelp =
      'This counter may include attempts from before a restart, if a '
      'successful unlock wasn\'t saved.';
  static const String clockNote = 'Times use the device clock.';
  static const String clockBack =
      'The device clock moved backwards before this event; its position in '
      'the list may be wrong.';
  static const String firstInProcess =
      'Detected when Smart App Lock checked protection. It may have begun '
      'earlier, while the app was closed.';
  static const String biometricNote =
      'Failed fingerprint or face attempts are not recorded.';
  static String counterAtTime(int r) =>
      'Consecutive-failure counter at the time: $r';
  static String suppressed(int n) =>
      '$n protection ${n == 1 ? 'change' : 'changes'} in between '
      '${n == 1 ? 'wasn\'t' : 'weren\'t'} recorded individually.';
}

/// Immutable row + render-time labels, held in a box the details screen
/// clears when the session ends (nothing is kept).
final class SecurityTimelineDetailData {
  SecurityTimelineDetailData(this._row, Map<String, String> labels,
      {required bool? failureLogDamaged})
      : _labels = labels,
        _failureLogDamaged = failureLogDamaged;

  TimelineRow? _row;
  Map<String, String> _labels;
  bool? _failureLogDamaged;

  TimelineRow? get row => _row;
  Map<String, String> get labels => _labels;

  /// F-CL-1 metadata safety: the failed-attempt history's recovery state
  /// when the row was captured (null = unknown ⇒ no photo action).
  bool? get failureLogDamaged => _failureLogDamaged;

  void clear() {
    _row = null;
    _labels = const <String, String>{};
    _failureLogDamaged = null;
  }
}

String _fmt(DateTime t) {
  String two(int v) => v.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)} '
      '${two(t.hour)}:${two(t.minute)}';
}

class SecurityTimelineDetailScreen extends StatefulWidget {
  const SecurityTimelineDetailScreen({
    super.key,
    required this.container,
    required this.session,
    required this.data,
  });

  final AppContainer container;
  final IntruderOwnerSession session;
  final SecurityTimelineDetailData data;

  @override
  State<SecurityTimelineDetailScreen> createState() =>
      _SecurityTimelineDetailScreenState();
}

class _SecurityTimelineDetailScreenState
    extends State<SecurityTimelineDetailScreen> with WidgetsBindingObserver {
  bool _ready = false;
  bool _secureFailed = false;
  bool _closing = false;
  bool _covered = false;
  int _prepOp = 0;
  StreamSubscription<Result<ScreenStateEvent>>? _screen;

  IntruderOwnerSession get session => widget.session;

  void _onInvalidated(String reason) {
    widget.data.clear();
    _ready = false;
    _prepOp++;
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
    unawaited(_prepare());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) {
      session.invalidate('lifecycle:${state.name}');
    }
  }

  /// FLAG_SECURE -> credential re-check -> render. Runs on open and on
  /// every surfacing.
  Future<void> _prepare() async {
    final int op = ++_prepOp;
    final AppContainer c = widget.container;
    if (!session.isValid) return;
    final Result<void> secure = await c.overlay.setSecureWindow(true);
    if (!mounted || !session.isValid || op != _prepOp) return;
    if (secure.isFailure) {
      setState(() => _secureFailed = true); // fail closed: nothing renders
      return;
    }
    final bool current =
        await intruderOwnerStillCurrent(c.auth, session.method);
    if (!mounted || !session.isValid || op != _prepOp) return;
    if (!current) {
      session.invalidate('credentialChanged');
      return;
    }
    setState(() => _ready = true);
  }

  void _onSessionEnded() {
    if (_closing) return;
    setState(() {
      _ready = false;
      widget.data.clear();
    });
    final ModalRoute<Object?>? me = ModalRoute.of(context);
    if (me == null || !me.isActive) {
      _closing = true;
      return;
    }
    if (!me.isCurrent) return; // covered: close when it surfaces again
    _closing = true;
    Navigator.of(context).pop();
  }

  /// Any route above the details is foreign: it ends the session.
  void _trackCover(ModalRoute<Object?>? me) {
    final bool top = me?.isCurrent ?? false;
    if (!top && !_covered) {
      _covered = true;
      scheduleMicrotask(() {
        if (!mounted) return;
        final ModalRoute<Object?>? r = ModalRoute.of(context);
        if (r != null && r.isActive && !r.isCurrent) {
          session.invalidate('covered');
        }
      });
    } else if (top && _covered) {
      _covered = false;
      scheduleMicrotask(() {
        if (!mounted) return;
        if (!session.isValid) {
          _onSessionEnded();
        } else {
          _ready = false;
          unawaited(_prepare());
        }
      });
    }
  }

  Future<void> _viewPhoto(TimelineRow row, TimelineEntry e) async {
    final int? trig = e.trig;
    if (!session.isValid || trig == null) return;
    // Re-checked at the action (defence in depth; same predicate).
    if (!timelinePhotoActionAllowed(row, e,
        failureLogDamaged: widget.data.failureLogDamaged)) {
      return;
    }
    // Q-M2-8 A: the timeline session ends BEFORE any verification route.
    session.invalidate('evidenceOpened');
    await openIntruderEvidenceForSeq(context, widget.container, trig);
  }

  @override
  void dispose() {
    unawaited(_screen?.cancel());
    WidgetsBinding.instance.removeObserver(this);
    session.removeListener(_onInvalidated);
    widget.data.clear();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final ModalRoute<Object?>? me = ModalRoute.of(context);
    _trackCover(me);
    final bool show = session.isValid &&
        !_covered &&
        (me?.isCurrent ?? false) &&
        _ready &&
        !_secureFailed;
    final TimelineRow? row = show ? widget.data.row : null;
    final Widget body;
    if (_secureFailed && session.isValid) {
      body = const _Msg(
        SecurityTimelineText.secureFailed,
        key: Key('security_timeline_detail_secure_failed'),
      );
    } else if (row == null) {
      body = const SizedBox.shrink();
    } else {
      body = ListView(
        key: const Key('security_timeline_detail_list'),
        children: _content(row, widget.data.labels),
      );
    }
    return Scaffold(
      appBar: AppBar(title: const Text(SecurityTimelineDetailText.title)),
      body: body,
    );
  }

  List<Widget> _content(TimelineRow row, Map<String, String> labels) {
    final List<Widget> out = <Widget>[];
    switch (row) {
      case TimelineFailureGroup():
        out.add(ListTile(
          key: Key('security_timeline_detail_group_${row.lastSeq}'),
          title: Text(SecurityTimelineText.attempts(row.count)),
          subtitle: Text(row.packages
              .map((String? p) => SecurityTimelineText.appLabel(p, labels))
              .join(', ')),
        ));
        for (final TimelineEntry a in row.attempts) {
          out.add(_attempt(a, labels));
        }
        if (row.outcomes.isEmpty) {
          out.add(const ListTile(
            key: Key('security_timeline_detail_outcome_not_recorded'),
            title: Text(SecurityTimelineDetailText.outcomeNotRecorded),
          ));
        }
        for (final TimelineEntry o in row.outcomes) {
          out.addAll(_journal(o, row));
        }
        out.add(const _Note(SecurityTimelineDetailText.counterHelp));
        out.add(const _Note(SecurityTimelineDetailText.biometricNote));
      case TimelineEntryRow(:final TimelineEntry entry):
        if (row.detachedOutcome) {
          out.add(const _Note(SecurityTimelineText.detachedOutcome));
        }
        out.addAll(_journal(entry, row));
    }
    out.add(const _Note(SecurityTimelineDetailText.clockNote));
    return out;
  }

  Widget _attempt(TimelineEntry a, Map<String, String> labels) {
    final (String title, _) = SecurityTimelineText.entryText(a, _fmt(a.at));
    final List<String> lines = <String>[
      'at ${_fmt(a.at)}',
      if (a.packageName != null)
        SecurityTimelineText.appLabel(a.packageName, labels),
      if (a.lockoutTriggered) 'Cooldown started',
      if (a.consecutiveFailures != null)
        SecurityTimelineDetailText.counterAtTime(a.consecutiveFailures!),
      if (!a.persisted) '⚠ attempt counter couldn\'t be saved',
    ];
    return ListTile(
      key: Key('security_timeline_detail_attempt_${a.sourceSeq}'),
      title: Text(title),
      subtitle: Text(lines.join('\n')),
    );
  }

  List<Widget> _journal(TimelineEntry e, TimelineRow row) {
    final (String title, String text) =
        SecurityTimelineText.entryText(e, _fmt(e.at));
    final List<String> extra = <String>[
      if (e.healthFirst) SecurityTimelineDetailText.firstInProcess,
      if (e.suppressed > 0) SecurityTimelineDetailText.suppressed(e.suppressed),
      if (e.clockBack) SecurityTimelineDetailText.clockBack,
    ];
    final int? trig = e.trig;
    return <Widget>[
      ListTile(
        key: Key('security_timeline_detail_event_${e.sourceSeq}'),
        title: Text(title),
        subtitle: Text(<String>[text, ...extra].join('\n')),
      ),
      // F-CL-1 metadata safety: no focusSeq lookup when the attempt
      // identity is ambiguous (detached, or failure-log recovery).
      if (trig != null &&
          timelinePhotoActionAllowed(row, e,
              failureLogDamaged: widget.data.failureLogDamaged))
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: DsSpacing.lg),
          child: TextButton(
            key: Key('security_timeline_detail_view_photo_$trig'),
            onPressed: () => _viewPhoto(row, e),
            child: const Text(SecurityTimelineDetailText.viewPhoto),
          ),
        ),
    ];
  }
}

class _Note extends StatelessWidget {
  const _Note(this.text);

  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(
            horizontal: DsSpacing.lg, vertical: DsSpacing.sm),
        child: Text(text),
      );
}

class _Msg extends StatelessWidget {
  const _Msg(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(DsSpacing.xl),
          child: Text(text, textAlign: TextAlign.center),
        ),
      );
}
