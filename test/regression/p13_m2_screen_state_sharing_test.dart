// Phase 13 / M2 — F-CL-2 (shared screen-state subscription ownership) and
// W-03 (fail-closed end-of-stream) over the PRODUCTION
// MethodChannelScreenStateService.
//
// The platform side is a deterministic fake of the Android embedding's
// EventChannel (one active sink per channel; a repeated `listen` is
// separated by `onCancel`; `cancel` without an active sink is an error;
// events are dropped after end-of-stream) plus ScreenStateChannel.kt (a
// runtime BroadcastReceiver registered in onListen, unregistered in
// onCancel). A device broadcast reaches Dart only while a receiver is
// registered — exactly as on a device.
//
// SIMULATED: no device claims. Real screen-off delivery, activity/engine
// recreation and OEM behaviour remain device-QA release blockers.

import 'dart:async';
import 'dart:math';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/models/app_security_level.dart';
import 'package:smart_app_lock/data/models/protected_app.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_owner_session.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';
import 'package:smart_app_lock/security/timeline/security_timeline_grouping.dart';
import 'package:smart_app_lock/services/impl/method_channel_screen_state_service.dart';
import 'package:smart_app_lock/services/impl/static_intruder_evidence_service.dart';
import 'package:smart_app_lock/services/impl/static_watcher_service.dart';
import 'package:smart_app_lock/services/screen_state_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/ui/screens/security/intruder_evidence_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_detail_screen.dart';
import 'package:smart_app_lock/ui/screens/security/security_timeline_screen.dart';
import 'package:smart_app_lock/utilities/result.dart';

import '../support/intruder_fixtures.dart';

const String _pin = '482916';
const String _app = 'com.example.bank';
const String _channel = 'smart_app_lock/screen_state';

/// Fake Android side: embedding EventChannel + ScreenStateChannel.kt.
class _FakeNative {
  _FakeNative(this.messenger);

  final TestDefaultBinaryMessenger messenger;
  static const MethodCodec codec = StandardMethodCodec();

  bool active = false; // embedding: activeSink != null
  bool ended = false; // embedding: the active sink has ended
  int receivers = 0; // registered BroadcastReceivers
  int maxReceivers = 0;
  int listenCalls = 0;
  int cancelCalls = 0;
  int failListens = 0; // the next N onListen calls throw
  final List<String> calls = <String>[]; // ordered listen/cancel log

  void install() {
    messenger.setMockMessageHandler(_channel, (ByteData? message) async {
      final MethodCall call = codec.decodeMethodCall(message);
      if (call.method == 'listen') {
        listenCalls++;
        calls.add('listen');
        if (active) {
          active = false; // handler.onCancel(null) before a repeated listen
          _unregister();
        }
        ended = false;
        if (failListens > 0) {
          failListens--;
          return codec.encodeErrorEnvelope(
              code: 'error', message: 'registerReceiver failed');
        }
        active = true;
        receivers++;
        maxReceivers = max(maxReceivers, receivers);
        return codec.encodeSuccessEnvelope(null);
      }
      if (call.method == 'cancel') {
        cancelCalls++;
        calls.add('cancel');
        if (!active) {
          return codec.encodeErrorEnvelope(
              code: 'error', message: 'No active stream to cancel');
        }
        active = false;
        _unregister();
        return codec.encodeSuccessEnvelope(null);
      }
      return null;
    });
  }

  void uninstall() => messenger.setMockMessageHandler(_channel, null);

  void _unregister() {
    if (receivers > 0) receivers--;
  }

  bool get delivering => active && !ended && receivers > 0;

  /// A device broadcast (dropped unless a receiver is registered).
  Future<void> broadcast(String payload) async {
    if (!delivering) return;
    await messenger.handlePlatformMessage(
        _channel, codec.encodeSuccessEnvelope(payload), (_) {});
  }

  Future<void> sendError() async {
    if (!delivering) return;
    await messenger.handlePlatformMessage(_channel,
        codec.encodeErrorEnvelope(code: 'screen_error', message: 'x'), (_) {});
  }

  Future<void> endOfStream() async {
    if (!active || ended) return;
    ended = true;
    await messenger.handlePlatformMessage(_channel, null, (_) {});
  }
}

/// One consumer of the shared stream.
class _Consumer {
  _Consumer(ScreenStateService s) {
    sub = s.events.listen(
      (Result<ScreenStateEvent> r) {
        if (r.isFailure) {
          failures++;
        } else if (r.valueOrNull == ScreenStateEvent.screenOff) {
          offs++;
        } else {
          ons++;
        }
      },
      onDone: () => done++,
    );
  }

  late final StreamSubscription<Result<ScreenStateEvent>> sub;
  int offs = 0, ons = 0, failures = 0, done = 0;
}

/// Whether a Dart inbound message handler is currently registered for the
/// screen-state channel. Probes the engine-facing channel buffer directly:
/// with a registered handler the probe is dispatched and answered at once;
/// with none it is queued (and is then drained by a throw-away listener so
/// it can never reach a later subscriber). Use only while no OPEN shared
/// controller exists (an unknown payload would surface as a failure).
Future<bool> _inboundHandlerRegistered() async {
  bool replied = false;
  ui.channelBuffers.push(
      _channel,
      const StandardMethodCodec().encodeSuccessEnvelope('probe'),
      (ByteData? _) => replied = true);
  await pumpEventQueue();
  final bool registered = replied;
  if (!registered) {
    ui.channelBuffers.setListener(_channel,
        (ByteData? _, ui.PlatformMessageResponseCallback cb) {
      cb(null);
    });
    await pumpEventQueue();
    ui.channelBuffers.clearListener(_channel);
  }
  return registered;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final TestDefaultBinaryMessenger messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  late _FakeNative native;

  setUp(() {
    native = _FakeNative(messenger)..install();
  });
  tearDown(() => native.uninstall());

  // ---------------------------------------------------------------- unit
  group('F-CL-2 service (production MethodChannelScreenStateService)', () {
    test(
        'SS-01 three consumers share ONE native registration and each '
        'receives every event exactly once', () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      final List<_Consumer> cs = <_Consumer>[
        _Consumer(s),
        _Consumer(s),
        _Consumer(s)
      ];
      await pumpEventQueue();
      expect(native.listenCalls, 1);
      expect(native.receivers, 1);
      await native.broadcast('screen_off');
      await native.broadcast('screen_on');
      await pumpEventQueue();
      for (final _Consumer c in cs) {
        expect((c.offs, c.ons, c.failures, c.done), (1, 1, 0, 0));
      }
      expect(native.maxReceivers, 1);
    });

    test(
        'SS-02 one consumer cancelling never disconnects another; the LAST '
        'cancel releases the native listener', () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      final _Consumer lockTrigger = _Consumer(s);
      await pumpEventQueue();
      final _Consumer screen = _Consumer(s);
      await pumpEventQueue();
      await screen.sub.cancel();
      await pumpEventQueue();
      expect(native.cancelCalls, 0, reason: 'a non-last cancel stays local');
      expect(native.receivers, 1);
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect(lockTrigger.offs, 1, reason: 'LockTrigger still receives');
      await lockTrigger.sub.cancel();
      await pumpEventQueue();
      expect(native.cancelCalls, 1);
      expect(native.receivers, 0, reason: 'last cancel releases');
      expect(native.active, isFalse);
    });

    test(
        'SS-03 re-subscription after release restores delivery without '
        'duplicates', () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      final _Consumer a = _Consumer(s);
      await pumpEventQueue();
      await a.sub.cancel();
      await pumpEventQueue();
      expect(native.receivers, 0);
      final _Consumer b = _Consumer(s);
      final _Consumer b2 = _Consumer(s);
      await pumpEventQueue();
      expect(native.listenCalls, 2);
      expect(native.receivers, 1);
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect((b.offs, b2.offs, a.offs), (1, 1, 0));
      expect(native.maxReceivers, 1);
      await b.sub.cancel();
      await b2.sub.cancel();
    });

    test(
        'SS-04 rapid subscriber replacement and cancellation (seeded, 300 '
        'ops, incl. last-cancel + immediate re-listen in one turn) never '
        'stop an active consumer', () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      final Random rnd = Random(2026);
      final _Consumer keeper = _Consumer(s);
      await pumpEventQueue();
      final List<_Consumer> transient = <_Consumer>[];
      int sent = 0;
      for (int i = 0; i < 300; i++) {
        final int op = rnd.nextInt(3);
        if (op == 0 || transient.isEmpty) {
          transient.add(_Consumer(s));
        } else {
          unawaited(
              transient.removeAt(rnd.nextInt(transient.length)).sub.cancel());
        }
        if (i % 10 == 9) {
          await pumpEventQueue();
          await native.broadcast('screen_off');
          sent++;
          await pumpEventQueue();
          expect(keeper.offs, sent, reason: 'op $i');
        }
      }
      for (final _Consumer c in transient) {
        await c.sub.cancel();
      }
      await pumpEventQueue();
      expect(native.receivers, 1, reason: 'keeper still registered');
      // Last cancel and an immediate re-listen in the same turn.
      unawaited(keeper.sub.cancel());
      final _Consumer next = _Consumer(s);
      await pumpEventQueue();
      expect(native.active, isTrue);
      expect(native.receivers, 1);
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect(next.offs, 1);
      expect(native.maxReceivers, 1, reason: 'never two native receivers');
      await next.sub.cancel();
      await pumpEventQueue();
      expect(native.receivers, 0);
    });

    test(
        'SS-05 a failed native activation is surfaced to every consumer, '
        'keeps the stream open, and the next consumer retries it', () async {
      native.failListens = 1;
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      final _Consumer lockTrigger = _Consumer(s);
      await pumpEventQueue();
      expect(lockTrigger.failures, 1, reason: 'never swallowed');
      expect(lockTrigger.done, 0);
      expect(native.receivers, 0);
      final _Consumer screen = _Consumer(s);
      await pumpEventQueue();
      expect(native.listenCalls, 2, reason: 'retried');
      expect(native.receivers, 1);
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect((lockTrigger.offs, screen.offs), (1, 1));
      await screen.sub.cancel();
      await lockTrigger.sub.cancel();
    });

    test(
        'SS-06 a native error event reaches every consumer as one failure; '
        'later events are still delivered', () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      final _Consumer a = _Consumer(s), b = _Consumer(s);
      await pumpEventQueue();
      await native.sendError();
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect((a.failures, a.offs, a.done), (1, 1, 0));
      expect((b.failures, b.offs, b.done), (1, 1, 0));
      await a.sub.cancel();
      await b.sub.cancel();
    });

    test(
        'SS-07 end-of-stream: every consumer gets onDone once, native is '
        'released, and a successor subscribing inside onDone keeps its own '
        'registration', () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      _Consumer? successor;
      final _Consumer a = _Consumer(s);
      int bDone = 0;
      s.events.listen((_) {}, onDone: () {
        bDone++;
        successor = _Consumer(s); // re-subscribe from onDone
      });
      await pumpEventQueue();
      await native.endOfStream();
      await pumpEventQueue();
      expect((a.done, bDone), (1, 1));
      expect(successor, isNotNull);
      expect(native.active, isTrue, reason: 'successor registered');
      expect(native.receivers, 1);
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect(successor!.offs, 1);
      expect(a.offs, 0);
      await successor!.sub.cancel();
      await pumpEventQueue();
      expect(native.receivers, 0);
      // Without a successor, end-of-stream alone releases the receiver.
      final _Consumer c = _Consumer(s);
      await pumpEventQueue();
      expect(native.receivers, 1);
      await native.endOfStream();
      await pumpEventQueue();
      expect(c.done, 1);
      expect(native.receivers, 0, reason: 'released on end-of-stream');
    });

    test(
        'SS-08 ownership takeover race: a successor subscribed from the FIRST '
        "consumer's onDone keeps the native registration when the old "
        "controller's final cancellation runs afterwards", () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      _Consumer? successor;
      int firstDone = 0, secondDone = 0;
      bool secondPendingWhenSuccessorSubscribed = false;
      // Consumer 1 (first listener) re-subscribes from its onDone.
      final StreamSubscription<Result<ScreenStateEvent>> first =
          s.events.listen((_) {}, onDone: () {
        firstDone++;
        // The original controller still has consumer 2 pending: its final
        // cancellation (onCancel) has NOT run yet.
        secondPendingWhenSuccessorSubscribed = secondDone == 0;
        successor = _Consumer(s);
      });
      // Consumer 2 (second listener) — the original controller's last.
      final StreamSubscription<Result<ScreenStateEvent>> second =
          s.events.listen((_) {}, onDone: () => secondDone++);
      await pumpEventQueue();
      expect(native.calls, <String>['listen']);
      expect(native.receivers, 1);

      await native.endOfStream();
      await pumpEventQueue();

      expect((firstDone, secondDone), (1, 1));
      expect(successor, isNotNull);
      expect(secondPendingWhenSuccessorSubscribed, isTrue,
          reason: 'the race must be constructed: successor subscribed '
              "before the old controller's final cancellation");
      // end-of-stream released the old owner once; the successor listened.
      // No stale cancel after the successor's listen.
      expect(native.calls, <String>['listen', 'cancel', 'listen'],
          reason: 'no stale cancellation may release the successor');
      expect(native.active, isTrue, reason: 'successor is the native owner');
      expect(native.receivers, 1, reason: 'exactly one native receiver');
      expect(native.maxReceivers, 1);
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect(successor!.offs, 1, reason: 'successor receives screen_off');
      expect(successor!.done, 0);
      await successor!.sub.cancel();
      await pumpEventQueue();
      expect(native.calls, <String>['listen', 'cancel', 'listen', 'cancel']);
      expect(native.receivers, 0);
      await first.cancel();
      await second.cancel();
    });

    test(
        'SS-09 a consumer PAUSED at end-of-stream: the native receiver and '
        'the inbound handler are released before it resumes; onDone exactly '
        'once after resume; no duplicate release or registration leak',
        () async {
      final MethodChannelScreenStateService s =
          MethodChannelScreenStateService();
      final _Consumer c = _Consumer(s);
      await pumpEventQueue();
      expect(native.calls, <String>['listen']);
      expect(native.receivers, 1);
      c.sub.pause();
      // The end-of-stream handler awaits the close, which completes only
      // once the paused consumer has taken its done event — do not await.
      bool eosHandled = false;
      final Future<void> eos =
          native.endOfStream().then((_) => eosHandled = true);
      await pumpEventQueue();

      // BEFORE resuming.
      expect(c.done, 0, reason: 'paused: done is still buffered');
      expect(native.calls, <String>['listen', 'cancel'],
          reason: 'released at end-of-stream, not deferred to resume');
      expect(native.active, isFalse);
      expect(native.receivers, 0, reason: 'native receiver released');
      expect(await _inboundHandlerRegistered(), isFalse,
          reason: 'inbound handler cleared');

      c.sub.resume();
      await pumpEventQueue();
      await eos;
      expect(eosHandled, isTrue);
      expect(c.done, 1, reason: 'onDone exactly once');
      expect((c.offs, c.ons, c.failures), (0, 0, 0));
      expect(native.calls, <String>['listen', 'cancel'],
          reason: 'no duplicate release after resume');
      expect(native.receivers, 0);
      expect(await _inboundHandlerRegistered(), isFalse);

      // No leak: a fresh consumer registers exactly once and is served.
      final _Consumer next = _Consumer(s);
      await pumpEventQueue();
      expect(native.calls, <String>['listen', 'cancel', 'listen']);
      expect(native.receivers, 1);
      expect(native.maxReceivers, 1);
      await native.broadcast('screen_off');
      await pumpEventQueue();
      expect((next.offs, c.offs, c.done), (1, 0, 1));
      await next.sub.cancel();
      await pumpEventQueue();
      expect(native.receivers, 0);
    });
  });

  // ---------------------------------------------------------- integration
  group('F-CL-2 / W-03 integration (real LockTrigger + screens)', () {
    late AppContainer c;
    int imageFrames = 0;

    Finder image() => find.byKey(const Key('intruder_evidence_image'));
    StaticWatcherService watcher() => c.watcher as StaticWatcherService;
    NavigatorState nav(WidgetTester t) =>
        t.state<NavigatorState>(find.byType(Navigator).first);

    Future<void> frames(WidgetTester t, [int n = 30]) async {
      for (int i = 0; i < n; i++) {
        await t.pump(const Duration(milliseconds: 16));
        if (image().evaluate().isNotEmpty) imageFrames++;
      }
    }

    Future<void> settle(WidgetTester t) async {
      await frames(t);
      await t.pumpAndSettle();
    }

    Future<void> typePin(WidgetTester t) async {
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      await frames(t, 16);
      for (final String d in _pin.split('')) {
        await t.tap(find.byKey(Key('pin_key_$d')));
        await frames(t, 3);
      }
      await settle(t);
    }

    /// Screen-off through the native fake; returns LockTrigger's revocation
    /// delta (StaticWatcherService.revokeAllAuthorizations is called by
    /// LockTrigger's Phase 5K screen-off path only).
    Future<int> screenOff(WidgetTester t) async {
      final int before = watcher().revokeAllAuthorizationsCalls;
      await t.runAsync(() => native.broadcast('screen_off'));
      await settle(t);
      return watcher().revokeAllAuthorizationsCalls - before;
    }

    Future<void> boot(WidgetTester t) async {
      imageFrames = 0;
      c = AppContainer.inMemory(
          intruderEvidence: StaticIntruderEvidenceService(),
          screenState: MethodChannelScreenStateService());
      t.view.physicalSize = const Size(800, 2400);
      t.view.devicePixelRatio = 1.0;
      addTearDown(t.view.reset);
      await t.pumpWidget(SmartAppLockApp(container: c));
      await t.pumpAndSettle();
      await c.auth.enrollPin(_pin);
      await c.protectedApps.add(ProtectedApp(
        packageName: _app,
        label: _app,
        addedAt: DateTime(2026, 10, 22),
        securityLevel: AppSecurityLevel.defaultLevel,
      ));
      await c.protectionBootstrap.synchronize();
      await c.intruderStartup;
      await c.securityJournalStartup;
      for (int i = 0; i < 2; i++) {
        await c.auth.authenticatePin('000000');
      }
      await c.intruderMonitor.idle();
      expect(await c.intruderEvidence.save(seq: 1, jpeg: jpegWithMetadata()),
          EvidenceSaveResult.saved);
      c.securityJournal.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
      await c.securityJournal.idle();
      await settle(t);
      // LockTrigger (started by LockChallengeHost) is the FIRST subscriber.
      expect(c.lockTrigger.isRunning, isTrue);
      expect(native.listenCalls, 1);
      expect(native.receivers, 1);
    }

    Future<BuildContext> launcher(WidgetTester t) async {
      late BuildContext ctx;
      nav(t).push(MaterialPageRoute<void>(builder: (BuildContext b) {
        ctx = b;
        return const Scaffold(body: Text('launcher'));
      }));
      await settle(t);
      return ctx;
    }

    Future<IntruderOwnerSession> openTimeline(WidgetTester t) async {
      unawaited(openSecurityTimeline(await launcher(t), c));
      await settle(t);
      await typePin(t);
      expect(find.byType(SecurityTimelineScreen), findsOneWidget);
      return c.securityTimelineSessions.current!;
    }

    Future<void> openGroupDetails(WidgetTester t) async {
      final Finder btn = find
          .byKey(const ValueKey<String>('security_timeline_group_details_1'));
      await t.scrollUntilVisible(btn, 200,
          scrollable: find.byType(Scrollable).last);
      await settle(t);
      await t.tap(btn);
      await settle(t);
      expect(find.byType(SecurityTimelineDetailScreen), findsOneWidget);
    }

    Future<IntruderOwnerSession> openEvidence(WidgetTester t) async {
      unawaited(openIntruderEvidence(await launcher(t), c));
      await settle(t);
      await typePin(t);
      expect(find.byType(IntruderEvidenceScreen), findsOneWidget);
      return c.intruderOwnerSessions.current!;
    }

    void expectSharedRegistration() {
      expect(native.listenCalls, 1, reason: 'screens join, never re-register');
      expect(native.receivers, 1);
      expect(native.maxReceivers, 1);
    }

    testWidgets(
        'SS-A LockTrigger subscribes first; the timeline opens and closes; '
        'LockTrigger receives screen-off before, during and after',
        (WidgetTester t) async {
      await boot(t);
      expect(await screenOff(t), 1, reason: 'before');
      final IntruderOwnerSession s = await openTimeline(t);
      expectSharedRegistration();
      await t.pageBack();
      await settle(t);
      expect(find.byType(SecurityTimelineScreen), findsNothing);
      expect(s.invalidationReason, 'closed');
      expectSharedRegistration();
      expect(native.cancelCalls, 0);
      expect(await screenOff(t), 1, reason: 'after the timeline closed');
      final IntruderOwnerSession s2 = await openTimeline(t);
      expect(await screenOff(t), 1, reason: 'during');
      expect(s2.invalidationReason, 'screenOff');
      expect(find.byType(SecurityTimelineScreen), findsNothing);
      expect(await screenOff(t), 1, reason: 'after a screen-off close');
      expectSharedRegistration();
    });

    testWidgets(
        'SS-B1 timeline and details coexist: screen-off ends the timeline '
        'session (both routes close) and still reaches LockTrigger',
        (WidgetTester t) async {
      await boot(t);
      final IntruderOwnerSession s = await openTimeline(t);
      await openGroupDetails(t);
      expectSharedRegistration();
      expect(await screenOff(t), 1);
      expect(s.invalidationReason, 'screenOff');
      expect(find.byType(SecurityTimelineDetailScreen), findsNothing);
      expect(find.byType(SecurityTimelineScreen), findsNothing);
      expect(c.securityTimelineSessions.current, isNull);
    });

    testWidgets(
        'SS-B2 details closed (disposed) above a still-open timeline: a '
        'later screen-off still closes the timeline AND reaches LockTrigger',
        (WidgetTester t) async {
      await boot(t);
      final IntruderOwnerSession s = await openTimeline(t);
      await openGroupDetails(t);
      await t.pageBack();
      await settle(t);
      expect(find.byType(SecurityTimelineDetailScreen), findsNothing);
      expect(find.byType(SecurityTimelineScreen), findsOneWidget);
      expect(s.isValid, isTrue);
      expectSharedRegistration();
      expect(native.cancelCalls, 0, reason: 'details cancel stays local');
      expect(await screenOff(t), 1);
      expect(s.invalidationReason, 'screenOff');
      expect(find.byType(SecurityTimelineScreen), findsNothing);
    });

    testWidgets(
        'SS-C the evidence viewer opens and closes; LockTrigger still '
        'receives screen-off (and during: the viewer closes)',
        (WidgetTester t) async {
      await boot(t);
      final IntruderOwnerSession s = await openEvidence(t);
      expectSharedRegistration();
      await t.pageBack();
      await settle(t);
      expect(find.byType(IntruderEvidenceScreen), findsNothing);
      expect(s.invalidationReason, 'closed');
      expect(await screenOff(t), 1, reason: 'after the viewer closed');
      final IntruderOwnerSession s2 = await openEvidence(t);
      expect(await screenOff(t), 1, reason: 'during');
      expect(s2.invalidationReason, 'screenOff');
      expect(find.byType(IntruderEvidenceScreen), findsNothing);
      expectSharedRegistration();
    });

    testWidgets(
        'SS-G native channel failure does not silently disable protection: '
        'an error event closes the open timeline (fail closed) without '
        'stopping LockTrigger; a failed activation is surfaced and retried '
        'by the next screen, restoring LockTrigger delivery',
        (WidgetTester t) async {
      native.failListens = 1; // LockTrigger's first activation fails
      imageFrames = 0;
      c = AppContainer.inMemory(
          intruderEvidence: StaticIntruderEvidenceService(),
          screenState: MethodChannelScreenStateService());
      t.view.physicalSize = const Size(800, 2400);
      t.view.devicePixelRatio = 1.0;
      addTearDown(t.view.reset);
      await t.pumpWidget(SmartAppLockApp(container: c));
      await t.pumpAndSettle();
      await c.auth.enrollPin(_pin);
      await c.intruderStartup;
      await c.securityJournalStartup;
      await settle(t);
      expect(c.lockTrigger.isRunning, isTrue);
      expect(native.listenCalls, 1);
      expect(native.receivers, 0, reason: 'activation failed');
      expect(await screenOff(t), 0, reason: 'nothing can arrive yet');
      final IntruderOwnerSession s = await openTimeline(t);
      expect(native.listenCalls, 2, reason: 'the screen retried activation');
      expect(native.receivers, 1);
      await t.runAsync(() => native.sendError());
      await settle(t);
      expect(s.invalidationReason, 'screenOff',
          reason: 'a failure fails the timeline closed');
      expect(find.byType(SecurityTimelineScreen), findsNothing);
      expect(await screenOff(t), 1,
          reason: 'LockTrigger still receives after the error');
      expect(native.maxReceivers, 1);
    });

    // ------------------------------------------------------------ W-03
    testWidgets(
        'W-03-T1 timeline: an unexpected end of the screen-state stream ends '
        'the session (screenStateClosed) and closes the timeline',
        (WidgetTester t) async {
      await boot(t);
      final IntruderOwnerSession s = await openTimeline(t);
      await t.runAsync(() => native.endOfStream());
      await settle(t);
      expect(s.invalidationReason, 'screenStateClosed');
      expect(find.byType(SecurityTimelineScreen), findsNothing);
      expect(find.byKey(const Key('security_timeline_list')), findsNothing);
    });

    testWidgets(
        'W-03-T2 details (alone, no timeline beneath): end-of-stream ends the '
        'session (screenStateClosed) and closes the details',
        (WidgetTester t) async {
      await boot(t);
      final SecurityTimelineSnapshot snap = await c.securityTimeline.load();
      final TimelineFailureGroup g = buildTimelineRows(snap.entries)
          .whereType<TimelineFailureGroup>()
          .first;
      final IntruderOwnerSession s =
          c.securityTimelineSessions.begin(AuthType.pin);
      await launcher(t);
      unawaited(nav(t).push(MaterialPageRoute<void>(
        settings: const RouteSettings(name: securityTimelineDetailRouteName),
        builder: (_) => SecurityTimelineDetailScreen(
          container: c,
          session: s,
          data: SecurityTimelineDetailData(g, snap.labels,
              failureLogDamaged: failureLogDamagedEarlier(snap)),
        ),
      )));
      await settle(t);
      expect(find.byKey(const Key('security_timeline_detail_list')),
          findsOneWidget);
      await t.runAsync(() => native.endOfStream());
      await settle(t);
      expect(s.invalidationReason, 'screenStateClosed');
      expect(find.byType(SecurityTimelineDetailScreen), findsNothing);
      expect(
          find.byKey(const Key('security_timeline_detail_list')), findsNothing);
    });

    testWidgets(
        'W-03-T3 evidence list: end-of-stream ends the evidence session '
        '(screenStateClosed) and closes the viewer', (WidgetTester t) async {
      await boot(t);
      final IntruderOwnerSession s = await openEvidence(t);
      expect(find.byKey(const Key('intruder_evidence_item_1')), findsOneWidget);
      await t.runAsync(() => native.endOfStream());
      await settle(t);
      expect(s.invalidationReason, 'screenStateClosed');
      expect(find.byType(IntruderEvidenceScreen), findsNothing);
      expect(find.byKey(const Key('intruder_evidence_item_1')), findsNothing);
      expect(c.intruderOwnerSessions.current, isNull);
    });

    testWidgets(
        'W-03-T4 normal dispose with an open stream: no screenStateClosed '
        'invalidation, the shared registration survives for LockTrigger',
        (WidgetTester t) async {
      await boot(t);
      final IntruderOwnerSession s = await openTimeline(t);
      await openGroupDetails(t);
      await t.pageBack();
      await settle(t);
      await t.pageBack();
      await settle(t);
      expect(s.invalidationReason, 'closed');
      final IntruderOwnerSession e = await openEvidence(t);
      await t.pageBack();
      await settle(t);
      expect(e.invalidationReason, 'closed');
      expect(native.cancelCalls, 0);
      expectSharedRegistration();
      expect(await screenOff(t), 1);
    });

    testWidgets(
        'W-03-T5 evidence detail showing a photo: end-of-stream drops the '
        'pixels and closes detail + list (screenStateClosed)',
        (WidgetTester t) async {
      await boot(t);
      final IntruderOwnerSession s = await openEvidence(t);
      await t.tap(find.byKey(const Key('intruder_evidence_item_1')));
      await settle(t);
      expect(find.byType(IntruderEvidenceDetailScreen), findsOneWidget);
      expect(image(), findsOneWidget);
      expect(imageFrames, greaterThan(0));
      await t.runAsync(() => native.endOfStream());
      await settle(t);
      expect(s.invalidationReason, 'screenStateClosed');
      expect(image(), findsNothing);
      expect(find.byType(IntruderEvidenceDetailScreen), findsNothing);
      expect(find.byType(IntruderEvidenceScreen), findsNothing);
    });
  });
}
