import 'dart:async';

import 'package:flutter/services.dart';

import '../../utilities/result.dart';
import '../screen_state_service.dart';

/// Production [ScreenStateService] over the native
/// `smart_app_lock/screen_state` EventChannel (Phase 5K).
///
/// The native side relays `ACTION_SCREEN_OFF` / `ACTION_SCREEN_ON`
/// broadcasts as `screen_off` / `screen_on` payloads while a listener
/// is attached. Fail-closed (QA fix #4C.1): unknown payloads, channel
/// errors and a missing native handler surface as [Result.failure]
/// events — never fabricated screen states.
///
/// Phase 13 / M2 F-CL-2 (shared subscription ownership): a platform channel
/// has exactly ONE inbound message handler and the native side exactly one
/// active event sink, so every consumer (LockTrigger, the security timeline,
/// its details, the evidence viewer) listens to ONE shared broadcast
/// controller owned by this service. Its first listener installs the
/// handler and activates the native stream once; further listeners only
/// attach; a consumer cancelling detaches only itself; the LAST cancel
/// releases the handler and the native registration. Previously every
/// `events` call built its own controller whose `onListen` replaced the
/// handler of the earlier consumer and whose `onCancel` released the native
/// registration under it (a screen closing left LockTrigger deaf).
///  * End-of-stream (a null platform message) closes the shared controller:
///    every consumer gets `onDone` (the security screens fail closed, W-03);
///    the next `events` call builds a fresh controller and re-activates.
///    A closed predecessor never touches its successor's registration.
///  * A failed activation is surfaced to every consumer as one failure; the
///    stream stays open, and the next `events` call retries the activation
///    (the native side never holds more than one sink — a repeated `listen`
///    is separated by an `onCancel` in the embedding's EventChannel).
class MethodChannelScreenStateService implements ScreenStateService {
  MethodChannelScreenStateService({EventChannel? channel})
      : _channel = channel ?? const EventChannel('smart_app_lock/screen_state');

  final EventChannel _channel;

  /// The one shared controller (rebuilt only after end-of-stream closed it).
  StreamController<Result<ScreenStateEvent>>? _shared;

  /// The controller that currently owns the inbound handler and the native
  /// registration; null while released.
  StreamController<Result<ScreenStateEvent>>? _owner;

  /// The last activation of the current owner failed (retry pending).
  bool _activationFailed = false;

  @override
  Stream<Result<ScreenStateEvent>> get events {
    StreamController<Result<ScreenStateEvent>>? shared = _shared;
    if (shared == null || shared.isClosed) {
      shared = _shared = _createShared();
    } else if (_activationFailed && identical(_owner, shared)) {
      // A consumer arrives while the active stream's activation failed:
      // retry (never a second registration — see the class comment).
      _activate(shared);
    }
    return shared.stream;
  }

  MethodChannel get _activation => MethodChannel(_channel.name, _channel.codec);

  StreamController<Result<ScreenStateEvent>> _createShared() {
    // Phase 5 mobile-QA fix #4C.1: the framework's
    // `EventChannel.receiveBroadcastStream` SWALLOWS `listen` activation
    // failures — a missing native handler (MissingPluginException) or a
    // platform error during activation is caught inside its `onListen`
    // and routed to `FlutterError.reportError`, so it NEVER reaches the
    // stream (subscribers see nothing, not even a failure). Owning the
    // stream lifecycle here (register the inbound message handler and
    // invoke `listen` ourselves) surfaces EVERY channel error — error
    // envelopes AND a missing native handler — as exactly one
    // [Result.failure] data event. Fail-closed: an error or an unknown
    // payload is never turned into a screen state; the fail-quiet
    // consumer (LockTrigger) stays quiet.
    final EventChannel eventChannel = _channel;
    late final StreamController<Result<ScreenStateEvent>> controller;
    void emit(Result<ScreenStateEvent> result) {
      if (!controller.isClosed) {
        controller.add(result);
      }
    }

    controller = StreamController<Result<ScreenStateEvent>>.broadcast(
      onListen: () {
        _owner = controller;
        // Inbound platform messages on this channel: success envelopes
        // carry screen-state payloads; error envelopes carry failures;
        // a null reply signals end-of-stream.
        eventChannel.binaryMessenger.setMessageHandler(
          eventChannel.name,
          (ByteData? reply) async {
            if (reply == null) {
              // End-of-stream: release (once) and close; consumers get
              // onDone. A later consumer re-arms a fresh controller.
              if (identical(_owner, controller)) {
                unawaited(_release(controller));
              }
              if (!controller.isClosed) {
                await controller.close();
              }
              return null;
            }
            try {
              final dynamic payload = eventChannel.codec.decodeEnvelope(reply);
              emit(
                switch (payload) {
                  'screen_off' => Result.success(ScreenStateEvent.screenOff),
                  'screen_on' => Result.success(ScreenStateEvent.screenOn),
                  'user_present' =>
                    Result.success(ScreenStateEvent.userPresent),
                  _ => Result.failure(
                      StateError('Unknown screen-state payload: $payload'),
                    ),
                },
              );
            } catch (error) {
              // PlatformException (error envelope) or an undecodable
              // payload — a failure, never fabricated data.
              emit(Result<ScreenStateEvent>.failure(error));
            }
            return null;
          },
        );
        _activate(controller);
      },
      // Runs only when the LAST consumer cancels (broadcast semantics).
      onCancel: () async {
        if (identical(_owner, controller)) {
          await _release(controller);
        }
      },
    );
    return controller;
  }

  /// Activates the native stream for [controller]. If activation itself
  /// fails (no native handler, platform error), surfaces exactly one
  /// failure instead of losing the error to FlutterError.
  void _activate(StreamController<Result<ScreenStateEvent>> controller) {
    _activationFailed = false;
    unawaited(
      _activation.invokeMethod<void>('listen').then(
        (_) {},
        onError: (Object error, StackTrace stackTrace) {
          if (identical(_owner, controller)) {
            _activationFailed = true;
          }
          if (!controller.isClosed) {
            controller.add(Result<ScreenStateEvent>.failure(error));
          }
        },
      ),
    );
  }

  /// Releases the inbound handler and the native registration of the
  /// current owner [controller]. Synchronous up to the platform send, so a
  /// re-subscription right after is ordered after this cancel.
  Future<void> _release(
      StreamController<Result<ScreenStateEvent>> controller) async {
    _owner = null;
    _activationFailed = false;
    _channel.binaryMessenger.setMessageHandler(_channel.name, null);
    try {
      await _activation.invokeMethod<void>('cancel');
    } catch (_) {
      // Fail-quiet: nothing to cancel (missing handler, teardown).
    }
  }
}
