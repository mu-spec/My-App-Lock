import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/challenge_latency_recorder.dart';
import 'package:smart_app_lock/app/lock_challenge_host.dart';
import 'package:smart_app_lock/protection/lock_trigger.dart';
import 'package:smart_app_lock/services/impl/method_channel_screen_state_service.dart';
import 'package:smart_app_lock/services/impl/native_latency_report_channel.dart';
import 'package:smart_app_lock/services/impl/static_native_challenge_contract.dart';
import 'package:smart_app_lock/services/pending_lock_challenge.dart';
import 'package:smart_app_lock/services/screen_state_service.dart';
import 'package:smart_app_lock/ui/screens/pin/pin_unlock_screen.dart';
import 'package:smart_app_lock/utilities/result.dart';

import '../support/p17_latency_device.dart';

/// Phase 17 / M1 — lock latency instrumentation and the USER_PRESENT
/// ready-retry optimization.
///
/// SIMULATED: everything here runs under flutter_test's fake clock with
/// [StaticNativeChallengeContract] (the test double of the Kotlin hand-off
/// contract). Durations printed by the `SIM-LAT` tests are fake-clock
/// milliseconds of the Dart retry scheduling, NOT device measurements.
void main() {
  // ---------------------------------------------------------------- recorder
  group('ChallengeLatencyRecorder (pure)', () {
    late int now;
    ChallengeLatencyRecorder rec() =>
        ChallengeLatencyRecorder(nowMicros: () => now);

    test('ordered stages produce one ready sample with elapsed times', () {
      now = 1000;
      final ChallengeLatencyRecorder r = rec()
        ..begin(ChallengeLatencySource.lockTrigger);
      for (final ChallengeLatencyStage s in ChallengeLatencyStage.values) {
        now += 10;
        r.mark(s);
      }
      final ChallengeLatencySample s = r.samples.single;
      expect(s.outcome, ChallengeLatencyOutcome.ready);
      expect(s.ordered, isTrue);
      expect(s.totalMicros, 60);
      expect(s.stageMicros[ChallengeLatencyStage.credentialRead], 10);
      expect(r.isOpen, isFalse);
    });

    test('marks without a measurement and duplicate marks are counted', () {
      now = 0;
      final ChallengeLatencyRecorder r = rec()
        ..mark(ChallengeLatencyStage.firstFrame);
      expect(r.stagesWithoutAttempt, 1);
      r.begin(ChallengeLatencySource.bootstrap);
      r.mark(ChallengeLatencyStage.nativeShow);
      r.mark(ChallengeLatencyStage.nativeShow);
      expect(r.duplicateStages, 1);
    });

    test('a missing stage still yields a sample without that stage', () {
      now = 0;
      final ChallengeLatencyRecorder r = rec()
        ..begin(ChallengeLatencySource.nativePending);
      now = 5;
      r.mark(ChallengeLatencyStage.nativeShow);
      now = 40;
      r.mark(ChallengeLatencyStage.readyAccepted);
      final ChallengeLatencySample s = r.samples.single;
      expect(s.stageMicros.containsKey(ChallengeLatencyStage.secureWindow),
          isFalse);
      expect(s.totalMicros, 40);
    });

    test('out-of-order stages are flagged and excluded from statistics', () {
      now = 0;
      final ChallengeLatencyRecorder r = rec()
        ..begin(ChallengeLatencySource.lockTrigger);
      now = 30;
      r.mark(ChallengeLatencyStage.firstFrame);
      now = 40;
      r.mark(ChallengeLatencyStage.nativeShow); // earlier stage, later time
      now = 50;
      r.mark(ChallengeLatencyStage.readyAccepted);
      expect(r.samples.single.ordered, isFalse);
      expect(r.totalStats().n, 0);
    });

    test('begin supersedes, abandon closes, and samples are bounded', () {
      now = 0;
      final ChallengeLatencyRecorder r =
          ChallengeLatencyRecorder(nowMicros: () => now, capacity: 3)
            ..begin(ChallengeLatencySource.lockTrigger)
            ..begin(ChallengeLatencySource.userPresent)
            ..abandon();
      expect(
          r.samples.map((s) => s.outcome).toList(), <ChallengeLatencyOutcome>[
        ChallengeLatencyOutcome.superseded,
        ChallengeLatencyOutcome.abandoned,
      ]);
      for (int i = 0; i < 5; i++) {
        r
          ..begin(ChallengeLatencySource.other)
          ..mark(ChallengeLatencyStage.readyAccepted);
      }
      expect(r.samples.length, 3);
      r.reset();
      expect(r.samples, isEmpty);
    });

    test('a throwing clock never throws out of the recorder', () {
      final ChallengeLatencyRecorder r =
          ChallengeLatencyRecorder(nowMicros: () => throw StateError('clock'))
            ..begin(ChallengeLatencySource.lockTrigger)
            ..mark(ChallengeLatencyStage.readyAccepted)
            ..abandon();
      expect(r.samples.single.totalMicros, 0);
    });

    test('nearest-rank P50/P95/max with minimum sample counts', () {
      expect(LatencyStats.of(<int>[3, 1, 2, 4]).p50, isNull);
      expect(LatencyStats.of(<int>[3, 1, 2, 4]).max, 4);
      final LatencyStats five = LatencyStats.of(<int>[5, 1, 2, 4, 3]);
      expect(five.p50, 3);
      expect(five.p95, isNull);
      final LatencyStats twenty =
          LatencyStats.of(List<int>.generate(20, (int i) => i + 1));
      expect(twenty.p50, 10);
      expect(twenty.p95, 19);
      expect(twenty.max, 20);
    });

    test('describe() emits labels and durations only', () {
      now = 0;
      final ChallengeLatencyRecorder r = rec()
        ..begin(ChallengeLatencySource.lockTrigger);
      now = 7;
      r.mark(ChallengeLatencyStage.readyAccepted);
      final String line = ChallengeLatencyRecorder.describe(r.samples.single);
      expect(line, contains('source=lockTrigger'));
      expect(line, contains('readyAccepted=7us'));
      expect(line, isNot(contains('com.')));
    });
  });

  // ------------------------------------------------------ host instrumentation
  group('host instrumentation (simulated)', () {
    testWidgets('warm foreground lock: all Dart stages recorded in order',
        (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      await d.openProtectedApp();
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      expect(d.native.shieldVisible, isFalse);
      final ChallengeLatencySample s =
          LockChallengeHost.latencyRecorder.samples.single;
      expect(s.source, ChallengeLatencySource.lockTrigger);
      expect(s.outcome, ChallengeLatencyOutcome.ready);
      expect(s.ordered, isTrue);
      expect(s.stageMicros.keys.toSet(), ChallengeLatencyStage.values.toSet());
      // Shield released, but nothing is usable before authentication.
      d.expectNoAccess();
      await d.enterPin(p17Pin);
      expect(d.native.authorizedPackages, contains(p17Pkg));
    });

    testWidgets('cold start / process restore: bootstrap-sourced sample',
        (WidgetTester tester) async {
      final P17Device d =
          await p17Launch(tester, nativeTicketBeforeMount: true);
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      expect(d.native.shieldVisible, isFalse);
      final List<ChallengeLatencySample> ready = LockChallengeHost
          .latencyRecorder.samples
          .where((s) => s.outcome == ChallengeLatencyOutcome.ready)
          .toList();
      expect(ready, hasLength(1));
      expect(ready.single.source, ChallengeLatencySource.bootstrap);
      d.expectNoAccess();
    });

    testWidgets(
        'delayed Flutter: native shield stays and nothing is granted while '
        'the challenge cannot become ready', (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      // The Activity is not resumed (Flutter slow / background start
      // deferred). Native detects the app; Dart learns nothing yet.
      d.native.onActivityPaused();
      await d.lifecycle(AppLifecycleState.paused);
      d.native.reportForeground(p17Pkg);
      for (int i = 0; i < 10; i++) {
        await tester.pump(const Duration(seconds: 1));
        expect(d.native.shieldVisible, isTrue, reason: 'second $i');
        d.expectNoAccess();
      }
      expect(d.native.readyAccepted, 0);
      // Flutter catches up: the exact pending ticket is presented and only
      // then may the shield be released.
      d.native.onActivityResumed();
      await d.lifecycle(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      expect(d.native.shieldVisible, isFalse);
      d.expectNoAccess();
    });
  });

  // ------------------------------------------------ USER_PRESENT optimization
  group('USER_PRESENT early ready retry', () {
    testWidgets(
        'keyguard dismissed + userPresent releases the shield without waiting '
        'for the retry timer; access still requires the PIN',
        (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      final PendingLockChallenge wake = await p17WakeBehindKeyguard(d);
      expect(await d.alignToRetryTick(), isTrue);
      await tester.pump(const Duration(milliseconds: 100));
      d.native.dismissKeyguard();
      d.screen.emitUserPresent();
      expect(await d.msUntilShieldReleased(), 0);
      expect(d.native.readyChallenge, wake);
      expect(find.byType(PinUnlockScreen), findsOneWidget);
      d.expectNoAccess();
      final ChallengeLatencySample last =
          LockChallengeHost.latencyRecorder.samples.last;
      expect(last.source, ChallengeLatencySource.userPresent);
      expect(last.outcome, ChallengeLatencyOutcome.ready);
      await d.enterPin(p17Pin);
      expect(d.native.authorizedPackages, contains(p17Pkg));
    });

    testWidgets(
        'Dart hint before native USER_PRESENT recovery (reversed broadcast '
        'order) is equally safe', (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      await p17WakeBehindKeyguard(d);
      expect(await d.alignToRetryTick(), isTrue);
      d.native.keyguardLocked = false; // keyguard gone, receiver not yet run
      d.screen.emitUserPresent();
      expect(await d.msUntilShieldReleased(), 0);
      d.native.dismissKeyguard(); // native USER_PRESENT recovery runs late
      await tester.pump();
      expect(d.native.shieldVisible, isFalse,
          reason: 'the exact ready challenge is not re-covered');
      d.expectNoAccess();
    });

    testWidgets(
        'userPresent while the keyguard is still locked is rejected, keeps '
        'the shield and re-arms the bounded retry',
        (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      await p17WakeBehindKeyguard(d);
      expect(await d.alignToRetryTick(), isTrue);
      final int rejections = d.native.readyRejections.length;
      d.screen.emitUserPresent(); // spurious: keyguard still locked
      await tester.pump();
      expect(d.native.readyRejections.length, rejections + 1);
      expect(d.native.readyRejections.last,
          <NativeReadyRejection>{NativeReadyRejection.keyguardLocked});
      expect(d.native.shieldVisible, isTrue);
      d.expectNoAccess();
      // The retry was re-armed: once the keyguard is dismissed (without a
      // hint) the existing timer path still completes the hand-off.
      d.native.dismissKeyguard();
      final int waited = await d.msUntilShieldReleased();
      expect(waited, inInclusiveRange(1, 1000));
    });

    testWidgets('userPresent with no rejected hand-off does nothing',
        (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      await d.openProtectedApp();
      expect(d.native.shieldVisible, isFalse);
      final int calls = d.overlay.markChallengeReadyCalls;
      d.screen.emitUserPresent();
      await tester.pump();
      expect(d.overlay.markChallengeReadyCalls, calls);
      d.expectNoAccess();
    });

    testWidgets('screenOn does not trigger the early retry',
        (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      await p17WakeBehindKeyguard(d);
      expect(await d.alignToRetryTick(), isTrue);
      final int calls = d.overlay.markChallengeReadyCalls;
      d.screen.emitScreenOn();
      await tester.pump();
      expect(d.overlay.markChallengeReadyCalls, calls);
      expect(d.native.shieldVisible, isTrue);
    });

    testWidgets(
        'userPresent is not a wake for the lock trigger (no extra lock '
        'requirement)', (WidgetTester tester) async {
      final P17Device d = await p17Launch(tester);
      await d.openProtectedApp();
      await d.enterPin(p17Pin);
      expect(d.native.authorizedPackages, contains(p17Pkg));
      final List<LockRequired> emitted = <LockRequired>[];
      final sub = d.container.lockTrigger.lockRequired.listen(emitted.add);
      addTearDown(sub.cancel);
      // Dart-side screen-off only: the trigger now holds a pending re-lock.
      d.screen.emitScreenOff();
      await tester.pump();
      d.screen.emitUserPresent();
      await tester.pump();
      await tester.pump();
      expect(emitted, isEmpty, reason: 'userPresent must not act as screenOn');
      d.screen.emitScreenOn();
      await tester.pump();
      await tester.pump();
      expect(emitted, isNotEmpty, reason: 'control: screenOn still re-locks');
    });
  });

  // ------------------------------------------------ method-channel mapping
  group('MethodChannelScreenStateService user_present decoding', () {
    test('user_present decodes to userPresent (not screenOn)', () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      final TestDefaultBinaryMessenger messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      const String channel = 'smart_app_lock/screen_state';
      const MethodCodec codec = StandardMethodCodec();
      messenger.setMockMessageHandler(channel, (ByteData? message) async {
        return codec.encodeSuccessEnvelope(null); // listen / cancel
      });
      addTearDown(() => messenger.setMockMessageHandler(channel, null));
      final MethodChannelScreenStateService service =
          MethodChannelScreenStateService();
      final List<Result<ScreenStateEvent>> got = <Result<ScreenStateEvent>>[];
      final sub = service.events.listen(got.add);
      await pumpEventQueue();
      for (final String payload in <String>[
        'user_present',
        'screen_on',
        'screen_off',
      ]) {
        await messenger.handlePlatformMessage(
            channel, codec.encodeSuccessEnvelope(payload), (_) {});
      }
      await pumpEventQueue();
      expect(got.map((r) => r.valueOrNull).toList(), <ScreenStateEvent?>[
        ScreenStateEvent.userPresent,
        ScreenStateEvent.screenOn,
        ScreenStateEvent.screenOff,
      ]);
      await sub.cancel();
    });
  });

  // ------------------------------------------------ QA native report reader
  group('NativeLatencyReportChannel (QA only)', () {
    const MethodChannel channel = MethodChannel('p17_test/overlay');
    late TestDefaultBinaryMessenger messenger;
    setUp(() {
      TestWidgetsFlutterBinding.ensureInitialized();
      messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    });
    tearDown(() => messenger.setMockMethodCallHandler(channel, null));

    test('returns the native JSON from getLatencyReport', () async {
      final List<String> methods = <String>[];
      messenger.setMockMethodCallHandler(channel, (MethodCall call) async {
        methods.add(call.method);
        return '{"schema":1}';
      });
      expect(await const NativeLatencyReportChannel(channel: channel).fetch(),
          '{"schema":1}');
      expect(methods, <String>['getLatencyReport']);
    });

    test('never throws: a platform error or missing handler is null', () async {
      messenger.setMockMethodCallHandler(channel, (MethodCall call) async {
        throw PlatformException(code: 'x');
      });
      expect(await const NativeLatencyReportChannel(channel: channel).fetch(),
          isNull);
      messenger.setMockMethodCallHandler(channel, null);
      expect(await const NativeLatencyReportChannel(channel: channel).fetch(),
          isNull);
    });
  });

  // ------------------------------------------------ native source contracts
  group('native source contracts (static)', () {
    const String dir = 'android/app/src/main/kotlin/com/smartapplock/app';
    String read(String f) => File('$dir/$f').readAsStringSync();
    String body(String src, String start, String end) {
      final int a = src.indexOf(start);
      expect(a, greaterThanOrEqualTo(0), reason: start);
      final int b = src.indexOf(end, a + start.length);
      expect(b, greaterThan(a), reason: end);
      return src.substring(a, b);
    }

    test(
        'the host never consumes the shared screen-state stream itself '
        '(LockTrigger stays its only consumer; see SS-G)', () {
      final String host =
          File('lib/app/lock_challenge_host.dart').readAsStringSync();
      expect(host, isNot(contains('screenState.events')));
      expect(host, contains('keyguardDismissed.listen('));
    });

    test('native latency export is read-only channel data, no dump/logging',
        () {
      final String overlay = read('OverlayStatusChannel.kt');
      expect(overlay, contains('"getLatencyReport" ->'));
      expect(read('WatcherService.kt'), isNot(contains('override fun dump(')));
    });

    test('ScreenStateChannel relays USER_PRESENT as user_present', () {
      final String src = read('ScreenStateChannel.kt');
      expect(
          src,
          contains(
              'Intent.ACTION_USER_PRESENT -> events?.success("user_present")'));
      expect(src, contains('addAction(Intent.ACTION_USER_PRESENT)'));
    });

    test('recoverProtected keeps shield first, activity hand-off second', () {
      final String fn = body(read('WatcherService.kt'),
          'private fun recoverProtected(', 'private fun resetRecovery(');
      final int show = fn.indexOf('ProtectionOverlayController.show(context)');
      final int traced = fn.indexOf('LockLatency.tracer.shieldShown(');
      final int launch =
          fn.indexOf('MainActivity.foregroundForRecovery(context, pending)');
      expect(show, greaterThanOrEqualTo(0));
      expect(traced, greaterThan(show));
      expect(launch, greaterThan(traced));
      expect(fn, contains('val launched = shielded &&'));
    });

    test('wake identity is still persisted before recovery (unchanged)', () {
      final String fn = body(read('WatcherService.kt'), 'fun reportForeground(',
          'fun setGracePeriod(');
      final int remember = fn.indexOf(
          'ProtectionStateStore.rememberWakeReauthPackage(context, packageName)');
      final int recover = fn.indexOf('recoverProtected(');
      expect(remember, greaterThanOrEqualTo(0));
      expect(recover, greaterThan(remember));
    });

    test('latency calls are statements only: never in a condition or value',
        () {
      for (final String f in <String>[
        'WatcherService.kt',
        'OverlayStatusChannel.kt',
        'MainActivity.kt',
      ]) {
        final String src = read(f);
        for (final RegExp bad in <RegExp>[
          RegExp(r'if\s*\([^)]*LockLatency'),
          RegExp(r'(&&|\|\||!)\s*LockLatency'),
          RegExp(r'=\s*LockLatency\.tracer\.(shieldShown|activityRequested|'
              r'challengeReady|wakePersisted)'),
        ]) {
          expect(bad.hasMatch(src), isFalse, reason: '$f: ${bad.pattern}');
        }
      }
      final String tracer = read('LockLatencyTracer.kt');
      expect(tracer, isNot(contains('packageName')));
      expect(tracer, isNot(contains('android.util.Log')));
      expect(tracer, isNot(contains('currentTimeMillis')));
    });

    test('ready stage is recorded only after the shield was really hidden', () {
      final String src = read('OverlayStatusChannel.kt');
      final String fn =
          body(src, '"markChallengeReady" ->', 'result.success(hidden)');
      final int hide =
          fn.indexOf('val hidden = ProtectionOverlayController.hide()');
      final int guard = fn.indexOf('if (hidden) {');
      final int ready = fn.indexOf('LockLatency.tracer.challengeReady(');
      expect(hide, greaterThanOrEqualTo(0));
      expect(guard, greaterThan(hide));
      expect(ready, greaterThan(guard));
    });
  });
}
