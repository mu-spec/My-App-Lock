import 'package:flutter_test/flutter_test.dart';

import 'package:smart_app_lock/app/challenge_latency_recorder.dart';

import '../support/p17_latency_device.dart';

/// Phase 17 / M1 SIMULATED before/after: keyguard dismissal to shield
/// release, WITH the USER_PRESENT hint (after M1).
///
/// Fake-clock milliseconds at {P17Device.stepMs} ms resolution; the
/// dismissal is placed at 20 evenly spaced offsets within the one-second
/// retry period. These are scheduling numbers from a test double, NOT
/// device measurements.
final List<int> _samplesMs = <int>[];

void main() {
  group('SIM-LAT optimized', () {
    for (int offset = 0; offset < 1000; offset += 50) {
      testWidgets('offset=${offset}ms', (WidgetTester tester) async {
        final P17Device d = await p17Launch(tester);
        await p17WakeBehindKeyguard(d);
        expect(await d.alignToRetryTick(), isTrue);
        await tester.pump(Duration(milliseconds: offset));
        d.native.dismissKeyguard();
        d.screen.emitUserPresent();
        final int ms = await d.msUntilShieldReleased();
        expect(ms, 0);
        _samplesMs.add(ms);
        d.expectNoAccess();
      });
    }
    tearDownAll(() {
      // ignore: avoid_print
      print('SIM-LAT optimized ms: ${LatencyStats.of(_samplesMs)} '
          'samples=$_samplesMs');
    });
  });
}
