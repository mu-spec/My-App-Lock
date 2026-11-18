import 'package:flutter/services.dart';

/// Phase 17 / M1: reads the native lock-latency aggregate (QA only).
///
/// `getLatencyReport` on the existing in-process overlay channel returns a
/// compact JSON string of monotonic stage durations and enum labels only
/// (no package names, credentials or timestamps). The host calls this only
/// when the compile-time QA diagnostics flag is on. It never throws and
/// nothing reads the result for enforcement.
class NativeLatencyReportChannel {
  const NativeLatencyReportChannel({
    MethodChannel channel = const MethodChannel('smart_app_lock/overlay'),
  }) : _channel = channel;

  final MethodChannel _channel;

  /// The report JSON, or null when unavailable.
  Future<String?> fetch() async {
    try {
      return await _channel.invokeMethod<String>('getLatencyReport');
    } catch (_) {
      return null;
    }
  }
}
