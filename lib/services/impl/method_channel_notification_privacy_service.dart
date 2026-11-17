import 'package:flutter/services.dart';

import '../../security/notification_privacy/notification_privacy_settings.dart';
import '../../utilities/result.dart';
import '../notification_privacy_service.dart';

/// Production [NotificationPrivacyService] over the native
/// `smart_app_lock/notification_privacy` channel (Phase 14 / M1).
class MethodChannelNotificationPrivacyService
    implements NotificationPrivacyService {
  MethodChannelNotificationPrivacyService({MethodChannel? channel})
      : _channel = channel ??
            const MethodChannel('smart_app_lock/notification_privacy');

  final MethodChannel _channel;

  Future<Result<T>> _guard<T>(Future<T> Function() op) async {
    try {
      return Result.success(await op());
    } catch (e, stackTrace) {
      return Result.failure(e, stackTrace);
    }
  }

  @override
  Future<Result<NotificationPrivacyStatus>> status() => _guard(() async {
        final Map<dynamic, dynamic>? m =
            await _channel.invokeMethod<Map<dynamic, dynamic>>('getStatus');
        if (m == null) throw StateError('no status');
        return NotificationPrivacyStatus.fromMap(m);
      });

  @override
  Future<Result<bool>> configure(Map<String, NotificationPrivacyMode> modes) =>
      _guard(() async {
        final Map<dynamic, dynamic>? m =
            await _channel.invokeMethod<Map<dynamic, dynamic>>(
          'configure',
          <String, Object?>{
            'modes': <String, String>{
              for (final MapEntry<String, NotificationPrivacyMode> e
                  in modes.entries)
                e.key: e.value.id,
            },
          },
        );
        return m?['applied'] == true;
      });

  @override
  Future<Result<bool>> openAccessSettings() => _guard(() async =>
      await _channel.invokeMethod<bool>('openAccessSettings') ?? false);

  @override
  Future<Result<bool>> openAppNotificationSettings(String packageName) =>
      _guard(() async =>
          await _channel.invokeMethod<bool>(
            'openAppNotificationSettings',
            <String, Object?>{'packageName': packageName},
          ) ??
          false);
}
