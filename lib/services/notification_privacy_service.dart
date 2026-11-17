import '../security/notification_privacy/notification_privacy_settings.dart';
import '../utilities/result.dart';

/// Phase 14 / M1: native notification-privacy state (no content, ever).
final class NotificationPrivacyStatus {
  const NotificationPrivacyStatus({
    required this.accessGranted,
    required this.listenerConnected,
    required this.storeInvalid,
    required this.configuredCount,
  });

  static const NotificationPrivacyStatus unknown = NotificationPrivacyStatus(
    accessGranted: false,
    listenerConnected: false,
    storeInvalid: false,
    configuredCount: 0,
  );

  /// The user granted Notification access to Smart App Lock.
  final bool accessGranted;

  /// Android has the listener bound right now.
  final bool listenerConnected;

  /// The native copy is unreadable (native then uses the strictest mode).
  final bool storeInvalid;

  /// Apps with a mode other than Off in the native copy.
  final int configuredCount;

  factory NotificationPrivacyStatus.fromMap(Map<dynamic, dynamic> m) =>
      NotificationPrivacyStatus(
        accessGranted: m['accessGranted'] == true,
        listenerConnected: m['listenerConnected'] == true,
        storeInvalid: m['storeInvalid'] == true,
        configuredCount:
            m['configuredCount'] is int ? m['configuredCount'] as int : 0,
      );
}

/// Phase 14 / M1: bridge to the native notification privacy foundation.
abstract interface class NotificationPrivacyService {
  Future<Result<NotificationPrivacyStatus>> status();

  /// Replaces the native copy of the per-app modes. Resolves `true` only
  /// when native validated and durably stored the whole snapshot.
  Future<Result<bool>> configure(Map<String, NotificationPrivacyMode> modes);

  /// Opens Android's Notification access screen (user decides there).
  Future<Result<bool>> openAccessSettings();

  /// Fallback: opens Android's own notification settings for a protected
  /// app. Native refuses packages that are not protected.
  Future<Result<bool>> openAppNotificationSettings(String packageName);
}
