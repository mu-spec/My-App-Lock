import '../../../services/notification_privacy_service.dart';
import '../../../services/watcher_service.dart';
import '../../../utilities/result.dart';
import '../onboarding/onboarding_permissions_step.dart'
    show
        OnboardingNotificationReading,
        OnboardingPermissionStatus,
        readOnboardingNotifications;

/// Settings module: the state shown for a notification-related permission.
///
/// Only a successful Android read that reports the permission as granted
/// becomes [granted]. A failed or unreadable read is [unknown] and is never
/// shown as granted.
enum SettingsPermissionState {
  granted('Allowed'),
  notGranted('Not allowed'),

  /// Android below 13 has no runtime notification permission.
  notRequired('No permission needed on this Android version'),
  unknown('Unknown');

  const SettingsPermissionState(this.label);

  final String label;
}

/// App notifications (POST_NOTIFICATIONS on Android 13+). Reuses the
/// existing onboarding mapping of the native health read
/// ([readOnboardingNotifications]).
Future<SettingsPermissionState> readSettingsNotificationPermission(
  Future<Result<ProtectionEngineHealth>> Function() probe,
) async {
  final OnboardingNotificationReading reading =
      await readOnboardingNotifications(probe);
  switch (reading.status) {
    case OnboardingPermissionStatus.unknown:
      return SettingsPermissionState.unknown;
    case OnboardingPermissionStatus.enabled:
      // Below Android 13 native reports "granted" because no runtime
      // permission exists; that says nothing about the user's app
      // notification switch, so it is not shown as Allowed.
      return reading.applicable
          ? SettingsPermissionState.granted
          : SettingsPermissionState.notRequired;
    case OnboardingPermissionStatus.notEnabled:
      return SettingsPermissionState.notGranted;
  }
}

/// Notification access (the Notification Privacy listener), from the
/// existing [NotificationPrivacyService.status] read.
Future<SettingsPermissionState> readSettingsNotificationAccess(
  NotificationPrivacyService service,
) async {
  try {
    final Result<NotificationPrivacyStatus> result = await service.status();
    final NotificationPrivacyStatus? status = result.valueOrNull;
    if (result.isFailure || status == null) {
      return SettingsPermissionState.unknown;
    }
    return status.accessGranted
        ? SettingsPermissionState.granted
        : SettingsPermissionState.notGranted;
  } catch (_) {
    return SettingsPermissionState.unknown;
  }
}
