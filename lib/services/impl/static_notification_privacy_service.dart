import '../../security/notification_privacy/notification_privacy_settings.dart';
import '../../utilities/result.dart';
import '../notification_privacy_service.dart';

/// In-memory [NotificationPrivacyService] for tests and previews.
class StaticNotificationPrivacyService implements NotificationPrivacyService {
  StaticNotificationPrivacyService({this.accessGranted = false});

  bool accessGranted;
  bool failConfigure = false;
  bool failStatus = false;

  /// Every snapshot native accepted, in order.
  final List<Map<String, NotificationPrivacyMode>> configured =
      <Map<String, NotificationPrivacyMode>>[];
  int accessSettingsOpened = 0;
  final List<String> appSettingsOpened = <String>[];

  Map<String, NotificationPrivacyMode>? get native =>
      configured.isEmpty ? null : configured.last;

  @override
  Future<Result<NotificationPrivacyStatus>> status() async {
    if (failStatus) return Result.failure(StateError('status unavailable'));
    return Result.success(NotificationPrivacyStatus(
      accessGranted: accessGranted,
      listenerConnected: accessGranted && (native?.isNotEmpty ?? false),
      storeInvalid: false,
      configuredCount: native?.length ?? 0,
    ));
  }

  @override
  Future<Result<bool>> configure(
      Map<String, NotificationPrivacyMode> modes) async {
    if (failConfigure) return Result.success(false);
    configured.add(Map<String, NotificationPrivacyMode>.unmodifiable(<String,
        NotificationPrivacyMode>{
      for (final MapEntry<String, NotificationPrivacyMode> e in modes.entries)
        if (e.value != NotificationPrivacyMode.off) e.key: e.value,
    }));
    return Result.success(true);
  }

  @override
  Future<Result<bool>> openAccessSettings() async {
    accessSettingsOpened++;
    return Result.success(true);
  }

  @override
  Future<Result<bool>> openAppNotificationSettings(String packageName) async {
    appSettingsOpened.add(packageName);
    return Result.success(true);
  }
}
