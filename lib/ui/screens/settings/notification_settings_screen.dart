import 'dart:async';

import 'package:flutter/material.dart';

import '../../../app/app_container.dart';
import '../../../app/app_scope.dart';
import '../../../design_system/design_system.dart';
import '../../../services/watcher_service.dart';
import '../../../utilities/result.dart';
import '../security/notification_privacy_screen.dart';
import 'settings_notification_status.dart';

/// Settings module: access to the app's EXISTING notification features.
///
/// Shows the real Android states (re-read on open, on app resume and after
/// every hand-off) and opens:
///  * this app's Android notification settings, through the existing
///    `openProtectionSettings(notifications)` hand-off used by onboarding
///    and Protection Health;
///  * Android's Notification access screen, through
///    [NotificationPrivacyService.openAccessSettings];
///  * the existing Notification Privacy screen (unchanged; weakening a mode
///    still verifies inside it).
///
/// Nothing is requested or granted here; a destination Android cannot open
/// shows a message instead.
class NotificationSettingsScreen extends StatefulWidget {
  const NotificationSettingsScreen({super.key});

  static const String routeName = '/settings/notifications';

  static Route<void> route() => MaterialPageRoute<void>(
        settings: const RouteSettings(name: routeName),
        builder: (_) => const NotificationSettingsScreen(),
      );

  static const String openFailedMessage =
      'Android could not open this settings screen.';

  @override
  State<NotificationSettingsScreen> createState() =>
      _NotificationSettingsScreenState();
}

class _NotificationSettingsScreenState extends State<NotificationSettingsScreen>
    with WidgetsBindingObserver {
  SettingsPermissionState _permission = SettingsPermissionState.unknown;
  SettingsPermissionState _access = SettingsPermissionState.unknown;
  bool _loaded = false;
  int _generation = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => unawaited(_reload()));
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) unawaited(_reload());
  }

  Future<void> _reload() async {
    final AppContainer? c = AppScope.read(context);
    if (c == null) return;
    final int generation = ++_generation;
    final List<SettingsPermissionState> states =
        await Future.wait(<Future<SettingsPermissionState>>[
      readSettingsNotificationPermission(c.watcher.getHealth),
      readSettingsNotificationAccess(c.notificationPrivacyService),
    ]);
    if (!mounted || generation != _generation) return;
    setState(() {
      _permission = states[0];
      _access = states[1];
      _loaded = true;
    });
  }

  Future<void> _open(Future<Result<bool>> Function() action) async {
    final ScaffoldMessengerState messenger = ScaffoldMessenger.of(context);
    bool opened;
    try {
      opened = (await action()).valueOrNull == true;
    } catch (_) {
      opened = false;
    }
    if (!opened && mounted) {
      messenger.showSnackBar(const SnackBar(
        content: Text(NotificationSettingsScreen.openFailedMessage),
      ));
    }
    if (mounted) await _reload();
  }

  Future<void> _openPrivacy(AppContainer c) async {
    await Navigator.of(context).push<void>(MaterialPageRoute<void>(
      settings: const RouteSettings(name: notificationPrivacyRouteName),
      builder: (_) => NotificationPrivacyScreen(container: c),
    ));
    if (mounted) await _reload();
  }

  static DsTone _tone(SettingsPermissionState s) => switch (s) {
        SettingsPermissionState.granted => DsTone.success,
        SettingsPermissionState.notGranted => DsTone.warning,
        SettingsPermissionState.notRequired => DsTone.info,
        SettingsPermissionState.unknown => DsTone.neutral,
      };

  Widget _status(String key, SettingsPermissionState s) => DsStatusPill(
        key: Key(key),
        label: _loaded ? s.label : 'Checking…',
        tone: _loaded ? _tone(s) : DsTone.neutral,
      );

  @override
  Widget build(BuildContext context) {
    final AppContainer? c = AppScope.maybeOf(context);
    return Scaffold(
      appBar: AppBar(title: const Text('Notifications')),
      body: ListView(
        padding: DsInsets.screen,
        children: <Widget>[
          DsCard(
            key: const Key('notif_settings_permission_card'),
            title: 'App notifications',
            subtitle: 'Lets Smart App Lock show its protection status and '
                'privacy placeholders.',
            trailing: _status('notif_settings_permission_status', _permission),
            child: Align(
              alignment: Alignment.centerLeft,
              child: TextButton(
                key: const Key('notif_settings_open_android'),
                onPressed: c == null
                    ? null
                    : () => _open(() => c.watcher.openProtectionSettings(
                          ProtectionSettingsTarget.notifications,
                        )),
                child: const Text('Open Android notification settings'),
              ),
            ),
          ),
          const SizedBox(height: DsSpacing.md),
          DsCard(
            key: const Key('notif_settings_access_card'),
            title: 'Notification access',
            subtitle: 'Needed only for Notification Privacy.',
            trailing: _status('notif_settings_access_status', _access),
            child: Align(
              alignment: Alignment.centerLeft,
              child: TextButton(
                key: const Key('notif_settings_open_access'),
                onPressed: c == null
                    ? null
                    : () => _open(c.notificationPrivacyService.openAccessSettings),
                child: const Text('Open Notification access settings'),
              ),
            ),
          ),
          const SizedBox(height: DsSpacing.md),
          DsCard(
            key: const Key('notif_settings_privacy'),
            title: 'Notification Privacy',
            subtitle: 'Hide notification content of protected apps.',
            trailing: const Icon(Icons.chevron_right),
            onTap: c == null ? null : () => _openPrivacy(c),
          ),
        ],
      ),
    );
  }
}
