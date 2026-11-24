import 'package:flutter/material.dart';

import '../../../app/app_scope.dart';
import '../../../app/theme/theme_preference.dart';
import '../../../design_system/design_system.dart';
import 'about_screen.dart';
import 'notification_settings_screen.dart';

/// Settings tab: Appearance & theme, Notifications, About & support.
///
/// Every control performs a real action. Language selection and Backup &
/// restore are intentionally absent (postponed / pending a separate
/// security approval). Building this tab reads nothing from Android; the
/// notification statuses are read only when the Notifications screen is
/// opened.
class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  static const String description =
      'Tune Smart App Lock to behave exactly how you want.';

  static const Map<AppThemePreference, String> themeLabels =
      <AppThemePreference, String>{
    AppThemePreference.system: 'System default',
    AppThemePreference.light: 'Light',
    AppThemePreference.dark: 'Dark',
  };

  @override
  Widget build(BuildContext context) {
    final ThemePreferenceController? theme =
        ThemePreferenceScope.maybeOf(context);
    final bool hasContainer = AppScope.maybeOf(context) != null;
    return ListView(
      key: const Key('settings_list'),
      padding: DsInsets.screen,
      children: <Widget>[
        Text(
          description,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: context.dsColors.textSecondary,
              ),
        ),
        const SizedBox(height: DsSpacing.lg),
        const DsSectionTitle('Appearance & theme'),
        const SizedBox(height: DsSpacing.sm),
        if (theme != null) _ThemeCard(controller: theme),
        const SizedBox(height: DsSpacing.lg),
        const DsSectionTitle('Notifications'),
        const SizedBox(height: DsSpacing.sm),
        DsCard(
          key: const Key('settings_notifications'),
          title: 'Notifications',
          subtitle: hasContainer
              ? 'Android notification settings, notification access and '
                  'Notification Privacy'
              : 'Not available',
          trailing: const Icon(Icons.chevron_right),
          onTap: hasContainer
              ? () => Navigator.of(context).push<void>(
                    NotificationSettingsScreen.route(),
                  )
              : null,
        ),
        const SizedBox(height: DsSpacing.lg),
        const DsSectionTitle('About & support'),
        const SizedBox(height: DsSpacing.sm),
        DsCard(
          key: const Key('settings_about'),
          title: 'About Smart App Lock',
          subtitle: 'Version and app information',
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push<void>(AboutScreen.route()),
        ),
      ],
    );
  }
}

class _ThemeCard extends StatelessWidget {
  const _ThemeCard({required this.controller});

  final ThemePreferenceController controller;

  Future<void> _select(BuildContext context, AppThemePreference p) async {
    final ScaffoldMessengerState? messenger = ScaffoldMessenger.maybeOf(context);
    final bool saved = await controller.select(p);
    if (!saved && controller.store != null) {
      messenger?.showSnackBar(const SnackBar(
        content: Text('Theme applied, but it could not be saved.'),
      ));
    }
  }

  @override
  Widget build(BuildContext context) {
    return DsCard(
      key: const Key('settings_theme_card'),
      title: 'Theme',
      subtitle: 'System default follows your Android appearance setting.',
      child: Padding(
        padding: const EdgeInsets.only(top: DsSpacing.md),
        child: ValueListenableBuilder<AppThemePreference>(
          valueListenable: controller,
          builder: (BuildContext context, AppThemePreference selected, _) =>
              SizedBox(
            width: double.infinity,
            child: DsSegmented<AppThemePreference>(
              key: const Key('settings_theme_selector'),
              segments: <DsSegment<AppThemePreference>>[
                for (final AppThemePreference p in AppThemePreference.values)
                  DsSegment<AppThemePreference>(
                    value: p,
                    label: SettingsScreen.themeLabels[p]!,
                  ),
              ],
              selected: selected,
              onSelected: (AppThemePreference p) => _select(context, p),
            ),
          ),
        ),
      ),
    );
  }
}
