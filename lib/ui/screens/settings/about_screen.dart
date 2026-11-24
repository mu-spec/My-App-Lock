import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show appBuildName, appBuildNumber;

import '../../../design_system/design_system.dart';

/// Settings module: About Smart App Lock.
///
/// The version and build number are the values the Flutter tool compiled
/// into this build (`FLUTTER_BUILD_NAME` / `FLUTTER_BUILD_NUMBER`, the same
/// values Gradle uses as `versionName` / `versionCode`), so they match the
/// installed APK. When a build does not provide them, "Not available" is
/// shown. Privacy Policy and Support links are intentionally absent until
/// the owner provides real destinations.
class AboutScreen extends StatelessWidget {
  const AboutScreen({
    super.key,
    this.version = appBuildName,
    this.buildNumber = appBuildNumber,
  });

  static const String routeName = '/settings/about';
  static const String appName = 'Smart App Lock';
  static const String notAvailable = 'Not available';

  static Route<void> route() => MaterialPageRoute<void>(
        settings: const RouteSettings(name: routeName),
        builder: (_) => const AboutScreen(),
      );

  /// Test seams; default to the compiled build values.
  final String? version;
  final String? buildNumber;

  static String _orNotAvailable(String? v) =>
      (v == null || v.trim().isEmpty) ? notAvailable : v;

  @override
  Widget build(BuildContext context) {
    final String shownVersion = _orNotAvailable(version);
    return Scaffold(
      appBar: AppBar(title: const Text('About')),
      body: ListView(
        padding: DsInsets.screen,
        children: <Widget>[
          DsCard(
            key: const Key('about_info_card'),
            title: appName,
            subtitle: 'App lock for Android.',
            child: Padding(
              padding: const EdgeInsets.only(top: DsSpacing.sm),
              child: Column(
                children: <Widget>[
                  _InfoRow(
                    key: const Key('about_version'),
                    label: 'Version',
                    value: shownVersion,
                  ),
                  _InfoRow(
                    key: const Key('about_build'),
                    label: 'Build number',
                    value: _orNotAvailable(buildNumber),
                  ),
                  const _InfoRow(label: 'Platform', value: 'Android'),
                ],
              ),
            ),
          ),
          const SizedBox(height: DsSpacing.md),
          DsCard(
            key: const Key('about_licenses'),
            title: 'Open-source licenses',
            subtitle: 'Licenses of the libraries this app uses.',
            trailing: const Icon(Icons.chevron_right),
            onTap: () => showLicensePage(
              context: context,
              applicationName: appName,
              applicationVersion:
                  shownVersion == notAvailable ? null : shownVersion,
            ),
          ),
        ],
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  const _InfoRow({super.key, required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: DsInsets.row,
      child: Row(
        children: <Widget>[
          Expanded(
            child: Text(
              label,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: context.dsColors.textSecondary,
                  ),
            ),
          ),
          Text(value, style: Theme.of(context).textTheme.bodyMedium),
        ],
      ),
    );
  }
}
