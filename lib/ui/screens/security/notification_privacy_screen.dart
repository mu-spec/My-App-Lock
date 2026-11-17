// Phase 14 / M1 — per-app notification privacy for protected apps.
// Phase 14 / M2 — the modes act (native): Android's limits are stated, and a
// warning appears when placeholders cannot be shown.
//
// Viewing needs no verification (no notification content is ever shown).
// Making a protected app's notifications MORE private needs nothing;
// revealing more (a weaker mode) needs a fresh owner verification (primary
// PIN/pattern, biometric refused, lockout re-checked: the same rule as the
// intruder settings).

import 'dart:async';

import 'package:flutter/material.dart';

import '../../../app/app_container.dart';
import '../../../data/models/protected_app.dart';
import '../../../design_system/design_system.dart';
import '../../../security/credentials/auth_type.dart';
import '../../../security/notification_privacy/notification_privacy_controller.dart';
import '../../../security/notification_privacy/notification_privacy_settings.dart';
import 'intruder_owner_verification.dart';

const String notificationPrivacyRouteName = '/security/notification-privacy';

abstract final class NotificationPrivacyText {
  static const String title = 'Notification privacy';
  static const String rowSubtitle =
      'Choose how protected apps\u2019 notifications appear';
  static const String intro =
      'Choose how notifications from each protected app appear. Smart App '
      'Lock only checks which app sent a notification and whether Android '
      'lets it be removed. Notification content is never read, stored, '
      'logged or sent anywhere.';
  static const String limits =
      'Android shows a notification before Smart App Lock can replace it, so '
      'it may briefly appear, sound or reach a connected watch. Ongoing '
      'notifications (calls, music, downloads, running services) can\u2019t '
      'be hidden. For the strongest protection, also restrict the app in '
      'Android\u2019s notification settings.';
  static const String placeholdersBlocked =
      'Smart App Lock can\u2019t show notifications. Hidden notifications are '
      'removed without a placeholder, so you won\u2019t see that they '
      'arrived.';
  static const String allowPlaceholders = 'Allow Smart App Lock notifications';
  static const String accessTitle = 'Notification access';
  static const String accessGranted = 'Allowed';
  static const String accessMissing = 'Not allowed';
  static const String accessUnknown = 'Unknown';
  static const String accessHint =
      'Android must allow Notification access before Smart App Lock can '
      'hide notifications. Without it, use Android\u2019s notification '
      'settings for each app.';
  static const String openAccess = 'Open Notification access';
  static const String androidSettings = 'Android notification settings';
  static const String noApps =
      'Protect an app first. Notification privacy applies only to protected '
      'apps.';
  static const String unavailable =
      'Notification privacy settings can\u2019t be read right now. Nothing '
      'was changed.';
  static const String notChanged = 'Notification privacy unchanged.';
  static const String notApplied =
      'Saved, but not applied yet. Smart App Lock will retry.';
  static const String couldNotOpen = 'Could not open Android settings.';
  static const String chooseTitle = 'Notifications from';

  static const String profilesNote =
      'Active profiles and rules can make this stricter: an app raised to '
      'Critical uses Maximum privacy and one raised to Sensitive uses Hide '
      'content. They never make it weaker than your choice here.';

  /// M3: an active profile or rule is stricter than [chosen] right now.
  static String raisedBy(
          NotificationPrivacyMode chosen, NotificationPrivacyMode now) =>
      '${chosen.label} \u00b7 ${now.label} now (profile or rule)';

  static String saved(String label, NotificationPrivacyMode m) =>
      '$label: ${m.label}';

  static String modeHint(NotificationPrivacyMode m) => switch (m) {
        NotificationPrivacyMode.off => 'Notifications appear normally.',
        NotificationPrivacyMode.hideContent =>
          'Shows the app name and \u201cNew notification\u201d only.',
        // Matches the native placeholder: posted by Smart App Lock (Android
        // shows its name in the header), title "New notification", no text.
        NotificationPrivacyMode.maximum =>
          'Shows a silent \u201cNew notification\u201d from Smart App Lock, '
              'without the app\u2019s name. Hidden on the lock screen.',
      };
}

class NotificationPrivacyScreen extends StatefulWidget {
  const NotificationPrivacyScreen({super.key, required this.container});

  final AppContainer container;

  @override
  State<NotificationPrivacyScreen> createState() =>
      _NotificationPrivacyScreenState();
}

class _NotificationPrivacyScreenState extends State<NotificationPrivacyScreen>
    with WidgetsBindingObserver {
  NotificationPrivacyView? _view;
  bool _busy = false;

  AppContainer get _c => widget.container;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    unawaited(_reload());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // The user may have changed Notification access in Android settings.
    if (state == AppLifecycleState.resumed) unawaited(_reload());
  }

  Future<void> _reload() async {
    final NotificationPrivacyView v = await _c.notificationPrivacy.load();
    if (mounted) setState(() => _view = v);
  }

  void _say(String text) {
    final ScaffoldMessengerState? m = ScaffoldMessenger.maybeOf(context);
    m?.hideCurrentSnackBar();
    m?.showSnackBar(SnackBar(content: Text(text)));
  }

  Future<void> _openAccess() async {
    final bool ok = (await _c.notificationPrivacyService.openAccessSettings())
            .valueOrNull ==
        true;
    if (!ok && mounted) _say(NotificationPrivacyText.couldNotOpen);
  }

  Future<void> _openOwnSettings() async {
    final bool ok =
        (await _c.notificationPrivacyService.openOwnNotificationSettings())
                .valueOrNull ==
            true;
    if (!ok && mounted) _say(NotificationPrivacyText.couldNotOpen);
  }

  Future<void> _openAndroidSettings(String packageName) async {
    final bool ok = (await _c.notificationPrivacyService
                .openAppNotificationSettings(packageName))
            .valueOrNull ==
        true;
    if (!ok && mounted) _say(NotificationPrivacyText.couldNotOpen);
  }

  Future<void> _choose(
      ProtectedApp app, NotificationPrivacyMode current) async {
    final NotificationPrivacyMode? next =
        await showModalBottomSheet<NotificationPrivacyMode>(
      context: context,
      builder: (BuildContext ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Padding(
              padding: const EdgeInsets.all(DsSpacing.lg),
              child: Text('${NotificationPrivacyText.chooseTitle} ${app.label}',
                  style: Theme.of(ctx).textTheme.titleMedium),
            ),
            for (final NotificationPrivacyMode m
                in NotificationPrivacyMode.values)
              ListTile(
                key: Key('np_mode_${m.id}'),
                leading: Icon(m == current
                    ? Icons.radio_button_checked
                    : Icons.radio_button_unchecked),
                title: Text(m.label),
                subtitle: Text(NotificationPrivacyText.modeHint(m)),
                onTap: () => Navigator.of(ctx).pop(m),
              ),
          ],
        ),
      ),
    );
    if (next == null || next == current || !mounted) return;
    setState(() => _busy = true);
    try {
      if (current.isWeakenedBy(next)) {
        final AuthType? method =
            await verifyIntruderOwner(Navigator.of(context), _c.auth);
        if (!mounted) return;
        if (method == null) {
          _say(NotificationPrivacyText.notChanged);
          return;
        }
      }
      final NotificationPrivacyChangeOutcome r =
          await _c.notificationPrivacy.setMode(app.packageName, next);
      if (!mounted) return;
      _say(switch (r) {
        NotificationPrivacyChangeOutcome.saved =>
          NotificationPrivacyText.saved(app.label, next),
        NotificationPrivacyChangeOutcome.savedNotApplied =>
          NotificationPrivacyText.notApplied,
        NotificationPrivacyChangeOutcome.unchanged ||
        NotificationPrivacyChangeOutcome.refused =>
          NotificationPrivacyText.notChanged,
      });
    } finally {
      if (mounted) setState(() => _busy = false);
      await _reload();
    }
  }

  @override
  Widget build(BuildContext context) {
    final NotificationPrivacyView? v = _view;
    return Scaffold(
      appBar: AppBar(title: const Text(NotificationPrivacyText.title)),
      body: v == null
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(DsSpacing.lg),
              children: <Widget>[
                const Text(NotificationPrivacyText.intro),
                const SizedBox(height: DsSpacing.sm),
                const Text(NotificationPrivacyText.limits,
                    key: Key('np_limits')),
                const SizedBox(height: 8),
                const Text(NotificationPrivacyText.profilesNote,
                    key: Key('np_profiles_note')),
                const SizedBox(height: DsSpacing.md),
                if (v.status != null &&
                    v.status!.accessGranted &&
                    !v.status!.placeholdersAllowed &&
                    v.apps.any((ProtectedApp a) =>
                        v.settings.modeFor(a.packageName) !=
                        NotificationPrivacyMode.off)) ...<Widget>[
                  DsCard(
                    key: const Key('np_placeholders_blocked'),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        const Text(NotificationPrivacyText.placeholdersBlocked),
                        TextButton(
                          key: const Key('np_allow_placeholders'),
                          onPressed: _busy ? null : _openOwnSettings,
                          child: const Text(
                              NotificationPrivacyText.allowPlaceholders),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: DsSpacing.md),
                ],
                if (!v.writable) ...<Widget>[
                  const Text(NotificationPrivacyText.unavailable,
                      key: Key('np_unavailable')),
                  const SizedBox(height: DsSpacing.md),
                ],
                DsCard(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      ListTile(
                        key: const Key('np_access_status'),
                        contentPadding: EdgeInsets.zero,
                        title: const Text(NotificationPrivacyText.accessTitle),
                        trailing: Text(v.status == null
                            ? NotificationPrivacyText.accessUnknown
                            : v.status!.accessGranted
                                ? NotificationPrivacyText.accessGranted
                                : NotificationPrivacyText.accessMissing),
                      ),
                      if (v.status?.accessGranted != true) ...<Widget>[
                        const Text(NotificationPrivacyText.accessHint),
                        const SizedBox(height: DsSpacing.sm),
                      ],
                      TextButton(
                        key: const Key('np_open_access'),
                        onPressed: _busy ? null : _openAccess,
                        child: const Text(NotificationPrivacyText.openAccess),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: DsSpacing.lg),
                if (v.apps.isEmpty)
                  const Text(NotificationPrivacyText.noApps,
                      key: Key('np_no_apps'))
                else
                  DsCard(
                    child: Column(
                      children: <Widget>[
                        for (final ProtectedApp app in v.apps)
                          _AppRow(
                            app: app,
                            mode: v.settings.modeFor(app.packageName),
                            raisedTo: v.status?.raisedNow[app.packageName],
                            showAndroidLink: v.status?.accessGranted != true,
                            onTap: !v.writable || _busy
                                ? null
                                : () => _choose(
                                    app, v.settings.modeFor(app.packageName)),
                            onAndroidSettings: _busy
                                ? null
                                : () => _openAndroidSettings(app.packageName),
                          ),
                      ],
                    ),
                  ),
              ],
            ),
    );
  }
}

class _AppRow extends StatelessWidget {
  const _AppRow({
    required this.app,
    required this.mode,
    this.raisedTo,
    required this.showAndroidLink,
    required this.onTap,
    required this.onAndroidSettings,
  });

  final ProtectedApp app;
  final NotificationPrivacyMode mode;

  /// M3: stricter mode applied now by an active profile or rule, if any.
  final NotificationPrivacyMode? raisedTo;
  final bool showAndroidLink;
  final VoidCallback? onTap;
  final VoidCallback? onAndroidSettings;

  @override
  Widget build(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          ListTile(
            key: Key('np_app_${app.packageName}'),
            contentPadding: EdgeInsets.zero,
            title: Text(app.label),
            subtitle: Text(
              raisedTo != null && raisedTo!.rank > mode.rank
                  ? NotificationPrivacyText.raisedBy(mode, raisedTo!)
                  : mode.label,
              key: Key('np_app_mode_${app.packageName}'),
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: onTap,
          ),
          if (showAndroidLink)
            TextButton(
              key: Key('np_android_settings_${app.packageName}'),
              onPressed: onAndroidSettings,
              child: const Text(NotificationPrivacyText.androidSettings),
            ),
        ],
      );
}
