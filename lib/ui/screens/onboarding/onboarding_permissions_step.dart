import 'package:flutter/material.dart';

import '../../../app/app_scope.dart';
import '../../../app/router.dart';
import '../../../design_system/design_system.dart';
import '../../../services/watcher_service.dart';
import '../../../utilities/result.dart';

/// What Android reported for one capability.
enum OnboardingPermissionStatus {
  /// Android confirmed the capability is granted/enabled.
  enabled,

  /// Android confirmed it is not granted.
  notEnabled,

  /// The state could not be read. Never shown as granted.
  unknown,
}

/// One capability explained during onboarding (Phase 15 / M2).
class OnboardingPermission {
  const OnboardingPermission({
    required this.id,
    required this.title,
    required this.why,
    required this.route,
    required this.icon,
    required this.required,
  });

  final String id;
  final String title;

  /// Plain-language reason Smart App Lock needs it.
  final String why;

  /// The EXISTING dedicated setup flow (disclosure → Android settings →
  /// re-check). Core rows never open system settings directly.
  final String route;
  final IconData icon;

  /// Required for the native lock; otherwise recommended.
  final bool required;
}

/// Reads a capability from Android. Overridable in tests.
typedef OnboardingPermissionProbe = Future<Result<bool>> Function();

/// Maps an Android read to a status. Only a successful `true` is
/// [OnboardingPermissionStatus.enabled]; a failure (or an exception) is
/// [OnboardingPermissionStatus.unknown], never "enabled".
Future<OnboardingPermissionStatus> readOnboardingPermission(
  OnboardingPermissionProbe probe,
) async {
  try {
    final Result<bool> result = await probe();
    if (result.isFailure) {
      return OnboardingPermissionStatus.unknown;
    }
    return result.valueOrNull == true
        ? OnboardingPermissionStatus.enabled
        : OnboardingPermissionStatus.notEnabled;
  } catch (_) {
    return OnboardingPermissionStatus.unknown;
  }
}

/// First Android release with the runtime notification permission
/// (POST_NOTIFICATIONS, Android 13 / API 33).
const int onboardingNotificationMinSdk = 33;

/// The Android 13+ notification permission as read from Android.
class OnboardingNotificationReading {
  const OnboardingNotificationReading({
    required this.applicable,
    required this.status,
  });

  /// False only when Android reported an SDK below 13 (no runtime
  /// permission there). Unknown SDK → shown.
  final bool applicable;
  final OnboardingPermissionStatus status;
}

/// Maps the native health read to the notification row (Phase 15 final).
/// Only a successful read reporting the permission granted is
/// [OnboardingPermissionStatus.enabled]; a failure or exception is
/// [OnboardingPermissionStatus.unknown] and the row stays visible.
Future<OnboardingNotificationReading> readOnboardingNotifications(
  Future<Result<ProtectionEngineHealth>> Function() probe,
) async {
  const OnboardingNotificationReading unknown = OnboardingNotificationReading(
    applicable: true,
    status: OnboardingPermissionStatus.unknown,
  );
  try {
    final Result<ProtectionEngineHealth> result = await probe();
    final ProtectionEngineHealth? health = result.valueOrNull;
    if (result.isFailure || health == null) {
      return unknown;
    }
    final int? sdk = health.sdkInt;
    return OnboardingNotificationReading(
      applicable: sdk == null || sdk >= onboardingNotificationMinSdk,
      status: health.notificationPermissionGranted
          ? OnboardingPermissionStatus.enabled
          : OnboardingPermissionStatus.notEnabled,
    );
  } catch (_) {
    return unknown;
  }
}

/// Phase 15 / M2 — permission education and guided activation.
///
/// Explains each capability and opens the app's existing setup flow for it
/// (Accessibility and Draw over apps keep their prominent disclosure and
/// the Android settings hand-off unchanged). Status is re-read from Android
/// after every return and on app resume; nothing is granted here. The user
/// may continue without granting: protection then stays incomplete and the
/// step says so.
///
/// Phase 15 final: on Android 13+ an optional, separately explained
/// Notifications row opens this app's Android notification settings through
/// the existing `openProtectionSettings` hand-off (as Protection Health
/// does). It never counts toward the required set and never blocks
/// continuing.
class OnboardingPermissionsStep extends StatefulWidget {
  const OnboardingPermissionsStep({
    super.key,
    required this.onContinue,
    this.probes,
  });

  final VoidCallback onContinue;

  /// Test seam: capability id → probe. Defaults to the app's services.
  final Map<String, OnboardingPermissionProbe>? probes;

  static const String title = 'Allow protection';
  static const String subtitle =
      'Android needs your permission before Smart App Lock can cover a '
      'protected app. Each item opens a short explanation first, then the '
      'Android settings page where you decide.';
  static const String enabledLabel = 'Enabled';
  static const String notEnabledRequiredLabel = 'Required';
  static const String notEnabledRecommendedLabel = 'Recommended';
  static const String unknownLabel = "Couldn't check";
  static const String continueLabel = 'Continue';
  static const String skipLabel = 'Skip for now';
  static const String incompleteNote =
      'Protected apps will not lock until Accessibility and the lock shield '
      'are both enabled. You can finish this later in Security → App '
      'lock permissions.';
  static const String openFailedMessage =
      "Couldn't open that setup screen. Please try again.";

  static const String optionalHeading = 'Optional — not needed for app locking';
  static const String notificationsTitle = 'Notifications';
  static const String notificationsWhy =
      'Lets Smart App Lock show its protection status notification (and '
      'notification privacy placeholders, if you use them). App locking '
      'does not depend on it: protected apps still lock without it, but you '
      'may not notice if protection stops. Opens Android notification '
      'settings.';
  static const String notificationsOptionalLabel = 'Optional';

  static const List<OnboardingPermission> permissions = <OnboardingPermission>[
    OnboardingPermission(
      id: 'accessibility',
      title: 'Accessibility service',
      why: 'Tells Smart App Lock which app just opened, so a protected app '
          'is covered right away. It never reads your screen, types or '
          'taps for you, or collects data.',
      route: RouteNames.accessibilitySetup,
      icon: Icons.accessibility_new,
      required: true,
    ),
    OnboardingPermission(
      id: 'overlay',
      title: 'Draw over apps',
      why: 'Shows the lock shield over a protected app while the PIN, '
          'pattern or biometric screen opens. Used only for the lock '
          'screen.',
      route: RouteNames.overlaySetup,
      icon: Icons.layers,
      required: true,
    ),
    OnboardingPermission(
      id: 'usage',
      title: 'Usage access',
      why: 'A slower backup that notices protected apps if the '
          'Accessibility service is stopped. Optional but recommended.',
      route: RouteNames.usageAccess,
      icon: Icons.insights,
      required: false,
    ),
  ];

  @override
  State<OnboardingPermissionsStep> createState() =>
      _OnboardingPermissionsStepState();
}

class _OnboardingPermissionsStepState extends State<OnboardingPermissionsStep>
    with WidgetsBindingObserver {
  final Map<String, OnboardingPermissionStatus> _status =
      <String, OnboardingPermissionStatus>{};
  OnboardingNotificationReading _notifications =
      const OnboardingNotificationReading(
    applicable: true,
    status: OnboardingPermissionStatus.unknown,
  );
  bool _checking = true;
  bool _opening = false;
  String? _message;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _refresh());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// Returning from Android settings directly also re-checks.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _refresh();
    }
  }

  Map<String, OnboardingPermissionProbe> _probes() {
    final Map<String, OnboardingPermissionProbe>? override = widget.probes;
    if (override != null) {
      return override;
    }
    final container = AppScope.read(context);
    if (container == null) {
      return const <String, OnboardingPermissionProbe>{};
    }
    return <String, OnboardingPermissionProbe>{
      'accessibility': container.accessibility.isServiceEnabled,
      'overlay': container.overlay.canDrawOverlays,
      'usage': container.installedAppsService.hasUsageAccess,
    };
  }

  Future<void> _refresh() async {
    if (!mounted) {
      return;
    }
    final Map<String, OnboardingPermissionProbe> probes = _probes();
    final Map<String, OnboardingPermissionStatus> next =
        <String, OnboardingPermissionStatus>{};
    for (final OnboardingPermission p
        in OnboardingPermissionsStep.permissions) {
      final OnboardingPermissionProbe? probe = probes[p.id];
      next[p.id] = probe == null
          ? OnboardingPermissionStatus.unknown
          : await readOnboardingPermission(probe);
    }
    final OnboardingNotificationReading notifications =
        await _readNotifications();
    if (!mounted) {
      return;
    }
    setState(() {
      _status
        ..clear()
        ..addAll(next);
      _notifications = notifications;
      _checking = false;
    });
  }

  Future<OnboardingNotificationReading> _readNotifications() {
    final container = widget.probes == null ? AppScope.read(context) : null;
    if (container == null) {
      // No Android read available (or a probe override without one):
      // unknown, never granted.
      return Future<OnboardingNotificationReading>.value(
        const OnboardingNotificationReading(
          applicable: true,
          status: OnboardingPermissionStatus.unknown,
        ),
      );
    }
    return readOnboardingNotifications(container.watcher.getHealth);
  }

  Future<void> _openNotifications() async {
    if (_opening) {
      return;
    }
    final container = AppScope.read(context);
    setState(() {
      _opening = true;
      _message = null;
    });
    bool opened = false;
    try {
      // Android decides; the result is not trusted — re-read below.
      final Result<bool>? result = await container?.watcher
          .openProtectionSettings(ProtectionSettingsTarget.notifications);
      opened = result != null && result.isSuccess && result.valueOrNull == true;
    } catch (_) {
      opened = false;
    }
    if (!mounted) {
      return;
    }
    setState(() {
      _opening = false;
      if (!opened) _message = OnboardingPermissionsStep.openFailedMessage;
    });
    await _refresh();
  }

  OnboardingPermissionStatus _of(String id) =>
      _status[id] ?? OnboardingPermissionStatus.unknown;

  bool get _coreReady => OnboardingPermissionsStep.permissions
      .where((OnboardingPermission p) => p.required)
      .every(
        (OnboardingPermission p) =>
            _of(p.id) == OnboardingPermissionStatus.enabled,
      );

  Future<void> _open(OnboardingPermission permission) async {
    if (_opening) {
      return;
    }
    setState(() {
      _opening = true;
      _message = null;
    });
    try {
      // The existing flow handles denial, cancellation and an unavailable
      // settings screen; its pop result is not trusted — re-read below.
      await Navigator.of(context).pushNamed<Object?>(permission.route);
    } catch (_) {
      if (mounted) {
        setState(() => _message = OnboardingPermissionsStep.openFailedMessage);
      }
    } finally {
      if (mounted) {
        setState(() => _opening = false);
      }
    }
    await _refresh();
  }

  String _label(OnboardingPermission p) => switch (_of(p.id)) {
        OnboardingPermissionStatus.enabled =>
          OnboardingPermissionsStep.enabledLabel,
        OnboardingPermissionStatus.notEnabled => p.required
            ? OnboardingPermissionsStep.notEnabledRequiredLabel
            : OnboardingPermissionsStep.notEnabledRecommendedLabel,
        OnboardingPermissionStatus.unknown =>
          OnboardingPermissionsStep.unknownLabel,
      };

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    final String? message = _message;
    return ListView(
      key: const ValueKey<String>('onboarding_permissions'),
      padding: DsInsets.screen,
      children: <Widget>[
        Text(OnboardingPermissionsStep.title,
            style: theme.textTheme.headlineSmall),
        const SizedBox(height: DsSpacing.sm),
        Text(
          OnboardingPermissionsStep.subtitle,
          style: theme.textTheme.bodyMedium?.copyWith(
            color: palette.textSecondary,
          ),
        ),
        const SizedBox(height: DsSpacing.xl),
        for (final OnboardingPermission p
            in OnboardingPermissionsStep.permissions) ...<Widget>[
          DsCard(
            key: Key('onboarding_perm_${p.id}'),
            onTap: _checking || _opening ? null : () => _open(p),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Icon(p.icon, color: palette.primary),
                const SizedBox(width: DsSpacing.md),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(p.title, style: theme.textTheme.titleSmall),
                      const SizedBox(height: DsSpacing.xs),
                      Text(
                        p.why,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: palette.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: DsSpacing.sm),
                if (_checking)
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                else
                  DsStatusPill(
                    key: Key('onboarding_perm_${p.id}_status'),
                    label: _label(p),
                    tone: switch (_of(p.id)) {
                      OnboardingPermissionStatus.enabled => DsTone.success,
                      OnboardingPermissionStatus.notEnabled =>
                        p.required ? DsTone.danger : DsTone.warning,
                      OnboardingPermissionStatus.unknown => DsTone.warning,
                    },
                  ),
              ],
            ),
          ),
          const SizedBox(height: DsSpacing.md),
        ],
        if (_notifications.applicable) ...<Widget>[
          const SizedBox(height: DsSpacing.sm),
          Text(
            OnboardingPermissionsStep.optionalHeading,
            style: theme.textTheme.labelLarge?.copyWith(
              color: palette.textSecondary,
            ),
          ),
          const SizedBox(height: DsSpacing.sm),
          DsCard(
            key: const Key('onboarding_perm_notifications'),
            onTap: _checking || _opening ? null : _openNotifications,
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Icon(Icons.notifications_outlined, color: palette.primary),
                const SizedBox(width: DsSpacing.md),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        OnboardingPermissionsStep.notificationsTitle,
                        style: theme.textTheme.titleSmall,
                      ),
                      const SizedBox(height: DsSpacing.xs),
                      Text(
                        OnboardingPermissionsStep.notificationsWhy,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: palette.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: DsSpacing.sm),
                if (_checking)
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                else
                  DsStatusPill(
                    key: const Key('onboarding_perm_notifications_status'),
                    label: switch (_notifications.status) {
                      OnboardingPermissionStatus.enabled =>
                        OnboardingPermissionsStep.enabledLabel,
                      OnboardingPermissionStatus.notEnabled =>
                        OnboardingPermissionsStep.notificationsOptionalLabel,
                      OnboardingPermissionStatus.unknown =>
                        OnboardingPermissionsStep.unknownLabel,
                    },
                    tone: switch (_notifications.status) {
                      OnboardingPermissionStatus.enabled => DsTone.success,
                      OnboardingPermissionStatus.notEnabled => DsTone.neutral,
                      OnboardingPermissionStatus.unknown => DsTone.warning,
                    },
                  ),
              ],
            ),
          ),
          const SizedBox(height: DsSpacing.md),
        ],
        if (message != null) ...<Widget>[
          Text(message, style: TextStyle(color: palette.danger)),
          const SizedBox(height: DsSpacing.md),
        ],
        if (!_checking && !_coreReady) ...<Widget>[
          Text(
            OnboardingPermissionsStep.incompleteNote,
            style: theme.textTheme.bodySmall?.copyWith(color: palette.warning),
          ),
          const SizedBox(height: DsSpacing.md),
        ],
        const SizedBox(height: DsSpacing.sm),
        DsButton(
          label: !_checking && _coreReady
              ? OnboardingPermissionsStep.continueLabel
              : OnboardingPermissionsStep.skipLabel,
          variant: !_checking && _coreReady
              ? DsButtonVariant.primary
              : DsButtonVariant.outline,
          expand: true,
          onPressed: _checking || _opening ? null : widget.onContinue,
        ),
      ],
    );
  }
}
