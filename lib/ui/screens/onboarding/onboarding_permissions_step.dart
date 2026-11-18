import 'package:flutter/material.dart';

import '../../../app/app_scope.dart';
import '../../../app/router.dart';
import '../../../design_system/design_system.dart';
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
  /// re-check). Onboarding never opens system settings itself.
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

/// Phase 15 / M2 — permission education and guided activation.
///
/// Explains each capability and opens the app's existing setup flow for it
/// (Accessibility and Draw over apps keep their prominent disclosure and
/// the Android settings hand-off unchanged). Status is re-read from Android
/// after every return and on app resume; nothing is granted here. The user
/// may continue without granting: protection then stays incomplete and the
/// step says so.
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
    if (!mounted) {
      return;
    }
    setState(() {
      _status
        ..clear()
        ..addAll(next);
      _checking = false;
    });
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
