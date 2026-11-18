import 'package:flutter/material.dart';

import '../../../app/app_scope.dart';
import '../../../app/router.dart';
import '../../../design_system/design_system.dart';
import '../../../protection/protection_health.dart';
import '../onboarding/onboarding_permissions_step.dart'
    show OnboardingPermissionStatus, readOnboardingNotifications;

/// One required capability shown on the centralized setup screen.
class _Capability {
  const _Capability({
    required this.name,
    required this.description,
    required this.icon,
    required this.rowKey,
    required this.requirement,
    this.route,
  });

  final String name;
  final String description;
  final String? route;
  final IconData icon;
  final String rowKey;
  final CapabilityRequirement requirement;
}

/// Centralized permission setup (Phase 4E).
///
/// Shows every capability the protection architecture requires — Usage
/// Access (recovery), Accessibility (early detection), Draw over apps — each with
/// an **Enabled** or **Action Required** status. Tapping a row opens that
/// capability's dedicated setup flow (4B/4C/4D); returning re-checks the
/// capability state. App resume also re-checks (the user may have enabled
/// a capability in the system settings and come back directly).
class PermissionSetupScreen extends StatefulWidget {
  const PermissionSetupScreen({super.key, this.title = 'Permissions'});

  final String title;

  static const String headerTitle = 'App lock permissions';
  static const String headerSubtitle =
      'Enable the shield and Accessibility for the earliest native lock. '
      'Usage access is a slower recovery fallback.';
  static const String enabledLabel = 'Enabled';

  /// Notification row: Android reports the permission denied.
  static const String notificationNotEnabledLabel = 'Not enabled';

  /// Notification row: no Android answer (failure, exception, timeout or
  /// no platform) — never shown as Enabled.
  static const String notificationCouldNotCheckLabel = "Couldn't check";
  static const String checkingLabel = 'Checking…';

  /// Bound on the notification read (matches ProtectionHealthMonitor's
  /// default probe timeout); a slower answer is treated as unknown.
  static const Duration notificationCheckTimeout = Duration(seconds: 3);
  static const String actionRequiredLabel = 'Action Required';
  static String readyCount(int n) => '$n of 3 ready';
  static const String coreReadyLabel = 'Core requirements ready';
  static const String coreMissingLabel = 'Core setup incomplete';

  @override
  State<PermissionSetupScreen> createState() => _PermissionSetupScreenState();
}

class _PermissionSetupScreenState extends State<PermissionSetupScreen>
    with WidgetsBindingObserver {
  static const List<_Capability> _capabilities = <_Capability>[
    _Capability(
      name: 'Usage access',
      description: 'Recommended recovery fallback; polling may react late',
      route: RouteNames.usageAccess,
      icon: Icons.insights,
      rowKey: 'perm_row_usage',
      requirement: CapabilityRequirement.recommended,
    ),
    _Capability(
      name: 'Accessibility service',
      description: 'Required for the earliest event-driven native shield',
      route: RouteNames.accessibilitySetup,
      icon: Icons.accessibility_new,
      rowKey: 'perm_row_accessibility',
      requirement: CapabilityRequirement.required,
    ),
    _Capability(
      name: 'Background lock shield',
      description: 'Blocks protected content while secure unlock opens',
      route: RouteNames.overlaySetup,
      icon: Icons.layers,
      rowKey: 'perm_row_overlay',
      requirement: CapabilityRequirement.required,
    ),
    _Capability(
      name: 'Protection notification',
      description: 'Optional visible indicator for the recovery service',
      icon: Icons.notifications_outlined,
      rowKey: 'perm_row_notification',
      requirement: CapabilityRequirement.optional,
    ),
  ];

  final Map<String, bool> _granted = <String, bool>{
    'usage': false,
    'accessibility': false,
    'overlay': false,
  };

  /// Notification permission as last reported by Android. Starts unknown:
  /// "Enabled" needs an explicit Android grant, never a default.
  OnboardingPermissionStatus _notification = OnboardingPermissionStatus.unknown;
  bool _probing = true;

  /// Only the newest re-check may update the screen (a slower, older read
  /// must not overwrite a newer one, e.g. after a revocation).
  int _readSerial = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _refresh();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// Returning from the system settings (or from a setup flow) re-checks
  /// every capability.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _refresh();
    }
  }

  bool get _coreReady => _granted['accessibility']! && _granted['overlay']!;

  Future<void> _refresh() async {
    final int serial = ++_readSerial;
    final container = AppScope.read(context);
    if (container == null) {
      if (!mounted) {
        return;
      }
      setState(() {
        _notification = OnboardingPermissionStatus.unknown;
        _probing = false;
      });
      return;
    }

    final usage = await container.installedAppsService.hasUsageAccess();
    final accessibility = await container.accessibility.isServiceEnabled();
    final overlay = await container.overlay.canDrawOverlays();
    // Granted only when Android answers in time and says so; a failed,
    // thrown, malformed or timed-out read is unknown ("Couldn't check").
    final notification = await readOnboardingNotifications(
      () => container.watcher
          .getHealth()
          .timeout(PermissionSetupScreen.notificationCheckTimeout),
    );
    if (!mounted || serial != _readSerial) {
      return;
    }
    setState(() {
      _granted['usage'] = usage.isSuccess && usage.valueOrNull == true;
      _granted['accessibility'] =
          accessibility.isSuccess && accessibility.valueOrNull == true;
      _granted['overlay'] = overlay.isSuccess && overlay.valueOrNull == true;
      _notification = notification.status;
      _probing = false;
    });
  }

  Future<void> _openCapability(_Capability capability) async {
    final String? route = capability.route;
    if (route == null) {
      return;
    }
    await Navigator.of(context).pushNamed(route);
    if (mounted) {
      await _refresh();
    }
  }

  bool _grantedFor(_Capability capability) => switch (capability.rowKey) {
        'perm_row_usage' => _granted['usage']!,
        'perm_row_accessibility' => _granted['accessibility']!,
        'perm_row_overlay' => _granted['overlay']!,
        _ => _notification == OnboardingPermissionStatus.enabled,
      };

  /// Row label. The notification row is optional and kept out of the core
  /// set; it reads Enabled / Not enabled / Couldn't check.
  String _statusLabel(_Capability capability) {
    if (capability.rowKey == 'perm_row_notification') {
      return switch (_notification) {
        OnboardingPermissionStatus.enabled =>
          PermissionSetupScreen.enabledLabel,
        OnboardingPermissionStatus.notEnabled =>
          PermissionSetupScreen.notificationNotEnabledLabel,
        OnboardingPermissionStatus.unknown => _probing
            ? PermissionSetupScreen.checkingLabel
            : PermissionSetupScreen.notificationCouldNotCheckLabel,
      };
    }
    return _grantedFor(capability)
        ? PermissionSetupScreen.enabledLabel
        : _missingLabel(capability);
  }

  String _missingLabel(_Capability capability) =>
      switch (capability.requirement) {
        CapabilityRequirement.required => 'Required',
        CapabilityRequirement.recommended => 'Recommended',
        CapabilityRequirement.optional => 'Optional',
        CapabilityRequirement.internal => 'Unavailable',
      };

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(widget.title)),
      body: SafeArea(
        child: ListView(
          padding: DsInsets.screen,
          children: <Widget>[
            const SizedBox(height: DsSpacing.sm),
            Text(
              PermissionSetupScreen.headerTitle,
              style: theme.textTheme.headlineSmall,
            ),
            const SizedBox(height: DsSpacing.xs),
            Text(
              PermissionSetupScreen.headerSubtitle,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: context.dsColors.textSecondary,
              ),
            ),
            const SizedBox(height: DsSpacing.md),
            DsStatusPill(
              key: const Key('perm_ready_count'),
              label: _probing
                  ? 'Checking…'
                  : _coreReady
                      ? PermissionSetupScreen.coreReadyLabel
                      : PermissionSetupScreen.coreMissingLabel,
              tone: _probing || !_coreReady ? DsTone.warning : DsTone.success,
              showDot: !_probing,
            ),
            const SizedBox(height: DsSpacing.xl),
            DsCard(
              padding: const EdgeInsets.symmetric(vertical: DsSpacing.xs),
              child: Column(
                children: <Widget>[
                  for (final _Capability capability
                      in _capabilities) ...<Widget>[
                    SecurityStatusItem(
                      key: Key(capability.rowKey),
                      icon: capability.icon,
                      title: capability.name,
                      subtitle: capability.description,
                      level: _grantedFor(capability)
                          ? SecurityLevel.secured
                          : SecurityLevel.atRisk,
                      statusLabel: _statusLabel(capability),
                      onTap: capability.route == null
                          ? null
                          : () => _openCapability(capability),
                    ),
                    if (capability != _capabilities.last) const Divider(),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
